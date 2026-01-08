/*
 * Error reporting functions
 */

#include <stdio.h>
#include <time.h>

#include "pgpr.h"
#include "pgpr_internal.h"

static char *format_keyid(pgprKeyID_t keyid, char *userid)
{
    static const char hex[] = "0123456789abcdef";
    char *keyidstr = pgprMalloc(sizeof(pgprKeyID_t) * 2 + 1);
    int i;
    for (i = 0; i < sizeof(pgprKeyID_t); i++) {
	keyidstr[2 * i] = hex[keyid[i] >> 4 & 15];
	keyidstr[2 * i + 1] = hex[keyid[i] & 15];
    }
    keyidstr[2 * i] = 0;
    if (!userid) {
	return keyidstr;
    } else {
	char *ret = NULL;
	pgprAsprintf(&ret, "%s (%s)", keyidstr, userid);
	free(keyidstr);
	return ret;
    }
}

static char *format_time(time_t *t)
{
    char dbuf[BUFSIZ];
    struct tm _tm, *tms;
    char *ret = NULL;

    tms = localtime_r(t, &_tm);
    if (!(tms && strftime(dbuf, sizeof(dbuf), "%Y-%m-%d %H:%M:%S", tms) > 0)) {
	pgprAsprintf(&ret, "Invalid date (%lld)", (long long int)t);
    } else {
	ret = pgprStrdup(dbuf);
    }
    return ret;
}

static void pgprAddKeyLint(pgprDigParams key, char **lints, const char *msg)
{
    char *keyid = format_keyid(key->signid, key->tag == PGPRTAG_PUBLIC_SUBKEY ? NULL : key->userid);
    char *main_keyid = key->tag == PGPRTAG_PUBLIC_SUBKEY ? format_keyid(key->mainid, key->userid) : NULL;
    if (key->tag == PGPRTAG_PUBLIC_SUBKEY) {
	/* special case the message about subkeys with a revoked primary key */
	if (key->revoked == 2)
	    pgprAsprintf(lints, "Key %s is a subkey of key %s, which has been revoked", keyid, main_keyid);
	else
	    pgprAsprintf(lints, "Subkey %s of key %s %s", keyid, main_keyid, msg);
    } else {
	pgprAsprintf(lints, "Key %s %s", keyid, msg);
    }
    free(keyid);
    free(main_keyid);
}

static void pgprAddSigLint(pgprDigParams sig, char **lints, const char *msg)
{
    pgprAsprintf(lints, "Signature %s", msg);
}

static char *format_expired(uint32_t created, uint32_t expire)
{
    time_t exptime = (time_t)created + expire;
    char *expdate = format_time(&exptime);
    char *msg = NULL;
    pgprAsprintf(&msg, "expired on %s", expdate);
    free(expdate);
    return msg;
}

void pgprAddLint(pgprDigParams digp, char **lints, pgprRC error)
{
    const char *msg = NULL;
    char *exp_msg;
    if (error == PGPR_OK || !lints)
	return;
    *lints = NULL;

    /* if we have suitable DigParams we can make a better error message */
    if (digp && (digp->tag == PGPRTAG_PUBLIC_KEY || digp->tag == PGPRTAG_PUBLIC_SUBKEY)) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported pubkey version (V%d)", digp->version);
	    return;
	case PGPR_ERROR_KEY_EXPIRED:
	    exp_msg = format_expired(digp->time, digp->key_expire);
	    pgprAddKeyLint(digp, lints, exp_msg);
	    free(exp_msg);
	    return;
	case PGPR_ERROR_KEY_REVOKED:
	case PGPR_ERROR_PRIMARY_REVOKED:
	    pgprAddKeyLint(digp, lints, "has been revoked");
	    return;
	case PGPR_ERROR_KEY_NOT_VALID:
	    pgprAddKeyLint(digp, lints, "has no valid binding signature");
	    return;
	case PGPR_ERROR_KEY_NO_SIGNING:
	    pgprAddKeyLint(digp, lints, "is not suitable for signing");
	    return;
	case PGPR_ERROR_KEY_CREATED_AFTER_SIG:
	    pgprAddKeyLint(digp, lints, "has been created after the signature");
	    return;
	default:
	    break;
	}
    }
    if (digp && digp->tag == PGPRTAG_SIGNATURE) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported signature version (V%d)", digp->version);
	    return;
	case PGPR_ERROR_SIGNATURE_EXPIRED:
	    exp_msg = format_expired(digp->time, digp->sig_expire);
	    pgprAddSigLint(digp, lints, exp_msg);
	    free(exp_msg);
	    return;
	default:
	    break;
	}
    }
    if (digp) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported packet version (V%d)", digp->version);
	    return;
	case PGPR_ERROR_UNSUPPORTED_ALGORITHM:
	    pgprAsprintf(lints, "Unsupported pubkey algorithm (%d)", digp->pubkey_algo);
	    return;
	default:
	    break;
	}
    }

    switch (error) {
    case PGPR_ERROR_INTERNAL:
	msg = "Internal PGP parser error";
	break;
    case PGPR_ERROR_CORRUPT_PGP_PACKET:
	msg = "Corrupt PGP packet";
	break;
    case PGPR_ERROR_UNEXPECTED_PGP_PACKET:
	msg = "Unexpected PGP packet";
	break;
    case PGPR_ERROR_NO_CREATION_TIME:
	msg = "Signature without creation time";
	break;
    case PGPR_ERROR_DUPLICATE_DATA:
	msg = "Duplicate data in signature";
	break;
    case PGPR_ERROR_UNKNOWN_CRITICAL_PKT:
	msg = "Unknown critical packet in signature";
	break;
    case PGPR_ERROR_BAD_PUBKEY_STRUCTURE:
	msg = "Bad pubkey structure";
	break;
    case PGPR_ERROR_SELFSIG_VERIFICATION:
	msg = "Pubkey self-signature verification failure";
	break;
    case PGPR_ERROR_MISSING_SELFSIG:
	msg = "Pubkey misses a self-signature";
	break;
    case PGPR_ERROR_UNSUPPORTED_VERSION:
	msg = "Unsupported packet version";
	break;
    case PGPR_ERROR_UNSUPPORTED_ALGORITHM:
	msg = "Unsupported pubkey algorithm";
	break;
    case PGPR_ERROR_UNSUPPORTED_CURVE:
	msg = "Unsupported pubkey curve";
	break;
    case PGPR_ERROR_BAD_PUBKEY:
	msg = "Pubkey was not accepted by crypto backend";
	break;
    case PGPR_ERROR_BAD_SIGNATURE:
	msg = "Signature was not accepted by crypto backend";
	break;
    case PGPR_ERROR_SIGNATURE_VERIFICATION:
	msg = "Signature verification failure";
	break;
    case PGPR_ERROR_SIGNATURE_FROM_FUTURE:
	msg = "Signature was created in the future";
	break;
    case PGPR_ERROR_SIGNATURE_EXPIRED:
	msg = "Signature has expired";
	break;
    case PGPR_ERROR_KEY_EXPIRED:
	msg = "Key has expired";
	break;
    case PGPR_ERROR_KEY_REVOKED:
	msg = "Key has been revoked";
	break;
    case PGPR_ERROR_PRIMARY_REVOKED:
	msg = "Primary key has been revoked";
	break;
    case PGPR_ERROR_KEY_NOT_VALID:
	msg = "Key has no valid binding signature";
	break;
    case PGPR_ERROR_KEY_NO_SIGNING:
	msg = "Key is not suitable for signing";
	break;
    case PGPR_ERROR_KEY_CREATED_AFTER_SIG:
	msg = "Key has been created after the signature";
	break;
    default:
	pgprAsprintf(lints, "Unknown error (%d)", error);
	return;
    }
    *lints = pgprStrdup(msg);
}

