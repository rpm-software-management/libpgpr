/*
 * Error reporting functions
 */

#include <stdio.h>
#include <time.h>

#include "pgpr_internal.h"

static const char unknown_error[] = "Unknown error";

const char *pgprErrorStr(pgprRC rc)
{
    switch (rc) {
    case PGPR_OK:
	return "No error";
    case PGPR_ERROR_INTERNAL:
	return "Internal PGP parser error";
    case PGPR_ERROR_CORRUPT_PGP_PACKET:
	return "Corrupt PGP packet";
    case PGPR_ERROR_UNEXPECTED_PGP_PACKET:
	return "Unexpected PGP packet";
    case PGPR_ERROR_NO_CREATION_TIME:
	return "Signature without creation time";
    case PGPR_ERROR_DUPLICATE_DATA:
	return "Duplicate data in signature";
    case PGPR_ERROR_UNKNOWN_CRITICAL_PKT:
	return "Unknown critical packet in signature";
    case PGPR_ERROR_BAD_PUBKEY_STRUCTURE:
	return "Bad pubkey structure";
    case PGPR_ERROR_SELFSIG_VERIFICATION:
	return "Pubkey self-signature verification failure";
    case PGPR_ERROR_MISSING_SELFSIG:
	return "Pubkey misses a self-signature";
    case PGPR_ERROR_UNSUPPORTED_VERSION:
	return "Unsupported packet version";
    case PGPR_ERROR_UNSUPPORTED_ALGORITHM:
	return "Unsupported pubkey algorithm";
    case PGPR_ERROR_UNSUPPORTED_CURVE:
	return "Unsupported pubkey curve";
    case PGPR_ERROR_UNSUPPORTED_DIGEST:
	return "Unsupported digest algorithm";
    case PGPR_ERROR_BAD_PUBKEY:
	return "Pubkey not accepted by crypto backend";
    case PGPR_ERROR_BAD_SIGNATURE:
	return "Signature not accepted by crypto backend";
    case PGPR_ERROR_SIGNATURE_VERIFICATION:
	return "Signature verification failure";
    case PGPR_ERROR_SIGNATURE_FROM_FUTURE:
	return "Signature was created in the future";
    case PGPR_ERROR_SIGNATURE_EXPIRED:
	return "Signature has expired";
    case PGPR_ERROR_KEY_EXPIRED:
	return "Key has expired";
    case PGPR_ERROR_KEY_REVOKED:
	return "Key has been revoked";
    case PGPR_ERROR_PRIMARY_REVOKED:
	return "Primary key has been revoked";
    case PGPR_ERROR_KEY_NOT_VALID:
	return "Key has no valid binding signature";
    case PGPR_ERROR_KEY_NO_SIGNING:
	return "Key is not suitable for signing";
    case PGPR_ERROR_KEY_CREATED_AFTER_SIG:
	return "Key has been created after the signature";
    default:
	break;
    }
    return unknown_error;
}

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

static void pgprAddKeyLint(pgprItem key, char **lints, const char *msg)
{
    char *keyid = format_keyid(key->keyid, key->tag == PGPRTAG_PUBLIC_SUBKEY ? NULL : key->userid);
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

static void pgprAddSigLint(pgprItem sig, char **lints, const char *msg)
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

void pgprAddLint(pgprItem item, char **lints, pgprRC error)
{
    const char *msg = NULL;
    char *exp_msg;
    if (error == PGPR_OK || !lints)
	return;
    *lints = NULL;

    /* if we have a suitable item we can make a better error message */
    if (item && (item->tag == PGPRTAG_PUBLIC_KEY || item->tag == PGPRTAG_PUBLIC_SUBKEY)) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported pubkey version (V%d)", item->version);
	    return;
	case PGPR_ERROR_KEY_EXPIRED:
	    exp_msg = format_expired(item->time, item->key_expire);
	    pgprAddKeyLint(item, lints, exp_msg);
	    free(exp_msg);
	    return;
	case PGPR_ERROR_KEY_REVOKED:
	case PGPR_ERROR_PRIMARY_REVOKED:
	    pgprAddKeyLint(item, lints, "has been revoked");
	    return;
	case PGPR_ERROR_KEY_NOT_VALID:
	    pgprAddKeyLint(item, lints, "has no valid binding signature");
	    return;
	case PGPR_ERROR_KEY_NO_SIGNING:
	    pgprAddKeyLint(item, lints, "is not suitable for signing");
	    return;
	case PGPR_ERROR_KEY_CREATED_AFTER_SIG:
	    pgprAddKeyLint(item, lints, "has been created after the signature");
	    return;
	default:
	    break;
	}
    }
    if (item && item->tag == PGPRTAG_SIGNATURE) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported signature version (V%d)", item->version);
	    return;
	case PGPR_ERROR_UNSUPPORTED_DIGEST:
	    pgprAsprintf(lints, "Unsupported digest algorithm (%d)", item->hash_algo);
	    return;
	case PGPR_ERROR_SIGNATURE_EXPIRED:
	    exp_msg = format_expired(item->time, item->sig_expire);
	    pgprAddSigLint(item, lints, exp_msg);
	    free(exp_msg);
	    return;
	default:
	    break;
	}
    }
    if (item) {
	switch (error) {
	case PGPR_ERROR_UNSUPPORTED_VERSION:
	    pgprAsprintf(lints, "Unsupported packet version (V%d)", item->version);
	    return;
	case PGPR_ERROR_UNSUPPORTED_ALGORITHM:
	    pgprAsprintf(lints, "Unsupported pubkey algorithm (%d)", item->pubkey_algo);
	    return;
	case PGPR_ERROR_UNSUPPORTED_CURVE:
	    if (item->alg)
		pgprAsprintf(lints, "Unsupported pubkey curve (%d)", item->alg->curve);
	    else
		pgprAsprintf(lints, "Unsupported pubkey curve");
	    return;
	default:
	    break;
	}
    }

    msg = pgprErrorStr(error);
    if (msg == unknown_error) {
	pgprAsprintf(lints, "Unknown error (%d)", error);
    } else {
	*lints = pgprStrdup(msg);
    }
}

