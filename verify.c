#include <string.h>
#include <stdarg.h>

#include "pgpr.h"
#include "pgpr_internal.h"

pgprRC pgprVerifySignatureRaw(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen)
{
    /* make sure the parameters are correct and the pubkey algo matches */
    if (sig == NULL || sig->tag != PGPRTAG_SIGNATURE)
	return PGPR_ERROR_INTERNAL;
    if (key == NULL || (key->tag != PGPRTAG_PUBLIC_KEY && key->tag != PGPRTAG_PUBLIC_SUBKEY))
	return PGPR_ERROR_INTERNAL;
    if (hash == NULL || hashlen == 0 || hashlen != pgprDigestLength(sig->hash_algo))
	return PGPR_ERROR_INTERNAL;
    if (sig->pubkey_algo != key->pubkey_algo)
	return PGPR_ERROR_SIGNATURE_VERIFICATION;
    /* Compare leading 16 bits of digest for a quick check. */
    if (memcmp(hash, sig->signhash16, 2) != 0)
	return PGPR_ERROR_SIGNATURE_VERIFICATION;
    if (!key->alg || !sig->alg || !sig->alg->verify)
	return PGPR_ERROR_SIGNATURE_VERIFICATION;
    return sig->alg->verify(key->alg, sig->alg, hash, hashlen, sig->hash_algo);
}

pgprRC pgprVerifySignature(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen, char **lints)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */

    if (lints)
        *lints = NULL;

    if (!sig || sig->tag != PGPRTAG_SIGNATURE || (sig->sigtype != PGPRSIGTYPE_BINARY && sig->sigtype != PGPRSIGTYPE_TEXT && sig->sigtype != PGPRSIGTYPE_STANDALONE))
	goto exit;
    if (!key || (key->tag != PGPRTAG_PUBLIC_KEY && key->tag != PGPRTAG_PUBLIC_SUBKEY))
	goto exit;

    rc = pgprVerifySignatureRaw(key, sig, hash, hashlen);
    if (rc != PGPR_OK)
	goto exit;

    /* now check the meta information of the signature */
    if ((sig->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
	uint32_t now = pgprCurrentTime();
	if (now < sig->time) {
	    if (lints)
		pgprAddLint(sig, lints, PGPR_ERROR_SIGNATURE_FROM_FUTURE);
	    rc = PGPR_ERROR_SIGNATURE_FROM_FUTURE;
	} else if (sig->sig_expire < now - sig->time) {
	    if (lints)
		pgprAddLint(sig, lints, PGPR_ERROR_SIGNATURE_EXPIRED);
	    rc = PGPR_ERROR_SIGNATURE_EXPIRED;
	}
	if (rc != PGPR_OK)
	    goto exit;
    }
    /* now check the meta information of the key */
    if (key->revoked) {
	rc = key->revoked == 2 ? PGPR_ERROR_PRIMARY_REVOKED : PGPR_ERROR_KEY_REVOKED;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if ((key->saved & PGPRITEM_SAVED_VALID) == 0) {
	rc = PGPR_ERROR_KEY_NOT_VALID;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if (key->tag == PGPRTAG_PUBLIC_KEY && (key->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0 && (key->key_flags & 0x02) == 0) {
	rc = PGPR_ERROR_KEY_NO_SIGNING;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if (key->tag == PGPRTAG_PUBLIC_SUBKEY && ((key->saved & PGPRITEM_SAVED_KEY_FLAGS) == 0 || (key->key_flags & 0x02) == 0)) {
	rc = PGPR_ERROR_KEY_NO_SIGNING;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if (key->time > sig->time) {
	rc = PGPR_ERROR_KEY_CREATED_AFTER_SIG;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if ((key->saved & PGPRITEM_SAVED_KEY_EXPIRE) != 0 && key->key_expire && key->key_expire < sig->time - key->time) {
	rc = PGPR_ERROR_KEY_EXPIRED;
	if (lints)
	    pgprAddLint(key, lints, rc);
    }
exit:
    return rc;
}

pgprRC pgprVerifySignatureNoKey(pgprItem sig, const uint8_t *hash, size_t hashlen, char **lints)
{
    if (lints)
        *lints = NULL;
    if (!sig || sig->tag != PGPRTAG_SIGNATURE || (sig->sigtype != PGPRSIGTYPE_BINARY && sig->sigtype != PGPRSIGTYPE_TEXT && sig->sigtype != PGPRSIGTYPE_STANDALONE))
	return PGPR_ERROR_BAD_SIGNATURE;
    if (hash) {
	if (hashlen == 0 || hashlen != pgprDigestLength(sig->hash_algo))
	    return PGPR_ERROR_INTERNAL;
	/* Compare leading 16 bits of digest for a quick check. */
	if (memcmp(hash, sig->signhash16, 2) != 0)
	    return PGPR_ERROR_SIGNATURE_VERIFICATION;
    }
    /* now check the meta information of the signature */
    if ((sig->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
	uint32_t now = pgprCurrentTime();
	if (now < sig->time) {
	    if (lints)
		pgprAddLint(sig, lints, PGPR_ERROR_SIGNATURE_FROM_FUTURE);
	    return PGPR_ERROR_SIGNATURE_FROM_FUTURE;
	} else if (sig->sig_expire < now - sig->time) {
	    if (lints)
		pgprAddLint(sig, lints, PGPR_ERROR_SIGNATURE_EXPIRED);
	    return PGPR_ERROR_SIGNATURE_EXPIRED;
	}
    }
    return PGPR_OK;
}

