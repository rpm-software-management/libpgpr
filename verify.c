#include <stdarg.h>
#include <string.h>

#include "pgpr_internal.h"

pgprRC pgprVerifySignatureRaw(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen)
{
    /* make sure the parameters are correct and the pubkey algo matches */
    if (sig == NULL || sig->tag != PGPRTAG_SIGNATURE)
	// are these really internal errors and not rather usage errors / bad
	// parameters?
	return PGPR_ERROR_INTERNAL;
    if (key == NULL || (key->tag != PGPRTAG_PUBLIC_KEY && key->tag != PGPRTAG_PUBLIC_SUBKEY))
	return PGPR_ERROR_INTERNAL;
    if (hash == NULL || hashlen == 0 || hashlen != pgprDigestLength(sig->hash_algo))
	return PGPR_ERROR_INTERNAL;
    if (sig->pubkey_algo != key->pubkey_algo)
	return PGPR_ERROR_BAD_SIGNATURE;
    /* Compare leading 16 bits of digest for a quick check. */
    // on `hashlen < 2` this will access out of bounds memory.
    // this is unlikely due to the `pgprDigestLength()` restriction above. An
    // `assert()` could still be useful to avoid any unexpected situations.
    if (memcmp(hash, sig->signhash16, 2) != 0)
	return PGPR_ERROR_BAD_SIGNATURE;
    if (key->version < 4)
	return PGPR_ERROR_UNSUPPORTED_VERSION;
    if (key->version == 6 && sig->version != 6)
	return PGPR_ERROR_BAD_SIGNATURE;
    if (sig->pubkey_algo == PGPRPUBKEYALGO_MLDSA65_ED25519 || sig->pubkey_algo == PGPRPUBKEYALGO_MLDSA87_ED448) {
	if (sig->version < 6 || hashlen < 32)
	    return PGPR_ERROR_REJECTED_SIGNATURE;
    }
    return pgprAlgVerify(sig->alg, key->alg, hash, hashlen, sig->hash_algo);
}

pgprRC pgprVerifySignature(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen, char **lints)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */

    // `lints` sounds like this could accumulate multiple messages, but indeed
    // only one message is ever stored there, older ones are possible
    // overwritten.
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
	    // since `pgprAddLint` already returns if `lints == NULL` you
	    // could simply rely on this property and avoid all these `if
	    // (lints)` statements which create a lot of noise.
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
	// magic literal int values in `revoked` are hard to read, adding an
	// `enum` here would really be helpful.
	rc = key->revoked == 2 ? PGPR_ERROR_PRIMARY_REVOKED : PGPR_ERROR_KEY_REVOKED;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if ((key->saved & PGPRITEM_SAVED_VALID) == 0) {
	rc = PGPR_ERROR_KEY_NOT_VALID;
	if (lints)
	    pgprAddLint(key, lints, rc);
	// so what is the 0x02 constant supposed to mean here?
    } else if (key->tag == PGPRTAG_PUBLIC_KEY && (key->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0 && (key->key_flags & 0x02) == 0) {
	rc = PGPR_ERROR_KEY_NO_SIGNING;
	if (lints)
	    pgprAddLint(key, lints, rc);
	// a macro for checking flags in `key->saved` might increase
	// readability quite a bit and also reduce the likeliness for hard to
	// spot logic errors
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
	    return PGPR_ERROR_BAD_SIGNATURE;
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

