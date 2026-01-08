#include <string.h>
#include <stdarg.h>

#include "pgpr.h"
#include "pgpr_internal.h"

pgprDigParams pgprDigParamsNew(uint8_t tag)
{
    pgprDigParams digp = pgprCalloc(1, sizeof(*digp));
    digp->tag = tag;
    return digp;
}

pgprDigParams pgprDigParamsFree(pgprDigParams digp)
{
    if (digp) {
	pgprDigAlgFree(digp->alg);
	free(digp->userid);
	free(digp->hash);
	free(digp->embedded_sig);
	memset(digp, 0, sizeof(*digp));
	free(digp);
    }
    return NULL;
}

/* compare data of two signatures or keys */
int pgprDigParamsCmp(pgprDigParams p1, pgprDigParams p2)
{
    int rc = 1; /* assume different, eg if either is NULL */
    if (p1 && p2) {
	/* XXX Should we compare something else too? */
	if (p1->tag != p2->tag)
	    goto exit;
	if (p1->hash_algo != p2->hash_algo)
	    goto exit;
	if (p1->pubkey_algo != p2->pubkey_algo)
	    goto exit;
	if (p1->version != p2->version)
	    goto exit;
	if (p1->sigtype != p2->sigtype)
	    goto exit;
	if (memcmp(p1->signid, p2->signid, sizeof(p1->signid)) != 0)
	    goto exit;
	if (p1->userid && p2->userid && strcmp(p1->userid, p2->userid) != 0)
	    goto exit;

	/* Parameters match ... at least for our purposes */
	rc = 0;
    }
exit:
    return rc;
}

int pgprDigParamsTag(pgprDigParams digp)
{
    return digp ? digp->tag : -1;
}

int pgprDigParamsSignatureType(pgprDigParams digp)
{
    return digp && digp->tag == PGPRTAG_SIGNATURE ? digp->sigtype : -1;
}

int pgprDigParamsPubkeyAlgo(pgprDigParams digp)
{
    return digp ? digp->pubkey_algo : -1;
}

int pgprDigParamsHashAlgo(pgprDigParams digp)
{
    return digp ? digp->hash_algo : -1;
}

int pgprDigParamsCurve(pgprDigParams digp)
{
    return digp && digp->alg ? digp->alg->curve : -1;
}

const uint8_t *pgprDigParamsKeyID(pgprDigParams digp)
{
    return digp->signid;
}

const uint8_t *pgprDigParamsKeyFingerprint(pgprDigParams digp, size_t *fp_len, int *fp_version)
{
    if (fp_len)
	*fp_len = digp->fp_len;
    if (fp_version)
	*fp_version = digp->fp_len ? digp->fp_version : 0;
    return digp->fp_len ? digp->fp : NULL;
}

const char *pgprDigParamsUserID(pgprDigParams digp)
{
    return digp->userid;
}

int pgprDigParamsVersion(pgprDigParams digp)
{
    return digp->version;
}

uint32_t pgprDigParamsCreationTime(pgprDigParams digp)
{
    return digp->time;
}

uint32_t pgprDigParamsModificationTime(pgprDigParams digp)
{
    return digp->tag == PGPRTAG_PUBLIC_KEY ? digp->key_mtime : 0;
}

const uint8_t *pgprDigParamsHashHeader(pgprDigParams digp, size_t *headerlen)
{
    if (digp->tag != PGPRTAG_SIGNATURE) {
	*headerlen = 0;
	return NULL;
    }
    *headerlen = digp->saltlen;
    return digp->saltlen ? digp->hash + digp->hashlen : NULL;
}

const uint8_t *pgprDigParamsHashTrailer(pgprDigParams digp, size_t *trailerlen)
{
    if (digp->tag != PGPRTAG_SIGNATURE) {
	*trailerlen = 0;
	return NULL;
    }
    *trailerlen = digp->hashlen;
    return digp->hash;
}


pgprRC pgprSignatureParse(const uint8_t * pkts, size_t pktlen, pgprDigParams * ret, char **lints)
{
    pgprDigParams digp = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;	/* assume failure */
    pgprPkt pkt;

    if (lints)
        *lints = NULL;
    if (pktlen > PGPR_MAX_OPENPGP_BYTES || pgprDecodePkt(pkts, pktlen, &pkt))
	goto exit;

    if (pkt.tag != PGPRTAG_SIGNATURE) {
	rc = PGPR_ERROR_UNEXPECTED_PGP_PACKET;
	goto exit;
    }

    digp = pgprDigParamsNew(pkt.tag);
    rc = pgprPrtSig(pkt.tag, pkt.body, pkt.blen, digp);
    /* treat trailing data as error */
    if (rc == PGPR_OK && (pkt.body - pkt.head) + pkt.blen != pktlen)
	rc = PGPR_ERROR_CORRUPT_PGP_PACKET;

exit:
    if (ret && rc == PGPR_OK)
	*ret = digp;
    else {
	if (lints)
	    pgprAddLint(digp, lints, rc);
	pgprDigParamsFree(digp);
    }
    return rc;
}

pgprRC pgprVerifySignature(pgprDigParams key, pgprDigParams sig, const uint8_t *hash, size_t hashlen, char **lints)
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
    if ((sig->saved & PGPRDIG_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
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
    } else if ((key->saved & PGPRDIG_SAVED_VALID) == 0) {
	rc = PGPR_ERROR_KEY_NOT_VALID;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if (key->tag == PGPRTAG_PUBLIC_SUBKEY && ((key->saved & PGPRDIG_SAVED_KEY_FLAGS) == 0 || (key->key_flags & 0x02) == 0)) {
	rc = PGPR_ERROR_KEY_NO_SIGNING;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if (key->time > sig->time) {
	rc = PGPR_ERROR_KEY_CREATED_AFTER_SIG;
	if (lints)
	    pgprAddLint(key, lints, rc);
    } else if ((key->saved & PGPRDIG_SAVED_KEY_EXPIRE) != 0 && key->key_expire && key->key_expire < sig->time - key->time) {
	rc = PGPR_ERROR_KEY_EXPIRED;
	if (lints)
	    pgprAddLint(key, lints, rc);
    }
exit:
    return rc;
}

pgprRC pgprVerifySignatureNoKey(pgprDigParams sig, const uint8_t *hash, size_t hashlen, char **lints)
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
    if ((sig->saved & PGPRDIG_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
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

pgprRC pgprPubkeyParse(const uint8_t * pkts, size_t pktlen, pgprDigParams * ret, char **lints)
{
    pgprDigParams digp = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;	/* assume failure */
    pgprPkt pkt;

    if (lints)
        *lints = NULL;
    if (pktlen > PGPR_MAX_OPENPGP_BYTES || pgprDecodePkt(pkts, pktlen, &pkt))
	goto exit;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY) {
	rc = PGPR_ERROR_UNEXPECTED_PGP_PACKET;
	goto exit;
    }

    /* use specialized transferable pubkey implementation */
    digp = pgprDigParamsNew(pkt.tag);
    rc = pgprPrtTransferablePubkey(pkts, pktlen, digp);
exit:
    if (ret && rc == PGPR_OK)
	*ret = digp;
    else {
	if (lints)
	    pgprAddLint(digp, lints, rc);
	pgprDigParamsFree(digp);
    }
    return rc;
}

pgprRC pgprPubkeyParseSubkeys(const uint8_t *pkts, size_t pktlen,
			pgprDigParams mainkey, pgprDigParams **subkeys,
			int *subkeysCount)
{
    return pgprPrtTransferablePubkeySubkeys(pkts, pktlen, mainkey, subkeys, subkeysCount);
}

pgprRC pgprPubkeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    pgprPkt pkt;

    while (p < pend) {
	if (pgprDecodePkt(p, (pend - p), &pkt))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	if (pkt.tag == PGPRTAG_PUBLIC_KEY && pkts != p) {
	    pktslen = p - pkts;
	    break;
	}
	p += (pkt.body - pkt.head) + pkt.blen;
    }
    *certlen = pktslen;
    return PGPR_OK;
}

pgprRC pgprPubkeyKeyID(const uint8_t * pkts, size_t pktslen, pgprKeyID_t keyid)
{
    pgprPkt pkt;

    if (pgprDecodePkt(pkts, pktslen, &pkt))
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY && pkt.tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    return pgprGetKeyID(pkt.body, pkt.blen, keyid);
}

pgprRC pgprPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    pgprPkt pkt;

    if (pgprDecodePkt(pkts, pktslen, &pkt))
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY && pkt.tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    return pgprGetKeyFingerprint(pkt.body, pkt.blen, fp, fplen);
}

pgprRC pgprPubkeyMerge(const uint8_t *pkts1, size_t pkts1len, const uint8_t *pkts2, size_t pkts2len, uint8_t **pktsm, size_t *pktsmlen)
{
    return pgprMergeKeys(pkts1, pkts1len, pkts2, pkts2len, pktsm, pktsmlen);
}

