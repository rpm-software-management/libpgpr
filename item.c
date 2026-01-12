#include <string.h>
#include <stdarg.h>

#include "pgpr.h"
#include "pgpr_internal.h"

pgprItem pgprItemNew(uint8_t tag)
{
    pgprItem item = pgprCalloc(1, sizeof(*item));
    item->tag = tag;
    return item;
}

pgprItem pgprItemFree(pgprItem item)
{
    if (item) {
	pgprDigAlgFree(item->alg);
	free(item->userid);
	free(item->hash);
	free(item->embedded_sig);
	memset(item, 0, sizeof(*item));
	free(item);
    }
    return NULL;
}

/* compare data of two signatures or keys */
int pgprItemCmp(pgprItem p1, pgprItem p2)
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

int pgprItemTag(pgprItem item)
{
    return item ? item->tag : -1;
}

int pgprItemSignatureType(pgprItem item)
{
    return item && item->tag == PGPRTAG_SIGNATURE ? item->sigtype : -1;
}

int pgprItemPubkeyAlgo(pgprItem item)
{
    return item ? item->pubkey_algo : -1;
}

int pgprItemHashAlgo(pgprItem item)
{
    return item ? item->hash_algo : -1;
}

int pgprItemPubkeyAlgoInfo(pgprItem item)
{
    return item && item->alg ? item->alg->info: -1;
}

const uint8_t *pgprItemKeyID(pgprItem item)
{
    return item->signid;
}

const uint8_t *pgprItemKeyFingerprint(pgprItem item, size_t *fp_len, int *fp_version)
{
    if (fp_len)
	*fp_len = item->fp_len;
    if (fp_version)
	*fp_version = item->fp_len ? item->fp_version : 0;
    return item->fp_len ? item->fp : NULL;
}

const char *pgprItemUserID(pgprItem item)
{
    return item->userid;
}

int pgprItemVersion(pgprItem item)
{
    return item->version;
}

uint32_t pgprItemCreationTime(pgprItem item)
{
    return item->time;
}

uint32_t pgprItemModificationTime(pgprItem item)
{
    return item->tag == PGPRTAG_PUBLIC_KEY ? item->key_mtime : 0;
}

const uint8_t *pgprItemHashHeader(pgprItem item, size_t *headerlen)
{
    if (item->tag != PGPRTAG_SIGNATURE) {
	*headerlen = 0;
	return NULL;
    }
    *headerlen = item->saltlen;
    return item->saltlen ? item->hash + item->hashlen : NULL;
}

const uint8_t *pgprItemHashTrailer(pgprItem item, size_t *trailerlen)
{
    if (item->tag != PGPRTAG_SIGNATURE) {
	*trailerlen = 0;
	return NULL;
    }
    *trailerlen = item->hashlen;
    return item->hash;
}


pgprRC pgprSignatureParse(const uint8_t * pkts, size_t pktlen, pgprItem * ret, char **lints)
{
    pgprItem item = NULL;
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

    item = pgprItemNew(pkt.tag);
    rc = pgprPrtSig(pkt.tag, pkt.body, pkt.blen, item);
    /* treat trailing data as error */
    if (rc == PGPR_OK && (pkt.body - pkt.head) + pkt.blen != pktlen)
	rc = PGPR_ERROR_CORRUPT_PGP_PACKET;

exit:
    if (ret && rc == PGPR_OK)
	*ret = item;
    else {
	if (lints)
	    pgprAddLint(item, lints, rc);
	pgprItemFree(item);
    }
    return rc;
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

pgprRC pgprPubkeyParse(const uint8_t * pkts, size_t pktlen, pgprItem * ret, char **lints)
{
    pgprItem item = NULL;
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
    item = pgprItemNew(pkt.tag);
    rc = pgprPrtTransferablePubkey(pkts, pktlen, item);
exit:
    if (ret && rc == PGPR_OK)
	*ret = item;
    else {
	if (lints)
	    pgprAddLint(item, lints, rc);
	pgprItemFree(item);
    }
    return rc;
}

pgprRC pgprPubkeyParseSubkeys(const uint8_t *pkts, size_t pktlen,
			pgprItem mainkey, pgprItem **subkeys,
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

