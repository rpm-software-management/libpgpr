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
	pgprAlgFree(item->alg);
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
    rc = pgprParseSig(pkt.tag, pkt.body, pkt.blen, item);
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

pgprRC pgprPubkeyParse(const uint8_t * pkts, size_t pktlen, pgprItem * ret, char **lints)
{
    pgprItem key = NULL;
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
    key = pgprItemNew(pkt.tag);
    rc = pgprParseTransferablePubkey(pkts, pktlen, key);
exit:
    if (ret && rc == PGPR_OK)
	*ret = key;
    else {
	if (lints)
	    pgprAddLint(key, lints, rc);
	pgprItemFree(key);
    }
    return rc;
}

pgprRC pgprPubkeyParseSubkeys(const uint8_t *pkts, size_t pktlen,
			pgprItem key, pgprItem **subkeys,
			int *subkeysCount)
{
    return pgprParseTransferablePubkeySubkeys(pkts, pktlen, key, subkeys, subkeysCount);
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
    struct pgprItem_s key;
    pgprRC rc;

    if (pgprDecodePkt(pkts, pktslen, &pkt))
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY && pkt.tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    memset(&key, 0, sizeof(key));
    key.tag = pkt.tag;
    rc = pgprParseKeyFp(pkt.tag, pkt.body, pkt.blen, &key);
    if (rc == PGPR_OK && !(key.saved & PGPRITEM_SAVED_ID))
	rc = PGPR_ERROR_INTERNAL;
    if (rc == PGPR_OK)
	memcpy(keyid, key.signid, sizeof(key.signid));
    return rc;
}

pgprRC pgprPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    pgprPkt pkt;
    struct pgprItem_s key;
    pgprRC rc;

    if (pgprDecodePkt(pkts, pktslen, &pkt))
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY && pkt.tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    memset(&key, 0, sizeof(key));
    key.tag = pkt.tag;
    rc = pgprParseKeyFp(pkt.tag, pkt.body, pkt.blen, &key);
    if (rc == PGPR_OK && !(key.saved & PGPRITEM_SAVED_FP))
        rc = PGPR_ERROR_INTERNAL;
    if (rc == PGPR_OK) {
	*fplen = key.fp_len;
	*fp = pgprMemdup(key.fp, key.fp_len);
    }
    return rc;
}

