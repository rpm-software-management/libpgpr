/*
 * Routines that work on unarmored pgp packets
 */

#include <string.h>

#include "pgpr.h"
#include "pgpr_internal.h"

/*
 * PGP packet decoding
 *
 * Note that we reject indefinite length/partial bodies and lengths >= 16 MByte
 * right away so that we do not have to worry about integer overflows.
 */

/** \ingroup pgpr
 * Decode length in old format packet headers.
 * @param s		pointer to packet (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		packet header length, 0 on error
 */
static inline size_t pgprOldLen(const uint8_t *s, size_t slen, size_t * lenp)
{
    size_t dlen, lenlen;

    if (slen < 2)
	return 0;
    lenlen = 1 << (s[0] & 0x3);
    /* Reject indefinite length packets and check bounds */
    if (lenlen == 8 || slen < lenlen + 1)
	return 0;
    if (lenlen == 1)
	dlen = s[1];
    else if (lenlen == 2)
	dlen = s[1] << 8 | s[2];
    else if (lenlen == 4 && s[1] == 0)
	dlen = s[2] << 16 | s[3] << 8 | s[4];
    else
	return 0;
    if (slen - (1 + lenlen) < dlen)
	return 0;
    *lenp = dlen;
    return lenlen + 1;
}

/** \ingroup pgpr
 * Decode length from 1, 2, or 5 octet body length encoding, used in
 * new format packet headers.
 * Partial body lengths are (intentionally) not supported.
 * @param s		pointer to packet (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		packet header length, 0 on error
 */
static inline size_t pgprNewLen(const uint8_t *s, size_t slen, size_t *lenp)
{
    size_t dlen, hlen;

    if (slen > 1 && s[1] < 192) {
	hlen = 2;
	dlen = s[1];
    } else if (slen > 3 && s[1] < 224) {
	hlen = 3;
	dlen = (((s[1]) - 192) << 8) + s[2] + 192;
    } else if (slen > 6 && s[1] == 255 && s[2] == 0) {
	hlen = 6;
	dlen = s[3] << 16 | s[4] << 8 | s[5];
    } else {
	return 0;
    }
    if (slen - hlen < dlen)
	return 0;
    *lenp = dlen;
    return hlen;
}

pgprRC pgprDecodePkt(const uint8_t *p, size_t plen, pgprPkt *pkt)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET; /* assume failure */

    /* Valid PGP packet header must always have two or more bytes in it */
    if (p && plen >= 2 && p[0] & 0x80) {
	size_t hlen;

	if (p[0] & 0x40) {
	    /* New format packet, body length encoding in second byte */
	    hlen = pgprNewLen(p, plen, &pkt->blen);
	    pkt->tag = (p[0] & 0x3f);
	} else {
	    /* Old format packet */
	    hlen = pgprOldLen(p, plen, &pkt->blen);
	    pkt->tag = (p[0] >> 2) & 0xf;
	}

	/* Does the packet header and its body fit in our boundaries? */
	if (hlen && (hlen + pkt->blen <= plen)) {
	    pkt->head = p;
	    pkt->body = pkt->head + hlen;
	    rc = PGPR_OK;
	}
    }
    return rc;
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
    rc = pgprParseSig(&pkt, item);
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
    rc = pgprParseKeyFp(&pkt, &key);
    if (rc == PGPR_OK && !(key.saved & PGPRITEM_SAVED_ID))
	rc = PGPR_ERROR_INTERNAL;
    if (rc == PGPR_OK)
	memcpy(keyid, key.keyid, sizeof(key.keyid));
    return rc;
}

pgprRC pgprPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fp_len, int *fp_version)
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
    rc = pgprParseKeyFp(&pkt, &key);
    if (rc == PGPR_OK && !(key.saved & PGPRITEM_SAVED_FP))
        rc = PGPR_ERROR_INTERNAL;
    if (rc == PGPR_OK) {
	*fp_len = key.fp_len;
	*fp = pgprMemdup(key.fp, key.fp_len);
	if (fp_version)
	    *fp_version = key.fp_version;
    }
    return rc;
}

