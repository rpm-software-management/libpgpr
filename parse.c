/*
 * Routines to parse pgp key/signature packets into a pgprItem
 */

#include <string.h>

#include "pgpr_internal.h"

typedef struct pgprPktKeyV3_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t time[4];	/*!< time that the key was created. */
    uint8_t expdays[2]; /*!< time in days when the key expires */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgprPktKeyV3;

typedef struct pgprPktKeyV4_s {
    uint8_t version;	/*!< version number (4). */
    uint8_t time[4];	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgprPktKeyV4;

typedef struct pgprPktKeyV56_s {
    uint8_t version;	/*!< version number (5, 6). */
    uint8_t time[4];	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t pubkey_len[4];	/*!< public key material length. */
} * pgprPktKeyV56;

typedef struct pgprPktSigV3_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t hashlen;	/*!< length of following hashed material. MUST be 5. */
    uint8_t sigtype;	/*!< signature type. */
    uint8_t time[4];	/*!< time that the key was created. */
    pgprKeyID_t keyid;	/*!< key ID of signer. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t signhash16[2];	/*!< left 16 bits of signed hash value. */
} * pgprPktSigV3;

typedef struct pgprPktSigV456_s {
    uint8_t version;	/*!< version number (4, 5, 6). */
    uint8_t sigtype;	/*!< signature type. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t hashlen[2];	/*!< length of following hashed material (4 bytes for v6). */
} * pgprPktSigV456;


static inline unsigned int pgprGrab2(const uint8_t *s)
{
    return s[0] << 8 | s[1];
}

static inline unsigned int pgprGrab4(const uint8_t *s)
{
    return s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
}

static uint8_t curve_oids[] = {
    PGPRCURVE_NIST_P_256,	0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    PGPRCURVE_NIST_P_384,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    PGPRCURVE_NIST_P_521,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
    PGPRCURVE_BRAINPOOL_P256R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
    PGPRCURVE_BRAINPOOL_P384R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
    PGPRCURVE_BRAINPOOL_P512R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
    PGPRCURVE_ED25519,		0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
    PGPRCURVE_CURVE25519,	0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
    PGPRCURVE_ED25519,		0x03, 0x2b, 0x65, 0x70,		/* alternative oid */
    PGPRCURVE_CURVE25519,	0x03, 0x2b, 0x65, 0x6e,		/* alternative oid */
    PGPRCURVE_ED448,		0x03, 0x2b, 0x65, 0x71,
    PGPRCURVE_X448,		0x03, 0x2b, 0x65, 0x6f,
    0,
};

static int pgprCurveByOid(const uint8_t *p, int l)
{
    uint8_t *curve;
    for (curve = curve_oids; *curve; curve += 2 + curve[1])
        if (l == (int)curve[1] && !memcmp(p, curve + 2, l))
            return (int)curve[0];
    return 0;
}

/*
 * Key/Signature algorithm parameter handling
 */

static pgprRC pgprParseKeyParams(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc;
    const uint8_t *p;
    int curve = 0;

    if (item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_INTERNAL;
    /* We can't handle more than one key at a time */
    if (item->alg || !item->mpi_offset || item->mpi_offset > pkt->blen)
	return  PGPR_ERROR_INTERNAL;
    p = pkt->body + item->mpi_offset;
    if (item->pubkey_algo == PGPRPUBKEYALGO_EDDSA || item->pubkey_algo == PGPRPUBKEYALGO_ECDSA) {
	size_t plen = pkt->blen - item->mpi_offset;
	int len = plen > 0 ? p[0] : 0;
	if (len == 0 || len == 0xff || len + 1 > plen)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	curve = pgprCurveByOid(p + 1, len);
	if (!curve)
	    return PGPR_ERROR_UNSUPPORTED_CURVE;
	p += len + 1;
    }
    item->alg = pgprAlgNew();
    if (!item->alg)
	return PGPR_ERROR_NO_MEMORY;
    rc = pgprAlgSetupPubkey(item->alg, item->pubkey_algo, curve, p, pkt->body + pkt->blen);
    return rc;
}

pgprRC pgprParseSigParams(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc;
    if (item->tag != PGPRTAG_SIGNATURE)
	return PGPR_ERROR_INTERNAL;
    /* We can't handle more than one sig at a time */
    if (item->alg || !item->mpi_offset || item->mpi_offset > pkt->blen)
	return PGPR_ERROR_INTERNAL;
    item->alg = pgprAlgNew();
    if (!item->alg)
	return PGPR_ERROR_NO_MEMORY;
    rc = pgprAlgSetupSignature(item->alg, item->pubkey_algo, pkt->body + item->mpi_offset, pkt->body + pkt->blen);
    if (rc != PGPR_OK)
	item->alg = pgprAlgFree(item->alg);
    return rc;
}

/** \ingroup pgpr
 * Decode length from 1, 2, or 5 octet body length encoding, used in
 * signature subpackets. Note that this is slightly different from
 * the pgprNewLen function.
 * @param s		pointer to subpacket (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		subpacket header length (excluding type), 0 on error
 */
static inline size_t pgprSubPktLen(const uint8_t *s, size_t slen, size_t *lenp)
{
    size_t dlen, lenlen;

    if (slen > 0 && *s < 192) {
	lenlen = 1;
	dlen = *s;
    } else if (slen > 2 && *s < 255) {
	lenlen = 2;
	dlen = (((s[0]) - 192) << 8) + s[1] + 192;
    } else if (slen > 5 && *s == 255 && s[1] == 0) {
	lenlen = 5;
	dlen = s[2] << 16 | s[3] << 8 | s[4];
    } else {
	return 0;
    }
    if (slen - lenlen < dlen)
	return 0;
    *lenp = dlen;
    return lenlen;
}

static pgprRC pgprParseSigSubPkts(const uint8_t *h, size_t hlen, pgprItem item, int hashed)
{
    const uint8_t *p = h;

    while (hlen > 0) {
	size_t plen = 0, lenlen;
	int impl = 0;
	lenlen = pgprSubPktLen(p, hlen, &plen);
	if (lenlen == 0 || plen < 1 || lenlen + plen > hlen)
	    break;
	p += lenlen;
	hlen -= lenlen;

	switch (*p & ~PGPRSUBTYPE_CRITICAL) {
	case PGPRSUBTYPE_SIG_CREATE_TIME:
	    if (!hashed)
		break; /* RFC 4880 §5.2.3.4 creation time MUST be hashed */
	    if (plen - 1 != 4)
		break; /* other lengths not understood */
	    if (item->saved & PGPRITEM_SAVED_TIME)
		return PGPR_ERROR_DUPLICATE_DATA;
	    impl = 1;
	    item->time = pgprGrab4(p + 1);
	    item->saved |= PGPRITEM_SAVED_TIME;
	    break;

	case PGPRSUBTYPE_ISSUER_KEYID:
	    if (plen - 1 != sizeof(item->keyid))
		break; /* other lengths not understood */
	    impl = 1;
	    if (!(item->saved & PGPRITEM_SAVED_ID)) {
		memcpy(item->keyid, p + 1, sizeof(item->keyid));
		item->saved |= PGPRITEM_SAVED_ID;
	    }
	    break;

	case PGPRSUBTYPE_ISSUER_FINGERPRINT:
	    if (plen - 1 < 17)
		break;
	    impl = 1;
	    if (!(item->saved & PGPRITEM_SAVED_FP) && plen - 2 <= PGPR_MAX_FP_LENGTH) {
		if ((p[1] == 4 && plen - 1 == 21) || ((p[1] == 5 || p[1] == 6) && plen - 1 == 33)) {
		    memcpy(item->fp, p + 2, plen - 2);
		    item->fp_len = plen - 2;
		    item->fp_version = p[1];
		    item->saved |= PGPRITEM_SAVED_FP;
		}
	    }
	    if (p[1] == 4 && plen - 1 == 21 && !(item->saved & PGPRITEM_SAVED_ID)) {
		memcpy(item->keyid, p + plen - sizeof(item->keyid), sizeof(item->keyid));
		item->saved |= PGPRITEM_SAVED_ID;
	    }
	    if ((p[1] == 5 || p[1] == 6) && plen - 1 == 33 && !(item->saved & PGPRITEM_SAVED_ID)) {
		memcpy(item->keyid, p + 2, sizeof(item->keyid));
		item->saved |= PGPRITEM_SAVED_ID;
	    }
	    break;

	case PGPRSUBTYPE_KEY_FLAGS:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (item->saved & PGPRITEM_SAVED_KEY_FLAGS)
		return PGPR_ERROR_DUPLICATE_DATA;
	    impl = 1;
	    item->key_flags = plen >= 2 ? p[1] : 0;
	    item->saved |= PGPRITEM_SAVED_KEY_FLAGS;
	    break;

	case PGPRSUBTYPE_KEY_EXPIRE_TIME:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen - 1 != 4)
		break; /* other lengths not understood */
	    if (item->saved & PGPRITEM_SAVED_KEY_EXPIRE)
		return PGPR_ERROR_DUPLICATE_DATA;
	    impl = 1;
	    item->key_expire = pgprGrab4(p + 1);
	    item->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
	    break;

	case PGPRSUBTYPE_SIG_EXPIRE_TIME:
	    if (!hashed)
		break;	/* RFC 4880 §5.2.3.4 creation time MUST be hashed */
	    if (plen - 1 != 4)
		break;	/* other lengths not understood */
	    if (item->saved & PGPRITEM_SAVED_SIG_EXPIRE)
		return PGPR_ERROR_DUPLICATE_DATA;
	    impl = 1;
	    item->sig_expire = pgprGrab4(p + 1);
	    item->saved |= PGPRITEM_SAVED_SIG_EXPIRE;
	    break;

	case PGPRSUBTYPE_EMBEDDED_SIG:
	    if (item->sigtype != PGPRSIGTYPE_SUBKEY_BINDING)
		break;	/* do not bother for other types */
	    if (plen - 1 < 6)
		break;	/* obviously not a signature */
	    if (item->embedded_sig)
		break;	/* just store the first one. we may need to changed this to select the most recent. */
	    impl = 1;
	    item->embedded_sig_len = plen - 1;
	    item->embedded_sig = pgprMemdup(p + 1, plen - 1);
	    if (!item->embedded_sig)
		return PGPR_ERROR_NO_MEMORY;
	    break;

	case PGPRSUBTYPE_PRIMARY_USERID:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen - 1 != 1)
		break;	/* other lengths not understood */
	    impl = 1;
	    if (p[1])
		item->saved |= PGPRITEM_SAVED_PRIMARY;
	    break;

	default:
	    break;
	}

	if (!impl && (p[0] & PGPRSUBTYPE_CRITICAL))
	    return PGPR_ERROR_UNKNOWN_CRITICAL_PKT;

	p += plen;
	hlen -= plen;
    }

    if (hlen != 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    return PGPR_OK;
}

/* create the trailer used in v4/5/6 signatures */
static pgprRC create_sig_trailer(pgprItem item, const uint8_t *p, size_t plen)
{
    if (item->version == 4 || item->version == 6)
	item->hashlen = plen + 6;
    else if (item->version == 5)
	item->hashlen = plen + (item->sigtype == 0x00 || item->sigtype == 0x01 ? 6 : 0) + 10;
    else
	return PGPR_ERROR_UNSUPPORTED_VERSION;
    item->hash = pgprCalloc(1, item->hashlen);
    if (!item->hash)
	return PGPR_ERROR_NO_MEMORY;
    memcpy(item->hash, p, plen);
    if (item->version == 4 || item->version == 6) {
	uint8_t *trailer = item->hash + item->hashlen - 6;
	trailer[0] = item->version;
	trailer[1] = 0xff;
	trailer[2] = plen >> 24;
	trailer[3] = plen >> 16;
	trailer[4] = plen >> 8;
	trailer[5] = plen;
    } else if (item->version == 5) {
	uint8_t *trailer = item->hash + item->hashlen - 10;
	trailer[0] = 0x05;
	trailer[1] = 0xff;
	trailer[6] = plen >> 24;
	trailer[7] = plen >> 16;
	trailer[8] = plen >> 8;
	trailer[9] = plen;
    }
    return PGPR_OK;
}

static pgprRC create_sig_salt(pgprItem item, const uint8_t *salt, size_t saltlen)
{
    uint8_t *newhash = pgprRealloc(item->hash, item->hashlen + saltlen);
    if (!newhash)
	return PGPR_ERROR_NO_MEMORY;
    item->hash = newhash;
    memcpy(item->hash + item->hashlen, salt, saltlen);
    item->saltlen = saltlen;
    return PGPR_OK;
}

pgprRC pgprParseSigNoParams(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    const uint8_t * p;
    size_t plen;

    if (item->version || item->saved)
	return PGPR_ERROR_INTERNAL;
    if (item->tag != PGPRTAG_SIGNATURE || pkt->tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (pkt->blen == 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    item->version = pkt->body[0];

    switch (item->version) {
    case 3:
    {   pgprPktSigV3 v = (pgprPktSigV3)pkt->body;

	if (pkt->blen <= sizeof(*v) || v->hashlen != 5)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->hashlen = v->hashlen;
	item->sigtype = v->sigtype;
	item->hash = pgprMemdup(&v->sigtype, v->hashlen);
	if (!item->hash)
	    return PGPR_ERROR_NO_MEMORY;
	item->time = pgprGrab4(v->time);
	if (!item->time)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	memcpy(item->keyid, v->keyid, sizeof(item->keyid));
	item->saved = PGPRITEM_SAVED_TIME | PGPRITEM_SAVED_ID;
	item->pubkey_algo = v->pubkey_algo;
	item->hash_algo = v->hash_algo;
	memcpy(item->signhash16, v->signhash16, sizeof(item->signhash16));
	item->mpi_offset = sizeof(*v);
	rc = PGPR_OK;
    }	break;
    case 4:
    case 5:
    case 6:
    {   pgprPktSigV456 v = (pgprPktSigV456)pkt->body;
	const uint8_t *const hend = pkt->body + pkt->blen;
	int hashed;

	if (pkt->blen <= sizeof(*v))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->sigtype = v->sigtype;
	item->pubkey_algo = v->pubkey_algo;
	item->hash_algo = v->hash_algo;

	/* parse both the hashed and unhashed subpackets */
	p = &v->hashlen[0];
	for (hashed = 1; hashed >= 0; hashed--) {
	    if (item->version == 6) {
		if (p > hend || hend - p < 4)
		    return PGPR_ERROR_CORRUPT_PGP_PACKET;
		plen = pgprGrab4(p);
		p += 4;
	    } else {
		if (p > hend || hend - p < 2)
		    return PGPR_ERROR_CORRUPT_PGP_PACKET;
		plen = pgprGrab2(p);
		p += 2;
	    }
	    if (plen >= PGPR_MAX_OPENPGP_BYTES || hend - p < plen)
		return PGPR_ERROR_CORRUPT_PGP_PACKET;
	    if (hashed) {
		rc = create_sig_trailer(item, pkt->body, sizeof(*v) + (item->version == 6 ? 2 : 0) + plen);
		if (rc != PGPR_OK)
		    return rc;
	    }
	    rc = pgprParseSigSubPkts(p, plen, item, hashed);
	    if (rc != PGPR_OK)
		return rc;
	    p += plen;
	}

	if (!(item->saved & PGPRITEM_SAVED_TIME))
	    return PGPR_ERROR_NO_CREATION_TIME;	/* RFC 4880 §5.2.3.4 creation time MUST be present */
	if (!item->time)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;

	if (p > hend || hend - p < 2)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	memcpy(item->signhash16, p, sizeof(item->signhash16));
	p += 2;

	if (item->version == 6) {
	    int saltlen;
	    if (p > hend || hend - p < 1)
		return PGPR_ERROR_CORRUPT_PGP_PACKET;
	    saltlen = p[0];
	    if (saltlen) {
		if (hend - p < 1 + saltlen)
		    return PGPR_ERROR_CORRUPT_PGP_PACKET;
		rc = create_sig_salt(item, p + 1, saltlen);
		if (rc != PGPR_OK)
		    return rc;
	    }
	    p += 1 + saltlen;
	}

	if (p > hend)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->mpi_offset = p - pkt->body;
	rc = PGPR_OK;
    }	break;
    default:
	rc = PGPR_ERROR_UNSUPPORTED_VERSION;
	break;
    }
    return rc;
}

pgprRC pgprParseSig(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc = pgprParseSigNoParams(pkt, item);
    if (rc == PGPR_OK)
	rc = pgprParseSigParams(pkt, item);
    return rc;
}

static inline int pgprMpiLen(const uint8_t *p)
{
    int mpi_bits = (p[0] << 8) | p[1];
    return 2 + ((mpi_bits + 7) >> 3);
}

static pgprRC pgprParseKeyFp_V3(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc;
    pgprDigCtx ctx = NULL;
    uint8_t *out = NULL;
    size_t outlen = 0;
    const uint8_t *p = pkt->body;
    size_t blen = pkt->blen;
    int mpil1, mpil2;

    /* make sure this is a v3 rsa key */
    if (blen < sizeof(struct pgprPktKeyV3_s) + 4 + 8 || p[0] != 3 || p[7] != PGPRPUBKEYALGO_RSA)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    /* find the two rsa mpis */
    p += sizeof(struct pgprPktKeyV3_s);
    blen -= sizeof(struct pgprPktKeyV3_s);
    mpil1 = pgprMpiLen(p);
    if (mpil1 < 2 + 8 || blen < mpil1 + 2)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    mpil2 = pgprMpiLen(p + mpil1);
    if (mpil2 < 2 + 1 || blen !=  mpil1 + mpil2)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;

    rc = pgprDigestInit(PGPRHASHALGO_MD5, &ctx);
    if (rc != PGPR_OK)
	return rc;
    pgprDigestUpdate(ctx, p + 2, mpil1 - 2);
    pgprDigestUpdate(ctx, p + mpil1 + 2, mpil2 - 2);
    pgprDigestFinal(ctx, (void **)&out, &outlen);
    if (outlen != 16) {
	free(out);
	return PGPR_ERROR_INTERNAL;
    }
    memcpy(item->fp, out, outlen);
    item->fp_len = outlen;
    item->fp_version = 3;
    free(out);
    /* calculate the keyid from the modulus */
    memcpy(item->keyid, p + mpil1 - 8, 8);
    item->saved |= PGPRITEM_SAVED_FP | PGPRITEM_SAVED_ID;
    return PGPR_OK;
}

pgprRC pgprParseKeyFp(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc;
    pgprDigCtx ctx = NULL;
    uint8_t *out = NULL;
    size_t outlen = 0;
    int version;
    size_t blen = pkt->blen;

    if  ((item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY) || pkt->tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (blen == 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    version = pkt->body[0];

    if (version == 3)
	return pgprParseKeyFp_V3(pkt, item);
    if (version != 4 && version != 5 && version != 6)
	return PGPR_ERROR_UNSUPPORTED_VERSION;

    rc = pgprDigestInit(version == 4 ? PGPRHASHALGO_SHA1 : PGPRHASHALGO_SHA256, &ctx);
    if (rc != PGPR_OK)
	return rc;
    if (version == 4) {
	uint8_t in[3] = { 0x99, (blen >> 8), blen };
	pgprDigestUpdate(ctx, in, 3);
    } else {
	uint8_t in[5] = { version == 6 ? 0x9b : 0x9a, (blen >> 24), (blen >> 16), (blen >> 8), blen };
	pgprDigestUpdate(ctx, in, 5);
    }
    pgprDigestUpdate(ctx, pkt->body, blen);
    pgprDigestFinal(ctx, (void **)&out, &outlen);
    if (outlen != (version == 4 ? 20 : 32)) {
	free(out);
	return PGPR_ERROR_INTERNAL;
    }
    memcpy(item->fp, out, outlen);
    item->fp_len = outlen;
    item->fp_version = version;
    free(out);
    /* calculate the keyid from the fingerprint */
    if (version == 4)
	memcpy(item->keyid, (item->fp + (outlen - 8)), 8);
    else
	memcpy(item->keyid, item->fp, 8);
    item->saved |= PGPRITEM_SAVED_FP | PGPRITEM_SAVED_ID;
    return PGPR_OK;
}

pgprRC pgprParseKey(pgprPkt *pkt, pgprItem item)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if (item->version || item->saved)
	return PGPR_ERROR_INTERNAL;
    /* make sure that the item was initialized with the correct tag */
    if  ((item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY) || pkt->tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (pkt->blen == 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    item->version = pkt->body[0];

    switch (item->version) {
    case 3:
    {   pgprPktKeyV3 v = (pgprPktKeyV3)pkt->body;
	uint32_t expdays;

	if (pkt->blen <= sizeof(*v) || v->pubkey_algo != PGPRPUBKEYALGO_RSA)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->time = pgprGrab4(v->time);
	if (!item->time)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->saved |= PGPRITEM_SAVED_TIME;
	item->pubkey_algo = v->pubkey_algo;
	item->mpi_offset = sizeof(*v);
	expdays = pgprGrab2(v->expdays);
	if (expdays > 49710)
	    expdays = 49710;	/* 130 years */
	item->key_expire = expdays * 86400;
	item->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
	rc = PGPR_OK;
    }	break;
    case 4:
    {   pgprPktKeyV4 v = (pgprPktKeyV4)pkt->body;

	if (pkt->blen <= sizeof(*v))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->time = pgprGrab4(v->time);
	if (!item->time)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->saved |= PGPRITEM_SAVED_TIME;
	item->pubkey_algo = v->pubkey_algo;
	item->mpi_offset = sizeof(*v);
	rc = PGPR_OK;
    }	break;
    case 5:
    case 6:
    {   pgprPktKeyV56 v = (pgprPktKeyV56)pkt->body;
	uint32_t pubkey_len;
	if (pkt->blen <= sizeof(*v))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	pubkey_len = pgprGrab4(v->pubkey_len);
	if (pubkey_len > PGPR_MAX_OPENPGP_BYTES || pkt->blen != sizeof(*v) + pubkey_len)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->time = pgprGrab4(v->time);
	if (!item->time)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->saved |= PGPRITEM_SAVED_TIME;
	item->pubkey_algo = v->pubkey_algo;
	item->mpi_offset = sizeof(*v);
	rc = PGPR_OK;
    }	break;
    default:
	rc = PGPR_ERROR_UNSUPPORTED_VERSION;
	break;
    }

    /* read mpi data if there was no error */
    if (rc == PGPR_OK)
	rc = pgprParseKeyParams(pkt, item);

    /* calculate the key fingerprint and key id if we could parse the key */
    if (rc == PGPR_OK)
	rc = pgprParseKeyFp(pkt, item);
    return rc;
}

pgprRC pgprParseUserID(pgprPkt *pkt, pgprItem item)
{
    if (item->tag != PGPRTAG_PUBLIC_KEY || pkt->tag != PGPRTAG_USER_ID)
	return PGPR_ERROR_INTERNAL;
    free(item->userid);
    item->userid = pgprMalloc(pkt->blen + 1);
    if (!item->userid)
	return PGPR_ERROR_NO_MEMORY;
    memcpy(item->userid, pkt->body, pkt->blen);
    item->userid[pkt->blen] = 0;
    return PGPR_OK;
}

