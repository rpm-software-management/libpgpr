/*
 * Routines to parse pgp key/signature packets
 */

#include <string.h>

#include "pgpr.h"
#include "pgpr_internal.h"

typedef uint8_t pgprTime_t[4];

typedef struct pgprPktKeyV4_s {
    uint8_t version;	/*!< version number (4). */
    pgprTime_t time;	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgprPktKeyV4;

typedef struct pgprPktKeyV56_s {
    uint8_t version;	/*!< version number (4). */
    pgprTime_t time;	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t pubkey_len[4];	/*!< public key material length. */
} * pgprPktKeyV56;

typedef struct pgprPktSigV3_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t hashlen;	/*!< length of following hashed material. MUST be 5. */
    uint8_t sigtype;	/*!< signature type. */
    pgprTime_t time;	/*!< 4 byte creation time. */
    pgprKeyID_t signid;	/*!< key ID of signer. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t signhash16[2];	/*!< left 16 bits of signed hash value. */
} * pgprPktSigV3;

typedef struct pgprPktSigV456_s {
    uint8_t version;	/*!< version number (4). */
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

/** \ingroup pgpr
 * Decode length from 1, 2, or 5 octet body length encoding, used in
 * V4 signature subpackets. Note that this is slightly different from
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


/*
 * Key/Signature algorithm parameter handling
 */

static pgprAlg pgprAlgNew(void)
{
    pgprAlg alg;
    alg = pgprCalloc(1, sizeof(*alg));
    alg->mpis = -1;
    return alg;
}

pgprAlg pgprAlgFree(pgprAlg alg)
{
    if (alg) {
        if (alg->free)
            alg->free(alg);
        free(alg);
    }
    return NULL;
}

static inline int pgprMpiLen(const uint8_t *p)
{
    int mpi_bits = (p[0] << 8) | p[1];
    return 2 + ((mpi_bits + 7) >> 3);
}

static pgprRC pgprAlgProcessMpis(pgprAlg alg, const int mpis,
		       const uint8_t *p, const uint8_t *const pend)
{
    int i = 0;
    if (mpis == 0) {
	return alg->setmpi ? alg->setmpi(alg, -1, p, pend - p) : PGPR_ERROR_UNSUPPORTED_ALGORITHM;
    }
    for (; i < mpis && pend - p >= 2; i++) {
	int mpil = pgprMpiLen(p);
        pgprRC rc;
	if (mpil < 2 || pend - p < mpil)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	rc = alg->setmpi ? alg->setmpi(alg, i, p, mpil) : PGPR_ERROR_UNSUPPORTED_ALGORITHM;
	if (rc != PGPR_OK)
	    return rc;
	p += mpil;
    }

    /* Does the size and number of MPI's match our expectations? */
    return p == pend && i == mpis ? PGPR_OK : PGPR_ERROR_CORRUPT_PGP_PACKET;
}


/*
 * Key/Signature parameter parsing
 */

static uint8_t curve_oids[] = {
    PGPRCURVE_NIST_P_256,	0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    PGPRCURVE_NIST_P_384,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    PGPRCURVE_NIST_P_521,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
    PGPRCURVE_BRAINPOOL_P256R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
    PGPRCURVE_BRAINPOOL_P384R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
    PGPRCURVE_BRAINPOOL_P512R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
    PGPRCURVE_ED25519,		0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
    PGPRCURVE_CURVE25519,	0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
    PGPRCURVE_ED25519_ALT,	0x03, 0x2b, 0x65, 0x70,
    PGPRCURVE_CURVE25519_ALT,	0x03, 0x2b, 0x65, 0x6e,
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

static pgprRC pgprPrtKeyParams(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    pgprRC rc;
    const uint8_t *p;
    int curve = 0;

    if (item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY)
	return PGPR_ERROR_INTERNAL;
    /* We can't handle more than one key at a time */
    if (item->alg || !item->mpi_offset || item->mpi_offset > hlen)
	return  PGPR_ERROR_INTERNAL;
    p = h + item->mpi_offset;
    if (item->pubkey_algo == PGPRPUBKEYALGO_EDDSA || item->pubkey_algo == PGPRPUBKEYALGO_ECDSA) {
	size_t plen = hlen - item->mpi_offset;
	int len = plen > 0 ? p[0] : 0;
	if (len == 0 || len == 0xff || len + 1 > plen)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	curve = pgprCurveByOid(p + 1, len);
	if (!curve)
	    return PGPR_ERROR_UNSUPPORTED_CURVE;
	p += len + 1;
    }
    item->alg = pgprAlgNew();
    rc = pgprAlgInitPubkey(item->alg, item->pubkey_algo, curve);
    if (rc == PGPR_OK)
	rc = pgprAlgProcessMpis(item->alg, item->alg->mpis, p, h + hlen);
    return rc;
}

pgprRC pgprPrtSigParams(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    pgprRC rc;
    if (item->tag != PGPRTAG_SIGNATURE)
	return PGPR_ERROR_INTERNAL;
    /* We can't handle more than one sig at a time */
    if (item->alg || !item->mpi_offset || item->mpi_offset > hlen)
	return PGPR_ERROR_INTERNAL;
    item->alg = pgprAlgNew();
    rc = pgprAlgInitSignature(item->alg, item->pubkey_algo);
    if (rc == PGPR_OK)
	rc = pgprAlgProcessMpis(item->alg, item->alg->mpis, h + item->mpi_offset, h + hlen);
    if (rc != PGPR_OK) {
	pgprAlgFree(item->alg);
	item->alg = NULL;
    }
    return rc;
}



/*
 *  PGP packet data extraction
 */

static pgprRC pgprPrtSubType(const uint8_t *h, size_t hlen, pgprItem item, int hashed)
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
	    if (plen - 1 != sizeof(item->signid))
		break; /* other lengths not understood */
	    impl = 1;
	    if (!(item->saved & PGPRITEM_SAVED_ID)) {
		memcpy(item->signid, p + 1, sizeof(item->signid));
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
		memcpy(item->signid, p + plen - sizeof(item->signid), sizeof(item->signid));
		item->saved |= PGPRITEM_SAVED_ID;
	    }
	    if ((p[1] == 5 || p[1] == 6) && plen - 1 == 33 && !(item->saved & PGPRITEM_SAVED_ID)) {
		memcpy(item->signid, p + 2, sizeof(item->signid));
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

pgprRC pgprPrtSigNoParams(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    const uint8_t * p;
    size_t plen;

    if (item->version || item->saved || item->tag != PGPRTAG_SIGNATURE || tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (hlen == 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    item->version = h[0];

    switch (item->version) {
    case 3:
    {   pgprPktSigV3 v = (pgprPktSigV3)h;

	if (hlen <= sizeof(*v) || v->hashlen != 5)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->hashlen = v->hashlen;
	item->sigtype = v->sigtype;
	item->hash = pgprMemdup(&v->sigtype, v->hashlen);
	item->time = pgprGrab4(v->time);
	memcpy(item->signid, v->signid, sizeof(item->signid));
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
    {   pgprPktSigV456 v = (pgprPktSigV456)h;
	const uint8_t *const hend = h + hlen;
	uint8_t *trailer;
	int hashed;

	if (hlen <= sizeof(*v))
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
		if (plen >= PGPR_MAX_OPENPGP_BYTES)
		    return PGPR_ERROR_CORRUPT_PGP_PACKET;
		p += 4;
	    } else {
		if (p > hend || hend - p < 2)
		    return PGPR_ERROR_CORRUPT_PGP_PACKET;
		plen = pgprGrab2(p);
		p += 2;
	    }
	    if (hend - p < plen)
		return PGPR_ERROR_CORRUPT_PGP_PACKET;
	    if (hashed) {
		/* add bytes for the trailer */
		if (item->version == 4)
		    item->hashlen = sizeof(*v) + plen + 6;
		else if (item->version == 5)
		    item->hashlen = sizeof(*v) + plen + (item->sigtype == 0x00 || item->sigtype == 0x01 ? 6 : 0) + 10;
		else if (item->version == 6)
		    item->hashlen = sizeof(*v) + 2 + plen + 6;		/* len is 4 bytes */
		item->hash = pgprCalloc(1, item->hashlen);
		memcpy(item->hash, v, sizeof(*v) + plen + (item->version == 6 ? 2 : 0));
	    }
	    rc = pgprPrtSubType(p, plen, item, hashed);
	    if (rc != PGPR_OK)
		return rc;
	    p += plen;
	}

	if (!(item->saved & PGPRITEM_SAVED_TIME))
	    return PGPR_ERROR_NO_CREATION_TIME;	/* RFC 4880 §5.2.3.4 creation time MUST be present */

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
		item->hash = pgprRealloc(item->hash, item->hashlen + saltlen);
		memcpy(item->hash + item->hashlen, p + 1, saltlen);
		item->saltlen = saltlen;
	    }
	    p += 1 + saltlen;
	}

	if (p > hend)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->mpi_offset = p - h;
	if (item->version == 4 || item->version == 6) {
	    trailer = item->hash + item->hashlen - 6;
	    trailer[0] = item->version;
	    trailer[1] = 0xff;
	    trailer[2] = (item->hashlen - 6) >> 24;
	    trailer[3] = (item->hashlen - 6) >> 16;
	    trailer[4] = (item->hashlen - 6) >> 8;
	    trailer[5] = (item->hashlen - 6);
	} else if (item->version == 5) {
	    uint32_t len = item->hashlen - 10 - (item->sigtype == 0x00 || item->sigtype == 0x01 ? 6 : 0);
	    trailer = item->hash + item->hashlen - 10;
	    trailer[0] = 0x05;
	    trailer[1] = 0xff;
	    trailer[6] = len >> 24;
	    trailer[7] = len >> 16;
	    trailer[8] = len >> 8;
	    trailer[9] = len;
	}
	rc = PGPR_OK;
    }	break;
    default:
	rc = PGPR_ERROR_UNSUPPORTED_VERSION;
	break;
    }
    return rc;
}

pgprRC pgprPrtSig(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    pgprRC rc = pgprPrtSigNoParams(tag, h, hlen, item);
    if (rc == PGPR_OK)
	rc = pgprPrtSigParams(tag, h, hlen, item);
    return rc;
}

/* fingerprint calculation helper */
static pgprRC gen_key_fingerprint(const uint8_t *d, size_t dlen, const uint8_t *h, size_t hlen, int hashalgo, uint8_t *fp, size_t fplen)
{
    uint8_t *out = NULL;
    size_t outlen = 0;
    pgprRC rc = PGPR_ERROR_INTERNAL;
    pgprDigCtx ctx = pgprDigestInit(hashalgo);

    (void)pgprDigestUpdate(ctx, d, dlen);
    (void)pgprDigestUpdate(ctx, h, hlen);
    (void)pgprDigestFinal(ctx, (void **)&out, &outlen);
    if (outlen == fplen) {
	memcpy(fp, out, outlen);
	rc = PGPR_OK;
    }
    free(out);
    return rc;
}

pgprRC pgprPrtKeyFp(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    uint8_t *fp = NULL;
    size_t fplen = 0;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if  ((item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY) || tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (hlen == 0)
	return rc;

    /* We only permit V4/5/6 keys, V3 keys are long long since deprecated */
    switch (h[0]) {
    case 4:
      {
	uint8_t in[3] = { 0x99, (hlen >> 8), hlen };
	rc = gen_key_fingerprint(in, 3, h, hlen, PGPRHASHALGO_SHA1, item->fp, 20);
	if (rc == PGPR_OK)
	    item->fp_len = 20;
      }	break;
    case 5:
    case 6:
      {
	uint8_t in[5] = { h[0] == 6 ? 0x9b : 0x9a, (hlen >> 24), (hlen >> 16), (hlen >> 8), hlen };
	rc = gen_key_fingerprint(in, 5, h, hlen, PGPRHASHALGO_SHA256, item->fp, 32);
	if (rc == PGPR_OK)
	    item->fp_len = 32;
      }	break;
    default:
	rc = PGPR_ERROR_UNSUPPORTED_VERSION;
	break;
    }
    if (rc == PGPR_OK && item->fp_len <= 8)
	rc = PGPR_ERROR_INTERNAL;
    if (rc == PGPR_OK) {
	item->fp_version = h[0];
	/* calculate the keyid from the fp */
	if (h[0] == 4)
	    memcpy(item->signid, (item->fp + (item->fp_len - 8)), 8);
	else
	    memcpy(item->signid, item->fp, 8);
	item->saved |= PGPRITEM_SAVED_FP | PGPRITEM_SAVED_ID;
    }
    free(fp);
    return rc;
}

pgprRC pgprPrtKey(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if (item->version || item->saved)
	return PGPR_ERROR_INTERNAL;
    /* make sure that the item was initialized with the correct tag */
    if  ((item->tag != PGPRTAG_PUBLIC_KEY && item->tag != PGPRTAG_PUBLIC_SUBKEY) || tag != item->tag)
	return PGPR_ERROR_INTERNAL;

    if (hlen == 0)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    item->version = h[0];

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (item->version) {
    case 4:
    {   pgprPktKeyV4 v = (pgprPktKeyV4)h;

	if (hlen <= sizeof(*v))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->time = pgprGrab4(v->time);
	item->saved |= PGPRITEM_SAVED_TIME;
	item->pubkey_algo = v->pubkey_algo;
	item->mpi_offset = sizeof(*v);
	rc = PGPR_OK;
    }	break;
    case 5:
    case 6:
    {   pgprPktKeyV56 v = (pgprPktKeyV56)h;
	uint32_t pubkey_len;
	if (hlen <= sizeof(*v))
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	pubkey_len = pgprGrab4(v->pubkey_len);
	if (pubkey_len > PGPR_MAX_OPENPGP_BYTES || hlen != sizeof(*v) + pubkey_len)
	    return PGPR_ERROR_CORRUPT_PGP_PACKET;
	item->time = pgprGrab4(v->time);
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
	rc = pgprPrtKeyParams(tag, h, hlen, item);

    /* calculate the key fingerprint and key id if we could parse the key */
    if (rc == PGPR_OK)
	rc = pgprPrtKeyFp(tag, h, hlen, item);
    return rc;
}

pgprRC pgprPrtUserID(pgprTag tag, const uint8_t *h, size_t hlen, pgprItem item)
{
    if (item->tag != PGPRTAG_PUBLIC_KEY || tag != PGPRTAG_USER_ID)
	return PGPR_ERROR_INTERNAL;
    free(item->userid);
    item->userid = memcpy(pgprMalloc(hlen + 1), h, hlen);
    item->userid[hlen] = 0;
    return PGPR_OK;
}

