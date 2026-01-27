#include <openssl/evp.h>
#if OPENSSL_VERSION_MAJOR >= 3
# include <openssl/params.h>
#endif
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "pgpr_internal.h"

static const EVP_MD *getEVPMD(int hashalgo)
{
    switch (hashalgo) {

    case PGPRHASHALGO_MD5:
        return EVP_md5();
    case PGPRHASHALGO_SHA1:
        return EVP_sha1();
    case PGPRHASHALGO_SHA256:
        return EVP_sha256();
    case PGPRHASHALGO_SHA384:
        return EVP_sha384();
    case PGPRHASHALGO_SHA512:
        return EVP_sha512();
    case PGPRHASHALGO_SHA224:
        return EVP_sha224();
#if OPENSSL_VERSION_MAJOR >= 3 || (OPENSSL_VERSION_MAJOR == 1 && OPENSSL_VERSION_MINOR == 1 && OPENSSL_VERSION_PATCH >= 1)
    case PGPRHASHALGO_SHA3_256:
	return EVP_sha3_256();
    case PGPRHASHALGO_SHA3_512:
	return EVP_sha3_512();
#endif
    default:
        return EVP_md_null();
    }
}

static pgprRC check_out_of_mem(pgprRC rc)
{
    if (rc != PGPR_OK && rc != PGPR_ERROR_NO_MEMORY) {
	unsigned long err;
	while ((err = ERR_get_error()) != 0) {
	    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE) {
		pgprOOM(0, 0);
		return PGPR_ERROR_NO_MEMORY;
	    }
	}
    }
    return rc;
}

pgprRC pgprSupportedAlgo(int algo, int curve)
{
    pgprRC rc;
    switch (algo) {
    case PGPRPUBKEYALGO_RSA:
    case PGPRPUBKEYALGO_DSA:
	return PGPR_OK;
    case PGPRPUBKEYALGO_ECDSA:
	if (curve == PGPRCURVE_NIST_P_256 || curve == PGPRCURVE_NIST_P_384 || curve == PGPRCURVE_NIST_P_521)
	    return PGPR_OK;
	return curve ? PGPR_ERROR_UNSUPPORTED_CURVE : PGPR_OK;
#ifdef EVP_PKEY_ED25519
    case PGPRPUBKEYALGO_EDDSA:
    case PGPRPUBKEYALGO_ED25519:
    case PGPRPUBKEYALGO_ED448:
	if (algo == PGPRPUBKEYALGO_ED25519 || curve == PGPRCURVE_ED25519)
	    return PGPR_OK;
	if (algo == PGPRPUBKEYALGO_ED448)
	    curve = PGPRCURVE_ED448;
#ifdef EVP_PKEY_ED448
	if (curve == PGPRCURVE_ED448)
	    return PGPR_OK;
#endif
	return curve ? PGPR_ERROR_UNSUPPORTED_CURVE : PGPR_OK;
#endif
#if defined(EVP_PKEY_ML_DSA_65)
    case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
	return PGPR_OK;
#endif
#if defined(EVP_PKEY_ML_DSA_87)
    case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
	return PGPR_OK;
#endif
    case PGPRPUBKEYALGO_MLDSA65_ED25519:
	rc = pgprSupportedAlgo(PGPRPUBKEYALGO_INTERNAL_MLDSA65, 0);
	return rc == PGPR_OK ? pgprSupportedAlgo(PGPRPUBKEYALGO_ED25519, 0) : rc;
    case PGPRPUBKEYALGO_MLDSA87_ED448:
	rc = pgprSupportedAlgo(PGPRPUBKEYALGO_INTERNAL_MLDSA87, 0);
	return rc == PGPR_OK ? pgprSupportedAlgo(PGPRPUBKEYALGO_ED448, 0) : rc;
    default:
        break;
    }
    return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
}

/*********************** pkey construction *******************************/

#if OPENSSL_VERSION_MAJOR >= 3

static EVP_PKEY *construct_pkey_from_param(int id, OSSL_PARAM *params)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	pkey = NULL;
    if (ctx)
	EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static OSSL_PARAM create_bn_param(char *key, BIGNUM *bn)
{
    unsigned char *buf;
    int sz = bn ? BN_num_bytes(bn) : -1;
    if (sz < 0 || BN_is_negative(bn)) {
	OSSL_PARAM param = OSSL_PARAM_END;
	return param;
    }
    if (sz == 0)
	sz = 1;
    buf = CRYPTO_malloc(sz, NULL, 0);
    if (!buf) {
	ERR_new();
	ERR_set_error(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE, NULL);
	OSSL_PARAM param = OSSL_PARAM_END;
	return param;
    }
    BN_bn2nativepad(bn, buf, sz);
    OSSL_PARAM param = OSSL_PARAM_BN(key, buf, sz);
    return param;
}

static void free_bn_param(OSSL_PARAM *param)
{
    if (param->data)
	CRYPTO_free(param->data, NULL, 0);
}

#endif

/****************************** RSA **************************************/

/* Key */

struct pgprAlgKeyRSA_s {
    size_t nbytes; /* Size of modulus */

    BIGNUM *n; /* Common Modulus */
    BIGNUM *e; /* Public Exponent */
    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructRSASigningKey(struct pgprAlgKeyRSA_s *key)
{
    if (key->evp_pkey)
        return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PARAM params[] = {
	create_bn_param("n", key->n),
	create_bn_param("e", key->e),
	OSSL_PARAM_END
    };
    key->evp_pkey = construct_pkey_from_param(EVP_PKEY_RSA, params);
    free_bn_param(params + 0);
    free_bn_param(params + 1);
    if (key->evp_pkey) {
	/* pkey construction was successful, we can free the BNs */
	BN_clear_free(key->n);
	BN_clear_free(key->e);
	key->n = key->e = NULL;
    }
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the RSA key */
    RSA *rsa = RSA_new();
    if (!rsa)
	return 0;

    if (RSA_set0_key(rsa, key->n, key->e, NULL) != 1)
	goto exit;
    key->n = key->e = NULL;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the RSA key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_RSA(key->evp_pkey, rsa) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }

    return 1;
exit:
    RSA_free(rsa);
    return 0;
#endif
}

static pgprRC pgprSetKeyMpiRSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;	/* assume failure */
    struct pgprAlgKeyRSA_s *key = ka->data;

    if (!key)
        key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;

    if (key->evp_pkey)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    switch (num) {
    case 0:
        /* Modulus */
        if (key->n)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
	key->nbytes = mlen - 2;
	ka->info = 8 * (((mlen - 2) + 7) & ~7);
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGPR */
        key->n = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->n)
	    rc = PGPR_OK;
        break;

    case 1:
        /* Exponent */
        if (key->e)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGPR */
        key->e = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->e)
	    rc = PGPR_OK;
        break;
    }
    return check_out_of_mem(rc);
}

static void pgprFreeKeyRSA(pgprAlg ka)
{
    struct pgprAlgKeyRSA_s *key = ka->data;
    if (key) {
        if (key->evp_pkey)
            EVP_PKEY_free(key->evp_pkey);
	if (key->n)
            BN_clear_free(key->n);
	if (key->e)
            BN_clear_free(key->e);
        free(key);
    }
}

/* Signature */

struct pgprAlgSigRSA_s {
    BIGNUM *bn;
};

static pgprRC pgprSetSigMpiRSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;	/* assume failure */
    struct pgprAlgSigRSA_s *sig = sa->data;

    if (!sig)
        sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    ERR_clear_error();
    switch (num) {
    case 0:
        if (sig->bn)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per signature */
        /* Create a BIGNUM from the signature pointer.
           Note: this assumes big-endian data as required
           by the PGPR multiprecision integer format
           (RFC4880, Section 3.2)
           This will be useful later, as we can
           retrieve this value with appropriate
           padding. */
        sig->bn = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (sig->bn)
	    rc = PGPR_OK;
        break;
    }
    return check_out_of_mem(rc);
}

static void pgprFreeSigRSA(pgprAlg sa)
{
    struct pgprAlgSigRSA_s *sig = sa->data;
    if (sig) {
	if (sig->bn)
	    BN_clear_free(sig->bn);
        free(sa->data);
    }
}

static pgprRC pgprVerifySigRSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprAlgSigRSA_s *sig = sa->data;
    struct pgprAlgKeyRSA_s *key = ka->data;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    void *padded_sig = NULL;
    int pkey_len;

    if (!key || !sig)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    if (!constructRSASigningKey(key)) {
        rc = PGPR_ERROR_REJECTED_PUBKEY;
	goto done;
    }
    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
	goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
	goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
	goto done;

    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, getEVPMD(hash_algo)) <= 0)
	goto done;

    pkey_len = EVP_PKEY_size(key->evp_pkey);
    padded_sig = pgprCalloc(1, pkey_len);
    if (!padded_sig) {
	rc = PGPR_ERROR_NO_MEMORY;
	goto done;
    }
    if (BN_bn2binpad(sig->bn, padded_sig, pkey_len) <= 0)
	goto done;

    if (EVP_PKEY_verify(pkey_ctx, padded_sig, pkey_len, hash, hashlen) == 1)
        rc = PGPR_OK;		/* Success */

done:
    rc = check_out_of_mem(rc);
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(padded_sig);
    return rc;
}

static pgprRC pgprInitSigRSA(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiRSA;
    sa->free = pgprFreeSigRSA;
    sa->verify = pgprVerifySigRSA;
    sa->mpis = 1;
    return PGPR_OK;
}

static pgprRC pgprInitKeyRSA(pgprAlg ka)
{
    ka->setmpi = pgprSetKeyMpiRSA;
    ka->free = pgprFreeKeyRSA;
    ka->mpis = 2;
    return PGPR_OK;
}


/****************************** DSA ***************************************/
/* Key */

struct pgprAlgKeyDSA_s {
    BIGNUM *p; /* Prime */
    BIGNUM *q; /* Subprime */
    BIGNUM *g; /* Base */
    BIGNUM *y; /* Public Key */

    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructDSASigningKey(struct pgprAlgKeyDSA_s *key)
{
    if (key->evp_pkey)
        return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PARAM params[] = {
	create_bn_param("p", key->p),
	create_bn_param("q", key->q),
	create_bn_param("g", key->g),
	create_bn_param("pub", key->y),
	OSSL_PARAM_END
    };
    key->evp_pkey = construct_pkey_from_param(EVP_PKEY_DSA, params);
    free_bn_param(params + 0);
    free_bn_param(params + 1);
    free_bn_param(params + 2);
    free_bn_param(params + 3);
    if (key->evp_pkey) {
	/* pkey construction was successful, we can free the BNs */
	BN_clear_free(key->p);
	BN_clear_free(key->q);
	BN_clear_free(key->g);
	BN_clear_free(key->y);
	key->p = key->q = key->g = key->y = NULL;
    }
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the DSA key */
    DSA *dsa = DSA_new();
    if (!dsa)
	return 0;
    if (DSA_set0_pqg(dsa, key->p, key->q, key->g) != 1)
        goto exit;
    key->p = key->q = key->g = NULL;
    if (DSA_set0_key(dsa, key->y, NULL) != 1)
        goto exit;
    key->y = NULL;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the DSA key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_DSA(key->evp_pkey, dsa) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }
    return 1;

exit:
    DSA_free(dsa);
    return 0;
#endif
}


static pgprRC pgprSetKeyMpiDSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;	/* assume failure */
    struct pgprAlgKeyDSA_s *key = ka->data;

    if (!key)
        key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;

    ERR_clear_error();
    switch (num) {
    case 0:
        /* Prime */
        if (key->p)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
	ka->info = 8 * (((mlen - 2) + 7) & ~7);
        key->p = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->p)
	    rc = PGPR_OK;
        break;
    case 1:
        /* Subprime */
        if (key->q)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
        key->q = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->q)
	    rc = PGPR_OK;
        break;
    case 2:
        /* Base */
        if (key->g)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
        key->g = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->g)
	    rc = PGPR_OK;
        break;
    case 3:
        /* Public */
        if (key->y)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per key */
        key->y = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->y)
	    rc = PGPR_OK;
        break;
    }
    return check_out_of_mem(rc);
}

static void pgprFreeKeyDSA(pgprAlg ka)
{
    struct pgprAlgKeyDSA_s *key = ka->data;
    if (key) {
        if (key->evp_pkey)
            EVP_PKEY_free(key->evp_pkey);
	if (key->p)
            BN_clear_free(key->p);
	if (key->q)
            BN_clear_free(key->q);
	if (key->g)
            BN_clear_free(key->g);
	if (key->y)
            BN_clear_free(key->y);
        free(key);
    }
}

/* Signature */

struct pgprAlgSigDSA_s {
    unsigned char *r;
    int rlen;
    unsigned char *s;
    int slen;
};

static void add_asn1_tag(unsigned char *p, int tag, int len)
{
    *p++ = tag;
    if (len >= 256) {
	*p++ = 130;
	*p++ = len >> 8;
    } else if (len > 128) {
	*p++ = 129;
    }
    *p++ = len;
}

/* create the DER encoding of the SEQUENCE of two INTEGERs r and s */
/* used by DSA and ECDSA */
static unsigned char *constructDSASignature(unsigned char *r, int rlen, unsigned char *s, int slen, size_t *siglenp)
{
    int len1 = rlen + (!rlen || (*r & 0x80) != 0 ? 1 : 0), hlen1 = len1 < 128 ? 2 : len1 < 256 ? 3 : 4;
    int len2 = slen + (!slen || (*s & 0x80) != 0 ? 1 : 0), hlen2 = len2 < 128 ? 2 : len2 < 256 ? 3 : 4;
    int len3 = hlen1 + len1 + hlen2 + len2, hlen3 = len3 < 128 ? 2 : len3 < 256 ? 3 : 4;
    unsigned char *buf;
    if (rlen < 0 || rlen >= 65534 || slen < 0 || slen >= 65534 || len3 > 65535)
	return 0;	/* should never happen as pgpr's MPIs have a length < 8192 */
    buf = pgprMalloc(hlen3 + len3);
    if (!buf)
	return 0;
    add_asn1_tag(buf, 0x30, len3);
    add_asn1_tag(buf + hlen3, 0x02, len1);
    buf[hlen3 + hlen1] = 0;		/* zero first byte of the integer */
    memcpy(buf + hlen3 + hlen1 + len1 - rlen, r, rlen);
    add_asn1_tag(buf + hlen3 + hlen1 + len1, 0x02, len2);
    buf[hlen3 + len3 - len2] = 0;	/* zero first byte of the integer */
    memcpy(buf + hlen3 + len3 - slen, s, slen);
    *siglenp = hlen3 + len3;
    return buf;
}

static pgprRC pgprSetSigMpiDSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;	/* assume failure */
    struct pgprAlgSigDSA_s *sig = sa->data;

    if (!sig)
        sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    ERR_clear_error();
    switch (num) {
    case 0:
        if (sig->r)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per signature */
	sig->r = pgprMemdup(p + 2, mlen - 2);
	if (!sig->r)
	    return PGPR_ERROR_NO_MEMORY;
        sig->rlen = mlen - 2;
        rc = PGPR_OK;
        break;
    case 1:
        if (sig->s)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per signature */
	sig->s = pgprMemdup(p + 2, mlen - 2);
	if (!sig->s)
	    return PGPR_ERROR_NO_MEMORY;
        sig->slen = mlen - 2;
        rc = PGPR_OK;
        break;
    }
    return check_out_of_mem(rc);
}

static void pgprFreeSigDSA(pgprAlg sa)
{
    struct pgprAlgSigDSA_s *sig = sa->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(sa->data);
}

static pgprRC pgprVerifySigDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprAlgSigDSA_s *sig = sa->data;
    struct pgprAlgKeyDSA_s *key = ka->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!key || !sig)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    if (!constructDSASigningKey(key)) {
	rc = PGPR_ERROR_REJECTED_PUBKEY;
	goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig) {
	rc = PGPR_ERROR_NO_MEMORY;
	goto done;
    }
    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
	goto done;
    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
	goto done;
    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
	rc = PGPR_OK;		/* Success */

done:
    rc = check_out_of_mem(rc);
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

static pgprRC pgprInitSigDSA(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiDSA;
    sa->free = pgprFreeSigDSA;
    sa->verify = pgprVerifySigDSA;
    sa->mpis = 2;
    return PGPR_OK;
}

static pgprRC pgprInitKeyDSA(pgprAlg ka)
{
    ka->setmpi = pgprSetKeyMpiDSA;
    ka->free = pgprFreeKeyDSA;
    ka->mpis = 4;
    return PGPR_OK;
}

/****************************** ECDSA ***************************************/

struct pgprAlgKeyECDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructECDSASigningKey(struct pgprAlgKeyECDSA_s *key, int curve)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    if (curve == PGPRCURVE_NIST_P_256) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-256", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    } else if (curve == PGPRCURVE_NIST_P_384) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-384", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    } else if (curve == PGPRCURVE_NIST_P_521) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-521", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    }
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the EC key */
    EC_KEY *ec = NULL;
    if (curve == PGPRCURVE_NIST_P_256)
	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    else if (curve == PGPRCURVE_NIST_P_384)
	ec = EC_KEY_new_by_curve_name(NID_secp384r1);
    else if (curve == PGPRCURVE_NIST_P_521)
	ec = EC_KEY_new_by_curve_name(NID_secp521r1);
    if (!ec)
	return 0;

    if (EC_KEY_oct2key(ec, key->q, key->qlen, NULL) != 1)
        goto exit;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the EC key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_EC_KEY(key->evp_pkey, ec) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }
    return 1;

exit:
    EC_KEY_free(ec);
    return 0;
#endif
}

static pgprRC pgprSetKeyMpiECDSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyECDSA_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;	/* assume failure */

    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;

    if (num == 0 && mlen > 3 && p[2] == 0x04) {
	if (key->q)
	    return PGPR_ERROR_INTERNAL;
	key->q = pgprMemdup(p + 2, mlen - 2);
	if (!key->q)
	    return PGPR_ERROR_NO_MEMORY;
	key->qlen = mlen - 2;
	rc = PGPR_OK;
    }
    return rc;
}

static void pgprFreeKeyECDSA(pgprAlg ka)
{
    struct pgprAlgKeyECDSA_s *key = ka->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgprAlgSigECDSA_s {
    unsigned char *r;
    int rlen;
    unsigned char *s;
    int slen;
};

static pgprRC pgprSetSigMpiECDSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;	/* assume failure */
    struct pgprAlgSigECDSA_s *sig = sa->data;

    if (!sig)
        sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    switch (num) {
    case 0:
        if (sig->r)
            return PGPR_ERROR_INTERNAL;	/* This should only ever happen once per signature */
	sig->r = pgprMemdup(p + 2, mlen - 2);
	if (!sig->r)
	    return PGPR_ERROR_NO_MEMORY;
	sig->rlen = mlen - 2;
        rc = PGPR_OK;
        break;
    case 1:
        if (sig->s)
            return 1;	/* This should only ever happen once per signature */
	sig->s = pgprMemdup(p + 2, mlen - 2);
	if (!sig->s)
	    return PGPR_ERROR_NO_MEMORY;
	sig->slen = mlen - 2;
        rc = PGPR_OK;
        break;
    }

    return rc;
}

static void pgprFreeSigECDSA(pgprAlg sa)
{
    struct pgprAlgSigECDSA_s *sig = sa->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(sa->data);
}

static pgprRC pgprVerifySigECDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprAlgSigECDSA_s *sig = sa->data;
    struct pgprAlgKeyECDSA_s *key = ka->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!key || !sig)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    if (!constructECDSASigningKey(key, ka->curve)) {
	rc = PGPR_ERROR_REJECTED_PUBKEY;
	goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig) {
	rc = PGPR_ERROR_NO_MEMORY;
	goto done;
    }
    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
	goto done;
    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
	goto done;
    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
	rc = PGPR_OK;		/* Success */

done:
    rc = check_out_of_mem(rc);
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

static pgprRC pgprInitSigECDSA(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiECDSA;
    sa->free = pgprFreeSigECDSA;
    sa->verify = pgprVerifySigECDSA;
    sa->mpis = 2;
    return PGPR_OK;
}

static pgprRC pgprInitKeyECDSA(pgprAlg ka)
{
    ka->setmpi = pgprSetKeyMpiECDSA;
    ka->free = pgprFreeKeyECDSA;
    ka->mpis = 1;
    ka->info = ka->curve;
    return PGPR_OK;
}

/****************************** EDDSA ***************************************/

#ifdef EVP_PKEY_ED25519

struct pgprAlgKeyEDDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructEDDSASigningKey(struct pgprAlgKeyEDDSA_s *key, int curve)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */
#ifdef EVP_PKEY_ED25519
    if (curve == PGPRCURVE_ED25519)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->q, key->qlen);
#endif
#ifdef EVP_PKEY_ED448
    if (curve == PGPRCURVE_ED448)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, key->q, key->qlen);
#endif
    return key->evp_pkey ? 1 : 0;
}

static pgprRC pgprSetKeyMpiEDDSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyEDDSA_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;

    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;

    if (num == -1) {
	if (key->q)
	    return PGPR_ERROR_INTERNAL;
	if (ka->curve == PGPRCURVE_ED25519 && mlen == 32) {
	    key->q = pgprMemdup(p, 32);
	    if (!key->q)
		return PGPR_ERROR_NO_MEMORY;
	    key->qlen = 32;
	    rc = PGPR_OK;
	} else if (ka->curve == PGPRCURVE_ED448 && mlen == 57) {
	    key->q = pgprMemdup(p, 57);
	    if (!key->q)
		return PGPR_ERROR_NO_MEMORY;
	    key->qlen = 57;
	    rc = PGPR_OK;
	}
	return rc;
    }
    if (ka->curve == PGPRCURVE_ED25519 && num == 0 && !key->q && mlen > 3 && p[2] == 0x40) {
	rc = PGPR_OK;
	key->q = pgprMemdup(p + 3, mlen - 3);	/* we do not copy the leading 0x40 */
	if (!key->q)
	    return PGPR_ERROR_NO_MEMORY;
	key->qlen = mlen - 3;
    }
    if (ka->curve == PGPRCURVE_ED448 && num == 0 && !key->q && mlen > 3 && mlen <= 59) {
	key->q = pgprCalloc(1, 57);
	if (!key->q)
	    return PGPR_ERROR_NO_MEMORY;
	key->qlen = 57;
	memcpy(key->q + 57 - (mlen - 2), p + 2, mlen - 2);
	rc = PGPR_OK;
    }
    return rc;
}

static void pgprFreeKeyEDDSA(pgprAlg ka)
{
    struct pgprAlgKeyEDDSA_s *key = ka->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgprAlgSigEDDSA_s {
    unsigned char sig[57 + 57];
    int not_ed25519;
};

static pgprRC pgprSetSigMpiEDDSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigEDDSA_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;

    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    if (num == -1) {
	if (sa->algo == PGPRPUBKEYALGO_ED25519 && mlen == 2 * 32) {
	    memcpy(sig->sig + (57 - 32), p, 32);
	    memcpy(sig->sig + (2 * 57 - 32), p + 32, 32);
	    rc = PGPR_OK;
	} else if (sa->algo == PGPRPUBKEYALGO_ED448 && mlen == 2 * 57) {
	    memcpy(sig->sig, p, 2 * 57);
	    rc = PGPR_OK;
	}
	return rc;
    }
    mlen -= 2;	/* skip mpi len */
    if ((num != 0 && num != 1) || mlen <= 0 || mlen > 57)
      return rc;
    memcpy(sig->sig + 57 * num + 57 - mlen, p + 2, mlen);
    if (mlen > 32)
	sig->not_ed25519 = 1;
    return PGPR_OK;
}

static void pgprFreeSigEDDSA(pgprAlg sa)
{
    struct pgprAlgSigEDDSA_s *sig = sa->data;
    if (sig)
	free(sig);
}

static pgprRC pgprVerifySigEDDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprAlgSigEDDSA_s *sig = sa->data;
    struct pgprAlgKeyEDDSA_s *key = ka->data;
    EVP_MD_CTX *md_ctx = NULL;

    if (!key || !sig)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    if (!constructEDDSASigningKey(key, ka->curve)) {
	rc = PGPR_ERROR_REJECTED_PUBKEY;
	goto done;
    }

    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_md_null(), NULL, key->evp_pkey) != 1)
	goto done;
    if (ka->curve == PGPRCURVE_ED25519 && !sig->not_ed25519) {
	unsigned char esig[64];
	memcpy(esig, sig->sig + 57 - 32, 32);
	memcpy(esig + 32, sig->sig + 2 * 57 - 32, 32);
	if (EVP_DigestVerify(md_ctx, esig, 64, hash, hashlen) == 1)
	    rc = PGPR_OK;		/* Success */
    }
    if (ka->curve == PGPRCURVE_ED448) {
	if (EVP_DigestVerify(md_ctx, sig->sig, 114, hash, hashlen) == 1)
	    rc = PGPR_OK;		/* Success */
    }
done:
    rc = check_out_of_mem(rc);
    if (md_ctx)
	EVP_MD_CTX_free(md_ctx);
    return rc;
}

static pgprRC pgprInitSigEDDSA(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiEDDSA;
    sa->free = pgprFreeSigEDDSA;
    sa->verify = pgprVerifySigEDDSA;
    sa->mpis = sa->algo == PGPRPUBKEYALGO_EDDSA ? 2 : 0;
    return PGPR_OK;
}

static pgprRC pgprInitKeyEDDSA(pgprAlg ka)
{
    /* fixup the curve */
    if (ka->algo == PGPRPUBKEYALGO_ED25519)
	ka->curve = PGPRCURVE_ED25519;
    if (ka->algo == PGPRPUBKEYALGO_ED448)
	ka->curve = PGPRCURVE_ED448;
    ka->setmpi = pgprSetKeyMpiEDDSA;
    ka->free = pgprFreeKeyEDDSA;
    ka->mpis = ka->algo == PGPRPUBKEYALGO_EDDSA ? 1 : 0;
    ka->info = ka->algo == PGPRPUBKEYALGO_EDDSA ? ka->curve : 0;
    return PGPR_OK;
}

#endif


/****************************** ML-DSA ***************************************/

#if defined(EVP_PKEY_ML_DSA_65) || defined(EVP_PKEY_ML_DSA_87)

struct pgprAlgKeyMLDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char key[2592];
    int keyl;
};

static int constructMLDSASigningKey(struct pgprAlgKeyMLDSA_s *key, int algo)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */
#ifdef EVP_PKEY_ML_DSA_65
    if (algo == PGPRPUBKEYALGO_INTERNAL_MLDSA65)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_65, NULL, key->key, key->keyl);
#endif
#ifdef EVP_PKEY_ML_DSA_87
    if (algo == PGPRPUBKEYALGO_INTERNAL_MLDSA87)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_87, NULL, key->key, key->keyl);
#endif
    return key->evp_pkey ? 1 : 0;
}

static void pgprFreeKeyMLDSA(pgprAlg ka)
{
    struct pgprAlgKeyMLDSA_s *key = ka->data;
    if (key) {
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

static pgprRC pgprSetKeyMpiMLDSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyMLDSA_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;
    int keyl = 0;

    if (num != -1)
	return rc;
    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;
    switch (ka->algo) {
	case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
	    keyl = 1952;
	    break;
	case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
	    keyl = 2592;
	    break;
	default:
	    break;
    }
    if (keyl && keyl <= sizeof(key->key) && mlen == keyl) {
	memcpy(key->key, p, keyl);
	key->keyl = keyl;
	rc = PGPR_OK;
    }
    return rc;
}

struct pgprAlgSigMLDSA_s {
    unsigned char sig[4627];
    int sigl;
};

static pgprRC pgprSetSigMpiMLDSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigMLDSA_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;
    int sigl = 0;

    if (num != -1)
	return rc;
    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    switch (sa->algo) {
	case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
	    sigl = 3309;
	    break;
	case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
	    sigl = 4627;
	    break;
	default:
	    break;
    }
    if (sigl && sigl <= sizeof(sig->sig) && mlen == sigl) {
	memcpy(sig->sig, p, sigl);
	sig->sigl = sigl;
	rc = PGPR_OK;
    }
    return rc;
}

static void pgprFreeSigMLDSA(pgprAlg sa)
{
    struct pgprAlgSigMLDSA_s *sig = sa->data;
    if (sig)
	free(sig);
}

static pgprRC pgprVerifySigMLDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    EVP_MD_CTX *md_ctx = NULL;
    struct pgprAlgKeyMLDSA_s *key = ka->data;
    struct pgprAlgSigMLDSA_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */

    if (!key || !sig)
	return PGPR_ERROR_INTERNAL;

    ERR_clear_error();
    if (!constructMLDSASigningKey(key, sa->algo)) {
	rc = PGPR_ERROR_REJECTED_PUBKEY;
	goto done;
    }
    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_md_null(), NULL, key->evp_pkey) != 1)
	goto done;
    if (EVP_DigestVerify(md_ctx, sig->sig, sig->sigl, hash, hashlen) == 1)
	rc = PGPR_OK;		/* Success */
done:
    rc = check_out_of_mem(rc);
    if (md_ctx)
	EVP_MD_CTX_free(md_ctx);
    return rc;
}

static pgprRC pgprInitSigMLDSA(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiMLDSA;
    sa->free = pgprFreeSigMLDSA;
    sa->verify = pgprVerifySigMLDSA;
    sa->mpis = 0;
    return PGPR_OK;
}

static pgprRC pgprInitKeyMLDSA(pgprAlg ka)
{
    ka->setmpi = pgprSetKeyMpiMLDSA;
    ka->free = pgprFreeKeyMLDSA;
    ka->mpis = 0;
    return PGPR_OK;
}

#endif


/****************************** PGP **************************************/

pgprRC pgprAlgInitPubkey(pgprAlg ka)
{
    switch (ka->algo) {
    case PGPRPUBKEYALGO_RSA:
	return pgprInitKeyRSA(ka);
    case PGPRPUBKEYALGO_DSA:
	return pgprInitKeyDSA(ka);
    case PGPRPUBKEYALGO_ECDSA:
	return pgprInitKeyECDSA(ka);
#ifdef EVP_PKEY_ED25519
    case PGPRPUBKEYALGO_EDDSA:
    case PGPRPUBKEYALGO_ED25519:
    case PGPRPUBKEYALGO_ED448:
	return pgprInitKeyEDDSA(ka);
#endif
#if defined(EVP_PKEY_ML_DSA_65) || defined(EVP_PKEY_ML_DSA_87)
    case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
    case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
	return pgprInitKeyMLDSA(ka);
#endif
    case PGPRPUBKEYALGO_MLDSA65_ED25519:
    case PGPRPUBKEYALGO_MLDSA87_ED448:
	return pgprInitKeyHybrid(ka);
    default:
        break;
    }
    return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
}

pgprRC pgprAlgInitSignature(pgprAlg sa)
{
    switch (sa->algo) {
    case PGPRPUBKEYALGO_RSA:
	return pgprInitSigRSA(sa);
    case PGPRPUBKEYALGO_DSA:
	return pgprInitSigDSA(sa);
    case PGPRPUBKEYALGO_ECDSA:
	return pgprInitSigECDSA(sa);
#ifdef EVP_PKEY_ED25519
    case PGPRPUBKEYALGO_EDDSA:
    case PGPRPUBKEYALGO_ED25519:
    case PGPRPUBKEYALGO_ED448:
	return pgprInitSigEDDSA(sa);
#endif
#if defined(EVP_PKEY_ML_DSA_65) || defined(EVP_PKEY_ML_DSA_87)
    case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
    case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
	return pgprInitSigMLDSA(sa);
#endif
    case PGPRPUBKEYALGO_MLDSA65_ED25519:
    case PGPRPUBKEYALGO_MLDSA87_ED448:
	return pgprInitSigHybrid(sa);
    default:
        break;
    }
    return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
}

#ifndef PGPR_RPM_INTREE
pgprRC pgprInitCrypto(void)
{
    return OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, 0) == 1 ? PGPR_OK : PGPR_ERROR_INTERNAL;
}

pgprRC pgprFreeCrypto(void)
{
    return PGPR_OK;
}


pgprRC pgprDigestInit(int hashalgo, pgprDigCtx *ret)
{
    const EVP_MD *md = getEVPMD(hashalgo);
    EVP_MD_CTX *ctx = NULL;
    if (!md || md == EVP_md_null())
	return PGPR_ERROR_UNSUPPORTED_DIGEST;
    ERR_clear_error();
    ctx = EVP_MD_CTX_new();
    if (ctx && !EVP_DigestInit_ex(ctx, md, NULL)) {
	EVP_MD_CTX_free(ctx);
	ctx = NULL;
    }
    *ret = ctx;
    return ctx ? PGPR_OK : check_out_of_mem(PGPR_ERROR_INTERNAL);
}

pgprRC pgprDigestUpdate(pgprDigCtx ctx, const void * data, size_t len)
{
    if (!ctx)
	return PGPR_ERROR_INTERNAL;
    EVP_DigestUpdate(ctx, data, len);
    return PGPR_OK;
}

pgprRC pgprDigestFinal(pgprDigCtx ctx, void ** datap, size_t *lenp)
{
    uint8_t *digest = NULL;
    int digestlen;
    if (!ctx)
	return PGPR_ERROR_INTERNAL;
    ERR_clear_error();
    digestlen = EVP_MD_CTX_size(ctx);
    if (digestlen > 0) {
	digest = (uint8_t *)pgprCalloc(digestlen, sizeof(*digest));
	if (!digest) {
	    EVP_MD_CTX_free(ctx);
	    return PGPR_ERROR_NO_MEMORY;
	}
	if (!EVP_DigestFinal_ex(ctx, digest, (unsigned int *)&digestlen)) {
	    digestlen = 0;
	} else {
	    if (datap) {
		*datap = digest;
		digest = NULL;
	    }
	    if (lenp)
		*lenp = digestlen;
	}
    }
    if (digest)
	free(digest);
    EVP_MD_CTX_free(ctx);
    return digestlen > 0 ? PGPR_OK : check_out_of_mem(PGPR_ERROR_INTERNAL);
}

pgprRC pgprDigestDup(pgprDigCtx oldctx,  pgprDigCtx *ret)
{
    pgprDigCtx ctx;
    if (!oldctx)
	return PGPR_ERROR_INTERNAL;
    ERR_clear_error();
    ctx = EVP_MD_CTX_new();
    if (ctx && !EVP_MD_CTX_copy(ctx, oldctx)) {
	EVP_MD_CTX_free(ctx);
	ctx = NULL;
    }
    *ret = ctx;
    return ctx ? PGPR_OK : check_out_of_mem(PGPR_ERROR_INTERNAL);
}

size_t pgprDigestLength(int hashalgo)
{
    const EVP_MD *md = getEVPMD(hashalgo);
    return md && md != EVP_md_null() ? EVP_MD_size(md) : 0;
}
#endif

