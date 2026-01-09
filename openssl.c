#include <openssl/evp.h>
#if OPENSSL_VERSION_MAJOR >= 3
# include <openssl/params.h>
#endif
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include "pgpr.h"
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

    default:
        return EVP_md_null();
    }
}


/*********************** pkey construction *******************************/

#if OPENSSL_VERSION_MAJOR >= 3

static EVP_PKEY *
construct_pkey_from_param(int id, OSSL_PARAM *params)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	pkey = NULL;
    if (ctx)
	EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static OSSL_PARAM 
create_bn_param(char *key, BIGNUM *bn)
{
    unsigned char *buf;
    int sz = bn ? BN_num_bytes(bn) : -1;
    if (sz < 0 || BN_is_negative(bn)) {
	OSSL_PARAM param = OSSL_PARAM_END;
	return param;
    }
    if (sz == 0)
	sz = 1;
    buf = pgprMalloc(sz);
    BN_bn2nativepad(bn, buf, sz);
    OSSL_PARAM param = OSSL_PARAM_BN(key, buf, sz);
    return param;
}

static void
free_bn_param(OSSL_PARAM *param)
{
    free(param->data);
}

#endif

/****************************** RSA **************************************/

/* Key */

struct pgprDigKeyRSA_s {
    size_t nbytes; /* Size of modulus */

    BIGNUM *n; /* Common Modulus */
    BIGNUM *e; /* Public Exponent */
    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructRSASigningKey(struct pgprDigKeyRSA_s *key)
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
    if (!rsa) return 0;

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

static pgprRC pgprSetKeyMpiRSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;	/* assume failure */
    struct pgprDigKeyRSA_s *key = pgprkey->data;

    if (!key)
        key = pgprkey->data = pgprCalloc(1, sizeof(*key));

    if (key->evp_pkey)
	return rc;

    switch (num) {
    case 0:
        /* Modulus */
        if (key->n)
            return 1;	/* This should only ever happen once per key */
	key->nbytes = mlen - 2;
	pgprkey->info = 8 * (((mlen - 2) + 7) & ~7);
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGPR */
        key->n = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->n)
	    rc = PGPR_OK;
        break;

    case 1:
        /* Exponent */
        if (key->e)
            return 1;	/* This should only ever happen once per key */
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGPR */
        key->e = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->e)
	    rc = PGPR_OK;
        break;
    }

    return rc;
}

static void pgprFreeKeyRSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyRSA_s *key = pgprkey->data;
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

struct pgprDigSigRSA_s {
    BIGNUM *bn;
};

static pgprRC pgprSetSigMpiRSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprDigSigRSA_s *sig = pgprsig->data;

    if (!sig)
        sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->bn)
            return rc;	/* This should only ever happen once per signature */
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
    return rc;
}

static void pgprFreeSigRSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigRSA_s *sig = pgprsig->data;
    if (sig) {
	if (sig->bn)
	    BN_clear_free(sig->bn);
        free(pgprsig->data);
    }
}

static pgprRC pgprVerifySigRSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig,
                           const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgprDigSigRSA_s *sig = pgprsig->data;
    struct pgprDigKeyRSA_s *key = pgprkey->data;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    void *padded_sig = NULL;

    if (!constructRSASigningKey(key)) {
        rc = PGPR_ERROR_BAD_PUBKEY;
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

    int pkey_len = EVP_PKEY_size(key->evp_pkey);
    padded_sig = pgprCalloc(1, pkey_len);
    if (BN_bn2binpad(sig->bn, padded_sig, pkey_len) <= 0)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, padded_sig, pkey_len, hash, hashlen) == 1)
        rc = PGPR_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(padded_sig);
    return rc;
}

/****************************** DSA ***************************************/
/* Key */

struct pgprDigKeyDSA_s {
    BIGNUM *p; /* Prime */
    BIGNUM *q; /* Subprime */
    BIGNUM *g; /* Base */
    BIGNUM *y; /* Public Key */

    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructDSASigningKey(struct pgprDigKeyDSA_s *key)
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
    if (!dsa) return 0;

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


static pgprRC pgprSetKeyMpiDSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;	/* assume failure */
    struct pgprDigKeyDSA_s *key = pgprkey->data;

    if (!key)
        key = pgprkey->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
        /* Prime */
        if (key->p)
            return rc;	/* This should only ever happen once per key */
	pgprkey->info = 8 * (((mlen - 2) + 7) & ~7);
        key->p = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->p)
	    rc = PGPR_OK;
        break;
    case 1:
        /* Subprime */
        if (key->q)
            return rc;	/* This should only ever happen once per key */
        key->q = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->q)
	    rc = PGPR_OK;
        break;
    case 2:
        /* Base */
        if (key->g)
            return rc;	/* This should only ever happen once per key */
        key->g = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->g)
	    rc = PGPR_OK;
        break;
    case 3:
        /* Public */
        if (key->y)
            return rc;	/* This should only ever happen once per key */
        key->y = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->y)
	    rc = PGPR_OK;
        break;
    }
    return rc;
}

static void pgprFreeKeyDSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyDSA_s *key = pgprkey->data;
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

struct pgprDigSigDSA_s {
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

static pgprRC pgprSetSigMpiDSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprDigSigDSA_s *sig = pgprsig->data;

    if (!sig)
        sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->r)
            return rc;	/* This should only ever happen once per signature */
        sig->rlen = mlen - 2;
	sig->r = pgprMemdup(p + 2, mlen - 2);
        rc = PGPR_OK;
        break;
    case 1:
        if (sig->s)
            return rc;	/* This should only ever happen once per signature */
        sig->slen = mlen - 2;
	sig->s = pgprMemdup(p + 2, mlen - 2);
        rc = PGPR_OK;
        break;
    }

    return rc;
}

static void pgprFreeSigDSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigDSA_s *sig = pgprsig->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(pgprsig->data);
}

static pgprRC pgprVerifySigDSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig,
                           const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgprDigSigDSA_s *sig = pgprsig->data;
    struct pgprDigKeyDSA_s *key = pgprkey->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!constructDSASigningKey(key)) {
        rc = PGPR_ERROR_BAD_PUBKEY;
        goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig)
        goto done;

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
        rc = PGPR_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

/****************************** ECDSA ***************************************/

struct pgprDigKeyECDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructECDSASigningKey(struct pgprDigKeyECDSA_s *key, int curve)
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

static pgprRC pgprSetKeyMpiECDSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    struct pgprDigKeyECDSA_s *key = pgprkey->data;
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;	/* assume failure */

    if (!key)
	key = pgprkey->data = pgprCalloc(1, sizeof(*key));
    if (num == 0 && !key->q && mlen > 3 && p[2] == 0x04) {
	key->qlen = mlen - 2;
	key->q = pgprMemdup(p + 2, mlen - 2);
	rc = PGPR_OK;
    }
    return rc;
}

static void pgprFreeKeyECDSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyECDSA_s *key = pgprkey->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgprDigSigECDSA_s {
    unsigned char *r;
    int rlen;
    unsigned char *s;
    int slen;
};

static pgprRC pgprSetSigMpiECDSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgprDigSigECDSA_s *sig = pgprsig->data;

    if (!sig)
        sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->r)
            return rc;	/* This should only ever happen once per signature */
	sig->rlen = mlen - 2;
	sig->r = pgprMemdup(p + 2, mlen - 2);
        rc = PGPR_OK;
        break;
    case 1:
        if (sig->s)
            return 1;	/* This should only ever happen once per signature */
	sig->slen = mlen - 2;
	sig->s = pgprMemdup(p + 2, mlen - 2);
        rc = PGPR_OK;
        break;
    }

    return rc;
}

static void pgprFreeSigECDSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigECDSA_s *sig = pgprsig->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(pgprsig->data);
}

static pgprRC pgprVerifySigECDSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig,
                           const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgprDigSigECDSA_s *sig = pgprsig->data;
    struct pgprDigKeyECDSA_s *key = pgprkey->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!constructECDSASigningKey(key, pgprkey->curve)) {
	rc = PGPR_ERROR_BAD_PUBKEY;
        goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig)
        goto done;

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
        rc = PGPR_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

/****************************** EDDSA ***************************************/

#ifdef EVP_PKEY_ED25519

struct pgprDigKeyEDDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructEDDSASigningKey(struct pgprDigKeyEDDSA_s *key, int curve)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */
#ifdef EVP_PKEY_ED25519
    if (curve == PGPRCURVE_ED25519 || curve == PGPRCURVE_ED25519_ALT)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->q, key->qlen);
#endif
#ifdef EVP_PKEY_ED448
    if (curve == PGPRCURVE_ED448)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, key->q, key->qlen);
#endif
    return key->evp_pkey ? 1 : 0;
}

static pgprRC pgprSetKeyMpiEDDSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    struct pgprDigKeyEDDSA_s *key = pgprkey->data;
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgprkey->data = pgprCalloc(1, sizeof(*key));
    if ((pgprkey->curve == PGPRCURVE_ED25519 || pgprkey->curve == PGPRCURVE_ED25519_ALT) && num == 0 && !key->q && mlen > 3 && p[2] == 0x40) {
	key->qlen = mlen - 3;
	key->q = pgprMemdup(p + 3, mlen - 3);	/* we do not copy the leading 0x40 */
	rc = PGPR_OK;
    }
    if (pgprkey->curve == PGPRCURVE_ED448 && num == 0 && !key->q && mlen > 3 && mlen <= 59) {
	key->qlen = 57;
	key->q = pgprCalloc(1, 57);
	memcpy(key->q + 57 - (mlen - 2), p + 2, mlen - 2);
	rc = PGPR_OK;
    }
    return rc;
}

static void pgprFreeKeyEDDSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyEDDSA_s *key = pgprkey->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgprDigSigEDDSA_s {
    unsigned char sig[57 + 57];
    int not_ed25519;
};

static pgprRC pgprSetSigMpiEDDSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    struct pgprDigSigEDDSA_s *sig = pgprsig->data;

    if (!sig)
	sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));
    mlen -= 2;	/* skip mpi len */
    if ((num != 0 && num != 1) || mlen <= 0 || mlen > 57)
      return PGPR_ERROR_BAD_SIGNATURE;
    memcpy(sig->sig + 57 * num + 57 - mlen, p + 2, mlen);
    if (mlen > 32)
	sig->not_ed25519 = 1;
    return PGPR_OK;
}

static void pgprFreeSigEDDSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigEDDSA_s *sig = pgprsig->data;
    if (sig) {
	free(pgprsig->data);
    }
}

static pgprRC pgprVerifySigEDDSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig,
                           const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgprDigSigEDDSA_s *sig = pgprsig->data;
    struct pgprDigKeyEDDSA_s *key = pgprkey->data;
    EVP_MD_CTX *md_ctx = NULL;

    if (!constructEDDSASigningKey(key, pgprkey->curve)) {
	rc = PGPR_ERROR_BAD_PUBKEY;
	goto done;
    }
    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_md_null(), NULL, key->evp_pkey) != 1)
	goto done;
    if ((pgprkey->curve == PGPRCURVE_ED25519 || pgprkey->curve == PGPRCURVE_ED25519_ALT) && !sig->not_ed25519) {
	unsigned char esig[64];
	memcpy(esig, sig->sig + 57 - 32, 32);
	memcpy(esig + 32, sig->sig + 2 * 57 - 32, 32);
	if (EVP_DigestVerify(md_ctx, esig, 64, hash, hashlen) == 1)
	    rc = PGPR_OK;		/* Success */
    }
    if (pgprkey->curve == PGPRCURVE_ED448) {
	if (EVP_DigestVerify(md_ctx, sig->sig, 114, hash, hashlen) == 1)
	    rc = PGPR_OK;		/* Success */
    }
done:
    if (md_ctx)
	EVP_MD_CTX_free(md_ctx);
    return rc;
}

#endif



/****************************** PGP **************************************/

static int pgprSupportedCurve(int algo, int curve)
{
#ifdef EVP_PKEY_ED25519
    if (algo == PGPRPUBKEYALGO_EDDSA && (curve == PGPRCURVE_ED25519 || curve == PGPRCURVE_ED25519_ALT))
	return 1;
#endif
#ifdef EVP_PKEY_ED448
    if (algo == PGPRPUBKEYALGO_EDDSA && curve == PGPRCURVE_ED448)
	return 1;
#endif
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_256)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_384)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_521)
	return 1;
    return 0;
}

pgprRC pgprDigAlgInitPubkey(pgprDigAlg ka, int algo, int curve)
{
    switch (algo) {
    case PGPRPUBKEYALGO_RSA:
        ka->setmpi = pgprSetKeyMpiRSA;
        ka->free = pgprFreeKeyRSA;
        ka->mpis = 2;
        return PGPR_OK;
    case PGPRPUBKEYALGO_DSA:
        ka->setmpi = pgprSetKeyMpiDSA;
        ka->free = pgprFreeKeyDSA;
        ka->mpis = 4;
        return PGPR_OK;
    case PGPRPUBKEYALGO_ECDSA:
        ka->curve = curve;
	if (!pgprSupportedCurve(algo, curve))
	    return PGPR_ERROR_UNSUPPORTED_CURVE;
        ka->setmpi = pgprSetKeyMpiECDSA;
        ka->free = pgprFreeKeyECDSA;
        ka->mpis = 1;
        ka->info = curve;
        return PGPR_OK;
#ifdef EVP_PKEY_ED25519
    case PGPRPUBKEYALGO_EDDSA:
        ka->curve = curve;
	if (!pgprSupportedCurve(algo, curve))
	    return PGPR_ERROR_UNSUPPORTED_CURVE;
        ka->setmpi = pgprSetKeyMpiEDDSA;
        ka->free = pgprFreeKeyEDDSA;
        ka->mpis = 1;
        ka->info = curve;
        return PGPR_OK;
#endif
    default:
        break;
    }
    return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
}

pgprRC pgprDigAlgInitSignature(pgprDigAlg sa, int algo)
{
    switch (algo) {
    case PGPRPUBKEYALGO_RSA:
        sa->setmpi = pgprSetSigMpiRSA;
        sa->free = pgprFreeSigRSA;
        sa->verify = pgprVerifySigRSA;
        sa->mpis = 1;
        return PGPR_OK;
    case PGPRPUBKEYALGO_DSA:
        sa->setmpi = pgprSetSigMpiDSA;
        sa->free = pgprFreeSigDSA;
        sa->verify = pgprVerifySigDSA;
        sa->mpis = 2;
        return PGPR_OK;
    case PGPRPUBKEYALGO_ECDSA:
        sa->setmpi = pgprSetSigMpiECDSA;
        sa->free = pgprFreeSigECDSA;
        sa->verify = pgprVerifySigECDSA;
        sa->mpis = 2;
        return PGPR_OK;
#ifdef EVP_PKEY_ED25519
    case PGPRPUBKEYALGO_EDDSA:
        sa->setmpi = pgprSetSigMpiEDDSA;
        sa->free = pgprFreeSigEDDSA;
        sa->verify = pgprVerifySigEDDSA;
        sa->mpis = 2;
        return PGPR_OK;
#endif
    default:
        break;
    }
    return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
}

#ifndef PGPR_RPM_INTREE
pgprRC pgprInitCrypto(void)
{
    return PGPR_OK;
}

pgprRC pgprFreeCrypto(void)
{
    return PGPR_OK;
}

pgprDigCtx pgprDigestInit(int hashalgo)
{
    const EVP_MD *md = getEVPMD(hashalgo);
    EVP_MD_CTX *ctx = NULL;
    if (md && md != EVP_md_null()) {
	ctx = EVP_MD_CTX_new();
	if (ctx && !EVP_DigestInit_ex(ctx, md, NULL)) {
	    EVP_MD_CTX_free(ctx);
	    ctx = NULL;
	}
    }
    return ctx;
}

int pgprDigestUpdate(pgprDigCtx ctx, const void * data, size_t len)
{
    if (!ctx)
	return -1;
    EVP_DigestUpdate(ctx, data, len);
    return 0;
}

int pgprDigestFinal(pgprDigCtx ctx, void ** datap, size_t *lenp)
{
    uint8_t *digest = NULL;
    int digestlen;
    if (!ctx)
	return -1;
    digestlen = EVP_MD_CTX_size(ctx);
    if (digestlen > 0) {
	digest = (uint8_t *)pgprCalloc(digestlen, sizeof(*digest));
	if (!EVP_DigestFinal_ex(ctx, digest, &digestlen)) {
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
    return digestlen > 0 ? 0 : -1;
}

pgprDigCtx pgprDigestDup(pgprDigCtx oldctx)
{
    pgprDigCtx ctx;
    if (!oldctx)
	return NULL;
    ctx = EVP_MD_CTX_new();
    if (ctx && !EVP_MD_CTX_copy(ctx, oldctx)) {
	EVP_MD_CTX_free(ctx);
	ctx = NULL;
    }
    return ctx;
}

size_t pgprDigestLength(int hashalgo)
{
    const EVP_MD *md = getEVPMD(hashalgo);
    return md && md != EVP_md_null() ? EVP_MD_size(md) : 0;
}
#endif

