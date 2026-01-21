#include <gcrypt.h>

#include "pgpr_internal.h"

static int hashalgo2gcryalgo(int hashalgo)
{
    switch (hashalgo) {
    case PGPRHASHALGO_MD5:
	return GCRY_MD_MD5;
    case PGPRHASHALGO_SHA1:
	return GCRY_MD_SHA1;
    case PGPRHASHALGO_SHA224:
	return GCRY_MD_SHA224;
    case PGPRHASHALGO_SHA256:
	return GCRY_MD_SHA256;
    case PGPRHASHALGO_SHA384:
	return GCRY_MD_SHA384;
    case PGPRHASHALGO_SHA512:
	return GCRY_MD_SHA512;
#if GCRYPT_VERSION_NUMBER >= 0x010700
    case PGPRHASHALGO_SHA3_256:
	return GCRY_MD_SHA3_256;
    case PGPRHASHALGO_SHA3_512:
	return GCRY_MD_SHA3_512;
#endif
    default:
	return 0;
    }
}

static int check_gcrypt_supported(const char *sexpstr)
{
    gcry_sexp_t sexp = NULL;
    unsigned int nbits;
    gcry_sexp_build(&sexp, NULL, sexpstr);
    nbits = gcry_pk_get_nbits(sexp);
    gcry_sexp_release(sexp);
    return nbits > 0 ? 1 : -1;
}

static int pgprSupportedCurve(int algo, int curve)
{
    if (algo == PGPRPUBKEYALGO_EDDSA && curve == PGPRCURVE_ED25519) {
	static int supported_ed25519;
	if (!supported_ed25519)
	    supported_ed25519 = check_gcrypt_supported("(public-key (ecc (curve \"Ed25519\")))");
	return supported_ed25519 > 0;
    }
    if (algo == PGPRPUBKEYALGO_EDDSA && curve == PGPRCURVE_ED448) {
	static int supported_ed448;
	if (!supported_ed448)
	    supported_ed448 = check_gcrypt_supported("(public-key (ecc (curve \"Ed448\")))");
	return supported_ed448 > 0;
    }
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_256)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_384)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_521)
	return 1;
    if (algo == PGPRPUBKEYALGO_INTERNAL_MLDSA65 || algo == PGPRPUBKEYALGO_INTERNAL_MLDSA87) {
	static int supported_mldsa;
	if (!supported_mldsa)
	    supported_mldsa = check_gcrypt_supported("(public-key (dilithium3))");
	return supported_mldsa > 0;
    }
    return 0;
}


/****************************** RSA **************************************/

struct pgprAlgSigRSA_s {
    gcry_mpi_t s;
};

struct pgprAlgKeyRSA_s {
    gcry_mpi_t n;
    gcry_mpi_t e;
};

static pgprRC pgprSetSigMpiRSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigRSA_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;

    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprSetKeyMpiRSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyRSA_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;

    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	ka->info = 8 * (((mlen - 2) + 7) & ~7);
	if (!gcry_mpi_scan(&key->n, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->e, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprVerifySigRSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprAlgKeyRSA_s *key = ka->data;
    struct pgprAlgSigRSA_s *sig = sa->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int gcry_hash_algo = hashalgo2gcryalgo(hash_algo);
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;

    if (!sig || !key || !gcry_hash_algo)
	return rc;

    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (rsa (s %M)))", sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags pkcs1) (hash %s %b))", gcry_md_algo_name(gcry_hash_algo), (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (rsa (n %M) (e %M)))", key->n, key->e);
    if (sexp_sig && sexp_data && sexp_pkey)
	if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
	    rc = PGPR_OK;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgprFreeSigRSA(pgprAlg sa)
{
    struct pgprAlgSigRSA_s *sig = sa->data;
    if (sig) {
        gcry_mpi_release(sig->s);
	free(sig);
	sa->data = NULL;
    }
}

static void pgprFreeKeyRSA(pgprAlg ka)
{
    struct pgprAlgKeyRSA_s *key = ka->data;
    if (key) {
        gcry_mpi_release(key->n);
        gcry_mpi_release(key->e);
	free(key);
	ka->data = NULL;
    }
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


/****************************** DSA **************************************/

struct pgprAlgSigDSA_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgprAlgKeyDSA_s {
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t g;
    gcry_mpi_t y;
};

static pgprRC pgprSetSigMpiDSA(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigDSA_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;

    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprSetKeyMpiDSA(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyDSA_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;

    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	ka->info = 8 * (((mlen - 2) + 7) & ~7);
	if (!gcry_mpi_scan(&key->p, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 2:
	if (!gcry_mpi_scan(&key->g, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 3:
	if (!gcry_mpi_scan(&key->y, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprVerifySigDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprAlgKeyDSA_s *key = ka->data;
    struct pgprAlgSigDSA_s *sig = sa->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;
    size_t qlen;

    if (!sig || !key)
	return rc;

    qlen = (mpi_get_nbits(key->q) + 7) / 8;
    if (qlen < 20)
	qlen = 20;		/* sanity */
    if (hashlen > qlen)
	hashlen = qlen;		/* dsa2: truncate hash to qlen */
    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (dsa (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags raw) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", key->p, key->q, key->g, key->y);
    if (sexp_sig && sexp_data && sexp_pkey)
	if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
	    rc = PGPR_OK;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgprFreeSigDSA(pgprAlg sa)
{
    struct pgprAlgSigDSA_s *sig = sa->data;
    if (sig) {
        gcry_mpi_release(sig->r);
        gcry_mpi_release(sig->s);
	free(sig);
	sa->data = NULL;
    }
}

static void pgprFreeKeyDSA(pgprAlg ka)
{
    struct pgprAlgKeyDSA_s *key = ka->data;
    if (key) {
        gcry_mpi_release(key->p);
        gcry_mpi_release(key->q);
        gcry_mpi_release(key->g);
        gcry_mpi_release(key->y);
	free(key);
	ka->data = NULL;
    }
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


/****************************** ECC **************************************/

struct pgprAlgSigECC_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgprAlgKeyECC_s {
    gcry_mpi_t q;
};

static pgprRC pgprSetSigMpiECC(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigECC_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;

    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));

    if (num == -1) {
	if (sa->algo == PGPRPUBKEYALGO_ED25519 && mlen == 2 * 32 && !gcry_mpi_scan(&sig->r, GCRYMPI_FMT_USG, p, 32, NULL) && !gcry_mpi_scan(&sig->s, GCRYMPI_FMT_USG, p + 32, 32, NULL))
	    rc = PGPR_OK;
	else if (sa->algo == PGPRPUBKEYALGO_ED448 && mlen == 2 * 57 && !gcry_mpi_scan(&sig->r, GCRYMPI_FMT_USG, p, 57, NULL) && !gcry_mpi_scan(&sig->s, GCRYMPI_FMT_USG, p + 57, 57, NULL))
	    rc = PGPR_OK;
	return rc;
    }
    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprSetKeyMpiECC(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyECC_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;

    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));

    if (num == -1) {
	if (ka->curve == PGPRCURVE_ED25519 && mlen == 32 && !gcry_mpi_scan(&key->q, GCRYMPI_FMT_USG, p, 32, NULL))
	    rc = PGPR_OK;
	else if (ka->curve == PGPRCURVE_ED448 && mlen == 57 && !gcry_mpi_scan(&key->q, GCRYMPI_FMT_USG, p, 57, NULL))
	    rc = PGPR_OK;
	return rc;
    }

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static int eddsa_zero_extend(gcry_mpi_t x, unsigned char *buf, int bufl)
{
    int n = (gcry_mpi_get_nbits(x) + 7) / 8;
    if (n == 0 || n > bufl)
	return 1;
    n = bufl - n;
    if (n)
	memset(buf, 0, n);
    gcry_mpi_print(GCRYMPI_FMT_USG, buf + n, bufl - n, NULL, x);
    return 0;
}

static pgprRC pgprVerifySigECC(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprAlgKeyECC_s *key = ka->data;
    struct pgprAlgSigECC_s *sig = sa->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;

    if (!sig || !key)
	return rc;
    if (ka->curve == PGPRCURVE_ED25519) {
	unsigned char buf_r[32], buf_s[32];
	if (eddsa_zero_extend(sig->r, buf_r, 32) || eddsa_zero_extend(sig->s, buf_s, 32))
	    return rc;
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 32, (const char *)buf_r, 32, (const char *)buf_s);
	gcry_sexp_build(&sexp_data, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", (int)hashlen, (const char *)hash);
	gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"Ed25519\") (flags eddsa) (q %M)))", key->q);
	if (sexp_sig && sexp_data && sexp_pkey)
	    if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = PGPR_OK;
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_data);
	gcry_sexp_release(sexp_pkey);
	return rc;
    }
    if (ka->curve == PGPRCURVE_ED448) {
	unsigned char buf_r[57], buf_s[57];
	if (eddsa_zero_extend(sig->r, buf_r, 57) || eddsa_zero_extend(sig->s, buf_s, 57))
	    return rc;
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 57, (const char *)buf_r, 57, (const char *)buf_s);
	gcry_sexp_build(&sexp_data, NULL, "(data (flags eddsa) (value %b))", (int)hashlen, (const char *)hash);
	gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"Ed448\") (flags eddsa) (q %M)))", key->q);
	if (sexp_sig && sexp_data && sexp_pkey)
	    if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = PGPR_OK;
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_data);
	gcry_sexp_release(sexp_pkey);
	return rc;
    }
    if (ka->curve == PGPRCURVE_NIST_P_256 || ka->curve == PGPRCURVE_NIST_P_384 || ka->curve == PGPRCURVE_NIST_P_521) {
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (ecdsa (r %M) (s %M)))", sig->r, sig->s);
	gcry_sexp_build(&sexp_data, NULL, "(data (value %b))", (int)hashlen, (const char *)hash);
	if (ka->curve == PGPRCURVE_NIST_P_256)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-256\") (q %M)))", key->q);
	else if (ka->curve == PGPRCURVE_NIST_P_384)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-384\") (q %M)))", key->q);
	else if (ka->curve == PGPRCURVE_NIST_P_521)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-521\") (q %M)))", key->q);
	if (sexp_sig && sexp_data && sexp_pkey)
	    if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = PGPR_OK;
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_data);
	gcry_sexp_release(sexp_pkey);
	return rc;
    }
    return rc;
}

static void pgprFreeSigECC(pgprAlg sa)
{
    struct pgprAlgSigECC_s *sig = sa->data;
    if (sig) {
	gcry_mpi_release(sig->r);
	gcry_mpi_release(sig->s);
	free(sig);
	sa->data = NULL;
    }
}

static void pgprFreeKeyECC(pgprAlg ka)
{
    struct pgprAlgKeyECC_s *key = ka->data;
    if (key) {
	gcry_mpi_release(key->q);
	free(key);
	ka->data = NULL;
    }
}

static pgprRC pgprInitSigECC(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiECC;
    sa->free = pgprFreeSigECC;
    sa->verify = pgprVerifySigECC;
    sa->mpis = sa->algo == PGPRPUBKEYALGO_ECDSA || sa->algo == PGPRPUBKEYALGO_EDDSA ? 2 : 0;
    return PGPR_OK;
}

static pgprRC pgprInitKeyECC(pgprAlg ka)
{
    if (ka->algo == PGPRPUBKEYALGO_ED25519)
	ka->curve = PGPRCURVE_ED25519;
    if (ka->algo == PGPRPUBKEYALGO_ED448)
	ka->curve = PGPRCURVE_ED448;
    if (!pgprSupportedCurve(ka->algo == PGPRPUBKEYALGO_ECDSA ? ka->algo : PGPRPUBKEYALGO_EDDSA, ka->curve))
	return PGPR_ERROR_UNSUPPORTED_CURVE;
    ka->setmpi = pgprSetKeyMpiECC;
    ka->free = pgprFreeKeyECC;
    ka->mpis = ka->algo == PGPRPUBKEYALGO_ECDSA || ka->algo == PGPRPUBKEYALGO_EDDSA ? 1 : 0;
    ka->info = ka->algo == PGPRPUBKEYALGO_ECDSA || ka->algo == PGPRPUBKEYALGO_EDDSA ? ka->curve : 0;
    return PGPR_OK;
}


/****************************** ML-DSA **************************************/

struct pgprAlgSigMLDSA_s {
    gcry_mpi_t s;
};

struct pgprAlgKeyMLDSA_s {
    gcry_mpi_t p;
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
    if (sigl && mlen == sigl) {
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_USG, p, sigl, NULL))
	    rc = PGPR_OK;
    }
    return rc;
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
    if (keyl && mlen == keyl) {
	if (!gcry_mpi_scan(&key->p, GCRYMPI_FMT_USG, p, keyl, NULL))
	    rc = PGPR_OK;
    }
    return rc;
}

static pgprRC pgprVerifySigMLDSA(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;
    struct pgprAlgKeyMLDSA_s *key = ka->data;
    struct pgprAlgSigMLDSA_s *sig = sa->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;

    if (!sig || !key || !sig->s || !key->p)
	return rc;
    gcry_sexp_build(&sexp_data, NULL, "(data (raw) (value %b))", (int)hashlen, (const char *)hash);
    if (ka->algo == PGPRPUBKEYALGO_INTERNAL_MLDSA65) {
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (dilithium3 (s %M)))", sig->s);
	gcry_sexp_build(&sexp_pkey, NULL, "(public-key (dilithium3 (p %M)))", key->p);
    } else if (ka->algo == PGPRPUBKEYALGO_INTERNAL_MLDSA87) {
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (dilithium5 (s %M)))", sig->s);
	gcry_sexp_build(&sexp_pkey, NULL, "(public-key (dilithium5 (p %M)))", key->p);
    }
    if (sexp_sig && sexp_data && sexp_pkey)
	if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = PGPR_OK;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgprFreeSigMLDSA(pgprAlg sa)
{
    struct pgprAlgSigMLDSA_s *sig = sa->data;
    if (sig) {
	gcry_mpi_release(sig->s);
	free(sig);
	sa->data = NULL;
    }
}

static void pgprFreeKeyMLDSA(pgprAlg ka)
{
    struct pgprAlgKeyMLDSA_s *key = ka->data;
    if (key) {
	gcry_mpi_release(key->p);
	free(key);
	ka->data = NULL;
    }
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
    if (!pgprSupportedCurve(ka->algo, 0))
	return PGPR_ERROR_UNSUPPORTED_ALGORITHM;
    ka->setmpi = pgprSetKeyMpiMLDSA;
    ka->free = pgprFreeKeyMLDSA;
    ka->mpis = 0;
    return PGPR_OK;
}


pgprRC pgprAlgInitPubkey(pgprAlg ka)
{
    switch (ka->algo) {
    case PGPRPUBKEYALGO_RSA:
	return pgprInitKeyRSA(ka);
    case PGPRPUBKEYALGO_DSA:
	return pgprInitKeyDSA(ka);
    case PGPRPUBKEYALGO_ECDSA:
    case PGPRPUBKEYALGO_EDDSA:
    case PGPRPUBKEYALGO_ED25519:
    case PGPRPUBKEYALGO_ED448:
	return pgprInitKeyECC(ka);
    case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
    case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
        return pgprInitKeyMLDSA(ka);
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
    case PGPRPUBKEYALGO_EDDSA:
    case PGPRPUBKEYALGO_ED25519:
    case PGPRPUBKEYALGO_ED448:
	return pgprInitSigECC(sa);
    case PGPRPUBKEYALGO_INTERNAL_MLDSA65:
    case PGPRPUBKEYALGO_INTERNAL_MLDSA87:
        return pgprInitSigMLDSA(sa);
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
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return PGPR_OK;
}

pgprRC pgprFreeCrypto(void)
{
    return PGPR_OK;
}

pgprRC pgprDigestInit(int hashalgo, pgprDigCtx *ret)
{
    gcry_md_hd_t h = NULL;
    int gcryalgo = hashalgo2gcryalgo(hashalgo);
    if (!gcryalgo)
	return PGPR_ERROR_UNSUPPORTED_DIGEST;
    if (gcry_md_open(&h, gcryalgo, 0) != 0)
	return PGPR_ERROR_INTERNAL;
    *ret = h;
    return h ? PGPR_OK : PGPR_ERROR_INTERNAL;
}

pgprRC pgprDigestUpdate(pgprDigCtx ctx, const void * data, size_t len)
{
    gcry_md_hd_t h = ctx;
    if (!ctx)
	return PGPR_ERROR_INTERNAL;
    gcry_md_write(h, data, len);
    return PGPR_OK;
}

pgprRC pgprDigestFinal(pgprDigCtx ctx, void ** datap, size_t *lenp)
{
    int gcryalgo;
    unsigned char *digest;
    unsigned int digestlen;
    gcry_md_hd_t h = ctx;

    if (!h || (gcryalgo = gcry_md_get_algo(h)) == 0)
	return PGPR_ERROR_INTERNAL;
    digestlen = gcry_md_get_algo_dlen(gcryalgo);
    if (digestlen == 0 || (digest = gcry_md_read(h, 0)) == NULL)
	return PGPR_ERROR_INTERNAL;
    if (lenp)
	*lenp = digestlen;
    if (datap)
	*datap = pgprMemdup(digest, digestlen);
    gcry_md_close(h);
    return PGPR_OK;
}

pgprRC pgprDigestDup(pgprDigCtx oldctx, pgprDigCtx *ret)
{
    gcry_md_hd_t oldh = oldctx;
    gcry_md_hd_t h = NULL;
    if (oldh && gcry_md_copy(&h, oldh) != 0)
	h = NULL;
    *ret = h;
    return h ? PGPR_OK : PGPR_ERROR_INTERNAL;
}

size_t pgprDigestLength(int hashalgo)
{
    int gcryalgo = hashalgo2gcryalgo(hashalgo);
    return gcryalgo ? gcry_md_get_algo_dlen(gcryalgo) : 0;
}
#endif
