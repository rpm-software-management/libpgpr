#include <gcrypt.h>

#include "pgpr.h"
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
    default:
	return 0;
    }
}

/****************************** RSA **************************************/

struct pgprDigSigRSA_s {
    gcry_mpi_t s;
};

struct pgprDigKeyRSA_s {
    gcry_mpi_t n;
    gcry_mpi_t e;
};

static pgprRC pgprSetSigMpiRSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    struct pgprDigSigRSA_s *sig = pgprsig->data;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static pgprRC pgprSetKeyMpiRSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    struct pgprDigKeyRSA_s *key = pgprkey->data;
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgprkey->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	pgprkey->info = 8 * (((mlen - 2) + 7) & ~7);
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

static pgprRC pgprVerifySigRSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprDigKeyRSA_s *key = pgprkey->data;
    struct pgprDigSigRSA_s *sig = pgprsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int gcry_hash_algo = hashalgo2gcryalgo(hash_algo);
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;

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

static void pgprFreeSigRSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigRSA_s *sig = pgprsig->data;
    if (sig) {
        gcry_mpi_release(sig->s);
	free(sig);
	pgprsig->data = NULL;
    }
}

static void pgprFreeKeyRSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyRSA_s *key = pgprkey->data;
    if (key) {
        gcry_mpi_release(key->n);
        gcry_mpi_release(key->e);
	free(key);
	pgprkey->data = NULL;
    }
}


/****************************** DSA **************************************/

struct pgprDigSigDSA_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgprDigKeyDSA_s {
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t g;
    gcry_mpi_t y;
};

static pgprRC pgprSetSigMpiDSA(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    struct pgprDigSigDSA_s *sig = pgprsig->data;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

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

static pgprRC pgprSetKeyMpiDSA(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    struct pgprDigKeyDSA_s *key = pgprkey->data;
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgprkey->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	pgprkey->info = 8 * (((mlen - 2) + 7) & ~7);
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

static pgprRC pgprVerifySigDSA(pgprDigAlg pgprkey, pgprDigAlg pgprsig, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprDigKeyDSA_s *key = pgprkey->data;
    struct pgprDigSigDSA_s *sig = pgprsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;
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

static void pgprFreeSigDSA(pgprDigAlg pgprsig)
{
    struct pgprDigSigDSA_s *sig = pgprsig->data;
    if (sig) {
        gcry_mpi_release(sig->r);
        gcry_mpi_release(sig->s);
	free(sig);
	pgprsig->data = NULL;
    }
}

static void pgprFreeKeyDSA(pgprDigAlg pgprkey)
{
    struct pgprDigKeyDSA_s *key = pgprkey->data;
    if (key) {
        gcry_mpi_release(key->p);
        gcry_mpi_release(key->q);
        gcry_mpi_release(key->g);
        gcry_mpi_release(key->y);
	free(key);
	pgprkey->data = NULL;
    }
}


/****************************** ECC **************************************/

struct pgprDigSigECC_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgprDigKeyECC_s {
    gcry_mpi_t q;
};

static pgprRC pgprSetSigMpiECC(pgprDigAlg pgprsig, int num, const uint8_t *p, int mlen)
{
    struct pgprDigSigECC_s *sig = pgprsig->data;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgprsig->data = pgprCalloc(1, sizeof(*sig));

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

static pgprRC pgprSetKeyMpiECC(pgprDigAlg pgprkey, int num, const uint8_t *p, int mlen)
{
    struct pgprDigKeyECC_s *key = pgprkey->data;
    pgprRC rc = PGPR_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgprkey->data = pgprCalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = PGPR_OK;
	break;
    }
    return rc;
}

static int
ed25519_zero_extend(gcry_mpi_t x, unsigned char *buf, int bufl)
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

static pgprRC pgprVerifySigECC(pgprDigAlg pgprkey, pgprDigAlg pgprsig, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprDigKeyECC_s *key = pgprkey->data;
    struct pgprDigSigECC_s *sig = pgprsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    pgprRC rc = PGPR_ERROR_SIGNATURE_VERIFICATION;
    unsigned char buf_r[32], buf_s[32];

    if (!sig || !key)
	return rc;
    if (pgprkey->curve == PGPRCURVE_ED25519) {
	if (ed25519_zero_extend(sig->r, buf_r, 32) || ed25519_zero_extend(sig->s, buf_s, 32))
	    return rc;
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 32, (const char *)buf_r, 32, (const char *)buf_s, 32);
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
    if (pgprkey->curve == PGPRCURVE_NIST_P_256 || pgprkey->curve == PGPRCURVE_NIST_P_384 || pgprkey->curve == PGPRCURVE_NIST_P_521) {
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (ecdsa (r %M) (s %M)))", sig->r, sig->s);
	gcry_sexp_build(&sexp_data, NULL, "(data (value %b))", (int)hashlen, (const char *)hash);
	if (pgprkey->curve == PGPRCURVE_NIST_P_256)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-256\") (q %M)))", key->q);
	else if (pgprkey->curve == PGPRCURVE_NIST_P_384)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-384\") (q %M)))", key->q);
	else if (pgprkey->curve == PGPRCURVE_NIST_P_521)
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

static void pgprFreeSigECC(pgprDigAlg pgprsig)
{
    struct pgprDigSigECC_s *sig = pgprsig->data;
    if (sig) {
	gcry_mpi_release(sig->r);
	gcry_mpi_release(sig->s);
	free(sig);
	pgprsig->data = NULL;
    }
}

static void pgprFreeKeyECC(pgprDigAlg pgprkey)
{
    struct pgprDigKeyECC_s *key = pgprkey->data;
    if (key) {
	gcry_mpi_release(key->q);
	free(key);
	pgprkey->data = NULL;
    }
}


static int pgprSupportedCurve(int algo, int curve)
{
    if (algo == PGPRPUBKEYALGO_EDDSA && curve == PGPRCURVE_ED25519) {
	static int supported_ed25519;
	if (!supported_ed25519) {
	    gcry_sexp_t sexp = NULL;
	    unsigned int nbits;
	    gcry_sexp_build(&sexp, NULL, "(public-key (ecc (curve \"Ed25519\")))");
	    nbits = gcry_pk_get_nbits(sexp);
	    gcry_sexp_release(sexp);
	    supported_ed25519 = nbits > 0 ? 1 : -1;
	}
	return supported_ed25519 > 0;
    }
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_256)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_384)
	return 1;
    if (algo == PGPRPUBKEYALGO_ECDSA && curve == PGPRCURVE_NIST_P_521)
	return 1;
    return 0;
}

void pgprDigAlgInitPubkey(pgprDigAlg ka, int algo, int curve)
{
    switch (algo) {
    case PGPRPUBKEYALGO_RSA:
        ka->setmpi = pgprSetKeyMpiRSA;
        ka->free = pgprFreeKeyRSA;
        ka->mpis = 2;
        break;
    case PGPRPUBKEYALGO_DSA:
        ka->setmpi = pgprSetKeyMpiDSA;
        ka->free = pgprFreeKeyDSA;
        ka->mpis = 4;
        break;
    case PGPRPUBKEYALGO_ECDSA:
    case PGPRPUBKEYALGO_EDDSA:
	if (!pgprSupportedCurve(algo, curve))
	    break;
        ka->setmpi = pgprSetKeyMpiECC;
        ka->free = pgprFreeKeyECC;
        ka->mpis = 1;
        ka->curve = curve;
        ka->info = curve;
        break;
    default:
        break;
    }
}

void pgprDigAlgInitSignature(pgprDigAlg sa, int algo)
{
    switch (algo) {
    case PGPRPUBKEYALGO_RSA:
        sa->setmpi = pgprSetSigMpiRSA;
        sa->free = pgprFreeSigRSA;
        sa->verify = pgprVerifySigRSA;
        sa->mpis = 1;
        break;
    case PGPRPUBKEYALGO_DSA:
        sa->setmpi = pgprSetSigMpiDSA;
        sa->free = pgprFreeSigDSA;
        sa->verify = pgprVerifySigDSA;
        sa->mpis = 2;
        break;
    case PGPRPUBKEYALGO_ECDSA:
    case PGPRPUBKEYALGO_EDDSA:
        sa->setmpi = pgprSetSigMpiECC;
        sa->free = pgprFreeSigECC;
        sa->verify = pgprVerifySigECC;
        sa->mpis = 2;
        break;
    default:
        break;
    }
}

#ifndef PGPR_RPM_INTREE
int pgprInitCrypto(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}

int pgprFreeCrypto(void)
{
    return 0;
}

pgprDigCtx pgprDigestInit(int hashalgo)
{
    gcry_md_hd_t h = NULL;
    int gcryalgo = hashalgo2gcryalgo(hashalgo);
    if (!gcryalgo || gcry_md_open(&h, gcryalgo, 0) != 0)
	return NULL;
    return h;
}

int pgprDigestUpdate(pgprDigCtx ctx, const void * data, size_t len)
{
    gcry_md_hd_t h = ctx;
    if (!ctx)
	return -1;
    gcry_md_write(h, data, len);
    return 0;
}

int pgprDigestFinal(pgprDigCtx ctx, void ** datap, size_t *lenp)
{
    int gcryalgo;
    unsigned char *digest;
    unsigned int digestlen;
    gcry_md_hd_t h = ctx;
    
    if (!h || (gcryalgo = gcry_md_get_algo(h)) == 0)
	return -1;
    digestlen = gcry_md_get_algo_dlen(gcryalgo);
    if (digestlen == 0 || (digest = gcry_md_read(h, 0)) == NULL)
	return -1;
    if (lenp)
	*lenp = digestlen;
    if (datap)
	*datap = pgprMemdup(digest, digestlen);
    gcry_md_close(h);
    return 0;
}

pgprDigCtx pgprDigestDup(pgprDigCtx oldctx)
{
    gcry_md_hd_t oldh = oldctx;
    gcry_md_hd_t h = NULL;
    if (oldh && gcry_md_copy(&h, oldh) != 0)
	h = NULL;
    return h;
}

size_t pgprDigestLength(int hashalgo)
{
    int gcryalgo = hashalgo2gcryalgo(hashalgo);
    return gcryalgo ? gcry_md_get_algo_dlen(gcryalgo) : 0;
}
#endif
