#include <string.h>
#include <stdarg.h>

#include "pgpr_internal.h"

pgprAlg pgprAlgNew(void)
{
    pgprAlg alg;
    alg = pgprCalloc(1, sizeof(*alg));
    if (alg) {
	alg->mpis = -1;
	alg->setup_rc = PGPR_ERROR_INTERNAL;
    }
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


/****************************** Hybrid **************************************/

struct pgprAlgSigHybrid_s {
    pgprAlg mldsa;
    pgprAlg eddsa;
};

struct pgprAlgKeyHybrid_s {
    pgprAlg mldsa;
    pgprAlg eddsa;
};

static pgprRC pgprSetSigMpiHybrid(pgprAlg sa, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgSigHybrid_s *sig = sa->data;
    pgprRC rc = PGPR_ERROR_REJECTED_SIGNATURE;
    int mldsaalgo = 0, eddsaalgo = 0, mldsasize = 0, eddsasize = 0;
    if (num != -1)
	return rc;
    if (!sig)
	sig = sa->data = pgprCalloc(1, sizeof(*sig));
    if (!sig)
	return PGPR_ERROR_NO_MEMORY;

    switch (sa->algo) {
	case PGPRPUBKEYALGO_MLDSA65_ED25519:
	    eddsasize = 64;
	    mldsasize = 3309;
	    eddsaalgo = PGPRPUBKEYALGO_ED25519;
	    mldsaalgo = PGPRPUBKEYALGO_INTERNAL_MLDSA65;
	    break;
	case PGPRPUBKEYALGO_MLDSA87_ED448:
	    eddsasize = 114;
	    mldsasize = 4627;
	    eddsaalgo = PGPRPUBKEYALGO_ED448;
	    mldsaalgo = PGPRPUBKEYALGO_INTERNAL_MLDSA87;
	    break;
	default:
	    break;
    }
    if (!eddsasize || !mldsasize || mlen != eddsasize + mldsasize || !eddsaalgo || !mldsaalgo)
	return rc;

    sig->eddsa = pgprAlgNew();
    if (!sig->eddsa)
	return PGPR_ERROR_NO_MEMORY;
    if ((rc = pgprAlgSetupSignature(sig->eddsa, eddsaalgo, p, p + eddsasize)) != PGPR_OK)
	return rc;
    sig->mldsa = pgprAlgNew();
    if (!sig->mldsa)
	return PGPR_ERROR_NO_MEMORY;
    if ((rc = pgprAlgSetupSignature(sig->mldsa, mldsaalgo, p + eddsasize, p + eddsasize + mldsasize)) != PGPR_OK)
	return rc;
    return PGPR_OK;
}

static pgprRC pgprSetKeyMpiHybrid(pgprAlg ka, int num, const uint8_t *p, int mlen)
{
    struct pgprAlgKeyHybrid_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_REJECTED_PUBKEY;
    int mldsaalgo = 0, eddsaalgo = 0, mldsasize = 0, eddsasize = 0;
    if (num != -1)
	return rc;
    if (!key)
	key = ka->data = pgprCalloc(1, sizeof(*key));
    if (!key)
	return PGPR_ERROR_NO_MEMORY;

    switch (ka->algo) {
	case PGPRPUBKEYALGO_MLDSA65_ED25519:
	    eddsasize = 32;
	    mldsasize = 1952;
	    eddsaalgo = PGPRPUBKEYALGO_ED25519;
	    mldsaalgo = PGPRPUBKEYALGO_INTERNAL_MLDSA65;
	    break;
	case PGPRPUBKEYALGO_MLDSA87_ED448:
	    eddsasize = 57;
	    mldsasize = 2592;
	    eddsaalgo = PGPRPUBKEYALGO_ED448;
	    mldsaalgo = PGPRPUBKEYALGO_INTERNAL_MLDSA87;
	    break;
	default:
	    break;
    }
    if (!eddsasize || !mldsasize || mlen != eddsasize + mldsasize || !eddsaalgo || !mldsaalgo)
	return rc;

    key->eddsa = pgprAlgNew();
    if (!key->eddsa)
	return PGPR_ERROR_NO_MEMORY;
    if ((rc = pgprAlgSetupPubkey(key->eddsa, eddsaalgo, 0, p, p + eddsasize)) != PGPR_OK)
	return rc;
    key->mldsa = pgprAlgNew();
    if (!key->mldsa)
	return PGPR_ERROR_NO_MEMORY;
    if ((rc = pgprAlgSetupPubkey(key->mldsa, mldsaalgo, 0, p + eddsasize, p + eddsasize + mldsasize)) != PGPR_OK)
	return rc;
    return PGPR_OK;
}

static void pgprFreeSigHybrid(pgprAlg sa)
{
    struct pgprAlgSigHybrid_s *sig = sa->data;
    if (sig) {
        pgprAlgFree(sig->mldsa);
        pgprAlgFree(sig->eddsa);
	free(sig);
    }
}

static void pgprFreeKeyHybrid(pgprAlg sa)
{
    struct pgprAlgKeyHybrid_s *key = sa->data;
    if (key) {
        pgprAlgFree(key->mldsa);
        pgprAlgFree(key->eddsa);
	free(key);
    }
}

static pgprRC pgprVerifySigHybrid(pgprAlg sa, pgprAlg ka, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgprAlgSigHybrid_s *sig = sa->data;
    struct pgprAlgKeyHybrid_s *key = ka->data;
    pgprRC rc = PGPR_ERROR_BAD_SIGNATURE;	/* assume failure */

    if (sig && sig->mldsa && sig->eddsa && sig->mldsa->verify && sig->eddsa->verify && key && key->mldsa && key->eddsa) {
	rc = sig->eddsa->verify(sig->eddsa, key->eddsa, hash, hashlen, hash_algo);
	if (rc == PGPR_OK)
	    rc = sig->mldsa->verify(sig->mldsa, key->mldsa, hash, hashlen, hash_algo);
    }
    return rc;
}

pgprRC pgprInitSigHybrid(pgprAlg sa)
{
    sa->setmpi = pgprSetSigMpiHybrid;
    sa->free = pgprFreeSigHybrid;
    sa->verify = pgprVerifySigHybrid;
    sa->mpis = 0;
    return PGPR_OK;
}

pgprRC pgprInitKeyHybrid(pgprAlg ka)
{
    ka->setmpi = pgprSetKeyMpiHybrid;
    ka->free = pgprFreeKeyHybrid;
    ka->mpis = 0;
    return PGPR_OK;
}


/****************************** mpi setup **************************************/

static inline int pgprMpiLen(const uint8_t *p)
{
    int mpi_bits = (p[0] << 8) | p[1];
    return 2 + ((mpi_bits + 7) >> 3);
}

static pgprRC pgprAlgProcessMpis(pgprAlg alg, const int mpis, const uint8_t *p, const uint8_t *const pend)
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

pgprRC pgprAlgSetupPubkey(pgprAlg alg, int algo, int curve, const uint8_t *p, const uint8_t *const pend)
{
    pgprRC rc;
    alg->algo = algo;
    alg->curve = curve;
    rc = pgprAlgInitPubkey(alg);
    if (rc == PGPR_OK)
	rc = pgprAlgProcessMpis(alg, alg->mpis, p, pend);
    alg->setup_rc = rc;
    return rc;
}

pgprRC pgprAlgSetupSignature(pgprAlg alg, int algo, const uint8_t *p, const uint8_t *const pend)
{
    pgprRC rc;
    alg->algo = algo;
    rc = pgprAlgInitSignature(alg);
    if (rc == PGPR_OK)
	rc = pgprAlgProcessMpis(alg, alg->mpis, p, pend);
    alg->setup_rc = rc;
    return rc;
}


pgprRC pgprAlgVerify(pgprAlg sigalg, pgprAlg keyalg, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    if (!sigalg || !keyalg || !hashlen)
	return PGPR_ERROR_INTERNAL;
    if (sigalg->setup_rc != PGPR_OK)
	return sigalg->setup_rc;
    if (keyalg->setup_rc != PGPR_OK)
	return keyalg->setup_rc;
    if (!sigalg->verify)
	return PGPR_ERROR_INTERNAL;
    return sigalg->verify(sigalg, keyalg, hash, hashlen, hash_algo);
}

