#include <string.h>
#include <stdarg.h>

#include "pgpr_internal.h"

pgprAlg pgprAlgNew(void)
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

pgprRC pgprAlgProcessMpis(pgprAlg alg, const int mpis,
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

pgprRC pgprAlgVerify(pgprAlg sigalg, pgprAlg keyalg, const uint8_t *hash, size_t hashlen, int hash_algo)
{
    if (!sigalg || !sigalg || !sigalg->verify || !hashlen)
	return PGPR_ERROR_INTERNAL;
    return sigalg->verify(sigalg, keyalg, hash, hashlen, hash_algo);
}

