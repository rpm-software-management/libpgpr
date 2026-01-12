/*
 * Public Key merging
 */

#include <string.h>

#include "pgpr.h"
#include "pgpr_internal.h"


typedef struct pgprMergePkt_s {
    pgprPkt pkt;
    int source;

    /* signature data */
    pgprKeyID_t signid;
    uint32_t time;
    int selfsig;

    size_t hashlen;
    uint32_t hash;
    struct pgprMergePkt_s *next_hash;

    uint32_t section;
    uint32_t subsection;
    struct pgprMergePkt_s *next;
    struct pgprMergePkt_s *sub;
} pgprMergePkt;


#define PGP_NUMSECTIONS 3

typedef struct pgprMergeKey_s {
    pgprMergePkt *hash[512];
    pgprMergePkt *sections[PGP_NUMSECTIONS];
} pgprMergeKey;


/*
 *  PGP Packet plus merge information
 */

static inline uint32_t simplehash(uint32_t h, const uint8_t *data, size_t len)
{
    while (len--)
	h = (h << 3) + *data++;
    return h;
}

static uint32_t pgprMergePktCalcHash(pgprMergePkt *mp)
{
    uint32_t hash = simplehash(mp->pkt.tag, mp->pkt.body, mp->hashlen);
    if (mp->pkt.tag == PGPRTAG_SIGNATURE)
	hash = simplehash(hash, mp->signid, sizeof(pgprKeyID_t));
    return hash;
}

static int pgprMergePktIdentical(pgprMergePkt *mp1, pgprMergePkt *mp2)
{
    if (mp1->pkt.tag != mp2->pkt.tag)
	return 0;
    if (mp1->hashlen != mp2->hashlen)
	return 0;
    if (memcmp(mp1->pkt.body, mp2->pkt.body, mp1->hashlen) != 0)
	return 0;
    if (mp1->pkt.tag == PGPRTAG_SIGNATURE && memcmp(mp1->signid, mp2->signid, sizeof(pgprKeyID_t)) != 0)
	return 0;
    return 1;
}

static pgprRC pgprMergePktNew(pgprPkt *pkt, int source, pgprKeyID_t primaryid, pgprMergePkt **mpptr) {
    pgprRC rc = PGPR_OK;
    pgprMergePkt *mp = pgprCalloc(1, sizeof(pgprMergePkt));

    mp->pkt = *pkt;
    mp->source = source;
    mp->hashlen = pkt->blen;
    if (pkt->tag == PGPRTAG_SIGNATURE) {
        pgprItem sigitem = pgprItemNew(pkt->tag);
	rc = pgprPrtSigNoParams(pkt->tag, pkt->body, pkt->blen, sigitem);
	if (rc == PGPR_OK) {
	    mp->time = sigitem->time;
	    memcpy(mp->signid, sigitem->signid, sizeof(pgprKeyID_t));
	    if (primaryid && memcmp(primaryid, mp->signid, sizeof(pgprKeyID_t)) == 0)
		mp->selfsig = 1;
	    if (sigitem->version > 3 && sigitem->hashlen > 6)
		mp->hashlen = sigitem->hashlen - 6;	/* 6: size of trailer */
	}
	pgprItemFree(sigitem);
    }
    mp->hash = pgprMergePktCalcHash(mp);
    if (rc != PGPR_OK)
	free(mp);
    else
	*mpptr = mp;
    return rc;
}

static pgprMergePkt *pgprMergePktFree(pgprMergePkt *mp)
{
    free(mp);
    return NULL;
}


/*
 *  Pubkey data handling
 */

static pgprMergeKey *pgprMergeKeyNew(void) {
    pgprMergeKey *mk = pgprCalloc(1, sizeof(pgprMergeKey));
    return mk;
}

static pgprMergeKey *pgprMergeKeyFree(pgprMergeKey *mk) {
    if (mk) {
	pgprMergePkt *mp, *smp;
	int i;
	for (i = 0; i < PGP_NUMSECTIONS; i++) {
	    for (mp = mk->sections[i]; mp; mp = mp->next) {
		for (smp = mp->sub; smp; smp = smp->next)
		    pgprMergePktFree(smp);
		pgprMergePktFree(mp);
	    }
	}
    }
    return NULL;
}

static int pgprMergeKeyMaxSource(pgprMergeKey *mk) {
    pgprMergePkt *mp, *smp;
    int i, max = 0;
    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    if (mp->source > max)
		max = mp->source;
	    for (smp = mp->sub; smp; smp = smp->next)
		if (smp->source > max)
		    max = smp->source;
	}
    }
    return max;
}


static pgprMergePkt *pgprMergeKeyHashFind(pgprMergeKey *mk, pgprMergePkt *mp, int checksubsection) {
    int hh = mp->hash % (sizeof(mk->hash) / sizeof(*mk->hash));
    pgprMergePkt *h = mk->hash[hh];
    for (; h; h = h->next_hash)
	if (pgprMergePktIdentical(h, mp) && h->section == mp->section && (!checksubsection || h->subsection == mp->subsection))
	    break;
    return h;
}

static void pgprMergeKeyHashAdd(pgprMergeKey *mk, pgprMergePkt *mp) {
    int hh = mp->hash % (sizeof(mk->hash) / sizeof(*mk->hash));
    mp->next_hash = mk->hash[hh];
    mk->hash[hh] = mp;
}

static void pgprMergeKeySectionAdd(pgprMergeKey *mk, pgprMergePkt *mp) {
    pgprMergePkt **mpp = mk->sections + mp->section;
    mp->subsection = 0;
    while (*mpp) {
	mpp = &(*mpp)->next;
	mp->subsection++;
    }
    *mpp = mp;
}

static void pgprMergeKeySubAddSig(pgprMergePkt *mp_section, pgprMergePkt *mp) {
    pgprMergePkt *lastsig = NULL, **mpp, *mp2;
    for (mpp = &mp_section->sub; (mp2 = *mpp) != NULL; mpp = &mp2->next) {
	if (mp2->pkt.tag == PGPRTAG_SIGNATURE && mp2->selfsig == mp->selfsig) {
	    if (mp->time >= mp2->time)
		break;
	    lastsig = mp2;
	}
    }
    if (!*mpp) {
	if (lastsig) {
	    /* all the matched signatures are newer than us. put us right behind the last one */
	    mpp = &lastsig->next;
	} else if (mp->selfsig) {
	    /* first selfsig. add to front */
	    mpp = &mp_section->sub;
	}
    }
    mp->next = *mpp;
    *mpp = mp;
}

static void pgprMergeKeySubAdd(pgprMergePkt *mp_section, pgprMergePkt *mp) {
    /* signatures are ordered by creation time, everything else goes to the end */
    /* (we only change the order of new packets, i.e. where source is not zero) */
    if (mp->pkt.tag == PGPRTAG_SIGNATURE && mp->source != 0) {
	pgprMergeKeySubAddSig(mp_section, mp);
    } else {
	pgprMergePkt **mpp;
	for (mpp = &mp_section->sub; *mpp; mpp = &(*mpp)->next)
	    ;
	*mpp = mp;
    }
}

static pgprRC pgprMergeKeyAddPubkey(pgprMergeKey *mk, int source, const uint8_t * pkts, size_t pktlen) {
    pgprRC rc;
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgprPkt pkt;
    pgprKeyID_t mainkeyid;
    pgprMergePkt *mp_section = NULL;
    pgprMergePkt *mp, *omp;

    if (pgprDecodePkt(p, (pend - p), &pkt) != PGPR_OK)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPRTAG_PUBLIC_KEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    if ((rc = pgprGetKeyID(pkt.body, pkt.blen, mainkeyid)) != PGPR_OK)
	return rc;
    if ((rc = pgprMergePktNew(&pkt, source, mainkeyid, &mp)) != PGPR_OK)
	return rc;
    if (mk->sections[0]) {
	if (!pgprMergePktIdentical(mk->sections[0], mp)) {
	    pgprMergePktFree(mp);
	    return PGPR_ERROR_INTERNAL;
	}
	pgprMergePktFree(mp);
    } else {
	mk->sections[0] = mp;
	pgprMergeKeyHashAdd(mk, mp);
    }
    p += (pkt.body - pkt.head) + pkt.blen;

    mp_section = mk->sections[0];
    while (p < pend) {
	if (pgprDecodePkt(p, (pend - p), &pkt) != PGPR_OK) {
	    rc = PGPR_ERROR_CORRUPT_PGP_PACKET;
	    break;
	}
	if (pkt.tag == PGPRTAG_PUBLIC_KEY || pkt.tag == PGPRTAG_SECRET_KEY) {
	    rc = PGPR_ERROR_UNEXPECTED_PGP_PACKET;
	    break;
	}
	if ((rc = pgprMergePktNew(&pkt, source, mainkeyid, &mp)) != PGPR_OK)
	    break;
	if (pkt.tag == PGPRTAG_USER_ID || pkt.tag == PGPRTAG_USER_ATTRIBUTE || pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    mp->section = pkt.tag == PGPRTAG_PUBLIC_SUBKEY ? 2 : 1;
	    mp->subsection = -1;
	    omp = pgprMergeKeyHashFind(mk, mp, 0);
	    if (omp) {
		pgprMergePktFree(mp);
		mp_section = omp;
	    } else {
		pgprMergeKeySectionAdd(mk, mp);
		pgprMergeKeyHashAdd(mk, mp);
		mp_section = mp;
	    }
	} else {
	    mp->section = mp_section->section;
	    mp->subsection = mp_section->subsection;
	    omp = pgprMergeKeyHashFind(mk, mp, 1);
	    if (omp) {
		pgprMergePktFree(mp);
	    } else {
		pgprMergeKeySubAdd(mp_section, mp);
		pgprMergeKeyHashAdd(mk, mp);
	    }
	}
	p += (pkt.body - pkt.head) + pkt.blen;
    }
    if (rc == PGPR_OK && p != pend)
	rc = PGPR_ERROR_INTERNAL;
    return rc;
}

static pgprRC pgprMergeKeyConcat(pgprMergeKey *mk, uint8_t **pktsm, size_t *pktlenm)
{
    pgprMergePkt *mp, *smp;
    int i;
    uint8_t *pkts, *p;
    size_t len = 0;

    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    len += (mp->pkt.body - mp->pkt.head) + mp->pkt.blen;
	    for (smp = mp->sub; smp; smp = smp->next)
		len += (smp->pkt.body - smp->pkt.head) + smp->pkt.blen;
	}
    }
    p = pkts = pgprMalloc(len);
    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    memcpy(p, mp->pkt.head, (mp->pkt.body - mp->pkt.head) + mp->pkt.blen);
	    p += (mp->pkt.body - mp->pkt.head) + mp->pkt.blen;
	    for (smp = mp->sub; smp; smp = smp->next) {
		memcpy(p, smp->pkt.head, (smp->pkt.body - smp->pkt.head) + smp->pkt.blen);
		p += (smp->pkt.body - smp->pkt.head) + smp->pkt.blen;
	    }
	}
    }
    *pktsm = pkts;
    *pktlenm = len;
    return PGPR_OK;
}

pgprRC pgprMergeKeys(const uint8_t *pkts1, size_t pktlen1, const uint8_t *pkts2, size_t pktlen2, uint8_t **pktsm, size_t *pktlenm) {
    pgprRC rc;
    pgprMergeKey *mk = pgprMergeKeyNew();

    if (pkts1 != NULL && (rc = pgprMergeKeyAddPubkey(mk, 0, pkts1, pktlen1)) != PGPR_OK)
	goto exit;
    if ((rc = pgprMergeKeyAddPubkey(mk, 1, pkts2, pktlen2)) != PGPR_OK)
	goto exit;
    if (pgprMergeKeyMaxSource(mk) == 0) {
	/* no new key material, return old key */
	*pktsm = pgprMemdup(pkts1, pktlen1);
	*pktlenm = pktlen1;
    } else {
	rc = pgprMergeKeyConcat(mk, pktsm, pktlenm);
    }
exit:
    pgprMergeKeyFree(mk);
    return rc;
}

