/** \ingroup rpmio signature
 * \file rpmapi.c
 * Rpm glue code for the PGP functions
 */

#include "system.h"
#include <rpm/rpmpgp.h>

#include "pgpr.h"

/* forward declaration for functions missing in some versions of rpmpgp.h */
extern uint32_t pgpDigParamsModificationTime(pgpDigParams digp);

extern int pgpDigParamsSalt(pgpDigParams digp, const uint8_t **datap, size_t *lenp);

/* forward declarations for internal function implemented by rpm */
RPM_GNUC_INTERNAL
void *pgprMalloc(size_t size);

RPM_GNUC_INTERNAL
void *pgprRealloc(void * ptr, size_t size);

RPM_GNUC_INTERNAL
void *pgprCalloc(size_t nmemb, size_t size);


pgpDigParams pgpDigParamsFree(pgpDigParams digp)
{
    return (pgpDigParams)pgprItemFree((pgprItem)digp);
}

int pgpDigParamsCmp(pgpDigParams p1, pgpDigParams p2)
{
    return pgprItemCmp((pgprItem)p1, (pgprItem)p2);
}

int pgpSignatureType(pgpDigParams digp)
{
    return pgprItemSignatureType((pgprItem)digp);
}

unsigned int pgpDigParamsAlgo(pgpDigParams digp, unsigned int algotype)
{
    int algo = 0;
    if (digp && algotype == PGPVAL_PUBKEYALGO)
	algo = pgprItemPubkeyAlgo((pgprItem)digp);
    if (digp && algotype == PGPVAL_HASHALGO)
	algo = pgprItemHashAlgo((pgprItem)digp);
    return algo < 0 ? 0 : (unsigned int)algo;
}

const uint8_t *pgpDigParamsSignID(pgpDigParams digp)
{
    return pgprItemKeyID((pgprItem)digp);
}

const char *pgpDigParamsUserID(pgpDigParams digp)
{
    return pgprItemUserID((pgprItem)digp);
}

int pgpDigParamsVersion(pgpDigParams digp)
{
    return pgprItemVersion((pgprItem)digp);
}

uint32_t pgpDigParamsCreationTime(pgpDigParams digp)
{
    return pgprItemCreationTime((pgprItem)digp);
}

uint32_t pgpDigParamsModificationTime(pgpDigParams digp)
{
    return pgprItemModificationTime((pgprItem)digp);
}

int pgpDigParamsSalt(pgpDigParams _digp, const uint8_t **datap, size_t *lenp)
{
    pgprItem sig = (pgprItem)_digp;
    const uint8_t *header;
    size_t headerlen;

    if(!sig || !datap || !lenp || pgprItemTag(sig) != PGPRTAG_SIGNATURE)
        return -1;
    *datap = NULL;
    *lenp = 0;
    header = pgprItemHashHeader(sig, &headerlen);
    if (header && headerlen) {
	*datap = memcpy(rmalloc(headerlen), header, headerlen);
	*lenp = headerlen;
    }
    return 0;
}

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    rpmRC res = RPMRC_FAIL;
    pgprRC rc;
    DIGEST_CTX ctx;
    uint8_t *hash = NULL;
    size_t hashlen = 0;
    const uint8_t *trailer = NULL;
    size_t trailerlen = 0;
    int sigtype;

    if (lints)
        *lints = NULL;

    if (!sig || pgprItemTag((pgprItem)sig) != PGPTAG_SIGNATURE)
	goto exit;
    sigtype = pgprItemSignatureType((pgprItem)sig);
    if (sigtype != PGPRSIGTYPE_BINARY && sigtype != PGPRSIGTYPE_TEXT && sigtype != PGPRSIGTYPE_STANDALONE)
	goto exit;

    /* hash trailer */
    ctx = rpmDigestDup(hashctx);
    if (!ctx)
	goto exit;
    trailer = pgprItemHashTrailer((pgprItem)sig, &trailerlen);
    if (trailer != NULL)
	rpmDigestUpdate(ctx, trailer, trailerlen);
    rpmDigestFinal(ctx, (void **)&hash, &hashlen, 0);

    if (key) {
	rc = pgprVerifySignature((pgprItem)key, (pgprItem)sig, hash, hashlen, lints);
    } else {
	rc = pgprVerifySignatureNoKey((pgprItem)key, hash, hashlen, lints);
	if (rc == PGPR_OK) {
	    res = RPMRC_NOKEY;
	    goto exit;
	}
    }
    switch (rc) {
    case PGPR_OK:
	res = RPMRC_OK;
	break;
    case PGPR_ERROR_PRIMARY_REVOKED:
    case PGPR_ERROR_KEY_REVOKED:
    case PGPR_ERROR_KEY_NOT_VALID:
    case PGPR_ERROR_KEY_NO_SIGNING:
    case PGPR_ERROR_KEY_CREATED_AFTER_SIG:
    case PGPR_ERROR_KEY_EXPIRED:
	res = RPMRC_NOTTRUSTED;
	break;
    default:
	break;
    }

exit:
    free(hash);
    return res;
}

rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    return pgpVerifySignature2(key, sig, hashctx, NULL);
}

int pgpPrtParams2(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret, char **lints)
{
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;	/* assume failure */
    pgprItem item = NULL;
    int tag;

    if (lints)
        *lints = NULL;
    if (!pkts || pktlen == 0 || (*pkts & 0x80) == 0) {
	if (lints)
	    *lints = rstrdup("Corrupt PGP packet");
	return -1;
    }
    tag = *pkts & 0x40 ? (*pkts & 0x3f) : ((*pkts >> 2) & 0x0f);
    rc = PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    if (pkttype && tag != pkttype) {
	if (lints)
	    *lints = rstrdup("Unexpected PGP packet");
	return -1;
    }
    if (tag == PGPTAG_PUBLIC_KEY) {
	rc = pgprPubkeyParse(pkts, pktlen, &item, lints);
    } else if (tag == PGPTAG_SIGNATURE) {
	rc = pgprSignatureParse(pkts, pktlen, &item, lints);
    } else {
	if (lints)
	    *lints = rstrdup("Not a public key or signature");
	return -1;
    }
    if (ret && rc == PGPR_OK)
	*ret = (pgpDigParams)item;
    else {
	pgprItemFree(item);
    }
    return rc == PGPR_OK ? 0 : -1;
}

int pgpPrtParams(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
                  pgpDigParams * ret)
{
    return pgpPrtParams2(pkts, pktlen, pkttype, ret, NULL);
}

int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount)
{
    pgprRC rc = pgprPubkeyParseSubkeys(pkts, pktlen, (pgprItem)mainkey, (pgprItem **)subkeys, subkeysCount);
    return rc == PGPR_OK ? 0 : -1;
}

rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation)
{
    pgprItem item = NULL;
    pgprRC rc = pgprPubkeyParse(pkts, pktslen, &item, explanation);
    pgprItemFree(item);
    return rc == PGPR_OK ? RPMRC_OK : RPMRC_FAIL;
}

int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    return pgprPubkeyCertLen(pkts, pktslen, certlen) == PGPR_OK ? 0 : -1;
}

int pgpPubkeyKeyID(const uint8_t * pkts, size_t pktslen, pgpKeyID_t keyid)
{
    return pgprPubkeyKeyID(pkts, pktslen, keyid) == PGPR_OK ? 0 : -1;
}

int pgpPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    return pgprPubkeyFingerprint(pkts, pktslen, fp, fplen, NULL) == PGPR_OK ? 0 : -1;
}

rpmRC pgpPubkeyMerge(const uint8_t *pkts1, size_t pkts1len, const uint8_t *pkts2, size_t pkts2len, uint8_t **pktsm, size_t *pktsmlen, int flags)
{
    pgprRC rc = pgprPubkeyMerge(pkts1, pkts1len, pkts2, pkts2len, pktsm, pktsmlen);
    return rc == PGPR_OK ? RPMRC_OK : RPMRC_FAIL;
}

char *pgpArmorWrap(int atype, const unsigned char * s, size_t ns)
{
    static const char *keys = "Version: rpm-" VERSION"\n";
    pgprRC rc = PGPR_OK;
    char *armor = NULL;

    if (atype == PGPARMOR_PUBKEY)
	rc = pgprArmorWrap("PUBLIC KEY BLOCK", keys, s, ns, &armor);
    else if (atype == PGPARMOR_SIGNATURE)
	rc = pgprArmorWrap("SIGNATURE", keys, s, ns, &armor);
    else
	return NULL;	/* only public key & signature supported */
    return rc == PGPR_OK ? armor : NULL;
}

pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen)
{
    pgpArmor ec = PGPARMOR_ERR_NO_BEGIN_PGP;	/* XXX assume failure */
    if (armor && strlen(armor) > 0) {
	pgprRC rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", armor, pkt, pktlen);
	if (rc == PGPR_OK)
	    ec = PGPARMOR_PUBKEY;
	else if (rc == PGPR_ERROR_ARMOR_NO_END_PGP)
	    ec = PGPARMOR_ERR_NO_END_PGP;
	else if (rc == PGPR_ERROR_ARMOR_CRC_CHECK)
	    ec = PGPARMOR_ERR_CRC_CHECK;
	else if (rc == PGPR_ERROR_ARMOR_BODY_DECODE)
	    ec = PGPARMOR_ERR_BODY_DECODE;
	else if (rc == PGPR_ERROR_ARMOR_CRC_DECODE)
	    ec = PGPARMOR_ERR_CRC_DECODE;
    }
    return ec;
}

/* functions implemented by rpm */

void *pgprMalloc(size_t size)
{
    return rmalloc(size);
}

void *pgprRealloc(void * ptr, size_t size)
{
    return rrealloc(ptr, size);
}

void *pgprCalloc(size_t nmemb, size_t size)
{
    return rcalloc(nmemb, size);
}

pgprRC pgprDigestInit(int hashalgo, pgprDigCtx *ret)
{
    /* might need to map from pgp hash algo to rpm hash algo in the future */
    *ret = rpmDigestInit(hashalgo, RPMDIGEST_NONE);
    return *ret ? PGPR_OK : PGPR_ERROR_UNSUPPORTED_DIGEST;
}

pgprRC pgprDigestUpdate(pgprDigCtx ctx,  const void *data, size_t len)
{
    return rpmDigestUpdate(ctx, data, len) == 0 ? PGPR_OK : PGPR_ERROR_INTERNAL;
}

pgprRC pgprDigestFinal(pgprDigCtx ctx, void ** datap, size_t * lenp)
{
    return rpmDigestFinal(ctx, datap, lenp, 0) == 0 ? PGPR_OK : PGPR_ERROR_INTERNAL;
}

size_t pgprDigestLength(int hashalgo)
{
    return rpmDigestLength(hashalgo);
}

