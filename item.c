#include <stdarg.h>
#include <string.h>

#include "pgpr_internal.h"

pgprItem pgprItemNew(uint8_t tag)
{
    pgprItem item = pgprCalloc(1, sizeof(*item));
    if (item)
	item->tag = tag;
    return item;
}

pgprItem pgprItemFree(pgprItem item)
{
    if (item) {
	pgprAlgFree(item->alg);
	free(item->userid);
	free(item->hash);
	free(item->embedded_sig);
	memset(item, 0, sizeof(*item));
	free(item);
    }
    return NULL;
}

/* compare data of two signatures or keys */
int pgprItemCmp(pgprItem p1, pgprItem p2)
{
    int rc = 1; /* assume different, eg if either is NULL */
    if (p1 && p2) {
	/* XXX Should we compare something else too? */
	if (p1->tag != p2->tag)
	    goto exit;
	if (p1->hash_algo != p2->hash_algo)
	    goto exit;
	if (p1->pubkey_algo != p2->pubkey_algo)
	    goto exit;
	if (p1->version != p2->version)
	    goto exit;
	if (p1->sigtype != p2->sigtype)
	    goto exit;
	if (memcmp(p1->keyid, p2->keyid, sizeof(p1->keyid)) != 0)
	    goto exit;
	if (p1->userid && p2->userid && strcmp(p1->userid, p2->userid) != 0)
	    goto exit;

	/* Parameters match ... at least for our purposes */
	rc = 0;
    }
exit:
    return rc;
}

int pgprItemTag(pgprItem item)
{
    return item ? item->tag : -1;
}

int pgprItemSignatureType(pgprItem item)
{
    return item && item->tag == PGPRTAG_SIGNATURE ? item->sigtype : -1;
}

int pgprItemPubkeyAlgo(pgprItem item)
{
    return item ? item->pubkey_algo : -1;
}

int pgprItemHashAlgo(pgprItem item)
{
    return item && item->tag == PGPRTAG_SIGNATURE ? item->hash_algo : -1;
}

int pgprItemPubkeyAlgoInfo(pgprItem item)
{
    return item && item->alg ? item->alg->info : -1;
}

const uint8_t *pgprItemKeyID(pgprItem item)
{
    return item->keyid;
}

const uint8_t *pgprItemKeyFingerprint(pgprItem item, size_t *fp_len, int *fp_version)
{
    if (fp_len)
	*fp_len = item->fp_len;
    if (fp_version)
	*fp_version = item->fp_len ? item->fp_version : 0;
    return item->fp_len ? item->fp : NULL;
}

const char *pgprItemUserID(pgprItem item)
{
    return item->userid;
}

int pgprItemVersion(pgprItem item)
{
    return item->version;
}

int64_t pgprItemCreationTime(pgprItem item)
{
    return item->time;
}

int64_t pgprItemModificationTime(pgprItem item)
{
    return item->tag == PGPRTAG_PUBLIC_KEY ? item->key_mtime : 0;
}

int64_t pgprItemExpirationTime(pgprItem item)
{
    if (item->tag == PGPRTAG_SIGNATURE) {
	if (!(item->saved & PGPRITEM_SAVED_SIG_EXPIRE) || item->sig_expire == 0)
	    return 0;
	return item->time + item->sig_expire;
    }
    if (item->tag == PGPRTAG_PUBLIC_KEY || item->tag == PGPRTAG_PUBLIC_SUBKEY) {
	if (!(item->saved & PGPRITEM_SAVED_KEY_EXPIRE) || item->key_expire == 0)
	    return 0;
	return item->time + item->key_expire;
    }
    return 0;
}

const uint8_t *pgprItemHashHeader(pgprItem item, size_t *headerlen)
{
    if (!item || item->tag != PGPRTAG_SIGNATURE) {
	*headerlen = 0;
	return NULL;
    }
    *headerlen = item->saltlen;
    return item->saltlen ? item->hash + item->hashlen : NULL;
}

const uint8_t *pgprItemHashTrailer(pgprItem item, size_t *trailerlen)
{
    if (!item || item->tag != PGPRTAG_SIGNATURE) {
	*trailerlen = 0;
	return NULL;
    }
    *trailerlen = item->hashlen;
    return item->hashlen ? item->hash : NULL;
}

