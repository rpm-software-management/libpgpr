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
	free(item);
    }
    return NULL;
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
    return item ? item->keyid : NULL;
}

const uint8_t *pgprItemKeyFingerprint(pgprItem item, size_t *fp_len, int *fp_version)
{
    *fp_len = item ? item->fp_len : 0;
    if (fp_version)
	*fp_version = item && item->fp_len ? item->fp_version : 0;
    return item && item->fp_len ? item->fp : NULL;
}

const char *pgprItemUserID(pgprItem item)
{
    return item ? item->userid : NULL;
}

int pgprItemVersion(pgprItem item)
{
    return item ? item->version : 0;
}

int64_t pgprItemCreationTime(pgprItem item)
{
    return item ? item->time : 0;
}

int64_t pgprItemModificationTime(pgprItem item)
{
    return item && item->tag == PGPRTAG_PUBLIC_KEY ? item->key_mtime : 0;
}

int64_t pgprItemExpirationTime(pgprItem item)
{
    if (!item)
	return 0;
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

