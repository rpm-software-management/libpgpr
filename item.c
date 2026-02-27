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
	// if this is supposed to clear any potential sensitive cryptographic
	// data, then it will be better to rely on something like memset_c
	// available since C11.
	// if this is not for security then I guess this can be dropped.
	memset(item, 0, sizeof(*item));
	free(item);
    }
    return NULL;
}

/* compare data of two signatures or keys */
int pgprItemCmp(pgprItem p1, pgprItem p2)
{
    // shouldn't this have type pgprRC?
    int rc = 1; /* assume different, eg if either is NULL */
    if (p1 && p2) {
    // is this inconsistent indentation here and across the code base (mixed
    // tabs and spaces) intended?
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
	// this means if one item has a userid and the other has not, then the
	// result can still be "equal".
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
    // no NULL pointer check here?
    // since there are NULL pointer checks above I suppose it should be
    // consistent, therefore I'm mentioning them where they're missing.
    return item->keyid;
}

const uint8_t *pgprItemKeyFingerprint(pgprItem item, size_t *fp_len, int *fp_version)
{
    // also no NULL pointer check for `item`
    if (fp_len)
	*fp_len = item->fp_len;
    if (fp_version)
	*fp_version = item->fp_len ? item->fp_version : 0;
    return item->fp_len ? item->fp : NULL;
}

const char *pgprItemUserID(pgprItem item)
{
    // NULL pointer check missing
    return item->userid;
}

// mismatch between the uint8_t version type used in pgprTime and the `int`
// return here. was this intended for error indication (-1)?
int pgprItemVersion(pgprItem item)
{
    // NULL pointer check missing
    return item->version;
}

int64_t pgprItemCreationTime(pgprItem item)
{
    // NULL pointer check missing

    // this is a uint32_t in the item struct, but an int64_t return value.
    // this could benefit from a common typedef like pgpr_time_t;
    //
    // for error indication it can make sense not to mix errors and the actual
    // return value in all cases. it's good enough for enums, in this case it
    // might be better to use a dedicated error return type and an out
    // parameter for the actual time data.
    return item->time;
}

// mismatch between key_mtime uint32_t and int64_t return type here
int64_t pgprItemModificationTime(pgprItem item)
{
    // NULL pointer check
    return item->tag == PGPRTAG_PUBLIC_KEY ? item->key_mtime : 0;
}

int64_t pgprItemExpirationTime(pgprItem item)
{
    // NULL pointer check
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
    // so `headerlen` is not optional here, contrary to pgprItemKeyFingerprint()?
    // this should be harmonized so that API users can know what to expect.
    *headerlen = item->saltlen;
    return item->saltlen ? item->hash + item->hashlen : NULL;
}

const uint8_t *pgprItemHashTrailer(pgprItem item, size_t *trailerlen)
{
    if (!item || item->tag != PGPRTAG_SIGNATURE) {
	*trailerlen = 0;
	return NULL;
    }
    // non-optional parameter like above
    *trailerlen = item->hashlen;
    return item->hashlen ? item->hash : NULL;
}

