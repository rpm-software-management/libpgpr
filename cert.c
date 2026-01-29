/*
 * Parse a certificate
 */

#include <string.h>

#include "pgpr_internal.h"

static pgprRC hashKey(pgprDigCtx ctx, const pgprPkt *pkt, int exptag, int version)
{
    pgprRC rc = PGPR_ERROR_INTERNAL;
    if (pkt && pkt->tag == exptag) {
	if (version == 3 || version == 4) {
	    uint8_t head[] = {
		0x99,
		(pkt->blen >> 8),
		(pkt->blen     ),
	    };
	    pgprDigestUpdate(ctx, head, 3);
	} else if (version == 5 || version == 6) {
	    uint8_t head[] = {
		version == 5 ? 0x9a : 0x9b,
		(pkt->blen >> 24),
		(pkt->blen >> 16),
		(pkt->blen >> 8),
		(pkt->blen     ),
	    };
	    pgprDigestUpdate(ctx, head, 5);
	}
	pgprDigestUpdate(ctx, pkt->body, pkt->blen);
	rc = PGPR_OK;
    }
    return rc;
}

static pgprRC hashUserID(pgprDigCtx ctx, const pgprPkt *pkt, int exptag, int version)
{
    pgprRC rc = PGPR_ERROR_INTERNAL;
    if (pkt && pkt->tag == exptag) {
	if (version == 4 || version == 5 || version == 6) {
	    uint8_t head[] = {
		exptag == PGPRTAG_USER_ID ? 0xb4 : 0xd1,
		(pkt->blen >> 24),
		(pkt->blen >> 16),
		(pkt->blen >>  8),
		(pkt->blen      ),
	    };
	    pgprDigestUpdate(ctx, head, 5);
	} else if (version != 3)
	    return rc;
	pgprDigestUpdate(ctx, pkt->body, pkt->blen);
	rc = PGPR_OK;
    }
    return rc;
}

static pgprRC pgprVerifySelfSig(pgprItem key, pgprItem selfsig,
			const pgprPkt *mainpkt, const pgprPkt *sectionpkt)
{
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;
    pgprDigCtx ctx = NULL;
    uint8_t *hash = NULL;
    size_t hashlen = 0;

    if (pgprDigestInit(selfsig->hash_algo, &ctx) != PGPR_OK)
	return rc;

    /* hash header */
    if (selfsig->saltlen)
	pgprDigestUpdate(ctx, selfsig->hash + selfsig->hashlen, selfsig->saltlen);

    switch (selfsig->sigtype) {
    case PGPRSIGTYPE_SUBKEY_BINDING:
    case PGPRSIGTYPE_SUBKEY_REVOKE:
    case PGPRSIGTYPE_PRIMARY_BINDING:
	rc = hashKey(ctx, mainpkt, PGPRTAG_PUBLIC_KEY, selfsig->version);
	if (rc == PGPR_OK)
	    rc = hashKey(ctx, sectionpkt, PGPRTAG_PUBLIC_SUBKEY, selfsig->version);
	break;
    case PGPRSIGTYPE_GENERIC_CERT:
    case PGPRSIGTYPE_PERSONA_CERT:
    case PGPRSIGTYPE_CASUAL_CERT:
    case PGPRSIGTYPE_POSITIVE_CERT:
    case PGPRSIGTYPE_CERT_REVOKE:
	rc = hashKey(ctx, mainpkt, PGPRTAG_PUBLIC_KEY, selfsig->version);
	if (rc == PGPR_OK)
	    rc = hashUserID(ctx, sectionpkt, sectionpkt->tag == PGPRTAG_USER_ATTRIBUTE ? PGPRTAG_USER_ATTRIBUTE : PGPRTAG_USER_ID, selfsig->version);
	break;
    case PGPRSIGTYPE_SIGNED_KEY:
    case PGPRSIGTYPE_KEY_REVOKE:
	rc = hashKey(ctx, mainpkt, PGPRTAG_PUBLIC_KEY, selfsig->version);
	break;
    default:
	break;
    }
    /* hash trailer */
    if (selfsig->hash)
	pgprDigestUpdate(ctx, selfsig->hash, selfsig->hashlen);
    pgprDigestFinal(ctx, (void **)&hash, &hashlen);

    if (rc == PGPR_OK) {
	if (!key)
	    rc = PGPR_ERROR_INTERNAL;
	else
	    rc = pgprVerifySignatureRaw(key, selfsig, hash, hashlen);
	if (rc == PGPR_ERROR_BAD_SIGNATURE)
	    rc = PGPR_ERROR_SELFSIG_VERIFICATION;
    }
    free(hash);
    return rc;
}

static pgprRC verifyPrimaryBindingSig(pgprPkt *mainpkt, pgprPkt *subkeypkt, pgprItem subkey, pgprItem bindsig)
{
    pgprItem emb = NULL;
    pgprPkt sigpkt;
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;		/* assume failure */
    if (!bindsig || !bindsig->embedded_sig)
	return rc;
    sigpkt.tag = PGPRTAG_SIGNATURE;
    sigpkt.body = bindsig->embedded_sig;
    sigpkt.blen = bindsig->embedded_sig_len;
    emb = pgprItemNew(sigpkt.tag);
    if (!emb)
	return PGPR_ERROR_NO_MEMORY;
    if (pgprParseSig(&sigpkt, emb) == PGPR_OK) {
	if (emb->sigtype == PGPRSIGTYPE_PRIMARY_BINDING)
	    rc = pgprVerifySelfSig(subkey, emb, mainpkt, subkeypkt);
    }
    emb = pgprItemFree(emb);
    return rc;
}

static int is_same_keyid(pgprItem item1, pgprItem item2)
{
    return (item1->saved & item2->saved & PGPRITEM_SAVED_ID) != 0 &&
	memcmp(item1->keyid, item2->keyid, sizeof(item1->keyid)) == 0;
}

/* Parse a complete pubkey with all associated packets (also called "transferable pubkey") */
/* This is similar to gnupg's merge_selfsigs_main() function */
pgprRC pgprParseCertificate(const uint8_t * pkts, size_t pktslen, pgprItem item)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    pgprItem sig = NULL;
    pgprItem newest_sig = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    uint32_t key_expire_sig_time = 0;
    uint32_t key_flags_sig_time = 0;
    pgprPkt mainpkt, sectionpkt;
    int haveselfsig;
    uint32_t now = 0;

    /* parse the main pubkey */
    if (pktslen > PGPR_MAX_OPENPGP_BYTES)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pgprDecodePkt(p, (pend - p), &mainpkt) != PGPR_OK)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPRTAG_PUBLIC_KEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    /* Parse the pubkey packet */
    if ((rc = pgprParseKey(&mainpkt, item)) != PGPR_OK)
	return rc;
    sectionpkt = mainpkt;
    haveselfsig = 1;
    item->key_mtime = item->time;

    rc = PGPR_OK;
    while (rc == PGPR_OK) {
	pgprPkt pkt;

	if (p < pend) {
	    if (pgprDecodePkt(p, (pend - p), &pkt)) {
		rc = PGPR_ERROR_CORRUPT_PGP_PACKET;
		break;
	    }
	    if (pkt.tag == PGPRTAG_PUBLIC_KEY || pkt.tag == PGPRTAG_SECRET_KEY) {
		rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		break;	/* start of another public key, error out */
	    }
	} else {
	    pkt.tag = 0;
	}

	/* did we end a direct/userid/subkey section? */
	if (p == pend || pkt.tag == PGPRTAG_USER_ID || pkt.tag == PGPRTAG_USER_ATTRIBUTE || pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    /* return an error if there was no self-sig at all */
	    if (!haveselfsig) {
		rc = PGPR_ERROR_MISSING_SELFSIG;
		break;
	    }
	    /* take the data from the newest signature */
	    if (newest_sig && (sectionpkt.tag == PGPRTAG_USER_ID || sectionpkt.tag == PGPRTAG_PUBLIC_KEY) && newest_sig->sigtype != PGPRSIGTYPE_CERT_REVOKE) {
		item->saved |= PGPRITEM_SAVED_VALID;	/* we have a valid binding sig */
		if ((newest_sig->saved & PGPRITEM_SAVED_KEY_EXPIRE) != 0) {
		    if ((!key_expire_sig_time || newest_sig->time > key_expire_sig_time)) {
			item->key_expire = newest_sig->key_expire;
			item->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
			key_expire_sig_time = newest_sig->time;
			if (newest_sig->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_expire_sig_time = 0xffffffffU;	/* expires from the direct signatures are final */
		    }
		}
		if ((newest_sig->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0) {
		    if ((!key_flags_sig_time || newest_sig->time > key_flags_sig_time)) {
			item->key_flags = newest_sig->key_flags;
			item->saved |= PGPRITEM_SAVED_KEY_FLAGS;
			key_flags_sig_time = newest_sig->time;
			if (newest_sig->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_flags_sig_time = 0xffffffffU;	/* key flags from the direct signatures are final */
		    }
		}
		if (sectionpkt.tag == PGPRTAG_USER_ID) {
		    if (!item->userid || ((newest_sig->saved & PGPRITEM_SAVED_PRIMARY) != 0 && (item->saved & PGPRITEM_SAVED_PRIMARY) == 0)) {
			if ((rc = pgprParseUserID(&sectionpkt, item)) != PGPR_OK)
			    break;
			if ((newest_sig->saved & PGPRITEM_SAVED_PRIMARY) != 0)
			    item->saved |= PGPRITEM_SAVED_PRIMARY;
		    }
		}
	    }
	    newest_sig = pgprItemFree(newest_sig);
	}

	if (p == pend)
	    break;	/* all packets processed */

	if (pkt.tag == PGPRTAG_SIGNATURE) {
	    int isselfsig, needsig = 0;
	    sig = pgprItemNew(pkt.tag);
	    if (!sig) {
		rc = PGPR_ERROR_NO_MEMORY;
		break;
	    }
	    /* use the NoParams variant because we want to ignore non self-sigs */
	    if ((rc = pgprParseSigNoParams(&pkt, sig)) != PGPR_OK)
		break;
	    isselfsig = is_same_keyid(item, sig);

	    /* check if we understand this signature type and make sure it is in the right section */
	    if (sig->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		needsig = 1;
	    } else if (sig->sigtype == PGPRSIGTYPE_SUBKEY_BINDING || sig->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_SUBKEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = 1;
	    } else if (sig->sigtype == PGPRSIGTYPE_SIGNED_KEY) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_KEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
	    } else if (sig->sigtype == PGPRSIGTYPE_GENERIC_CERT || sig->sigtype == PGPRSIGTYPE_PERSONA_CERT || sig->sigtype == PGPRSIGTYPE_CASUAL_CERT || sig->sigtype == PGPRSIGTYPE_POSITIVE_CERT || sig->sigtype == PGPRSIGTYPE_CERT_REVOKE) {
		if (sectionpkt.tag != PGPRTAG_USER_ID && sectionpkt.tag != PGPRTAG_USER_ATTRIBUTE) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
		/* note that cert revokations get overwritten by newer certifications (like in gnupg) */
	    }

	    /* verify self signature if we need it */
	    if (needsig) {
		if (!isselfsig) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;
		}
		/* add MPIs so we can verify */
	        if ((rc = pgprParseSigParams(&pkt, sig)) != PGPR_OK)
		    break;
		if ((rc = pgprVerifySelfSig(item, sig, &mainpkt, &sectionpkt)) != PGPR_OK)
		    break;		/* verification failed */
		if (sig->sigtype != PGPRSIGTYPE_KEY_REVOKE)
		    haveselfsig = 1;
		if (sig->time > item->key_mtime)
		    item->key_mtime = sig->time;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sig->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sig->time || sig->sig_expire < now - sig->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle key revokations right away */
	    if (needsig && sig->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		item->revoked = 1;				/* this is final */
		item->saved |= PGPRITEM_SAVED_VALID;		/* we have at least one correct self-sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_sig || sig->time >= newest_sig->time)) {
		newest_sig = pgprItemFree(newest_sig);
		newest_sig = sig;
		sig = NULL;
	    }
	    sig = pgprItemFree(sig);
	} else if (pkt.tag == PGPRTAG_USER_ID || pkt.tag == PGPRTAG_USER_ATTRIBUTE) {
	    if (sectionpkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
		rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		break;		/* no user id packets after subkeys allowed */
	    }
	    sectionpkt = pkt;
	    haveselfsig = 0;
	} else if (pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    sectionpkt = pkt;
	    haveselfsig = 0;
	} else if (pkt.tag == PGPRTAG_RESERVED) {
	    rc = PGPR_ERROR_CORRUPT_PGP_PACKET;
	    break;		/* not allowed */
	}
	p += (pkt.body - pkt.head) + pkt.blen;
    }
    if (rc == PGPR_OK && p != pend)
	rc = PGPR_ERROR_INTERNAL;
    sig = pgprItemFree(sig);
    newest_sig = pgprItemFree(newest_sig);
    return rc;
}
	
/* Return the subkeys for a pubkey. Note that the code in pgprParseParamsPubkey() already
 * made sure that the signatures are self-signatures and verified ok. */
/* This is similar to gnupg's merge_selfsigs_subkey() function */
pgprRC pgprParseCertificateSubkeys(const uint8_t *pkts, size_t pktslen,
			pgprItem mainkey, pgprItem **subkeys,
			int *subkeysCount)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    pgprItem *items = NULL, subkey = NULL;
    pgprItem sig = NULL;
    pgprItem newest_sig = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    int count = 0;
    int alloced = 10;
    pgprPkt mainpkt, subkeypkt, pkt;
    int i;
    uint32_t now = 0;

    if (mainkey->tag != PGPRTAG_PUBLIC_KEY || !mainkey->version)
	return PGPR_ERROR_INTERNAL;	/* main key must be a parsed pubkey */

    if (pktslen > PGPR_MAX_OPENPGP_BYTES)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pgprDecodePkt(p, (pend - p), &mainpkt) != PGPR_OK)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPRTAG_PUBLIC_KEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    memset(&subkeypkt, 0, sizeof(subkeypkt));

    items = pgprMalloc(alloced * sizeof(*items));
    if (!items)
	return PGPR_ERROR_NO_MEMORY;

    rc = PGPR_OK;
    while (rc == PGPR_OK) {
	if (p < pend) {
	    if (pgprDecodePkt(p, (pend - p), &pkt)) {
		rc = PGPR_ERROR_CORRUPT_PGP_PACKET;
		break;
	    }
	    if (pkt.tag == PGPRTAG_PUBLIC_KEY || pkt.tag == PGPRTAG_SECRET_KEY) {
		rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		break;	/* start of another public key, error out */
	    }
	} else {
	    pkt.tag = 0;
	}

	/* finish up this subkey if we are at the end or a new one comes next */
	if (p == pend || pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    /* take the data from the newest signature */
	    if (newest_sig && subkey && newest_sig->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		subkey->saved |= PGPRITEM_SAVED_VALID;	/* at least one binding sig */
		if ((newest_sig->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0) {
		    subkey->key_flags = newest_sig->key_flags;
		    subkey->saved |= PGPRITEM_SAVED_KEY_FLAGS;
		}
		if ((newest_sig->saved & PGPRITEM_SAVED_KEY_EXPIRE) != 0) {
		    subkey->key_expire = newest_sig->key_expire;
		    subkey->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
		}
	    }
	    newest_sig = pgprItemFree(newest_sig);
	}

	if (p == pend)
	    break;
	p += (pkt.body - pkt.head) + pkt.blen;

	if (pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    subkey = pgprItemNew(PGPRTAG_PUBLIC_SUBKEY);
	    if (!subkey) {
		rc = PGPR_ERROR_NO_MEMORY;
		break;
	    }
	    /* Copy keyid of main key for error messages */
	    memcpy(subkey->mainid, mainkey->keyid, sizeof(mainkey->keyid));
	    /* Copy UID from main key to subkey */
	    if (mainkey->userid) {
		if ((subkey->userid = pgprStrdup(mainkey->userid)) == NULL) {
		    rc = PGPR_ERROR_NO_MEMORY;
		    break;
		}
	    }
	    /* if the main key is revoked, all the subkeys are also revoked */
	    subkey->revoked = mainkey->revoked ? 2 : 0;
	    if (pgprParseKey(&pkt, subkey)) {
		subkey = pgprItemFree(subkey);
	    } else {
		if (mainkey->version == 6 && subkey->version != 6) {
		    /* version 6 keys can only have version 6 subkeys */
		    subkey = pgprItemFree(subkey);
		    continue;
		}
		if (count == alloced) {
		    pgprItem *newitems;
		    alloced <<= 1;
		    newitems = pgprRealloc(items, alloced * sizeof(*items));
		    if (!newitems) {
			rc = PGPR_ERROR_NO_MEMORY;
			break;
		    }
		    items = newitems;
		}
		items[count++] = subkey;
		subkeypkt = pkt;
	    }
	} else if (pkt.tag == PGPRTAG_SIGNATURE && subkey != NULL) {
	    int needsig = 0;
	    sig = pgprItemNew(pkt.tag);
	    if (!sig) {
		rc = PGPR_ERROR_NO_MEMORY;
		break;
	    }
	    /* we use the NoParams variant because we do not verify */
	    if (pgprParseSigNoParams(&pkt, sig) != PGPR_OK) {
		sig = pgprItemFree(sig);
	    }

	    /* check if we understand this signature */
	    if (sig && sig->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		needsig = 1;
	    } else if (sig && sig->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		/* insist on a embedded primary key binding signature if this is used for signing */
		int key_flags = (sig->saved & PGPRITEM_SAVED_KEY_FLAGS) ? sig->key_flags : 0;
		if (!(key_flags & 0x02) || verifyPrimaryBindingSig(&mainpkt, &subkeypkt, subkey, sig) == PGPR_OK)
		    needsig = 1;
	    }
	    /* the code in pgprParseCertificate always checks that SUBKEY_BINDING
             * and SUBKEY_REVOKE are self-signatures and verify ok */

	    /* check if this signature is expired */
	    if (needsig && (sig->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sig->time || sig->sig_expire < now - sig->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle subkey revokations right away */
	    if (needsig && sig->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (subkey->revoked != 2)
		    subkey->revoked = 1;
		subkey->saved |= PGPRITEM_SAVED_VALID;	/* at least one binding sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_sig || sig->time >= newest_sig->time)) {
		newest_sig = pgprItemFree(newest_sig);
		newest_sig = sig;
		sig = NULL;
	    }
	    sig = pgprItemFree(sig);
	}
    }
    if (rc == PGPR_OK && p != pend)
	rc = PGPR_ERROR_INTERNAL;
    sig = pgprItemFree(sig);
    newest_sig = pgprItemFree(newest_sig);

    if (rc == PGPR_OK) {
	pgprItem *newitems = pgprRealloc(items, count * sizeof(*items));
	if (!newitems) {
	    rc = PGPR_ERROR_NO_MEMORY;
	} else {
	    items = newitems;
	}
    }
    if (rc == PGPR_OK) {
	*subkeys = items;
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgprItemFree(items[i]);
	free(items);
    }
    return rc;
}

