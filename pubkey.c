/*
 * Parse a transferable public key
 */

#include <string.h>

#include "pgpr.h"
#include "pgpr_internal.h"

static pgprRC hashKey(pgprDigCtx ctx, const pgprPkt *pkt, int exptag, int version)
{
    pgprRC rc = PGPR_ERROR_INTERNAL;
    if (pkt && pkt->tag == exptag) {
	if (version == 4) {
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
	} else if (version != 3)
	    return rc;
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

static pgprRC pgprVerifySelf(pgprItem key, pgprItem selfsig,
			const pgprPkt *mainpkt, const pgprPkt *sectionpkt)
{
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;
    pgprDigCtx ctx;
    uint8_t *hash = NULL;
    size_t hashlen = 0;

    ctx = pgprDigestInit(selfsig->hash_algo);
    if (!ctx)
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
	if (rc == PGPR_ERROR_SIGNATURE_VERIFICATION)
	    rc = PGPR_ERROR_SELFSIG_VERIFICATION;
    }
    free(hash);
    return rc;
}

static pgprRC verifyPrimaryBindingSig(pgprPkt *mainpkt, pgprPkt *subkeypkt, pgprItem subkey, pgprItem bindsig)
{
    pgprItem emb = NULL;
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;		/* assume failure */
    if (!bindsig || !bindsig->embedded_sig)
	return rc;
    emb = pgprItemNew(PGPRTAG_SIGNATURE);
    if (pgprParseSig(PGPRTAG_SIGNATURE, bindsig->embedded_sig, bindsig->embedded_sig_len, emb) == PGPR_OK)
	if (emb->sigtype == PGPRSIGTYPE_PRIMARY_BINDING)
	    rc = pgprVerifySelf(subkey, emb, mainpkt, subkeypkt);
    emb = pgprItemFree(emb);
    return rc;
}

static int is_same_keyid(pgprItem item1, pgprItem item2)
{
    return (item1->saved & item2->saved & PGPRITEM_SAVED_ID) != 0 &&
	memcmp(item1->signid, item2->signid, sizeof(item1->signid)) == 0;
}

/* Parse a complete pubkey with all associated packets */
/* This is similar to gnupg's merge_selfsigs_main() function */
pgprRC pgprParseTransferablePubkey(const uint8_t * pkts, size_t pktlen, pgprItem item)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgprItem sigitem = NULL;
    pgprItem newest_item = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    uint32_t key_expire_sig_time = 0;
    uint32_t key_flags_sig_time = 0;
    pgprPkt mainpkt, sectionpkt;
    int haveselfsig;
    uint32_t now = 0;

    /* parse the main pubkey */
    if (pktlen > PGPR_MAX_OPENPGP_BYTES)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pgprDecodePkt(p, (pend - p), &mainpkt) != PGPR_OK)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPRTAG_PUBLIC_KEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    /* Parse the pubkey packet */
    if ((rc = pgprParseKey(mainpkt.tag, mainpkt.body, mainpkt.blen, item)) != PGPR_OK)
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
	    if (newest_item && (sectionpkt.tag == PGPRTAG_USER_ID || sectionpkt.tag == PGPRTAG_PUBLIC_KEY) && newest_item->sigtype != PGPRSIGTYPE_CERT_REVOKE) {
		item->saved |= PGPRITEM_SAVED_VALID;	/* we have a valid binding sig */
		if ((newest_item->saved & PGPRITEM_SAVED_KEY_EXPIRE) != 0) {
		    if ((!key_expire_sig_time || newest_item->time > key_expire_sig_time)) {
			item->key_expire = newest_item->key_expire;
			item->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
			key_expire_sig_time = newest_item->time;
			if (newest_item->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_expire_sig_time = 0xffffffffU;	/* expires from the direct signatures are final */
		    }
		}
		if ((newest_item->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0) {
		    if ((!key_flags_sig_time || newest_item->time > key_flags_sig_time)) {
			item->key_flags = newest_item->key_flags;
			item->saved |= PGPRITEM_SAVED_KEY_FLAGS;
			key_flags_sig_time = newest_item->time;
			if (newest_item->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_flags_sig_time = 0xffffffffU;	/* key flags from the direct signatures are final */
		    }
		}
		if (sectionpkt.tag == PGPRTAG_USER_ID) {
		    if (!item->userid || ((newest_item->saved & PGPRITEM_SAVED_PRIMARY) != 0 && (item->saved & PGPRITEM_SAVED_PRIMARY) == 0)) {
			if ((rc = pgprParseUserID(sectionpkt.tag, sectionpkt.body, sectionpkt.blen, item)) != PGPR_OK)
			    break;
			if ((newest_item->saved & PGPRITEM_SAVED_PRIMARY) != 0)
			    item->saved |= PGPRITEM_SAVED_PRIMARY;
		    }
		}
	    }
	    newest_item = pgprItemFree(newest_item);
	}

	if (p == pend)
	    break;	/* all packets processed */

	if (pkt.tag == PGPRTAG_SIGNATURE) {
	    int isselfsig, needsig = 0;
	    sigitem = pgprItemNew(pkt.tag);
	    /* use the NoParams variant because we want to ignore non self-sigs */
	    if ((rc = pgprParseSigNoParams(pkt.tag, pkt.body, pkt.blen, sigitem)) != PGPR_OK)
		break;
	    isselfsig = is_same_keyid(item, sigitem);

	    /* check if we understand this signature type and make sure it is in the right section */
	    if (sigitem->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		needsig = 1;
	    } else if (sigitem->sigtype == PGPRSIGTYPE_SUBKEY_BINDING || sigitem->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_SUBKEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = 1;
	    } else if (sigitem->sigtype == PGPRSIGTYPE_SIGNED_KEY) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_KEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
	    } else if (sigitem->sigtype == PGPRSIGTYPE_GENERIC_CERT || sigitem->sigtype == PGPRSIGTYPE_PERSONA_CERT || sigitem->sigtype == PGPRSIGTYPE_CASUAL_CERT || sigitem->sigtype == PGPRSIGTYPE_POSITIVE_CERT || sigitem->sigtype == PGPRSIGTYPE_CERT_REVOKE) {
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
	        if ((rc = pgprParseSigParams(pkt.tag, pkt.body, pkt.blen, sigitem)) != PGPR_OK)
		    break;
		if ((rc = pgprVerifySelf(item, sigitem, &mainpkt, &sectionpkt)) != PGPR_OK)
		    break;		/* verification failed */
		if (sigitem->sigtype != PGPRSIGTYPE_KEY_REVOKE)
		    haveselfsig = 1;
		if (sigitem->time > item->key_mtime)
		    item->key_mtime = sigitem->time;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigitem->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sigitem->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sigitem->time || sigitem->sig_expire < now - sigitem->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle key revokations right away */
	    if (needsig && sigitem->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		item->revoked = 1;				/* this is final */
		item->saved |= PGPRITEM_SAVED_VALID;		/* we have at least one correct self-sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_item || sigitem->time >= newest_item->time)) {
		newest_item = pgprItemFree(newest_item);
		newest_item = sigitem;
		sigitem = NULL;
	    }
	    sigitem = pgprItemFree(sigitem);
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
    sigitem = pgprItemFree(sigitem);
    newest_item = pgprItemFree(newest_item);
    return rc;
}
	
/* Return the subkeys for a pubkey. Note that the code in pgprParseParamsPubkey() already
 * made sure that the signatures are self-signatures and verified ok. */
/* This is similar to gnupg's merge_selfsigs_subkey() function */
pgprRC pgprParseTransferablePubkeySubkeys(const uint8_t *pkts, size_t pktlen,
			pgprItem mainkey, pgprItem **subkeys,
			int *subkeysCount)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgprItem *items = NULL, subitem = NULL;
    pgprItem sigitem = NULL;
    pgprItem newest_item = NULL;
    pgprRC rc = PGPR_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    int count = 0;
    int alloced = 10;
    pgprPkt mainpkt, subkeypkt, pkt;
    int i;
    uint32_t now = 0;

    if (mainkey->tag != PGPRTAG_PUBLIC_KEY || !mainkey->version)
	return PGPR_ERROR_INTERNAL;	/* main key must be a parsed pubkey */

    if (pktlen > PGPR_MAX_OPENPGP_BYTES)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (pgprDecodePkt(p, (pend - p), &mainpkt) != PGPR_OK)
	return PGPR_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPRTAG_PUBLIC_KEY)
	return PGPR_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    memset(&subkeypkt, 0, sizeof(subkeypkt));

    items = pgprMalloc(alloced * sizeof(*items));
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
	    if (newest_item && subitem && newest_item->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		subitem->saved |= PGPRITEM_SAVED_VALID;	/* at least one binding sig */
		if ((newest_item->saved & PGPRITEM_SAVED_KEY_FLAGS) != 0) {
		    subitem->key_flags = newest_item->key_flags;
		    subitem->saved |= PGPRITEM_SAVED_KEY_FLAGS;
		}
		if ((newest_item->saved & PGPRITEM_SAVED_KEY_EXPIRE) != 0) {
		    subitem->key_expire = newest_item->key_expire;
		    subitem->saved |= PGPRITEM_SAVED_KEY_EXPIRE;
		}
	    }
	    newest_item = pgprItemFree(newest_item);
	}

	if (p == pend)
	    break;
	p += (pkt.body - pkt.head) + pkt.blen;

	if (pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    subitem = pgprItemNew(PGPRTAG_PUBLIC_SUBKEY);
	    /* Copy keyid of main key for error messages */
	    memcpy(subitem->mainid, mainkey->signid, sizeof(mainkey->signid));
	    /* Copy UID from main key to subkey */
	    subitem->userid = mainkey->userid ? pgprStrdup(mainkey->userid) : NULL;
	    /* if the main key is revoked, all the subkeys are also revoked */
	    subitem->revoked = mainkey->revoked ? 2 : 0;
	    if (pgprParseKey(pkt.tag, pkt.body, pkt.blen, subitem)) {
		subitem = pgprItemFree(subitem);
	    } else {
		if (count == alloced) {
		    alloced <<= 1;
		    items = pgprRealloc(items, alloced * sizeof(*items));
		}
		items[count++] = subitem;
		subkeypkt = pkt;
	    }
	} else if (pkt.tag == PGPRTAG_SIGNATURE && subitem != NULL) {
	    int needsig = 0;
	    sigitem = pgprItemNew(pkt.tag);
	    /* we use the NoParams variant because we do not verify */
	    if (pgprParseSigNoParams(pkt.tag, pkt.body, pkt.blen, sigitem) != PGPR_OK) {
		sigitem = pgprItemFree(sigitem);
	    }

	    /* check if we understand this signature */
	    if (sigitem && sigitem->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		needsig = 1;
	    } else if (sigitem && sigitem->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		/* insist on a embedded primary key binding signature if this is used for signing */
		int key_flags = (sigitem->saved & PGPRITEM_SAVED_KEY_FLAGS) ? sigitem->key_flags : 0;
		if (!(key_flags & 0x02) || verifyPrimaryBindingSig(&mainpkt, &subkeypkt, subitem, sigitem) == PGPR_OK)
		    needsig = 1;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigitem->saved & PGPRITEM_SAVED_SIG_EXPIRE) != 0 && sigitem->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sigitem->time || sigitem->sig_expire < now - sigitem->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle subkey revokations right away */
	    if (needsig && sigitem->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (subitem->revoked != 2)
		    subitem->revoked = 1;
		subitem->saved |= PGPRITEM_SAVED_VALID;	/* at least one binding sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_item || sigitem->time >= newest_item->time)) {
		newest_item = pgprItemFree(newest_item);
		newest_item = sigitem;
		sigitem = NULL;
	    }
	    sigitem = pgprItemFree(sigitem);
	}
    }
    if (rc == PGPR_OK && p != pend)
	rc = PGPR_ERROR_INTERNAL;
    sigitem = pgprItemFree(sigitem);
    newest_item = pgprItemFree(newest_item);

    if (rc == PGPR_OK) {
	*subkeys = pgprRealloc(items, count * sizeof(*items));
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgprItemFree(items[i]);
	free(items);
    }
    return rc;
}

