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
	} else if (version == 5) {
	    uint8_t head[] = {
		0x9a,
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
	if (version == 4 || version == 5) {
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

static pgprRC pgprVerifySelf(pgprDigParams key, pgprDigParams selfsig,
			const pgprPkt *mainpkt, const pgprPkt *sectionpkt)
{
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;
    pgprDigCtx ctx = pgprDigestInit(selfsig->hash_algo);
    uint8_t *hash = NULL;
    size_t hashlen = 0;

    if (!ctx)
	return rc;

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
    /* hash signature data and trailer */
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

static pgprRC verifyPrimaryBindingSig(pgprPkt *mainpkt, pgprPkt *subkeypkt, pgprDigParams subkeydig, pgprDigParams bindsigdig)
{
    pgprDigParams emb_digp = NULL;
    int rc = PGPR_ERROR_SELFSIG_VERIFICATION;		/* assume failure */
    if (!bindsigdig || !bindsigdig->embedded_sig)
	return rc;
    emb_digp = pgprDigParamsNew(PGPRTAG_SIGNATURE);
    if (pgprPrtSig(PGPRTAG_SIGNATURE, bindsigdig->embedded_sig, bindsigdig->embedded_sig_len, emb_digp) == PGPR_OK)
	if (emb_digp->sigtype == PGPRSIGTYPE_PRIMARY_BINDING)
	    rc = pgprVerifySelf(subkeydig, emb_digp, mainpkt, subkeypkt);
    emb_digp = pgprDigParamsFree(emb_digp);
    return rc;
}

static int is_same_keyid(pgprDigParams digp, pgprDigParams sigdigp)
{
    return (digp->saved & sigdigp->saved & PGPRDIG_SAVED_ID) != 0 &&
	memcmp(digp->signid, sigdigp->signid, sizeof(digp->signid)) == 0;
}

/* Parse a complete pubkey with all associated packets */
/* This is similar to gnupg's merge_selfsigs_main() function */
pgprRC pgprPrtTransferablePubkey(const uint8_t * pkts, size_t pktlen, pgprDigParams digp)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgprDigParams sigdigp = NULL;
    pgprDigParams newest_digp = NULL;
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
    if ((rc = pgprPrtKey(mainpkt.tag, mainpkt.body, mainpkt.blen, digp)) != PGPR_OK)
	return rc;
    sectionpkt = mainpkt;
    haveselfsig = 1;
    digp->key_mtime = digp->time;

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
	    if (newest_digp && (sectionpkt.tag == PGPRTAG_USER_ID || sectionpkt.tag == PGPRTAG_PUBLIC_KEY) && newest_digp->sigtype != PGPRSIGTYPE_CERT_REVOKE) {
		digp->saved |= PGPRDIG_SAVED_VALID;	/* we have a valid binding sig */
		if ((newest_digp->saved & PGPRDIG_SAVED_KEY_EXPIRE) != 0) {
		    if ((!key_expire_sig_time || newest_digp->time > key_expire_sig_time)) {
			digp->key_expire = newest_digp->key_expire;
			digp->saved |= PGPRDIG_SAVED_KEY_EXPIRE;
			key_expire_sig_time = newest_digp->time;
			if (newest_digp->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_expire_sig_time = 0xffffffffU;	/* expires from the direct signatures are final */
		    }
		}
		if ((newest_digp->saved & PGPRDIG_SAVED_KEY_FLAGS) != 0) {
		    if ((!key_flags_sig_time || newest_digp->time > key_flags_sig_time)) {
			digp->key_flags = newest_digp->key_flags;
			digp->saved |= PGPRDIG_SAVED_KEY_FLAGS;
			key_flags_sig_time = newest_digp->time;
			if (newest_digp->sigtype == PGPRSIGTYPE_SIGNED_KEY)
			    key_flags_sig_time = 0xffffffffU;	/* key flags from the direct signatures are final */
		    }
		}
		if (sectionpkt.tag == PGPRTAG_USER_ID) {
		    if (!digp->userid || ((newest_digp->saved & PGPRDIG_SAVED_PRIMARY) != 0 && (digp->saved & PGPRDIG_SAVED_PRIMARY) == 0)) {
			if ((rc = pgprPrtUserID(sectionpkt.tag, sectionpkt.body, sectionpkt.blen, digp)) != PGPR_OK)
			    break;
			if ((newest_digp->saved & PGPRDIG_SAVED_PRIMARY) != 0)
			    digp->saved |= PGPRDIG_SAVED_PRIMARY;
		    }
		}
	    }
	    newest_digp = pgprDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;	/* all packets processed */

	if (pkt.tag == PGPRTAG_SIGNATURE) {
	    int isselfsig, needsig = 0;
	    sigdigp = pgprDigParamsNew(pkt.tag);
	    /* use the NoParams variant because we want to ignore non self-sigs */
	    if ((rc = pgprPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != PGPR_OK)
		break;
	    isselfsig = is_same_keyid(digp, sigdigp);

	    /* check if we understand this signature type and make sure it is in the right section */
	    if (sigdigp->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		needsig = 1;
	    } else if (sigdigp->sigtype == PGPRSIGTYPE_SUBKEY_BINDING || sigdigp->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_SUBKEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = 1;
	    } else if (sigdigp->sigtype == PGPRSIGTYPE_SIGNED_KEY) {
		if (sectionpkt.tag != PGPRTAG_PUBLIC_KEY) {
		    rc = PGPR_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
	    } else if (sigdigp->sigtype == PGPRSIGTYPE_GENERIC_CERT || sigdigp->sigtype == PGPRSIGTYPE_PERSONA_CERT || sigdigp->sigtype == PGPRSIGTYPE_CASUAL_CERT || sigdigp->sigtype == PGPRSIGTYPE_POSITIVE_CERT || sigdigp->sigtype == PGPRSIGTYPE_CERT_REVOKE) {
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
	        if ((rc = pgprPrtSigParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != PGPR_OK)
		    break;
		if ((rc = pgprVerifySelf(digp, sigdigp, &mainpkt, &sectionpkt)) != PGPR_OK)
		    break;		/* verification failed */
		if (sigdigp->sigtype != PGPRSIGTYPE_KEY_REVOKE)
		    haveselfsig = 1;
		if (sigdigp->time > digp->key_mtime)
		    digp->key_mtime = sigdigp->time;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigdigp->saved & PGPRDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle key revokations right away */
	    if (needsig && sigdigp->sigtype == PGPRSIGTYPE_KEY_REVOKE) {
		digp->revoked = 1;				/* this is final */
		digp->saved |= PGPRDIG_SAVED_VALID;		/* we have at least one correct self-sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgprDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgprDigParamsFree(sigdigp);
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
    sigdigp = pgprDigParamsFree(sigdigp);
    newest_digp = pgprDigParamsFree(newest_digp);
    return rc;
}
	
/* Return the subkeys for a pubkey. Note that the code in pgprPrtParamsPubkey() already
 * made sure that the signatures are self-signatures and verified ok. */
/* This is similar to gnupg's merge_selfsigs_subkey() function */
pgprRC pgprPrtTransferablePubkeySubkeys(const uint8_t *pkts, size_t pktlen,
			pgprDigParams mainkey, pgprDigParams **subkeys,
			int *subkeysCount)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgprDigParams *digps = NULL, subdigp = NULL;
    pgprDigParams sigdigp = NULL;
    pgprDigParams newest_digp = NULL;
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

    digps = pgprMalloc(alloced * sizeof(*digps));
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
	    if (newest_digp && subdigp && newest_digp->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		subdigp->saved |= PGPRDIG_SAVED_VALID;	/* at least one binding sig */
		if ((newest_digp->saved & PGPRDIG_SAVED_KEY_FLAGS) != 0) {
		    subdigp->key_flags = newest_digp->key_flags;
		    subdigp->saved |= PGPRDIG_SAVED_KEY_FLAGS;
		}
		if ((newest_digp->saved & PGPRDIG_SAVED_KEY_EXPIRE) != 0) {
		    subdigp->key_expire = newest_digp->key_expire;
		    subdigp->saved |= PGPRDIG_SAVED_KEY_EXPIRE;
		}
	    }
	    newest_digp = pgprDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;
	p += (pkt.body - pkt.head) + pkt.blen;

	if (pkt.tag == PGPRTAG_PUBLIC_SUBKEY) {
	    subdigp = pgprDigParamsNew(PGPRTAG_PUBLIC_SUBKEY);
	    /* Copy keyid of main key for error messages */
	    memcpy(subdigp->mainid, mainkey->signid, sizeof(mainkey->signid));
	    /* Copy UID from main key to subkey */
	    subdigp->userid = mainkey->userid ? pgprStrdup(mainkey->userid) : NULL;
	    /* if the main key is revoked, all the subkeys are also revoked */
	    subdigp->revoked = mainkey->revoked ? 2 : 0;
	    if (pgprPrtKey(pkt.tag, pkt.body, pkt.blen, subdigp)) {
		subdigp = pgprDigParamsFree(subdigp);
	    } else {
		if (count == alloced) {
		    alloced <<= 1;
		    digps = pgprRealloc(digps, alloced * sizeof(*digps));
		}
		digps[count++] = subdigp;
		subkeypkt = pkt;
	    }
	} else if (pkt.tag == PGPRTAG_SIGNATURE && subdigp != NULL) {
	    int needsig = 0;
	    sigdigp = pgprDigParamsNew(pkt.tag);
	    /* we use the NoParams variant because we do not verify */
	    if (pgprPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp) != PGPR_OK) {
		sigdigp = pgprDigParamsFree(sigdigp);
	    }

	    /* check if we understand this signature */
	    if (sigdigp && sigdigp->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		needsig = 1;
	    } else if (sigdigp && sigdigp->sigtype == PGPRSIGTYPE_SUBKEY_BINDING) {
		/* insist on a embedded primary key binding signature if this is used for signing */
		int key_flags = (sigdigp->saved & PGPRDIG_SAVED_KEY_FLAGS) ? sigdigp->key_flags : 0;
		if (!(key_flags & 0x02) || verifyPrimaryBindingSig(&mainpkt, &subkeypkt, subdigp, sigdigp) == PGPR_OK)
		    needsig = 1;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigdigp->saved & PGPRDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgprCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle subkey revokations right away */
	    if (needsig && sigdigp->sigtype == PGPRSIGTYPE_SUBKEY_REVOKE) {
		if (subdigp->revoked != 2)
		    subdigp->revoked = 1;
		subdigp->saved |= PGPRDIG_SAVED_VALID;	/* at least one binding sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgprDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgprDigParamsFree(sigdigp);
	}
    }
    if (rc == PGPR_OK && p != pend)
	rc = PGPR_ERROR_INTERNAL;
    sigdigp = pgprDigParamsFree(sigdigp);
    newest_digp = pgprDigParamsFree(newest_digp);

    if (rc == PGPR_OK) {
	*subkeys = pgprRealloc(digps, count * sizeof(*digps));
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgprDigParamsFree(digps[i]);
	free(digps);
    }
    return rc;
}

