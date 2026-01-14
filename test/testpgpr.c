#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "../pgpr.h"

static char *slurp(const char *fn, size_t *lenp)
{
    size_t len = 0;
    char *buf = 0;
    int l;
    FILE *fp;

    if ((fp = fopen(fn, "r")) == 0) {
	perror(fn);
	exit(1);
    }
    while (1) {
	buf = realloc(buf, len + 65536);
	l = fread(buf + len, 1, 65536, fp);
	if (l < 0) {
	    perror("fread");
	    exit(1);
	}
	if (l == 0)
	    break;
	len += l;
    }
    fclose(fp);
    buf = realloc(buf, len + 1);
    buf[len] = 0;
    if (lenp)
	*lenp = len;
    return buf;
}

static void
printhex(const char *what, const uint8_t *d, size_t l)
{
    size_t i;
    printf("%s: ", what);
    for (i = 0; i < l; i++)
	printf("%02x", d[i]);
    printf("\n");
}

static void
die(const char *str, pgprRC rc)
{
    if (rc == PGPR_OK)
	fprintf(stderr, "%s\n", str);
    else
	fprintf(stderr, "%s: %s\n", str, pgprErrorStr(rc));
    exit(1);
}


pgprItem
select_subkey(const uint8_t *pkts, size_t pktlen, pgprItem key, int subkey)
{
    pgprRC rc;
    pgprItem *subkeys;
    int nsubkeys = 0;

    if ((rc = pgprPubkeyParseSubkeys(pkts, pktlen, key, &subkeys, &nsubkeys)) != PGPR_OK)
	die("subkeys parse error", rc);
    if (subkey <= 0 || subkey > nsubkeys) {
	fprintf(stderr, "no subkey #%d\n", subkey);
	exit(1);
    }
    pgprItemFree(key);
    key = subkeys[subkey - 1];
    for (; nsubkeys > 0; nsubkeys--)
	if (nsubkeys != subkey)
	    pgprItemFree(subkeys[nsubkeys - 1]);
    free(subkeys);
    return key;
}

static int
verifysignature(int argc, char **argv)
{
    pgprRC rc;
    char *pubkey_a;
    char *signature_a;
    unsigned char *data;
    size_t datalen = 0;
    unsigned char *pubkey;
    size_t pubkeyl;
    unsigned char *signature;
    size_t signaturel;
    pgprItem key = NULL, sig = NULL;
    char *lints;
    pgprDigCtx ctx = NULL;
    const uint8_t *trailer;
    size_t trailerlen;
    const uint8_t *header;
    size_t headerlen;
    void *hash;
    size_t hashlen;
    int c;
    int subkey = 0;

    while ((c = getopt(argc, argv, "s:")) >= 0) {
	switch(c) {
	case 's':
	    subkey = atoi(optarg);
	    break;
	default:
	    break;
	}
    }
    if (argc - optind != 3) {
	fprintf(stderr, "usage: testpgpr verifysignature [-s subkey] <pubkey> <sig> <data>\n");
	exit(1);
    }
    pubkey_a = slurp(argv[optind], NULL);
    signature_a = slurp(argv[optind + 1], NULL);
    data = slurp(argv[optind + 2], &datalen);

    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die("pubkey unwrap error", rc);
    if ((rc = pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel)) != PGPR_OK)
	die("signature unwrap error", rc);
    lints = 0;
    if ((rc = pgprPubkeyParse(pubkey, pubkeyl, &key, &lints)) != PGPR_OK) {
	if (!lints)
	    die("pubkey parse error", rc);
	fprintf(stderr, "pubkey parse error: %s\n", lints);
	exit(1);
    }
    free(lints);

    if (subkey)
	key = select_subkey(pubkey, pubkeyl, key, subkey);

    lints = 0;
    if ((rc = pgprSignatureParse(signature, signaturel, &sig, &lints)) != PGPR_OK) {
	if (!lints)
	    die("signature parse error", rc);
	fprintf(stderr, "signature parse error: %s\n", lints);
	exit(1);
    }
    free(lints);

    if ((rc = pgprDigestInit(pgprItemHashAlgo(sig), &ctx)) != PGPR_OK)
	die("digest init error", rc);
    header = pgprItemHashHeader(sig, &headerlen);
    if (header)
	pgprDigestUpdate(ctx, header, headerlen);
    pgprDigestUpdate(ctx, data, datalen);
    trailer = pgprItemHashTrailer(sig, &trailerlen);
    if (trailer)
	pgprDigestUpdate(ctx, trailer, trailerlen);
    pgprDigestFinal(ctx, &hash, &hashlen);

    lints = 0;
    if ((rc = pgprVerifySignature(key, sig, hash, hashlen, &lints)) != PGPR_OK) {
	if (!lints)
	    die("signature verification error", rc);
	fprintf(stderr, "signature verification error: %s\n", lints);
	exit(1);
    }
    free(lints);
    printf("signature verified OK\n");

    free(hash);
    pgprItemFree(key);
    pgprItemFree(sig);
    free(pubkey_a);
    free(pubkey);
    free(signature_a);
    free(signature);
    free(data);
    return 0;
}

const char *nullify(const char *str)
{
    return str ? str : "<NULL>";
}

static int
keyinfo(int argc, char **argv)
{
    pgprRC rc;
    char *pubkey_a;
    unsigned char *pubkey;
    size_t pubkeyl;
    char *lints;
    pgprItem key = NULL;
    const unsigned char *keyid;
    const unsigned char *keyfp;
    size_t keyfp_len = 0;
    int c, i;
    int subkey = 0;

    while ((c = getopt(argc, argv, "s:")) >= 0) {
	switch(c) {
	case 's':
	    subkey = atoi(optarg);
	    break;
	default:
	    break;
	}
    }
    if (argc - optind != 1) {
	fprintf(stderr, "usage: testpgpr keyinfo [-s subkey] <pubkey>\n");
	exit(1);
    }
    pubkey_a = slurp(argv[optind], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die("pubkey unwrap error", rc);
    lints = 0;
    if ((rc = pgprPubkeyParse(pubkey, pubkeyl, &key, &lints)) != PGPR_OK) {
	if (!lints)
	    die("pubkey parse error", rc);
	fprintf(stderr, "pubkey parse error: %s\n", lints);
	exit(1);
    }
    free(lints);
    if (subkey)
	key = select_subkey(pubkey, pubkeyl, key, subkey);
    printf("Version: %d\n", pgprItemVersion(key));
    printf("CreationTime: %d\n", pgprItemCreationTime(key));
    printf("Algorithm: %d\n", pgprItemPubkeyAlgo(key));
    printf("AlgorithmInfo: %d\n", pgprItemPubkeyAlgoInfo(key));
    printf("UserID: %s\n", nullify(pgprItemUserID(key)));
    keyfp = pgprItemKeyFingerprint(key, &keyfp_len, NULL);
    if (keyfp)
	printhex("KeyFP", keyfp, keyfp_len);
    keyid = pgprItemKeyID(key);
    if (keyid)
	printhex("KeyID", keyid, 8);
    pgprItemFree(key);
    free(pubkey_a);
    free(pubkey);
    return 0;
}

static int
certinfo(int argc, char **argv)
{
    pgprRC rc;
    char *pubkey_a;
    unsigned char *pubkey;
    size_t pubkeyl;
    pgprKeyID_t keyid;
    uint8_t *fp = NULL;
    size_t fplen = 0;
    size_t certlen = 0;
    
    int i;

    if (argc - 1 != 1) {
	fprintf(stderr, "usage: testpgpr certinfo <pubkey>\n");
	exit(1);
    }
    pubkey_a = slurp(argv[optind], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die("pubkey unwrap error", rc);
    if ((rc = pgprPubkeyFingerprint(pubkey, pubkeyl, &fp, &fplen, NULL)) != PGPR_OK)
	die("pgprPubkeyFingerprint error", rc);
    printhex("KeyFP", fp, fplen);
    memset(keyid, 0, sizeof(keyid));
    if ((rc = pgprPubkeyKeyID(pubkey, pubkeyl, keyid)) != PGPR_OK)
	die("pgprPubkeyKeyID error", rc);
    printhex("KeyID", keyid, 8);
    if ((rc = pgprPubkeyCertLen(pubkey, pubkeyl, &certlen)) != PGPR_OK)
	die("pgprPubkeyCertLen error", rc);
    printf("CertLen: %zd\n", certlen);
    free(fp);
    free(pubkey_a);
    free(pubkey);
    return 0;
}

static int
siginfo(int argc, char **argv)
{
    pgprRC rc;
    char *signature_a;
    unsigned char *signature;
    size_t signaturel;
    char *lints;
    pgprItem sig = NULL;
    const unsigned char *keyid;
    const unsigned char *keyfp;
    size_t keyfp_len = 0;
    int i;

    if (argc != 2) {
	fprintf(stderr, "usage: testpgpr siginfo <signature>\n");
	exit(1);
    }
    signature_a = slurp(argv[1], NULL);
    if ((rc = pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel)) != PGPR_OK)
	die("signature unwrap error", rc);
    lints = 0;
    if ((rc = pgprSignatureParse(signature, signaturel, &sig, &lints)) != PGPR_OK) {
	if (!lints)
	    die("signature parse error", rc);
	fprintf(stderr, "signature parse error: %s\n", lints);
	exit(1);
    }
    free(lints);
    printf("Version: %d\n", pgprItemVersion(sig));
    printf("CreationTime: %d\n", pgprItemCreationTime(sig));
    printf("Algorithm: %d\n", pgprItemPubkeyAlgo(sig));
    printf("Hash: %d\n", pgprItemHashAlgo(sig));
    keyfp = pgprItemKeyFingerprint(sig, &keyfp_len, NULL);
    if (keyfp)
	printhex("KeyFP", keyfp, keyfp_len);
    keyid = pgprItemKeyID(sig);
    if (keyid)
	printhex("KeyID", keyid, 8);
    pgprItemFree(sig);
    free(signature_a);
    free(signature);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
	fprintf(stderr, "usage: testpgpr <cmd>...\n");
	exit(1);
    }
    if (!strcmp(argv[1], "verifysignature")) {
        return verifysignature(argc - 1, argv + 1);
    }
    if (!strcmp(argv[1], "keyinfo")) {
        return keyinfo(argc - 1, argv + 1);
    }
    if (!strcmp(argv[1], "siginfo")) {
        return siginfo(argc - 1, argv + 1);
    }
    if (!strcmp(argv[1], "certinfo")) {
        return certinfo(argc - 1, argv + 1);
    }
    fprintf(stderr, "unknown command '%s'\n", argv[1]);
    exit(1);
}
