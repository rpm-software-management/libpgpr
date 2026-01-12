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

pgprItem
select_subkey(const uint8_t *pkts, size_t pktlen, pgprItem key, int subkey)
{
    pgprItem *subkeys;
    int nsubkeys = 0;
    if (pgprPubkeyParseSubkeys(pkts, pktlen, key, &subkeys, &nsubkeys) != PGPR_OK) {
	fprintf(stderr, "subkeys parse error\n");
	exit(1);
    }
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
    pgprDigCtx ctx;
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

    if (pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl) != PGPR_OK) {
	fprintf(stderr, "pubkey unwrap error\n");
	exit(1);
    }
    if (pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel) != PGPR_OK) {
	fprintf(stderr, "signature unwrap error\n");
	exit(1);
    }
    lints = 0;
    if (pgprPubkeyParse(pubkey, pubkeyl, &key, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "pubkey parse error: %s\n", lints);
	else
	    fprintf(stderr, "pubkey parse error\n");
	exit(1);
    }
    free(lints);

    if (subkey)
	key = select_subkey(pubkey, pubkeyl, key, subkey);

    lints = 0;
    if (pgprSignatureParse(signature, signaturel, &sig, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "signature parse error: %s\n", lints);
	else
	    fprintf(stderr, "signature parse error\n");
	exit(1);
    }
    free(lints);

    ctx = pgprDigestInit(pgprItemHashAlgo(sig));
    if (!ctx) {
	fprintf(stderr, "unsupported hash algorithm in signature\n");
	exit(1);
    }
    header = pgprItemHashHeader(sig, &headerlen);
    if (header)
	pgprDigestUpdate(ctx, header, headerlen);
    pgprDigestUpdate(ctx, data, datalen);
    trailer = pgprItemHashTrailer(sig, &trailerlen);
    if (trailer)
	pgprDigestUpdate(ctx, trailer, trailerlen);
    pgprDigestFinal(ctx, &hash, &hashlen);

    lints = 0;
    if (pgprVerifySignature(key, sig, hash, hashlen, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "signature verification error: %s\n", lints);
	else
	    fprintf(stderr, "signature verification error\n");
	exit(1);
    }
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
    if (pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl) != PGPR_OK) {
	fprintf(stderr, "pubkey unwrap error\n");
	exit(1);
    }
    lints = 0;
    if (pgprPubkeyParse(pubkey, pubkeyl, &key, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "pubkey parse error: %s\n", lints);
	else
	    fprintf(stderr, "pubkey parse error\n");
	exit(1);
    }
    if (subkey)
	key = select_subkey(pubkey, pubkeyl, key, subkey);
    printf("Version: %d\n", pgprItemVersion(key));
    printf("CreationTime: %d\n", pgprItemCreationTime(key));
    printf("Algorithm: %d\n", pgprItemPubkeyAlgo(key));
    printf("AlgorithmInfo: %d\n", pgprItemPubkeyAlgoInfo(key));
    printf("UserID: %s\n", nullify(pgprItemUserID(key)));
    keyfp = pgprItemKeyFingerprint(key, &keyfp_len, NULL);
    if (keyfp) {
	printf("KeyFP: ");
	for (i = 0; i < keyfp_len; i++)
	    printf("%02x", keyfp[i]);
	printf("\n");
    }
    keyid = pgprItemKeyID(key);
    if (keyid) {
	printf("KeyID: ");
	for (i = 0; i < 8; i++)
	    printf("%02x", keyid[i]);
	printf("\n");
    }
    pgprItemFree(key);
    free(pubkey_a);
    free(pubkey);
    return 0;
}

static int
siginfo(int argc, char **argv)
{
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
    if (pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel) != PGPR_OK) {
	fprintf(stderr, "signature unwrap error\n");
	exit(1);
    }
    lints = 0;
    if (pgprSignatureParse(signature, signaturel, &sig, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "signature parse error: %s\n", lints);
	else
	    fprintf(stderr, "signature parse error\n");
	exit(1);
    }
    printf("Version: %d\n", pgprItemVersion(sig));
    printf("CreationTime: %d\n", pgprItemCreationTime(sig));
    printf("Algorithm: %d\n", pgprItemPubkeyAlgo(sig));
    printf("Hash: %d\n", pgprItemHashAlgo(sig));
    keyfp = pgprItemKeyFingerprint(sig, &keyfp_len, NULL);
    if (keyfp) {
	printf("KeyFP: ");
	for (i = 0; i < keyfp_len; i++)
	    printf("%02x", keyfp[i]);
	printf("\n");
    }
    keyid = pgprItemKeyID(sig);
    if (keyid) {
	printf("KeyID: ");
	for (i = 0; i < 8; i++)
	    printf("%02x", keyid[i]);
	printf("\n");
    }
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
    fprintf(stderr, "unknown command '%s'\n", argv[1]);
    exit(1);
}
