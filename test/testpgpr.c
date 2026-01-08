#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

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
    pgprDigParams key = NULL, sig = NULL;
    char *lints;
    pgprDigCtx ctx;
    const uint8_t *trailer;
    size_t trailerlen;
    const uint8_t *header;
    size_t headerlen;
    void *hash;
    size_t hashlen;

    if (argc != 4) {
	fprintf(stderr, "usage: testpgpr verifysignature <pubkey> <sig> <data>\n");
	exit(1);
    }
    pubkey_a = slurp(argv[1], NULL);
    signature_a = slurp(argv[2], NULL);
    data = slurp(argv[3], &datalen);

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

    lints = 0;
    if (pgprSignatureParse(signature, signaturel, &sig, &lints) != PGPR_OK) {
	if (lints)
	    fprintf(stderr, "signature parse error: %s\n", lints);
	else
	    fprintf(stderr, "signature parse error\n");
	exit(1);
    }
    free(lints);

    ctx = pgprDigestInit(pgprDigParamsHashAlgo(sig));
    if (!ctx) {
	fprintf(stderr, "unsupported hash algorithm in signature\n");
	exit(1);
    }
    header = pgprDigParamsHashHeader(sig, &headerlen);
    if (header)
	pgprDigestUpdate(ctx, header, headerlen);
    pgprDigestUpdate(ctx, data, datalen);
    trailer = pgprDigParamsHashTrailer(sig, &trailerlen);
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
    pgprDigParamsFree(key);
    pgprDigParamsFree(sig);
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
    pgprDigParams key = NULL;
    const unsigned char *keyid;
    const unsigned char *keyfp;
    size_t keyfp_len = 0;
    int i;

    if (argc != 2) {
	fprintf(stderr, "usage: testpgpr keyinfo <pubkey>\n");
	exit(1);
    }
    pubkey_a = slurp(argv[1], NULL);
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
    printf("Version: %d\n", pgprDigParamsVersion(key));
    printf("CreationTime: %d\n", pgprDigParamsCreationTime(key));
    printf("Algorithm: %d\n", pgprDigParamsPubkeyAlgo(key));
    printf("UserID: %s\n", nullify(pgprDigParamsUserID(key)));
    keyfp = pgprDigParamsKeyFingerprint(key, &keyfp_len, NULL);
    if (keyfp) {
	printf("KeyFP: ");
	for (i = 0; i < keyfp_len; i++)
	    printf("%02x", keyfp[i]);
	printf("\n");
    }
    keyid = pgprDigParamsKeyID(key);
    if (keyid) {
	printf("KeyID: ");
	for (i = 0; i < 8; i++)
	    printf("%02x", keyid[i]);
	printf("\n");
    }
    pgprDigParamsFree(key);
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
    pgprDigParams sig = NULL;
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
    printf("Version: %d\n", pgprDigParamsVersion(sig));
    printf("CreationTime: %d\n", pgprDigParamsCreationTime(sig));
    printf("Algorithm: %d\n", pgprDigParamsPubkeyAlgo(sig));
    printf("Hash: %d\n", pgprDigParamsHashAlgo(sig));
    keyfp = pgprDigParamsKeyFingerprint(sig, &keyfp_len, NULL);
    if (keyfp) {
	printf("KeyFP: ");
	for (i = 0; i < keyfp_len; i++)
	    printf("%02x", keyfp[i]);
	printf("\n");
    }
    keyid = pgprDigParamsKeyID(sig);
    if (keyid) {
	printf("KeyID: ");
	for (i = 0; i < 8; i++)
	    printf("%02x", keyid[i]);
	printf("\n");
    }
    pgprDigParamsFree(sig);
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
