#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "../pgpr.h"

static void
die(const char *str)
{
    fprintf(stderr, "%s\n", str);
}

static void
die_errno(const char *str)
{
    perror(str);
    exit(1);
}

static void
die_rc(const char *str, pgprRC rc)
{
    if (rc == PGPR_OK)
	fprintf(stderr, "%s\n", str);
    else
	fprintf(stderr, "%s: %s\n", str, pgprErrorStr(rc));
    exit(1);
}

static char *slurp(const char *fn, size_t *lenp)
{
    size_t len = 0;
    char *buf = 0;
    int l;
    FILE *fp;

    if ((fp = fopen(fn, "r")) == 0)
	die_errno(fn);
    while (1) {
	buf = realloc(buf, len + 65536);
	if (!buf)
	    die("Out of memory");
	l = fread(buf + len, 1, 65536, fp);
	if (l < 0)
	    die_errno("fread");
	if (l == 0)
	    break;
	len += l;
    }
    fclose(fp);
    buf = realloc(buf, len + 1);
    if (!buf)
	die("Out of memory");
    buf[len] = 0;
    if (lenp)
	*lenp = len;
    return buf;
}

static void
printhex(const char *what, const uint8_t *d, size_t l)
{
    size_t i;
    if (what)
	printf("%s: ", what);
    for (i = 0; i < l; i++)
	printf("%02x", d[i]);
    printf("\n");
}


pgprItem
select_subkey(const uint8_t *pkts, size_t pktlen, pgprItem key, int subkey)
{
    pgprRC rc;
    pgprItem *subkeys;
    int nsubkeys = 0;

    if ((rc = pgprPubkeyParseSubkeys(pkts, pktlen, key, &subkeys, &nsubkeys)) != PGPR_OK)
	die_rc("subkeys parse error", rc);
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
    void *hash = NULL;
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
    if (argc - optind != 3)
	die("usage: testpgpr verifysignature [-s subkey] <pubkey> <sig> <data>");
    pubkey_a = slurp(argv[optind], NULL);
    signature_a = slurp(argv[optind + 1], NULL);
    data = (unsigned char *)slurp(argv[optind + 2], &datalen);

    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die_rc("pubkey unwrap error", rc);
    if ((rc = pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel)) != PGPR_OK)
	die_rc("signature unwrap error", rc);
    lints = 0;
    if ((rc = pgprPubkeyParse(pubkey, pubkeyl, &key, &lints)) != PGPR_OK) {
	if (!lints)
	    die_rc("pubkey parse error", rc);
	fprintf(stderr, "pubkey parse error: %s\n", lints);
	exit(1);
    }
    free(lints);

    if (subkey)
	key = select_subkey(pubkey, pubkeyl, key, subkey);

    lints = 0;
    if ((rc = pgprSignatureParse(signature, signaturel, &sig, &lints)) != PGPR_OK) {
	if (!lints)
	    die_rc("signature parse error", rc);
	fprintf(stderr, "signature parse error: %s\n", lints);
	exit(1);
    }
    free(lints);

    if ((rc = pgprDigestInit(pgprItemHashAlgo(sig), &ctx)) != PGPR_OK)
	die_rc("digest init error", rc);
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
	    die_rc("signature verification error", rc);
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
    if (argc - optind != 1)
	die("usage: testpgpr keyinfo [-s subkey] <pubkey>");
    pubkey_a = slurp(argv[optind], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die_rc("pubkey unwrap error", rc);
    lints = 0;
    if ((rc = pgprPubkeyParse(pubkey, pubkeyl, &key, &lints)) != PGPR_OK) {
	if (!lints)
	    die_rc("pubkey parse error", rc);
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
    
    if (argc - 1 != 1)
	die("usage: testpgpr certinfo <pubkey>");
    pubkey_a = slurp(argv[optind], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey_a, &pubkey, &pubkeyl)) != PGPR_OK)
	die_rc("pubkey unwrap error", rc);
    if ((rc = pgprPubkeyFingerprint(pubkey, pubkeyl, &fp, &fplen, NULL)) != PGPR_OK)
	die_rc("pgprPubkeyFingerprint error", rc);
    printhex("KeyFP", fp, fplen);
    memset(keyid, 0, sizeof(keyid));
    if ((rc = pgprPubkeyKeyID(pubkey, pubkeyl, keyid)) != PGPR_OK)
	die_rc("pgprPubkeyKeyID error", rc);
    printhex("KeyID", keyid, 8);
    if ((rc = pgprPubkeyCertLen(pubkey, pubkeyl, &certlen)) != PGPR_OK)
	die_rc("pgprPubkeyCertLen error", rc);
    printf("CertLen: %zd\n", certlen);
    free(fp);
    free(pubkey_a);
    free(pubkey);
    return 0;
}

static int
merge(int argc, char **argv)
{
    pgprRC rc;
    char *pubkey1_a;
    unsigned char *pubkey1;
    size_t pubkey1l;
    char *pubkey2_a;
    unsigned char *pubkey2;
    size_t pubkey2l;
    unsigned char *pubkeym = NULL;
    size_t pubkeyml = 0;
    char *pubkeym_a = NULL;
    
    if (argc - 1 != 2)
	die("usage: testpgpr merge <pubkey1> <pubkey2>");
    pubkey1_a = slurp(argv[1], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey1_a, &pubkey1, &pubkey1l)) != PGPR_OK)
	die_rc("pubkey1 unwrap error", rc);
    pubkey2_a = slurp(argv[2], NULL);
    if ((rc = pgprArmorUnwrap("PUBLIC KEY BLOCK", pubkey2_a, &pubkey2, &pubkey2l)) != PGPR_OK)
	die_rc("pubkey2 unwrap error", rc);
    if ((rc = pgprPubkeyMerge(pubkey1, pubkey1l, pubkey2, pubkey2l, &pubkeym, &pubkeyml)) != PGPR_OK)
	die_rc("merge error", rc);
    if ((rc = pgprArmorWrap("PUBLIC KEY BLOCK", NULL, pubkeym, pubkeyml, &pubkeym_a)) != PGPR_OK)
	die_rc("pubkey wrap error", rc);
    printf("%s", pubkeym_a);
    free(pubkey1_a);
    free(pubkey1);
    free(pubkey2_a);
    free(pubkey2);
    free(pubkeym_a);
    free(pubkeym);
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

    if (argc != 2)
	die("usage: testpgpr siginfo <signature>");
    signature_a = slurp(argv[1], NULL);
    if ((rc = pgprArmorUnwrap("SIGNATURE", signature_a, &signature, &signaturel)) != PGPR_OK)
	die_rc("signature unwrap error", rc);
    lints = 0;
    if ((rc = pgprSignatureParse(signature, signaturel, &sig, &lints)) != PGPR_OK) {
	if (!lints)
	    die_rc("signature parse error", rc);
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

static int
enarmor(int argc, char **argv)
{
    pgprRC rc;
    int c;
    char *keys = NULL;
    unsigned char *data = NULL;
    size_t datal;
    char *armor = NULL;

    while ((c = getopt(argc, argv, "k:")) >= 0) {
	switch(c) {
	case 'k':
	    keys = optarg;
	    break;
	default:
	    break;
	}
    }
    if (argc - optind != 2)
	die("usage: testpgpr enarmor [-k keyline] <type> <file>");
    data = (unsigned char *)slurp(argv[optind + 1], &datal);
    if ((rc = pgprArmorWrap(argv[optind], keys, data, datal, &armor)) != PGPR_OK)
	die_rc("wrap error", rc);
    printf("%s", armor);
    free(armor);
    free(data);
    return 0;
}

static int
dearmor(int argc, char **argv)
{
    pgprRC rc;
    char *armor = NULL;
    unsigned char *data = NULL;
    size_t datal;
    if (argc != 3)
	die("usage: testpgpr dearmor <type> <file>");
    armor = slurp(argv[2], NULL);
    if ((rc = pgprArmorUnwrap(argv[1], armor, &data, &datal)) != PGPR_OK)
	die_rc("unwrap error", rc);
    printhex(NULL, data, datal);
    free(data);
    free(armor);
    return 0;
}

static int
digest(int argc, char **argv)
{
    pgprRC rc;
    unsigned char *data = NULL;
    size_t datal;
    pgprDigCtx ctx = NULL;
    int algo;
    void *hash = NULL;
    size_t hashlen = 0;

    if (argc != 3)
	die("usage: testpgpr dearmor <algo> <file>");
    data = (unsigned char *)slurp(argv[2], &datal);
    algo = atoi(argv[1]);
    if ((rc = pgprDigestInit(algo, &ctx)) != PGPR_OK)
	die_rc("digest init error", rc);
    pgprDigestUpdate(ctx, data, datal);
    if ((rc = pgprDigestFinal(ctx, &hash, &hashlen)) != PGPR_OK)
	die_rc("digest final error", rc);
    printhex(NULL, hash, hashlen);
    free(hash);
    free(data);
    return 0;
}

static int
feature(int argc, char **argv)
{
    pgprRC rc = PGPR_OK;
    char *feature;
    size_t len;
    if (argc != 2)
	die("usage: testpgpr feature <name>");
    feature = argv[1];
    len = strlen(feature);
    if (!strncmp(feature, "algo(", 5) && feature[len - 1] == ')') {
	int curve = 0, algo = atoi(feature + 5);
	char *cp;
	if ((cp = strchr(feature + 5, '.')) != 0)
	    curve = atoi(cp + 1);
	rc = pgprSupportedAlgo(algo, curve);
    } else if (!strncmp(feature, "digest(", 7) && feature[len - 1] == ')') {
	int digest = atoi(feature + 7);
	rc = pgprDigestLength(digest) > 0 ? PGPR_OK : PGPR_ERROR_UNSUPPORTED_DIGEST;
    } else {
	fprintf(stderr, "unknown feature '%s'\n", feature);
	exit(1);
    }
    if (rc == PGPR_OK) {
	printf("OK\n");
    } else {
	printf("FAIL: %s\n", pgprErrorStr(rc));
    }
    return 0;
}

int main(int argc, char **argv)
{
    pgprRC rc;
    int st = 1;
    if (argc < 2)
	die("usage: testpgpr <cmd>...");
    if ((rc = pgprInitCrypto()) != PGPR_OK)
	die_rc("crypto backend init failed", rc);
    if (!strcmp(argv[1], "verifysignature")) {
        st = verifysignature(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "keyinfo")) {
        st = keyinfo(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "siginfo")) {
        st = siginfo(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "certinfo")) {
        st = certinfo(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "enarmor")) {
        st = enarmor(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "dearmor")) {
        st = dearmor(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "digest")) {
        st = digest(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "merge")) {
        st = merge(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "feature")) {
        st = feature(argc - 1, argv + 1);
    } else {
	fprintf(stderr, "unknown command '%s'\n", argv[1]);
	exit(1);
    }
    if ((rc = pgprFreeCrypto()) != PGPR_OK)
	die_rc("crypto backend free failed", rc);
    return st;
}
