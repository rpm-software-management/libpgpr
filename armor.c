/*
 * Routines to handle RFC-2440 ascii armor.
 */

#include <string.h>

#include "pgpr.h"
#include "pgpr_internal.h"

#define CRC24_INIT	0xb704ce
#define CRC24_POLY	0x1864cfb

static unsigned int pgprCRC(const uint8_t *octets, size_t len)
{
    unsigned int crc = CRC24_INIT;
    size_t i;

    while (len--) {
	crc ^= (*octets++) << 16;
	for (i = 0; i < 8; i++) {
	    crc <<= 1;
	    if (crc & 0x1000000)
		crc ^= CRC24_POLY;
	}
    }
    return crc & 0xffffff;
}

static inline const char *r64dec1(const char *p, unsigned int *vp, int *eofp)
{
    int i, x;
    unsigned int v = 0;

    for (i = 0; i < 4; ) {
	x = *p++;
	if (!x && i)
	    return 0;	/* expected '=' padding */
	if (x >= 'A' && x <= 'Z')
	    x -= 'A';
	else if (x >= 'a' && x <= 'z')
	    x -= 'a' - 26;
	else if (x >= '0' && x <= '9')
	    x -= '0' - 52;
	else if (x == '+')
	    x = 62;
	else if (x == '/')
	    x = 63;
	else if (x == '=' || x == 0) {
	    x = 0;
	    if (i == 0)
	      {
		*eofp = 3;
		*vp = 0;
		return p - 1;
	      }
	    *eofp += 1;
	} else if (x > 0 && x <= 32) {
	    continue;	/* ignore control chars */
	} else {
	    return 0;
	}
	v = v << 6 | x;
	i++;
    }
    *vp = v;
    return p;
}

static int pgprBase64Decode(const char *in, void **out, size_t *outlen)
{
    size_t inlen = strlen(in);
    unsigned char *obuf = pgprMalloc(inlen * 3 / 4 + 4);
    unsigned char *optr = obuf;
    int eof = 0;
    while (!eof) {
        unsigned int v;
	in = r64dec1(in, &v, &eof);
	if (!in) {
	    free(obuf);
	    return 1;
	}
        *optr++ = v >> 16;
        *optr++ = v >> 8;
        *optr++ = v;
    }
    *out = obuf;
    *outlen = (optr - eof) - obuf;
    return 0;
}

static const char bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *pgprBase64Encode(const unsigned char *data, size_t len)
{
    char *out, *optr;
    size_t olen;
    int a, b, c, linelen = 64;
    if (data == NULL)
	return NULL;
    olen = ((len + 2) / 3) * 4;
    optr = out = pgprMalloc(olen + olen / 64 + 2);
    while (len) {
	if (linelen-- == 0) {
	    linelen = 64;
	    *optr++ = '\n';
	}
        a = *data++;
        b = len > 1 ? *data++ : 0;
        c = len > 2 ? *data++ : 0;
        *optr++ = bintoasc[a >> 2];
        *optr++ = bintoasc[(a & 3) << 4 | b >> 4];
        *optr++ = len > 1 ? bintoasc[(b & 15) << 2 | c >> 6] : '=';
        *optr++ = len > 2 ? bintoasc[c & 63] : '=';
	len = len < 3 ? 0 : len - 3;
    }
    return out;
}

static pgprRC decodePkts(const char *armortype, uint8_t *b, uint8_t **pkt, size_t *pktlen)
{
    const char * enc = NULL;
    const char * crcenc = NULL;
    uint8_t * dec;
    size_t declen;
    unsigned int crcpkt;
    uint32_t crc;
    char * t, * te;
    int pstate = 0;
    int crceof = 0;
    pgprRC ec = PGPR_ERROR_ARMOR_NO_BEGIN_PGP;	/* XXX assume failure */

#define	TOKEQ(_s, _tok)	(strncmp((_s), (_tok), sizeof(_tok)-1) == 0)

    for (t = (char *)b; t && *t; t = te) {
	if ((te = strchr(t, '\n')) == NULL)
	    te = t + strlen(t);
	else
	    te++;

	switch (pstate) {
	case 0:
	    if (!TOKEQ(t, "-----BEGIN PGP "))
		continue;
	    t += sizeof("-----BEGIN PGP ")-1;
	    if (strncmp(t, armortype, strlen(armortype)) != 0)
		continue;
	    t += strlen(armortype);
	    if (!TOKEQ(t, "-----"))
		continue;
	    t += sizeof("-----")-1;
	    if (*t != '\n' && *t != '\r')
		continue;
	    *t = '\0';
	    pstate++;
	    break;
	case 1:
	    enc = NULL;
	    if ((*t >= 'a' && *t <= 'z') || (*t >= 'A' && *t <= 'Z')) {
		/* skip all armor keys */
		t++;
		while ((*t >= 'a' && *t <= 'z') || (*t >= 'A' && *t <= 'Z'))
		    t++;
		if (*t != ':')
		    pstate = 0;		/* syntax error */
		continue;
	    }
	    if (*t != '\n' && *t != '\r') {
		pstate = 0;
		continue;
	    }
	    enc = te;		/* Start of encoded packets */
	    pstate++;
	    break;
	case 2:
	    crcenc = NULL;
	    if (*t != '=')
		continue;
	    *t++ = '\0';	/* Terminate encoded packets */
	    crcenc = t;		/* Start of encoded crc */
	    pstate++;
	    break;
	case 3:
	    pstate = 0;
	    if (!TOKEQ(t, "-----END PGP ")) {
		ec = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    *t = '\0';		/* Terminate encoded crc */
	    t += sizeof("-----END PGP ")-1;
	    if (t >= te) continue;

	    if (strncmp(t, armortype, strlen(armortype)) != 0)
		continue;

	    t += strlen(armortype);
	    if (t >= te) continue;

	    if (!TOKEQ(t, "-----")) {
		ec = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    t += (sizeof("-----")-1);
	    /* Handle EOF without EOL here, *t == '\0' at EOF */
	    if (*t && (t >= te)) continue;
	    /* XXX permitting \r here is not RFC-2440 compliant <shrug> */
	    if (!(*t == '\n' || *t == '\r' || *t == '\0')) continue;

	    if (r64dec1(crcenc, &crcpkt, &crceof) == 0 || crceof != 0) {
		ec = PGPR_ERROR_ARMOR_CRC_DECODE;
		goto exit;
	    }
	    dec = NULL;
	    declen = 0;
	    if (pgprBase64Decode(enc, (void **)&dec, &declen) != 0) {
		ec = PGPR_ERROR_ARMOR_BODY_DECODE;
		goto exit;
	    }
	    crc = pgprCRC(dec, declen);
	    if (crcpkt != crc) {
#if 0
		printf("=%c%c%c%c\n", bintoasc[(crc >> 18) & 63], bintoasc[(crc >> 12) & 63], bintoasc[(crc >> 6) & 63], bintoasc[crc & 63]);
#endif
		ec = PGPR_ERROR_ARMOR_CRC_CHECK;
		free(dec);
		goto exit;
	    }
	    if (pkt)
		*pkt = dec;
	    else
		free(dec);
	    if (pktlen) *pktlen = declen;
	    ec = PGPR_OK;
	    goto exit;
	    break;
	}
    }

exit:
    return ec;
}

pgprRC pgprArmorUnwrap(const char *armortype, const char *armor, uint8_t ** pkt, size_t * pktlen)
{
    pgprRC rc = PGPR_ERROR_ARMOR_NO_BEGIN_PGP;
    if (armortype && armor && *armor) {
	uint8_t *b = (uint8_t*) pgprStrdup(armor);
	rc = decodePkts(armortype, b, pkt, pktlen);
	free(b);
    }
    return rc;
}

char *pgprArmorWrap(const char *armortype, const char *keys, const unsigned char * s, size_t ns)
{
    char *buf = NULL, *val = NULL, *enc;
    unsigned int crc;

    enc = pgprBase64Encode(s, ns);
    crc = pgprCRC(s, ns);
    if (enc != NULL)
	pgprAsprintf(&buf, "%s=%c%c%c%c", enc, bintoasc[(crc >> 18) & 63], bintoasc[(crc >> 12) & 63], bintoasc[(crc >> 6) & 63], bintoasc[crc & 63]);
    free(enc);
    pgprAsprintf(&val, "-----BEGIN PGP %s-----\n%s\n"
		    "%s\n-----END PGP %s-----\n",
		    armortype, keys != NULL ? keys : "", buf != NULL ? buf : "", armortype);
    free(buf);
    return val;
}
