/*
 * Routines to handle RFC-2440 ascii armor.
 */

#include <string.h>

#include "pgpr_internal.h"

#define CRC24_INIT	0xb704ce
#define CRC24_POLY	0x1864cfb

static unsigned int r64crc(const uint8_t *octets, size_t len)
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
	    if (i == 0) {
		*eofp = 3;
		*vp = 0;
		return p - 1;
	    }
	    if (!x)
		return 0;	/* expected '=' padding */
	    x = 0;
	    *eofp += 1;
	} else if (x == '-' && i == 0) {
	    *eofp = 3;
	    *vp = 0;
	    return p - 1;
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

static const char *r64dec(const char *in, uint8_t **out, size_t *outlen)
{
    size_t inlen = strlen(in);
    unsigned char *obuf = pgprMalloc(inlen * 3 / 4 + 4);	/* can overshoot 3 bytes */
    unsigned char *optr = obuf;
    int eof = 0;
    if (!obuf) {
	*out = NULL;
	*outlen = 0;
	return in;
    }
    while (!eof) {
        unsigned int v;
	in = r64dec1(in, &v, &eof);
	if (!in) {
	    free(obuf);
	    return NULL;
	}
        *optr++ = v >> 16;
        *optr++ = v >> 8;
        *optr++ = v;
    }
    *out = obuf;
    *outlen = (optr - eof) - obuf;
    return in;
}

static const char bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *r64enc(const unsigned char *data, size_t len)
{
    char *out, *optr;
    size_t olen;
    int a, b, c, linelen = 64 / 4;
    if (data == NULL)
	return NULL;
    olen = ((len + 2) / 3) * 4;
    olen += olen / linelen;
    optr = out = pgprMalloc(olen + 2);
    if (!out)
	return NULL;
    while (len) {
	if (linelen-- == 0) {
	    linelen = 64 / 4 - 1;
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
    *optr = 0;
    return out;
}

pgprRC pgprArmorUnwrap(const char *armortype, const char *armor, uint8_t **pkts, size_t *pktslen)
{
    const char *enc = NULL;
    const char *encend = NULL;
    uint8_t * dec;
    size_t declen;
    const char *t, *te;
    int pstate = 0;
    pgprRC rc = PGPR_ERROR_ARMOR_NO_BEGIN_PGP;	/* XXX assume failure */

    if (!armortype || !armor || !*armor)
	return rc;

    for (t = armor; t && *t; t = te) {
	if ((te = strchr(t, '\n')) == NULL)
	    te = t + strlen(t);
	else
	    te++;

	switch (pstate) {
	case 0:
	    if (strncmp(t, "-----BEGIN PGP ", 15) != 0)
		continue;
	    t += 15;
	    if (strncmp(t, armortype, strlen(armortype)) != 0)
		continue;
	    t += strlen(armortype);
	    if (strncmp(t, "-----", 5) != 0)
		continue;
	    t += 5;
	    if (*t != '\n' && *t != '\r')
		continue;
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
	    encend = NULL;
	    if (*t != '=' && *t != '-')
		continue;
	    encend = t;		/* Start of encoded crc */
	    pstate++;
	    if (*t == '=')
		break;
	    /* FALLTHROUGH */
	case 3:
	    pstate = 0;
	    if (strncmp(t, "-----END PGP ", 13) != 0) {
		rc = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    t += 13;
	    if (strncmp(t, armortype, strlen(armortype)) != 0) {
		rc = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    t += strlen(armortype);
	    if (strncmp(t, "-----", 5) != 0) {
		rc = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    t += 5;
	    /* XXX permitting \r here is not RFC-2440 compliant <shrug> */
	    if (*t != '\n' && *t != '\r' && *t == '\0') {
		rc = PGPR_ERROR_ARMOR_NO_END_PGP;
		goto exit;
	    }
	    dec = NULL;
	    declen = 0;
	    enc = r64dec(enc, &dec, &declen);
	    if (enc && !dec) {
		rc = PGPR_ERROR_NO_MEMORY;
		goto exit;
	    }
	    if (enc == 0 || enc > encend || ((*enc == '=' || *enc == '-') && enc != encend)) {
		rc = PGPR_ERROR_ARMOR_BODY_DECODE;
		goto exit;
	    }
	    if (*encend == '=') {
		unsigned int crcpkt;
		uint32_t crc;
		int crceof = 0;

		if (r64dec1(encend + 1, &crcpkt, &crceof) == 0 || crceof != 0 || (encend[5] != '\n' && encend[5] != '\r')) {
		    rc = PGPR_ERROR_ARMOR_CRC_DECODE;
		    goto exit;
		}
		crc = r64crc(dec, declen);
		if (crcpkt != crc) {
#if 0
		    printf("=%c%c%c%c\n", bintoasc[(crc >> 18) & 63], bintoasc[(crc >> 12) & 63], bintoasc[(crc >> 6) & 63], bintoasc[crc & 63]);
#endif
		    rc = PGPR_ERROR_ARMOR_CRC_CHECK;
		    free(dec);
		    goto exit;
		}
	    }
	    if (pkts)
		*pkts = dec;
	    else
		free(dec);
	    if (pktslen)
		*pktslen = declen;
	    rc = PGPR_OK;
	    goto exit;
	}
    }

exit:
    return rc;
}

pgprRC pgprArmorWrap(const char *armortype, const char *keys, const unsigned char *s, size_t ns, char **armorp)
{
    char *buf = NULL, *val = NULL, *enc;
    unsigned int crc;
    const char *keysnl = "";

    if (keys && *keys && keys[strlen(keys) - 1] != '\n')
	keysnl = "\n";
    enc = r64enc(s, ns);
    if (!enc)
	return PGPR_ERROR_NO_MEMORY;
    crc = r64crc(s, ns);
    pgprAsprintf(&buf, "%s%s=%c%c%c%c", enc, (*enc ? "\n" : ""), bintoasc[(crc >> 18) & 63], bintoasc[(crc >> 12) & 63], bintoasc[(crc >> 6) & 63], bintoasc[crc & 63]);
    free(enc);
    if (!buf)
	return PGPR_ERROR_NO_MEMORY;
    pgprAsprintf(&val, "-----BEGIN PGP %s-----\n%s%s\n"
		    "%s\n-----END PGP %s-----\n",
		    armortype, keys != NULL ? keys : "", keysnl, buf != NULL ? buf : "", armortype);
    free(buf);
    if (!val)
	return PGPR_ERROR_NO_MEMORY;
    *armorp = val;
    return PGPR_OK;
}
