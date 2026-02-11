#include <stdlib.h>
#include <stdint.h>

#define PGPR_KEYID_LEN 8

/* type definitions */
typedef struct pgprItem_s * pgprItem;
typedef void * pgprDigCtx;
typedef uint8_t pgprKeyID_t[PGPR_KEYID_LEN];

/* enum definitions */
typedef enum pgprRC_e {
    PGPR_OK				= 0,
    PGPR_ERROR_INTERNAL			= 10,
    PGPR_ERROR_BAD_ARGUMENT		= 11,
    PGPR_ERROR_NO_MEMORY		= 12,

    PGPR_ERROR_CORRUPT_PGP_PACKET	= 20,
    PGPR_ERROR_UNEXPECTED_PGP_PACKET	= 21,
    PGPR_ERROR_UNSUPPORTED_VERSION	= 22,
    PGPR_ERROR_UNSUPPORTED_ALGORITHM	= 23,
    PGPR_ERROR_UNSUPPORTED_CURVE	= 24,
    PGPR_ERROR_UNSUPPORTED_DIGEST	= 25,
    PGPR_ERROR_NO_CREATION_TIME		= 26,
    PGPR_ERROR_DUPLICATE_DATA		= 27,
    PGPR_ERROR_UNKNOWN_CRITICAL_PKT	= 28,
    PGPR_ERROR_BAD_PUBKEY_STRUCTURE	= 29,
    PGPR_ERROR_MISSING_SELFSIG		= 30,
    PGPR_ERROR_SELFSIG_VERIFICATION	= 31,
    PGPR_ERROR_BAD_SIGNATURE		= 32,
    PGPR_ERROR_REJECTED_PUBKEY		= 33,
    PGPR_ERROR_REJECTED_SIGNATURE	= 34,
    PGPR_ERROR_SIGNATURE_FROM_FUTURE  	= 35,
    PGPR_ERROR_SIGNATURE_EXPIRED	= 36,
    PGPR_ERROR_KEY_EXPIRED		= 37,
    PGPR_ERROR_KEY_REVOKED		= 38,
    PGPR_ERROR_PRIMARY_REVOKED		= 39,
    PGPR_ERROR_KEY_NOT_VALID		= 40,
    PGPR_ERROR_KEY_NO_SIGNING		= 41,
    PGPR_ERROR_KEY_CREATED_AFTER_SIG	= 42,

    PGPR_ERROR_ARMOR_NO_BEGIN_PGP	= 50,
    PGPR_ERROR_ARMOR_NO_END_PGP		= 51,
    PGPR_ERROR_ARMOR_CRC_CHECK		= 52,
    PGPR_ERROR_ARMOR_BODY_DECODE	= 53,
    PGPR_ERROR_ARMOR_CRC_DECODE		= 54
} pgprRC;

typedef enum pgprTag_e {
    PGPRTAG_RESERVED		=  0, /*!< Reserved/Invalid */
    PGPRTAG_PUBLIC_SESSION_KEY	=  1, /*!< Public-Key Encrypted Session Key */
    PGPRTAG_SIGNATURE		=  2, /*!< Signature */
    PGPRTAG_SYMMETRIC_SESSION_KEY= 3, /*!< Symmetric-Key Encrypted Session Key*/
    PGPRTAG_ONEPASS_SIGNATURE	=  4, /*!< One-Pass Signature */
    PGPRTAG_SECRET_KEY		=  5, /*!< Secret Key */
    PGPRTAG_PUBLIC_KEY		=  6, /*!< Public Key */
    PGPRTAG_SECRET_SUBKEY	=  7, /*!< Secret Subkey */
    PGPRTAG_COMPRESSED_DATA	=  8, /*!< Compressed Data */
    PGPRTAG_SYMMETRIC_DATA	=  9, /*!< Symmetrically Encrypted Data */
    PGPRTAG_MARKER		= 10, /*!< Marker */
    PGPRTAG_LITERAL_DAT		= 11, /*!< Literal Data */
    PGPRTAG_TRUST		= 12, /*!< Trust */
    PGPRTAG_USER_ID		= 13, /*!< User ID */
    PGPRTAG_PUBLIC_SUBKEY	= 14, /*!< Public Subkey */
    PGPRTAG_COMMENT_OLD		= 16, /*!< Comment (from OpenPGPR draft) */
    PGPRTAG_USER_ATTRIBUTE	= 17, /*!< User Attribute packet */
    PGPRTAG_ENCRYPTED_MDC	= 18, /*!< Integrity protected encrypted data */
    PGPRTAG_MDC			= 19, /*!< Manipulaion detection code packet */
    PGPRTAG_PADDING		= 21, /*!< Padding packet */
    PGPRTAG_PRIVATE_60		= 60, /*!< Private or Experimental Values */
    PGPRTAG_COMMENT		= 61, /*!< Comment */
    PGPRTAG_PRIVATE_62		= 62, /*!< Private or Experimental Values */
    PGPRTAG_CONTROL		= 63  /*!< Control (GPG) */
} pgprTag;

typedef enum pgprSigType_e {
    PGPRSIGTYPE_BINARY		 = 0x00, /*!< Binary document */
    PGPRSIGTYPE_TEXT		 = 0x01, /*!< Canonical text document */
    PGPRSIGTYPE_STANDALONE	 = 0x02, /*!< Standalone */
    PGPRSIGTYPE_GENERIC_CERT	 = 0x10,
		/*!< Generic certification of a User ID & Public Key */
    PGPRSIGTYPE_PERSONA_CERT	 = 0x11,
		/*!< Persona certification of a User ID & Public Key */
    PGPRSIGTYPE_CASUAL_CERT	 = 0x12,
		/*!< Casual certification of a User ID & Public Key */
    PGPRSIGTYPE_POSITIVE_CERT	 = 0x13,
		/*!< Positive certification of a User ID & Public Key */
    PGPRSIGTYPE_SUBKEY_BINDING	 = 0x18, /*!< Subkey Binding */
    PGPRSIGTYPE_PRIMARY_BINDING	 = 0x19, /*!< Primary Binding */
    PGPRSIGTYPE_SIGNED_KEY	 = 0x1F, /*!< Signature directly on a key */
    PGPRSIGTYPE_KEY_REVOKE	 = 0x20, /*!< Key revocation */
    PGPRSIGTYPE_SUBKEY_REVOKE	 = 0x28, /*!< Subkey revocation */
    PGPRSIGTYPE_CERT_REVOKE	 = 0x30, /*!< Certification revocation */
    PGPRSIGTYPE_TIMESTAMP	 = 0x40, /*!< Timestamp */
    PGPRSIGTYPE_THIRD_PARTY	 = 0x50, /*!< Third-Party Confirmation */
} pgprSigType;

typedef enum pgprPubkeyAlgo_e {
    PGPRPUBKEYALGO_RSA		=  1,	/*!< RSA */
    PGPRPUBKEYALGO_RSA_ENCRYPT	=  2,	/*!< RSA(Encrypt-Only) */
    PGPRPUBKEYALGO_RSA_SIGN	=  3,	/*!< RSA(Sign-Only) */
    PGPRPUBKEYALGO_ELGAMAL_ENCRYPT = 16,	/*!< Elgamal(Encrypt-Only) */
    PGPRPUBKEYALGO_DSA		= 17,	/*!< DSA */
    PGPRPUBKEYALGO_EC		= 18,	/*!< Elliptic Curve */
    PGPRPUBKEYALGO_ECDSA	= 19,	/*!< ECDSA */
    PGPRPUBKEYALGO_ELGAMAL	= 20,	/*!< Elgamal */
    PGPRPUBKEYALGO_DH		= 21,	/*!< Diffie-Hellman (X9.42) */
    PGPRPUBKEYALGO_EDDSA	= 22,	/*!< EdDSA */
    PGPRPUBKEYALGO_X25519	= 25,	/*!< X25519 */
    PGPRPUBKEYALGO_X448		= 26,	/*!< X448 */
    PGPRPUBKEYALGO_ED25519	= 27,	/*!< Ed25519 */
    PGPRPUBKEYALGO_ED448	= 28,	/*!< Ed448 */
    PGPRPUBKEYALGO_MLDSA65_ED25519 = 30, /*!< ML-DSA-65+Ed25519 hybrid */
    PGPRPUBKEYALGO_MLDSA87_ED448   = 31, /*!< ML-DSA-87+Ed448 hybrid */
} pgprPubkeyAlgo;

typedef enum pgprHashAlgo_e {
    PGPRHASHALGO_MD5		=  1,	/*!< MD5 */
    PGPRHASHALGO_SHA1		=  2,	/*!< SHA1 */
    PGPRHASHALGO_RIPEMD160	=  3,	/*!< RIPEMD160 */
    PGPRHASHALGO_MD2		=  5,	/*!< MD2 */
    PGPRHASHALGO_TIGER192	=  6,	/*!< TIGER192 */
    PGPRHASHALGO_HAVAL_5_160	=  7,	/*!< HAVAL-5-160 */
    PGPRHASHALGO_SHA256		=  8,	/*!< SHA2-256 */
    PGPRHASHALGO_SHA384		=  9,	/*!< SHA2-384 */
    PGPRHASHALGO_SHA512		= 10,	/*!< SHA2-512 */
    PGPRHASHALGO_SHA224		= 11,	/*!< SHA2-224 */
    PGPRHASHALGO_SHA3_256	= 12,	/*!< SHA3-256 */
					/*!< 13 reserved */
    PGPRHASHALGO_SHA3_512	= 14,	/*!< SHA3-256 */
} pgprHashAlgo;

/*
 * ECC Curves
 *
 * The following curve ids are private to pgpr. PGP uses
 * oids to identify a curve.
 */
typedef enum pgprCurveId_e {
    PGPRCURVE_NIST_P_256	=  1,	/*!< NIST P-256 */
    PGPRCURVE_NIST_P_384	=  2,	/*!< NIST P-384 */
    PGPRCURVE_NIST_P_521	=  3,	/*!< NIST P-521 */
    PGPRCURVE_BRAINPOOL_P256R1	=  4,	/*!< brainpoolP256r1 */
    PGPRCURVE_BRAINPOOL_P384R1	=  5,	/*!< brainpoolP384r1 */
    PGPRCURVE_BRAINPOOL_P512R1	=  6,	/*!< brainpoolP512r1 */
    PGPRCURVE_ED25519		=  7,	/*!< Ed25519 */
    PGPRCURVE_CURVE25519	=  8,	/*!< Curve25519 */
    PGPRCURVE_ED448		=  9,	/*!< Ed448 */
    PGPRCURVE_X448		=  10,	/*!< X448 */
} pgprCurveId;


/* function declarations */

/* initialization */
pgprRC pgprInitCrypto(void);

pgprRC pgprFreeCrypto(void);

/* feature introspection */
pgprRC pgprSupportedAlgo(int algo, int curve);

/* item management */
pgprItem pgprItemNew(uint8_t tag);

pgprItem pgprItemFree(pgprItem item);

/* item introspection methods */
int pgprItemTag(pgprItem item);

int pgprItemCmp(pgprItem p1, pgprItem p2);

int pgprItemSignatureType(pgprItem item);

int pgprItemPubkeyAlgo(pgprItem item);

int pgprItemPubkeyAlgoInfo(pgprItem item);

int pgprItemHashAlgo(pgprItem item);

const uint8_t *pgprItemKeyID(pgprItem item);

const uint8_t *pgprItemKeyFingerprint(pgprItem item, size_t *fp_len, int *fp_version);

const char *pgprItemUserID(pgprItem item);

int pgprItemVersion(pgprItem item);

int64_t pgprItemCreationTime(pgprItem item);

int64_t pgprItemModificationTime(pgprItem item);

int64_t pgprItemExpirationTime(pgprItem item);

const uint8_t *pgprItemHashHeader(pgprItem item, size_t *headerlen);

const uint8_t *pgprItemHashTrailer(pgprItem item, size_t *trailerlen);

/* signature verification*/
pgprRC pgprVerifySignature(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen, char **lints);

pgprRC pgprVerifySignatureNoKey(pgprItem sig, const uint8_t *hash, size_t hashlen, char **lints);

/* pgp packet parsing */
pgprRC pgprSignatureParse(const uint8_t *pkts, size_t pktslen, pgprItem *ret, char **lints);

pgprRC pgprPubkeyParse(const uint8_t *pkts, size_t pktslen, pgprItem *ret, char **lints);

pgprRC pgprPubkeyParseSubkeys(const uint8_t *pkts, size_t pktslen, pgprItem key, pgprItem **subkeys, int *subkeysCount);

pgprRC pgprPubkeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen);

pgprRC pgprPubkeyKeyID(const uint8_t *pkts, size_t pktslen, pgprKeyID_t keyid);

pgprRC pgprPubkeyFingerprint(const uint8_t *pkts, size_t pktslen, uint8_t **fp, size_t *fp_len, int *fp_version);

pgprRC pgprPubkeyMerge(const uint8_t *pkts1, size_t pkts1len, const uint8_t *pkts2, size_t pkts2len, uint8_t **pktsm, size_t *pktsmlen, int flags);

/* armor functions */
pgprRC pgprArmorWrap(const char *armortype, const char *keys, const unsigned char *s, size_t ns, char **armorp);

pgprRC pgprArmorUnwrap(const char *armortype, const char *armor, uint8_t **pkts, size_t *pktslen);

/* digest functions */
pgprRC pgprDigestInit(int hashalgo, pgprDigCtx *ret);

pgprRC pgprDigestUpdate(pgprDigCtx ctx,  const void *data, size_t len);

pgprRC pgprDigestFinal(pgprDigCtx ctx, void **datap, size_t *lenp);

pgprRC pgprDigestDup(pgprDigCtx oldctx, pgprDigCtx *ret);

size_t pgprDigestLength(int hashalgo);

/* error reporting */
const char *pgprErrorStr(pgprRC rc);

/* configuration and testing */
void pgprSetFixedTime(uint64_t t);
