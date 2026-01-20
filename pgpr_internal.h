/*
 * internal definitions and function declarations
 */

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define PGPR_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))
#else
# define PGPR_GNUC_PRINTF( format_idx, arg_idx )
#endif

#if    __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)
# define PGPR_GNUC_INTERNAL __attribute__((visibility("hidden")))
#else
# define PGPR_GNUC_INTERNAL
#endif


#include "pgpr.h"


/* max number of bytes in a key */
#define PGPR_MAX_OPENPGP_BYTES (65535)
/* maximum fingerprint length */
#define PGPR_MAX_FP_LENGTH 32

typedef struct pgprAlg_s * pgprAlg;
typedef pgprRC (*setmpifunc)(pgprAlg item, int num, const uint8_t *p, int mlen);
typedef pgprRC (*verifyfunc)(pgprAlg pgprkey, pgprAlg pgprsig,
                          const uint8_t *hash, size_t hashlen, int hash_algo);
typedef void (*freefunc)(pgprAlg item);

struct pgprAlg_s {
    setmpifunc setmpi;
    verifyfunc verify;
    freefunc free;
    pgprRC setup_rc;
    int algo;
    int curve;
    int info;
    int mpis;
    void *data;			/*!< algorithm specific private data */
};

/*
 * Values parsed from OpenPGP signature/pubkey packet(s).
 */
struct pgprItem_s {
    uint8_t tag;
    char * userid;		/*!< key user id */
    uint8_t key_flags;		/*!< key usage flags */

    uint8_t version;		/*!< key/signature version number. */
    uint32_t time;		/*!< key/signature creation time. */
    uint32_t key_mtime;		/*!< key last modification time */
    uint8_t pubkey_algo;	/*!< key/signature public key algorithm. */
    uint8_t hash_algo;		/*!< signature hash algorithm */
    uint8_t sigtype;
    uint8_t fp[PGPR_MAX_FP_LENGTH];	/*!< fingerprint of key or sig */
    int fp_len;				/*!< length of fp or zero */
    int fp_version;			/*!< key version of fp */
    pgprKeyID_t keyid;		/*!< key id of pubkey or signature */
    uint32_t key_expire;	/*!< key expire time. */
    uint32_t sig_expire;	/*!< signature expire time. */
    int revoked;		/*!< is the key revoked? */
    int saved;			/*!< Various flags. */
#define	PGPRITEM_SAVED_TIME		(1 << 0)
#define	PGPRITEM_SAVED_ID		(1 << 1)
#define	PGPRITEM_SAVED_KEY_FLAGS		(1 << 2)
#define	PGPRITEM_SAVED_KEY_EXPIRE	(1 << 3)
#define	PGPRITEM_SAVED_PRIMARY		(1 << 4)
#define	PGPRITEM_SAVED_VALID		(1 << 5)
#define	PGPRITEM_SAVED_SIG_EXPIRE	(1 << 6)
#define	PGPRITEM_SAVED_FP		(1 << 7)
    uint8_t * embedded_sig;	/* embedded signature */
    size_t embedded_sig_len;	/* length of the embedded signature */
    pgprKeyID_t mainid;		/* key id of main key if this is a subkey */

    uint8_t * hash;
    uint32_t hashlen;
    uint32_t saltlen;

    uint8_t signhash16[2];

    size_t mpi_offset;		/* start of mpi data */
    pgprAlg alg;		/*!< algorithm specific data like MPIs */
};

/*
 * decoded PGP packet
 */
typedef struct pgprPkt_s {
    uint8_t tag;		/* decoded PGP tag */
    const uint8_t *head;	/* pointer to start of packet (header) */
    const uint8_t *body;	/* pointer to packet body */
    size_t blen;		/* length of body in bytes */
} pgprPkt;

typedef enum pgprSubType_e {
    PGPRSUBTYPE_NONE		=   0, /*!< none */
    PGPRSUBTYPE_SIG_CREATE_TIME	=   2, /*!< signature creation time */
    PGPRSUBTYPE_SIG_EXPIRE_TIME	=   3, /*!< signature expiration time */
    PGPRSUBTYPE_EXPORTABLE_CERT	=   4, /*!< exportable certification */
    PGPRSUBTYPE_TRUST_SIG	=   5, /*!< trust signature */
    PGPRSUBTYPE_REGEX		=   6, /*!< regular expression */
    PGPRSUBTYPE_REVOCABLE	=   7, /*!< revocable */
    PGPRSUBTYPE_KEY_EXPIRE_TIME	=   9, /*!< key expiration time */
    PGPRSUBTYPE_ARR		=  10, /*!< additional recipient request */
    PGPRSUBTYPE_PREFER_SYMKEY	=  11, /*!< preferred symmetric algorithms */
    PGPRSUBTYPE_REVOKE_KEY	=  12, /*!< revocation key */
    PGPRSUBTYPE_ISSUER_KEYID	=  16, /*!< issuer key ID */
    PGPRSUBTYPE_NOTATION	=  20, /*!< notation data */
    PGPRSUBTYPE_PREFER_HASH	=  21, /*!< preferred hash algorithms */
    PGPRSUBTYPE_PREFER_COMPRESS	=  22, /*!< preferred compression algorithms */
    PGPRSUBTYPE_KEYSERVER_PREFERS = 23, /*!< key server preferences */
    PGPRSUBTYPE_PREFER_KEYSERVER = 24, /*!< preferred key server */
    PGPRSUBTYPE_PRIMARY_USERID	=  25, /*!< primary user id */
    PGPRSUBTYPE_POLICY_URL	=  26, /*!< policy URL */
    PGPRSUBTYPE_KEY_FLAGS	=  27, /*!< key flags */
    PGPRSUBTYPE_SIGNER_USERID	=  28, /*!< signer's user id */
    PGPRSUBTYPE_REVOKE_REASON	=  29, /*!< reason for revocation */
    PGPRSUBTYPE_FEATURES	=  30, /*!< feature flags (gpg) */
    PGPRSUBTYPE_EMBEDDED_SIG	=  32, /*!< embedded signature (gpg) */
    PGPRSUBTYPE_ISSUER_FINGERPRINT = 33, /*!< issuer fingerprint */
    PGPRSUBTYPE_INTREC_FINGERPRINT = 35, /*!< intended recipient fingerprint */
    PGPRSUBTYPE_PREFER_AEAD	= 39,  /*!<  preferred AEAD ciphercuites */

    PGPRSUBTYPE_CRITICAL	= 128  /*!< critical subpacket marker */
} pgprSubType;

/* internal pubkey algorithms. They cannot conflict with the official definitions
   ss pgp uses just one byte for the algo */
#define PGPRPUBKEYALGO_INTERNAL_MLDSA65	(256 + 0)
#define PGPRPUBKEYALGO_INTERNAL_MLDSA87	(256 + 1)


/* pgpr packet decoding */
PGPR_GNUC_INTERNAL
pgprRC pgprDecodePkt(const uint8_t *p, size_t plen, pgprPkt *pkt);

/* crypto handling */
PGPR_GNUC_INTERNAL
pgprAlg pgprAlgNew(void);

PGPR_GNUC_INTERNAL
pgprAlg pgprAlgFree(pgprAlg alg);

PGPR_GNUC_INTERNAL
pgprRC pgprAlgSetupPubkey(pgprAlg alg, int algo, int curve, const uint8_t *p, const uint8_t *const pend);

PGPR_GNUC_INTERNAL
pgprRC pgprAlgSetupSignature(pgprAlg alg, int algo, const uint8_t *p, const uint8_t *const pend);

PGPR_GNUC_INTERNAL
pgprRC pgprAlgVerify(pgprAlg sigalg, pgprAlg keyalg, const uint8_t *hash, size_t hashlen, int hash_algo);

PGPR_GNUC_INTERNAL
pgprRC pgprInitSigHybrid(pgprAlg sa);

PGPR_GNUC_INTERNAL
pgprRC pgprInitKeyHybrid(pgprAlg ka);

/* crypto internal, provided by the crypto backend glue */
PGPR_GNUC_INTERNAL
pgprRC pgprAlgInitPubkey(pgprAlg alg);

PGPR_GNUC_INTERNAL
pgprRC pgprAlgInitSignature(pgprAlg alg);

/* pgp packet data extraction */
PGPR_GNUC_INTERNAL
pgprRC pgprParseKey(pgprPkt *pkt, pgprItem item);

PGPR_GNUC_INTERNAL
pgprRC pgprParseSig(pgprPkt *pkt, pgprItem item);

PGPR_GNUC_INTERNAL
pgprRC pgprParseSigNoParams(pgprPkt *pkt, pgprItem item);

PGPR_GNUC_INTERNAL
pgprRC pgprParseSigParams(pgprPkt *pkt, pgprItem sigp);

PGPR_GNUC_INTERNAL
pgprRC pgprParseUserID(pgprPkt *pkt, pgprItem item);

PGPR_GNUC_INTERNAL
pgprRC pgprParseKeyFp(pgprPkt *pkt,  pgprItem item);

/* diagnostics */
PGPR_GNUC_INTERNAL
void pgprAddLint(pgprItem item, char **lints, pgprRC error);

/* certificate parsing */
PGPR_GNUC_INTERNAL
pgprRC pgprParseCertificate(const uint8_t * pkts, size_t pktslen, pgprItem item);

PGPR_GNUC_INTERNAL
pgprRC pgprParseCertificateSubkeys(const uint8_t * pkts, size_t pktslen, pgprItem mainkey,
				   pgprItem **subkeys, int *subkeysCount);

/* signature verification */
PGPR_GNUC_INTERNAL
pgprRC pgprVerifySignatureRaw(pgprItem key, pgprItem sig, const uint8_t *hash, size_t hashlen);

/* misc */
PGPR_GNUC_INTERNAL
uint32_t pgprCurrentTime(void);

PGPR_GNUC_INTERNAL
void *pgprMalloc(size_t size);

PGPR_GNUC_INTERNAL
void *pgprRealloc(void * ptr, size_t size);

PGPR_GNUC_INTERNAL
void *pgprCalloc(size_t nmemb, size_t size);

PGPR_GNUC_INTERNAL
char *pgprStrdup(const char *s);

PGPR_GNUC_INTERNAL
void *pgprMemdup(const void *ptr, size_t len);

PGPR_GNUC_INTERNAL
int pgprAsprintf(char **strp, const char *fmt, ...) PGPR_GNUC_PRINTF(2, 3);

