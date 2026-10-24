/*
 * qedos — QEDOS Press PQ-wrap Protection Domain (`press_pq_pd.elf`), built only with
 * QEDOS_PRESS_PQ=1 (implies QEDOS_PRESS=1 -- see scripts/build-sel4.sh).
 *
 * Answers POST /press/pq-fetch: an application-layer, ML-KEM-768-protected envelope around the
 * same signed static content qedos_press_pd serves in the clear. Exists so that a client whose
 * outer TLS channel is classical (e.g. tls_compat_pd, for a device like iPad/WebKit that offers no
 * PQ group at all) still gets a PQ confidentiality guarantee for this content against a future
 * break of today's classical ECDHE ("harvest now, decrypt later") -- see docs/QEDOS_PRESS_PQ_WRAP.md
 * for the full design, honest limitations, and verification evidence.
 *
 * Isolation & Security Laws:
 *   - ONLY holder of the ML-KEM-768 decapsulation private key (pq_keystore, same discipline as
 *     tls_keystore/LAW_008). The `pq_keystore` memory region (VADDR_PQ_KEYSTORE = 0x41000000) and
 *     `.pq_keystore` section are mapped/embedded ONLY in `press_pq_pd`.
 *   - Reuses the SAME signed-bundle verifier (`pg_press_init`/`pg_press_handle`, crate `pg-press`,
 *     `#![forbid(unsafe_code)]`) and the SAME embedded `.press_bundle` as `qedos_press_pd`, so the
 *     trust/verification logic is not duplicated -- only re-linked into a second PD.
 *   - A garbage or tampered KEM ciphertext is never distinguished from a valid one here: ML-KEM's
 *     decapsulation is defined to never fail (implicit rejection -- see FIPS 203 and
 *     noble-post-quantum's own docs), so this PD always "succeeds" and returns *some* AEAD
 *     ciphertext. A client that didn't actually hold the matching shared secret simply cannot
 *     authenticate (GCM tag) what comes back -- the rejection happens at the client, by AEAD
 *     construction, not by a branch in this PD. A malformed (wrong-length) capsule IS rejected
 *     here, with a plain 400, before any OpenSSL call.
 *   - Deliberately single-in-flight (see pg_shm.h's section 10 comment) -- a second concurrent
 *     request is shed with 503, same accepted pattern as shm_policy_conn/shm_policy_script.
 */
#include "libc_shim.h"
#include <microkit.h>
#include "pg_shm.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define CH_PQ_POLICY 1
#define CH_PQ_HTTP   2

extern void    pg_press_reset(void);
extern int32_t pg_press_init(const uint8_t *blob_ptr, size_t blob_len);
extern size_t  pg_press_handle(
    uint8_t method_u8,
    const uint8_t *target_ptr, size_t target_len,
    uint8_t *out_ptr, size_t out_cap,
    uint16_t *status_out, uint8_t *ctype_out, uint32_t *content_len_out);

/* Same QPR1 signed release bundle as qedos_press_pd.c, re-injected at build time into THIS ELF's
 * own `.press_bundle` section -- not a shared region, same read-only-by-ELF-permissions argument. */
__attribute__((__section__(".press_bundle"), aligned(8)))
const uint8_t press_bundle_section[262144] = { 'Q', 'P', 'R', '1', 0 };

/* Static ML-KEM-768 decapsulation private key, PEM-encoded, injected at build time (see
 * scripts/build-sel4.sh and tools/pq-dump-pubkey.c for how the matching public key is derived and
 * published as a normal signed static asset, examples/press-site/pqkey.bin -- the PRIVATE key
 * never leaves this section). 4096 bytes comfortably covers an ML-KEM-768 private-key PEM (observed
 * ~3.4 KiB) with headroom, well under the pq_keystore MemoryRegion size (0x2000 = 8192) -- keep
 * this in sync with meta_proofgate.py if either changes. */
__attribute__((__section__(".pq_keystore"), aligned(8)))
const char pq_keystore_section[4096] = { 0 };

static pg_shm_policy_pq_t *shm_policy_pq = (pg_shm_policy_pq_t *)VADDR_SHM_POLICY_PQ;
static pg_shm_pq_http_t   *shm_pq_http   = (pg_shm_pq_http_t *)VADDR_SHM_PQ_HTTP;
static const char         *pq_keystore   = (const char *)VADDR_PQ_KEYSTORE;

static EVP_PKEY *g_pq_privkey = NULL;
static uint8_t   press_ready = 0;
static uint32_t  last_req_seq = 0;

static uint8_t req_target[PG_MAX_TARGET];
static uint8_t req_capsule[PG_PQ_CAPSULE_LEN];
static uint8_t plain_body[PG_PQ_BODY_MAX];

/* HKDF-SHA256(ikm=shared_secret[32], salt=NULL, info="qedos-press-pq-v1") -> 32-byte AES-256-GCM
 * key. Fixed, non-attacker-controlled info string; no secret or attacker-controlled data is ever
 * used as HKDF parameters other than the KEM shared secret itself. */
static int derive_aes_key(const unsigned char *shared_secret, size_t shared_len, unsigned char *key_out)
{
    static const unsigned char info[] = "qedos-press-pq-v1";
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (kctx == NULL) { return 0; }
    int ok = 0;
    size_t outlen = 32;
    /* Explicit, empty (zero-length) salt on both ends -- client-side WebCrypto HKDF is given the
     * same explicit empty Uint8Array(0), rather than relying on "no salt set" meaning the same
     * thing (RFC 5869's HashLen-zero-bytes default) in two different HKDF implementations. */
    static const unsigned char empty_salt[1] = { 0 };
    if (EVP_PKEY_derive_init(kctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(kctx, empty_salt, 0) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret, (int)shared_len) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(kctx, info, (int)(sizeof(info) - 1)) == 1 &&
        EVP_PKEY_derive(kctx, key_out, &outlen) == 1 && outlen == 32) {
        ok = 1;
    }
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

/* AES-256-GCM encrypt. Writes a fresh random 12-byte nonce to nonce_out and ciphertext||16-byte-tag
 * to out (out_cap must be >= plain_len + 16). Returns total bytes written to out, or 0 on failure. */
static size_t aes_gcm_encrypt(const unsigned char *key, const unsigned char *plain, size_t plain_len,
                               unsigned char *nonce_out, unsigned char *out, size_t out_cap)
{
    if (out_cap < plain_len + 16u) { return 0; }
    if (RAND_bytes(nonce_out, 12) != 1) { return 0; }
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) { return 0; }
    size_t total = 0;
    int len = 0;
    int ok = (EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1) &&
             (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1) &&
             (EVP_EncryptInit_ex(cctx, NULL, NULL, key, nonce_out) == 1) &&
             (EVP_EncryptUpdate(cctx, out, &len, plain, (int)plain_len) == 1);
    if (ok) {
        total = (size_t)len;
        int flen = 0;
        ok = (EVP_EncryptFinal_ex(cctx, out + total, &flen) == 1);
        total += (size_t)flen;
    }
    if (ok) {
        unsigned char tag[16];
        ok = (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);
        if (ok) {
            for (int i = 0; i < 16; i++) { out[total + (size_t)i] = tag[i]; }
            total += 16u;
        }
    }
    EVP_CIPHER_CTX_free(cctx);
    return ok ? total : 0;
}

void init(void)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    pg_press_reset();
    int32_t n = pg_press_init(press_bundle_section, sizeof(press_bundle_section));
    press_ready = (n >= 0) ? 1u : 0u;
    if (!press_ready) {
        microkit_dbg_puts("PRESS_PQ_PD: FATAL - malformed or unsigned release bundle; nothing will be served\n");
    }

    const char *keystore = (pq_keystore[0] == '-') ? pq_keystore : pq_keystore_section;
    BIO *kbio = BIO_new_mem_buf(keystore, (int)strlen(keystore));
    g_pq_privkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(kbio);
    if (g_pq_privkey == NULL) {
        microkit_dbg_puts("PRESS_PQ_PD: FATAL - failed to load ML-KEM-768 private key\n");
        return;
    }
    uint32_t rseq = shm_policy_pq->req_seq;
    last_req_seq = rseq;
    PG_FENCE();
    shm_policy_pq->ack_seq = rseq;
    PG_FENCE();
    microkit_dbg_puts("PRESS_PQ_PD: ML-KEM-768 private key loaded; app-layer PQ envelope for /press/pq-fetch ready\n");
}

void notified(microkit_channel ch)
{
    if (ch != CH_PQ_POLICY) {
        return;
    }
    uint32_t rseq = shm_policy_pq->req_seq;
    if (rseq == last_req_seq) {
        return;
    }
    last_req_seq = rseq;

    /* Copy the approved request out of shared memory first (no TOCTOU on shared memory). */
    uint8_t slot = shm_policy_pq->slot;
    uint8_t ka = shm_policy_pq->keep_alive;
    uint16_t tlen = shm_policy_pq->target_len;
    if (tlen > PG_MAX_TARGET) { tlen = PG_MAX_TARGET; }
    for (uint16_t i = 0; i < tlen; i++) { req_target[i] = shm_policy_pq->target[i]; }
    for (uint32_t i = 0; i < PG_PQ_CAPSULE_LEN; i++) { req_capsule[i] = shm_policy_pq->capsule[i]; }
    shm_policy_pq->ack_seq = rseq;   /* free this (single, shared) slot for the next request */
    PG_FENCE();

    uint16_t out_status = 503;
    uint8_t nonce[12] = { 0 };
    uint32_t ct_len = 0;

    if (slot < PG_MAX_CONNS && press_ready && g_pq_privkey != NULL) {
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(g_pq_privkey, NULL);
        unsigned char shared[64];
        size_t shared_len = sizeof(shared);
        int decap_ok = (dctx != NULL) &&
                        (EVP_PKEY_decapsulate_init(dctx, NULL) == 1) &&
                        (EVP_PKEY_decapsulate(dctx, shared, &shared_len, req_capsule, PG_PQ_CAPSULE_LEN) == 1);
        if (dctx != NULL) { EVP_PKEY_CTX_free(dctx); }

        if (!decap_ok) {
            /* Malformed capsule (e.g. wrong length) -- rejected here, before any content lookup. A
             * capsule of the right length but wrong content is NOT caught here (ML-KEM implicit
             * rejection -- see file header); it is "accepted" and produces an unusable key instead. */
            out_status = 400;
        } else {
            unsigned char aes_key[32];
            if (!derive_aes_key(shared, shared_len, aes_key)) {
                out_status = 500;
            } else {
                uint16_t status = 503;
                uint8_t ctype = 0;
                uint32_t content_len = 0;
                size_t n = pg_press_handle(/*GET*/ 0, req_target, tlen, plain_body, sizeof(plain_body),
                                            &status, &ctype, &content_len);
                if (n > PG_PQ_BODY_MAX) { n = PG_PQ_BODY_MAX; }
                size_t written = aes_gcm_encrypt(aes_key, plain_body, n, nonce,
                                                  shm_pq_http->ciphertext, sizeof(shm_pq_http->ciphertext));
                if (written == 0) {
                    out_status = 500;
                } else {
                    ct_len = (uint32_t)written;
                    out_status = status;
                }
            }
            OPENSSL_cleanse(shared, sizeof(shared));
        }
    }

    shm_pq_http->slot = slot;
    shm_pq_http->keep_alive = ka;
    shm_pq_http->status = out_status;
    for (int i = 0; i < 12; i++) { shm_pq_http->nonce[i] = nonce[i]; }
    shm_pq_http->ciphertext_len = ct_len;
    PG_FENCE();
    shm_pq_http->resp_seq = shm_pq_http->resp_seq + 1;
    PG_FENCE();
    microkit_notify(CH_PQ_HTTP);
}
