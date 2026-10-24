/*
 * qedos — TLS 1.3 + X25519MLKEM768 Protection Domain (`tls_pd.elf`).
 *
 * Isolation & Security Laws:
 *   - ONLY holder of the TLS server private key (LAW_008). The `tls_keystore` memory
 *     region (VADDR_TLS_KEYSTORE = 0x37000000) and `.tls_keystore` section are mapped
 *     ONLY in `tls_pd`. Neither `http_pd`, `policy_pd`, `connector_pd`, nor `tcp_pd`
 *     can read the private key.
 *   - Enforces TLS 1.3 only (LAW_002), key exchange group `X25519MLKEM768` only (LAW_003),
 *     cipher `TLS_AES_256_GCM_SHA384` only, 0-RTT disabled, compression disabled.
 *   - Re-verifies negotiated protocol version, group (`SSL_get0_group_name`), and cipher
 *     after every handshake before setting `session_active = 1` for `http_pd`.
 */
#include "libc_shim.h"
#include <microkit.h>
#include "pg_shm.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define CH_TLS_TCP  1
#define CH_TLS_HTTP 2

/* cert_pem is sized to hold a leaf cert plus one intermediate CA (a real public CA chain,
 * e.g. Let's Encrypt leaf+intermediate, is a few KB -- the committed dev self-signed cert is
 * much smaller and still fits). key_pem stays small (EC/RSA private keys are far under 2KB).
 * cert_pem + key_pem == 8192 == the tls_keystore MemoryRegion size (meta_proofgate.py) exactly;
 * do not grow either field without growing that region to match. */
typedef struct {
    char cert_pem[6144];
    char key_pem[2048];
} pg_tls_keystore_t;

/* Default keystore populated with config/dev/{cert,key}.pem and updatable via objcopy */
__attribute__((__section__(".tls_keystore"), aligned(8)))
pg_tls_keystore_t tls_keystore_section = {
    .cert_pem =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBaDCCAQ2gAwIBAgIUQ4cU8aRNZVfFUmnYI+5bP823irYwCgYIKoZIzj0EAwIw\n"
        "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxNzAzMzMwNVoXDTI2MTExNjAz\n"
        "MzMwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
        "AQcDQgAEm2CAhAsNohe9y7dCWWphGvAYkpvabFu9khAHF8CzmHgSn55au16ehv3k\n"
        "2wQUve9BJeu1VXm4gi7RC2fr4LX+3KM9MDswGgYDVR0RBBMwEYIJbG9jYWxob3N0\n"
        "hwR/AAABMB0GA1UdDgQWBBTV8r8xfrnE7xUXHc1Vbirtjc69RzAKBggqhkjOPQQD\n"
        "AgNJADBGAiEAhkgTm+gjAZhHBiJ8OYGCd/oMRfl0VwvUxfzIGoM7JqwCIQC6pMgn\n"
        "8CYfKkzABe+v1YzRqPltqRR7G4AnVXmGvwYZhw==\n"
        "-----END CERTIFICATE-----\n",
    .key_pem =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0nTrqf1sOhUmD3b3\n"
        "NmE45zt1M7HIt8l9xZL8fkVSDVahRANCAASbYICECw2iF73Lt0JZamEa8BiSm9ps\n"
        "W72SEAcXwLOYeBKfnlq7Xp6G/eTbBBS970El67VVebiCLtELZ+vgtf7c\n"
        "-----END PRIVATE KEY-----\n"
};

static const pg_tls_keystore_t *shm_keystore = (const pg_tls_keystore_t *)VADDR_TLS_KEYSTORE;
static pg_shm_tcp_tls_t        *shm_tcp_tls  = (pg_shm_tcp_tls_t *)VADDR_SHM_TCP_TLS;
static pg_shm_tls_http_t       *shm_tls_http = (pg_shm_tls_http_t *)VADDR_SHM_TLS_HTTP;

typedef struct {
    uint32_t conn_id;
    SSL     *ssl;
    BIO     *rbio;
    BIO     *wbio;
    uint8_t  hs_done;
    uint8_t  closing;
} tls_conn_t;

static SSL_CTX   *g_ssl_ctx = NULL;
static tls_conn_t g_conns[PG_MAX_CONNS];

static int str_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    unsigned int pos = 0;
    while (pos < inlen) {
        unsigned int plen = in[pos];
        if (pos + 1 + plen > inlen) {
            break;
        }
        if (plen == 8 && memcmp(&in[pos + 1], "http/1.1", 8) == 0) {
            *out = &in[pos + 1];
            *outlen = 8;
            return SSL_TLSEXT_ERR_OK;
        }
        pos += 1 + plen;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static void free_slot_ssl(uint8_t s)
{
    tls_conn_t *tc = &g_conns[s];
    if (tc->ssl != NULL) {
        SSL_free(tc->ssl); /* Also frees attached rbio & wbio */
        tc->ssl = NULL;
        tc->rbio = NULL;
        tc->wbio = NULL;
    }
    tc->hs_done = 0;
    tc->closing = 0;
}

static int flush_wbio_to_tcp(uint8_t s)
{
    tls_conn_t *tc = &g_conns[s];
    pg_tcp_tls_slot_t *ts = &shm_tcp_tls->slots[s];
    if (tc->wbio == NULL) {
        return 0;
    }
    int flushed = 0;
    uint8_t tmp[2048];
    for (;;) {
        uint32_t head = ts->tx_head;
        uint32_t tail = ts->tx_tail;
        uint32_t used = head - tail;
        if (used >= PG_RING_SIZE) {
            break;
        }
        uint32_t room = PG_RING_SIZE - used;
        int to_read = (room < sizeof(tmp)) ? (int)room : (int)sizeof(tmp);
        int n = BIO_read(tc->wbio, tmp, to_read);
        if (n <= 0) {
            break;
        }
        for (int i = 0; i < n; i++) {
            ts->tx_buf[(head + (uint32_t)i) % PG_RING_SIZE] = tmp[i];
        }
        PG_FENCE();
        ts->tx_head = head + (uint32_t)n;
        flushed += n;
    }
    return flushed;
}

static void pump_slot(uint8_t s, int *notify_tcp, int *notify_http)
{
    pg_tcp_tls_slot_t  *ts = &shm_tcp_tls->slots[s];
    pg_tls_http_slot_t *hs = &shm_tls_http->slots[s];
    tls_conn_t         *tc = &g_conns[s];

    uint32_t cid = ts->conn_id;
    uint8_t tstate = ts->tcp_state;

    if (cid == 0 || tstate == PG_TCP_STATE_FREE || tstate == PG_TCP_STATE_RESET) {
        if (tc->conn_id != 0) {
            free_slot_ssl(s);
            tc->conn_id = 0;
            hs->session_active = 0;
            hs->conn_id = 0;
        }
        return;
    }

    if (tc->conn_id != cid) {
        free_slot_ssl(s);
        tc->conn_id = cid;
        hs->session_active = 0;
        hs->conn_id = 0;
        hs->close_after_resp = 0;
        hs->client_eof = 0;
        hs->req_head = 0;
        hs->req_tail = 0;
        hs->resp_head = 0;
        hs->resp_tail = 0;
    }

    if (tc->closing) {
        if (flush_wbio_to_tcp(s) > 0) {
            *notify_tcp = 1;
        }
        return;
    }

    /* Check if client has sent any ciphertext bytes */
    uint32_t rx_head = ts->rx_head;
    uint32_t rx_tail = ts->rx_tail;

    /* Lazy SSL allocation only after first byte arrives (matches Stage A C10K design) */
    if (tc->ssl == NULL) {
        if (rx_head == rx_tail) {
            if (tstate == PG_TCP_STATE_CLIENT_EOF) {
                ts->tls_close_req = 1;
                tc->closing = 1;
                *notify_tcp = 1;
            }
            return;
        }
        tc->ssl = SSL_new(g_ssl_ctx);
        tc->rbio = BIO_new(BIO_s_mem());
        tc->wbio = BIO_new(BIO_s_mem());
        if (tc->ssl == NULL || tc->rbio == NULL || tc->wbio == NULL) {
            free_slot_ssl(s);
            ts->tls_close_req = 1;
            tc->closing = 1;
            *notify_tcp = 1;
            return;
        }
        SSL_set0_rbio(tc->ssl, tc->rbio);
        SSL_set0_wbio(tc->ssl, tc->wbio);
        SSL_set_accept_state(tc->ssl);
    }

    /* Feed incoming ciphertext from shm_tcp_tls into rbio */
    while (rx_tail != rx_head) {
        uint8_t chunk[1024];
        uint32_t avail = rx_head - rx_tail;
        uint32_t n = (avail < sizeof(chunk)) ? avail : (uint32_t)sizeof(chunk);
        for (uint32_t i = 0; i < n; i++) {
            chunk[i] = ts->rx_buf[(rx_tail + i) % PG_RING_SIZE];
        }
        int w = BIO_write(tc->rbio, chunk, (int)n);
        if (w <= 0) {
            break;
        }
        rx_tail += (uint32_t)w;
    }
    PG_FENCE();
    ts->rx_tail = rx_tail;

    /* Advance handshake if not yet completed */
    if (!tc->hs_done) {
        int rc = SSL_accept(tc->ssl);
        if (flush_wbio_to_tcp(s) > 0) {
            *notify_tcp = 1;
        }
        if (rc == 1) {
            /* Post-handshake defence-in-depth verification (LAW_002, LAW_003) */
            int ver = SSL_version(tc->ssl);
            const char *grp = SSL_get0_group_name(tc->ssl);
            const char *cph = SSL_get_cipher_name(tc->ssl);
            if (ver != TLS1_3_VERSION ||
                !str_eq(grp, "X25519MLKEM768") ||
                !str_eq(cph, "TLS_AES_256_GCM_SHA384")) {
                microkit_dbg_puts("TLS_PD: POLICY VIOLATION post-handshake check failed! Dropping.\n");
                free_slot_ssl(s);
                ts->tls_close_req = 1;
                tc->closing = 1;
                *notify_tcp = 1;
                return;
            }
            tc->hs_done = 1;
            hs->conn_id = cid;
            PG_FENCE();
            hs->session_active = 1;
            PG_FENCE();
            microkit_dbg_puts("TLS_PD: handshake OK version=TLSv1.3 group=X25519MLKEM768 cipher=TLS_AES_256_GCM_SHA384\n");
        } else {
            int err = SSL_get_error(tc->ssl, rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                microkit_dbg_puts("TLS_PD: handshake rejected (LAW_002/LAW_003)\n");
                (void)flush_wbio_to_tcp(s);
                free_slot_ssl(s);
                ts->tls_close_req = 1;
                tc->closing = 1;
                *notify_tcp = 1;
                return;
            }
            return;
        }
    }

    /* Read decrypted plaintext from SSL and forward to http_pd */
    for (;;) {
        uint32_t qhead = hs->req_head;
        uint32_t qtail = hs->req_tail;
        uint32_t used = qhead - qtail;
        if (used >= PG_RING_SIZE) {
            break;
        }
        uint32_t room = PG_RING_SIZE - used;
        uint8_t plain[2048];
        int max_r = (room < sizeof(plain)) ? (int)room : (int)sizeof(plain);
        int n = SSL_read(tc->ssl, plain, max_r);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                hs->req_buf[(qhead + (uint32_t)i) % PG_RING_SIZE] = plain[i];
            }
            PG_FENCE();
            hs->req_head = qhead + (uint32_t)n;
            *notify_http = 1;
        } else {
            int err = SSL_get_error(tc->ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN) {
                hs->client_eof = 1;
            } else if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                free_slot_ssl(s);
                ts->tls_close_req = 1;
                tc->closing = 1;
                *notify_tcp = 1;
                return;
            }
            break;
        }
    }

    /* Encrypt plaintext responses from http_pd and push to tcp_pd */
    uint32_t phead = hs->resp_head;
    uint32_t ptail = hs->resp_tail;
    while (ptail != phead) {
        uint8_t plain[2048];
        uint32_t avail = phead - ptail;
        uint32_t n = (avail < sizeof(plain)) ? avail : (uint32_t)sizeof(plain);
        for (uint32_t i = 0; i < n; i++) {
            plain[i] = hs->resp_buf[(ptail + i) % PG_MAX_RESP_RAW];
        }
        int w = SSL_write(tc->ssl, plain, (int)n);
        if (w <= 0) {
            break;
        }
        ptail += (uint32_t)w;
    }
    PG_FENCE();
    hs->resp_tail = ptail;

    if (flush_wbio_to_tcp(s) > 0) {
        *notify_tcp = 1;
    }

    /* Close session cleanly if http_pd requested close after response */
    if (hs->close_after_resp && hs->resp_tail == hs->resp_head) {
        (void)SSL_shutdown(tc->ssl);
        (void)flush_wbio_to_tcp(s);
        free_slot_ssl(s);
        hs->session_active = 0;
        PG_FENCE();
        ts->tls_close_req = 1;
        tc->closing = 1;
        *notify_tcp = 1;
    }
}

void init(void)
{
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        microkit_dbg_puts("TLS_PD: FATAL OPENSSL_init_ssl failed\n");
        return;
    }
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (g_ssl_ctx == NULL) {
        microkit_dbg_puts("TLS_PD: FATAL SSL_CTX_new failed\n");
        return;
    }

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(g_ssl_ctx, "TLS_AES_256_GCM_SHA384");
    SSL_CTX_set1_groups_list(g_ssl_ctx, "X25519MLKEM768");
    SSL_CTX_set_options(
        g_ssl_ctx,
        SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE
    );
    SSL_CTX_set_max_early_data(g_ssl_ctx, 0);
    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_alpn_select_cb(g_ssl_ctx, alpn_select_cb, NULL);

    const pg_tls_keystore_t *ks = (shm_keystore->cert_pem[0] == '-')
        ? shm_keystore
        : &tls_keystore_section;

    BIO *cbio = BIO_new_mem_buf(ks->cert_pem, (int)strlen(ks->cert_pem));
    X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    /* cert_pem may hold a leaf cert followed by one or more intermediate CA certs (a real
     * public-CA chain, e.g. Let's Encrypt). A client validating against its own trusted root
     * store does not trust intermediates directly, so every cert after the leaf must be sent
     * too. The committed dev self-signed cert has no intermediates, so this loop reads nothing
     * further for it -- a no-op for that case, not a behavior change for existing builds. */
    X509 *chain_cert;
    while ((chain_cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL)) != NULL) {
        if (SSL_CTX_add_extra_chain_cert(g_ssl_ctx, chain_cert) != 1) {
            X509_free(chain_cert); /* ownership stays with us only on failure to add */
            break;
        }
        /* on success, SSL_CTX_add_extra_chain_cert takes ownership -- do not free */
    }
    BIO_free(cbio);

    BIO *kbio = BIO_new_mem_buf(ks->key_pem, (int)strlen(ks->key_pem));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(kbio);

    if (cert == NULL || pkey == NULL ||
        SSL_CTX_use_certificate(g_ssl_ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(g_ssl_ctx, pkey) != 1 ||
        SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
        microkit_dbg_puts("TLS_PD: FATAL failed to load isolated X.509 cert/key\n");
        return;
    }
    X509_free(cert);
    EVP_PKEY_free(pkey);

    microkit_dbg_puts("TLS_PD: OpenSSL 3.6.1 initialized (TLS1.3 + X25519MLKEM768 + AES-256-GCM only, key isolated LAW_008)\n");
}

void notified(microkit_channel ch)
{
    (void)ch;
    libc_shim_set_clock_ns(shm_tcp_tls->now_ns);
    int notify_tcp = 0;
    int notify_http = 0;
    for (uint8_t s = 0; s < PG_MAX_CONNS; s++) {
        pump_slot(s, &notify_tcp, &notify_http);
    }
    if (notify_http) {
        microkit_notify(CH_TLS_HTTP);
    }
    if (notify_tcp) {
        microkit_notify(CH_TLS_TCP);
    }
}
