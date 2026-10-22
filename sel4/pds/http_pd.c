/*
 * qedos — HTTP Parser Protection Domain (`http_pd.elf`).
 *
 * Isolation & Security Laws:
 *   - Links `#![no_std]`, `#![forbid(unsafe_code)]` Rust crate `pg-http` via `libpg_sel4_pds.a` (LAW_006).
 *   - Mapped memory regions: ONLY `shm_tls_http` (with tls_pd), `shm_http_policy` (with policy_pd),
 *     and `shm_conn_http` (with connector_pd).
 *   - Has ZERO access to the TLS private key (LAW_008), ZERO access to NIC/lwIP, and ZERO access
 *     to backend addresses (LAW_004, LAW_012).
 *   - Malformed requests are rejected locally and NEVER sent to policy_pd or connector_pd (LAW_007).
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include "pg_shm.h"

#define CH_HTTP_TLS    1
#define CH_HTTP_POLICY 2
#define CH_HTTP_CONN   3
#ifdef QEDOS_SCRIPT
#define CH_HTTP_SCRIPT 4
extern size_t pg_rust_format_script_response(uint16_t status, uint8_t ctype, uint8_t keep_alive,
                                             const uint8_t *body_ptr, size_t body_len,
                                             uint8_t *out_ptr, size_t out_cap);
#endif

extern int32_t pg_rust_parse_http_request(
    const uint8_t *buf_ptr,
    size_t buf_len,
    size_t max_body_cap,
    uint8_t *method_out,
    uint8_t *keep_alive_out,
    uint8_t *target_out,
    size_t target_cap,
    uint16_t *target_len_out,
    uint8_t *host_out,
    size_t host_cap,
    uint16_t *host_len_out,
    uint8_t *body_out,
    uint32_t *body_len_out,
    size_t *consumed_out
);

extern size_t pg_rust_format_local_response(
    uint16_t status,
    uint8_t is_health,
    uint8_t is_head_method,
    uint8_t keep_alive,
    uint8_t *out_ptr,
    size_t out_cap
);

static pg_shm_tls_http_t    *shm_tls_http    = (pg_shm_tls_http_t *)VADDR_SHM_TLS_HTTP;
static pg_shm_http_policy_t *shm_http_policy = (pg_shm_http_policy_t *)VADDR_SHM_HTTP_POLICY;
static pg_shm_conn_http_t   *shm_conn_http   = (pg_shm_conn_http_t *)VADDR_SHM_CONN_HTTP;

/* Per-slot linear accumulation buffer for parsing across TLS record boundaries */
typedef struct {
    uint32_t conn_id;
    uint32_t len;
    uint8_t  awaiting_backend;
    uint8_t  buf[PG_MAX_REQ_RAW];
} http_slot_state_t;

static http_slot_state_t slot_state[PG_MAX_CONNS];
static uint32_t last_policy_ack = 0;
static uint32_t last_conn_resp  = 0;
#ifdef QEDOS_SCRIPT
static pg_shm_script_http_t *shm_script_http = (pg_shm_script_http_t *)VADDR_SHM_SCRIPT_HTTP;
static uint32_t last_script_resp = 0;
/* The ONE script request currently in flight, as known by this PD from policy_pd's decision.
 * A script response is accepted only for exactly this (slot, connection generation) and only once:
 * script_pd is untrusted (LAW_013..022) and must not be able to write into any other client's stream. */
static struct {
    uint8_t  active;
    uint8_t  slot;
    uint32_t conn_id;
} script_inflight;
#endif

static void send_resp_to_tls(uint8_t s, const uint8_t *data, size_t len, uint8_t close_conn)
{
    pg_tls_http_slot_t *ts = &shm_tls_http->slots[s];
    uint32_t head = ts->resp_head;
    uint32_t used = head - ts->resp_tail; /* tail is written by the peer: treat as untrusted */
    if (used > PG_MAX_RESP_RAW || len > PG_MAX_RESP_RAW - used) {
        /* Not enough free space (or a corrupt tail): never overwrite unread data; end the connection. */
        ts->close_after_resp = 1;
        PG_FENCE();
        microkit_notify(CH_HTTP_TLS);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        ts->resp_buf[(head + i) % PG_MAX_RESP_RAW] = data[i];
    }
    PG_FENCE();
    ts->resp_head = head + (uint32_t)len;
    if (close_conn) {
        ts->close_after_resp = 1;
    }
    PG_FENCE();
    microkit_notify(CH_HTTP_TLS);
}

static void check_policy_completion(void);

static void process_slot_requests(uint8_t s)
{
    pg_tls_http_slot_t *ts = &shm_tls_http->slots[s];
    http_slot_state_t *st = &slot_state[s];

    uint32_t cid = ts->conn_id;
    if (cid == 0 || !ts->session_active) {
        st->conn_id = 0;
        st->len = 0;
        st->awaiting_backend = 0;
#ifdef QEDOS_SCRIPT
        if (script_inflight.active && script_inflight.slot == s) { script_inflight.active = 0; }
#endif
        return;
    }
    if (st->conn_id != cid) {
        st->conn_id = cid;
        st->len = 0;
        st->awaiting_backend = 0;
    }

    /* Drain newly decrypted plaintext bytes from shm_tls_http into st->buf */
    uint32_t rhead = ts->req_head;
    uint32_t rtail = ts->req_tail;
    while (rtail != rhead) {
        if (st->len >= PG_MAX_REQ_RAW) {
            /* Request head+body exceeds 16 KiB buffer -> 431/413 Reject */
            uint8_t resp[256];
            size_t rlen = pg_rust_format_local_response(431, 0, 0, 0, resp, sizeof(resp));
            ts->req_tail = rhead;
            st->len = 0;
            send_resp_to_tls(s, resp, rlen, 1);
            return;
        }
        st->buf[st->len++] = ts->req_buf[rtail % PG_RING_SIZE];
        rtail++;
    }
    PG_FENCE();
    ts->req_tail = rtail;

    if (st->len == 0 || st->awaiting_backend) {
        return;
    }

    /* A decision that policy_pd already acknowledged must be consumed BEFORE the shared request fields are
     * reused for a new evaluation; otherwise the decision (e.g. "script request in flight") is lost. */
    check_policy_completion();
    /* Do not start a new policy evaluation if policy_pd or connector_pd is busy */
    if (shm_http_policy->req_seq != shm_http_policy->ack_seq) {
        return;
    }

    uint8_t method = 0;
    uint8_t keep_alive = 0;
    uint16_t target_len = 0;
    uint16_t host_len = 0;
    uint32_t body_len = 0;
    size_t consumed = 0;

    int32_t rc = pg_rust_parse_http_request(
        st->buf,
        st->len,
        PG_MAX_REQ_RAW,
        &method,
        &keep_alive,
        shm_http_policy->target,
        PG_MAX_TARGET,
        &target_len,
        shm_http_policy->host,
        PG_MAX_HOST,
        &host_len,
        shm_http_policy->body,
        &body_len,
        &consumed
    );

    if (rc == 0) {
        /* Need more bytes */
        return;
    }

    if (rc < 0) {
        /* LAW_006 / LAW_007: Parse error -> reject immediately at HTTP PD, never forward! */
        uint16_t status = (uint16_t)(-rc);
        uint8_t resp[256];
        size_t rlen = pg_rust_format_local_response(status, 0, 0, 0, resp, sizeof(resp));
        st->len = 0;
        microkit_dbg_puts("HTTP_PD: rejected malformed request (LAW_006/LAW_007)\n");
        send_resp_to_tls(s, resp, rlen, 1);
        return;
    }

    /* Shift any pipelined bytes remaining in st->buf */
    if (consumed < st->len) {
        size_t rem = st->len - consumed;
        for (size_t i = 0; i < rem; i++) {
            st->buf[i] = st->buf[consumed + i];
        }
        st->len = (uint32_t)rem;
    } else {
        st->len = 0;
    }

    /* Populate shm_http_policy and notify policy_pd */
    shm_http_policy->slot = s;
    shm_http_policy->method = method;
    shm_http_policy->keep_alive = keep_alive;
    shm_http_policy->target_len = target_len;
    shm_http_policy->host_len = host_len;
    shm_http_policy->body_len = body_len;
    st->awaiting_backend = 1;
    PG_FENCE();
    shm_http_policy->req_seq = shm_http_policy->req_seq + 1;
    PG_FENCE();
    microkit_notify(CH_HTTP_POLICY);
}

static void check_policy_completion(void)
{
    uint32_t ack = shm_http_policy->ack_seq;
    if (ack == last_policy_ack || ack != shm_http_policy->req_seq) {
        return;
    }
    last_policy_ack = ack;

    uint8_t s = shm_http_policy->slot;
    uint8_t dec = shm_http_policy->decision;
    uint8_t is_head = (shm_http_policy->method == 1) ? 1 : 0;
    uint8_t ka = shm_http_policy->keep_alive;
    if (s >= PG_MAX_CONNS) {
        return; /* never index slot_state[] with a value read from shared memory */
    }

    if (dec == PG_DECISION_HEALTH) {
        uint8_t resp[256];
        size_t rlen = pg_rust_format_local_response(200, 1, is_head, ka, resp, sizeof(resp));
        slot_state[s].awaiting_backend = 0;
        send_resp_to_tls(s, resp, rlen, ka ? 0 : 1);
        process_slot_requests(s);
    } else if (dec == PG_DECISION_REJECT) {
        uint16_t status = shm_http_policy->reject_status;
        uint8_t resp[256];
        uint8_t close_conn = (status == 400 || status == 413 || status == 414 || status == 431 || !ka) ? 1 : 0;
        size_t rlen = pg_rust_format_local_response(status, 0, is_head, close_conn ? 0 : 1, resp, sizeof(resp));
        slot_state[s].awaiting_backend = 0;
        send_resp_to_tls(s, resp, rlen, close_conn);
        if (!close_conn) {
            process_slot_requests(s);
        }
    }
#ifdef QEDOS_SCRIPT
    else if (dec == PG_DECISION_SCRIPT) {
        script_inflight.active = 1;
        script_inflight.slot = s;
        script_inflight.conn_id = slot_state[s].conn_id;
    }
#endif
    /* If PG_DECISION_FORWARD, policy_pd notified connector_pd; wait for CH_HTTP_CONN */
}

static void check_connector_response(void)
{
    uint32_t rseq = shm_conn_http->resp_seq;
    if (rseq == last_conn_resp) {
        return;
    }
    last_conn_resp = rseq;

    uint8_t s = shm_conn_http->slot;
    uint8_t ka = shm_conn_http->keep_alive;
    uint32_t len = shm_conn_http->raw_resp_len;
    if (s < PG_MAX_CONNS && len > 0 && len <= PG_MAX_RESP_RAW) {
        slot_state[s].awaiting_backend = 0;
        send_resp_to_tls(s, shm_conn_http->raw_resp, len, ka ? 0 : 1);
    }
    PG_FENCE();
    shm_conn_http->resp_ack = rseq;
    PG_FENCE();
    if (s < PG_MAX_CONNS && ka) {
        process_slot_requests(s);
    }
}

#ifdef QEDOS_SCRIPT
static uint8_t script_http_buf[PG_SCRIPT_BODY_MAX + 1024u];
static uint8_t script_body_copy[PG_SCRIPT_BODY_MAX];

static void check_script_response(void)
{
    uint32_t rseq = shm_script_http->resp_seq;
    if (rseq == last_script_resp) {
        return;
    }
    last_script_resp = rseq;
    /* The decision notification from policy_pd may not have been processed yet on another core. */
    check_policy_completion();

    /* Snapshot every script-controlled scalar exactly once (no double fetch). */
    uint8_t  s      = shm_script_http->slot;
    uint8_t  ka     = shm_script_http->keep_alive;
    uint8_t  ctype  = shm_script_http->ctype;
    uint32_t len    = shm_script_http->body_len;
    uint16_t status = shm_script_http->status;
    PG_FENCE();
    shm_script_http->resp_ack = rseq;
    PG_FENCE();

    /* Accept only the response to the request that is actually in flight, once. */
    if (!script_inflight.active || s != script_inflight.slot || s >= PG_MAX_CONNS ||
        slot_state[s].conn_id != script_inflight.conn_id || slot_state[s].conn_id == 0 ||
        len > PG_SCRIPT_BODY_MAX) {
        return;
    }
    script_inflight.active = 0;

    /* Copy the body into private memory before parsing/framing it: the writer may still be running. */
    for (uint32_t i = 0; i < len; i++) {
        script_body_copy[i] = shm_script_http->body[i];
    }
    size_t rlen = pg_rust_format_script_response(status, ctype, ka, script_body_copy, len,
                                                 script_http_buf, sizeof(script_http_buf));
    slot_state[s].awaiting_backend = 0;
    if (rlen == 0) {
        uint8_t resp[256];
        rlen = pg_rust_format_local_response(502, 0, 0, 0, resp, sizeof(resp));
        send_resp_to_tls(s, resp, rlen, 1);
    } else {
        send_resp_to_tls(s, script_http_buf, rlen, ka ? 0 : 1);
    }
    if (ka) {
        process_slot_requests(s);
    }
}
#endif

void init(void)
{
    microkit_dbg_puts("HTTP_PD: initialized (no_std Rust pg-http, forbid(unsafe_code))\n");
}

void notified(microkit_channel ch)
{
    if (ch == CH_HTTP_POLICY) {
        check_policy_completion();
    } else if (ch == CH_HTTP_CONN) {
        check_connector_response();
#ifdef QEDOS_SCRIPT
    } else if (ch == CH_HTTP_SCRIPT) {
        check_script_response();
#endif
    } else if (ch == CH_HTTP_TLS) {
        for (uint8_t s = 0; s < PG_MAX_CONNS; s++) {
            process_slot_requests(s);
        }
    }
}
