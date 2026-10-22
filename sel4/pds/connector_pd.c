/*
 * qedos — Fixed-Backend Connector Protection Domain (`connector_pd.elf`).
 *
 * Isolation & Security Laws:
 *   - Only receives requests that `policy_pd` has explicitly approved with `Decision::Forward` (LAW_007).
 *   - Uses `backend_id` ONLY as an index into the Ed25519-verified fixed backend table
 *     (`shm_policy_conn->backends[backend_id]`) — client bytes never construct an IP or port (LAW_004).
 *   - Frames a canonical HTTP/1.1 request with fixed `Host` and `Connection: close` (stripping all
 *     spoofed headers) and validates the backend response with `pg_http::parse_response` (LAW_006).
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include "pg_shm.h"

#define CH_CONN_POLICY 1
#define CH_CONN_HTTP   2
#define CH_CONN_TCP    3

extern size_t pg_rust_format_backend_request(
    uint8_t method_u8,
    const uint8_t *target_ptr,
    size_t target_len,
    const uint8_t *backend_ipv4_ptr,
    uint16_t backend_port,
    const uint8_t *body_ptr,
    size_t body_len,
    uint8_t *out_ptr,
    size_t out_cap
);

extern size_t pg_rust_validate_and_frame_response(
    const uint8_t *raw_ptr,
    size_t raw_len,
    uint8_t is_head_req,
    uint8_t keep_alive,
    uint16_t *status_out,
    uint8_t *out_ptr,
    size_t out_cap
);

extern size_t pg_rust_format_local_response(
    uint16_t status,
    uint8_t is_health,
    uint8_t is_head_method,
    uint8_t keep_alive,
    uint8_t *out_ptr,
    size_t out_cap
);

static pg_shm_policy_conn_t *shm_policy_conn = (pg_shm_policy_conn_t *)VADDR_SHM_POLICY_CONN;
static pg_shm_conn_http_t   *shm_conn_http   = (pg_shm_conn_http_t *)VADDR_SHM_CONN_HTTP;
static pg_shm_tcp_conn_t    *shm_tcp_conn    = (pg_shm_tcp_conn_t *)VADDR_SHM_TCP_CONN;

static uint32_t last_fwd_seq  = 0;
static uint32_t last_tcp_resp = 0;

static uint8_t active_slot = 0;
static uint8_t active_method = 0;
static uint8_t active_ka = 0;

static void handle_forward_from_policy(void)
{
    uint32_t fseq = shm_policy_conn->fwd_seq;
    if (fseq == last_fwd_seq) {
        return;
    }
    last_fwd_seq = fseq;

    active_slot   = shm_policy_conn->slot;
    active_method = shm_policy_conn->method;
    active_ka     = shm_policy_conn->keep_alive;
    uint8_t bid   = shm_policy_conn->backend_id;

    uint8_t nbe = shm_policy_conn->num_backends;
    if (!shm_policy_conn->config_verified || nbe > PG_MAX_BACKENDS || bid >= nbe) {
        /* Fail closed if config not verified or backend index out of bounds */
        shm_conn_http->slot = active_slot;
        shm_conn_http->keep_alive = 0;
        shm_conn_http->status = 502;
        shm_conn_http->raw_resp_len = (uint32_t)pg_rust_format_local_response(
            502, 0, (active_method == 1) ? 1 : 0, 0, shm_conn_http->raw_resp, PG_MAX_RESP_RAW
        );
        PG_FENCE();
        shm_policy_conn->fwd_ack = last_fwd_seq;   /* release the policy_pd busy gate on every path */
        shm_conn_http->resp_seq = shm_conn_http->resp_seq + 1;
        PG_FENCE();
        microkit_notify(CH_CONN_HTTP);
        return;
    }

    pg_backend_entry_t be = shm_policy_conn->backends[bid];
    uint32_t tlen = shm_policy_conn->target_len;
    uint32_t blen = shm_policy_conn->body_len;
    if (tlen > PG_MAX_TARGET) { tlen = PG_MAX_TARGET; }
    if (blen > PG_MAX_REQ_RAW) { blen = PG_MAX_REQ_RAW; }
    size_t tx_len = pg_rust_format_backend_request(
        active_method,
        shm_policy_conn->target,
        tlen,
        be.ipv4,
        be.port,
        shm_policy_conn->body,
        blen,
        shm_tcp_conn->tx_buf,
        sizeof(shm_tcp_conn->tx_buf)
    );

    if (tx_len == 0) {
        shm_conn_http->slot = active_slot;
        shm_conn_http->keep_alive = 0;
        shm_conn_http->status = 500;
        shm_conn_http->raw_resp_len = (uint32_t)pg_rust_format_local_response(
            500, 0, (active_method == 1) ? 1 : 0, 0, shm_conn_http->raw_resp, PG_MAX_RESP_RAW
        );
        PG_FENCE();
        shm_policy_conn->fwd_ack = last_fwd_seq;
        shm_conn_http->resp_seq = shm_conn_http->resp_seq + 1;
        PG_FENCE();
        microkit_notify(CH_CONN_HTTP);
        return;
    }

    shm_tcp_conn->dst_ipv4[0] = be.ipv4[0];
    shm_tcp_conn->dst_ipv4[1] = be.ipv4[1];
    shm_tcp_conn->dst_ipv4[2] = be.ipv4[2];
    shm_tcp_conn->dst_ipv4[3] = be.ipv4[3];
    shm_tcp_conn->dst_port    = be.port;
    shm_tcp_conn->tx_len      = (uint32_t)tx_len;
    shm_tcp_conn->rx_len      = 0;
    shm_tcp_conn->status      = PG_CONN_STATUS_IN_PROGRESS;
    PG_FENCE();
    shm_tcp_conn->req_seq = shm_tcp_conn->req_seq + 1;
    PG_FENCE();
    microkit_notify(CH_CONN_TCP);
}

static void handle_response_from_tcp(void)
{
    uint32_t rseq = shm_tcp_conn->resp_seq;
    if (rseq == last_tcp_resp || rseq != shm_tcp_conn->req_seq) {
        return;
    }
    last_tcp_resp = rseq;

    uint8_t is_head = (active_method == 1) ? 1 : 0;
    uint16_t status_code = 502;
    size_t out_len = 0;

    uint32_t rxl = shm_tcp_conn->rx_len;           /* single fetch of a peer-controlled length */
    if (shm_tcp_conn->status == PG_CONN_STATUS_OK && rxl > 0 && rxl <= PG_MAX_RESP_RAW) {
        out_len = pg_rust_validate_and_frame_response(
            shm_tcp_conn->rx_buf,
            rxl,
            is_head,
            active_ka,
            &status_code,
            shm_conn_http->raw_resp,
            PG_MAX_RESP_RAW
        );
    } else {
        status_code = (shm_tcp_conn->status == PG_CONN_STATUS_ERR_TIMEOUT) ? 504 : 502;
        active_ka = 0;
        out_len = pg_rust_format_local_response(
            status_code, 0, is_head, 0, shm_conn_http->raw_resp, PG_MAX_RESP_RAW
        );
    }

    shm_conn_http->slot = active_slot;
    shm_conn_http->keep_alive = (status_code == 502 || status_code == 504) ? 0 : active_ka;
    shm_conn_http->status = status_code;
    shm_conn_http->raw_resp_len = (uint32_t)out_len;
    PG_FENCE();
    shm_policy_conn->fwd_ack = last_fwd_seq;
    shm_conn_http->resp_seq = shm_conn_http->resp_seq + 1;
    PG_FENCE();
    microkit_notify(CH_CONN_HTTP);
}

void init(void)
{
    microkit_dbg_puts("CONNECTOR_PD: initialized (fixed backend table + pg-http response validator)\n");
}

void notified(microkit_channel ch)
{
    if (ch == CH_CONN_POLICY) {
        handle_forward_from_policy();
    } else if (ch == CH_CONN_TCP) {
        handle_response_from_tcp();
    }
}
