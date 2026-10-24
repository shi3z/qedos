/*
 * qedos — Policy Engine Protection Domain (`policy_pd.elf`).
 *
 * Isolation & Security Laws:
 *   - Links `#![no_std]`, `#![forbid(unsafe_code)]` Rust crates `pg-policy` and `pg-config`
 *     via `libpg_sel4_pds.a` (LAW_001, LAW_004, LAW_007, LAW_011).
 *   - At `init()`, verifies the Ed25519 signature of the read-only `shm_signed_config`
 *     memory region against the pinned `pg_config::PUBLIC_KEY` before activating any
 *     route or backend (LAW_011).
 *   - On `Reject` or `Health`, never writes to `shm_policy_conn` and never notifies
 *     `connector_pd` (LAW_007).
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include "pg_shm.h"

#define CH_POLICY_HTTP 1
#define CH_POLICY_CONN 2
#ifdef QEDOS_SCRIPT
#define CH_POLICY_SCRIPT 3
extern uint8_t pg_rust_is_script_route(uint8_t method_u8, const uint8_t *target_ptr, size_t target_len);
#endif
#ifdef QEDOS_PRESS
#define CH_POLICY_PRESS 4
extern uint8_t pg_rust_is_press_route(const uint8_t *target_ptr, size_t target_len);
#endif

extern int32_t pg_rust_policy_init(
    const uint8_t *blob_ptr,
    size_t max_len,
    uint8_t *n_backends_out,
    uint8_t *backends_ipv4_out,
    uint16_t *backends_port_out
);

extern int32_t pg_rust_policy_decide(
    uint8_t method_u8,
    const uint8_t *target_ptr,
    size_t target_len,
    uint32_t body_len,
    uint8_t *decision_out,
    uint8_t *backend_id_out,
    uint16_t *reject_status_out
);

/* Embedded signed config section (updated at build time from config/sel4/proxy.sconf)
 * AND mirrored into the read-only `shm_signed_config` region (VADDR_SHM_SIGNED_CFG). */
__attribute__((__section__(".signed_config"), aligned(8)))
uint8_t signed_config_section[512] = { 'P', 'G', 'S', '1' };

static const uint8_t        *shm_signed_cfg  = (const uint8_t *)VADDR_SHM_SIGNED_CFG;
static pg_shm_http_policy_t *shm_http_policy = (pg_shm_http_policy_t *)VADDR_SHM_HTTP_POLICY;
static pg_shm_policy_conn_t *shm_policy_conn = (pg_shm_policy_conn_t *)VADDR_SHM_POLICY_CONN;

static uint32_t last_req_seq = 0;
#ifdef QEDOS_SCRIPT
static pg_shm_policy_script_t *shm_policy_script = (pg_shm_policy_script_t *)VADDR_SHM_POLICY_SCRIPT;
#endif
#ifdef QEDOS_PRESS
static pg_shm_policy_press_t *shm_policy_press = (pg_shm_policy_press_t *)VADDR_SHM_POLICY_PRESS;
#endif

void init(void)
{
    uint8_t n_be = 0;
    uint8_t ipv4s[PG_MAX_BACKENDS * 4];
    uint16_t ports[PG_MAX_BACKENDS];

    /* Prefer shm_signed_cfg if populated, else fallback to .signed_config ELF section */
    const uint8_t *cfg_ptr = (shm_signed_cfg[0] == 'P' && shm_signed_cfg[1] == 'G')
        ? shm_signed_cfg
        : signed_config_section;

    int32_t n_routes = pg_rust_policy_init(cfg_ptr, 512, &n_be, ipv4s, ports);
    if (n_routes <= 0) {
        shm_policy_conn->config_verified = 0;
        shm_policy_conn->num_backends = 0;
        microkit_dbg_puts("POLICY_PD: FATAL - Ed25519 signature verification failed (LAW_011)! All requests will be rejected.\n");
        return;
    }

    for (uint8_t i = 0; i < n_be && i < PG_MAX_BACKENDS; i++) {
        shm_policy_conn->backends[i].ipv4[0] = ipv4s[i * 4 + 0];
        shm_policy_conn->backends[i].ipv4[1] = ipv4s[i * 4 + 1];
        shm_policy_conn->backends[i].ipv4[2] = ipv4s[i * 4 + 2];
        shm_policy_conn->backends[i].ipv4[3] = ipv4s[i * 4 + 3];
        shm_policy_conn->backends[i].port    = ports[i];
    }
    shm_policy_conn->num_backends = n_be;
    PG_FENCE();
    shm_policy_conn->config_verified = 1;
    PG_FENCE();

    microkit_dbg_puts("POLICY_PD: Ed25519 signed config verified OK (LAW_011); fixed route & backend tables active\n");
}

void notified(microkit_channel ch)
{
    if (ch != CH_POLICY_HTTP) {
        return;
    }
    uint32_t rseq = shm_http_policy->req_seq;
    if (rseq == last_req_seq) {
        return;
    }
    last_req_seq = rseq;

    uint8_t dec = PG_DECISION_REJECT;
    uint8_t backend_id = 0;
    uint16_t reject_status = 503;

#ifdef QEDOS_SCRIPT
    /* QED Script dispatch: only for GET/POST /script/<module> that passes the shared path hygiene, and
     * only when the signed config was verified (fail closed). Everything else takes the unchanged path. */
    if (shm_policy_conn->config_verified &&
        pg_rust_is_script_route(shm_http_policy->method, shm_http_policy->target, shm_http_policy->target_len)) {
        if (shm_policy_script->req_seq != shm_policy_script->ack_seq) {
            /* script_pd busy (or dead): shed load instead of queueing; proxying is unaffected. */
            shm_http_policy->decision = PG_DECISION_REJECT;
            shm_http_policy->backend_id = 0;
            shm_http_policy->reject_status = 503;
            PG_FENCE();
            shm_http_policy->ack_seq = rseq;
            PG_FENCE();
            microkit_notify(CH_POLICY_HTTP);
            return;
        }
        uint16_t slen = shm_http_policy->target_len;
        if (slen > PG_MAX_TARGET) { slen = PG_MAX_TARGET; }
        uint32_t sblen = shm_http_policy->body_len;
        if (sblen > PG_MAX_REQ_RAW) { sblen = PG_MAX_REQ_RAW; }
        /* Whole-buffer overwrite: bytes of an earlier client's request never remain readable by script_pd
         * beyond the current request's length (request-state isolation even if script_pd is compromised). */
        for (uint32_t i = 0; i < PG_MAX_TARGET; i++) { shm_policy_script->target[i] = (i < slen) ? shm_http_policy->target[i] : 0; }
        for (uint32_t i = 0; i < PG_MAX_REQ_RAW; i++) { shm_policy_script->body[i] = (i < sblen) ? shm_http_policy->body[i] : 0; }
        shm_policy_script->target_len = slen;
        shm_policy_script->body_len = sblen;
        shm_policy_script->method = shm_http_policy->method;
        shm_policy_script->slot = shm_http_policy->slot;
        shm_policy_script->keep_alive = shm_http_policy->keep_alive;
        shm_http_policy->decision = PG_DECISION_SCRIPT;
        shm_http_policy->backend_id = 0;
        shm_http_policy->reject_status = 0;
        PG_FENCE();
        shm_http_policy->ack_seq = rseq;
        PG_FENCE();
        shm_policy_script->req_seq = shm_policy_script->req_seq + 1;
        PG_FENCE();
        microkit_notify(CH_POLICY_SCRIPT);
        microkit_notify(CH_POLICY_HTTP);   /* http_pd records the in-flight script request from this decision */
        return;
    }
#endif

#ifdef QEDOS_PRESS
    /* QEDOS Press dispatch: any method on a /press path goes to qedos_press_pd, which answers 200/404/405
     * itself (GET/HEAD against a known path => 200; known path, other method => 405; unknown => 404).
     * Only when the signed config was verified (fail closed), same gate as the QED Script branch. */
    if (shm_policy_conn->config_verified &&
        pg_rust_is_press_route(shm_http_policy->target, shm_http_policy->target_len)) {
        uint8_t ps = shm_http_policy->slot;
        if (ps >= PG_MAX_CONNS) {
            return; /* never index shm_policy_press->slots[] with a value read from shared memory */
        }
        pg_policy_press_slot_t *req = &shm_policy_press->slots[ps];
        if (req->req_seq != req->ack_seq) {
            /* qedos_press_pd hasn't yet consumed this SAME connection slot's previous request (it
             * runs no untrusted code and processes synchronously, so this is only reachable if this
             * slot is reused for a new request before the prior one was drained -- each OTHER slot
             * has its own independent record and is never shed because of this one being busy). */
            shm_http_policy->decision = PG_DECISION_REJECT;
            shm_http_policy->backend_id = 0;
            shm_http_policy->reject_status = 503;
            PG_FENCE();
            shm_http_policy->ack_seq = rseq;
            PG_FENCE();
            microkit_notify(CH_POLICY_HTTP);
            return;
        }
        uint16_t plen = shm_http_policy->target_len;
        if (plen > PG_MAX_TARGET) { plen = PG_MAX_TARGET; }
        /* Whole-buffer overwrite: bytes of an earlier client's request never remain readable by
         * qedos_press_pd beyond the current request's length. */
        for (uint32_t i = 0; i < PG_MAX_TARGET; i++) { req->target[i] = (i < plen) ? shm_http_policy->target[i] : 0; }
        req->target_len = plen;
        req->method = shm_http_policy->method;
        req->keep_alive = shm_http_policy->keep_alive;
        shm_http_policy->decision = PG_DECISION_PRESS;
        shm_http_policy->backend_id = 0;
        shm_http_policy->reject_status = 0;
        PG_FENCE();
        shm_http_policy->ack_seq = rseq;
        PG_FENCE();
        req->req_seq = req->req_seq + 1;
        PG_FENCE();
        microkit_notify(CH_POLICY_PRESS);
        microkit_notify(CH_POLICY_HTTP);   /* http_pd records the in-flight press request from this decision */
        return;
    }
#endif

    /* Lengths come from shared memory: clamp before they size any slice. */
    uint32_t decide_tlen = shm_http_policy->target_len;
    if (decide_tlen > PG_MAX_TARGET) { decide_tlen = PG_MAX_TARGET; }
    (void)pg_rust_policy_decide(
        shm_http_policy->method,
        shm_http_policy->target,
        decide_tlen,
        shm_http_policy->body_len,
        &dec,
        &backend_id,
        &reject_status
    );
    if (dec == PG_DECISION_FORWARD && shm_policy_conn->fwd_seq != shm_policy_conn->fwd_ack) {
        /* connector_pd is still serving the previous forwarded request: shed instead of overwriting
         * shm_policy_conn (which would corrupt that request and mis-attribute its response). */
        dec = PG_DECISION_REJECT;
        backend_id = 0;
        reject_status = 503;
    }

    shm_http_policy->decision = dec;
    shm_http_policy->backend_id = backend_id;
    shm_http_policy->reject_status = reject_status;
    PG_FENCE();
    shm_http_policy->ack_seq = rseq;
    PG_FENCE();

    if (dec == PG_DECISION_FORWARD) {
        /* Copy approved request to shm_policy_conn and notify connector_pd */
        shm_policy_conn->slot = shm_http_policy->slot;
        shm_policy_conn->backend_id = backend_id;
        shm_policy_conn->method = shm_http_policy->method;
        shm_policy_conn->keep_alive = shm_http_policy->keep_alive;
        uint16_t tlen = shm_http_policy->target_len;
        if (tlen > PG_MAX_TARGET) {
            tlen = PG_MAX_TARGET;
        }
        shm_policy_conn->target_len = tlen;
        for (uint16_t i = 0; i < tlen; i++) {
            shm_policy_conn->target[i] = shm_http_policy->target[i];
        }
        uint32_t blen = shm_http_policy->body_len;
        if (blen > PG_MAX_REQ_RAW) {
            blen = PG_MAX_REQ_RAW;
        }
        shm_policy_conn->body_len = blen;
        for (uint32_t i = 0; i < blen; i++) {
            shm_policy_conn->body[i] = shm_http_policy->body[i];
        }
        PG_FENCE();
        shm_policy_conn->fwd_seq = shm_policy_conn->fwd_seq + 1;
        PG_FENCE();
        microkit_notify(CH_POLICY_CONN);
    } else {
        /* LAW_007: Health and Reject return directly to http_pd; connector_pd is never notified! */
        microkit_notify(CH_POLICY_HTTP);
    }
}
