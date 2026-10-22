/*
 * qedos — Shared-Memory Ring & Mailbox Definitions across seL4 PDs.
 *
 * Capability Isolation Invariants (LAW_008, LAW_012):
 *   - VADDR_SHM_TCP_TLS     (0x30000000): mapped ONLY in tcp_pd and tls_pd
 *   - VADDR_SHM_TLS_HTTP    (0x31000000): mapped ONLY in tls_pd and http_pd
 *   - VADDR_SHM_HTTP_POLICY (0x32000000): mapped ONLY in http_pd and policy_pd
 *   - VADDR_SHM_SIGNED_CFG  (0x33000000): mapped ONLY in policy_pd (perms="r")
 *   - VADDR_SHM_POLICY_CONN (0x34000000): mapped ONLY in policy_pd and connector_pd
 *   - VADDR_SHM_CONN_HTTP   (0x35000000): mapped ONLY in connector_pd and http_pd
 *   - VADDR_SHM_TCP_CONN    (0x36000000): mapped ONLY in connector_pd and tcp_pd
 *   - VADDR_TLS_KEYSTORE    (0x37000000): mapped ONLY in tls_pd (perms="r", LAW_008)
 *   QED Script (only present in images built with QEDOS_SCRIPT=1):
 *   - VADDR_SHM_POLICY_SCRIPT (0x38000000): mapped ONLY in policy_pd and script_pd
 *   - VADDR_SHM_SCRIPT_HTTP   (0x39000000): mapped ONLY in script_pd and http_pd
 */
#ifndef PROOFGATE_SEL4_PG_SHM_H
#define PROOFGATE_SEL4_PG_SHM_H

#include <stdint.h>

#define VADDR_SHM_TCP_TLS     0x30000000ULL
#define VADDR_SHM_TLS_HTTP    0x31000000ULL
#define VADDR_SHM_HTTP_POLICY 0x32000000ULL
#define VADDR_SHM_SIGNED_CFG  0x33000000ULL
#define VADDR_SHM_POLICY_CONN 0x34000000ULL
#define VADDR_SHM_CONN_HTTP   0x35000000ULL
#define VADDR_SHM_TCP_CONN    0x36000000ULL
#define VADDR_TLS_KEYSTORE    0x37000000ULL
#define VADDR_SHM_POLICY_SCRIPT 0x38000000ULL
#define VADDR_SHM_SCRIPT_HTTP   0x39000000ULL
#define VADDR_SHM_HTTP_SUP      0x3A000000ULL   /* http_pd (rw) -> supervisor_pd (r): armed_seq/done_seq */
#define VADDR_SHM_SUP_HTTP      0x3B000000ULL   /* supervisor_pd (rw) -> http_pd (r): abort_seq */

#define PG_MAX_CONNS    4u
_Static_assert(PG_MAX_CONNS == 4u, "must equal pg_ipc::MAX_CONNS (crates/pg-ipc/src/lib.rs)");
#define PG_RING_SIZE    16384u
#define PG_MAX_TARGET   2048u
#define PG_MAX_HOST     256u
#define PG_MAX_REQ_RAW  16384u
#define PG_MAX_RESP_RAW 32768u
#define PG_MAX_BACKENDS 8u

/*
 * Fence for SMP/IPC ring synchronization.
 *   x86_64: TSO already orders store->store and load->load, a compiler barrier suffices.
 *   aarch64: weakly ordered; a real inner-shareable barrier is REQUIRED so that payload writes
 *            are visible before the head/tail/seq index update (and vice versa on the reader).
 */
#if defined(__x86_64__)
#define PG_FENCE() __asm__ __volatile__("" ::: "memory")
#elif defined(__aarch64__)
#define PG_FENCE() __asm__ __volatile__("dmb ish" ::: "memory")
#else
#error "pg_shm.h: unsupported architecture"
#endif

/* Decision logic for the single in-flight downstream request (crates/pg-ipc, Kani-verified). Layout == pg_ipc::InFlight. */
typedef struct {
    uint8_t  active;
    uint8_t  slot;
    uint8_t  _pad[2];
    uint32_t conn_id;
} pg_ipc_inflight_t;
extern void    pg_ipc_inflight_init(pg_ipc_inflight_t *f);
extern uint8_t pg_ipc_inflight_record(pg_ipc_inflight_t *f, uint8_t slot, const uint32_t *conn_ids /* [PG_MAX_CONNS] */);
extern uint8_t pg_ipc_inflight_accept(pg_ipc_inflight_t *f, uint8_t slot, const uint32_t *conn_ids /* [PG_MAX_CONNS] */);
extern void    pg_ipc_inflight_cancel_slot(pg_ipc_inflight_t *f, uint8_t slot);
extern uint8_t pg_ipc_ring_can_write(uint32_t head, uint32_t tail, uint32_t cap, uint32_t len);
typedef struct {            /* layout == pg_ipc::Watchdog */
    uint8_t  watching;
    uint32_t seq;
    uint64_t deadline_ns;
} pg_ipc_watchdog_t;
extern uint8_t pg_ipc_watchdog_step(pg_ipc_watchdog_t *w, uint32_t armed, uint32_t done, uint64_t now_ns, uint64_t timeout_ns, uint64_t *arm_ns);
extern uint8_t pg_ipc_watchdog_fault(pg_ipc_watchdog_t *w);
extern uint8_t pg_ipc_script_header_ok(uint16_t status, uint8_t ctype, uint32_t body_len, uint32_t max_body);

/* =========================================================================
 * 1. shm_tcp_tls: Socket-over-SHM between tcp_pd and tls_pd
 * ========================================================================= */
#define PG_TCP_STATE_FREE       0u
#define PG_TCP_STATE_OPEN       1u
#define PG_TCP_STATE_CLIENT_EOF 2u
#define PG_TCP_STATE_RESET      3u

typedef struct {
    volatile uint32_t conn_id;       /* Monotonic connection generation ID */
    volatile uint8_t  tcp_state;     /* PG_TCP_STATE_* written by tcp_pd */
    volatile uint8_t  tls_close_req; /* Set to 1 by tls_pd when session is done */
    uint8_t           _pad[2];
    volatile uint32_t rx_head;       /* Written by tcp_pd (ciphertext from client) */
    volatile uint32_t rx_tail;       /* Written by tls_pd */
    volatile uint32_t tx_head;       /* Written by tls_pd (ciphertext to client) */
    volatile uint32_t tx_tail;       /* Written by tcp_pd */
    uint8_t           rx_buf[PG_RING_SIZE];
    uint8_t           tx_buf[PG_RING_SIZE];
} pg_tcp_tls_slot_t;

typedef struct {
    pg_tcp_tls_slot_t slots[PG_MAX_CONNS];
    /* Monotonic nanoseconds from the sDDF timer, written by tcp_pd every timer tick. Placed after
     * the slots so existing offsets are unchanged. tls_pd has no timer client and, on aarch64,
     * EL0 cannot read CNTVCT_EL0 under seL4 hypervisor mode, so this is its only time source. */
    volatile uint64_t now_ns;
} pg_shm_tcp_tls_t;

/* =========================================================================
 * 2. shm_tls_http: Decrypted plaintext ring between tls_pd and http_pd
 * ========================================================================= */
typedef struct {
    volatile uint32_t conn_id;          /* Matches tcp_tls conn_id once TLS 1.3 + X25519MLKEM768 verified */
    volatile uint8_t  session_active;   /* 1 only after post-handshake LAW_002/LAW_003 check */
    volatile uint8_t  client_eof;       /* 1 if peer closed TLS cleanly */
    volatile uint8_t  close_after_resp; /* Set by http_pd when response complete & close needed */
    uint8_t           _pad;
    volatile uint32_t req_head;         /* Written by tls_pd (plaintext request bytes) */
    volatile uint32_t req_tail;         /* Written by http_pd */
    volatile uint32_t resp_head;        /* Written by http_pd (plaintext response bytes) */
    volatile uint32_t resp_tail;        /* Written by tls_pd */
    uint8_t           req_buf[PG_RING_SIZE];
    uint8_t           resp_buf[PG_MAX_RESP_RAW];
} pg_tls_http_slot_t;

typedef struct {
    pg_tls_http_slot_t slots[PG_MAX_CONNS];
} pg_shm_tls_http_t;

/* =========================================================================
 * 3. shm_http_policy: Parsed request -> Policy decision (http_pd <-> policy_pd)
 * ========================================================================= */
#define PG_DECISION_REJECT  0u
#define PG_DECISION_HEALTH  1u
#define PG_DECISION_FORWARD 2u
#define PG_DECISION_SCRIPT  3u /* QED Script dispatch (QEDOS_SCRIPT builds only) */

typedef struct {
    volatile uint32_t req_seq;       /* Incremented by http_pd when a request is ready */
    volatile uint32_t ack_seq;       /* Set to req_seq by policy_pd when decision is ready */
    volatile uint8_t  slot;          /* Connection slot index (0..PG_MAX_CONNS-1) */
    volatile uint8_t  method;        /* 0=GET, 1=HEAD, 2=POST, 3=PUT, 4=DELETE, 5=PATCH, 6=OPTIONS */
    volatile uint8_t  keep_alive;    /* 1 if HTTP/1.1 keep-alive requested */
    uint8_t           _pad0;
    volatile uint16_t target_len;
    volatile uint16_t host_len;
    volatile uint32_t body_len;
    /* Outputs written by policy_pd: */
    volatile uint8_t  decision;      /* PG_DECISION_* */
    volatile uint8_t  backend_id;    /* Fixed backend table index (LAW_004) */
    volatile uint16_t reject_status; /* HTTP status code on REJECT */
    /* Buffers written by http_pd: */
    uint8_t           target[PG_MAX_TARGET];
    uint8_t           host[PG_MAX_HOST];
    uint8_t           body[PG_MAX_REQ_RAW];
} pg_shm_http_policy_t;

/* =========================================================================
 * 4. shm_policy_conn: Approved Forward Ring (policy_pd -> connector_pd)
 *    LAW_007: Rejected and Health requests NEVER touch this region!
 * ========================================================================= */
typedef struct {
    uint8_t  ipv4[4];
    uint16_t port;
    uint8_t  _pad[2];
} pg_backend_entry_t;

typedef struct {
    volatile uint8_t   config_verified; /* 1 only after Ed25519 signature verification (LAW_011) */
    volatile uint8_t   num_backends;
    uint8_t            _pad0[2];
    pg_backend_entry_t backends[PG_MAX_BACKENDS];
    volatile uint32_t  fwd_seq;         /* Incremented by policy_pd on Decision::Forward */
    volatile uint32_t  fwd_ack;         /* Updated by connector_pd when processed */
    volatile uint8_t   slot;
    volatile uint8_t   backend_id;
    volatile uint8_t   method;
    volatile uint8_t   keep_alive;
    volatile uint16_t  target_len;
    uint16_t           _pad1;
    volatile uint32_t  body_len;
    uint8_t            target[PG_MAX_TARGET];
    uint8_t            body[PG_MAX_REQ_RAW];
} pg_shm_policy_conn_t;

/* =========================================================================
 * 5. shm_conn_http: Validated Backend Response (connector_pd -> http_pd)
 * ========================================================================= */
typedef struct {
    volatile uint32_t resp_seq;      /* Incremented by connector_pd when response ready */
    volatile uint32_t resp_ack;      /* Updated by http_pd when copied to shm_tls_http */
    volatile uint8_t  slot;
    volatile uint8_t  keep_alive;
    volatile uint16_t status;
    volatile uint32_t raw_resp_len;
    uint8_t           raw_resp[PG_MAX_RESP_RAW];
} pg_shm_conn_http_t;

/* =========================================================================
 * 6. shm_tcp_conn: Outbound Backend TCP Transaction (connector_pd <-> tcp_pd)
 * ========================================================================= */
#define PG_CONN_STATUS_IDLE        0u
#define PG_CONN_STATUS_IN_PROGRESS 1u
#define PG_CONN_STATUS_OK          2u
#define PG_CONN_STATUS_ERR_CONNECT 3u
#define PG_CONN_STATUS_ERR_TIMEOUT 4u

typedef struct {
    volatile uint32_t req_seq;       /* Incremented by connector_pd to open outbound TCP */
    volatile uint32_t resp_seq;      /* Set to req_seq by tcp_pd when response complete/error */
    volatile uint8_t  dst_ipv4[4];   /* Fixed backend IPv4 from table (e.g. 10.0.2.2) */
    volatile uint16_t dst_port;      /* Fixed backend port from table (e.g. 19001) */
    volatile uint8_t  status;        /* PG_CONN_STATUS_* */
    uint8_t           _pad;
    volatile uint32_t tx_len;
    volatile uint32_t rx_len;
    uint8_t           tx_buf[PG_MAX_REQ_RAW + 1024u];
    uint8_t           rx_buf[PG_MAX_RESP_RAW];
} pg_shm_tcp_conn_t;

/* =========================================================================
 * 7. QED Script (QEDOS_SCRIPT=1 images only)
 *    shm_policy_script: approved script request (policy_pd -> script_pd)
 *    shm_script_http:   script result            (script_pd -> http_pd)
 *    script_pd has NO other shared memory, NO timer/IRQ/ioport/TCB caps, and exactly two channels.
 * ========================================================================= */
#define PG_SCRIPT_BODY_MAX 16384u

typedef struct {
    volatile uint32_t req_seq;   /* policy_pd increments when a script request is ready */
    volatile uint32_t ack_seq;   /* script_pd sets to req_seq when the request has been consumed */
    volatile uint8_t  slot;
    volatile uint8_t  method;
    volatile uint8_t  keep_alive;
    uint8_t           _pad0;
    volatile uint16_t target_len;
    uint16_t          _pad1;
    volatile uint32_t body_len;
    uint8_t           target[PG_MAX_TARGET];
    uint8_t           body[PG_MAX_REQ_RAW];
} pg_shm_policy_script_t;

typedef struct {
    volatile uint32_t resp_seq;  /* script_pd increments when a result is ready */
    volatile uint32_t resp_ack;  /* http_pd sets to resp_seq once copied out */
    volatile uint8_t  slot;
    volatile uint8_t  keep_alive;
    volatile uint8_t  ctype;     /* 0 json, 1 html, 2 text */
    uint8_t           _pad0;
    volatile uint16_t status;
    uint16_t          _pad1;
    volatile uint32_t body_len;
    uint8_t           body[PG_SCRIPT_BODY_MAX];
} pg_shm_script_http_t;

/* =========================================================================
 * 8. Supervisor (QEDOS_SCRIPT=1 images only): one-way pages, single writer each (enforced by the MMU).
 *    script_pd has NO mapping of either page and NO channel to supervisor_pd.
 * ========================================================================= */
typedef struct {
    volatile uint32_t armed_seq;   /* http_pd: incremented when a script request is handed to script_pd */
    volatile uint32_t done_seq;    /* http_pd: set to armed_seq when script_pd has answered it */
} pg_shm_http_sup_t;

typedef struct {
    volatile uint32_t abort_seq;   /* supervisor_pd: incremented after it restarted script_pd */
} pg_shm_sup_http_t;

#endif /* PROOFGATE_SEL4_PG_SHM_H */
