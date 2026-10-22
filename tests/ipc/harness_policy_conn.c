/*
 * Host-side test of the REAL policy_pd.c + connector_pd.c glue with two clients forwarding concurrently
 * (a pre-existing race independent of QED Script): while connector_pd is still serving the first
 * forwarded request, a second one must not overwrite shm_policy_conn.
 * Rust FFI replaced by contract-level stand-ins.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "microkit.h"
#include "pg_shm.h"

unsigned stub_notify_count[64];
static int decide_forward = 1;

int32_t pg_rust_policy_init(const uint8_t *b, size_t n, uint8_t *nb, uint8_t *ip, uint16_t *port)
{ (void)b; (void)n; *nb = 1; ip[0] = 10; ip[1] = 0; ip[2] = 2; ip[3] = 2; port[0] = 19001; return 1; }
int32_t pg_rust_policy_decide(uint8_t m, const uint8_t *t, size_t tl, uint32_t bl, uint8_t *dec, uint8_t *bid, uint16_t *rs)
{ (void)m; (void)bl; assert(tl <= PG_MAX_TARGET); (void)t; *dec = decide_forward ? PG_DECISION_FORWARD : PG_DECISION_HEALTH; *bid = 0; *rs = 0; return 0; }
uint8_t pg_rust_is_script_route(uint8_t m, const uint8_t *t, size_t l) { (void)m; (void)t; (void)l; return 0; }
size_t pg_rust_format_backend_request(uint8_t m, const uint8_t *t, size_t tl, const uint8_t *ip, uint16_t p,
    const uint8_t *body, size_t bl, uint8_t *out, size_t cap)
{ (void)m; (void)ip; (void)p; assert(tl <= PG_MAX_TARGET && bl <= PG_MAX_REQ_RAW);
  size_t n = tl < cap ? tl : cap; memcpy(out, t, n); (void)body; return n; }
size_t pg_rust_validate_and_frame_response(const uint8_t *raw, size_t rl, uint8_t h, uint8_t ka, uint16_t *st, uint8_t *out, size_t cap)
{ (void)h; (void)ka; assert(rl <= PG_MAX_RESP_RAW); size_t n = rl < cap ? rl : cap; memcpy(out, raw, n); *st = 200; return n; }
size_t pg_rust_format_local_response(uint16_t st, uint8_t a, uint8_t b, uint8_t c, uint8_t *out, size_t cap)
{ (void)a; (void)b; (void)c; int n = snprintf((char *)out, cap, "LOCAL %u", st); return n > 0 ? (size_t)n : 0; }

/* two PDs in one process: rename their entry points */
#define init policy_init
#define notified policy_notified
#define CH_POLICY_HTTP CH_POLICY_HTTP_P
#include "../../sel4/pds/policy_pd.c"
#undef init
#undef notified
#undef last_req_seq
#define init conn_init
#define notified conn_notified
#define last_fwd_seq conn_last_fwd_seq
#define shm_policy_conn conn_shm_policy_conn
#include "../../sel4/pds/connector_pd.c"

static void *map_fixed(uint64_t addr, size_t size)
{
    void *p = mmap((void *)addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED || (uint64_t)p != addr) { perror("mmap"); exit(77); }
    return p;
}
static int failures;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s (line %d)\n", m, __LINE__); failures++; } } while (0)

static void http_requests(uint8_t slot, const char *target)
{
    pg_shm_http_policy_t *hp = (pg_shm_http_policy_t *)VADDR_SHM_HTTP_POLICY;
    hp->slot = slot; hp->method = 0; hp->keep_alive = 1;
    hp->target_len = (uint16_t)strlen(target); memcpy(hp->target, target, strlen(target)); hp->body_len = 0;
    hp->req_seq = hp->req_seq + 1;
    policy_notified(1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    map_fixed(VADDR_SHM_HTTP_POLICY, 0x10000);
    map_fixed(VADDR_SHM_SIGNED_CFG, 0x1000);
    map_fixed(VADDR_SHM_POLICY_CONN, 0x10000);
    map_fixed(VADDR_SHM_CONN_HTTP, 0x10000);
    map_fixed(VADDR_SHM_TCP_CONN, 0x20000);
    map_fixed(VADDR_SHM_POLICY_SCRIPT, 0x10000);
    memcpy((void *)VADDR_SHM_SIGNED_CFG, "PG", 2);
    policy_init();

    pg_shm_http_policy_t *hp = (pg_shm_http_policy_t *)VADDR_SHM_HTTP_POLICY;
    pg_shm_policy_conn_t *pc = (pg_shm_policy_conn_t *)VADDR_SHM_POLICY_CONN;
    pg_shm_tcp_conn_t *tc = (pg_shm_tcp_conn_t *)VADDR_SHM_TCP_CONN;

    /* client A forwards; connector starts working on it */
    http_requests(0, "/a");
    CHECK(hp->decision == PG_DECISION_FORWARD, "A forwarded");
    conn_notified(1);
    CHECK(tc->status == PG_CONN_STATUS_IN_PROGRESS && memcmp(tc->tx_buf, "/a", 2) == 0, "connector serving A");

    /* client B arrives while A is still outstanding at the backend */
    http_requests(1, "/b");
    CHECK(hp->decision == PG_DECISION_REJECT && hp->reject_status == 503, "B is shed with 503 while the connector is busy");
    CHECK(memcmp(pc->target, "/a", 2) == 0 && pc->slot == 0, "shm_policy_conn still describes A (not overwritten)");

    /* backend answers A; connector finishes; B may retry successfully */
    memcpy(tc->rx_buf, "RESP-A", 6); tc->rx_len = 6; tc->status = PG_CONN_STATUS_OK; tc->resp_seq = tc->req_seq;
    conn_notified(3);
    pg_shm_conn_http_t *ch = (pg_shm_conn_http_t *)VADDR_SHM_CONN_HTTP;
    CHECK(ch->slot == 0 && memcmp(ch->raw_resp, "RESP-A", 6) == 0, "A's response attributed to slot 0");
    http_requests(1, "/b");
    CHECK(hp->decision == PG_DECISION_FORWARD, "B forwarded after A finished");

    /* connector error paths must release the busy gate too (config-unverified / oversize) */
    pc->config_verified = 0;
    conn_notified(1);
    pc->config_verified = 1;
    CHECK(pc->fwd_ack == pc->fwd_seq, "error path acknowledges the forward (no permanent busy state)");

    /* hostile lengths from the neighbours */
    tc->rx_len = 0xFFFFFFFFu; tc->status = PG_CONN_STATUS_OK; tc->req_seq = 99; tc->resp_seq = 99;
    conn_notified(3);                                            /* must not read beyond rx_buf */
    pc->num_backends = 255; pc->backend_id = 200; pc->fwd_seq = pc->fwd_seq + 1;
    conn_notified(1);                                            /* must fail closed, not index backends[200] */
    printf("harness_policy_conn: %s (%d failure(s))\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
