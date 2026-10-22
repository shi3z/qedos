/*
 * Host-side adversarial test of the REAL sel4/pds/http_pd.c (QEDOS_SCRIPT build) against a fully
 * compromised script_pd: the "attacker" writes arbitrary bytes into shm_script_http and sends arbitrary
 * notifications. Built with ASan+UBSan; shared regions are mapped at the same fixed addresses as in
 * the Microkit system, each surrounded by unmapped memory, so any out-of-range access faults.
 *
 * The Rust pieces (HTTP parser / response formatter) are replaced by small C stand-ins with the same
 * contract; this test targets the C glue (slot and request correlation, ring writes, bounds).
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

/* ---- stand-ins for the Rust FFI (contract only) ---- */
int32_t pg_rust_parse_http_request(const uint8_t *buf, size_t len, size_t max_body, uint8_t *method_out,
    uint8_t *ka_out, uint8_t *target_out, size_t target_cap, uint16_t *target_len_out, uint8_t *host_out,
    size_t host_cap, uint16_t *host_len_out, uint8_t *body_out, uint32_t *body_len_out, size_t *consumed_out)
{
    (void)max_body; (void)host_out; (void)host_cap; (void)body_out;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            const char *t = "/script/x";
            size_t n = strlen(t);
            assert(n <= target_cap);
            memcpy(target_out, t, n);
            *target_len_out = (uint16_t)n; *host_len_out = 0; *body_len_out = 0;
            *method_out = 0; *ka_out = 1; *consumed_out = i + 4;
            return 1;
        }
    }
    return 0;
}
size_t pg_rust_format_local_response(uint16_t status, uint8_t is_health, uint8_t is_head, uint8_t ka, uint8_t *out, size_t cap)
{
    (void)is_health; (void)is_head; (void)ka;
    int n = snprintf((char *)out, cap, "LOCAL %u\r\n", status);
    return n > 0 ? (size_t)n : 0;
}
size_t pg_rust_format_script_response(uint16_t status, uint8_t ctype, uint8_t ka, const uint8_t *body, size_t blen, uint8_t *out, size_t cap)
{
    if (status < 200 || status > 599) return 0;
    int n = snprintf((char *)out, cap, "SCRIPT %u %u %u len=%zu\r\n", status, ctype, ka, blen);
    if (n <= 0 || (size_t)n + blen > cap) return 0;
    memcpy(out + n, body, blen);   /* ASan: body must be a private, fully readable buffer of blen bytes */
    return (size_t)n + blen;
}

#define QEDOS_SCRIPT 1
#ifndef HTTP_PD_SRC
#define HTTP_PD_SRC "../../sel4/pds/http_pd.c"
#endif
#include HTTP_PD_SRC

static void *map_fixed(uint64_t addr, size_t size)
{
    void *p = mmap((void *)addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED || (uint64_t)p != addr) { perror("mmap fixed"); exit(77); }
    return p;
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return rng_state; }

static int failures;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); failures++; } } while (0)

/* ---- helpers acting as tls_pd / policy_pd / script_pd ---- */
static void tls_feeds_request(int s, uint32_t conn)
{
    pg_tls_http_slot_t *ts = &shm_tls_http->slots[s];
    ts->conn_id = conn; ts->session_active = 1;
    const char *req = "GET /script/x HTTP/1.1\r\nHost: a\r\n\r\n";
    uint32_t h = ts->req_head;
    for (size_t i = 0; i < strlen(req); i++) ts->req_buf[(h + i) % PG_RING_SIZE] = (uint8_t)req[i];
    ts->req_head = h + (uint32_t)strlen(req);
    notified(CH_HTTP_TLS);
}
static void policy_decides_script(void)
{
    shm_http_policy->decision = PG_DECISION_SCRIPT;
    shm_http_policy->ack_seq = shm_http_policy->req_seq;
    notified(CH_HTTP_POLICY);
}
static void script_responds(uint8_t slot, uint16_t status)
{
    shm_script_http->slot = slot; shm_script_http->status = status; shm_script_http->ctype = 0; shm_script_http->keep_alive = 1;
    shm_script_http->body_len = 5; memcpy((void *)shm_script_http->body, "hello", 5);
    shm_script_http->resp_seq = shm_script_http->resp_seq + 1;
    notified(CH_HTTP_SCRIPT);
}
static uint32_t resp_bytes(int s) { return shm_tls_http->slots[s].resp_head; }
static void reset_world(void)
{
    memset((void *)shm_tls_http, 0, sizeof(*shm_tls_http));
    memset((void *)shm_http_policy, 0, sizeof(*shm_http_policy));
    memset((void *)shm_script_http, 0, sizeof(*shm_script_http));
    memset((void *)shm_conn_http, 0, sizeof(*shm_conn_http));
    memset(slot_state, 0, sizeof(slot_state));
#ifdef HAVE_INFLIGHT
    memset(&script_inflight, 0, sizeof(script_inflight));
#endif
    last_policy_ack = last_conn_resp = last_script_resp = 0;
}

int main(void)
{
    map_fixed(VADDR_SHM_TLS_HTTP, 0x40000);
    map_fixed(VADDR_SHM_HTTP_POLICY, 0x10000);
    map_fixed(VADDR_SHM_CONN_HTTP, 0x10000);
    map_fixed(VADDR_SHM_SCRIPT_HTTP, 0x8000);

    /* S1 legitimate round trip: exactly one response on the right slot */
    reset_world();
    tls_feeds_request(0, 7);
    CHECK(shm_http_policy->req_seq == 1, "request reached policy");
    shm_http_policy->slot = 0;
    policy_decides_script();
#ifdef HAVE_INFLIGHT
    CHECK(script_inflight.active && script_inflight.slot == 0, "script request tracked in flight");
#endif
    script_responds(0, 200);
    CHECK(resp_bytes(0) > 0, "S1 legit response delivered");
    uint32_t after = resp_bytes(0);

    /* S2 replay of the same response (resp_seq bumped again): must NOT deliver twice */
    script_responds(0, 200);
    CHECK(resp_bytes(0) == after, "S2 replayed response ignored");

    /* S3 forged response with nothing in flight, for every slot value incl. out of range */
    for (int s = 0; s < 256; s++) {
        script_responds((uint8_t)s, 200);
        for (int k = 0; k < PG_MAX_CONNS; k++) CHECK(k == 0 ? resp_bytes(0) == after : resp_bytes(k) == 0, "S3 forged unsolicited response delivered");
    }

    /* S4 request in flight on slot 1; attacker answers for slot 2 and 0 first, legit later */
    reset_world();
    tls_feeds_request(1, 11);
    shm_http_policy->slot = 1;
    policy_decides_script();
    script_responds(2, 200); script_responds(0, 200); script_responds(1, 99); /* 99: invalid status -> 502 for slot 1? */
    CHECK(resp_bytes(2) == 0 && resp_bytes(0) == 0, "S4 cross-slot injection blocked");

    /* S5 connection replaced between decision and response (slot reused by another client) */
    reset_world();
    tls_feeds_request(3, 21);
    shm_http_policy->slot = 3;
    policy_decides_script();
    shm_tls_http->slots[3].conn_id = 22;          /* tls_pd reuses the slot for a new connection */
    slot_state[3].conn_id = 22; slot_state[3].awaiting_backend = 0;
    script_responds(3, 200);
    CHECK(resp_bytes(3) == 0, "S5 stale response not delivered to a new connection");

    /* S6 hostile field values: huge length, bad status/ctype/ka, with a request legitimately in flight */
    reset_world();
    tls_feeds_request(0, 5);
    shm_http_policy->slot = 0;
    policy_decides_script();
    shm_script_http->slot = 0; shm_script_http->status = 0xFFFF; shm_script_http->ctype = 0xFF; shm_script_http->keep_alive = 0xFF;
    shm_script_http->body_len = 0xFFFFFFFFu; shm_script_http->resp_seq = 1;
    notified(CH_HTTP_SCRIPT);
    CHECK(resp_bytes(0) == 0, "S6 oversized length rejected, no read beyond region");

    /* S7 ring-full: corrupt/hostile tls_pd tail must not let http_pd overwrite unread data */
    reset_world();
    tls_feeds_request(0, 5);
    shm_http_policy->slot = 0;
    shm_tls_http->slots[0].resp_head = 100; shm_tls_http->slots[0].resp_tail = 0xFFFF0000u;   /* nonsense tail */
    uint32_t before = shm_tls_http->slots[0].resp_head;
    policy_decides_script();
    script_responds(0, 200);
    CHECK(shm_tls_http->slots[0].resp_head == before, "S7 no write when ring state is inconsistent");
    CHECK(shm_tls_http->slots[0].close_after_resp == 1, "S7 connection closed instead");

    /* S9 decision acked by policy_pd but its notification not yet handled when the next request arrives
     *    (this is what the QEMU runaway-script test does): the script response must still be delivered. */
    reset_world();
    tls_feeds_request(0, 31);
    shm_http_policy->slot = 0;
    shm_http_policy->decision = PG_DECISION_SCRIPT;
    shm_http_policy->ack_seq = shm_http_policy->req_seq;      /* NO notified(CH_HTTP_POLICY) */
    tls_feeds_request(1, 32);                                  /* another client shows up meanwhile */
    script_responds(0, 200);
    CHECK(resp_bytes(0) > 0, "S9 legit script response delivered even though the decision notification was late");
    CHECK(resp_bytes(1) == 0 || shm_http_policy->req_seq >= 2, "S9 no response leaked to the other client");

    /* S10 connector-side injection: unsolicited / replayed / wrong-slot backend responses are not delivered */
    reset_world();
    for (int sl = 0; sl < 8; sl++) {
        shm_conn_http->slot = (uint8_t)sl; shm_conn_http->keep_alive = 1; shm_conn_http->raw_resp_len = 4;
        memcpy((void *)shm_conn_http->raw_resp, "EVIL", 4);
        shm_conn_http->resp_seq = shm_conn_http->resp_seq + 1;
        notified(CH_HTTP_CONN);
    }
    for (int k = 0; k < PG_MAX_CONNS; k++) CHECK(resp_bytes(k) == 0, "S10 unsolicited backend response delivered");
    tls_feeds_request(2, 41);
    shm_http_policy->slot = 2; shm_http_policy->decision = PG_DECISION_FORWARD; shm_http_policy->ack_seq = shm_http_policy->req_seq;
    notified(CH_HTTP_POLICY);
    shm_conn_http->slot = 1; shm_conn_http->raw_resp_len = 4; shm_conn_http->resp_seq = shm_conn_http->resp_seq + 1; notified(CH_HTTP_CONN);
    CHECK(resp_bytes(1) == 0 && resp_bytes(2) == 0, "S10 wrong-slot answer dropped (and does not consume the in-flight request)");

    /* S8 random adversary: hammer every script-controlled byte + policy slot field, interleaved with legit traffic */
    reset_world();
    for (long it = 0; it < 400000; it++) {
        uint32_t r = (uint32_t)rnd();
        switch (r % 6) {
        case 0: tls_feeds_request((int)(rnd() % PG_MAX_CONNS), 1 + (uint32_t)(rnd() % 4)); break;
        case 1: shm_http_policy->slot = (uint8_t)rnd(); policy_decides_script(); break;
        case 2: {
            uint8_t *b = (uint8_t *)shm_script_http;
            for (int k = 0; k < 16; k++) b[rnd() % 32] = (uint8_t)rnd();     /* header bytes */
            b[32 + rnd() % PG_SCRIPT_BODY_MAX] = (uint8_t)rnd();
            notified(CH_HTTP_SCRIPT);
            break; }
        case 3: shm_script_http->resp_seq = (uint32_t)rnd(); notified(CH_HTTP_SCRIPT); break;
        case 4: shm_http_policy->slot = (uint8_t)rnd(); shm_http_policy->decision = (uint8_t)rnd();
                shm_http_policy->reject_status = (uint16_t)rnd(); shm_http_policy->ack_seq = shm_http_policy->req_seq;
                notified(CH_HTTP_POLICY); break;
        default: notified(CH_HTTP_TLS); break;
        }
        /* drain rings like a cooperative tls_pd so they do not just fill up */
        for (int s = 0; s < PG_MAX_CONNS; s++) shm_tls_http->slots[s].resp_tail = shm_tls_http->slots[s].resp_head;
    }
    printf("harness_http: %s (%d failure(s))\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
