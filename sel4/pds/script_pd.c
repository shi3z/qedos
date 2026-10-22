/*
 * qedos — QED Script Protection Domain (`script_pd.elf`), built only with QEDOS_SCRIPT=1.
 *
 * Runs untrusted, Ed25519-signed WebAssembly (LAW_013..LAW_022). Authority held by this PD:
 *   - memory: `shm_policy_script` (rw, shared with policy_pd) and `shm_script_http` (rw, shared with http_pd);
 *     its own ELF image (code, BSS wasm scratch memory, the read-only `.script_bundles` table).
 *   - channels: exactly two (policy_pd, http_pd). It cannot signal any other PD (LAW_014/LAW_022).
 *   - NOT held: TLS keystore, signed config, tcp/NIC/serial/timer, IRQ, ioport, TCB or untyped caps,
 *     any socket or filesystem (LAW_018, LAW_022). Verified mechanically by scripts/check-script-caps.py.
 * The Wasm guest itself never touches any of this: it only sees its linear memory and the allow-listed
 * host calls implemented in pg-script (LAW_013/LAW_015).
 *
 * Hardening in this glue:
 *   - request bytes are copied into PD-private buffers before use (no TOCTOU on shared memory);
 *   - one request in flight (policy_pd refuses further script requests while shm_policy_script is busy);
 *   - the response length is clamped before the copy into shm_script_http.
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include "pg_shm.h"

#define CH_SCRIPT_POLICY 1
#define CH_SCRIPT_HTTP   2

#define SCRIPT_MEM_BYTES (256u * 1024u)

extern int32_t pg_script_init(const uint8_t *blob_ptr, size_t blob_len, uint32_t *rejected_out);
extern size_t pg_script_handle(
    uint8_t method_u8,
    const uint8_t *target_ptr, size_t target_len,
    const uint8_t *body_ptr, size_t body_len,
    uint8_t *mem_ptr, size_t mem_len,
    uint8_t *out_ptr, size_t out_cap,
    uint16_t *status_out, uint8_t *ctype_out, uint32_t *reason_out);

/* QSB1 table of signed bundles, injected at build time (scripts/build-sel4.sh -> .script_bundles). */
__attribute__((__section__(".script_bundles"), aligned(8)))
uint8_t script_bundles_section[65536] = { 'Q', 'S', 'B', '1', 0 };

static pg_shm_policy_script_t *shm_policy_script = (pg_shm_policy_script_t *)VADDR_SHM_POLICY_SCRIPT;
static pg_shm_script_http_t   *shm_script_http   = (pg_shm_script_http_t *)VADDR_SHM_SCRIPT_HTTP;

static uint8_t wasm_mem[SCRIPT_MEM_BYTES];          /* zeroed again by the runtime on every request */
static uint8_t req_target[PG_MAX_TARGET];
static uint8_t req_body[PG_MAX_REQ_RAW];
static uint8_t resp_body[PG_SCRIPT_BODY_MAX];

static uint32_t last_req_seq = 0;
static uint32_t script_ready = 0;

static void put_u32(uint32_t v)
{
    char b[11];
    int i = 10;
    b[i] = 0;
    if (v == 0) { b[--i] = '0'; }
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    microkit_dbg_puts(&b[i]);
}

void init(void)
{
    uint32_t rejected = 0;
    int32_t n = pg_script_init(script_bundles_section, sizeof(script_bundles_section), &rejected);
    if (n < 0) {
        microkit_dbg_puts("SCRIPT_PD: FATAL - malformed bundle table; no script will run (LAW_020)\n");
        return;
    }
    script_ready = 1;
    microkit_dbg_puts("SCRIPT_PD: Ed25519 code-signature verification done (LAW_020): verified=");
    put_u32((uint32_t)n);
    microkit_dbg_puts(" rejected=");
    put_u32(rejected);
    microkit_dbg_puts("; Wasm interpreter, no JIT, fuel/memory/stack bounded (LAW_013..017)\n");
}

void notified(microkit_channel ch)
{
    if (ch != CH_SCRIPT_POLICY) {
        return;
    }
    uint32_t rseq = shm_policy_script->req_seq;
    if (rseq == last_req_seq) {
        return;
    }
    last_req_seq = rseq;

    /* Copy the approved request out of shared memory first. */
    uint16_t tlen = shm_policy_script->target_len;
    if (tlen > PG_MAX_TARGET) { tlen = PG_MAX_TARGET; }
    for (uint16_t i = 0; i < tlen; i++) { req_target[i] = shm_policy_script->target[i]; }
    uint32_t blen = shm_policy_script->body_len;
    if (blen > PG_MAX_REQ_RAW) { blen = PG_MAX_REQ_RAW; }
    for (uint32_t i = 0; i < blen; i++) { req_body[i] = shm_policy_script->body[i]; }
    uint8_t method = shm_policy_script->method;
    uint8_t slot = shm_policy_script->slot;
    uint8_t ka = shm_policy_script->keep_alive;

#ifdef QEDOS_SCRIPT_TEST_FAULT
    /* TEST-ONLY (never in production images): deliberately crash this PD to prove fault containment. */
    if (tlen >= 13 && req_target[8] == 'c' && req_target[9] == 'r' && req_target[10] == 'a' && req_target[11] == 's' && req_target[12] == 'h') {
        *(volatile uint32_t *)0 = 0xdead;
    }
#endif
    uint16_t status = 503;
    uint8_t ctype = 0;
    uint32_t reason = 0;
    size_t n = 0;
    if (script_ready) {
        n = pg_script_handle(method, req_target, tlen, req_body, blen,
                             wasm_mem, sizeof(wasm_mem), resp_body, sizeof(resp_body),
                             &status, &ctype, &reason);
    }
    if (n > PG_SCRIPT_BODY_MAX) { n = PG_SCRIPT_BODY_MAX; }
    if (reason != 0) {
        /* Operator-only diagnostic on the debug serial; never sent to the client (LAW_018). */
        microkit_dbg_puts("SCRIPT_PD: request ended with reason code ");
        put_u32(reason);
        microkit_dbg_puts("\n");
    }

    for (size_t i = 0; i < n; i++) { shm_script_http->body[i] = resp_body[i]; }
    shm_script_http->body_len = (uint32_t)n;
    shm_script_http->status = status;
    shm_script_http->ctype = ctype;
    shm_script_http->slot = slot;
    shm_script_http->keep_alive = ka;
    PG_FENCE();
    shm_script_http->resp_seq = shm_script_http->resp_seq + 1;
    PG_FENCE();
    shm_policy_script->ack_seq = rseq;   /* request slot free again */
    PG_FENCE();
    microkit_notify(CH_SCRIPT_HTTP);
}
