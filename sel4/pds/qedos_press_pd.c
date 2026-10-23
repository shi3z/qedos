/*
 * qedos — QEDOS Press Protection Domain (`qedos_press_pd.elf`), built only with QEDOS_PRESS=1.
 *
 * Serves read-only static content from a signed release bundle (GET/HEAD only). Authority held by
 * this PD:
 *   - memory: `shm_policy_press` (rw, shared with policy_pd) and `shm_press_http` (rw, shared with
 *     http_pd); its own ELF image (code + the read-only `.press_bundle` section holding the signed
 *     content bundle -- `const`, placed in `.rodata`, so it is read-only via the ELF loader's segment
 *     permissions even to this PD itself, not merely by convention -- see docs/QEDOS_PRESS_CMS.md for
 *     the readelf verification of this).
 *   - channels: exactly two (policy_pd, http_pd). It cannot signal any other PD.
 *   - NOT held: TLS keystore, signed config, tcp/NIC/serial/timer, IRQ, ioport, TCB or untyped caps,
 *     any socket or filesystem, no write capability to its own content.
 *
 * Gap, stated plainly (see docs/QEDOS_PRESS_CMS.md): unlike script_pd, this PD has no supervisor
 * parent and no watchdog -- a fault here is not restarted. This is the narrower, simpler choice made
 * because this PD runs no untrusted/attacker-controlled code (only a fixed, signed content lookup
 * over bounded-size static data), so the risk profile that motivated script_pd's supervisor does not
 * apply in the same way; it is nonetheless a real availability gap, not implemented this phase.
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include "pg_shm.h"

#define CH_PRESS_POLICY 1
#define CH_PRESS_HTTP   2

extern void    pg_press_reset(void);
extern int32_t pg_press_init(const uint8_t *blob_ptr, size_t blob_len);
extern size_t  pg_press_handle(
    uint8_t method_u8,
    const uint8_t *target_ptr, size_t target_len,
    uint8_t *out_ptr, size_t out_cap,
    uint16_t *status_out, uint8_t *ctype_out, uint32_t *content_len_out);

/* QPR1 signed release bundle, injected at build time (scripts/build-sel4.sh -> .press_bundle).
 * `const`: placed in `.rodata`, mapped read-only by the ELF loader's own segment permissions. */
__attribute__((__section__(".press_bundle"), aligned(8)))
const uint8_t press_bundle_section[262144] = { 'Q', 'P', 'R', '1', 0 };

static pg_shm_policy_press_t *shm_policy_press = (pg_shm_policy_press_t *)VADDR_SHM_POLICY_PRESS;
static pg_shm_press_http_t   *shm_press_http   = (pg_shm_press_http_t *)VADDR_SHM_PRESS_HTTP;

static uint8_t req_target[PG_MAX_TARGET];
static uint8_t resp_body[PG_PRESS_BODY_MAX];

static uint32_t last_req_seq = 0;
static uint32_t press_ready = 0;

static void put_u32(uint32_t v)
{
    char b[11];
    int i = 10;
    b[i] = 0;
    if (v == 0) { b[--i] = '0'; }
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    microkit_dbg_puts(&b[i]);
}

static void reset_state(void)
{
    pg_press_reset();
    for (size_t i = 0; i < sizeof(req_target); i++) { req_target[i] = 0; }
    for (size_t i = 0; i < sizeof(resp_body); i++) { resp_body[i] = 0; }
    press_ready = 0;
    last_req_seq = shm_policy_press->req_seq;
    PG_FENCE();
    shm_policy_press->ack_seq = last_req_seq;
    shm_press_http->body_len = 0;
    PG_FENCE();
}

void init(void)
{
    reset_state();
    int32_t n = pg_press_init(press_bundle_section, sizeof(press_bundle_section));
    if (n < 0) {
        microkit_dbg_puts("QEDOS_PRESS_PD: FATAL - malformed or unsigned release bundle; nothing will be served\n");
        return;
    }
    press_ready = 1;
    microkit_dbg_puts("QEDOS_PRESS_PD: Ed25519 release signature verified; routes=");
    put_u32((uint32_t)n);
    microkit_dbg_puts("; read-only static content, GET/HEAD only\n");
}

void notified(microkit_channel ch)
{
    if (ch != CH_PRESS_POLICY) {
        return;
    }
    uint32_t rseq = shm_policy_press->req_seq;
    if (rseq == last_req_seq) {
        return;
    }
    last_req_seq = rseq;

    /* Copy the approved request out of shared memory first (no TOCTOU on shared memory). */
    uint16_t tlen = shm_policy_press->target_len;
    if (tlen > PG_MAX_TARGET) { tlen = PG_MAX_TARGET; }
    for (uint16_t i = 0; i < tlen; i++) { req_target[i] = shm_policy_press->target[i]; }
    uint8_t method = shm_policy_press->method;
    uint8_t slot = shm_policy_press->slot;
    uint8_t ka = shm_policy_press->keep_alive;

    uint16_t status = 503;
    uint8_t ctype = 0;
    uint32_t content_len = 0;
    size_t n = 0;
    if (press_ready) {
        n = pg_press_handle(method, req_target, tlen, resp_body, sizeof(resp_body), &status, &ctype, &content_len);
    }
    if (n > PG_PRESS_BODY_MAX) { n = PG_PRESS_BODY_MAX; }

    for (size_t i = 0; i < n; i++) { shm_press_http->body[i] = resp_body[i]; }
    shm_press_http->body_len = (uint32_t)n;
    shm_press_http->content_len = content_len;
    shm_press_http->status = status;
    shm_press_http->ctype = ctype;
    shm_press_http->slot = slot;
    shm_press_http->keep_alive = ka;
    PG_FENCE();
    shm_press_http->resp_seq = shm_press_http->resp_seq + 1;
    PG_FENCE();
    shm_policy_press->ack_seq = rseq;   /* request slot free again */
    PG_FENCE();
    microkit_notify(CH_PRESS_HTTP);
}
