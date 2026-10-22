/*
 * qedos — Supervisor Protection Domain (`supervisor_pd.elf`), QEDOS_SCRIPT=1 images only.
 *
 * Purpose: liveness of the QED Script service without giving anything a general management interface.
 *   - It is the Microkit PARENT of script_pd, so it alone holds script_pd's TCB capability. It can restart or
 *     stop that one PD and nothing else; no other PD can reach it (no channel to script_pd, no shared page).
 *   - Inputs:  (1) a one-way read-only page written by http_pd: armed_seq / done_seq (a script request is pending
 *                  iff they differ);
 *              (2) the sDDF timer (monotonic ns, one-shot timeouts);
 *              (3) a fault of script_pd (Microkit delivers it to the parent).
 *   - Output:  restart of script_pd + abort_seq++ on a one-way page that http_pd reads, so http_pd can fail the
 *              request that was being served with 504.
 *   - Decisions are made by pg_ipc_watchdog_* (crates/pg-ipc, Kani-verified for all inputs): restart happens only
 *     for a pending request whose own clock has expired, or on a fault.
 *
 * What a restart does and does NOT do: it re-runs script_pd's entry point, whose init() re-verifies the signed
 * bundles, clears the interpreter scratch memory, KV store and shared-memory bookkeeping, and discards any
 * in-flight request (so a request that crashed the PD is never re-executed). It does NOT reload the ELF's data
 * segments: a PD that was compromised at the native level may leave arbitrary bytes in its own .data/.bss. That is
 * acceptable only because script_pd's authority is unchanged by the restart (it has nothing else to abuse);
 * see docs/SECURITY_BOUNDARIES.md.
 */
#include <stdint.h>
#include <stddef.h>
#include <microkit.h>
#include <sddf/timer/client.h>
#include <sddf/timer/config.h>
#include "pg_shm.h"

#define CH_HTTP          1     /* channel to http_pd (notifications both ways) */
#define SCRIPT_CHILD_ID  10    /* Microkit child id of script_pd (must match meta_proofgate.py) */
#define SCRIPT_ENTRY     0x200000ULL /* script_pd ELF entry point; scripts/build-sel4.sh asserts this against the ELF */

#ifndef SCRIPT_TIMEOUT_MS
#define SCRIPT_TIMEOUT_MS 5000ULL
#endif
#define NS_PER_MS 1000000ULL

__attribute__((__section__(".timer_client_config"))) timer_client_config_t timer_config;

static const pg_shm_http_sup_t *shm_http_sup = (const pg_shm_http_sup_t *)VADDR_SHM_HTTP_SUP;
static pg_shm_sup_http_t       *shm_sup_http = (pg_shm_sup_http_t *)VADDR_SHM_SUP_HTTP;

static pg_ipc_watchdog_t wd;
static uint32_t restarts;

/* Crash-loop containment: more than RESTART_BURST restarts inside RESTART_WINDOW_NS means the service is not
 * recoverable by restarting (hostile or broken script). Fail closed: leave script_pd stopped. policy_pd keeps shedding
 * script requests with 503 and every other service is unaffected; recovery needs an operator reboot. */
#define RESTART_BURST      8
#define RESTART_WINDOW_NS  (30ULL * 1000ULL * NS_PER_MS)
static uint64_t restart_ts[RESTART_BURST];
static uint32_t restart_next;
static uint8_t  script_disabled;

static void put_u32(uint32_t v)
{
    char b[11];
    int i = 10;
    b[i] = 0;
    if (v == 0) { b[--i] = '0'; }
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    microkit_dbg_puts(&b[i]);
}

static void restart_script_pd(const char *why)
{
    uint64_t now = sddf_timer_time_now(timer_config.driver_id);
    if (script_disabled) {
        return;
    }
    if (restart_ts[restart_next] != 0 && now - restart_ts[restart_next] < RESTART_WINDOW_NS) {
        script_disabled = 1;
        microkit_dbg_puts("SUPERVISOR: crash loop detected - script_pd left STOPPED (fail closed); other services unaffected\n");
        microkit_pd_stop(SCRIPT_CHILD_ID);
        PG_FENCE();
        shm_sup_http->abort_seq = shm_sup_http->abort_seq + 1;   /* still fail the request that was pending */
        PG_FENCE();
        microkit_notify(CH_HTTP);
        return;
    }
    restart_ts[restart_next] = now ? now : 1;
    restart_next = (restart_next + 1) % RESTART_BURST;
    restarts++;
    microkit_dbg_puts("SUPERVISOR: restarting script_pd (");
    microkit_dbg_puts(why);
    microkit_dbg_puts(") restart #");
    put_u32(restarts);
    microkit_dbg_puts("\n");
    microkit_pd_stop(SCRIPT_CHILD_ID);
    microkit_pd_restart(SCRIPT_CHILD_ID, SCRIPT_ENTRY);
    PG_FENCE();
    shm_sup_http->abort_seq = shm_sup_http->abort_seq + 1;
    PG_FENCE();
    microkit_notify(CH_HTTP);
}

static void evaluate(void)
{
    uint32_t armed = shm_http_sup->armed_seq;   /* untrusted bits: only (in)equality is used */
    uint32_t done  = shm_http_sup->done_seq;
    uint64_t now   = sddf_timer_time_now(timer_config.driver_id);
    uint64_t arm_ns = 0;
    uint8_t act = pg_ipc_watchdog_step(&wd, armed, done, now, SCRIPT_TIMEOUT_MS * NS_PER_MS, &arm_ns);
    if (act == 1) {
        sddf_timer_set_timeout(timer_config.driver_id, arm_ns);
    } else if (act == 2) {
        restart_script_pd("request overdue");
    }
}

void init(void)
{
    microkit_dbg_puts("SUPERVISOR: initialized (parent of script_pd; wall-clock watchdog ");
    put_u32((uint32_t)SCRIPT_TIMEOUT_MS);
    microkit_dbg_puts(" ms, Kani-verified decision logic)\n");
}

void notified(microkit_channel ch)
{
    if (ch == CH_HTTP || ch == timer_config.driver_id) {
        evaluate();
    }
}

/* script_pd faulted (invalid access, illegal instruction, ...): recover the service. */
seL4_Bool fault(microkit_child child, microkit_msginfo msginfo, microkit_msginfo *reply_msginfo)
{
    (void)msginfo;
    (void)reply_msginfo;
    if (child == SCRIPT_CHILD_ID) {
        (void)pg_ipc_watchdog_fault(&wd);
        restart_script_pd("fault");
    }
    return seL4_False; /* no fault reply: the thread is restarted explicitly above */
}
