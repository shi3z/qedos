# IPC verification

Scope: the shared-memory protocols between `http_pd`, `policy_pd`, `connector_pd` and (when built) `script_pd`/
`supervisor_pd`. Every value read from a shared region is treated as written by an attacker (LAW_013..022's model
for `script_pd`; for the other regions, by a buggy or compromised peer PD in general — see `docs/THREAT_MODEL.md`).

## Method

1. **Decision logic extracted into `crates/pg-ipc`** (`#![no_std]`, `#![forbid(unsafe_code)]`): request/response
   correlation (`InFlight`: one-shot, keyed by slot + connection generation), ring-buffer arithmetic
   (`ring_can_write`, `ring_pos`), and script-response header validation (`script_header_ok`). These functions are
   **total** (every bit pattern of every argument is a defined input) and contain no loops, so Kani proves them
   over the *entire* input domain, not a bounded slice of it — 14 harnesses, `build/kani/pg-ipc.log`.
2. **The C glue that calls them is not Kani-covered.** It is exercised instead by host-side adversarial harnesses
   (`tests/ipc/harness_http.c`, `tests/ipc/harness_policy_conn.c`) that `#include` the *actual*
   `sel4/pds/{http,policy,connector}_pd.c` sources (stubbing only the Rust HTTP-parsing FFI with a contract-level
   fake), map the real shared-memory regions at their real virtual addresses with `mmap(MAP_FIXED_NOREPLACE)`, and
   drive them with a hand-written hostile peer, under AddressSanitizer + UndefinedBehaviorSanitizer.
   `tests/ipc/run.sh` builds and runs both.

## What the harnesses found (and the fixes), reproduced against the pre-fix code in this session

| id | finding | harness case | fix |
|---|---|---|---|
| IPC-1 | A forged/replayed script or backend response was delivered to any client (wrong slot, stale connection, or a second notify for an already-answered request) | S2, S3, S4, S5, S10 in `harness_http.c` | `script_inflight`/`fwd_inflight` (now `pg_ipc::InFlight`) track the single in-flight request as (slot, connection generation) and accept exactly once |
| IPC-2 | A late policy-decision notification (processed after a new request reused the shared fields) silently dropped the in-flight marker | S9 | `check_policy_completion()` is now called before reusing `shm_http_policy`, and before accepting a connector/script response |
| IPC-3 | A hostile response length could overflow the TLS response ring (writing past unread data) | S7 | `pg_ipc::ring_can_write` checked before every ring write; refuses and closes the connection instead |
| IPC-4 | Two clients forwarding concurrently could have the second overwrite `shm_policy_conn` while `connector_pd` was still serving the first, corrupting that request and mis-attributing its response | `harness_policy_conn.c` main scenario | `policy_pd` now sheds (503) a new FORWARD decision while `shm_policy_conn`'s previous forward is unacknowledged |
| IPC-5 | Lengths/indices read from shared memory (`target_len`, `body_len`, `rx_len`, `num_backends`, `backend_id`) were not uniformly clamped before sizing a copy or indexing a table | throughout; hostile-length cases in both harnesses | every such value is clamped or bounds-checked before use in `connector_pd.c`/`policy_pd.c`/`http_pd.c` |

Reproduction: `git stash` the fix commits (or check out the pre-fix tree) and run `tests/ipc/run.sh` — each of IPC-1,
IPC-3 and IPC-4 reproduces as a harness `FAIL`; see each commit message for the exact harness line.

## Explicitly not covered

* `tcp_pd.c` and `tls_pd.c`'s own shared-memory handling (`shm_tcp_tls`) were not re-audited this session.
* Partial-write/duplicate-message/reset-during-communication scenarios for `shm_tcp_tls`/`shm_tls_http` specifically
  (the TCP/TLS boundary) are exercised only by the existing QEMU integration tests, not by a dedicated adversarial
  harness.
* The `pg-ipc` Kani proofs cover the functions, not the call sites' use of them (e.g. whether `http_pd.c` always
  calls `pg_ipc_inflight_accept` with the right slot) — that is why the ASan harnesses exist as a second,
  independent check on the same code.
