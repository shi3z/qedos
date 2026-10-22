# QED Script — results (2026-10-22)

Environment of every number below: Ubuntu 22.04 (kernel 5.15), 24-core x86-64 host, **no KVM** (QEMU TCG), rustc 1.91.1, Kani 0.68.0, Z3 4.15.4, Microkit SDK 2.3.1, sDDF `12f6667`, OpenSSL 3.6.1 (pinned build), QEMU from Ubuntu 22.04. Raw logs/summaries: `build/script/`, `build/kani/pg-script*.log`.
**Host-reference results and seL4 results are reported separately.** seL4 numbers come from QEMU TCG emulation and say nothing about hardware speed.

## 1. Baseline vs. after (existing functionality must not regress)

| Check | Before QED Script | After | Notes |
|---|---|---|---|
| `cargo test` pg-config / pg-http / pg-policy | 3 / 21 / 6 pass | 3 / 21 / 6 pass | `build/script/baseline-rust-tests.txt` (docs said 4 pg-config tests; actual 3, unchanged) |
| Kani, existing crates | documented 13/13 | **re-run: pg-http 8/8, pg-policy 3/3, pg-config 2/2** | `build/script/kani-*-after.summary` |
| `scripts/check-laws.sh` | exit 0 | exit 0 (+ LAW_013..022 static checks) | |
| `tests/test_sel4.py` on the committed prebuilt image | 6/6 pass | 6/6 pass (re-run with the modified harness) | |
| `tests/test_sel4.py` on an image **rebuilt from the modified sources** (default build, `QEDOS_SCRIPT` off) | n/a | **6/6 pass** (`QEDOS_OUT=build/sel4-rebuilt`) | shows the `#ifdef` glue and `rust_pds` additions do not change default behaviour |
| `/health` latency, seL4 under TCG, 30 sequential full PQ-TLS requests ×2 runs | median 83.0 / 82.7 ms (baseline image) | median 82.8 / 82.4 ms (script image) | dominated by the ML-KEM handshake in emulation; the script image adds no measurable cost to the proxy path (`build/script/sel4-latency.jsonl`) |
| Host reference proxy source | — | **unchanged** (`git diff` empty for `pg-proxy`, `pg-http`, `pg-policy`, `pg-config`) | |

### Things that could not be reproduced in this environment (not caused by this change)
* `tests/test_tls.py` (7 of 11 pass) and `tests/test_http.py` use the system Python `ssl`, linked to OpenSSL **3.0.2**, which cannot offer `X25519MLKEM768`; the clients fail before reaching the proxy. Chrome test skipped (no Chrome). The proxy source is unmodified, so these are environment limits, but they were **not** demonstrated green here.
* C10K re-run (`tests/perf.py`, 10 000 connections, host proxy, this machine): PERF_001–007 pass; **PERF_008 reports failed because its hostile-probe client (Python `ssl`) cannot negotiate the PQ group: `probes_run = 0`.** The parts of PERF_008 that ran: 221 653 responses OK under load, backend audit 632 556 requests with 0 violations, policy violations 0. Throughput on this machine (e.g. PERF_004 8.2 k req/s, PERF_006 2.6 k handshakes/s) differs from the figures in `docs/RESULTS.md` (13.4 k / 5.4 k) because those were taken on other hardware; no same-machine before/after was possible beyond "binary source identical". `build/perf/results.json` (committed) was left as it was; this run is in `build/script/c10k-host-after.json`.

## 2. Test counts (new)
| Suite | Result |
|---|---|
| Rust unit/fuzz: `pg-script` 18, `pg-script-policy` 9, `pg-script-verify` 9 | **36/36** pass |
| `tests/test_script.py` (functional) | **16/16** |
| `tests/test_script_security.py` (36 signed hostile modules + tamper cases) | **151/151** |
| `tests/test_script_sel4.py` (QEMU, seL4 + Microkit, PQ-TLS) | **9/9** — SCRIPT_001…009 |
| `scripts/check-script-caps.py --selftest` | pass; **9/9** weakened systems detected |
| Kani (new) | **7/7** harnesses verified (`pg-script` 4, `pg-script-policy` 3), cover checks satisfied |
| Z3 | `range_sound` unsat; `range_naive_unsound` sat (control); `kv_key_injective` unsat |
| Fuzz | 60 000 random programs (guard bands intact, fuel respected); 60 000 mutated modules (no panic) |

seL4 end-to-end (`tests/test_script_sel4.py`, recorded in `build/script/test_script_sel4.txt`): script image builds, passes the capability audit (13 PDs, 16 channels), boots; `script_pd` logs `verified=5 rejected=0`; **`GET /script/hello` over TLS 1.3 with negotiated `X25519MLKEM768` returns `{"message":"Hello from QEDOS"}`**; `POST /script/json-echo` transforms JSON; unknown module / traversal / bad method rejected before Wasm; proxying to backends A/B, hostile-request rejection, TLS 1.2 and classical-group refusal unchanged; OOB module → 500 generic; runaway module → 503; `/health` answered in 0.09 s while it ran; after a deliberately crashed `script_pd` (test-only flag `QEDOS_SCRIPT_TEST_FAULT`) TLS, `/health` and proxying keep working and `/script/*` returns 503.

## 3. Performance
### 3.1 Host reference runtime (`qs bench`, release build, one thread; includes zeroing/scrubbing memory and the response buffer every request)
| Workload | req/s | µs / request | fuel / request |
|---|---|---|---|
| Hello World (`examples/hello`, 30-byte JSON) | 180 322 | 5.6 | 9 |
| KV counter (`kv-counter`, 2 host KV calls) | 174 669 | 5.7 | 25 |
| JSON echo, 1000-byte body (`json-echo`) | 2 681 | 373 | 62 229 |
Module parse 0.3–0.8 µs; bundle verification (Ed25519, once per script at load) 230–340 µs; one `Instance` = 7 528 bytes inline (+ module memory: 64 KiB in the examples). "CPU per request" ≈ the µs column (single thread, CPU-bound). The interpreter executes ≈ 160 M fuel/s on this host (json-echo). These are *not* comparable to the proxy's req/s: no TLS, no network.

### 3.2 seL4 under QEMU TCG (30 sequential requests, fresh PQ-TLS handshake each)
| Path | baseline image | script image |
|---|---|---|
| `GET /health` | median 83.0 / 82.7 ms | median 82.8 / 82.4 ms |
| `GET /script/hello` | — | median 83.2 / 84.1 ms |
| `POST /script/json-echo` (500-byte body) | — | median 85.0 / 88.0 ms |
Boot to ready: 10.3–10.8 s baseline, 11.3 s script image. Script_pd static memory: 256 KiB Wasm scratch + 64 KiB bundle table + ≈34 KiB request/response copies + 256 KiB stack. Concurrency: 4 TLS slots (existing `PG_MAX_CONNS`), **1 script request in flight** (others get 503).

### 3.3 Not measured
req/s of the whole seL4 stack (emulator-bound), hardware numbers, script-induced TLS throughput degradation beyond the single `/health`-during-spin observation, C10K with script traffic (the host proxy has no script route), worker pools / module cache (not built; each request already reuses statically allocated memory and a parsed module).

## 4. Not done (explicit)
* Separate Storage PD; authentication/principal (KV unusable on seL4).
* Timer-based `max_exec_us` on seL4; restart of a dead `script_pd`.
* TinyGo/Rust SDK and JS-like API (the MVP subset rejects what those compilers emit).
* Proof checker (envelope only).
* Viper obligations were generated, not discharged; aarch64 image with Script PD not built.
* Differential testing against a reference Wasm engine.
