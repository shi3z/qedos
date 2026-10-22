# Security laws — specification, evidence, and scope

Legend:
* **PROVEN-BOUNDED** = Kani model checking of the real Rust code (`13/13` harnesses pass, 0 failures), for inputs up to the stated length bound.
* **VIPER-AUDITED** = Microkit `--viper-output` formal capability/memory invariant export (`build/sel4/viper/*.vpr`) + `scripts/check-caps.py` verification on `build/sel4/proofgate.system` and PD ELFs.
* **TESTED** = automated tests on both the Linux host reference proxy (`tests/test_tls.py`, `tests/test_http.py`, `tests/perf.py`) and the seL4 multi-PD OS image in QEMU (`tests/test_sel4.py`).

| Law | Spec (informal) | Evidence today | Assumptions | Not proven / scope limits |
|---|---|---|---|---|
| `LAW_001` only fixed routes reachable | `decide()` returns `Health`, `Forward(table index)` or `Reject`; path hygiene rejects dot-segments, `;`, `//`, encoded `/ \ . %`, controls, overlong UTF-8 | **PROVEN-BOUNDED** `pg-policy::proofs::accepted_path_has_no_traversal` (≤8 B, 0 failed); **TESTED** unit tests + 34 HTTP tests + `SEL4_004/005` + `PERF_008` (18 513 hostile probes, 0 backend violations) | Kani bound | inputs >8 B in Kani (covered by unit/fuzz/integration tests) |
| `LAW_002` TLS ≥1.3 only | handshake with <1.3 never completes | **TESTED** `TEST_TLS_002` (host) + `SEL4_002` (seL4 `tls_pd`); config `min=max=TLS1_3_VERSION` + post-handshake `SSL_version` re-check | OpenSSL 3.6.1 correct | no formal proof of OpenSSL C code |
| `LAW_003` only `X25519MLKEM768` | no other key-exchange group negotiated | **TESTED** `TEST_TLS_003/004/006/007/008` (host) + `SEL4_001/003` (seL4 `tls_pd`) + `test_tls_shim_runner`; `set1_groups_list` + post-handshake `SSL_get0_group_name` re-check | OpenSSL 3.6.1 correct | group name read from OpenSSL |
| `LAW_004` no client-chosen backend | backend address only from fixed table | **PROVEN-BOUNDED** `forward_backend_is_table_member` & `deployed_routes_forward_only_to_valid_backends` (`pg-policy`); **TESTED** `SEL4_004` (seL4 `connector_pd`) + `PERF_008` | signed config key trusted | Kani bound ≤8 B |
| `LAW_005` no shell/exec path | no process-spawn API reachable from HTTP input | **STATIC CHECK** `scripts/check-laws.sh` across `crates/*` and `sel4/*`; **VERIFIED ON seL4** (`build/sel4/loader.img` has no shell or process-creation syscall) | — | on Linux host mode, the host OS itself has a shell |
| `LAW_006` parser stays in bounds | no OOB / arithmetic overflow for any input | `#![forbid(unsafe_code)]` in `pg-http`, `pg-policy`, `pg-config`; **PROVEN-BOUNDED** `pg-http` **8/8 harnesses pass** (`parse_request_spans_in_bounds`, `parse_response_spans_in_bounds`, `accepted_request_is_http11_with_host`, `chunk_decoder_in_bounds`, plus 4 validator harnesses; logs in `build/kani/`) | Kani bounds (`N=18..20`, `MAX_HEADERS=2` under Kani) | inputs larger than Kani bound rely on safe Rust bounds checks (`panic=abort`) |
| `LAW_007` rejected ⇒ not forwarded | parse error or `Reject` ⇒ no backend connect | **VIPER-AUDITED & TESTED**: on seL4, `http_pd` has no channel to `connector_pd` or `tcp_pd`, and `policy_pd` notifies `connector_pd` only on `Decision::Forward`; verified by `SEL4_005`, `test_http.py`, `PERF_008` | `policy_pd` C glue (~30 lines) | — |
| `LAW_008` TLS key not reachable from HTTP layer | private key mapped only in `tls_pd` | **VIPER-AUDITED** (`build/sel4/viper/tls_pd.vpr` vs `http_pd.vpr`, `policy_pd.vpr`, `connector_pd.vpr`, `tcp_pd.vpr` + ELF scan in `scripts/check-caps.py`) and **TESTED** `TEST_TLS_010`, `SEL4_006` | seL4 kernel + Microkit initializer | not satisfied when running the single-process Linux reference proxy |
| `LAW_009` resources freed after close | connection state & heap reclaimed on close | **TESTED** `PERF_007` (host: 10k conns → active 0, fds 6→6, RSS 9.3 MB) + `test_tls_shim_runner` (seL4 `libc_shim` coalescing heap: 0 bytes leaked across repeated TLS 1.3 `X25519MLKEM768` handshakes) | — | no formal heap proof |
| `LAW_010` no unauthenticated admin op | no dynamic route/admin endpoint exists | **VERIFIED** by code inspection (`pg-policy` and `pg-config` have no admin routes or runtime mutation API) | — | config updates require reboot with newly signed image |
| `LAW_011` only signed config applied | Ed25519 signature verified against pinned `PUBLIC_KEY` before applying routes/backends | **PROVEN-BOUNDED** `pg-config` **2/2 harnesses pass** (`unverified_blob_always_rejected`, `parse_blob_in_bounds`); **TESTED** `test_signed_config_law_011` (`tests/test_http.py`) + `SEL4_001` (`policy_pd` verifies `shm_signed_config` at boot) | Ed25519 private key security | — |
| `LAW_012` minimal capabilities for proxy | each PD holds only its required shm/channel caps; no app PD holds IRQ/ioport/TCB caps | **VIPER-AUDITED** (`build/sel4/viper/*.vpr` + `scripts/check-caps.py` + `SEL4_006`) | Microkit tool & CapDL initializer | — |

Reproduce all checks:
```sh
cargo test
cargo kani -p pg-policy && cargo kani -p pg-http && cargo kani -p pg-config
scripts/check-laws.sh
python3 tests/test_tls.py && python3 tests/test_http.py && python3 tests/test_sel4.py
```

---

# QED Script — LAW_013 … LAW_022

Added with the QED Script runtime (see [QED_SCRIPT.md](QED_SCRIPT.md), [SCRIPT_SECURITY.md](SCRIPT_SECURITY.md)).
`LAW_001..012` are unchanged; nothing below weakens them. **Evidence for LAW_001..012 does not extend to the new PD**:
each new law lists only evidence produced for the new code.

Legend (stricter than above, because several kinds of "checked" exist):
* **KANI-PROVEN (fn)** — Kani proved the harness for *all* values of its symbolic inputs; the claim covers exactly that function/model, not the whole runtime.
* **KANI-BOUNDED** — Kani proof under stated size bounds on arrays/strings.
* **SMT-PROVEN (model)** — Z3 `unsat` on a hand-written model of the code; the model→code link is by inspection, not mechanised.
* **AUDITED (static)** — mechanical check of the Microkit system description (`scripts/check-script-caps.py`, `scripts/check-caps.py`); it checks the *declared* capability graph, not the kernel.
* **TESTED** — automated tests (unit, fuzz, hostile-module, QEMU end-to-end). Tests show absence of the failures tried, nothing more.
* **ARGUED** — by construction/code inspection only.

| Law | One-line spec | Strongest evidence today | Not covered |
|---|---|---|---|
| `LAW_013` memory isolation | every guest/host access lies in `[0, len(mem))`, no wrap | **KANI-PROVEN** `checked_range_sound`; **KANI-BOUNDED** `memory_access_never_panics`; **SMT-PROVEN** `range_sound.smt2`; **TESTED** 60 000-program canary fuzz | no whole-interpreter proof that *every* access uses `checked_range` (ARGUED) |
| `LAW_014` capability non-escalation | guest cannot obtain/forge/transfer seL4 caps | **AUDITED** script_pd = 2 regions + 2 channels, no irq/ioport/child/VM (9/9 mutants detected); **TESTED** hostile imports refused | authority of a *fully compromised* script_pd is bounded by the audit, not proven by it |
| `LAW_015` host-API confinement | only allow-listed, imported, signature-matching host functions are callable | **KANI-PROVEN** `resolver_is_confined_to_allowlist` (for a one-API policy); **TESTED** 7 hostile-import modules | proof is for one fixed policy; per-call re-check (`Ctx::call`) is TESTED only |
| `LAW_016` resource boundedness | memory/stack/fuel/IO/host-calls ≤ signed limits ≤ platform ceilings | **TESTED** (exact fuel accounting, ceilings, 8 hostile limit cases, QEMU) | no Kani/SMT proof for fuel, stack or response caps |
| `LAW_017` termination control | over-limit runs are aborted without hurting other PDs | **TESTED** on host (fuel + wall clock) and seL4/QEMU (fuel; `/health` served during runaway; script_pd crash-injection) | **no hard wall-clock bound on seL4** (no timer client); no restart of a dead script_pd; no MCS budget proof |
| `LAW_018` key non-disclosure | script cannot read TLS key / other secrets | **AUDITED** `tls_keystore` mapped only in `tls_pd`; ELF/image scan finds key only in `tls_pd` | no information-flow proof; side channels excluded (below) |
| `LAW_019` request-state isolation | no guest-visible memory survives between requests | **TESTED** host + seL4 (memory scrubbed on create and drop, output zeroed) | PD-private C buffers retain the last request outside guest view; no proof |
| `LAW_020` signed-script enforcement | unsigned/modified bundles never run | **TESTED** exhaustive single-byte flips of policy+wasm, sig flips, wrong key, domain separation, QEMU boot (`verified=5 rejected=0`) | Ed25519/SHA-512 not formally verified; no anti-rollback; dev key committed |
| `LAW_021` storage access control | KV access needs authenticated principal + policy prefix; namespaces disjoint | **KANI-BOUNDED** 3 harnesses; **SMT-PROVEN (bounded layout)**; **TESTED** exhaustive small-alphabet injectivity | **no authentication yet** (principal always 0 on seL4 ⇒ KV always denied); **no Storage PD yet** — KV lives inside `script_pd` |
| `LAW_022` backend-network isolation | script cannot open connections | **AUDITED** no channel/region to `tcp_pd`/`connector_pd`; **TESTED** `tcp_connect`/`env` imports refused; static grep | scripts have *no* outbound path at all in this version (stronger than the law requires) |

Reproduce everything (offline-capable except the seL4 build, which needs the toolchain described in QED_SCRIPT.md):
```sh
scripts/qs-ws.sh test                                   # Rust unit/fuzz tests of all pure crates (incl. pg-ipc, pg-script-proofcheck)
python3 tests/test_script.py && python3 tests/test_script_security.py
cargo kani -p pg-script -p pg-script-policy -p pg-ipc -p pg-script-proofcheck   # 7 + 3 + 14 + 3 harnesses
for f in proofs/smt/*.smt2; do z3 $f; done                                    # unsat, sat(control), unsat
python3 scripts/capgraph.py --dir build/sel4-script --selftest                # 20/20 weakened models detected
python3 scripts/viper-capability.py build/sel4-script                        # Silicon+Z3 obligations, 13/13 PDs
sh scripts/check-laws.sh                                # static checks incl. QED Script
tests/ipc/run.sh                                        # ASan/UBSan adversarial IPC harnesses
python3 tests/test_wasm_differential.py --cases 1000000 --jobs $(nproc)       # differential fuzz vs V8
python3 tests/test_wasm_regress.py                       # regression corpus of bugs the fuzzer found
python3 tests/test_script_sel4.py                       # builds QEDOS_SCRIPT=1 image, boots QEMU, 11 end-to-end tests
```

## LAW_013 — MEMORY ISOLATION
1. **Definition.** A script can read or write only bytes of its own linear memory (a fixed-size region chosen at instantiation).
2. **Spec.** Let `L` = memory length, `b,o,s ∈ u32` base, static offset, access size. Access is performed iff `(b + o + s) ≤ L` evaluated in ℕ (not mod 2³²). Memory never changes length (`memory.grow` is rejected at load).
3. **Code.** `crates/pg-script/src/wasm.rs`: `checked_range`, `Memory::{load,store,range,slice,slice_mut}`; all guest accesses and all host-function pointer arguments go through them.
4. **Method.** Kani `checked_range_sound` (all `u32`/`usize`, loop-free ⇒ unbounded in value); Kani `memory_access_never_panics` (8-byte memory, all addresses); Z3 `proofs/smt/range_sound.smt2` (+ control `range_naive_unsound.smt2` shows the 32-bit formula is unsound, so the 64-bit form is necessary); unit test over boundary values; `fuzz_random_programs_stay_confined` runs 60 000 random programs with 0xA5 guard bands above and below the memory.
5. **Commands.** `cargo kani -p pg-script`; `z3 proofs/smt/range_sound.smt2`; `scripts/qs-ws.sh test -p pg-script`.
6. **Result (2026-10-22).** Kani `4/4` harnesses verified (cover checks satisfied ⇒ not vacuous), `build/kani/pg-script.log`; Z3 `unsat` / control `sat`; fuzz: guard bands intact in every run.
7. **Assumptions.** Rust semantics/compiler, `panic=abort`; the PD's address space gives the interpreter's own data no overlap with `wasm_mem`.
8. **Not verified.** That no other interpreter code path touches `Memory.bytes` (ARGUED: the field is `pub(crate)` only for proof harnesses; the interpreter is `forbid(unsafe_code)`). No proof that the interpreter is free of arithmetic-overflow panics (fuzzed only; a panic parks `script_pd`, it does not break memory isolation). Wasm validation is a custom subset validator, not the full spec validator.

## LAW_014 — CAPABILITY NON-ESCALATION
1. **Definition.** Nothing a script does can obtain, forge, create or hand over seL4 capabilities.
2. **Spec.** (a) The guest instruction set contains no system-call instruction and the host API (`Api`, 8 functions) takes only integers and linear-memory ranges; (b) the capabilities of `script_pd` are exactly those Microkit derives from its SDF entry: its own image, `shm_policy_script` (rw), `shm_script_http` (rw), two channels (policy_pd, http_pd).
3. **Code.** `crates/pg-script-policy/src/lib.rs` (`Api`), `sel4/meta_proofgate.py` (QEDOS_SCRIPT branch), `sel4/script/script.fragment.xml`, `scripts/check-script-caps.py`, `scripts/check-caps.py`.
4. **Method.** AUDITED: exact-equality checks on maps, channels, IRQ/ioport/child-PD/VM, priority; fragment ↔ `meta_proofgate.py` mirror check; 9 deliberately weakened systems must each be rejected; Microkit `--viper-output` emits `script_pd.vpr`, and `check-caps.py` applies the existing "no IRQ/ioport/TCB cap" checks to it.
5. **Commands.** `python3 scripts/check-script-caps.py --selftest`; `python3 scripts/check-script-caps.py build/sel4-script/proofgate.system`; `QEDOS_SEL4_DIR=build/sel4-script python3 scripts/check-caps.py`.
6. **Result.** Superseded by `scripts/capgraph.py` (checks against the *generated CapDL authority*, not just the SDF): selftest `20/20` mutants detected including a `supervisor_pd`-aware set; real generated system `CAPGRAPH PASS` (checks A1-A7, C1-C8, see `docs/CAPABILITY_AUDIT.md`); Z3 Datalog re-derivation (C8) independently confirms no path to a secret region or hardware authority.
7. **Assumptions.** Microkit tool + CapDL initialiser realise the SDF faithfully; seL4 kernel enforces capabilities (x86_64 proof status: see SECURITY.md caveat).
8. **Not verified.** `scripts/viper-capability.py` now DOES run Silicon+Z3 against the exported `.vpr` predicates for all 13 PDs (see `docs/HARDENING_RESULTS.md`); this still checks the exported predicates against the SDF, not the kernel's enforcement of them. No proof that `script_pd.c` / the C-ABI Rust shim are memory-safe (mitigated by `#![forbid(unsafe_code)]` Rust + ASan host testing of the C glue, `docs/IPC_VERIFICATION.md`). If the interpreter were exploited, the attacker would hold exactly the audited authority.

## LAW_015 — HOST API CONFINEMENT
1. **Definition.** A guest can invoke only host functions that its signed policy allows, that it declares as imports, and whose signature matches.
2. **Spec.** `link(module,name,type) = Some(id)  ⇒  module="qs" ∧ name = Api(id).name ∧ policy.allows(Api(id)) ∧ type = Api(id).signature`. Call dispatch uses only ids produced by `link`; `Ctx::call` re-checks `policy.allows`.
3. **Code.** `crates/pg-script/src/host.rs` (`resolver`, `Ctx::call`), `wasm.rs` (`Instance::new`, `CALL`), `pg-script-verify::load` (refuses unresolved imports before any execution).
4. **Method.** Kani `resolver_is_confined_to_allowlist`; 7 hostile-import modules (`env.system`, WASI `fd_write`, `sel4_cap_copy`, `tcp_connect`, `tls_key_read`, wrong arity, un-allowed `kv_get`, …) must be rejected at load.
5. **Commands.** `cargo kani -p pg-script`; `python3 tests/test_script_security.py`.
6. **Result.** Kani verified; all import cases `rejected at load`, nothing executed.
7. **Assumptions.** The 8-entry `Api` table is the complete list of host capabilities (reviewed + grep-checked by `check-laws.sh`).
8. **Not verified.** The proof uses a policy that allows only `resp_write`; generalisation over all policies is by symmetry, not mechanised. The `Ctx::call` re-check and "`link[idx]` is always in range" are tested/argued only.

## LAW_016 — RESOURCE BOUNDEDNESS
1. **Definition.** Memory, call depth, value stack, fuel, request/response bytes and host calls never exceed the signed limits, which never exceed platform ceilings.
2. **Spec.** For every execution: `|mem| ≤ max_memory_bytes ≤ 1 MiB`, `fuel_used ≤ max_fuel ≤ 5·10⁷`, `frames ≤ min(max_stack_depth,16)`, `sp ≤ 1024`, `request ≤ max_request_bytes ≤ 64 KiB`, `response ≤ max_response_bytes ≤ 64 KiB (16 KiB in the appliance)`, `host_calls ≤ max_host_calls ≤ 4096`.
3. **Code.** `pg-script-policy::{Policy::parse, CEIL_*}`, `wasm.rs` (`burn`, `enter`, `push`), `host.rs` (`execute`, `RespWrite`).
4. **Method.** TESTED: ceilings for each key, exact fuel accounting (`fuel_is_exact_and_bounds_infinite_loops`), recursion/stack/ memory-declaration/huge-memory/output-overflow/host-flood hostile modules, fuzz asserts `fuel_used ≤ max_fuel`.
5. **Commands.** `scripts/qs-ws.sh test -p pg-script -p pg-script-policy`; `python3 tests/test_script_security.py`.
6. **Result.** all pass (see SCRIPT_RESULTS.md).
7. **Assumptions.** Platform ceilings are the intended trust limits; CPU time per fuel unit is not specified.
8. **Not verified.** No Kani/SMT proof of any of these bounds. CPU, memory and KV quotas *across* scripts are only partially enforced (KV namespace quota; single in-flight script request; 4 TLS slots).

## LAW_017 — TERMINATION CONTROL
1. **Definition.** A script that exceeds limits or misbehaves is stopped, the client gets a generic error, and no other PD loses availability.
2. **Spec.** Every exit path of `execute` returns one of {200 script result, 413, 500, 502, 503} with a fixed generic body for non-200; script_pd runs at the lowest application priority, has one request in flight, and a stalled/crashed script_pd only causes script requests to be refused with 503.
3. **Code.** `host.rs` (`execute`, `fail`), `sel4/pds/script_pd.c`, `policy_pd.c` (busy gate), `meta_proofgate.py` (priority 92).
4. **Method.** TESTED: host (fuel, wall-clock via `Clock`), seL4/QEMU SCRIPT_007 (runaway loop → 503), SCRIPT_008 (`/health` served in 0.09 s while it runs), SCRIPT_009 (script_pd deliberately faulted via a test-only build flag: TLS handshakes, `/health`, proxying continue; later `/script/*` requests get 503).
5. **Commands.** `python3 tests/test_script_sel4.py`.
6. **Result.** 11/11 on QEMU TCG (added SCRIPT_010 wall-clock watchdog, SCRIPT_011 crash-loop fail-closed).
7. **Assumptions.** seL4 priority scheduling; Microkit fault handling delivers the fault to the parent PD.
8. **Now implemented: `supervisor_pd`** (parent of `script_pd`, holds its TCB capability) — a wall-clock watchdog
   (`pg_ipc::Watchdog`, Kani-proven over its full input domain) restarts `script_pd` when a request outruns a
   configured timeout independent of fuel, and on any fault; a burst of restarts inside a window makes the
   supervisor fail closed (leave `script_pd` stopped) rather than loop forever. `max_exec_us` is still enforced
   only on the host runtime, not inside `script_pd` itself on seL4 — the backstop is the external watchdog, not an
   in-PD timer. Restart re-establishes all of `script_pd`'s state from `init()` (data/bss are not reloaded by a
   Microkit restart) and discards the in-flight request; this is TESTED (SCRIPT_009/010/011), not proven.

## LAW_018 — KEY NON-DISCLOSURE
1. **Definition.** No script-observable output depends on the TLS private key or on other PDs' private state.
2. **Spec (non-interference sketch).** Observation = bytes/status the script can receive (its request fields, KV values it is allowed to read, results of its own computation) and bytes it can emit (HTTP response). For two system states that differ only in `tls_keystore`, tcp/tls/http/connector private memory, those observations are equal. Realised by: `tls_keystore` mapped only in `tls_pd` (r); `script_pd` maps nothing else; error bodies are fixed strings; diagnostics (reason code only) go to the operator debug serial.
3. **Code.** `meta_proofgate.py`, `scripts/check-caps.py`, `scripts/check-script-caps.py`, `host.rs::fail`, `script_pd.c`.
4. **Method.** AUDITED (map equality; image/ELF scan for PEM key outside `tls_pd` incl. `script_pd.elf`); TESTED (error bodies exactly `{"error":"script error"}`, no internal text; secret-marker never echoed).
5. **Commands.** `QEDOS_SEL4_DIR=build/sel4-script python3 scripts/check-caps.py`; `python3 tests/test_script_security.py`.
6. **Result.** PASS (key found once, in `tls_pd`).
7. **Assumptions.** seL4 memory isolation; debug serial is an operator channel (a production image must not expose it to scripts' clients).
8. **Not verified / excluded.** No mechanised non-interference proof. **Excluded channels:** execution-time and response-latency differences (fuel use is observable via latency), CPU-cache / TLB / branch-predictor and other microarchitectural channels, memory-bandwidth contention, interrupt timing, response length of non-error paths, the debug serial console, physical attacks.

## LAW_019 — REQUEST STATE ISOLATION
1. **Definition.** Guest-visible memory contents of one request never reach another request.
2. **Spec.** For consecutive requests r₁, r₂ using the same buffers: at `Instance::new` all `|module memory|` bytes are zero except data segments from the signed module; on `Drop` all bytes are zeroed; the response buffer is zeroed at start of `execute` and again on failure. Locals/stack/control stacks are fresh arrays per instance. Only the KV store persists, under LAW_021.
3. **Code.** `wasm.rs` (`Instance::new`, `Drop`), `host.rs` (`execute`, `fail`).
4. **Method.** TESTED: `no_state_survives_between_requests`, hostile `memory_residue_reader`/`sel4_leak` (secret in request 1, request 2 reads memory — host with `--repeat 3`, and seL4 SCRIPT_007), concurrent-execution test with per-thread buffers.
5. **Commands.** `scripts/qs-ws.sh test -p pg-script`; `python3 tests/test_script_sel4.py`.
6. **Result.** pass.
7. **Assumptions.** Zeroing is not optimised away (plain stores through `&mut [u8]` in safe Rust; not volatile — **a compiler could in principle elide the final scrub**, but the *start-of-request* zeroing is what the guarantee relies on).
8. **Not verified.** No Kani proof (scrub loops are long). `script_pd.c` keeps `req_body`/`resp_body` copies in PD-private BSS until overwritten (not guest-visible, but not scrubbed). Interpreter stacks hold stale values inside the instance, which is dropped. No claim about side channels.

## LAW_020 — SIGNED SCRIPT ENFORCEMENT
1. **Definition.** Only a bundle whose Ed25519 signature (pinned code-signing key) covers its exact Wasm bytes, policy, runtime and proof digest is ever instantiated.
2. **Spec.** `load(w,p,σ,π,K)` returns a `VerifiedScript` only if `Verify(K, DOMAIN‖len(rt)‖rt‖len(p)‖p‖SHA512(w)‖SHA512(π|ε), σ)`; then policy parse, module parse, import/allow cross-check, memory ≤ policy, proof envelope check all succeed. Verification precedes parsing of any untrusted byte. `K ≠ pg_config::PUBLIC_KEY` (configuration key), and `DOMAIN` separates the message spaces.
3. **Code.** `crates/pg-script-verify/src/{lib,bundles,proof}.rs`, `config/keys/qs-code-signing-*`.
4. **Method.** TESTED: flip every single byte of policy and wasm (513 cases: 348 policy bytes + 165 wasm bytes of `examples/hello`) ⇒ all rejected; flip every signature nibble; wrong key; config-style message; bad signature precedes module parse; bundle table drops tampered entries and duplicates; seL4 boot shows `verified=5 rejected=0`.
5. **Commands.** `scripts/qs-ws.sh test -p pg-script-verify`; `python3 tests/test_script_security.py`.
6. **Result.** pass.
7. **Assumptions.** The pure-Rust Ed25519/SHA-512 in `pg-config` is correct (unit-tested, **not formally verified**); the signing seed is secret.
8. **Not verified.** No Kani harness for the new `load`. **The development signing seed is committed to the repository** (`config/keys/qs-code-signing-seed.hex`) — a production deployment must replace the pinned key. No anti-rollback (the version is signed but not compared with stored state). Which bundles are in an image is decided at image-build time.

## LAW_021 — STORAGE ACCESS CONTROL
1. **Definition.** A script can read/write only keys inside its own (principal, module) namespace and only under prefixes granted in its signed policy; anonymous requests get no storage access.
2. **Spec.** `authorize(policy, principal, op, key) = Ok ⇔ principal ≠ 0 ∧ key ∈ [a-z0-9._/-]{1,32} ∧ ∃ prefix ∈ policy.grants(op). prefix ⊑ key`. Storage key = `principal(4,BE) ‖ module_id ‖ 0x00 ‖ key`, injective in (principal, module, key). Per-namespace quota 8 entries, 32 total, values ≤ 128 bytes. The script supplies neither principal nor namespace.
3. **Code.** `pg-script-policy/src/lib.rs` (`kv_authorize`, `namespaced_key`, `Kv`), `host.rs` (`Api::Kv*`).
4. **Method.** KANI-BOUNDED `anonymous_never_authorized` (keys ≤ 8 B), `authorized_key_has_granted_prefix` (≤ 6 B, cover satisfied), `namespaced_key_injective_in_principal_and_key` (keys ≤ 3 B); SMT `kv_key_injective.smt2` (fixed 3-byte layout); exhaustive Rust test over all modules/keys of length ≤ 3 on a 3-letter alphabet; unit tests for cross-principal/cross-module/quota; CLI tests (`--principal`).
5. **Commands.** `cargo kani -p pg-script-policy`; `z3 proofs/smt/kv_key_injective.smt2`; `python3 tests/test_script.py`.
6. **Result.** Kani `3/3` verified, Z3 `unsat`, tests pass.
7. **Assumptions.** `principal` comes from a trusted authentication context.
8. **Not implemented / not verified.** **There is no authentication in QEDOS yet: the appliance always passes `principal = 0`, so every KV call is denied on seL4.** **The KV store is not a separate Storage PD** — it is a static object inside `script_pd`; a script-PD compromise exposes it. No persistence, transactions, or encryption. Bounds for the Kani harnesses are small; the general-length statement is not proven.

## LAW_022 — BACKEND NETWORK ISOLATION
1. **Definition.** A script cannot create or use any network connection.
2. **Spec.** No host function performs I/O other than the response buffer and KV; `script_pd` has no channel or shared memory to `tcp_pd`, `connector_pd` or any driver; `policy_pd` forwards to backends only via the signed fixed table, and script routes never reach that code path.
3. **Code.** As LAW_014; `policy_pd.c` (script dispatch happens *before* and instead of `Forward`).
4. **Method.** AUDITED (peers of `script_pd` = {policy_pd, http_pd}; no net regions); `check-laws.sh` greps the QED Script TCB for socket/fs/process APIs; hostile `tcp_connect` import refused.
5. **Commands.** `python3 scripts/check-script-caps.py --selftest`; `sh scripts/check-laws.sh`.
6. **Result.** PASS.
7. **Assumptions.** As LAW_014.
8. **Not verified.** Indirect influence through `http_pd`/`policy_pd` protocols is not modelled; no formal reachability proof beyond the declared graph.
