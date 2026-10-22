# QED Script — threat model, attack tests, residual attack surface

## 1. Attacker model
**Attacker controls:** the bytes of any Wasm module that has a valid signature (a compromised or careless signer, or a signed-but-buggy script), plus every field of the HTTP requests sent to it (path, query, body).
**Attacker does not control:** the signing key, the image build, the Microkit system description, other PDs' code, the host hardware.
**Goal examined:** read/write outside the module's memory; reach TLS key material; call anything beyond the allow-list; open connections; escalate seL4 authority; persist state across requests or users; exhaust CPU/memory so that other traffic (TLS, proxying) fails; learn internals from error messages.
**Out of scope / excluded:** hardware and microarchitectural side channels (cache, TLB, branch predictors, timing of fuel use), speculative execution, DMA by devices, physical access, kernel bugs, compiler bugs, bugs in OpenSSL/lwIP, denial of service by network flooding outside the script route, supply-chain compromise of the build.
Unsigned code is not part of the attacker model *because* LAW_020 refuses it; for signed code we assume nothing about intent.

## 2. Defence layers (each independent of the one above it)
1. **Admission:** Ed25519 over wasm+policy+runtime+proof digest; strict policy; import cross-check; static validator (opcode whitelist, nesting, indices) — `pg-script-verify`, `pg-script::Module::parse`.
2. **Interpreter sandbox:** safe Rust, no heap, bounds-checked memory (`checked_range`), fuel, frame/value-stack limits, host-call budget, clock polling.
3. **Host API:** 8 functions, integer args only, pointer ranges re-validated, policy re-checked per call.
4. **Process boundary:** `script_pd` has only two shared regions and two channels; lowest priority; one request in flight; nothing else is mapped (audited).
5. **Fail-safe responses:** generic `{"error":"script error"}`; reason codes only to the debug serial.
If layers 1–3 had a bug and the attacker got code execution inside `script_pd`, layer 4 limits them to: that PD's memory, the request/response regions it already shares, and signalling `policy_pd`/`http_pd`. They could then send malformed data to those two PDs (which parse it with the same bounded code as any input — not formally analysed for this adversarial *peer* case) and could poison/starve script responses.

## 3. Attack tests (all local; nothing external is contacted)
`tests/test_script_security.py` (151 checks) runs 36 hostile modules, each **validly signed**, plus tamper cases. For each module it asserts: refused or contained with the expected status/reason; the runner survives; no secret in output; a following benign request (`hello`) still works.

| Required attack | Module / test | Observed result |
|---|---|---|
| infinite loop | `infinite_loop`, `sel4_spin`, `timeout_by_clock` | 503 `OutOfFuel` / `Timeout`; seL4: `/health` answered in 0.09 s during run |
| out-of-bounds access | `oob_load`, `oob_load_edge`, `oob_offset_wrap`, `oob_neg_index` (incl. `base+offset` 32-bit wrap) | 500 `OutOfBounds` |
| huge memory request | `huge_memory_decl` (17 pages), `memory_over_policy`, `memory_grow` | refused at load (`MemoryTooLarge`, `MemoryExceedsPolicy`, `UnsupportedOpcode`) |
| stack exhaustion | `call_recursion`, `value_stack_overflow` | 500 `CallDepth` / `ValueStackOverflow` |
| integer overflow | `div_overflow` (MIN/-1), `div_zero`, `wrapping_add_ok` | traps as Wasm specifies; wrap-around add is legal and returns |
| malformed Wasm | `bad_magic`, `truncated`, `garbage`, `section_start_fn`, `float_opcode`; 60 000 mutated binaries (fuzz) | refused at load; loader never panicked |
| unauthorised import | `import_kv_not_allowed`, `import_env_system`, `import_wasi_fd_write`, `import_wrong_arity` | refused at load (`UnsupportedImport`) |
| signature tamper | flipped sig nibbles (128), wrong key, missing/short sig | `BadSignature` / `BadSignatureEncoding` |
| policy tamper | every single-byte flip of the signed policy, raised fuel limit, added allowed API, version bump | `BadSignature` |
| module tamper | every single-byte flip of `app.wasm` | `BadSignature` |
| TLS key access attempt | `import_tls_key_read`; out-of-bounds sweeps; guard-band fuzz; ELF/image scan | refused / no write outside memory / key present only in `tls_pd` |
| illegal capability use | `import_sel4_cap_copy`; capability audit with 9 weakened systems | refused; every weakened system detected |
| unauthorised backend connection | `import_tcp_connect` | refused at load; `script_pd` has no net path (audit) |
| cross-request leak | `memory_residue_reader`, `sel4_leak` (secret in request 1, probe in request 2), `no_state_survives_between_requests` | probe sees zeros |
| concurrent access | `concurrent_requests_do_not_interfere` (8 threads × 200 requests, own buffers); seL4: single in-flight request by design | outputs always correct; no interference |
| output overflow | `output_overflow` | 502, generic body, partial output discarded |
| host-API flood | `host_call_flood` | 503 `HostCallLimit` |
| state after termination | memory scrubbed on drop; later requests start zeroed (tests above); seL4 SCRIPT_009 after `script_pd` crash | no residue visible; others unaffected |
| KV abuse | `kv_cross_prefix`, `kv_anonymous`, cross-principal/module unit tests | denied (-1), no data returned |
| fuzzing | `fuzz_random_programs_stay_confined` (60 000 random instruction streams), `fuzz_mutated_binaries_never_panic` (60 000 mutations) | 0 panics, guard bands intact, fuel never exceeded |

Per-test checks required by the task: (1) rejected ✔, (2) protected PD not compromised — shown by the capability audit and by SCRIPT_009 crash injection, not by exploiting attempts against the kernel ✔, (3) no secret in output ✔, (4) other requests continue ✔ (every case re-runs `hello`; SCRIPT_007–009 on seL4), (5) no sensitive data in logs — the only log line a script can trigger is `SCRIPT_PD: request ended with reason code N`; it contains no request or key material. *This was checked by reading the C code and by grepping the recorded serial logs for the test secret, not by a systematic log-leak test.*

## 4. Error handling and secrecy
`execute` maps every failure to {413, 500, 502, 503} with the constant body `{"error":"script error"}`; the precise `Reason` (trap kind) is returned to the PD glue only, which prints a numeric code on the debug serial. `fail()` zeroes the entire response buffer first so a partially written response cannot leak.

## 5. Residual attack surface (what an adversary can still try)
* **Interpreter correctness bugs** (spec deviations, arithmetic panics): fuzzed, partly proved for memory addressing; a panic parks `script_pd` (DoS of scripts, not of proxying).
* **Dead `script_pd` is not restarted:** after a fault or panic every `/script/*` request is shed with 503 until reboot. Proxy/TLS continue (tested).
* **No wall-clock bound on seL4:** a script can use up to `max_fuel` instructions (≤ 5·10⁷ ≈ seconds under TCG, less on hardware) at the lowest priority; it cannot starve higher-priority PDs, but it does occupy `script_pd` and delays other script requests (single in-flight). Because `policy_pd` sheds rather than queues, a flood of slow script requests can deny the script service to everyone.
* **Network-level DoS** of the TLS front end is unchanged from the base system (`PG_MAX_CONNS = 4` slots).
* **Side channels:** timing/microarchitectural leakage between `script_pd` and `tls_pd` is not analysed (same core, shared caches).
* **KV in `script_pd`:** no authentication, so unusable on seL4; once authentication exists, the store should move to its own PD.
* **Signer risk:** a malicious signed module is contained by the sandbox, not rejected. The committed development seed must be rotated for any real use; there is no revocation list or anti-rollback.
* **Peer-PD attack from a compromised `script_pd`** (malformed shared-memory contents to `http_pd`/`policy_pd`): the receivers clamp lengths (`PG_SCRIPT_BODY_MAX`, slot index < `PG_MAX_CONNS`), but this interface was not fuzzed or verified.
* **Debug configuration:** the image is a Microkit *debug* build with serial output; production hardening is out of scope.
* **Kernel assurance on x86_64:** see `docs/SECURITY.md`.

## 6. Why the isolation claims are not "proofs of safety"
Kani proofs cover single functions (`checked_range`, the linker, KV authorisation) under stated bounds. The capability claims are an audit of the declared Microkit graph, not a machine-checked proof of the running system. Where a statement is only tested, `LAWS.md` says TESTED.
