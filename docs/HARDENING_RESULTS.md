# QEDOS security hardening — results

Baseline commit: `611d36d` (QED Script landed). This session's commits: `7114678` (Phase 1: capability graph),
`3e77d5d`/`a422714`/`17c9517` (Phase 2/4/5: IPC + availability), `c889ad5`/`f825d90` (Phase 3: Wasm interpreter +
differential fuzzing), plus the proof-checker and documentation work in the final commit. Attacker model, scope
and exclusions: `docs/THREAT_MODEL.md`. Per-property assurance levels: `docs/SECURITY_ASSURANCE.md`. Per-LAW
detail: `docs/LAWS.md`.

## 1. Vulnerabilities found, by severity

| id | severity | summary |
|---|---|---|
| IPC-1 | **High** | A compromised or buggy `script_pd`/backend could inject a forged response into another client's TLS stream, or replay one response twice (`http_pd` had no record of which request was actually outstanding) |
| IPC-4 | **High** | Two concurrently forwarded requests could overwrite each other's `shm_policy_conn` entry, corrupting the request `connector_pd` was serving and mis-attributing its response (pre-existing, independent of QED Script) |
| IPC-3 | Medium | A hostile response length could write past unread data in the TLS response ring |
| WASM-1 | Medium | The Wasm loader accepted modules with non-UTF-8 or duplicate import/export names, and malformed/empty custom sections — valid rejects per the spec, found by differential fuzzing against V8 |
| IPC-5 | Medium | Several lengths/indices read from shared memory were not uniformly clamped before sizing a copy or indexing a table (`target_len`, `body_len`, `rx_len`, `num_backends`, `backend_id`) |
| IPC-2 | Low | A late policy-decision notification could be processed after its shared fields were reused, silently losing the in-flight marker |
| CAP-1 | **High (configuration)** | Images are built with Microkit's debug kernel, which exposes capability-free debug syscalls to every PD |

## 2. Vulnerabilities actually fixed

IPC-1 through IPC-5: fixed in `sel4/pds/{http,policy,connector}_pd.c`, with the correlation/ring/header logic moved
into Kani-verified `crates/pg-ipc` functions. WASM-1: fixed in `crates/pg-script/src/wasm.rs`
(`LoadError::BadName`), with a permanent regression corpus (`tests/wasm-corpus/reject/`,
`tests/test_wasm_regress.py`). CAP-1: **not fixed** — see §13.

## 3. Tests and verification tools added

`crates/pg-ipc` (14 Kani harnesses), `crates/pg-script-proofcheck` (3 Kani harnesses + unit/fuzz tests),
`scripts/capgraph.py` (capability-graph verifier over the generated CapDL authority, 20-mutant self-test),
`scripts/viper-capability.py` (runs Silicon+Z3 against the Microkit-exported `.vpr` predicates),
`tests/ipc/{harness_http,harness_policy_conn}.c` (ASan/UBSan adversarial harnesses on the real PD sources),
`tests/test_wasm_differential.py` + `tests/v8_ref.js` + `crates/pg-script-cli/src/fuzzgen.rs` (differential fuzzer
and AST shrinker against V8), `tests/test_wasm_regress.py`, `sel4/pds/supervisor_pd.c` (availability watchdog),
`security/cap-policy.json` (intended-authority specification capgraph checks against).

## 4. Formal verification that succeeded

* Kani, full input domain (no loops in the functions): `pg-ipc` (14/14), `checked_range`/`grow_len`/`eval_num`/LEB
  decoders in `pg-script` (part of its 7/7), `pg-script-proofcheck`'s three harnesses (3/3, one needed its scope
  narrowed from a 4-way to a 2-way sweep to finish in practical CBMC time — see that file's comments).
* Kani, bounded input length: `pg-script-policy` (3/3, keys ≤ 8 B), existing `pg-config`/`pg-http`/`pg-policy`
  harnesses (unchanged).
* Z3: `proofs/smt/*.smt2` (unchanged) plus the capability-graph's independent Datalog re-derivation (`capgraph.py`
  check C8) and `viper-capability.py`'s own obligation encoding, both decided by Z3 through Silicon.
* Viper (Silicon+Z3), **actually run** for the first time this session: per-PD memory/capability/channel
  obligations against the Microkit-exported predicates, all 13 PDs of the script image and 12 of the default
  image, each with a positive check and a negative control that must be refuted (`build/viper-obligations/*/result.json`).

## 5. Preconditions of the formal results

Every PROVEN/BOUNDED claim is qualified in `docs/SECURITY_ASSURANCE.md` and the relevant `docs/LAWS.md` entry with
its prover, exact property, and bound. In short: Kani proofs assume Rust/LLVM semantics and `panic=abort`; Z3/Viper
results are over the *extracted* model (CapDL authority, exported predicates), not a re-derivation from the seL4
kernel's own formal semantics; the differential fuzzer's ground truth is V8, not the official spec test suite.

## 6. Properties not provable (in this session)

The interpreter's dispatch loop and the Wasm validator's control-flow pass were not made Kani-bounded (CBMC did
not converge in practical time on symbolic module bytes of useful size — see `crates/pg-script-proofcheck/src/
proofs.rs` for a smaller instance of the same difficulty, and the note in `docs/WASM_CONFORMANCE.md`). The
Proof-Carrying Script checker is not wired into the runtime's trust decision (§7). Microarchitectural side
channels and the Microkit monitor's own code are out of scope entirely (`docs/THREAT_MODEL.md`).

## 7. What is possible with full native-code control of `script_pd`

Per the extracted and audited authority (`docs/CAPABILITY_AUDIT.md`): signal `policy_pd` and `http_pd`; read/write
`shm_policy_script` and `shm_script_http`; consume CPU and the fuel/memory it was given; cause itself to be
restarted (by hanging or faulting, up to the crash-loop limit, after which the supervisor leaves it stopped). It
cannot reach any secret region, any hardware authority, any other PD's memory, or the network, under this model.

## 8. What was shown impossible under this model

See §7's negative half, and `docs/SECURITY_ASSURANCE.md` Properties A–D, each with its own evidence level — none
claimed as an unconditional proof.

## 9. Wasm-spec mismatches found and fixed

Non-UTF-8 import/export names, duplicate export names, and malformed/empty custom sections were accepted by the
loader; all three are now `LoadError::BadName`. See `docs/WASM_CONFORMANCE.md`.

## 10. QEMU integration results

Default image: `SEL4_001-006`, 6/6 (`build/script/final-default.log`). Script image: `SCRIPT_001-011`, 11/11
(`build/script/final-script.log`), including the three new availability tests (SCRIPT_009/010/011) and the
capability-graph check (SCRIPT_001, now delegated to `capgraph.py`). Both runs are from this session's final build,
commit state as of this document.

## 11. Performance impact

Not re-measured end-to-end this session (see `docs/SCRIPT_RESULTS.md`/`docs/RESULTS.md` for the last recorded
numbers, which predate this session's changes). The interpreter gained i64/globals/tables/bulk-memory support and
a real type-checking validator pass (`crates/pg-script/src/validate.rs`), which is strictly more work per module
load than the previous subset validator; per-instruction execution cost is materially unchanged (same dispatch
loop shape). No QEMU-side latency regression was observed in the SCRIPT_003/008 timings above relative to the
prior recorded runs, but this is an informal observation, not a controlled benchmark.

## 12. TCB composition and size

Unchanged in kind from `docs/QED_SCRIPT.md`/`docs/SECURITY.md`; additions this session: `crates/pg-ipc` (≈250
lines, `forbid(unsafe_code)`, no heap) now sits in the trust path of `http_pd`/`policy_pd`/`connector_pd`/
`supervisor_pd`'s decision logic; `sel4/pds/supervisor_pd.c` is a new PD with TCB-capability authority over
`script_pd` — a new, narrow piece of trusted authority (restart/stop of exactly one PD) that did not exist before.
`crates/pg-script-proofcheck` is NOT in the TCB: its verdict is not yet consulted by the runtime (§7 of
`docs/SECURITY_ASSURANCE.md`'s Property G row).

## 13. Residual risks blocking production use

Debug-kernel image (CAP-1, not fixed — no release-kernel build was produced or tested this session); development
signing key committed to the repository; no anti-rollback; no authentication (KV always denied); Proof-Carrying
Script checker not wired into the trust path; `tcp_pd.c`/`tls_pd.c`'s own shared-memory handling was not
re-audited with the same adversarial-harness method as `http_pd`/`policy_pd`/`connector_pd`; no physical-hardware
run (NIC, DMA/IOMMU, entropy source, secure boot all unverified — `docs/THREAT_MODEL.md`).

## 14. What needs independent third-party audit

The seL4/Microkit kernel configuration actually shipped (x86_64, MCS, debug build) against the upstream proof
scope; the Ed25519/SHA-512 implementation in `pg-config`; `tls_pd.c`'s OpenSSL integration and `tcp_pd.c`'s lwIP
integration (not re-audited this session); the Viper obligation encoding in `scripts/viper-capability.py` itself
(a bug there could make every PD's check vacuously pass); any future wiring of the proof checker into the trust
path, before it is relied upon.

---

**The question this work set out to answer**: how far can it be mathematically shown that QEDOS protects the TLS
private key and the backend's authority even if an attacker fully controls `script_pd`'s native code execution?

See `docs/SECURITY_ASSURANCE.md`'s closing section for the full answer. In short: the capability structure that
would have to exist for such an attack to succeed was extracted from the built system (not the design) and shown,
by two independent methods (a mutation-tested structural audit and a Z3 re-derivation), not to exist; the two
shared-memory protocols script_pd's authority actually reaches were given Kani-proven decision logic and found,
by adversarial testing, to have real defects before this session's fixes, which are now closed and regression-
tested. That is BOUNDED and TESTED evidence of real strength — including that it survived an adversarial search
for counterexamples — not a single end-to-end mathematical proof from the kernel's semantics to the conclusion.
