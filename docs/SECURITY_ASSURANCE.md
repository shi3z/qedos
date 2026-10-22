# Security assurance levels

Evidence levels used throughout this repository (same five used in `README.md`):

* **PROVEN** — formally proven under stated assumptions: a named prover, a precise target property, the
  assumptions/bounds, a run record, and the commit it was run against.
* **BOUNDED** — model-checked over a finite range (Kani/CBMC with a stated input-length or unwind bound). A
  BOUNDED result is never described as a general proof.
* **TESTED** — confirmed by running real code (unit tests, fuzzing, differential testing, QEMU integration).
* **DESIGNED** — a specific mechanism exists for this property but has not been independently checked.
* **UNVERIFIED** — no check beyond code review.

This file is the authoritative index; `docs/LAWS.md` carries the per-LAW detail (code pointers, exact harness
names, commands to reproduce). Numbers below are from commit `17c9517` plus the hardening work landed in this
session (capability-graph verifier, IPC fixes, Wasm interpreter extension + differential fuzzing, `supervisor_pd`,
the independent proof checker); re-run the commands to reproduce on top of your own checkout.

## Properties A–H (Attacker B: full native-code compromise of `script_pd`)

| | Property | Level | Evidence |
|---|---|---|---|
| A | Capability confinement | **BOUNDED** (structural) | `scripts/capgraph.py` discharges checks A1–C8 against the *generated* CapDL authority (every CNode slot, object, right, badge) for all 13 PDs; 20/20 deliberately weakened models are caught (`--selftest`). This proves properties of the **extracted model**, cross-checked against the real artifacts (A-series checks); it does not re-derive the model from the seL4 kernel's own semantics. |
| B | Memory isolation (other PDs' private memory) | **BOUNDED** (A3/C1/C5) + **TESTED** | No PD CSpace holds a Frame/PageTable/TCB/Untyped capability other than its own VSpace root (A3); `script_pd` maps exactly `shm_policy_script`/`shm_script_http` and nothing else (C1/C5). Adversarial ASan/UBSan harnesses (`tests/ipc/*`) run the *real* `http_pd.c`/`policy_pd.c`/`connector_pd.c` against a hand-written hostile peer and found two real races before this session's fixes (see `docs/IPC_VERIFICATION.md`). |
| C | IPC integrity | **TESTED** + **BOUNDED** | `crates/pg-ipc` (request/response correlation, ring arithmetic, header validation) has 14 Kani harnesses over the *entire* input domain of those functions (no length bound: they contain no loops). The C glue that calls them is covered by the ASan harnesses, not by Kani. |
| D | Secret non-disclosure (TLS key) | **BOUNDED** (C1/C8) + **AUDITED** | `tls_keystore` is mapped only in `tls_pd`; Z3 Datalog re-derivation (C8) finds no path from `script_pd` to that region or to any I/O/IRQ authority. No side-channel or timing analysis (explicitly excluded, see `docs/THREAT_MODEL.md`). |
| E | Wasm confinement (guest escapes its own sandbox) | **TESTED** (differential) + **BOUNDED** (Kani on sub-functions) | 1,000,000-case differential run against V8 (`tests/test_wasm_differential.py`, seed 11, 0 disagreements) across four module categories (well-typed, corrupted, re-encoded, forbidden-construct); it found and fixed two real acceptance bugs (non-UTF-8/duplicate export names, malformed custom sections) before this run. `checked_range`, `grow_len`, `eval_num` and the LEB decoders are Kani-proven over their full numeric domain; the interpreter's control-flow/dispatch loop is not Kani-covered (too large to bound; see `docs/WASM_CONFORMANCE.md`). |
| F | Resource isolation (availability) | **TESTED** | QEMU: a runaway script does not delay `/health` (SCRIPT_008); a crashed `script_pd` is restarted by `supervisor_pd` and the pending request fails fast with 504 (SCRIPT_009); a script at the platform fuel ceiling is ended by `supervisor_pd`'s wall-clock watchdog, not by fuel alone (SCRIPT_010); a crash loop makes the supervisor fail closed — `script_pd` stays stopped, every other service keeps working (SCRIPT_011). The watchdog's restart/no-restart decision is Kani-proven (`pg_ipc::Watchdog`, full input domain). |
| G | Proof-carrying script integrity | **TESTED** (unit + fuzz) + **BOUNDED** (Kani on sub-checks) | `crates/pg-script-proofcheck` re-derives `HostApiSubset` and `FuelBounded` from the module/policy bytes (never from the proof payload); unit tests include bit-flip/truncation/wrong-checker-id tampering, all rejected; 200,000-case fuzz of the envelope parser found no panic. Kani proofs cover the checker's building blocks for small fixed shapes (full generality of the branch-depth check is confirmed by a 16-combination exhaustive Rust test instead of Kani, which did not finish within this session's time budget on the wider range — see the harness comment in `crates/pg-script-proofcheck/src/proofs.rs`). **This checker is not yet wired into the runtime's trust decision**: `pg_script_verify::VerifiedScript::proof_accepted()` is still unconditionally `false`; `qs proof-check` reports the checker's verdict for inspection only. |
| H | PQC key-exchange policy preserved | **TESTED** (unchanged) | `SEL4_001-003`/`SCRIPT_006` on the hardened image: TLS 1.3 + X25519MLKEM768 only, `<1.3` and classical groups refused. No change was made to `tls_pd` in this session. |

## The owner's question, answered directly

**"How far can it be mathematically shown that QEDOS protects the TLS private key and the backend's authority,
even if an attacker fully controls script_pd's native code execution?"**

Not as a single end-to-end mathematical proof. What is actually established, with the evidence above:

1. The **access-control structure** script_pd would have to use for any of these attacks is extracted from the
   actually-built system (not the design) and checked against an independently written intended-authority list,
   with a 20/20 mutation self-test (BOUNDED, structural — not a kernel-level proof).
2. The **two shared-memory protocols** script_pd's authority actually lets it touch (`shm_policy_script`,
   `shm_script_http`) have had their correlation/framing logic re-implemented as total, Kani-proven functions, and
   the C call sites exercised under ASan/UBSan with a hostile peer standing in for a compromised script_pd; this
   found and fixed two real defects, not merely ran clean.
3. The **TLS key and signed config** are not reachable from script_pd under this model, including by an
   independent Z3 re-derivation, not just the primary audit path.
4. What is **not** covered: the fidelity of the extracted model to seL4's own enforcement (kernel proof scope is
   not re-derived here), any side channel, the Microkit monitor's own code, and whether the C/Rust glue outside
   `tests/ipc`'s two covered flows is free of the same class of bug (`connector_pd`'s TCP-facing code and `tls_pd`
   were not re-audited this session).

So: for the specific properties that were modelled and checked, the claim holds with BOUNDED/TESTED strength and
has survived adversarial testing designed to break it. It is not a PROVEN, kernel-to-application, end-to-end
result, and this document does not claim it is.
