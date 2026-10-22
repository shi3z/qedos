# QED Script — signatures, proofs, and Proof-Carrying Script design

**Principle:** a signature says *who vouched for these bytes*; a proof says *a property holds for these bytes*; a checker is the only thing allowed to turn a proof into trust. QEDOS today trusts signatures (LAW_020) and a sandbox; it trusts **no** proof, because no checker exists.

## 1. What is implemented
| Piece | Where | State |
|---|---|---|
| Ed25519 code signature bound to wasm+policy(module id, version, limits, APIs)+runtime+proof digest | `pg-script-verify::{signed_message, load}` | implemented, tested |
| Key and domain separation from the configuration signature | `CODE_SIGNING_PUBLIC_KEY`, `DOMAIN` | implemented, tested |
| Static validator (opcode whitelist, structured control, indices) | `pg-script::Module::parse` | implemented (subset; fuzzed) |
| Policy binding (imports ⊆ allow-list, memory ≤ policy) | `pg-script-verify::load` | implemented |
| `app.proof` envelope (`QSPF1`): claim kind, checker id, SHA-512 of wasm and policy, payload | `pg-script-verify::proof` | implemented: parse + binding |
| Proof **checker** | — | **does not exist** |

## 2. Execution-permission policy vs. proof format (kept separate)
* `Admission` (what lets code run) has exactly one variant, `SignedSandboxed`. There is no `ProofChecked` variant to select by accident.
* `VerifiedScript::proof_accepted()` is a constant `false`; `ProofStatus` can be `Absent` or `PresentUnchecked`.
* A present `app.proof` must still be a well-formed envelope **bound to this wasm and policy** (otherwise the bundle is refused, fail-closed), and its SHA-512 is signed. This prevents swapping proofs after signing; it does *not* make the proof true.
* `proof::check` returns only `NoCheckerAvailable`. Strings such as "verified by external tool", or a signature over a proof, are not certificates and are rejected by the envelope parser (`verified by external tool` → `BadProof(TooShort)` in the tests).
* Policy limits (fuel, memory, host calls) stay enforced at run time even for a hypothetically proved script: proofs may later *reduce* what is dynamically checked only by an explicit, reviewed policy change, never implicitly.

## 3. Target pipeline and trust placement
```
Source → Wasm compiler → .wasm → static validator (in TCB, small)
      → proof generator (ANY tool, incl. AI/ATP: UNTRUSTED) → .proof
      → policy binding (hash wasm, hash policy into envelope)
      → signature (vouches for the bundle, not for the proof)
      → QEDOS proof checker (TCB; must be small, independent of the generator) → Script execution
```
Requirements for the future checker (not yet met):
1. Input: `(wasm bytes, policy bytes, claim, certificate)`; output: accept/reject; deterministic; total (no unbounded loops: certificate has an explicit size/step budget).
2. Independent: shares no code with the generator; ≤ a few thousand lines; `forbid(unsafe_code)`; Kani-checked for panic-freedom.
3. Sound against a written semantics: for claim `MemorySafe` it must re-derive, from the Wasm bytes, that every `load/store` is dominated by a check or an invariant the certificate proves; for `FuelBounded(N)` it must validate a ranking/bound certificate; for `HostApiSubset` it must check the import list against the claim.
4. Self-contained certificate formats first (e.g. loop-free / bounded-loop straight-line bounds, interval-domain invariants with explicit witnesses), LCF-style kernel for anything richer.
5. Semantics gap to close: the Wasm subset semantics used by the checker must be the one `pg-script` implements; a mechanised relation between them (or differential testing against a reference engine) is a prerequisite for accepting any claim.

## 4. What a proof could buy (and the order to build it)
1. `FuelBounded(N)` for loop-free modules: run-time fuel accounting stays; the benefit is admission-time rejection of modules that cannot fit their policy.
2. `HostApiSubset`: duplicate of the import check; trivial first checker, proves the pipeline end-to-end.
3. `MemorySafe`: would let a faster engine drop bounds checks. Only worthwhile once a JIT/AOT is on the table — which the project excludes for now.

## 5. Formal-verification status of the new code (summary; details per law in LAWS.md)
* Kani: 7 new harnesses verified (4 in `pg-script`, 3 in `pg-script-policy`); the 13 pre-existing harnesses were re-run and still verify.
* Z3: `range_sound` (unsat), `range_naive_unsound` (sat — control), `kv_key_injective` (unsat, fixed-layout model).
* Viper: Microkit's `--viper-output` is generated for `script_pd` and pattern-checked; **Viper itself was not run** (same as for the existing PDs).
* Not verified at all: Wasm semantics conformance, fuel accounting, Ed25519/SHA-512 implementations, C glue, seL4 kernel on x86_64.
