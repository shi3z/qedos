# Wasm interpreter conformance

QED Script implements a **subset** of WebAssembly 1.0 plus sign-extension ops and bulk-memory `memory.copy`/
`memory.fill`: i32/i64 values, one linear memory (growable to a hard 16-page cap), one funcref table,
structured control including `br_table` and `call_indirect`. No floats, SIMD, atomics, reference types,
multi-value, tail calls, or passive segments — those are rejected at load time, not at run time.

## Differential testing against V8

`tests/test_wasm_differential.py` generates four categories of module from a typed AST generator
(`crates/pg-script-cli/src/fuzzgen.rs`): **VALID** (well-typed, terminating programs covering i32/i64 arithmetic,
memory, globals, calls, `call_indirect`, `br_table`, loops, `memory.grow`, bulk ops), **CORRUPT** (byte-level
mutations of a valid module), **PADDED** (semantics-preserving re-encodings: non-minimal LEB sizes, interleaved
custom sections) and **FORBIDDEN** (valid WebAssembly outside the subset, spliced into an otherwise-valid module).
Each case runs through both our interpreter (`qs diff-run`) and V8 (`tests/v8_ref.js`, via Node's embedded engine)
and the results — accept/reject, trap kind, final linear memory hash, final global values — must agree (with the
documented, narrow exceptions below).

**Recorded run** (`build/fuzz/diff-11.json`, seed 11, commit `17c9517` + this session's checker work):
**1,000,000 cases, 0 disagreements**, in 45s on 24 cores. Category split and outcome split are in the JSON.
Smaller recorded runs at other seeds are in `build/fuzz/diff-*.json`.

**Found and fixed by this run** (before the recorded 0-disagreement run): the loader accepted non-UTF-8 import/
export names, duplicate export names, and malformed/empty custom sections — three real acceptance bugs, now
rejected (`crates/pg-script/src/wasm.rs`, `LoadError::BadName`). `tests/wasm-corpus/reject/*.wasm` is a permanent
regression corpus of the modules that triggered them; `tests/test_wasm_regress.py` checks they stay rejected.

## Coverage of the differential corpus (not sufficiency — see caveat below)

`scripts/wasm-coverage.sh` (needs `rustup component add llvm-tools-preview`) instruments `qs diff-run` with
`-C instrument-coverage` and reports `llvm-cov` line/region coverage restricted to `pg-script`'s interpreter files.
At 200,000 generated cases: `validate.rs` 93% region / 98% line, `ops.rs` 100%/99.6%, `wasm.rs` 85%/85% (most of the
remainder is public accessor methods used only by the proof checker/tooling, not interpreter control flow).
**A high coverage number is not a completeness argument**: the generator can still systematically avoid some
input shapes; coverage says which lines ran, not which semantics were checked against the reference.

## What is Kani-proven instead of differentially tested

`checked_range`, `grow_len`, `eval_num` (the pure numeric evaluator, both opcodes and operand widths) and the two
LEB decoders are proven over their *entire* `u32`/`u64` input domain (`crates/pg-script/src/proofs.rs`, no length
bound: these functions contain no loops). The interpreter's dispatch loop and the validator's control-flow pass
are not Kani-covered — they are large, deeply loop-structured functions where a useful Kani bound was not found
to terminate in practical time this session (see the discussion in `crates/pg-script-proofcheck/src/proofs.rs`'s
comments for a concrete instance of the same difficulty in a much smaller function). Their correctness evidence is
the differential run above, not a model-checking proof.

## Limits of this evidence

* The reference is V8's engine, not the official WebAssembly spec test suite; the spec test suite was not run
  against either engine.
* Generated programs are constrained by the generator's grammar; a semantic bug reachable only through a module
  shape the generator cannot produce would not be found.
* "Reject" on the CORRUPT category is accepted as correct whenever V8 also rejects OR our loader rejects first
  (never the reverse for VALID/PADDED categories, where accept-and-agree is required) — see `compare()` in
  `tests/test_wasm_differential.py` for the exact rule and its rationale.
