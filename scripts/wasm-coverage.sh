#!/bin/sh
# Source-level coverage of the Wasm interpreter/validator achieved by the differential corpus.
# usage: scripts/wasm-coverage.sh [cases] [seed]     -> build/fuzz/coverage/{summary.txt,html/}
# Needs: rustup component llvm-tools-preview (llvm-profdata, llvm-cov). Reports SKIPPED otherwise.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
N=${1:-200000}; SEED=${2:-7}
BIN=$(ls -d "$HOME"/.rustup/toolchains/stable-*/lib/rustlib/*/bin 2>/dev/null | head -1)
[ -x "$BIN/llvm-cov" ] && [ -x "$BIN/llvm-profdata" ] || { echo "SKIPPED: llvm-tools-preview not installed"; exit 2; }
OUT=$R/build/fuzz/coverage; mkdir -p "$OUT"
W=$R/build/qs/ws
export RUSTFLAGS="-C instrument-coverage"
CARGO_TARGET_DIR=$OUT/target "$R/scripts/qs-ws.sh" build --release -p pg-script-cli >/dev/null 2>&1
Q=$OUT/target/release/qs
rm -f "$OUT"/*.profraw
"$Q" fuzz-gen "$SEED" 0 "$N" "$OUT/cases.bin"
LLVM_PROFILE_FILE="$OUT/p-%p.profraw" "$Q" diff-run "$OUT/cases.bin" > "$OUT/ours.txt"
"$BIN/llvm-profdata" merge -sparse "$OUT"/*.profraw -o "$OUT/all.profdata"
"$BIN/llvm-cov" report "$Q" -instr-profile="$OUT/all.profdata" \
  --ignore-filename-regex='(/rustc/|\.cargo/|pg-script-cli|pg-script-policy|pg-script-verify|pg-config|tests\.rs)' > "$OUT/summary.txt"
"$BIN/llvm-cov" show "$Q" -instr-profile="$OUT/all.profdata" --format=html -output-dir="$OUT/html" \
  --ignore-filename-regex='(/rustc/|\.cargo/|pg-script-cli|pg-script-policy|pg-script-verify|pg-config|tests\.rs)' >/dev/null
cat "$OUT/summary.txt"
