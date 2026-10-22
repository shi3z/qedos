#!/bin/sh
# Build and run the host-side adversarial IPC harnesses (real PD C sources, real pg-ipc Rust logic, ASan+UBSan).
# usage: tests/ipc/run.sh      exit 0 only if every harness passes; prints SKIPPED (exit 2) if clang/cargo are missing.
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
command -v clang >/dev/null && command -v cargo >/dev/null || { echo "SKIPPED: clang/cargo missing"; exit 2; }
mkdir -p "$R/build/ipc"
cargo build --release --offline --manifest-path "$R/tests/ipc/hostffi/Cargo.toml" --target-dir "$R/build/ipc/hostffi" >/dev/null 2>&1 \
  || cargo build --release --manifest-path "$R/tests/ipc/hostffi/Cargo.toml" --target-dir "$R/build/ipc/hostffi" >/dev/null
LIB="$R/build/ipc/hostffi/release/libpg_ipc_hostffi.a"
F="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined -w -I$R/tests/ipc/stubs -I$R/sel4/include"
fail=0
for h in harness_http harness_policy_conn; do
  clang $F ${EXTRA:-} -o "$R/build/ipc/$h" "$R/tests/ipc/$h.c" "$LIB" -lpthread -ldl -lm
  "$R/build/ipc/$h" || fail=1
done
exit $fail
