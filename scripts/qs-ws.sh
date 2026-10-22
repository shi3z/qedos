#!/bin/sh
# Run cargo for the QED Script crates in a dependency-free scratch workspace (build/qs/ws).
# The root workspace also contains pg-proxy (mio/OpenSSL deps); this helper lets the pure-Rust
# no_std crates build and test offline. Usage: scripts/qs-ws.sh test|build|... [cargo args]
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
W=$R/build/qs/ws
mkdir -p "$W/crates"
for c in pg-http pg-policy pg-config pg-script-policy pg-script pg-script-verify pg-script-cli pg-ipc pg-script-proofcheck; do
  [ -e "$W/crates/$c" ] || ln -s "$R/crates/$c" "$W/crates/$c"
done
[ -e "$W/config" ] || ln -s "$R/config" "$W/config"
cat > "$W/Cargo.toml" <<'T'
[workspace]
resolver = "2"
members = ["crates/pg-http","crates/pg-policy","crates/pg-config","crates/pg-script-policy","crates/pg-script","crates/pg-script-verify","crates/pg-script-cli","crates/pg-ipc","crates/pg-script-proofcheck"]
[workspace.package]
edition = "2021"
license = "Apache-2.0"
version = "0.1.0"
[profile.release]
opt-level = 3
lto = "thin"
panic = "abort"
overflow-checks = true
debug = 1
T
cd "$W"
exec cargo "$@" --offline
