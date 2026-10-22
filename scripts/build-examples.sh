#!/bin/sh
# Rebuild every example module from its build.py and re-sign it with the (development) code-signing key.
# Needed whenever tools/qswasm.py or the accepted Wasm subset changes. Production signing never uses this key.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
"$R/scripts/qs-ws.sh" build --release -p pg-script-cli >&2
QS=${QS:-$R/build/qs/ws/target/release/qs}
for d in hello json-echo params kv-counter; do
  python3 "$R/examples/$d/build.py"
  "$QS" sign --seed "$R/config/keys/qs-code-signing-seed.hex" "$R/examples/$d"
  "$QS" verify "$R/examples/$d" | head -1
done
