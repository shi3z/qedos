#!/bin/sh
# Pack the signed example bundles into a 64 KiB QSB1 table for script_pd's `.script_bundles` section.
# usage: scripts/pack-script-bundles.sh OUT.data
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
OUT=$1
QS=${QS:-$R/build/qs/ws/target/release/qs}
[ -x "$QS" ] || { "$R/scripts/qs-ws.sh" build --release -p pg-script-cli >&2; }
for d in hello json-echo; do
  [ -f "$R/examples/$d/app.sig" ] || { python3 "$R/examples/$d/build.py"; "$QS" sign --seed "$R/config/keys/qs-code-signing-seed.hex" "$R/examples/$d"; }
done
# QEDOS_SCRIPT_EXTRA: space-separated extra bundle dirs (tests add hostile modules; max 8 in total)
"$QS" pack "$OUT.tmp" "$R/examples/hello" "$R/examples/json-echo" ${QEDOS_SCRIPT_EXTRA:-}
python3 - "$OUT.tmp" "$OUT" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
assert len(d) <= 65536, "bundle table exceeds script_pd .script_bundles (64 KiB)"
open(sys.argv[2], "wb").write(d.ljust(65536, b"\0"))
PY
rm -f "$OUT.tmp"
