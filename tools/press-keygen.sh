#!/bin/sh
# Convenience wrapper around tools/press-sign-offline.py's `keygen` mode: builds the `qs` CLI if
# needed, then generates a fresh Ed25519 production keypair for QEDOS Press.
#
# ================================================================================================
#  RUN THIS ONLY ON A SEPARATE MACHINE YOU PERSONALLY CONTROL -- NEVER ON THE SHARED,
#  MULTI-TENANT, INTERNET-FACING QEDOS HOST. See docs/QEDOS_PRESS_ADMIN.md and
#  docs/QEDOS_PRESS_PROD_KEY.md for why: that host must never hold any signing private key
#  material, plaintext or encrypted, because its own compromise is explicitly in scope.
# ================================================================================================
#
# This script does NOT bypass the human confirmation prompt in press-sign-offline.py -- it still
# asks you to type "yes" interactively before touching any key material. That is deliberate: it
# must never be possible for automation (on any machine) to silently generate a real production
# key. It also refuses outright if it detects it is running on the known shared QEDOS host, as a
# second, independent safety net.
#
# usage: tools/press-keygen.sh [output_dir]
#   output_dir defaults to ./qedos-prod-key/ (created if missing).
set -eu

R=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR="${1:-$R/qedos-prod-key}"

# Second, independent safety net: refuse by hostname if this looks like the known shared host.
# This is NOT the only protection (press-sign-offline.py's own interactive confirmation is the
# primary one) -- it just catches the specific, foreseeable mistake of running this script here
# by habit after copying the repo, rather than on the separate machine it's meant for.
KNOWN_SHARED_HOST="tsuginosuke"
if [ "$(hostname 2>/dev/null)" = "$KNOWN_SHARED_HOST" ]; then
  echo "press-keygen.sh: refusing to run -- this looks like the shared QEDOS host ($KNOWN_SHARED_HOST)." >&2
  echo "                 Copy this repository to a SEPARATE machine you control and run it there." >&2
  exit 1
fi

echo "This will generate a new Ed25519 PRODUCTION signing keypair for QEDOS Press."
echo "The output directory will be: $OUT_DIR"
echo

QS="$R/build/qs/ws/target/release/qs"
if [ ! -x "$QS" ]; then
  echo "Building the qs CLI (first run only)..."
  "$R/scripts/qs-ws.sh" build --release -p pg-script-cli
fi
if [ ! -x "$QS" ]; then
  echo "press-keygen.sh: expected qs CLI at $QS after build, but it's not there." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
SEED="$OUT_DIR/prod-seed.hex"
PUB="$OUT_DIR/prod-pub.hex"

if [ -e "$SEED" ]; then
  echo "press-keygen.sh: $SEED already exists -- refusing to overwrite an existing key." >&2
  echo "                 Pick a different output_dir if you really want a new keypair." >&2
  exit 1
fi

# No --yes-i-am-on-a-separate-machine here on purpose: this still prompts you interactively.
python3 "$R/tools/press-sign-offline.py" keygen \
  --qs "$QS" --out-seed "$SEED" --out-pub "$PUB"

cat <<EOF

================================================================================================
Done.

  $SEED   <- the PRIVATE key. Keep it ONLY on this machine, forever. Never copy it anywhere,
              especially not to the shared QEDOS host.
  $PUB   <- the PUBLIC key. Safe to copy to the shared host as:
              config/keys/qedos-press-prod-pub.hex

Next: to sign a release with this key, use:
  python3 tools/press-sign-offline.py sign --qs "$QS" --seed "$SEED" \\
      --release N --out release.qpr path/to/content_dir
================================================================================================
EOF
