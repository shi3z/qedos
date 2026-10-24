#!/bin/sh
# Build the complete seL4 + Microkit + sDDF + Freestanding OpenSSL 3.6.1 + Rust no_std
# qedos multi-PD image (`build/sel4/loader.img`) and Viper capability models (`build/sel4/viper/`).
set -eu

R=$(cd "$(dirname "$0")/.." && pwd)
cd "$R"
export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/opt/lld/bin:/opt/homebrew/opt/llvm/bin:$R/third_party/venv/bin:$R/tools/conda/bin:$PATH"

# QEDOS_ARCH=x86_64 (default, output build/sel4) or aarch64 (output build/sel4-$QEDOS_BOARD).
# QEDOS_BOARD defaults to x86_64_generic / qemu_virt_aarch64 (also: rpi4b_1gb).
ARCH=${QEDOS_ARCH:-x86_64}
case "$ARCH" in
  x86_64)
    BOARD=${QEDOS_BOARD:-x86_64_generic}
    RUST_TARGET=x86_64-unknown-none
    CLANG_TARGET="-target x86_64-none-elf"
    ARCH_CFLAGS="-mno-red-zone"
    OPENSSL_SEL4="$R/third_party/openssl-sel4"
    OPENSSL_HOST_BIN="$R/third_party/openssl-install/bin/openssl"  # host-side (ML-KEM-768 keygen etc.)
    ECHO_DIR="$R/build/echo"
    OUT="$R/build/sel4"
    [ "${QEDOS_SCRIPT:-0}" = 1 ] && OUT="$R/build/sel4-script"   # never clobber the baseline image
    [ "${QEDOS_PRESS:-0}" = 1 ] && OUT="$R/build/sel4-press"
    [ "${QEDOS_SCRIPT:-0}" = 1 ] && [ "${QEDOS_PRESS:-0}" = 1 ] && OUT="$R/build/sel4-script-press"
    # QEDOS_PRESS_COMPAT=1 implies QEDOS_PRESS=1 (it only ever replaces tls_pd in a press image)
    # and gets its own output directory -- it never overwrites build/sel4-press (the full-assurance,
    # PQ-only image stays separately buildable and testable; see docs/QEDOS_PRESS_TLS_COMPAT.md).
    if [ "${QEDOS_PRESS_COMPAT:-0}" = 1 ]; then
      export QEDOS_PRESS=1   # must be exported: sel4/meta_proofgate.py reads it as a subprocess
      OUT="$R/build/sel4-press-compat"
    fi
    # QEDOS_PRESS_PQ=1 implies QEDOS_PRESS=1 and adds the separate press_pq_pd (app-layer
    # ML-KEM-768 envelope for POST /press/pq-fetch -- see docs/QEDOS_PRESS_PQ_WRAP.md). Own output
    # directory, never combined with QEDOS_PRESS_COMPAT=1 in this phase.
    if [ "${QEDOS_PRESS_PQ:-0}" = 1 ]; then
      export QEDOS_PRESS=1
      OUT="$R/build/sel4-press-pq"
    fi
    [ -n "${QEDOS_OUT:-}" ] && OUT="$QEDOS_OUT"                  # explicit override (e.g. rebuild-from-source checks)
    ;;
  aarch64)
    BOARD=${QEDOS_BOARD:-qemu_virt_aarch64}
    RUST_TARGET=aarch64-unknown-none
    CLANG_TARGET="-target aarch64-none-elf"
    ARCH_CFLAGS="-mcpu=cortex-a53"
    OPENSSL_SEL4="$R/third_party/openssl-sel4-aarch64"
    ECHO_DIR="$R/build/echo-$BOARD"
    OUT="$R/build/sel4-$BOARD"
    ;;
  *) echo "unsupported QEDOS_ARCH=$ARCH" >&2; exit 1 ;;
esac

MICROKIT_SDK="$R/third_party/microkit/microkit-sdk-2.3.1"
BOARD_DIR="$MICROKIT_SDK/board/$BOARD/debug"
MICROKIT_TOOL="$MICROKIT_SDK/bin/microkit"
SDDF="$R/third_party/sddf"

mkdir -p "$OUT" "$OUT/viper"

# 1. Ensure signed configs and freestanding OpenSSL exist
if [ ! -f "$R/config/sel4/proxy.sconf" ]; then
  "$R/scripts/sign-config.sh"
fi
if [ ! -f "$OPENSSL_SEL4/lib/libssl.a" ]; then
  QEDOS_ARCH="$ARCH" "$R/scripts/build-openssl-sel4.sh"
fi
if [ "$ARCH" = aarch64 ] && [ ! -f "$ECHO_DIR/eth_driver.elf" ]; then
  QEDOS_BOARD="$BOARD" "$R/scripts/build-sddf.sh"
fi

# 2. Build the Rust `#![no_std]` static library (`libpg_sel4_pds.a`) for x86_64-unknown-none
cargo build --manifest-path "$R/sel4/rust_pds/Cargo.toml" --target "$RUST_TARGET" --release
RUST_PDS_A="$R/sel4/rust_pds/target/$RUST_TARGET/release/libpg_sel4_pds.a"

# 3. Copy prebuilt sDDF driver ELFs & libraries from build/echo into build/sel4
for f in eth_driver.elf network_virt_rx.elf network_virt_tx.elf network_copy.elf \
         timer_driver.elf serial_driver.elf serial_virt_tx.elf \
         libsddf_util.a libsddf_util_debug.a lib_sddf_lwip_echo.a; do
  cp "$ECHO_DIR/$f" "$OUT/$f"
done

# 4. Compile freestanding libc shim
COMMON_CFLAGS="$CLANG_TARGET $ARCH_CFLAGS -ffreestanding -fno-stack-protector -O2 -g3 -Wall -Wno-unused-function -I$BOARD_DIR/include -I$R/sel4/include"

clang $COMMON_CFLAGS -Isel4/libc_shim/include -I"$OPENSSL_SEL4/include" \
  -c "$R/sel4/libc_shim/libc_shim.c" -o "$OUT/libc_shim.o"

# 5. Compile & link `tcp_pd.elf` (sDDF + lwIP)
LWIP_CFLAGS="-I$SDDF/include/sddf/util/custom_libc -I$SDDF/include/microkit -I$SDDF/include -I$SDDF/examples/echo_server/include/lwip -I$SDDF/examples/echo_server/include -I$SDDF/network/ipstacks/lwip/src/include -I$SDDF/network/ipstacks/lwip/src/include/ipv4 -Wno-tautological-constant-out-of-range-compare"
clang $COMMON_CFLAGS $LWIP_CFLAGS -c "$R/sel4/pds/tcp_pd.c" -o "$OUT/tcp_pd.o"
ld.lld -L"$BOARD_DIR/lib" --start-group \
  "$OUT/tcp_pd.o" "$OUT/libsddf_util.a" "$OUT/libsddf_util_debug.a" "$OUT/lib_sddf_lwip_echo.a" \
  -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/tcp_pd.elf"

# 6. Compile & link `tls_pd.elf` (Freestanding OpenSSL 3.6.1, TLS 1.3 + X25519MLKEM768 only) --
#    or, under QEDOS_PRESS_COMPAT=1, the separate, narrower-assurance `tls_compat_pd.elf`
#    instead (PQ preferred, classical fallback -- see docs/QEDOS_PRESS_TLS_COMPAT.md). An image
#    links exactly one of the two, never both.
TLS_PD_SRC="$R/sel4/pds/tls_pd.c"
TLS_PD_NAME="tls_pd"
if [ "${QEDOS_PRESS_COMPAT:-0}" = 1 ]; then
  TLS_PD_SRC="$R/sel4/pds/tls_compat_pd.c"
  TLS_PD_NAME="tls_compat_pd"
fi
clang $COMMON_CFLAGS -I"$R/sel4/libc_shim" -I"$R/sel4/libc_shim/include" -I"$OPENSSL_SEL4/include" \
  -c "$TLS_PD_SRC" -o "$OUT/$TLS_PD_NAME.o"
ld.lld -L"$BOARD_DIR/lib" --start-group \
  "$OUT/$TLS_PD_NAME.o" "$OUT/libc_shim.o" "$OPENSSL_SEL4/lib/libssl.a" "$OPENSSL_SEL4/lib/libcrypto.a" \
  -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/$TLS_PD_NAME.elf"

# 7. Compile & link `http_pd.elf`, `policy_pd.elf`, `connector_pd.elf` (Rust `#![no_std]` crates)
for pd in http_pd policy_pd connector_pd; do
  clang $COMMON_CFLAGS -Isel4/libc_shim/include -c "$R/sel4/pds/${pd}.c" -o "$OUT/${pd}.o"
  ld.lld -L"$BOARD_DIR/lib" --start-group \
    "$OUT/${pd}.o" "$OUT/libc_shim.o" "$RUST_PDS_A" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/${pd}.elf"
done

# 7b. Feature dispatch glue (opt-in: QEDOS_SCRIPT=1 and/or QEDOS_PRESS=1, independently combinable).
#     Policy/HTTP PDs are rebuilt once with whichever -DQEDOS_* defines are active, so both features'
#     dispatch branches compile in together when both are requested.
FEATURE_DEFS=""
[ "${QEDOS_SCRIPT:-0}" = 1 ] && FEATURE_DEFS="$FEATURE_DEFS -DQEDOS_SCRIPT=1"
[ "${QEDOS_PRESS:-0}" = 1 ] && FEATURE_DEFS="$FEATURE_DEFS -DQEDOS_PRESS=1"
[ "${QEDOS_PRESS_PQ:-0}" = 1 ] && FEATURE_DEFS="$FEATURE_DEFS -DQEDOS_PRESS_PQ=1"
if [ -n "$FEATURE_DEFS" ]; then
  for pd in http_pd policy_pd; do
    clang $COMMON_CFLAGS $FEATURE_DEFS -Isel4/libc_shim/include -c "$R/sel4/pds/${pd}.c" -o "$OUT/${pd}.o"
    ld.lld -L"$BOARD_DIR/lib" --start-group \
      "$OUT/${pd}.o" "$OUT/libc_shim.o" "$RUST_PDS_A" \
      -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/${pd}.elf"
  done
fi

# 7c. QED Script PD (opt-in: QEDOS_SCRIPT=1). Separate Rust staticlib => the Wasm interpreter is linked
#     into script_pd.elf ONLY.
if [ "${QEDOS_SCRIPT:-0}" = 1 ]; then
  cargo build --manifest-path "$R/sel4/rust_script/Cargo.toml" --target "$RUST_TARGET" --release
  RUST_SCRIPT_A="$R/sel4/rust_script/target/$RUST_TARGET/release/libpg_sel4_script.a"
  clang $COMMON_CFLAGS -DQEDOS_SCRIPT=1 ${QEDOS_SCRIPT_TEST_FAULT:+-DQEDOS_SCRIPT_TEST_FAULT=1} -Isel4/libc_shim/include -c "$R/sel4/pds/script_pd.c" -o "$OUT/script_pd.o"
  ld.lld -L"$BOARD_DIR/lib" --start-group \
    "$OUT/script_pd.o" "$OUT/libc_shim.o" "$RUST_SCRIPT_A" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/script_pd.elf"
  # supervisor_pd: parent of script_pd. --gc-sections drops the (unused) HTTP/policy code that shares the rust_pds archive.
  clang $COMMON_CFLAGS -DQEDOS_SCRIPT=1 -DSCRIPT_TIMEOUT_MS="${QEDOS_SCRIPT_TIMEOUT_MS:-5000}ULL" \
    -I"$SDDF/include" -I"$SDDF/include/microkit" -I"$SDDF/include/sddf/util/custom_libc" -Isel4/libc_shim/include \
    -c "$R/sel4/pds/supervisor_pd.c" -o "$OUT/supervisor_pd.o"
  ld.lld --gc-sections -L"$BOARD_DIR/lib" --start-group \
    "$OUT/supervisor_pd.o" "$OUT/libc_shim.o" "$OUT/libsddf_util.a" "$OUT/libsddf_util_debug.a" "$RUST_PDS_A" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/supervisor_pd.elf"
  # the entry point baked into supervisor_pd.c must be script_pd's real ELF entry (restart would jump there)
  ENTRY=$(llvm-readelf -h "$OUT/script_pd.elf" 2>/dev/null | awk '/Entry point/ {print $4}')
  [ "$ENTRY" = "0x200000" ] || { echo "script_pd.elf entry point is $ENTRY, supervisor_pd.c expects 0x200000" >&2; exit 1; }
fi

# 7d. QEDOS Press PD (opt-in: QEDOS_PRESS=1). Separate Rust staticlib, linked into qedos_press_pd.elf
# (and press_pq_pd.elf, below, which links the SAME staticlib -- both PDs trust the one key below).
#
# PRESS_PUBLIC_KEY (sel4/rust_press/src/press_pubkey.rs) is regenerated on EVERY build, dev or
# prod -- never left as whatever a previous build happened to write. Default: the committed dev
# key. QEDOS_PRESS_PROD=1 selects a real production key instead, read from
# QEDOS_PRESS_PROD_PUBKEY (defaults to config/keys/qedos-press-prod-pub.hex -- the SAME file
# tools/press-admin.py already verifies signatures against, by default, so host-side and seL4-side
# trust the identical bytes by construction, not by convention). Fails closed (exit 1, no partial
# build) if that file is missing, malformed, or -- the specific case this exists to catch --
# identical to the dev key. See docs/QEDOS_PRESS_PROD_KEY.md.
if [ "${QEDOS_PRESS:-0}" = 1 ]; then
  PRESS_PUBKEY_RS="$R/sel4/rust_press/src/press_pubkey.rs"
  DEV_PUB_HEX_FILE="$R/config/keys/qedos-press-dev-pub.hex"
  if [ "${QEDOS_PRESS_PROD:-0}" = 1 ]; then
    : "${QEDOS_PRESS_PROD_PUBKEY:=$R/config/keys/qedos-press-prod-pub.hex}"
    if [ ! -f "$QEDOS_PRESS_PROD_PUBKEY" ]; then
      echo "FATAL: QEDOS_PRESS_PROD=1 requires QEDOS_PRESS_PROD_PUBKEY to point at an existing" >&2
      echo "       32-byte-hex Ed25519 public key file (got: $QEDOS_PRESS_PROD_PUBKEY)." >&2
      echo "       Generate a production keypair on a SEPARATE machine with" >&2
      echo "       tools/press-sign-offline.py and copy only the PUBLIC key here. Refusing to" >&2
      echo "       build (fail closed -- never falls back to the dev key)." >&2
      exit 1
    fi
    QEDOS_PRESS_PROD_FINGERPRINT=$(python3 - "$QEDOS_PRESS_PROD_PUBKEY" "$DEV_PUB_HEX_FILE" "$PRESS_PUBKEY_RS" <<'PY'
import hashlib
import sys
prod_path, dev_path, out_rs = sys.argv[1], sys.argv[2], sys.argv[3]
prod_hex = open(prod_path).read().strip()
if len(prod_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in prod_hex):
    sys.exit(f"FATAL: {prod_path} must contain exactly 64 hex characters (32 bytes); "
              f"got {len(prod_hex)} characters. Refusing to build.")
prod_bytes = bytes.fromhex(prod_hex)
dev_bytes = bytes.fromhex(open(dev_path).read().strip())
if prod_bytes == dev_bytes:
    sys.exit("FATAL: QEDOS_PRESS_PROD_PUBKEY is byte-for-byte identical to the committed dev key "
              "(config/keys/qedos-press-dev-pub.hex). Refusing to use the dev key as a production "
              "key -- generate a real keypair on a separate machine with tools/press-sign-offline.py.")
arr = ", ".join(f"0x{b:02x}" for b in prod_bytes)
with open(out_rs, "w") as f:
    f.write(
        "// GENERATED by scripts/build-sel4.sh from QEDOS_PRESS_PROD_PUBKEY. PRODUCTION key --\n"
        "// NOT the dev default. See docs/QEDOS_PRESS_PROD_KEY.md.\n"
        f"pub const PRESS_PUBLIC_KEY: [u8; 32] = [{arr}];\n"
    )
print(hashlib.sha256(prod_bytes).hexdigest())
PY
    ) || exit 1
    echo "QEDOS Press: PRODUCTION pubkey fingerprint (sha256) = $QEDOS_PRESS_PROD_FINGERPRINT"
    echo "QEDOS Press: compare this against tools/press-admin.py's own fingerprint for the same"
    echo "             file (--show-pubkey-fingerprint) before trusting any deploy."
    # Force a clean rebuild of this one small crate so a stale cached rlib from a previous build
    # (different key, same source paths) can never be silently reused.
    rm -rf "$R/sel4/rust_press/target"
  else
    python3 - "$DEV_PUB_HEX_FILE" "$PRESS_PUBKEY_RS" <<'PY'
import sys
dev_hex = open(sys.argv[1]).read().strip()
arr = ", ".join(f"0x{b:02x}" for b in bytes.fromhex(dev_hex))
with open(sys.argv[2], "w") as f:
    f.write(
        "// GENERATED by scripts/build-sel4.sh -- dev key (default; QEDOS_PRESS_PROD=1 for a real one).\n"
        f"pub const PRESS_PUBLIC_KEY: [u8; 32] = [{arr}];\n"
    )
PY
  fi
  cargo build --manifest-path "$R/sel4/rust_press/Cargo.toml" --target "$RUST_TARGET" --release
  RUST_PRESS_A="$R/sel4/rust_press/target/$RUST_TARGET/release/libpg_sel4_press.a"
  clang $COMMON_CFLAGS -DQEDOS_PRESS=1 -Isel4/libc_shim/include -c "$R/sel4/pds/qedos_press_pd.c" -o "$OUT/qedos_press_pd.o"
  ld.lld -L"$BOARD_DIR/lib" --start-group \
    "$OUT/qedos_press_pd.o" "$OUT/libc_shim.o" "$RUST_PRESS_A" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/qedos_press_pd.elf"
fi

# 7e. QEDOS Press PQ-wrap PD (opt-in: QEDOS_PRESS_PQ=1). Reuses the same pg-press Rust staticlib
# (manifest verify/lookup, not duplicated) plus the freestanding OpenSSL build (ML-KEM-768
# decapsulate, HKDF, AES-256-GCM) -- same link pattern as tls_pd. See docs/QEDOS_PRESS_PQ_WRAP.md.
if [ "${QEDOS_PRESS_PQ:-0}" = 1 ]; then
  clang $COMMON_CFLAGS -DQEDOS_PRESS_PQ=1 -I"$R/sel4/libc_shim" -Isel4/libc_shim/include -I"$OPENSSL_SEL4/include" \
    -c "$R/sel4/pds/press_pq_pd.c" -o "$OUT/press_pq_pd.o"
  ld.lld -L"$BOARD_DIR/lib" --start-group \
    "$OUT/press_pq_pd.o" "$OUT/libc_shim.o" "$RUST_PRESS_A" "$OPENSSL_SEL4/lib/libssl.a" "$OPENSSL_SEL4/lib/libcrypto.a" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/press_pq_pd.elf"
fi

# 8. Generate `proofgate.system` and sDDF `.data` sections, then patch ELFs
DTB_ARG=""
[ "$ARCH" = aarch64 ] && DTB_ARG="--dtb $ECHO_DIR/$BOARD.dtb"
python3 "$R/sel4/meta_proofgate.py" --sddf "$SDDF" --output "$OUT" --sdf proofgate.system --board "$BOARD" $DTB_ARG

cp "$OUT/network_copy.elf" "$OUT/network_copy0.elf"
llvm-objcopy --update-section .device_resources="$OUT/serial_driver_device_resources.data" "$OUT/serial_driver.elf"
llvm-objcopy --update-section .serial_driver_config="$OUT/serial_driver_config.data" "$OUT/serial_driver.elf"
llvm-objcopy --update-section .serial_virt_tx_config="$OUT/serial_virt_tx.data" "$OUT/serial_virt_tx.elf"
llvm-objcopy --update-section .device_resources="$OUT/ethernet_driver_device_resources.data" "$OUT/eth_driver.elf"
llvm-objcopy --update-section .net_driver_config="$OUT/net_driver.data" "$OUT/eth_driver.elf"
llvm-objcopy --update-section .net_virt_rx_config="$OUT/net_virt_rx.data" "$OUT/network_virt_rx.elf"
llvm-objcopy --update-section .net_virt_tx_config="$OUT/net_virt_tx.data" "$OUT/network_virt_tx.elf"
llvm-objcopy --update-section .net_copy_config="$OUT/net_copy_tcp_net_copier.data" "$OUT/network_copy0.elf"
llvm-objcopy --update-section .device_resources="$OUT/timer_driver_device_resources.data" "$OUT/timer_driver.elf"
llvm-objcopy --update-section .timer_client_config="$OUT/timer_client_tcp_pd.data" "$OUT/tcp_pd.elf"
[ "${QEDOS_SCRIPT:-0}" = 1 ] && llvm-objcopy --update-section .timer_client_config="$OUT/timer_client_supervisor_pd.data" "$OUT/supervisor_pd.elf"
llvm-objcopy --update-section .net_client_config="$OUT/net_client_tcp_pd.data" "$OUT/tcp_pd.elf"
llvm-objcopy --update-section .serial_client_config="$OUT/serial_client_tcp_pd.data" "$OUT/tcp_pd.elf"
llvm-objcopy --update-section .lib_sddf_lwip_config="$OUT/lib_sddf_lwip_config_tcp_pd.data" "$OUT/tcp_pd.elf"

# Inject the Ed25519-signed configuration (`config/sel4/proxy.sconf`, padded to 512B) into `policy_pd.elf`
python3 - "$R/config/sel4/proxy.sconf" "$OUT/signed_config.data" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
assert len(data) <= 512
open(dst, "wb").write(data.ljust(512, b"\x00"))
PY
llvm-objcopy --update-section .signed_config="$OUT/signed_config.data" "$OUT/policy_pd.elf"

# Inject the signed QSB1 script bundle table into script_pd.elf `.script_bundles` ONLY (QEDOS_SCRIPT=1).
# The table is verified at boot inside script_pd against the pinned code-signing key (LAW_020).
if [ "${QEDOS_SCRIPT:-0}" = 1 ]; then
  "$R/scripts/pack-script-bundles.sh" "$OUT/script_bundles.data"
  llvm-objcopy --update-section .script_bundles="$OUT/script_bundles.data" "$OUT/script_pd.elf"
fi

# Inject the ML-KEM-768 decapsulation private key material ONLY (QEDOS_PRESS_PQ=1). Must run
# BEFORE the release-bundle packing step below: it produces examples/press-site-pq/pqkey.bin, one
# of the files that step packs. config/dev/pq-priv.pem is a dev-only key, same committed-dev-key
# precedent as config/dev/key.pem; a real deployment would use a QEDOS_PQ_PRIVATE_KEY-style
# override (not added in this phase -- see docs/QEDOS_PRESS_PQ_WRAP.md).
if [ "${QEDOS_PRESS_PQ:-0}" = 1 ]; then
  if [ ! -f "$R/config/dev/pq-priv.pem" ]; then
    mkdir -p "$R/config/dev"
    "$OPENSSL_HOST_BIN" genpkey -algorithm ML-KEM-768 -out "$R/config/dev/pq-priv.pem"
  fi
  if [ ! -f "$R/examples/press-site-pq/pqkey.bin" ]; then
    PQ_DUMP_BIN="$R/build/host-tools/pq-dump-pubkey"
    if [ ! -x "$PQ_DUMP_BIN" ]; then
      mkdir -p "$R/build/host-tools"
      cc "$R/tools/pq-dump-pubkey.c" \
        -I"$R/third_party/openssl-install/include" \
        -L"$R/third_party/openssl-install/lib64" -L"$R/third_party/openssl-install/lib" -lcrypto \
        -Wl,-rpath,"$R/third_party/openssl-install/lib64" \
        -o "$PQ_DUMP_BIN"
    fi
    mkdir -p "$R/examples/press-site-pq"
    "$PQ_DUMP_BIN" "$R/config/dev/pq-priv.pem" > "$R/examples/press-site-pq/pqkey.bin"
  fi
fi

# Inject the signed QPR1 release bundle into qedos_press_pd.elf `.press_bundle` ONLY (QEDOS_PRESS=1).
# The bundle is Ed25519-verified at boot inside qedos_press_pd against the pinned dev press key
# (config/keys/qedos-press-dev-pub.hex -- NOT production-grade; see docs/QEDOS_PRESS_CMS.md).
# QEDOS_PRESS_PQ=1 images pack a SEPARATE, richer site (examples/press-site-pq/ -- adds pqkey.bin,
# pq-client.js, vendor/ml-kem768.bundle.js) into its own cached .qpr, and inject that same bundle
# into press_pq_pd.elf too (it reuses qedos_press_pd's manifest verify/lookup code and needs the
# same signed content to answer pg_press_handle() lookups for pq-fetch). Every QEDOS_PRESS=1 image
# WITHOUT QEDOS_PRESS_PQ=1 keeps packing the original, smaller examples/press-site/ unchanged --
# this keeps that image's route count (and every existing test's assumptions about it) unaffected
# by this feature.
if [ "${QEDOS_PRESS:-0}" = 1 ]; then
  PRESS_SITE_DIR="$R/examples/press-site"
  PRESS_QPR="$R/config/dev/press-release.qpr"
  if [ "${QEDOS_PRESS_PQ:-0}" = 1 ]; then
    PRESS_SITE_DIR="$R/examples/press-site-pq"
    PRESS_QPR="$R/config/dev/press-pq-release.qpr"
  fi
  # QEDOS_PRESS_SITE_DIR/QEDOS_PRESS_QPR: explicit overrides (e.g. tools/press-admin.py publishing
  # a draft, or a test using an isolated site copy) -- default is unchanged, so no existing
  # invocation's behavior changes. Never overwrite the committed config/dev/*.qpr from a non-default
  # site_dir; always route those through their own scratch .qpr path instead.
  [ -n "${QEDOS_PRESS_SITE_DIR:-}" ] && PRESS_SITE_DIR="$QEDOS_PRESS_SITE_DIR"
  [ -n "${QEDOS_PRESS_QPR:-}" ] && PRESS_QPR="$QEDOS_PRESS_QPR"
  if [ ! -f "$PRESS_QPR" ]; then
    QS="$R/build/qs/ws/target/release/qs"
    [ -x "$QS" ] || "$R/scripts/qs-ws.sh" build --release -p pg-script-cli
    mkdir -p "$R/config/dev"
    python3 "$R/tools/press-release.py" \
      --site-id 1 --release 1 \
      --qs "$QS" --seed "$R/config/keys/qedos-press-dev-seed.hex" \
      --out "$PRESS_QPR" \
      "$PRESS_SITE_DIR"
  fi
  python3 - "$PRESS_QPR" "$OUT/press_bundle.data" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
assert len(d) <= 262144, "release bundle exceeds qedos_press_pd .press_bundle (256 KiB)"
open(sys.argv[2], "wb").write(d.ljust(262144, b"\0"))
PY
  llvm-objcopy --update-section .press_bundle="$OUT/press_bundle.data" "$OUT/qedos_press_pd.elf"
  [ "${QEDOS_PRESS_PQ:-0}" = 1 ] && llvm-objcopy --update-section .press_bundle="$OUT/press_bundle.data" "$OUT/press_pq_pd.elf"
fi

# Inject the ML-KEM-768 decapsulation private key into `press_pq_pd.elf` `.pq_keystore` section
# ONLY (QEDOS_PRESS_PQ=1). The matching public key is a normal signed static asset
# (examples/press-site-pq/pqkey.bin, produced by tools/pq-dump-pubkey.c above) -- NOT injected
# here, it rides the same Ed25519-signed bundle as every other press-site-pq file.
if [ "${QEDOS_PRESS_PQ:-0}" = 1 ]; then
  PQ_KEY_PEM="${QEDOS_PQ_PRIVATE_KEY:-$R/config/dev/pq-priv.pem}"
  python3 - "$PQ_KEY_PEM" "$OUT/pq_keystore.data" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
assert len(data) < 4096, "ML-KEM-768 private key PEM exceeds press_pq_pd .pq_keystore (4096 B)"
open(sys.argv[2], "wb").write(data.ljust(4096, b"\x00"))
PY
  llvm-objcopy --update-section .pq_keystore="$OUT/pq_keystore.data" "$OUT/press_pq_pd.elf"
fi

# Inject TLS cert/key into `tls_pd.elf` `.tls_keystore` section ONLY (LAW_008).
# Override with QEDOS_TLS_CERT/QEDOS_TLS_KEY (e.g. a real CA cert kept outside the repo,
# never committed) -- defaults to the committed dev cert/key, unchanged for every other build.
TLS_CERT="${QEDOS_TLS_CERT:-$R/config/dev/cert.pem}"
TLS_KEY="${QEDOS_TLS_KEY:-$R/config/dev/key.pem}"
python3 - "$TLS_CERT" "$TLS_KEY" "$OUT/tls_keystore.data" <<'PY'
import sys
cert = open(sys.argv[1], "rb").read()
key = open(sys.argv[2], "rb").read()
assert len(cert) < 6144 and len(key) < 2048
open(sys.argv[3], "wb").write(cert.ljust(6144, b"\x00") + key.ljust(2048, b"\x00"))
PY
llvm-objcopy --update-section .tls_keystore="$OUT/tls_keystore.data" "$OUT/$TLS_PD_NAME.elf"

# 9. Build the bootable seL4 Microkit image (`loader.img`), memory report (`report.txt`),
#    and formal Viper capability invariants (`build/sel4/viper/*.vpr`)
"$MICROKIT_TOOL" "$OUT/proofgate.system" \
  --search-path "$OUT" \
  --board "$BOARD" \
  --config debug \
  --viper-output "$OUT/viper" \
  -o "$OUT/loader.img" \
  -r "$OUT/report.txt"

if [ "${QEDOS_SCRIPT:-0}" = 1 ]; then
  python3 "$R/scripts/check-script-caps.py" "$OUT/proofgate.system"
fi

# Build-time self-check + provenance record (QEDOS_PRESS_PROD=1 only): confirm the FINAL
# loader.img that will actually be booted really does contain the production pubkey bytes (not a
# stale-cache artifact of some earlier build), and record a build manifest an operator can review.
# This is an integrity/provenance record for human review, NOT a cryptographic secure-boot chain --
# it does not prove the loader/kernel itself wasn't tampered with before this check ever ran. See
# docs/QEDOS_PRESS_PROD_KEY.md's "What is NOT verified" section.
if [ "${QEDOS_PRESS_PROD:-0}" = 1 ]; then
  python3 - "$QEDOS_PRESS_PROD_PUBKEY" "$OUT/loader.img" "$OUT/BUILD_PROVENANCE.txt" "$QEDOS_PRESS_PROD_FINGERPRINT" <<'PY'
import hashlib
import subprocess
import sys
import time

pub_path, img_path, out_path, fingerprint = sys.argv[1:5]
pub_bytes = bytes.fromhex(open(pub_path).read().strip())
img_bytes = open(img_path, "rb").read()
if pub_bytes not in img_bytes:
    sys.exit(f"FATAL build-time self-check: production pubkey bytes are NOT present in {img_path}. "
              f"This almost always means a stale build cache served an old key -- refusing to ship "
              f"this image. Re-run the build (it already does `rm -rf sel4/rust_press/target` in "
              f"production mode, so this should not recur).")
img_hash = hashlib.sha256(img_bytes).hexdigest()
try:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
except Exception:
    commit = "unknown (git rev-parse failed)"
with open(out_path, "w") as f:
    f.write(
        "QEDOS Press production build provenance record\n"
        "================================================\n"
        "This is a build record for OPERATOR REVIEW. It is NOT a cryptographic secure-boot or\n"
        "attestation chain -- it does not prove the loader/kernel/initrd chain itself was not\n"
        "tampered with before this record was written, and it is not verifiable against anything\n"
        "outside this host's own filesystem at build time. See docs/QEDOS_PRESS_PROD_KEY.md.\n\n"
        f"build timestamp (UTC):        {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"git commit:                   {commit}\n"
        f"production pubkey fingerprint (sha256): {fingerprint}\n"
        f"loader.img sha256:            {img_hash}\n"
        f"loader.img path:              {img_path}\n"
        f"self-check:                   production pubkey bytes confirmed present in loader.img\n"
    )
print(f"build-time self-check OK -- wrote {out_path}")
PY
fi

ls -lh "$OUT/loader.img" "$OUT/report.txt" "$OUT/viper/"
