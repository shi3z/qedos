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

# 7d. QEDOS Press PD (opt-in: QEDOS_PRESS=1). Separate Rust staticlib, linked into qedos_press_pd.elf ONLY.
if [ "${QEDOS_PRESS:-0}" = 1 ]; then
  cargo build --manifest-path "$R/sel4/rust_press/Cargo.toml" --target "$RUST_TARGET" --release
  RUST_PRESS_A="$R/sel4/rust_press/target/$RUST_TARGET/release/libpg_sel4_press.a"
  clang $COMMON_CFLAGS -DQEDOS_PRESS=1 -Isel4/libc_shim/include -c "$R/sel4/pds/qedos_press_pd.c" -o "$OUT/qedos_press_pd.o"
  ld.lld -L"$BOARD_DIR/lib" --start-group \
    "$OUT/qedos_press_pd.o" "$OUT/libc_shim.o" "$RUST_PRESS_A" \
    -lmicrokit -Tmicrokit.ld --end-group -o "$OUT/qedos_press_pd.elf"
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

# Inject the signed QPR1 release bundle into qedos_press_pd.elf `.press_bundle` ONLY (QEDOS_PRESS=1).
# The bundle is Ed25519-verified at boot inside qedos_press_pd against the pinned dev press key
# (config/keys/qedos-press-dev-pub.hex -- NOT production-grade; see docs/QEDOS_PRESS_CMS.md).
if [ "${QEDOS_PRESS:-0}" = 1 ]; then
  if [ ! -f "$R/config/dev/press-release.qpr" ]; then
    QS="$R/build/qs/ws/target/release/qs"
    [ -x "$QS" ] || "$R/scripts/qs-ws.sh" build --release -p pg-script-cli
    mkdir -p "$R/config/dev"
    python3 "$R/tools/press-release.py" \
      --site-id 1 --release 1 \
      --qs "$QS" --seed "$R/config/keys/qedos-press-dev-seed.hex" \
      --out "$R/config/dev/press-release.qpr" \
      "$R/examples/press-site"
  fi
  python3 - "$R/config/dev/press-release.qpr" "$OUT/press_bundle.data" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
assert len(d) <= 262144, "release bundle exceeds qedos_press_pd .press_bundle (256 KiB)"
open(sys.argv[2], "wb").write(d.ljust(262144, b"\0"))
PY
  llvm-objcopy --update-section .press_bundle="$OUT/press_bundle.data" "$OUT/qedos_press_pd.elf"
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

ls -lh "$OUT/loader.img" "$OUT/report.txt" "$OUT/viper/"
