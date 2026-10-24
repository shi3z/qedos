#!/bin/sh
# Boot the separate, narrower-assurance QEDOS_PRESS_COMPAT=1 image (tls_compat_pd in place of
# tls_pd -- see docs/QEDOS_PRESS_TLS_COMPAT.md) in QEMU, with the exact same host-protection and
# network-isolation discipline as tools/run-qedos-press.sh. This is a separate script, not a flag
# on that one, so the two images (and which one a given host port is wired to) are never confused.
#
# Isolation policy (see SECURITY_BASELINE.md / docs/QEDOS_PRESS_DEPLOYMENT.md):
#   - QEMU user-mode networking (SLiRP) only: no TAP, no bridge, no macvtap.
#   - restrict=on: the guest cannot reach the external network or the host's LAN;
#     it can only use SLiRP's internal services (DHCP/DNS stub) and the one
#     hostfwd rule below.
#   - ipv6=off: no IPv6 path out of the guest.
#   - The hostfwd rule binds the HOST side to 127.0.0.1 explicitly. Without an
#     explicit host address, QEMU's hostfwd defaults to 0.0.0.0 (binds every
#     host interface) — this is the exact mistake this script exists to avoid.
#     Do not remove the "127.0.0.1:" prefix below.
#
# Resource containment (host protection — see docs/QEDOS_PRESS_HOST_HARDENING.md):
#   - Must never be run as root (checked below — refuses to start as uid 0).
#   - Same QEMU flags, same systemd-run --user --scope resource caps, same ulimit -n
#     fallback behavior as tools/run-qedos-press.sh.
#
# usage: run-qedos-press-compat.sh LOADER_IMG SERIAL_LOG HOST_PORT [seconds]
set -eu

if [ "$(id -u)" -eq 0 ]; then
  echo "run-qedos-press-compat.sh: refusing to run as root (see docs/QEDOS_PRESS_HOST_HARDENING.md)" >&2
  exit 1
fi

R=$(cd "$(dirname "$0")/.." && pwd)
IMG="$1"
SERIAL_LOG="$2"
HOST_PORT="$3"
SECONDS="${4:-120}"

# Guest-internal port stays 8443 (tcp_pd.c's PROXY_HTTPS_PORT, unchanged) -- this is a fully
# independent VM/network namespace from the strict image, so there is no collision; only the
# HOST-side port (this script's 3rd argument) needs to differ when running both side by side.
NETDEV="restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${HOST_PORT}-10.0.2.15:8443"

MEM_MAX="3G"
CPU_QUOTA="150%"
TASKS_MAX="64"
FD_MAX="1024"

ulimit -n "$FD_MAX"

if command -v systemd-run >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  exec systemd-run --user --scope --quiet \
    -p "MemoryMax=${MEM_MAX}" -p "MemoryHigh=${MEM_MAX}" \
    -p "CPUQuota=${CPU_QUOTA}" -p "TasksMax=${TASKS_MAX}" \
    -- "$R/tools/run-echo.sh" "$IMG" "$SERIAL_LOG" "$NETDEV" "$SECONDS"
else
  echo "run-qedos-press-compat.sh: WARNING: systemd-run --user not available; running WITHOUT resource caps" >&2
  exec "$R/tools/run-echo.sh" "$IMG" "$SERIAL_LOG" "$NETDEV" "$SECONDS"
fi
