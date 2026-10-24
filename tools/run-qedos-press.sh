#!/bin/sh
# Boot a Microkit x86_64 QEDOS image in QEMU with network isolation suitable for
# a host-deployed, locally-reachable-only service (QEDOS Press CMS).
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
#   - QEMU itself is already launched with -display none, -monitor none, no -usb,
#     no -fsdev/virtfs (no host directory sharing), and no disk image (sel4/initrd
#     boot only) — see tools/run-echo.sh. Those are not re-stated here.
#   - Memory/CPU/task-count/fd caps are applied via a transient, unprivileged
#     `systemd-run --user --scope` around the QEMU process, so a runaway or
#     compromised guest cannot consume unbounded host resources. This requires
#     no root and leaves no persistent host state (the scope is cleaned up when
#     the process exits). If `systemd-run` isn't available, this falls back to
#     running unwrapped and says so loudly — it does not silently skip the cap.
#
# usage: run-qedos-press.sh LOADER_IMG SERIAL_LOG HOST_PORT [seconds]
set -eu

if [ "$(id -u)" -eq 0 ]; then
  echo "run-qedos-press.sh: refusing to run as root (see docs/QEDOS_PRESS_HOST_HARDENING.md)" >&2
  exit 1
fi

R=$(cd "$(dirname "$0")/.." && pwd)
IMG="$1"
SERIAL_LOG="$2"
HOST_PORT="$3"
SECONDS="${4:-120}"

NETDEV="restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${HOST_PORT}-10.0.2.15:8443"

# Caps: the VM itself is given 2G (-m 2G in run-echo.sh) and 1 vCPU (no -smp, so
# QEMU's default); these leave headroom for QEMU's own process + vCPU/IO threads,
# not for a larger VM — raise them together with run-echo.sh's -m if that changes.
MEM_MAX="3G"
CPU_QUOTA="150%"
TASKS_MAX="64"
FD_MAX="1024"

# LimitNOFILE is an exec-context property that `systemd-run --scope` (which wraps
# an already-forked process, not an ExecStart=) does not accept — the fd cap is
# applied as an ordinary ulimit in this shell instead, which QEMU inherits.
ulimit -n "$FD_MAX"

if command -v systemd-run >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  exec systemd-run --user --scope --quiet \
    -p "MemoryMax=${MEM_MAX}" -p "MemoryHigh=${MEM_MAX}" \
    -p "CPUQuota=${CPU_QUOTA}" -p "TasksMax=${TASKS_MAX}" \
    -- "$R/tools/run-echo.sh" "$IMG" "$SERIAL_LOG" "$NETDEV" "$SECONDS"
else
  echo "run-qedos-press.sh: WARNING: systemd-run --user not available; running WITHOUT resource caps" >&2
  exec "$R/tools/run-echo.sh" "$IMG" "$SERIAL_LOG" "$NETDEV" "$SECONDS"
fi
