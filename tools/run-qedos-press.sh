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
# usage: run-qedos-press.sh LOADER_IMG SERIAL_LOG HOST_PORT [seconds]
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
IMG="$1"
SERIAL_LOG="$2"
HOST_PORT="$3"
SECONDS="${4:-120}"

NETDEV="restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:${HOST_PORT}-10.0.2.15:8443"

exec "$R/tools/run-echo.sh" "$IMG" "$SERIAL_LOG" "$NETDEV" "$SECONDS"
