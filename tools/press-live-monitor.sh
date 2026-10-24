#!/bin/bash
# Autonomous safety monitor for a temporary live-public QEDOS Press window.
# Runs independently in the background (nohup) for up to DURATION_SECONDS, checking:
#   1. the relay (socat) and QEMU processes are still alive
#   2. the one 443 ACCEPT firewall rule is still present and unmodified
#   3. the service actually still answers correctly (functional liveness, via a real
#      TLS1.3+PQ handshake using this project's own OpenSSL build)
#   4. the connection rate to port 443 hasn't spiked abnormally (possible flood/attack)
# On ANY of these, or on reaching DURATION_SECONDS, it tears everything down the same
# way every other phase of this project did: remove the exact firewall rule, kill the
# relay, kill QEMU -- and logs why.
#
# usage: press-live-monitor.sh SOCAT_PID QEMU_PID DURATION_SECONDS
set -u
R=$(cd "$(dirname "$0")/.." && pwd)
SOCAT_PID="$1"
QEMU_PID="$2"
DURATION="${3:-86400}"
IFACE="enp3s0f1"
PUBLIC_IP="219.104.122.252"
DOMAIN="qedos.zelpm.com"
OSSL="$R/third_party/openssl-install/bin/openssl"
OPENSSL_CONF="$R/config/openssl-min.cnf"
LOG=/tmp/qedos-press-live-monitor.log
ALERT=/tmp/qedos-press-live-ALERT.log

# Tuned generously for a small static demo page: real attack traffic should clear this
# by a wide margin without false-triggering on normal background internet noise.
MAX_CONN_PER_SAMPLE=300
SAMPLE_SECONDS=30
FAIL_STREAK_LIMIT=3

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

teardown() {
  reason="$1"
  log "ALERT: $reason -- tearing down public exposure now"
  echo "[$(date -u +%FT%TZ)] ALERT: $reason" >> "$ALERT"
  sudo iptables -D INPUT -i "$IFACE" -p tcp --dport 443 -j ACCEPT 2>>"$LOG"
  sudo kill "$SOCAT_PID" 2>>"$LOG"   # socat runs under sudo; plain kill lacks permission
  kill "$QEMU_PID" 2>>"$LOG"        # QEMU runs as the invoking user, not root
  sleep 2
  log "teardown complete. iptables INPUT now:"
  sudo iptables -L INPUT -n -v --line-numbers 2>&1 | tee -a "$LOG"
  exit 0
}

log "monitor started: socat=$SOCAT_PID qemu=$QEMU_PID duration=${DURATION}s"
END=$(( $(date +%s) + DURATION ))
fail_streak=0
prev_accept_pkts=0
prev_drop_pkts=0

while [ "$(date +%s)" -lt "$END" ]; do
  # 1. process health. /proc existence, not `kill -0`: socat runs under sudo (root), so an
  #    unprivileged `kill -0` against it fails with EPERM (not ESRCH) and would be
  #    indistinguishable from "dead" -- a false positive this script hit once already
  #    during setup. Checking /proc/<pid> needs no permission over the target process.
  [ -d "/proc/$SOCAT_PID" ] || teardown "socat relay process ($SOCAT_PID) died"
  [ -d "/proc/$QEMU_PID" ] || teardown "QEMU process ($QEMU_PID) died"

  # 2. firewall rule integrity (exactly this rule, nothing broader)
  sudo iptables -C INPUT -i "$IFACE" -p tcp --dport 443 -j ACCEPT 2>/dev/null \
    || teardown "the 443 ACCEPT rule is missing or was changed -- cannot confirm scope is still narrow"

  # 3. connection-rate check on the 443 ACCEPT rule and the catch-all DROP rule (the
  #    latter is informational only -- it's what's already silently absorbing any
  #    scan/attack traffic against ssh, 8765, or anything else on this interface; it
  #    was never reachable and opening 443 did not change that).
  read -r accept_pkts <<< "$(sudo iptables -L INPUT -n -v -x 2>/dev/null | awk '$0 ~ /dpt:443/ {print $1; exit}')"
  read -r drop_pkts   <<< "$(sudo iptables -L INPUT -n -v -x 2>/dev/null | awk '$3=="DROP" && $4=="all" {print $1; exit}')"
  accept_pkts="${accept_pkts:-0}"; drop_pkts="${drop_pkts:-0}"
  accept_delta=$(( accept_pkts - prev_accept_pkts ))
  drop_delta=$(( drop_pkts - prev_drop_pkts ))
  prev_accept_pkts=$accept_pkts; prev_drop_pkts=$drop_pkts
  log "sample: +$accept_delta pkts to :443 (ACCEPT), +$drop_delta pkts dropped on $IFACE (everything else, incl. ssh/8765 scan noise) this interval"
  if [ "$accept_delta" -gt "$MAX_CONN_PER_SAMPLE" ]; then
    teardown "abnormal connection volume to :443 ($accept_delta packets in ${SAMPLE_SECONDS}s, threshold $MAX_CONN_PER_SAMPLE) -- possible flood/attack"
  fi

  # 4. functional liveness: a real request through the real public endpoint
  resp=$(OPENSSL_CONF="$OPENSSL_CONF" timeout 8 bash -c "
    echo -e 'GET /press/index.html HTTP/1.1\r\nHost: $DOMAIN\r\nConnection: close\r\n\r\n' | \
    '$OSSL' s_client -connect $PUBLIC_IP:443 -servername $DOMAIN -tls1_3 -groups X25519MLKEM768 \
      -verify_return_error -CAfile /etc/ssl/certs/ca-certificates.crt -quiet 2>&1" | grep -c "^HTTP/1.1 200")
  if [ "${resp:-0}" -ge 1 ]; then
    fail_streak=0
  else
    fail_streak=$(( fail_streak + 1 ))
    log "functional check failed (streak=$fail_streak/$FAIL_STREAK_LIMIT)"
    if [ "$fail_streak" -ge "$FAIL_STREAK_LIMIT" ]; then
      teardown "service failed $FAIL_STREAK_LIMIT consecutive functional checks (not serving correctly over the public endpoint)"
    fi
  fi

  sleep "$SAMPLE_SECONDS"
done

teardown "scheduled window (${DURATION}s) elapsed normally"
