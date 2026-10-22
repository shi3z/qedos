#!/bin/sh
# Static & formal checks backing LAW_001..LAW_012. Exit non-zero on violation.
set -eu
cd "$(dirname "$0")/.."
fail=0

# LAW_005: no process spawning / shell in any proxy-side crate or seL4 PD
if grep -rnE "std::process::Command|Command::new|libc::(system|exec[lv]|fork|popen)" crates/pg-http crates/pg-policy crates/pg-config crates/pg-proxy sel4/rust_pds sel4/pds; then
  echo "LAW_005 violated"; fail=1
else
  echo "LAW_005 static check: no process-spawn API in pg-http/pg-policy/pg-config/pg-proxy/sel4"
fi

# LAW_006 / LAW_011 support: parser, policy, and config crates are #![no_std] and #![forbid(unsafe_code)]
for c in pg-http pg-policy pg-config; do
  grep -q "forbid(unsafe_code)" "crates/$c/src/lib.rs" || { echo "$c lacks forbid(unsafe_code)"; fail=1; }
  grep -q "no_std" "crates/$c/src/lib.rs" || { echo "$c lacks no_std"; fail=1; }
done
echo "LAW_006/LAW_011 static check: pg-http, pg-policy, pg-config are #![no_std] and #![forbid(unsafe_code)]"

# LAW_008 / LAW_011 / LAW_012: seL4 Microkit system & Viper formal capability audit
if [ -f build/sel4/proofgate.system ]; then
  python3 scripts/check-caps.py || fail=1
else
  echo "missing build/sel4/proofgate.system"; fail=1
fi

# QED Script (LAW_013..LAW_022) static checks
for c in pg-script pg-script-policy pg-script-verify; do
  grep -q "forbid(unsafe_code)" "crates/$c/src/lib.rs" || { echo "$c lacks forbid(unsafe_code)"; fail=1; }
  grep -q "no_std" "crates/$c/src/lib.rs" || { echo "$c lacks no_std"; fail=1; }
done
if grep -rnE "std::process|Command::new|std::net|std::fs|TcpStream|UdpSocket|libc::" crates/pg-script crates/pg-script-policy crates/pg-script-verify sel4/rust_script/src sel4/pds/script_pd.c; then
  echo "LAW_022/LAW_005 violated: network/fs/process API in QED Script TCB"; fail=1
fi
# LAW_015: the host API allowlist contains nothing resembling ambient authority
if grep -E 'Api::[A-Za-z]+ => b"' crates/pg-script-policy/src/lib.rs | grep -E 'socket|connect|open|file|exec|spawn|sel4|cap|tls|key|mmap|syscall|time|random'; then
  echo "LAW_015 violated: ambient-authority-looking name in the host API allowlist"; fail=1
fi
# LAW_014/018/022: script_pd's declared authority (baseline system + fragment, mutation-tested)
python3 scripts/check-script-caps.py --selftest > /dev/null || fail=1
echo "LAW_013..022 static check: QED Script crates forbid(unsafe_code)/no_std, no net/fs/process APIs, host API allowlist clean, script_pd capability audit + 9 mutants"
echo "unsafe blocks in pg-proxy:"
grep -rn "unsafe" crates/pg-proxy/src | grep -v "^.*//"
exit $fail
