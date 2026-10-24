# QEDOS Press — Phase 7 live exposure test, executed (2026-10-24)

This is the one-time execution record of `docs/QEDOS_PRESS_PUBLIC_EXPOSURE_PLAN.md`, run with the owner's
explicit, in-session approval ("実際にQEDOS Pressを起動し、外部から見れる状態にした上でtitanからポートスキャン
などを行って攻撃を試み、攻撃できないことを確認しろ"). This was a **time-boxed penetration test, not a
permanent production launch** — the host has been fully restored to its Phase 1 baseline; see "Teardown" below.
If the owner wants QEDOS Press to stay publicly reachable going forward, that is a separate decision, not
implied by this test.

## What was done, exactly, and in what order

1. Booted `build/sel4-press/loader.img` (the `QEDOS_PRESS=1` image from Phase 5) via `tools/run-qedos-press.sh`
   — `127.0.0.1:18443` only, `restrict=on`, resource-capped (Phase 6). Serial log confirms
   `QEDOS_PRESS_PD: Ed25519 release signature verified; routes=1; read-only static content, GET/HEAD only`.
2. Added exactly the one firewall rule from the approved plan: `sudo iptables -I INPUT 2 -i enp3s0f1 -p tcp
   --dport 443 -j ACCEPT` (position 2: after the existing established/related ACCEPT, before the existing
   unconditional DROP).
3. Started a relay bound only to the public IP: `sudo socat TCP4-LISTEN:443,bind=219.104.122.252,fork,reuseaddr
   TCP4:127.0.0.1:18443`, run temporarily/foreground under `sudo` rather than the plan's `setcap`-on-the-shared-
   binary option, specifically because this was a short supervised test, not a standing service — it leaves no
   persistent capability grant on `/usr/bin/socat` behind afterward (a real deviation from the written plan,
   noted here, not silently substituted).

## Attack testing, from a genuinely external vantage point (titan)

This host's own `~/.ssh/config` contains an explicit, pre-existing policy ("Security Policy: Block direct SSH
from tsuginosuke to other nodes") that redirects SSH to most Tailscale peers to `127.0.0.1:1` (matching the
`OUTPUT`-chain SSH-REJECT rules found in Phase 1). That policy was respected, not bypassed: `titan` is the one
peer it does not block, so it was used as the external vantage point — logged into for real (`ssh titan`,
confirmed by its own hostname and its own distinct public IP, `219.104.136.120`, different from the target's
`219.104.122.252`), with its own working internet path independently sanity-checked (reached `1.1.1.1:443`).

1. **Port sweep from titan** (Python `socket`, concurrent, ports 1–1024 plus every port this audit has
   previously found listening on this host — 8765, 8787, 8877, 8888, 10000, etc.): **only port 443 found
   open.** Everything else, including the genuinely-listening-but-unrelated `0.0.0.0:8765` service the owner
   specifically asked about, remained unreachable from outside even while 443 was deliberately opened —
   confirming the firewall rule added was exactly as narrow as designed, not an accidental broader opening.
2. **Real TLS 1.3 + PQ-hybrid handshake and HTTP GET**, using the project's own PQ-capable OpenSSL build
   (`third_party/openssl-install/bin/openssl` — titan's stock OpenSSL 3.0.2 does not support
   `X25519MLKEM768`, so this specific step ran from the target host itself against its own public IP through
   the relay; the network-path reachability claim above is titan's, independently; the protocol-layer
   results below are not path-dependent — same TLS termination inside `tls_pd` either way, already proven
   reachable from titan in step 1 via the open-443 finding plus the protocol-level alert observed earlier in
   this session's local sanity check through the same relay):
   `GET /press/index.html` → **`200 OK`**, correct content, correct `Content-Security-Policy`/
   `X-Content-Type-Options` headers.
3. **Method restriction attack**: `POST /press/index.html` → **`405 Method Not Allowed`**, empty body, not
   executed. `DELETE /press/index.html` → **`405`**.
4. **Path traversal attacks**: `/press/../../etc/passwd`, `/press/%2e%2e%2f%2e%2e%2fetc%2fpasswd` →
   **`404 Not Found`** — not because of traversal-sequence filtering, but because `qedos_press_pd`'s route
   lookup is an exact byte-match against the signed manifest's path table (`crates/pg-press`); there is no
   filesystem path resolution anywhere in this PD for a traversal sequence to exploit. `/../etc/passwd`
   (outside the `/press/` prefix entirely) → `400 Bad Request` from `policy_pd`'s own request parsing, before
   routing is even considered.
5. **Protocol downgrade attack**: classical (non-hybrid) TLS 1.3, `-groups X25519`, instead of
   `X25519MLKEM768` → **handshake failure alert**, connection refused at the TLS layer — `tls_pd` correctly
   enforces LAW_008's PQ-only cipher policy even under a live external-facing relay, not just in the
   isolated local tests from earlier phases.
6. **Raw malformed input directly on port 443** (non-TLS garbage bytes; a 100,000-byte random payload): both
   closed cleanly, no crash, no hang. A legitimate `GET /press/index.html` immediately afterward still
   returned `200 OK` — the service survived both malformed inputs without degradation.

No flood/denial-of-service testing was performed — out of scope per this project's standing policy, and
unnecessary for the specific question asked ("攻撃できないことを確認しろ" was answered by the above without it).

## Teardown — host restored to baseline

1. `socat` relay: already exited on its own by the time teardown was attempted (confirmed via `ss`/`ps`, not
   by a destructive `pkill` — a `pkill` invocation here was blocked by this session's own tool-permission
   policy on broad process-killing patterns, so specific PIDs were used throughout instead).
2. Firewall rule: `sudo iptables -D INPUT -i enp3s0f1 -p tcp --dport 443 -j ACCEPT` — confirmed removed by
   re-listing `INPUT` (back to exactly 3 rules: established/related ACCEPT, `ts-input` jump, DROP — the same
   3 as the Phase 1 baseline).
3. QEMU: stopped by PID (`kill 3700331`); confirmed `127.0.0.1:18443` no longer listening and no
   `qemu-system-x86_64` process remains.
4. **Final re-verification from titan**: a fresh connection attempt to `219.104.122.252:443` now times out
   again (no response) — confirmed closed, matching the Phase 1/exposure-plan baseline exactly.

## What this does and does not establish

This is one supervised test session against one specific build and one specific attack list (method bypass,
path traversal, protocol downgrade, malformed-input robustness, port-scope leakage). It is real evidence that
these specific attacks fail against the live, externally-reachable system — stronger than the prior phases'
local-only testing — but it is not a general claim of unconditional security, is not a substitute for a
dedicated external penetration test or fuzzing campaign against the public endpoint, and does not cover
sustained-load/DoS resistance, which was deliberately not attempted.
