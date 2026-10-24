# QEDOS Press — public exposure plan (Phase 7, design only — NOT executed)

**Nothing in this document has been applied.** Per the master prompt's own §0/§7, public exposure is a
separate final phase requiring the owner's fresh, explicit approval, re-reading the live firewall state at
that time (not this snapshot) — this document exists so that approval can be an informed decision, not a
blind one. It designs the change, states its exact commands and rollback, and re-states what re-verification
must happen immediately before and after, if and when the owner approves it.

## Re-confirmed immediately before writing this plan (2026-10-24, read-only)

* TCP 443/80 are still free on both the public (`enp3s0f1`) and LAN (`enp3s0f0`) interfaces — only
  `tailscaled` holds 443, bound only to the Tailscale addresses, as in the Phase 1 baseline.
* The load-bearing firewall rule from `SECURITY_BASELINE.md` is unchanged:
  ```
  -A INPUT -i enp3s0f1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  -A INPUT -j ts-input
  -A INPUT -i enp3s0f1 -j DROP
  ```
* **New observation, not in the Phase 1 baseline**: root filesystem free space has dropped from 75 GB (92%
  used) to **59 GB (94% used)** since that audit — unrelated to this work (this host runs many unrelated
  services), but worth the owner's attention before adding any persistent CMS content storage; re-check at
  approval time, not from this number, since it is already stale by the time this is read.

## Why this specific change, and nothing broader

The mission's own target topology:
```
Internet --443/tcp--> Ubuntu Firewall --> L4 TCP Proxy --127.0.0.1:18443--> QEMU --> QEDOS Press
```
TLS is terminated inside QEDOS (`tls_pd`), not by the proxy — the proxy is a dumb TCP relay, never a TLS
endpoint, so the private key never leaves the guest's `tls_keystore` region (unchanged from everything
already proven/tested in `docs/CAPABILITY_AUDIT.md`/`docs/IPC_VERIFICATION.md`). This section is deliberately
narrow: it is the smallest change that connects the already-isolated local service
(`tools/run-qedos-press.sh`, verified in Phase 4/6) to the public interface, nothing more.

## Candidate L4 proxy

**Recommendation: a userspace relay (`socat` or HAProxy in pure TCP mode), not an `iptables REDIRECT`.**
Rationale: a userspace process is independently restartable/loggable/resource-capped (same
`systemd-run --user --scope` pattern already verified in Phase 6) without touching the host's shared,
unmanaged `nftables` ruleset beyond the one narrow allow-rule below; an `iptables REDIRECT` would instead
require adding NAT-table rules to that same unmanaged ruleset, increasing the blast radius of a mistake on a
ruleset nobody owns (`SECURITY_BASELINE.md`'s finding). Binding to port 443 (<1024) without running as root:
`sudo setcap 'cap_net_bind_service=+ep' $(command -v socat)` once, then run `socat` as the unprivileged
`qedos-press` user from Phase 6 — this is a one-time, auditable capability grant to one binary, not a
standing root process.

```
# PROPOSED relay command (run as the unprivileged service user, NOT root):
socat TCP4-LISTEN:443,bind=219.104.122.252,fork,reuseaddr,keepalive TCP4:127.0.0.1:18443
```
Binding the relay explicitly to `219.104.122.252` (not `0.0.0.0`) means it never listens on the LAN interface
either — mirrors the same "explicit bind address, never the default" rule that governs the QEMU hostfwd
itself (Phase 4).

## The one firewall change this requires (exact command, exact rollback)

The existing `-A INPUT -i enp3s0f1 -j DROP` rule would drop the relay's own inbound connections just like
everything else on that interface — a new rule must come **before** it, allowing only new TCP connections to
port 443:
```
# PROPOSED — NOT applied. Exact command for the owner's review:
sudo iptables -I INPUT 2 -i enp3s0f1 -p tcp --dport 443 -j ACCEPT
#                    ^ position 2: after the existing established/related ACCEPT (position 1),
#                      before the unconditional DROP — matches by being more specific, does not
#                      require reordering or touching any existing rule.

# Rollback (removes exactly this one rule, nothing else):
sudo iptables -D INPUT -i enp3s0f1 -p tcp --dport 443 -j ACCEPT
```
This is additive and narrow: it does not touch `ts-input`/`ts-forward` (Tailscale's own rules), any `DOCKER*`
chain, the `FORWARD` or `OUTPUT` chains, or any other port. It does not run `iptables -F` or `nft flush
ruleset` — both remain explicitly forbidden regardless of approval, per rule 0. **This command is not run by
this document** — it is the exact text for the owner to review or run themselves, or to approve explicitly
before an agent runs it.

## Pre-publication checklist (per the master prompt's §7, answered where answerable now; the rest must be
re-checked at approval time, not assumed from this document)

| item | status |
|---|---|
| TCP 443 の既存利用者がいないか | Re-confirmed free, this session (above) |
| IPv4/IPv6 両方の待受状態 | IPv4 plan above; **IPv6 deliberately not exposed** — the QEMU guest-side has `ipv6=off` (Phase 4) and no IPv6 relay/firewall rule is proposed here; if IPv6 reachability is wanted later it needs its own explicit decision, not an implicit extension of this plan |
| Firewallの管理主体 | Confirmed in Phase 1: no identified owner, hand-maintained — reinforces using the single additive rule above, nothing broader |
| Dockerのポート公開ルール | Unaffected — this plan touches none of Docker's chains |
| ホストの他の公開ポート | Unaffected — no other rule changed |
| SSH管理経路 | Unaffected (port `22806`, untouched by this plan) |
| VPN管理経路 | Unaffected (Tailscale's `ts-input`/`ts-forward`, untouched) |
| 内部LANへのアクセス制御 | Unaffected — the relay binds only the public IP; `restrict=on` (Phase 4) still blocks the guest from reaching the LAN regardless |
| QEMUがrootで動いていないか | Already enforced (Phase 6: hard refusal in `run-qedos-press.sh`) |
| TLS証明書と秘密鍵の取り扱い | Unaffected — TLS stays inside `tls_pd`; the relay never sees plaintext key material (it's a TCP relay, not a TLS terminator) |
| 外部からの接続試験方法 | Proposed: from a network the owner controls that is *not* this host (e.g. a phone on mobile data, or a separate VPS) attempt `openssl s_client -connect 219.104.122.252:443`, expect a TLS 1.3 handshake attempt reaching `tls_pd` (not a refused/timed-out connection) — **not performed in this document**, since it requires the firewall change to exist first |
| ロールバック手順 | Exact `iptables -D` command above; additionally `systemctl stop` (or kill) the `socat` relay process, which alone (even before the firewall rule is removed) stops all traffic from reaching QEDOS |

## TLS certificate — a real gap, found during the Phase 7 live test, not addressed here

`tls_pd` currently loads `config/dev/cert.pem`/`config/dev/key.pem` (baked into `tls_keystore` at build time
by `scripts/build-sel4.sh`): a **self-signed** certificate, `CN=localhost`, SAN limited to
`DNS:localhost, IP:127.0.0.1` — it names neither the public IP (`219.104.122.252`) nor any real domain, and
is signed by nothing a real client trusts. This is fine for the isolated/loopback testing every prior phase
did, and was still fine for Phase 7's supervised attack test (TLS-layer behavior — handshake enforcement,
method/path handling — does not depend on the certificate's trust chain). **It is not fine for any real
public launch**: every real client would show a certificate warning or refuse outright, independent of
anything this project's own security work has verified. Getting a real certificate (e.g. via Let's Encrypt
for an actual domain name pointed at `219.104.122.252`, or any other public CA) and replacing
`config/dev/{cert,key}.pem` with it before the build that would actually go live is a **prerequisite for
Phase 7 proper**, not an optional follow-up — it was simply outside the scope of "confirm it cannot be
attacked," which doesn't depend on certificate trust. The dev private key remaining in the repository at all
is also already listed as a residual risk in `docs/HARDENING_RESULTS.md` §13; a real deployment needs its own
key generated and kept out of version control, not a rotation of the committed dev key.

## What is explicitly NOT in this plan

Online/updatable content publishing (still out of scope per Phase 5's own documented limits — releases remain
baked in at build time); a production (non-dev) signing key; anti-rollback; any authentication; IPv6 exposure;
any change to `enp3s0f0` (LAN) reachability; any change to `ts-input`/`ts-forward`; running anything as root.

## Next step

This plan is ready for the owner's review. Nothing here executes without a separate, explicit "やっていい"
(or equivalent) specifically naming the firewall rule and the relay — the same bar Phase 1 through 6 were
held to, not loosened because this is the last phase.
