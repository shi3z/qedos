# SECURITY_BASELINE.md — Ubuntu host audit for QEDOS Press deployment

Read-only audit, 2026-10-23. No configuration was changed to produce this report (see "Commands run" at the
end — all read-only, four required `sudo` for ruleset visibility only). This document is the precondition for
any later deployment work on **QEDOS Press** (the QEDOS CMS); it must be re-read, not assumed, if deployment
work resumes after any gap, since this file is a snapshot, not a live view.

## Host identity

* Ubuntu 22.04.5 LTS, kernel 5.15.0-125-generic, x86_64.
* KVM available (`/dev/kvm` present, `kvm`/`kvm_intel` modules loaded, group `kvm`).
* QEMU 6.2.0 (Debian build) installed.
* 48 logical CPUs, 1.7 TiB RAM (132 GiB free), 877 GB root filesystem at **92% used (75 GB free)** — disk
  headroom is the tightest resource on this host; a QEMU disk image plus CMS content should be sized
  conservatively and placed with that in mind.

## This is a shared, heavily-loaded multi-tenant host — not a dedicated box

This machine runs, concurrently and independently of this task: a Slurm cluster controller+node daemon, 6
GPU "forge-worker" containers, Postgres/pgvector, MySQL, an LDAP server (`slapd`), NFS client/server services,
Postfix mail, several bespoke web/dashboard services (`gallery`, `editor-server`, `tailnet-dashboard`,
`attacker-dossier`, `security-guard` — names suggest this host already runs its own security-monitoring
tooling from past incidents), a `storyboard` backend+frontend, Redis, and roughly 30 ad-hoc Python/Node
processes bound to high ports. **Any firewall or network change on this host is a shared-risk action**, not
one scoped to QEDOS alone — this is the central reason rule 0's prohibitions matter here specifically.

## Network interfaces

| interface | address | role |
|---|---|---|
| `enp3s0f1` | `219.104.122.252/28` (public range), default route via `219.104.122.241` | **The internet-facing NIC.** `ip route get 8.8.8.8` resolves out through it. |
| `enp3s0f0` | `192.168.2.111/24`, default route via `192.168.2.1` | Internal LAN NIC (second default route, lower priority metric 50 vs. 10). |
| `tailscale0` | `100.126.237.55/32` (+ IPv6 ULA) | Tailscale mesh VPN; this is the host's actual remote-admin path (see below). |
| `wg0` | `10.20.40.13/32` | A WireGuard interface, point-to-point, currently `UP`; detail not readable without root on the interface's own config (did not pursue — out of scope, not touched). |
| `docker0`, `br-*` | `172.17–172.22.0.0/16` | Docker bridge networks, each individually NAT'd and locked down by Docker's own per-bridge DROP rules (see below). |
| ~10 `veth*` | link-local only | Docker container veth pairs. |

IPv4 forwarding (`net.ipv4.ip_forward`) is **already `1`** system-wide (needed by Docker/Tailscale — not
something this task should ever disable, and also not something it needs to further enable). IPv6 forwarding
is `0` globally and `0` specifically on `enp3s0f1`.

## The firewall that actually protects this host today

`ufw` is **inactive** — it is not the enforcement mechanism. The real enforcement is a hand-maintained
`nftables`/`iptables` ruleset (compat layer; `iptables-save`/`nft list ruleset` both show it) plus rules
injected by `tailscaled` itself (`ts-input`, `ts-forward` chains) and by `dockerd` (`DOCKER`, `DOCKER-USER`,
`DOCKER-FORWARD` chains). No systemd unit or config file under `/etc/{iptables,nftables.conf,ufw}` was
identified as the owner of the hand-written rules (not pursued further — read-only scope); treat this ruleset
as **unmanaged/manual state that a careless `nft flush ruleset` or `iptables -F` would permanently destroy**,
which is exactly why rule 0 forbids exactly those actions.

The load-bearing rule, in `filter/INPUT`:
```
-A INPUT -i enp3s0f1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j ts-input
-A INPUT -i enp3s0f1 -j DROP
```
INPUT's policy is `ACCEPT`, but for the public NIC specifically, every **new** inbound connection is
dropped unless it is first routed through `ts-input` (i.e. arrives already over the Tailscale mesh, which
is itself authenticated/encrypted) or is a reply to a connection this host initiated. **This is the real
reason none of the ~30 services bound to `0.0.0.0` on this host are actually reachable from the open
internet today** — they are listening, but `enp3s0f1`'s un-established new-connection traffic is dropped
before it reaches any socket. `FORWARD`'s policy is `DROP`, and nothing routes traffic from `enp3s0f1` into
any Docker bridge (`DOCKER-USER` drops `enp3s0f1`-sourced forward traffic explicitly) — confirming Docker
containers are not reachable from the internet either, independent of their own port bindings.

**This means the host's current global-IP exposure is effectively zero for new inbound connections**, and
the correct way to add QEDOS Press's HTTPS service later (phase 7, not now) is almost certainly a narrow,
additive rule granting port 443 on `enp3s0f1` specifically — not a ufw/nft reset, and not something to infer
further detail about without re-reading this exact ruleset at that time, since it could have changed.

## Existing use of TCP 443 / 80

**Confirmed free on both the public and LAN interfaces.** The only process holding port 443 is `tailscaled`,
bound only to the Tailscale addresses (`100.126.237.55:443`, its IPv6 ULA) — this is Tailscale's own internal
use (certificate services / Taildrop over the mesh), not a conflict with binding 443 on `enp3s0f1` or via a
QEMU hostfwd to `127.0.0.1`. `nginx.service` is reported `active` by systemd, but `sites-enabled/` is empty
and `ss`/`nginx -T` show it is **not actually bound to any port** right now — it is not a live conflict, but
its systemd unit should be re-checked, not assumed inert, if it is ever reactivated with a real site config
before QEDOS Press goes to the public-facing phase.

## Docker's own isolation (independent finding, not to be relied on for QEDOS)

Docker already isolates its bridges from each other and from the public NIC using per-bridge `DROP` rules in
`raw/PREROUTING` and `filter/DOCKER*`, plus NAT-based DNAT for its published ports. This is Docker's own
mechanism and says nothing about QEDOS's isolation — QEDOS will run under QEMU/KVM as a whole VM, a different
isolation boundary entirely, and must be evaluated on its own terms (phase 4 of the mission).

## Answering the mission's six required baseline questions

1. **Services possibly exposed today**: none to new internet connections, per the `enp3s0f1` DROP rule above.
   Everything reachable from outside goes through Tailscale's authenticated mesh. SSH is on a non-default
   port (`22806`, confirmed via `sshd`) — note the standard port `22` is also listed by `ss` as `LISTEN
   0.0.0.0:22`, but per the same INPUT rule, that too is new-connection-dropped on the public NIC; it is
   reachable only on the LAN NIC or over Tailscale, and this report does not re-verify that interface-by-
   interface split beyond the one explicit `-i enp3s0f1` rule shown above — a live external port-scan
   (not performed; would be an internet-sourced test, out of this audit's read-only local scope) is the only
   way to be fully sure, and should precede any public-facing decision in phase 7.
2. **Routes into the internal LAN**: `enp3s0f0` (`192.168.2.0/24`) is a second, independent path with its own
   default route; nothing in the firewall dump restricts outbound/forward traffic between the two NICs
   explicitly (`FORWARD` policy `DROP` covers this generally, but a compromised process with socket access to
   both interfaces' own bound services is a different risk than packet forwarding — not evaluated here).
3. **Firewall's administrator**: no identifiable systemd/config owner found; it is unmanaged, manually
   applied state plus Tailscale's and Docker's own auto-injected rules. Any change must assume there is no
   safety net that reapplies it after a mistake.
4. **Current admin access path**: Tailscale mesh (`100.126.237.55`) is the de facto admin channel; a
   secondary WireGuard interface (`wg0`) exists but was not inspected further (root-owned config, out of
   read-only reach, not pursued since it wasn't necessary to answer this baseline).
5. **Risk of unintended exposure**: concretely, **binding a QEMU hostfwd to `0.0.0.0` instead of `127.0.0.1`
   would bypass none of the above protections** by itself (the `enp3s0f1` DROP rule would still apply to new
   inbound connections) — but it would newly expose the forwarded port to the LAN NIC (`enp3s0f0`,
   `192.168.2.0/24`) and to any other local process/user on the host, which is exactly the kind of
   over-broad exposure the mission's incident history warns about. This is the concrete justification for
   this mission's rule mandating `hostfwd=tcp:127.0.0.1:18443-:443` and nothing broader.
6. **Can QEDOS be introduced without changing current exposure?** Yes, for the local-development phases:
   QEMU user-mode networking with a `127.0.0.1`-only hostfwd adds a new local TCP listener but changes no
   existing firewall rule, route, or interface state, and is not reachable from either NIC's external side
   given the ruleset above. **No**, for the eventual public phase, without an explicit, narrow, reviewed
   firewall addition — which is out of scope until the mission's phase 7 and requires the owner's separate
   explicit approval.

## Commands run (all read-only; the four marked required `sudo` for ruleset visibility only)

```
uname -a; cat /etc/os-release; ls -la /dev/kvm; lsmod | grep -i kvm; nproc; free -h; df -h /
which/version qemu-system-x86_64
ip -br address; ip -4/-6 route show table all; ip rule show; ss -lntup
docker ps -a; docker network ls; docker ps --format '{{.Names}}: {{.Ports}}'
virsh list --all (not installed); pgrep -fal qemu
systemctl list-units --type=service --state=running
which/status tailscale, wg
nft list ruleset (sudo); iptables-save (sudo); ip6tables-save (sudo); ufw status verbose (sudo)
cat /proc/sys/net/ipv4/ip_forward, net/ipv6/conf/{all,enp3s0f1}/forwarding
nginx -T; ls /etc/nginx/sites-enabled; ss -lntp | grep nginx
ip route get 8.8.8.8
```

No secrets, tokens, or VPN private configuration were displayed or recorded. Tailscale peer hostnames/IPs
shown above are this host's own mesh roster, not credentials.

## Conclusion

**Safe to proceed with local-only QEDOS Press development** (mission phases 1–4: local QEMU VM, local CMS
function, 127.0.0.1-only network isolation testing, host hardening review) **without any firewall, routing,
or network-interface change.** Public exposure (phase 7) requires a fresh, explicit decision at that time,
re-reading the live ruleset rather than this snapshot, plus the owner's separate sign-off per rule 0.
