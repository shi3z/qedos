# QEDOS Press — Ubuntu host protection (Phase 6)

Scope: protecting the Ubuntu host from a compromised or resource-exhausting QEDOS guest. This is separate from
network isolation (`docs/QEDOS_PRESS_DEPLOYMENT.md` Phase 4) and from the guest-internal capability model
(`docs/CAPABILITY_AUDIT.md`, `docs/THREAT_MODEL.md`'s Attack B/D). Per the mission's rule 0, account creation,
systemd unit installation, and AppArmor profile installation on the actual host all require the owner's
separate explicit approval before being applied — this document designs them and applies only what's possible
without root and without touching any existing host state (below, "Done now" vs. "Proposed, needs approval").

## Done now (no root required, no existing host state touched, empirically verified)

**`tools/run-qedos-press.sh`** was extended, not replaced:

1. **Refuses to run as root** (`id -u` check, hard exit) — satisfies "QEMUをrootで実行しない" directly; there
   is no scenario in which this script should ever run as `root`, so this is a hard refusal, not a warning.
2. **Resource caps via a transient, unprivileged `systemd-run --user --scope`** around the QEMU process:
   `MemoryMax=3G`, `MemoryHigh=3G`, `CPUQuota=150%`, `TasksMax=64`. These are **not proposed** — they were
   booted and checked against the live transient scope this session:
   ```
   MemoryMax=3221225472   (3G, matches the cap)
   TasksMax=64
   CPUQuotaPerSecUSec=1.500000s   (150%)
   ```
   A `systemd-run --user --scope` is cleaned up automatically on process exit; it creates no persistent file,
   service, or account, which is why this did not need the owner's prior sign-off under rule 0 — it is as
   reversible as running any other unprivileged command, and only constrains resources the invoking user's
   own QEMU process can already consume.
3. **File-descriptor cap** (`ulimit -n 1024`) applied in the launching shell — `systemd-run --scope` does not
   accept `LimitNOFILE` (it's an exec-context property that only applies to units with their own `ExecStart=`,
   not a scope wrapped around an already-running process; this was discovered by trying it and getting
   `Unknown assignment: LimitNOFILE=1024`, not assumed).
4. **If `systemd-run --user` is unavailable** (e.g. a minimal/non-systemd host), the script does not silently
   drop the caps — it runs unwrapped and prints an explicit `WARNING` to stderr naming the gap.
5. **Already true of the existing `tools/run-echo.sh` this script wraps, re-confirmed by reading it, not
   newly added here**: `-display none` (no GUI/clipboard/USB passthrough surface at all — there is no
   `-usb`, `-device usb-*`, or `-spice`/`-vnc` anywhere in the invocation), `-monitor none` (QEMU's own
   management interface is disabled, not merely unbound), no `-fsdev`/`-virtfs` (no host directory sharing),
   and no attached disk image (the guest boots from `-kernel`/`-initrd` only — there is no QEMU-managed disk
   file that could grow unbounded on the host's already-tight 75 GB free root filesystem).

**What this does and does not protect against**: these caps bound the *QEMU process's* own consumption
(memory, CPU share, thread/process count, open files) regardless of what the seL4 guest inside it does —
this is a host-level backstop independent of (and in addition to) the guest's own internal fault handling.
It does not protect against a QEMU *escape* (a hypervisor bug letting guest code execute as the host user) —
that is a different, much stronger threat than this phase addresses, and is explicitly out of scope: this
project's Attacker Model D (`docs/THREAT_MODEL.md`) already states that host compromise is not something
QEDOS can be protected against from inside the guest.

## Proposed, needs the owner's explicit approval before being applied to the real host

Nothing below has been executed. Each would change real, persistent host state (`useradd`, a systemd unit
file under `/etc/systemd/system/`, an AppArmor profile under `/etc/apparmor.d/`) — exactly the category of
action rule 0 reserves for explicit sign-off, and exactly what the master prompt's §6 says should wait for
approval ("専用のサービスユーザーを設ける設計とし、実際のユーザー作成や権限変更は承認後に行う").

### Dedicated service user (design only)

```
useradd --system --no-create-home --shell /usr/sbin/nologin qedos-press
```
Rationale: isolates the QEDOS Press QEMU process's Unix-level identity from the operator's own account
(`shi3z`, which has `sudo`/`docker`/other group memberships) and from every other service already running on
this shared host. A dedicated, unprivileged, login-disabled system account is the standard least-privilege
baseline for any long-running service process, independent of anything specific to QEDOS.

**Why not created now**: creating a system account is a persistent, if minor, change to the host's user
database, and the master prompt is explicit that this step waits for approval even though it's low-risk —
this document honors that rather than treating "low risk" as equivalent to "pre-approved."

### systemd service unit (design only — not installed)

A draft, for review, of what running QEDOS Press as a real (not ad hoc, foregrounded) service would look
like, *using the already-verified isolated launcher*:

```ini
# PROPOSED — not installed. Would require: useradd above, plus root to install under
# /etc/systemd/system/ and `systemctl daemon-reload` + `enable` + `start`.
[Unit]
Description=QEDOS Press (isolated QEMU/KVM instance)
After=network.target

[Service]
Type=simple
User=qedos-press
Group=qedos-press
ExecStart=/home/shi3z/git/qedos/tools/run-qedos-press.sh /path/to/loader.img /var/log/qedos-press/serial.log 18443 0
Restart=on-failure
RestartSec=5
# Belt-and-suspenders alongside the script's own systemd-run --scope wrapping (the
# scope wraps the QEMU child; these apply to the unit's own process tree too and
# would be authoritative if the script's internal wrapping were ever removed):
MemoryMax=3G
CPUQuota=150%
TasksMax=64
LimitNOFILE=1024
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# No public network grant in the unit itself — the script's own -netdev restrict=on
# and 127.0.0.1-only hostfwd remain the actual network boundary (see Phase 4).

[Install]
WantedBy=multi-user.target
```
`SECONDS=0` in `ExecStart` would need `tools/run-echo.sh`'s `timeout` wrapping adjusted (it currently always
applies a `timeout`, defaulting to 120s, appropriate for test runs, not a long-lived service) — **not changed
here**, flagged as a real gap: today's launcher is shaped for bounded test runs, not an indefinitely-running
service, and that mismatch needs resolving (likely: pass `0`/omit `timeout` only in the systemd-managed case)
before this unit would actually work as drafted, not just when it's installed.

### AppArmor profile (design sketch only — compatibility not verified)

A confining profile for `qemu-system-x86_64` restricted to this one use (no disk, no display, no USB) would
plausibly deny: writing anywhere outside the designated serial-log path, opening any device node beyond
`/dev/kvm` and `/dev/net/tun` (not even needed here, since networking is pure SLiRP, not TAP) and `/dev/null`,
and any `ptrace`/`mount`/network-raw capability. **This was not written as an installable profile and its
compatibility with this host's actual QEMU 6.2.0 + KVM invocation was not test-booted under `aa-complain`.**

`sudo aa-status` (read-only, run this session) confirms: AppArmor is loaded and enforcing on this host
(48 profiles, 47 in enforce mode — `mysqld`, `slapd`, Docker's `docker-default`, several snap/NetworkManager
profiles, etc.), but **no `qemu-system-x86_64` (or similarly-named) profile is present at all** — QEMU on
this host currently runs completely unconfined by AppArmor, regardless of who invokes it. Ubuntu does ship
an optional `qemu-system-x86` AppArmor profile package in some configurations; it is not installed here. This
means the sketch above would be a net-new profile, not a tightening of an existing one, and should be
developed and tested under `aa-complain` (logs violations without enforcing) before ever being switched to
`aa-enforce` — not attempted this session; flagged as unfinished design, not a completed deliverable.

## Summary against the master prompt's §6 checklist

| requirement | status |
|---|---|
| QEMUをrootで実行しない | **Done** — hard refusal in the launcher, verified |
| 専用のサービスユーザー | Designed, **not created** (needs approval) |
| VMメモリ容量の上限 | **Done** — `-m 2G` (pre-existing) + `MemoryMax=3G` scope cap, verified live |
| vCPU数の上限 | **Done** — no `-smp` (1 vCPU default, pre-existing) + `CPUQuota=150%`, verified live |
| プロセス数の上限 | **Done** — `TasksMax=64`, verified live |
| ファイルディスクリプタ数の上限 | **Done** — `ulimit -n 1024` in the launcher |
| ディスク使用容量の上限 | **N/A as currently built** — no QEMU-managed disk image exists (kernel+initrd boot only); revisit if a disk is ever added |
| 不要なデバイスの無効化 | **Already true** (re-confirmed) — no USB/clipboard/GUI device lines in the existing invocation |
| QEMU管理インターフェースの非公開 | **Already true** (re-confirmed) — `-monitor none` |
| ホストディレクトリ共有の禁止 | **Already true** (re-confirmed) — no `-fsdev`/`-virtfs` |
| クリップボード・USB・GUI共有の禁止 | **Already true** (re-confirmed) — `-display none`, no USB/SPICE/VNC |
| AppArmor/systemd sandboxing検討 | systemd unit **drafted**; AppArmor **sketched only** — host confirmed enforcing (47/48 profiles) but has **no existing QEMU profile** to build on; a new profile needs `aa-complain` testing before enforce |
