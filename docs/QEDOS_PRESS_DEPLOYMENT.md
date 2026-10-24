# QEDOS Press — deployment phase log

Mission: build a CMS ("**QEDOS Press**") as a new PD inside QEDOS, eventually exposed over HTTPS from an
Ubuntu host via QEMU/KVM, without weakening the host's existing security posture. Full rules: the owner's
"QEDOS CMS — Zero-Trust Deployment & Migration Master Prompt". Phase numbering below matches that prompt.

## Phase 0 — absolute rules

No firewall/routing/network-interface/host-service change has been made or will be made without the owner's
separate explicit approval. Every action below is read-only investigation, in-repo source changes, or local
(127.0.0.1-bound, non-public) QEMU runs.

## Phase 1 — Ubuntu host audit

See `SECURITY_BASELINE.md` at the repo root. Summary of the result this phase depends on: the host's public
NIC (`enp3s0f1`) already drops all new inbound connections except over the Tailscale mesh; TCP 443/80 are
free; the host is shared/multi-tenant, so any firewall change is a shared-risk action requiring separate
sign-off. Conclusion reached there: local-only development (this phase and the next) needs no host network
change at all.

## Phase 3 — existing QEDOS architecture (what QEDOS Press builds on)

Current data flow (implemented, tested — `tests/test_sel4.py`/`test_script_sel4.py`):
```
ethernet_driver → tcp_pd (lwIP, :8443) → tls_pd (OpenSSL 3.6.1, sole tls_keystore holder, LAW_008)
  → http_pd (no_std Rust parser) → policy_pd (Ed25519-verified route/backend table)
      → connector_pd → tcp_pd → fixed backend IP:port   (dynamic proxying — the only path that exists today)
      → script_pd (optional, QEDOS_SCRIPT=1 build flag) → Wasm interpreter
```
**Nothing in the existing system serves static content.** Every existing PD either proxies to a host-side
backend or runs a Wasm module; QEDOS Press needs a genuinely new PD, not an extension of one. QED Script is
off by default (opt-in build flag) and is independent of QEDOS Press — QEDOS Press's initial static-only
version does not need it and will not enable it.

Wiring mechanics confirmed for adding the new PD safely (`sel4/meta_proofgate.py` + `security/cap-policy.json`):
a new `ProtectionDomain`, two new narrow shared-memory regions (request-in / response-out) rather than reuse
of `shm_policy_script`, a cap-policy.json entry declaring exactly its signal set (`http_pd`,`policy_pd`) and
no secret-region map, no IRQ/I/O-port, content mapped read-only — `scripts/capgraph.py` will fail the build
if the generated CapDL authority and this declaration disagree, in either direction. `policy_pd` needs a new,
deliberately-added dispatch branch (e.g. `GET /press/*`); nothing auto-discovers new PDs.

**Gap found in the existing test tooling, fixed in phase 4 below, not before**: `tools/run-echo.sh`'s callers
(`tests/test_sel4.py`, `tests/test_script_sel4.py`, `tests/perf_script.py`) all build their QEMU `hostfwd`
string as `hostfwd=tcp::PORT-10.0.2.15:8443` — no explicit host bind address (QEMU defaults this to `0.0.0.0`)
and no `restrict=on`. This is adequate for a local dev-only test loopback on a trusted machine but is not a
safe template to copy for anything host-exposed, and was not modified — it remains as-is for those tests'
own existing purpose; QEDOS Press uses its own launcher instead (below).

## Phase 4 — QEMU isolation configuration, designed and empirically verified

New file: `tools/run-qedos-press.sh`. Wraps the existing `tools/run-echo.sh` (unchanged) with:
```
-netdev user,id=netdev0,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:<HOST_PORT>-10.0.2.15:8443
```
* `restrict=on` — the guest's SLiRP network cannot reach the external network or the host's other
  interfaces/LAN; only SLiRP's internal DHCP/DNS stub and the one explicit `hostfwd` rule are reachable.
* `ipv6=off` — no IPv6 path out of the guest.
* The host side of `hostfwd` is bound to `127.0.0.1` explicitly. This is the one bug this script exists to
  prevent: QEMU's hostfwd binds `0.0.0.0` (every host interface) when no host address is given, which is
  exactly the pattern the mission's incident history warns about.

### Verification performed (this session, local-only, non-public — `build/sel4/loader.img`, the existing
default image; no new image was built for this)

1. **Host listen-socket scope**: booted with `run-qedos-press.sh ... 18443`, then `ss -lntp`:
   ```
   LISTEN 127.0.0.1:18443  (qemu-system-x86)
   ```
   Bound to `127.0.0.1` only — confirmed by direct inspection, not inferred.
2. **Reachability from other host addresses**: with the VM running, `/dev/tcp` connect attempts to the same
   port on the host's LAN IP (`192.168.2.111`) and public IP (`219.104.122.252`) both got **connection
   refused** immediately (nothing listens there) — `127.0.0.1` itself connected successfully.
3. **Forwarded path actually reaches the guest**: `openssl s_client -connect 127.0.0.1:<port>` reached the
   guest's TLS layer (got an SSL alert, not a connection failure) — confirms the hostfwd path is live end to
   end, not merely "a socket exists". The alert itself (`handshake failure`) is `tls_pd` correctly rejecting
   a classical-only `openssl` client because the existing system requires TLS 1.3 with the PQ-hybrid group
   X25519MLKEM768 (`docs/SECURITY.md`'s LAW_008 scope) — an expected, pre-existing policy, not a defect found
   by this verification.
4. A script bug was found and fixed during this verification: the first draft of `run-qedos-press.sh` passed
   `user,id=netdev0,` twice (once from this script, once already added inside `run-echo.sh`), which QEMU
   rejected outright (`Invalid parameter 'user'`) — fail-closed (QEMU refused to start) rather than silently
   running unisolated, but corrected immediately rather than left as a latent trap.

### Guest-to-host outbound blocking under `restrict=on` — verified (A/B test, this session)

The item above ("not independently exercised from inside the guest") is now closed for the one real
guest-initiated outbound path this system has: `connector_pd` dialing its fixed backend table, which in the
existing default build targets `10.0.2.2:19001`/`19002` — SLiRP's magic alias for the host itself (used
by `tests/test_sel4.py`'s SEL4_004, which proxies to `tests/backend.py` listening on `127.0.0.1:19001`).
Per QEMU's own documentation, `restrict=on` specifically blocks the guest from contacting the host and from
having any guest IP packet routed out through the host; it does not affect inbound `hostfwd` redirections.
This makes the existing backend-dial mechanism a direct test of that exact property — no rebuild, no new
probe, no production config touched.

**Procedure** (A/B, same unmodified `build/sel4/loader.img`, same `tests/backend.py`, only the launcher
differs):
1. **Positive control** — booted via the existing `tools/run-echo.sh` with no `restrict` (the same
   unrestricted invocation `tests/test_sel4.py` itself uses), sent the same `POST /api/chat` request used by
   that suite's SEL4_004 over the loopback hostfwd. Result: `HTTP/1.1 200 OK`, body
   `{"backend": "A", ..., "host": "10.0.2.2:19001", ...}` — confirms the probe genuinely reaches the host
   backend when nothing blocks it.
2. **Real test** — reset the backend's request log, booted the identical image via `tools/run-qedos-press.sh`
   (`restrict=on,ipv6=off`), sent the identical request over its loopback hostfwd. Result: `HTTP/1.1 502 Bad
   Gateway`, empty body, connection cleanly closed — a definite failure signal from `connector_pd`, not a
   hang. Queried the backend's own `/__log__` endpoint directly afterward: **`[]` — zero connections ever
   reached the host-side listener.** This is independent, host-side evidence (not just "the client saw an
   error"): the backend process itself never saw the attempt.
3. DHCP lease acquisition (SLiRP's internal service) still succeeded under `restrict=on` in the same run,
   confirming the guest boots and runs normally — the 502 is specifically the blocked *outbound-to-host*
   connection, not a general guest malfunction under restriction.

**Scope of what this proves, stated precisely**: this confirms guest→host blocking (the `10.0.2.2` path),
which is the same `restrict=on` mechanism QEMU's documentation states also covers guest→real-LAN and
guest→internet (SLiRP enforces this as one feature, not three separately-configured ones) — but this test
did not independently exercise a *second*, different destination (e.g. a real address on `192.168.2.0/24`)
to confirm that sub-case directly, since the system's only guest-initiated egress today happens to resolve
to the host alias. That remaining narrower gap is now the accurate statement of what's untested, replacing
the broader "not exercised at all" from before this session.

### Still not independently verified

* The guest→real-LAN/guest→internet sub-cases of `restrict=on` specifically (as opposed to guest→host,
  closed above) — would require `connector_pd`'s backend table to target a non-`10.0.2.2` address, which the
  current build doesn't do; not pursued since it is the same single QEMU mechanism already shown to engage.
* This used the pre-existing default image, not a QEDOS-Press-carrying image — the isolation properties
  shown here (both this test and the earlier socket-binding ones) are about the *launcher*, independent of
  which PD set is inside; Phase 5 (below) since added the actual `qedos_press_pd` and re-ran its own full
  test suite, but did not re-run this specific egress A/B test against that image (not expected to differ,
  since `connector_pd`/the backend table are unchanged by Phase 5 — but stated plainly as not re-run, not
  assumed).

## Phase 5 — the QEDOS Press PD itself

Implemented. Full detail (architecture, bundle format, read-only enforcement, assurance levels, the
explicit no-supervisor gap) is in `docs/QEDOS_PRESS_CMS.md`. Summary of what changed and what was
verified, in this document's own style:

* New opt-in PD `qedos_press_pd` (`QEDOS_PRESS=1`, independent of `QEDOS_SCRIPT=1` — both build flags
  combine cleanly; a combined build was run and its capability audit passes for both subjects).
* `scripts/capgraph.py --subject qedos_press_pd` against the actual built image: **A1–A7, C1–C8 all
  PASS** (no secret region, no IRQ/ioport, no TCB/Untyped/CNode caps, signals exactly `{http_pd,
  policy_pd}`, independently re-derived by Z3 Datalog, same method as `docs/CAPABILITY_AUDIT.md`).
* Content read-only enforcement verified directly (`llvm-readelf -l`: the `.press_bundle` ELF segment
  has no write flag), not merely asserted — a narrower, simpler mechanism than the `tls_keystore`
  shared-`MemoryRegion` pattern first considered, chosen because investigation found Microkit's
  `MemoryRegion` API has no mechanism to pre-load an anonymous region's content from an ELF section.
* Real end-to-end QEMU test (`tests/test_press_sel4.py`, PRESS_001–007, 7/7 pass): TLS 1.3 +
  X25519MLKEM768 handshake, `GET /press/index.html` → 200 with the exact signed bytes, unknown path →
  404, `POST` on a known path → 405, `HEAD` → 200 with correct `Content-Length` and no body, existing
  `/health` proxy path unaffected.
* Regression-checked: `tests/test_sel4.py` (6/6) and `tests/test_script_sel4.py` (11/11) both re-run
  after this work and both still pass unchanged — this PD's addition did not touch any existing
  behavior outside new `#ifdef QEDOS_PRESS` branches.
* Stated gap, not hidden: no supervisor/watchdog restarts `qedos_press_pd` on crash/hang this phase
  (deliberate, narrower choice — this PD runs no untrusted code, unlike `script_pd`).
* Explicitly out of scope this phase (per the master prompt's own phasing): online/updatable releases,
  authentication, anti-rollback. The dev Ed25519 signing key generated for this
  (`config/keys/qedos-press-dev-seed.hex`) is not production-grade, same caveat as the existing QED
  Script dev signing key.

## Phase 6+ — not started

Online/updatable releases, authentication, the eventual public-exposure phase (mission phase 7) and its
required owner sign-off are future phases. This document will grow with them rather than be replaced.
