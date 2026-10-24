# QEDOS Press — a separate, narrower-assurance TLS compatibility endpoint

## Why this exists

QEDOS Press's `tls_pd` enforces TLS 1.3 only (LAW_002) and exactly one key-exchange group,
`X25519MLKEM768` (LAW_003) — a post-quantum hybrid. This is a deliberate, central security claim
of the project, and this session's standing rule has been to never weaken an existing LAW.

A real device was tested against the live, publicly-reachable QEDOS Press endpoint: an iPad's
Chrome browser, which (like every iOS browser) is required by Apple to use WebKit's networking
stack, not its own. The connection failed with a TLS protocol error. To find the real cause rather
than guess, the actual ClientHello was captured with `tcpdump` on loopback (between the socat
relay and the local QEMU instance) and parsed by hand (`supported_groups` / `key_share` TLS
extensions). The result: this device's WebKit TLS stack offers only classical groups —
`x25519`, `secp256r1`, `secp384r1`, `secp521r1` (plus GREASE) — and **no PQ group at all**. There
is no shared group with `tls_pd`'s strict allow-list, so the handshake fails immediately; this is
not a HelloRetryRequest bug, because there is nothing to retry with. Apple's TLS stack, as of this
device's OS version, simply does not yet offer a post-quantum hybrid key exchange.

## What was built

A new, separate Protection Domain, `tls_compat_pd` (`sel4/pds/tls_compat_pd.c`), built only into a
new opt-in image flavor, `QEDOS_PRESS_COMPAT=1` (own output directory,
`build/sel4-press-compat/`, own launcher `tools/run-qedos-press-compat.sh`). It is a close copy of
`tls_pd.c` with exactly one policy difference:

| | `tls_pd` (unchanged, every other image) | `tls_compat_pd` (only in `QEDOS_PRESS_COMPAT=1`) |
|---|---|---|
| TLS version | 1.3 only | 1.3 only (unchanged) |
| Cipher | `TLS_AES_256_GCM_SHA384` only | `TLS_AES_256_GCM_SHA384` only (unchanged) |
| Key exchange group | `X25519MLKEM768` only (LAW_003) | `X25519MLKEM768` (preferred), `X25519`, or `P-256` |
| Post-handshake re-check | asserts exactly `X25519MLKEM768` | asserts group is one of the three above |

`tls_pd.c` itself is **not touched** — byte-for-byte identical in every image that doesn't set
`QEDOS_PRESS_COMPAT=1`. The two PDs are never linked into the same image; `QEDOS_PRESS_COMPAT=1`
implies `QEDOS_PRESS=1` and reuses the rest of the already-verified press chain (`http_pd`,
`policy_pd`, `connector_pd`, `qedos_press_pd`) completely unchanged.

This is explicitly **not** framed as a general fallback that should replace `tls_pd` for everyone.
It is a narrower-assurance compatibility path, named and reviewable as its own PD, that exists
*alongside* the full-assurance, PQ-only path — a choice the operator makes per deployment (which
image to boot, which host port to expose), not something baked into a single endpoint's behavior.

### A real naming gotcha found while building this

`SSL_CTX_set1_groups_list` and `SSL_get0_group_name` do not use the same casing for every group in
this OpenSSL build: the config-time alias `"X25519"` negotiates fine, but
`SSL_get0_group_name()` reports the negotiated classical groups back as `"x25519"` (lower case) and
`"secp256r1"` (not `"P-256"`), while the PQ hybrid group is reported as `"X25519MLKEM768"` (mixed
case, matching its config name). A first version of the post-handshake check compared against the
config-time names case-sensitively and silently rejected classical handshakes that should have been
accepted — caught by actually booting the image and testing all three groups individually, not
assumed from reading the OpenSSL headers. The fix uses a case-insensitive match against the names
`SSL_get0_group_name` actually returns.

## Capability / verification changes

- `security/cap-policy.json`: no new PD entry was hand-duplicated. `scripts/capgraph.py`'s
  `load_policy()` renames the existing `tls_pd` policy entry (and every other PD's reference to
  it) to `tls_compat_pd` for exactly the one image that contains `tls_compat_pd` instead of
  `tls_pd` — the two PDs have identical priority, channels, and memory maps, so this is a pure
  rename, not a new authority shape to review separately.
- `sel4/meta_proofgate.py`: the `tls_pd` `ProtectionDomain` is now parameterized by
  `QEDOS_PRESS_COMPAT=1` for its name/ELF only; every map, channel, and priority is identical in
  both cases.
- `scripts/build-sel4.sh`: `QEDOS_PRESS_COMPAT=1` selects `tls_compat_pd.c`/`.elf` instead of
  `tls_pd.c`/`.elf` for exactly one build step and the TLS cert/key injection step; everything else
  is unchanged. (A first version of this change set the `QEDOS_PRESS=1` implication as a plain,
  unexported shell variable, which `sel4/meta_proofgate.py` — a separate `python3` subprocess —
  never saw, silently producing a system description with no `qedos_press_pd` at all while the C
  side still compiled press dispatch code for memory that was never mapped. Fixed by exporting it.)

## Verification performed

1. `scripts/capgraph.py --dir build/sel4-press-compat --subject tls_compat_pd --allow-debug-kernel`
   — PASS (A1–A7, B1; C0 "N/A", same as `tls_pd` — it is not a confinement subject).
2. `scripts/capgraph.py --dir build/sel4-press-compat --subject qedos_press_pd --allow-debug-kernel`
   — PASS, identical result shape to the `QEDOS_PRESS=1` image (C1–C8, only the pre-existing D1
   debug-kernel WARN).
3. Booted locally (loopback only, no host network/firewall changes) with the real
   `config/local/qedos-press-prod-{cert,key}.pem` (Let's Encrypt, `qedos.zelpm.com`) injected the
   same way as `tls_pd`:
   - A client offering only `X25519:P-256` (and separately, only `P-256` alone, and only `X25519`
     alone) completes a TLS 1.3 handshake and gets the exact `GET /press/index.html` body, and the
     exact `/` → `301 Location: /press/index.html` redirect.
   - A client offering only `X25519MLKEM768` still works identically to `tls_pd`.
4. Re-ran the full existing regression suites, unchanged, against their own images:
   `tests/test_sel4.py` (6/6), `tests/test_script_sel4.py` (11/11), `tests/test_press_sel4.py`
   (8/8), `tests/test_press_concurrent_sel4.py` (3/3) — all pass, proving this feature is additive.
5. New `tests/test_press_compat_sel4.py` (COMPAT_001–005), including COMPAT_005: re-booting the
   **unrelated, byte-for-byte-unchanged** `build/sel4-press` (`tls_pd`) image and confirming it
   still refuses a classical-group-only handshake — i.e., this compat PD's existence is proven not
   to have weakened `tls_pd`'s own LAW_002/LAW_003 enforcement.

## What this does and does not mean

This gives the operator a second, explicitly-named, independently-auditable TLS policy for QEDOS
Press, for deployments where device compatibility matters more than the PQ-only guarantee. It does
not change what `tls_pd` enforces anywhere it is still used, and it is not on by default — building
and exposing `build/sel4-press-compat` is a separate decision from building and exposing
`build/sel4-press`, including which (if any) public host port either is ever wired to.

Making this new compat endpoint reachable from the public internet — a new socat relay and a new,
narrow firewall rule for whichever host port is chosen — was intentionally left undone by this
work; that is a decision for the human operator to make explicitly, the same way every other live
public-exposure step in this project has required explicit sign-off.
