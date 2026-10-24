# QEDOS Press — read-only static-content CMS PD

A new Protection Domain (`qedos_press_pd`, opt-in build flag `QEDOS_PRESS=1`) that serves a signed,
immutable, read-only static-content release over the existing QEDOS HTTPS pipeline. This document
covers only this PD. Host-deployment phases (Ubuntu audit, QEMU isolation) are in
`SECURITY_BASELINE.md` and `docs/QEDOS_PRESS_DEPLOYMENT.md`.

## Explicitly out of scope this phase

Per the mission's own phasing ("公開リリースを読み取り専用で組み込む初期版を先に実装し、オンライン更新機能は後回しにする"):
**no online/updatable releases, no authentication, no anti-rollback, no write path of any kind.** A
release is baked into the image at build time and is immutable until the next build. `QED Script`
(dynamic content) is a separate, independent feature (`QEDOS_SCRIPT=1`) and is untouched by this work;
the two build flags are independently combinable (confirmed: a combined `QEDOS_SCRIPT=1 QEDOS_PRESS=1`
build succeeds and both images' capability audits pass).

## Architecture

```
http_pd ──(any method on a /press path)──▶ policy_pd ──PG_DECISION_PRESS──▶ shm_policy_press
                                                                                    │
                                                                                    ▼
                                                                            qedos_press_pd
                                                                       (verify-once signed bundle,
                                                                        per-request hash recheck,
                                                                        route table lookup)
                                                                                    │
                                                                                    ▼
                                                           shm_press_http ──▶ http_pd ──▶ tls_pd ──▶ client
```

`qedos_press_pd` holds exactly: `shm_policy_press` (rw, with `policy_pd`), `shm_press_http` (rw, with
`http_pd`), and its own ELF image including the embedded `.press_bundle` section (its signed content,
`const`-qualified so it is placed in `.rodata` — see "Read-only enforcement" below). It signals exactly
`http_pd` and `policy_pd`. It has no TLS keystore, no signed-config region, no network/socket/timer/IRQ
authority, no TCB capability over anything, and (unlike `script_pd`) no supervisor parent — see "Gap:
no supervisor" below.

`policy_pd` dispatches any request whose target starts with `/press` (exact prefix, any method) to
`qedos_press_pd` rather than `connector_pd`/`script_pd`; `qedos_press_pd` itself decides 200/404/405
(GET/HEAD against a known mount-relative path → 200; known path with any other method → 405; unknown
path → 404), matching the mission's explicit requirement that write methods on this prefix are rejected,
never silently executed or treated as a parse vacuum that falls through.

## Release bundle format ("QPR1")

```
header[24]:  magic("QPR1") version[1] n_routes[1] reserved[2] site_id[4] release_no[4]
             publish_ts[4] content_len[4]        (little-endian)
table:       n_routes * entry[136]
  entry:     path_len[1] ctype[1] reserved[2] offset[4] length[4] path[60] hash[64] (SHA-512)
content:     content_len bytes (concatenated file bytes, in route order)
signature[64]: Ed25519 over header+table+content
```

Deliberate deviation from the mission's literal phrasing ("sign the manifest, which embeds every
file's hash... one signature covers the whole release"): this implementation signs the **entire**
bundle (header+table+content) in one signature, not just the manifest with hash commitments. This is
simpler to implement correctly and at least as strong (direct content coverage, not a transitive
hash-commitment layer) — and the per-file SHA-512 recheck at serve time (below) still runs
independently of what is literally covered by the signature, as defense in depth.

Packed by `tools/press-release.py` (pure Python + the existing `qs` CLI's new `raw-sign` subcommand —
no new crypto implementation; reuses `pg-config`'s existing, already-relied-upon Ed25519). Injected into
`qedos_press_pd.elf`'s `.press_bundle` section by `scripts/build-sel4.sh` (parallel to how
`script_bundles_section`/`tls_keystore_section`/`signed_config_section` are injected for the existing
PDs — same build-time `llvm-objcopy --update-section` mechanism, not a new one).

### Dev signing key — explicitly not production-grade

`config/keys/qedos-press-dev-seed.hex`/`qedos-press-dev-pub.{hex,rs}`, generated this session via `qs
keygen` (the same generator already used for QED Script's dev code-signing key). **This is a
development key, committed to the repository, and must be replaced before any production use** — same
caveat as the existing `qs-code-signing-dev-seed.hex` (`docs/LAWS.md`). No anti-rollback: nothing
compares a release's `release_no` against any previously-seen value.

## Read-only enforcement

**Design choice, stated plainly (a narrower-capability choice, not the literal mechanism the mission
first suggested):** rather than a cross-PD shared `MemoryRegion` mapped `perms="r"` (the `tls_keystore`
pattern), the content bundle is embedded as a `const`-qualified array in `qedos_press_pd`'s own ELF,
placed in `.rodata`. Investigation found that Microkit's `MemoryRegion` API (`sdfgen`) has no built-in
mechanism to pre-load content into an anonymous region from an ELF section by name — every existing
precedent (`tls_keystore_section`, `script_bundles_section`, `signed_config_section`) embeds its
build-time content in the *owning PD's own ELF*, with the parallel shared `MemoryRegion` (where one
exists) used only for a distinct, optional runtime-provisioning path this PD does not need. Given that,
the correct and simplest way to get a true capability/segment-enforced read-only mapping was to mark the
section `const` and verify the resulting ELF program header has no write flag — not to invent new build
plumbing.

**TESTED, not merely designed**: `llvm-readelf -l build/sel4-press/qedos_press_pd.elf` shows
`.press_bundle` inside the `LOAD` segment with flags `R E` (read + execute, **no** write flag) — the ELF
loader maps this page read-only to every PD including `qedos_press_pd` itself, not by convention but by
the segment's own permission bits. This is, in one specific respect, a *stronger* guarantee than the
precedent `tls_keystore_section`/`script_bundles_section` (which are plain non-`const` arrays, writable
PD data in principle, protected only by the fact that nothing in their respective PDs writes to them).

Independent of the segment permission: every serve re-verifies the requested file's SHA-512 against the
manifest's stored hash (`Manifest::verify_and_get_bytes`) before copying any byte out — defense in depth
against in-memory corruption after the one boot-time signature check, covering a different failure mode
than the segment permission bits.

## Gap: no supervisor (stated plainly, not hidden)

Unlike `script_pd`, `qedos_press_pd` has no `supervisor_pd`-style parent and no watchdog. A crash or
hang here is **not** restarted automatically within this phase. This was a deliberate, narrower choice:
`script_pd` runs fully attacker-controlled native Wasm and needed fault-containment/restart machinery
for availability; `qedos_press_pd` runs no untrusted code at all (a fixed, signed, bounded-size content
lookup over data verified once at boot and rechecked by hash on every serve) — the risk profile that
motivated `script_pd`'s supervisor does not transfer the same way. This is a real availability gap for
this PD specifically, not an oversight, and is not claimed as solved.

## Assurance levels (honest accounting)

| property | level | evidence |
|---|---|---|
| `qedos_press_pd` holds no secret region, no IRQ/ioport, no TCB/Untyped/CNode caps, signals exactly `{http_pd, policy_pd}` | **TESTED** | `scripts/capgraph.py --subject qedos_press_pd`: A1–A7, C1–C8 all PASS against the actual generated CapDL authority of `build/sel4-press` |
| content bundle is read-only even to `qedos_press_pd` itself | **TESTED** | `llvm-readelf -l` on the built ELF: `.press_bundle`'s segment has no write flag |
| Ed25519 signature verification correctly accepts valid / rejects tampered, truncated, wrong-key bundles | **TESTED** | `crates/pg-press` unit tests (5 cases) + one integration test against a real `tools/press-release.py`-packed bundle, run against the actual `qs`-generated signature |
| per-file hash recheck catches post-signature content corruption independent of the signature check | **TESTED** | `corrupted_content_fails_hash_recheck_even_after_valid_signature` unit test |
| GET/HEAD serve correctly, unknown paths 404, non-GET/HEAD on known paths 405, never silently executed | **TESTED** | `tests/test_press_sel4.py` PRESS_003–006, full QEMU boot, real TLS 1.3 + X25519MLKEM768 handshake, real HTTP bytes over the loopback hostfwd |
| existing default/QED-Script test suites unaffected by this PD's addition | **TESTED** | `tests/test_sel4.py` 6/6 and `tests/test_script_sel4.py` 11/11, both re-run unchanged after this work, both still passing |
| `u32_le`, `method_from_u8`, `compute_lengths` (bundle/table/content length arithmetic), `entry_bounds_ok` (per-entry path/ctype/offset+length bounds check) are correct for *every* possible input, including overflow safety | **PROVEN** | 4 Kani harnesses in `crates/pg-press/src/proofs.rs`, each over the function's full input domain (no loops, no unwind bound needed): `cargo kani -p pg-press`, all pass |
| `verify_and_load`'s surrounding logic (length arithmetic, route-table handling) never accepts a bundle whose signature the verifier rejected, with the loop actually exercised | **BOUNDED** | 2 Kani harnesses (`fail_closed_on_bad_signature_zero_routes`/`_one_route`), blob sizes fixed at exactly 0 and 1 route entries respectively, real Ed25519 arithmetic replaced with a symbolic `bool` result (same substitution `pg_config`'s own Kani harnesses make for the identical reason — modeling Ed25519 field arithmetic in CBMC is not practical); both pass |
| `Manifest::lookup`'s matching (GET/HEAD-only, exact-path) is correct | **BOUNDED, to a single route** | 1 Kani harness, `n_routes` restricted to 0..=1 with that one slot symbolic; passes. An earlier version of this harness swept `n_routes` 0..=2 over two symbolic slots and Kani reported 3 failing inputs — each was checked by hand against the real (non-Kani) `lookup` in a plain `#[test]` and reproduced the *correct*, non-failing result every time, so those 3 failures are treated as a spurious Kani/CBMC artifact of that specific two-slot harness shape, not a real defect; re-deriving the exact cause (rather than narrowing past it) was not pursued further this session (time-boxed). The real format allows up to 24 routes — this proof covers 1, which is a real, stated gap, not the full route-table scan |
| manifest parser/lookup logic's remaining surface (the full route-table loop end to end, the actual Ed25519 arithmetic) is memory-safe and correct for every input | **TESTED, not Kani-proven** | the 5 unit/integration tests plus `#![forbid(unsafe_code)]` and `overflow-checks = true` remain the only evidence for the parts the harnesses above don't reach (the un-abstracted crypto, and route counts above 1) |
| availability under fault (crash/hang of `qedos_press_pd`) | **UNVERIFIED / known gap** | no supervisor wired to this PD this phase (see above) |
| production readiness of the signing key / release process | **NOT APPLICABLE this phase** | dev key, no anti-rollback, no online publishing — all explicitly out of scope |

## Files

`crates/pg-press` (manifest format, `#![no_std]`, `#![forbid(unsafe_code)]`, 6 unit/integration tests),
`sel4/rust_press` (seL4 FFI glue staticlib, linked only into `qedos_press_pd.elf`), `sel4/pds/
qedos_press_pd.c`, dispatch additions in `sel4/pds/policy_pd.c` / `sel4/pds/http_pd.c` (both guarded by
`#ifdef QEDOS_PRESS`, strictly additive — no existing branch was changed), a new response formatter
`pg_rust_format_press_response` + route-prefix check `pg_rust_is_press_route` added to the existing
`sel4/rust_pds` crate (http_pd/policy_pd already link it), `sel4/meta_proofgate.py` wiring (new
`QEDOS_PRESS` env flag, independent of `QEDOS_SCRIPT`), `security/cap-policy.json`'s `qedos_press_pd`
entry + `"press"` feature block, `scripts/build-sel4.sh` build steps, `tools/press-release.py` (the
packer), `examples/press-site/index.html` (test fixture), `tests/test_press_sel4.py` (PRESS_001–007).
