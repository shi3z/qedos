# QEDOS Press admin tool — login, draft editing, and verified deployment, outside the seL4 TCB

The user asked for QEDOS Press to work like an actual CMS: login and content editing. Adding
those directly to `qedos_press_pd` (or any other seL4 PD) was rejected: that PD is deliberately
read-only, holds no secrets, and has no write path (`docs/QEDOS_PRESS_CMS.md`), and this
project's standing rule is to never give it capabilities beyond its documented minimum. Instead,
everything "CMS" happens in `tools/press-admin.py`, an ordinary Python process on the host,
entirely outside the seL4 Trusted Computing Base. It never touches `tls_pd`/`tls_compat_pd`/
`press_pq_pd`/`qedos_press_pd` source, and the seL4 image it builds from is produced by the
unchanged `scripts/build-sel4.sh` pipeline.

## The signing-key boundary (the design actually shipped, after a mid-flight correction)

An earlier version of this tool encrypted the Ed25519 signing private key at rest on this host
(AES-256-GCM, passphrase-derived key) and decrypted it in memory for just the duration of a
publish. **That design was rejected and removed before shipping.** The reason: this host is a
shared, public, internet-facing, multi-tenant machine, and its own compromise has to be in the
threat model — a passphrase-protected key sitting on a compromised host can still be captured the
moment it's decrypted for use. Encryption-at-rest protects against someone who merely reads the
disk; it does not protect against an attacker with code execution on the box at publish time.

**The actual boundary**: this host holds **no Ed25519 signing private key material, in any
form, ever.** Signing happens on a completely separate, independent, operator-controlled machine
— a laptop, an air-gapped box, anything that is not this shared host — using
`tools/press-sign-offline.py`. That script's own header is explicit, in large unmissable
comments, that it must never run on the shared QEDOS host or as part of this project's own
automation; it refuses to run non-interactively without an explicit
`--yes-i-am-on-a-separate-machine` flag specifically so no script can invoke real key generation
by accident.

This host holds only the resulting **public** key (`config/keys/qedos-press-prod-pub.hex`, not
committed in this repo, filled in by the operator by hand once they generate a real keypair
elsewhere — until then `press-admin.py` prints a clear warning and nothing can be deployed). The
`tools/press-admin.py` "publish" step was re-scoped from "sign and build" to **verify an
already-signed bundle, then build**:

```
operator's SEPARATE machine                         this shared host
  tools/press-sign-offline.py                          tools/press-admin.py
  (holds the ONLY copy of the                            - verifies Ed25519 signature against
   private seed; never copied here)                        config/keys/qedos-press-prod-pub.hex
        |                                                  (public key ONLY, safe to store here)
        | produces a signed .qpr                         - checks the bundle's release-generation
        v                                                   number against the highest ever
  copy the .qpr file into                                   accepted (rollback/replay protection)
  config/local/press-inbox/ on this host  ------------->  - only if both pass: stages the bytes
  (e.g. scp)                                                verbatim and runs scripts/build-sel4.sh
```

No private key is read, held, or used anywhere in `press-admin.py`. The old on-host
encrypt/decrypt C helper (`tools/press-admin-crypto.c`, AES-256-GCM via the project's own vendored
OpenSSL) was removed entirely rather than left half-wired-in.

### What editing in the web UI is actually for

The `/edit` page (textarea, Save Draft, Preview) is a **staging convenience only** — it writes to
a draft file and lets the operator preview it, but it never signs or publishes anything by
itself. The intended flow: draft here, `/export-draft` to pull the HTML out, sign it properly on
the separate machine with `tools/press-sign-offline.py`, copy the resulting `.qpr` into the inbox
directory, then use the `/inbox` page to verify-and-deploy it. The one *trusted* action this host
performs is verifying a bundle that was signed elsewhere, never producing a signature of its own.

### Rollback / replay protection

Every QPR1 bundle carries a `release_no` (generation number) in its header. `press-admin.py`
tracks the highest generation number it has ever accepted in a small, non-secret, host-local
state file (`config/local/press-admin-last-generation`) and rejects any bundle whose generation is
**not strictly greater**, even if its signature verifies perfectly (`tests/test_press_admin.py`'s
ADMIN_005 proves this: a validly-signed, lower-generation bundle is rejected and never triggers a
rebuild). This stops an old, validly-signed release from being replayed to roll the site back to
previously-published content. **What it does not do**: it says nothing about whether a public key
was ever the *right* one to trust in the first place — if the wrong public key is ever installed
at `config/keys/qedos-press-prod-pub.hex`, every bundle signed by its matching private key will
verify "successfully" against it. Trusting the right public key's provenance (generating it
properly on a separate machine, copying only that file, verifying you copied the right one) is the
operator's responsibility, not something this mechanism can check for them.

### A real gap found and left open: `qedos_press_pd`'s verification key is still compile-time-fixed

While testing the accept flow end-to-end (actually booting the built image, not just checking
that `build-sel4.sh` exits 0), a genuine architectural gap surfaced: `sel4/rust_press/src/lib.rs`
pins `PRESS_PUBLIC_KEY` as a **compile-time Rust constant** (currently the committed dev key —
see `docs/QEDOS_PRESS_CMS.md`), completely independent of whatever public key
`press-admin.py`'s host-side pre-check is configured against. A bundle that passes
`press-admin.py`'s verification (because it was signed with, say, a brand-new "production" key)
will still be rejected *inside* the booted seL4 image at `qedos_press_pd`'s own boot-time
signature check, because that check trusts a different, hardcoded key entirely
(`tests/test_press_admin.py`'s ADMIN_006 works around this by deliberately using the project's
*existing* dev keypair for that one boot-confirmation test, not a fresh "production" key, and
says so in a comment).

This was **not fixed** as part of this work — doing so would mean editing `sel4/rust_press/src/lib.rs`
and/or `scripts/build-sel4.sh`'s injection step, i.e. seL4 PD-side Rust/build code, which was
explicitly out of scope for this directive (no seL4 PD code changes). Until it is addressed, a
*real* production deployment using a freshly-generated offline keypair would need that constant
updated to match (the same kind of build-time constant substitution already used for
`tls_keystore`/`press_bundle`/`pq_keystore` injection, just not yet wired up for this one). Until
then, this admin tool's verification step is real and correctly implemented, but a genuinely new
production key pair would currently need that additional, not-yet-built wiring to also change what
the booted image itself will accept.

## TOTP two-factor login

Separately from the signing-key boundary above (this protects "who can trigger a deploy", not
"where signing happens"), logging into the admin web UI requires both the configured password
*and* a current 6-digit TOTP code (RFC 6238, HMAC-SHA1, 30-second step — the exact algorithm
every standard authenticator app already implements, so the operator adds this to whatever app
they already use; no custom scheme). Implemented with stdlib `hmac`/`hashlib`/`struct` only —
Python has no TOTP library in the standard library, and the rule for this tool throughout is no
new pip dependency.

Enrollment: `python3 tools/press-admin.py --enroll-totp` generates a random 160-bit secret,
writes it (base32-encoded) to `config/local/press-admin-totp` (gitignored, `chmod 600`), and
writes a **local-only** HTML file (not served over any network) containing a QR code for the
`otpauth://totp/...` enrollment URI, rendered client-side by a vendored, pinned, MIT-licensed pure
JS QR generator (`third_party/qrcode-generator/`, kazuhikoarase's `qrcode-generator` 1.4.4 —
chosen the same way `third_party/noble-post-quantum/` was vendored earlier this session: small,
well-known, pinned, LICENSE included, npm tarball kept for provenance). The operator opens that
file in a local browser and scans it with Google Authenticator / Authy / 1Password / any standard
TOTP app, then deletes the file. The otpauth URI is also printed as plain text, for manual entry
as a fallback if scanning isn't convenient.

Verification allows a narrow ±1 step (±30s) window for clock skew, using `hmac.compare_digest`
for constant-time comparison, same discipline as the password hash and CSRF token checks.

## Other security properties (unchanged from the original design)

- **Auth**: single admin account, PBKDF2-HMAC-SHA256 password hashing (310,000 iterations, random
  salt), stored at `config/local/press-admin-passwd` (gitignored). `--set-password` sets/replaces it.
- **Sessions**: a signed, HMAC-protected cookie (`hmac`+`secrets`+`hashlib`, no server-side session
  store), 2-hour expiry.
- **CSRF**: every state-changing POST requires a token tied to the session, checked with
  `hmac.compare_digest`.
- **Network exposure**: binds to `127.0.0.1` by default; the tool refuses to assume anything about
  how the operator reaches it remotely (SSH tunnel, Tailscale, etc. are the operator's choice) and
  prints a warning if told to bind elsewhere. This tool is never wired to the public firewall or
  the socat relay that exposes the actual QEDOS Press service — those remain separate, explicit,
  human-approved steps, same as every other live-exposure action this session.
- **Build isolation**: an `--out-dir`/`--site-dir` pointing anywhere other than the real,
  canonical `examples/press-site/` routes the generated `.qpr` through its own scratch path
  (`scripts/build-sel4.sh`'s new `QEDOS_PRESS_QPR`/`QEDOS_PRESS_SITE_DIR` env var overrides,
  additive, default-unchanged) so test/isolated runs can never corrupt the committed
  `config/dev/press-release.qpr` or any currently-running production image's build directory.

## Verification performed

- `tests/test_press_admin.py` (ADMIN_001–006, all independently re-run and passing): unauthenticated
  rejection, wrong password / wrong TOTP / wrong CSRF all rejected, draft staging never mutates the
  real site file, a bundle signed with the wrong key is rejected, a lower-generation validly-signed
  bundle is rejected as rollback with no rebuild attempted, and the accepted bundle's freshly-built
  image actually boots and serves the exact signed content over a real TLS1.3 connection.
- `tools/press-sign-offline.py` tested only in throwaway scratch directories, confirming keygen and
  sign both work and produce a bundle `press-admin.py` can correctly verify or correctly reject —
  never run for, or treated as, a real production key.
- No private key bytes of any kind (test or otherwise) are printed, logged, or committed anywhere;
  confirmed by grepping test output.
- Existing regression suites (`test_sel4.py`, `test_script_sel4.py`, `test_press_sel4.py`,
  `test_press_concurrent_sel4.py`, `test_press_compat_sel4.py`) are unaffected — this feature adds
  new files and one small additive env-var override in `scripts/build-sel4.sh`, touching no
  existing seL4 PD source.

## What this does and does not mean

This gives the operator real login-gated draft editing and a safe, verified deployment path for
already-signed content, without this shared host ever holding signing authority. It does **not**
mean a production key exists yet (none is committed; `config/keys/qedos-press-prod-pub.hex` must
be filled in by the operator after running `tools/press-sign-offline.py` elsewhere), and it does
**not** close the `PRESS_PUBLIC_KEY` compile-time-constant gap described above — that remains
real, separate follow-up work.
