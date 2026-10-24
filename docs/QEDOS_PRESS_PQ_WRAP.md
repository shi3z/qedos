# QEDOS Press — application-layer ML-KEM-768 envelope over a classical TLS channel

## Why this exists

`docs/QEDOS_PRESS_TLS_COMPAT.md` added `tls_compat_pd`: a separate, narrower-assurance TLS policy
for devices (confirmed for an iPad's WebKit-based browser, via packet capture) that offer no
post-quantum key-exchange group at all. That channel's confidentiality rests entirely on classical
ECDHE, which is vulnerable to "harvest now, decrypt later": a passive adversary recording today's
traffic could decrypt it later if a sufficiently capable quantum computer ever breaks that ECDHE.

This adds a second, independent, application-layer encryption step — ML-KEM-768 encapsulation plus
AES-256-GCM, entirely separate from whatever TLS policy carried the bytes — so the actual `/press/`
content stays confidential against that future-break threat even when the outer TLS channel is
classical. It is **additive**: the existing plaintext `GET /press/*` paths are completely
unchanged, and `tls_pd`/`tls_compat_pd` are untouched by this work.

**What this does not claim.** This does *not* protect against an attacker who can act as a real,
present-day, active man-in-the-middle on the classical TLS connection (e.g. by presenting a
fraudulent but client-trusted certificate) — such an attacker could tamper with or substitute the
PQ public key itself before the browser ever encapsulates against it. The scope here is narrower
and honestly stated: confidentiality of this content against a *future* quantum break of *today's*
recorded classical ECDHE traffic, nothing more.

## Design

```
Browser                                  tls_compat_pd/http_pd/policy_pd           press_pq_pd
  |-- GET /press/pqkey.bin  ------------------------->  (plain GET, qedos_press_pd)
  |<----------------- 1184-byte ML-KEM-768 public key --------------------------------|
  |
  |  ml_kem768.encapsulate(pubkey) -> {cipherText, sharedSecret}
  |  HKDF-SHA256(sharedSecret, salt="", info="qedos-press-pq-v1") -> AES-256-GCM key
  |
  |-- POST /press/pq-fetch ---------------------------------------------------------->|
  |     body = [2B path_len LE][path][1088B ML-KEM-768 ciphertext]                    |
  |                                                           decapsulate -> secret   |
  |                                                           same HKDF -> same key   |
  |                                                           pg_press_handle(path)   |
  |                                                           AES-256-GCM encrypt     |
  |<------------------------- HTTP 200, body = [2B app_status][12B nonce][ciphertext] -|
  |
  |  AES-256-GCM decrypt+verify -> real status + real body
```

- **Server-side secret**: a static ML-KEM-768 keypair. The private key lives ONLY in the new
  `press_pq_pd` PD's `pq_keystore` region (same isolation discipline as `tls_keystore`/LAW_008 —
  read-only, mapped in no other PD, proven by `capgraph.py`'s B1 check). The public key is a normal
  **signed static asset** (`examples/press-site-pq/pqkey.bin`), riding the exact same Ed25519
  signature chain `qedos_press_pd` already verifies for every other file — no new trust mechanism
  was invented for it.
- **Client-side crypto**: `@noble/post-quantum`'s `ml_kem768` (Paul Miller's noble-post-quantum,
  MIT-licensed, audited, pure JS/TS, zero native dependencies beyond `@noble/hashes`), bundled with
  esbuild into one file, vendored at `examples/press-site-pq/vendor/ml-kem768.bundle.js` and
  `third_party/noble-post-quantum/` (LICENSE files + the original npm tarballs, for provenance —
  carved out of the normal `/third_party/*` gitignore rule since it's small and
  security-sensitive, unlike the large toolchains that directory otherwise holds). HKDF and
  AES-256-GCM on the client use the browser's own Web Crypto API (`crypto.subtle`) directly —
  not re-implemented.
- **Server-side crypto**: OpenSSL 3.6.1 (the same freestanding build `tls_pd`/`tls_compat_pd`
  already link), via `EVP_PKEY_decapsulate` (ML-KEM-768), the legacy `EVP_PKEY_CTX`-based HKDF API,
  and `EVP_aes_256_gcm`. **Interop was verified independently, byte-for-byte, before this PD was
  ever wired up**: a throwaway C program using this exact OpenSSL build and a Node script using
  the exact vendored JS library were run side by side, confirming (1) OpenSSL's
  `EVP_PKEY_decapsulate` output equals noble's `ml_kem768.encapsulate` shared secret for the same
  keypair/ciphertext, (2) OpenSSL's HKDF-SHA256 output equals `crypto.subtle.deriveKey` for the
  same inputs, and (3) OpenSSL's AES-256-GCM ciphertext decrypts correctly under
  `crypto.subtle.decrypt`. The HKDF salt is explicitly set to an empty (zero-length) byte string on
  *both* sides, rather than relying on "no salt provided" meaning the same thing in two different
  HKDF implementations (RFC 5869's "HashLen zero bytes" default is implementation-defined whether
  it's literally applied the same way).
- **Wire format choice**: the plan allowed either a query parameter or an AEAD-encrypted field for
  the requested path. This implementation puts the path in the **plaintext** POST body, framed as
  `[2-byte length][UTF-8 path][capsule]`, not a query string — avoiding any need to touch
  `pg-http`'s query-string parsing (which doesn't currently split one out) and keeping the whole
  framing trivial to validate in `policy_pd.c` before ever touching `press_pq_pd`. The path is not
  secret for this public, signed, read-only demo content, so leaving it in plaintext alongside (but
  outside) the encrypted capsule is a defensible, explicitly-stated choice, not an oversight.
- **Response framing**: the outer HTTP status is always `200` — the real application status
  (`200`, `404`, ...) lives *inside* the AEAD envelope (`[2-byte status][12-byte nonce][ciphertext
  || 16-byte tag]`), decoded only after a successful decrypt. This avoids leaking even the
  resource's existence via the outer status code.
- **Garbage/forged ciphertexts**: ML-KEM's decapsulation is defined to *never fail* on its own
  (implicit rejection, FIPS 203) — a garbage-but-correctly-sized ciphertext still "succeeds" and
  produces *some* shared secret, just not one the real client knows. `press_pq_pd` therefore always
  returns a well-formed envelope; the actual rejection of a forged request happens at the client
  (or an adversary without the real shared secret), via the AES-GCM authentication tag failing to
  verify — by construction, not by a branch in this PD. A capsule of the *wrong length* (clearly
  malformed, not a forgery attempt against a real key) IS rejected server-side with a plain `400`,
  before any OpenSSL call.
- **In-flight discipline**: deliberately single-in-flight (one shared `shm_policy_pq`/`shm_pq_http`
  record, not the per-connection-slot array `shm_policy_press`/`shm_press_http` now use) — a second
  concurrent `POST /press/pq-fetch` is shed with `503` while the first is still being processed.
  Same accepted pattern as `shm_policy_conn` (`connector_pd`) and `shm_policy_script` (`script_pd`)
  — see `docs/IPC_VERIFICATION.md`. Chosen deliberately to keep this new, lower-traffic path's
  blast radius small; if real concurrent pq-fetch traffic later justifies it, the same per-slot
  treatment `shm_policy_press` got (see the N=4 starvation fix in a prior commit) could be applied
  here the same way.

## What was built (new/changed files)

- `sel4/pds/press_pq_pd.c` (new) — the PD. Links the existing `pg-press` Rust static lib (reused
  unchanged — the signed-manifest verify/lookup logic is NOT duplicated, only re-linked into a
  second PD) plus OpenSSL, same link pattern as `tls_pd.c`.
- `sel4/include/pg_shm.h` — new section 10 (`pg_shm_policy_pq_t`/`pg_shm_pq_http_t`,
  `PG_PQ_CAPSULE_LEN`, `PG_PQ_BODY_MAX`), new `PG_DECISION_PRESS_PQ`, new `VADDR_*` constants.
- `sel4/meta_proofgate.py` — new opt-in `press_pq_pd` PD (`QEDOS_PRESS_PQ=1`, implies
  `QEDOS_PRESS=1`), its two shared regions, its own `pq_keystore` secret region, and its two
  channels (`policy_pd`↔`press_pq_pd`, `press_pq_pd`↔`http_pd`).
- `security/cap-policy.json` — `pq_keystore` added to the secrets list; new `press_pq_pd` entry
  (same reasoning as `tls_pd`'s for why it has no `interface_pds`: it's a secret *holder*, proven
  isolated by B1, not a subject being confined *away* from one); new `press_pq` feature block.
- `sel4/pds/policy_pd.c` — one new, narrowly-scoped dispatch block: an *exact* `POST
  /press/pq-fetch` match (checked before the general `/press` prefix dispatch) parses the fixed
  wire framing and forwards to `press_pq_pd`; any framing/length violation is rejected with `400`
  before `press_pq_pd` is ever notified.
- `sel4/pds/http_pd.c` — mirrors the existing press-response plumbing: `check_pq_response()`,
  `pq_inflight` (single, not array — see above), dispatch on the new `CH_HTTP_PQ` channel.
- `sel4/rust_pds/src/lib.rs` — `pg_rust_format_pq_response()`: frames the fixed-shape response
  (status always `200`; no caller-supplied string data in any header, only the opaque
  nonce/ciphertext bytes).
- `tools/pq-dump-pubkey.c` (new) — host-side-only helper: given the ML-KEM-768 private-key PEM,
  extracts the raw 1184-byte public key via `EVP_PKEY_get_octet_string_param`, for packing into the
  signed site as `pqkey.bin`.
- `examples/press-site-pq/` (new, separate from `examples/press-site/`) — `index.html` (same
  content), `pqkey.bin`, `pq-client.js` (the real browser-side implementation), and
  `vendor/ml-kem768.bundle.js`. Kept as a **separate** site/bundle from `examples/press-site/`
  specifically so that building a plain `QEDOS_PRESS=1` image (no PQ wrap) is byte-for-byte
  unaffected — it still packs the original, smaller site and still reports `routes=1`, which
  `tests/test_press_sel4.py`'s `PRESS_002` already asserted before this work existed.
- `scripts/build-sel4.sh` — `QEDOS_PRESS_PQ=1` (implies `QEDOS_PRESS=1`, own output directory
  `build/sel4-press-pq`): generates/caches the dev ML-KEM-768 keypair and `pqkey.bin`, packs
  `examples/press-site-pq/` into its own cached `config/dev/press-pq-release.qpr`, compiles/links
  `press_pq_pd.elf`, and injects both the shared press bundle and the `.pq_keystore` section.
- `tests/test_press_pqwrap_sel4.py`, `tests/pq_wrap_node_helper.mjs` (new) — see Verification below.
- `.gitignore` — carved out `/third_party/noble-post-quantum/` from the general `third_party/*`
  exclusion.

## Verification performed

1. **Crypto interop, independently, before any PD wiring**: OpenSSL `EVP_PKEY_decapsulate` vs.
   noble's `ml_kem768.encapsulate` (same shared secret), OpenSSL HKDF vs. `crypto.subtle.deriveKey`
   (same 32-byte key), OpenSSL AES-256-GCM encrypt vs. `crypto.subtle.decrypt` (correct plaintext
   recovered) — all three confirmed byte-for-byte equal.
2. **`scripts/capgraph.py`** for both `press_pq_pd` (A1-A7, B1 PASS; C0 "needs interface_pds" —
   same as `tls_pd`, it's a secret holder not a confinement subject) and `qedos_press_pd` (C1-C8
   PASS, and C1's evidence list now explicitly includes `pq_keystore` among the secrets it
   provably cannot reach, alongside `tls_keystore`/`shm_signed_config`).
3. **`tests/test_press_pqwrap_sel4.py`** (`PQWRAP_001`-`006`), driving the real booted image over
   the real TLS1.3+PQ connection with the project's own OpenSSL, using
   `tests/pq_wrap_node_helper.mjs` to run the *actual* vendored `ml-kem768.bundle.js` (the same file
   the browser gets) for the client-side crypto — not a reimplementation:
   - `POST /press/pq-fetch` for `/press/index.html` decrypts to the exact real file bytes.
   - the same for `/press/missing` → `appStatus 404` inside the envelope.
   - the existing plain `GET /press/index.html` still works, unchanged (additive, not a
     replacement).
   - a correct-length but garbage KEM ciphertext: server returns a well-formed envelope (no crash,
     no server-side branch taken), and the test's own (wrong, by construction) derived key fails to
     authenticate it under AES-GCM — the real rejection, confirmed to happen where the design says
     it should.
   - a malformed (wrong-length) request body is rejected with a plain `400` before any OpenSSL call.
4. **Full existing regression suites re-run, unchanged**, against their own (independently rebuilt
   from scratch) images: `tests/test_sel4.py` (6/6), `tests/test_script_sel4.py` (11/11),
   `tests/test_press_sel4.py` (8/8, including `PRESS_002`'s `routes=1` assertion — confirming the
   site-separation design actually keeps the plain press image unaffected), `tests/test_press_concurrent_sel4.py`
   (3/3), `tests/test_press_compat_sel4.py` (5/5, confirming `tls_compat_pd`'s own LAW_002/003
   relaxation is likewise untouched by this separate feature).

## Known gaps / not done in this phase

- No live public exposure was set up or tested for this endpoint — that is a separate decision for
  the primary session/operator, same as every other live-exposure step in this project.
- The ML-KEM-768 private key has no rotation mechanism; `QEDOS_PQ_PRIVATE_KEY` exists as a build-time
  override point (mirroring `QEDOS_TLS_CERT`/`QEDOS_TLS_KEY`) but nothing automates rotation.
- `press_pq_pd`'s single-in-flight design (see above) means heavy concurrent pq-fetch traffic will
  shed load with `503` rather than serve it — a known, accepted, documented limit, not a bug.
