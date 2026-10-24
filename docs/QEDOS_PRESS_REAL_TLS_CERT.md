# QEDOS Press — real Let's Encrypt certificate, issued and verified (2026-10-24)

The prior gap noted in `docs/QEDOS_PRESS_PUBLIC_EXPOSURE_PLAN.md` ("tls_pd currently serves the committed dev
self-signed cert... a real public launch needs a real CA certificate") is now closed for one real domain,
`qedos.zelpm.com`, pointed by the owner at this host's public IP (`219.104.122.252`, confirmed via DNS lookup
before anything else was done).

## How the certificate was obtained

`acme.sh` (https://github.com/acmesh-official/acme.sh, open source) installed into the user's home directory
only — no `apt install`, no root-owned system package, so no persistent change to shared host state beyond
the renewal entry it added to the user's own crontab (`43 1,7,13,19 * * * ... acme.sh --cron ...`). Issued via
the standard ACME HTTP-01 challenge, standalone mode (acme.sh binds port 80 itself for the few seconds the
challenge takes): the host's one temporary, narrow, additive firewall rule (`-I INPUT 2 -i enp3s0f1 -p tcp
--dport 80 -j ACCEPT`), same pattern as the Phase 7 exposure test, removed again immediately after issuance.

The first attempt used acme.sh's default CA (ZeroSSL, not Let's Encrypt) — caught and corrected by reissuing
explicitly with `--server letsencrypt`; the final certificate is genuinely `issuer=... O=Let's Encrypt`.

Issued certificate: `CN=qedos.zelpm.com`, SAN `DNS:qedos.zelpm.com`, valid 2026-10-24 to 2027-01-22 (90-day
Let's Encrypt lifetime; acme.sh's own cron entry will attempt renewal around the ARI-suggested window,
2026-12-22). The cert, key, and full chain live only at `config/local/qedos-press-prod-{cert,key}.pem`
(git-ignored — added `/config/local/` to `.gitignore` specifically so this, or any future real key material,
can never be committed) — never inside `config/dev/`, which stays the committed, intentionally-dev-only
self-signed cert for every other build.

## A real bug found and fixed while wiring this in

`tls_pd.c`'s certificate loading (`PEM_read_bio_X509` called once) only ever read the **first** certificate
in the `cert_pem` buffer and loaded only that one via `SSL_CTX_use_certificate`. This was invisible with the
dev self-signed cert (which has no chain to send), but a real public CA's leaf certificate is not trusted
directly by clients — only a root is, and clients don't carry every CA's intermediates, so the intermediate(s)
must be sent during the handshake. Without this fix, a strict client (`-verify_return_error`) failed with
`unable to get local issuer certificate` even though the full chain was present in the keystore buffer.

Fixed: after loading the leaf, `tls_pd.c` now loops `PEM_read_bio_X509` over the same PEM blob and adds every
subsequent certificate via `SSL_CTX_add_extra_chain_cert`. For the dev cert (no intermediates), this loop is a
no-op — verified by the full existing regression suite still passing unchanged (below).

Also increased `cert_pem` from `2048` to `6144` bytes (`key_pem` unchanged at `2048`) — `6144 + 2048 == 8192`,
exactly the existing `tls_keystore` `MemoryRegion` size in `sel4/meta_proofgate.py` (`0x2000`), so **no
capability-graph or memory-layout change was needed**; the region already had this much headroom unused.
`scripts/build-sel4.sh`'s injector assert/pad was updated to match. A new `QEDOS_TLS_CERT`/`QEDOS_TLS_KEY`
env-var override (defaulting to the unchanged `config/dev/{cert,key}.pem` path) lets a build point at real
cert material without ever hardcoding a real path into a committed script.

## Verification performed (real evidence, not assumption)

1. **`scripts/capgraph.py --subject qedos_press_pd`**, against the rebuilt-with-real-cert image: all A/B/C
   checks **PASS** (only the pre-existing, unrelated D1 debug-kernel warning, same as every other build this
   session) — the cert change touches none of the capability structure.
2. **Full existing regression suites, rebuilt and re-run, unchanged**: `tests/test_sel4.py` 6/6,
   `tests/test_script_sel4.py` 11/11, `tests/test_press_sel4.py` 7/7 (all three against their normal
   dev-cert builds) — the chain-loading fix is provably a no-op for every build that doesn't supply extra
   chain certs.
3. **Strict TLS chain validation, local loopback first**: `openssl s_client -verify_return_error -CAfile
   /etc/ssl/certs/ca-certificates.crt` against `127.0.0.1` with `-servername qedos.zelpm.com` — every depth
   (`leaf -> YE2 -> Root YE -> ISRG Root X2`, with `ISRG Root X1` as the already-trusted anchor) reported
   `verify return:1`; `GET /press/index.html` returned `200` with the correct body.
4. **The same strict validation repeated live over the real public IP**, with the same temporary,
   narrow firewall rule + relay pattern as `docs/QEDOS_PRESS_PHASE7_EXECUTION.md`, and re-confirmed
   externally reachable from `titan` (a genuinely separate host) beforehand: identical `verify return:1` at
   every depth and the correct `200 OK` body, this time actually over `219.104.122.252:443`, not loopback.
   `titan`'s own `curl`/`openssl` (3.0.2) cannot complete the handshake at all — it lacks `X25519MLKEM768`
   support, the same documented limitation noted in Phase 7, confirmed again here, not a QEDOS-side issue.
5. **Teardown, fully verified**: relay and QEMU stopped by exact PID, the one firewall rule removed (`INPUT`
   back to its exact 3-rule baseline), and `titan` re-confirmed `219.104.122.252:443` closed again afterward.

## What this does and does not mean

This is real evidence that QEDOS Press's TLS termination works correctly with a real, publicly-trusted
certificate chain, served from inside `tls_pd` exactly as designed, with no weakening of any existing
security property (capgraph clean, every prior regression suite unchanged). It is not a decision to leave
the service permanently public — the firewall and relay were torn down at the end of this session, same as
Phase 7. Leaving QEDOS Press continuously reachable going forward, and the renewal cron job acme.sh installed
actually completing a future HTTP-01 challenge (which needs port 80 open at that moment), are both separate
decisions for the owner to make explicitly, not something this verification implies.
