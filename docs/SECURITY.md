# QEDOS security specification (current, honest)

## Scope of the guarantees
* **TLS (`LAW_002`, `LAW_003`)**: TLS 1.3 only; key exchange group `X25519MLKEM768` only; cipher
  `TLS_AES_256_GCM_SHA384` only; no fallback, no TLS ≤1.2, no classical-only groups, 0-RTT disabled,
  compression disabled. Enforced by OpenSSL 3.6.1 configuration **and** re-checked after every handshake
  in both the host reference proxy (`crates/pg-proxy`) and the seL4 `tls_pd` (`sel4/pds/tls_pd.c`).
* **Limitation — authentication is not post-quantum.** The server certificate is ordinary X.509 (ECDSA
  P-256 in the dev setup). Key *exchange* is PQC-hybrid (protects recorded traffic against a future
  quantum adversary), but a quantum adversary able to forge ECDSA/RSA signatures could impersonate the
  server in the future. Hybrid ≠ fully PQC; ML-DSA certificates are not used because browser support
  (Chrome) for them is not available.
* The hybrid still relies on classical X25519 for the classical half; its security against a classical
  attacker is that of X25519, against a quantum one that of ML-KEM-768 (+X25519).
* **Memory-safe & formally bounded HTTP/Policy/Config (`LAW_001`, `LAW_004`, `LAW_005`, `LAW_006`, `LAW_011`)**:
  `crates/pg-http`, `crates/pg-policy`, and `crates/pg-config` are `#![no_std]`, `#![forbid(unsafe_code)]`,
  zero-heap-allocation crates shared identically between the Linux reference proxy and the seL4 PDs (`http_pd`,
  `policy_pd`). All 13 Kani bounded verification harnesses pass with zero counterexamples.
* **Ed25519 signed configuration (`LAW_011`)**:
  Configuration blobs (`PGS1` binary format on seL4, `.conf` + `.conf.sig` sidecar on Linux) are verified
  against a compile-time pinned Ed25519 public key before activation. In `pg-config`, `VerifiedConfig` has
  private fields and can only be constructed by `VerifiedConfig::verify_and_parse` (proven via Kani).
* **seL4 + Microkit PD Isolation (`LAW_008`, `LAW_009`, `LAW_010`, `LAW_012`)**:
  In the seL4 appliance (`build/sel4/loader.img`), TLS keys live exclusively in `tls_pd`'s address space;
  `tls_pd` has no shared memory or IPC channel to `connector_pd` or the network driver (`eth_driver`).
  Every proxied request must pass `http_pd` (framing/header sanitization) and `policy_pd` (signed route/method
  evaluation) before `connector_pd` opens a backend socket. No shell, `/bin/sh`, or SSH daemon exists in the
  appliance (`LAW_010`). Capability isolation is verified by `scripts/check-caps.py` and Microkit's Viper
  specification generator (`build/sel4/viper/*.vpr`).

## QED Script (untrusted code) — summary
Untrusted signed WebAssembly runs in `script_pd` (opt-in image). Claims and limits are in `docs/LAWS.md` (`LAW_013..022`) and `docs/SCRIPT_SECURITY.md`. In short: memory addressing is proven for one function (Kani + Z3), capability separation is a *static audit* of the Microkit graph (Viper not run), most other properties are tested; there is **no wall-clock bound on seL4** (fuel only), **no authentication/Storage PD**, and the development code-signing seed is committed. An `app.proof` is never treated as evidence: no proof checker exists.

## Boundaries and Limitations
* **seL4 kernel proofs on x86_64**: While seL4 has machine-checked functional-correctness and integrity proofs
  on specific architectures (e.g. ARMv7/AArch64/RISC-V configurations), double-check the exact verification
  status of the `x86_64_generic` Microkit configuration before relying on kernel-level formal proof claims in
  production.
* **Pure-Rust Ed25519 / SHA-512 in `pg-config`**: Used solely for boot-time/reload-time verification of static
  configuration against a public key (no secret key material is processed by `pg-config`). All TLS session
  cryptography is performed by OpenSSL 3.6.1 (sha256-pinned source).
* Dev certificates (`scripts/gen-dev-cert.sh`) and signing keys (`config/keys/`) in the repository are for
  development and testing only.
* DoS resistance in the seL4 appliance is bounded by fixed ring buffer slots and connection slots; the Linux
  reference proxy enforces the full 10 000-connection cap, timeouts, and per-direction buffer limits.

## Test and Verification Evidence
* `tests/test_tls.py` (`TEST_TLS_001–010`), `tests/test_http.py` (34 tests including `LAW_011`), `tests/perf.py` (`PERF_001–008`), `tests/test_sel4.py` (`SEL4_001–006`).
* `build/kani/pg-http.log`, `build/kani/pg-policy.log`, `build/kani/pg-config.log`, `build/sel4/viper/*.vpr`.
* See [docs/RESULTS.md](file:///home/shi3z/proofsecure/docs/RESULTS.md) and [docs/LAWS.md](file:///home/shi3z/proofsecure/docs/LAWS.md).

