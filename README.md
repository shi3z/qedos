# QEDOS

**QEDOS** is a formally verified, PQC-hybrid-only HTTPS reverse-proxy OS appliance running on **seL4 + Microkit 2.3.1 (`x86_64_generic`)** with a matching Linux reference proxy.
Enforces **TLS 1.3 + `X25519MLKEM768` + `TLS_AES_256_GCM_SHA384` only**, strict `#![no_std]` / `#![forbid(unsafe_code)]` HTTP/1.1 parsing (`pg-http`), fixed-route policy (`pg-policy`), Ed25519 signed configuration (`pg-config`, `LAW_011`), 5 isolated seL4 Protection Domains (`tcp_pd`, `tls_pd`, `http_pd`, `policy_pd`, `connector_pd`), Kani bounded proofs (`13/13` harnesses passing), and Microkit Viper capability verification (`LAW_008`, `LAW_012`).

**Read `docs/STATUS.md` first** — it separates what is verified from what remains hardware-dependent.

* `docs/ARCHITECTURE.md` — stages A–D (all verified), seL4 multi-PD architecture & shared-memory rings
* `docs/SECURITY.md` — guarantees and limits (X.509 auth is *not* post-quantum)
* `docs/LAWS.md` — `LAW_001..012`: specification, Kani / Viper / test evidence, and assumptions
* `docs/RESULTS.md` — TLS, HTTP, seL4 multi-PD, Kani, and C10K measurement results
* **QED Script** (untrusted signed WebAssembly in an extra `script_pd`, opt-in `QEDOS_SCRIPT=1`): `docs/QED_SCRIPT.md`, `docs/SCRIPT_SECURITY.md`, `docs/SCRIPT_VERIFICATION.md`, `docs/SCRIPT_RESULTS.md`; laws `LAW_013..022` in `docs/LAWS.md`

## Quick start (no root needed)
```sh
scripts/build-openssl.sh            # pinned OpenSSL 3.6.1 for host (sha256-checked), once
scripts/build-openssl-sel4.sh       # freestanding OpenSSL 3.6.1 for seL4 tls_pd, once
scripts/gen-dev-cert.sh             # self-signed localhost cert (tests only)
scripts/sign-config.sh              # Ed25519-sign host (.sig) and seL4 (proxy.sconf) configs
cargo build --release
scripts/build-sel4.sh               # build seL4 multi-PD image (build/sel4/loader.img) + Viper (.vpr)

# Verification & test suites:
cargo test                                         # unit tests (pg-http, pg-policy, pg-config)
scripts/check-laws.sh                              # static checks + Viper capability audit (LAW_005/008/011/012)
python3 tests/test_tls.py                          # TEST_TLS_001..010
python3 tests/test_http.py                         # 34 HTTP + Ed25519 signed-config (LAW_011) tests
python3 tests/test_sel4.py                         # SEL4_001..006 end-to-end multi-PD seL4 tests in QEMU
python3 tests/perf.py                              # PERF_001..008 at 10 000 connections (host reference)
cargo kani -p pg-policy && cargo kani -p pg-http && cargo kani -p pg-config   # 13/13 Kani bounded proofs
```

## QED Script (opt-in)
```sh
scripts/qs-ws.sh test                               # new crates: 36 unit/fuzz tests (+ existing pure crates), offline
python3 tests/test_script.py && python3 tests/test_script_security.py
cargo kani -p pg-script && cargo kani -p pg-script-policy
PATH=$PWD/third_party/venv/bin:$PATH QEDOS_SCRIPT=1 scripts/build-sel4.sh   # build/sel4-script/loader.img (13 PDs)
python3 tests/test_script_sel4.py                   # boots it in QEMU: GET /script/hello over PQ-TLS, hostile modules, crash isolation
```
The default build (`scripts/build-sel4.sh` without the flag) is unchanged and still 12 PDs.

## Running on macOS (Apple Silicon / Intel)
Prebuilt seL4 multi-PD images (`build/sel4/loader.img.gz` + `build/sel4/sel4_32.elf.gz`) are included in the repository so you can boot and test **QEDOS** on seL4 directly on a Mac without rebuilding the cross-toolchains:
```sh
brew install qemu openssl@3 rust
git clone https://github.com/shi3z/qedos.git && cd qedos

# 1. Boot the 12-PD seL4 QEDOS appliance in QEMU and run all 6 end-to-end PQC HTTPS tests:
python3 tests/test_sel4.py

# 2. Run Rust unit tests & Viper capability audit natively on macOS:
cargo test --workspace --exclude pg-load
python3 scripts/check-caps.py
```

## aarch64 / Raspberry Pi 4 (experimental)
QEDOS also builds for aarch64: the full 6-test seL4 suite passes on QEMU `virt`, and a Raspberry Pi 4 image builds (not yet booted on hardware).
**The aarch64 entropy source is a development placeholder, not secure.** See `docs/AARCH64.md` before use.
