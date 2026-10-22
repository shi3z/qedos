# Build, run and test QEDOS

Detailed setup instructions. The top-level [README](../README.md) has the short path; everything from the earlier
README quick-start sections is kept here. Commands are listed as they exist in the repo; only the ones named in
"Recorded runs" below have a recorded result. Recorded runs on Linux used Ubuntu 22.04 (no KVM, QEMU TCG); the
macOS run is in [TEST_REPORT.md](TEST_REPORT.md).

## 1. Prebuilt image on macOS or Linux (default 12-PD image)

The repository contains a prebuilt default image (`build/sel4/loader.img.gz`, `build/sel4/sel4_32.elf.gz`), so you can boot
and test QEDOS on seL4 without rebuilding the cross-toolchains. There is **no** prebuilt copy of the 13-PD QED Script image.

Prerequisites: `git`, `python3`, QEMU (`qemu-system-x86_64`), Rust (`cargo`), and an OpenSSL command-line client that can
offer `X25519MLKEM768` (OpenSSL 3.5 or later). `tests/common.py` and `tests/test_sel4.py` look for
`third_party/openssl-install/bin/openssl`, then Homebrew `openssl@3` (`/opt/homebrew/opt/openssl@3`, `/usr/local/opt/openssl@3`),
then `openssl` on `PATH`. Python's own `ssl` module linked to OpenSSL 3.0.x cannot offer the PQC group.

```sh
brew install qemu openssl@3 rust
git clone https://github.com/shi3z/qedos.git && cd qedos

# 1. Boot the 12-PD seL4 QEDOS appliance in QEMU and run the 6 end-to-end PQC HTTPS tests:
python3 tests/test_sel4.py

# 2. Rust unit tests and the capability audit, natively:
scripts/build-openssl.sh                 # once: pinned OpenSSL 3.6.1 that cargo expects in third_party/openssl-install
cargo test --workspace --exclude pg-load
python3 scripts/check-caps.py
```

`scripts/build-openssl.sh` is needed before `cargo test` on a fresh checkout (see the problems list in
[TEST_REPORT.md](TEST_REPORT.md)).

### Boot by hand and check the negotiated key exchange

```sh
tools/run-echo.sh build/sel4/loader.img /tmp/qedos-serial.log "hostfwd=tcp::18443-10.0.2.15:8443" 300
# second terminal:
printf 'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
  OPENSSL_CONF=config/openssl-min.cnf openssl s_client -connect 127.0.0.1:18443 -tls1_3 -groups X25519MLKEM768 -ign_eof
# expect "Negotiated TLS1.3 group: X25519MLKEM768" and an HTTP 200; with -groups X25519 the handshake must fail
```

`/health` does not need the backends. The tests additionally start two host backends on ports 19001/19002 for the proxy tests.
`curl --tlsv1.3` alone does not show that the post-quantum exchange happened; check the group from `openssl s_client`
or the `TLS_PD: handshake OK ... group=X25519MLKEM768` line in the serial log.

## 2. Full build from source (Linux, no root needed except installing packages)

```sh
scripts/build-openssl.sh            # pinned OpenSSL 3.6.1 for host (sha256-checked), once
scripts/build-openssl-sel4.sh       # freestanding OpenSSL 3.6.1 for seL4 tls_pd, once
scripts/gen-dev-cert.sh             # self-signed localhost cert (tests only)
scripts/sign-config.sh              # Ed25519-sign host (.sig) and seL4 (proxy.sconf) configs
cargo build --release
scripts/build-sel4.sh               # build seL4 multi-PD image (build/sel4/loader.img) + Viper models (.vpr, generated, not run)
```

Toolchain used for the recorded results: Microkit SDK 2.3.1 (`third_party/microkit`), sDDF `12f6667` (`scripts/build-sddf.sh`),
`sdfgen` 0.35 in a venv (`third_party/venv`), clang/lld, `qemu-system-x86`. See [QED_SCRIPT.md](QED_SCRIPT.md) section 6.
The images are built with Microkit `--config debug` (see `scripts/build-sel4.sh`).

## 3. Verification and test suites

```sh
cargo test                                         # unit tests (pg-http, pg-policy, pg-config)
scripts/check-laws.sh                              # static checks + capability audit (LAW_005/008/011/012, QED Script laws)
python3 tests/test_tls.py                          # TEST_TLS_001..010 (host reference proxy)
python3 tests/test_http.py                         # 34 HTTP + Ed25519 signed-config (LAW_011) tests (host reference proxy)
python3 tests/test_sel4.py                         # SEL4_001..006 end-to-end multi-PD seL4 tests in QEMU
python3 tests/perf.py                              # PERF_001..008 at 10 000 connections (host reference)
cargo kani -p pg-policy && cargo kani -p pg-http && cargo kani -p pg-config   # 13 Kani harnesses (bounded)
```

## 4. QED Script (opt-in)

```sh
scripts/qs-ws.sh test                               # Rust unit/fuzz tests of the script crates + existing pure crates, offline
python3 tests/test_script.py && python3 tests/test_script_security.py
cargo kani -p pg-script && cargo kani -p pg-script-policy
for f in proofs/smt/*.smt2; do z3 $f; done          # Z3 models
python3 scripts/check-script-caps.py --selftest     # capability audit incl. weakened systems
PATH=$PWD/third_party/venv/bin:$PATH QEDOS_SCRIPT=1 scripts/build-sel4.sh   # build/sel4-script/loader.img (13 PDs)
python3 tests/test_script_sel4.py                   # boots it in QEMU: GET /script/hello over PQ-TLS, hostile modules, crash isolation
```

The default build (`scripts/build-sel4.sh` without the flag) is unchanged and still 12 PDs.

Run an example on the host without seL4:

```sh
scripts/qs-ws.sh build --release -p pg-script-cli      # -> build/qs/ws/target/release/qs
build/qs/ws/target/release/qs verify examples/hello
build/qs/ws/target/release/qs run examples/hello
scripts/build-examples.sh                              # rebuild and re-sign all example modules with the dev key
```

## 5. Hardening tools (Phases 1-3)

```sh
python3 scripts/capgraph.py --dir build/sel4-script --subject script_pd --json out.json --md out.md
python3 scripts/capgraph.py --selftest --dir build/sel4-script
python3 tests/test_wasm_differential.py --cases 100000 --seed 2     # needs node and the built qs CLI; compares with V8
```

The Datalog-based checks in `scripts/capgraph.py` import the Python `z3` module. The ASan harnesses are in `tests/ipc/` (`harness_http.c`,
`harness_policy_conn.c`, `stubs/microkit.h`); their build command is not documented in the repo.

## 6. aarch64 / Raspberry Pi 4 (experimental)

QEDOS also builds for aarch64: the 6-test seL4 suite passes on QEMU `virt`, and a Raspberry Pi 4 image builds (not booted
on hardware). **The aarch64 entropy source is a development placeholder, not secure.** See [AARCH64.md](AARCH64.md).

```sh
brew install qemu lld llvm rustup dtc && rustup target add aarch64-unknown-none
python3 -m venv third_party/venv && third_party/venv/bin/pip install sdfgen
QEDOS_ARCH=aarch64 scripts/build-sel4.sh
QEDOS_ARCH=aarch64 python3 tests/test_sel4.py
```

## Recorded runs

| Run | Where recorded |
|---|---|
| `tests/test_sel4.py` 6/6, `cargo test` 30 passed, `check-caps.py` PASS on macOS (Apple Silicon, QEMU 11.1.2, prebuilt image) | [TEST_REPORT.md](TEST_REPORT.md) |
| `tests/test_sel4.py` 6/6 on a rebuilt default image (Linux) | `build/script/sel4-default-hardened.log` |
| `tests/test_script_sel4.py` 9/9 (Linux, QEMU TCG) | `build/script/sel4-hardened-3.log`, `build/script/test_script_sel4.txt` |
