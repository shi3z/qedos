# QEDOS — architecture and implementation

Status legend: **[verified]** = built, tested, and reproduced in this repo; **[open]** = requires physical bare-metal hardware.

## 1. Stages

| Stage | What | Status |
|---|---|---|
| A. Host reference | Rust proxy (`mio` + OpenSSL 3.6.1) on Linux sharing `pg-http`, `pg-policy`, `pg-config`. | **[verified]** `TEST_TLS_001–010`, 34 HTTP/config tests, `PERF_001–008` (10k conns) |
| B. seL4 base | seL4 + Microkit 2.3.1 `x86_64_generic` + sDDF `virtio-net` + lwIP, QEMU | **[verified]** boots; DHCP + TCP stack operational |
| C. TLS PD on seL4 | Freestanding OpenSSL 3.6.1 (`third_party/openssl-sel4` + `sel4/libc_shim`) in `tls_pd`, memory-BIO over `shm_tcp_tls`, isolated `tls_keystore` (`LAW_008`) | **[verified]** `SEL4_001–003` (`X25519MLKEM768` only) |
| D. HTTP / Policy / Connector PDs + Viper Audit | `http_pd`, `policy_pd` (Ed25519 `LAW_011`), `connector_pd` linking `no_std` Rust crates on seL4; Microkit `--viper-output` + `scripts/check-caps.py` (`LAW_008`, `LAW_012`) | **[verified]** `SEL4_004–006` + `13/13` Kani proofs |
| E. Bare metal / UEFI / SMP / physical NIC | Multiboot2 hardware boot + physical NIC driver + hardware C10K | **[open]** (dev host has no KVM or bare-metal testbed) |

## 2. seL4 investigation & implementation summary

1. **Microkit x86-64 QEMU support** — **[verified]** Microkit 2.3.1 `x86_64_generic` boots via `sel4_32.elf` + `-initrd build/sel4/loader.img` under QEMU (`+fsgsbase,+pdpe1gb,+xsave,+xsaveopt,+rdrand`). Each application PD is configured with a 256 KiB stack (`stack_size=0x40000`) to accommodate ML-KEM-768 stack frames.
2. **virtio-net driver** — **[verified]** sDDF `drivers/network/virtio/pci` at PCI slot `0x2.0`.
3. **TCP/IP stack (`tcp_pd`)** — **[verified]** lwIP runs inside `tcp_pd`, listening on `:8443` and bridging raw ciphertext streams to `tls_pd` over `shm_tcp_tls` while opening outbound TCP connections to fixed backends on behalf of `connector_pd` over `shm_tcp_conn`.
4. **Freestanding TLS 1.3 + `X25519MLKEM768` (`tls_pd`)** — **[verified]** OpenSSL 3.6.1 built static/freestanding (`scripts/build-openssl-sel4.sh`) with `no-threads no-sock no-posix-io no-dso no-engine no-stdio` and linked with `sel4/libc_shim/libc_shim.c` (16 MiB coalescing block allocator, CPUID-guarded `rdrand` + `rdtsc` entropy, UTC `gmtime_r`).
5. **Capability separation & Viper model (`LAW_008`, `LAW_012`)** — **[verified]** `scripts/build-sel4.sh` invokes `microkit --viper-output build/sel4/viper`, producing formal Viper invariants (`*.vpr`) for all 12 PDs. `scripts/check-caps.py` mechanically verifies that `tls_keystore` is mapped read-only in `tls_pd` only (`LAW_008`), `shm_signed_config` is mapped read-only in `policy_pd` only (`LAW_011`), hardware IRQs/ioports are absent from all application PDs, and inter-PD channels match the strict pipeline graph (`LAW_012`).

## 3. Verified seL4 PD graph (`build/sel4/proofgate.system`)

```
NIC driver (ethernet_driver) → net_virt_rx / net_virt_tx / tcp_net_copier
  → tcp_pd (lwIP :8443) ──shm_tcp_tls──▶ tls_pd (OpenSSL 3.6.1; ONLY holder of tls_keystore -> LAW_008)
      ▲                                    │ shm_tls_http (plaintext ring)
      │                                    ▼
      │                               http_pd (Rust no_std `pg-http`, forbid(unsafe_code) -> LAW_006)
      │                                    │ shm_http_policy (parsed request ring)
      │                                    ▼
      │                               policy_pd (Rust no_std `pg-policy` + `pg-config` Ed25519 -> LAW_001/004/007/011)
      │                                    │ shm_policy_conn (approved Forward only)
      │                                    ▼
      └───shm_tcp_conn─────────────── connector_pd (fixed backend IP:port table + `pg-http::parse_response`)
```

### 3b. Optional QED Script PD (`QEDOS_SCRIPT=1`, 13 PDs)
`policy_pd` additionally dispatches `GET|POST /script/<module>` (after the shared path-hygiene check) through `shm_policy_script` to `script_pd`, whose result returns through `shm_script_http` to `http_pd`. `script_pd` maps only those two regions, has two channels (policy_pd, http_pd), priority 92 (lowest), and links the Wasm interpreter `pg-script` via its own staticlib `sel4/rust_script`; no other PD contains interpreter code. Details and rationale: `docs/QED_SCRIPT.md`; capability audit: `scripts/check-script-caps.py`.

## 4. Crate & component inventory

* `crates/pg-http`: `#![no_std]`, `#![forbid(unsafe_code)]` strict HTTP/1.1 request/response head parser + chunked decoder (8/8 Kani proofs).
* `crates/pg-policy`: `#![no_std]`, `#![forbid(unsafe_code)]` fixed-route decision engine + path/UTF-8 hygiene (3/3 Kani proofs).
* `crates/pg-config`: `#![no_std]`, `#![forbid(unsafe_code)]` deterministic binary signed config format (`PGS1`) + pure-Rust RFC 8032 Ed25519 & FIPS 180-4 SHA-512 verification (2/2 Kani proofs).
* `crates/pg-proxy`: Linux single-thread epoll reference proxy for C10K validation.
* `crates/pg-script` (Wasm i32-subset interpreter + host API), `crates/pg-script-policy` (policy, route, KV ACL), `crates/pg-script-verify` (signed bundles, proof envelope), `crates/pg-script-cli` (`qs`): all `#![no_std]` + `#![forbid(unsafe_code)]` except the CLI. `sel4/rust_script` + `sel4/pds/script_pd.c`: the Script PD.
* `sel4/rust_pds`, `sel4/pds`, `sel4/libc_shim`, `sel4/meta_proofgate.py`: seL4/Microkit Protection Domains and system description generator.
