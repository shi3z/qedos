# QEDOS STATUS — verified vs. not (2026-10-18)

**What exists and is verified:**
1. **seL4 + Microkit Multi-PD Appliance (`build/sel4/loader.img`, Stages B–D):**
   * Boots on seL4 + Microkit 2.3.1 (`x86_64_generic`) in QEMU with 12 Protection Domains: 7 sDDF hardware/virtualiser PDs (`timer_driver`, `serial_driver`, `serial_virt_tx`, `ethernet_driver`, `net_virt_rx`, `net_virt_tx`, `tcp_net_copier`) and 5 isolated QEDOS application PDs (`tcp_pd`, `tls_pd`, `http_pd`, `policy_pd`, `connector_pd`).
   * `tls_pd` runs freestanding OpenSSL 3.6.1 over memory BIOs enforcing TLS 1.3 + `X25519MLKEM768` + `TLS_AES_256_GCM_SHA384` only, and is the **sole holder of the TLS private key (`LAW_008`)**.
   * `http_pd`, `policy_pd`, and `connector_pd` link the `#![no_std]`, `#![forbid(unsafe_code)]` Rust crates `pg-http`, `pg-policy`, and `pg-config` compiled for `x86_64-unknown-none`.
   * `policy_pd` verifies the Ed25519 signature of `shm_signed_config` (`config/sel4/proxy.sconf`) against the pinned public key at boot before activating any route or backend (`LAW_011`).
   * End-to-end HTTPS tests (`tests/test_sel4.py`, `SEL4_001..006`) verify TLS 1.3 `X25519MLKEM768` handshakes, TLS 1.2 / classical-group rejection, `/health`, multi-PD proxying to host backends A & B with header sanitization, traversal/malformed rejection with zero backend leakage, and formal Viper capability models (`build/sel4/viper/*.vpr` via `scripts/check-caps.py`, `LAW_008`, `LAW_012`).
2. **Host Reference Proxy (`pg-proxy`, Stage A):**
   * Linux single-thread epoll HTTPS reverse proxy sharing `pg-http`, `pg-policy`, and `pg-config` (Ed25519 signature check on `<config>.sig`).
   * Passes `TEST_TLS_001–010`, 34 HTTP & signed-config tests (`tests/test_http.py`), and `PERF_001–008` (10 000 concurrent connections on loopback).
3. **Kani Bounded Proofs (`13/13` harnesses passing):**
   * `pg-http`: **8/8** harnesses pass (`parse_request_spans_in_bounds`, `parse_response_spans_in_bounds`, `accepted_request_is_http11_with_host`, `chunk_decoder_in_bounds`, `validate_head_bytes_in_bounds`, `validate_target_in_bounds`, `validate_host_in_bounds`, `parse_u64_digits_no_overflow`).
   * `pg-policy`: **3/3** harnesses pass (`accepted_path_has_no_traversal`, `forward_backend_is_table_member`, `deployed_routes_forward_only_to_valid_backends`).
   * `pg-config`: **2/2** harnesses pass (`unverified_blob_always_rejected`, `parse_blob_in_bounds`).

4. **QED Script (opt-in, 2026-10-22) — see `docs/QED_SCRIPT.md`, `docs/SCRIPT_RESULTS.md`:** 13th PD `script_pd` (`QEDOS_SCRIPT=1`) executing Ed25519-signed WebAssembly (custom i32 subset interpreter, fuel/memory/stack/host-call bounded). Verified: `tests/test_script_sel4.py` 9/9 on seL4 in QEMU (PQ-TLS `GET /script/hello` → `{"message":"Hello from QEDOS"}`, hostile-module containment, crash isolation); 36 Rust tests; 16 + 151 Python tests; 7 new Kani harnesses (bounded/function-level) + 3 Z3 models; capability audit with 9 mutants; existing 13 Kani harnesses and `SEL4_001..006` re-run green (also on an image rebuilt from the modified sources). **Not done / not proven:** timer-based time limit on seL4, separate Storage PD, authentication (KV is denied on seL4), proof checker (`app.proof` is never trusted), Viper obligations not discharged, Rust/TinyGo SDK, hardware measurements. `LAW_013..022` evidence levels are in `docs/LAWS.md`; several are TESTED/AUDITED only.

**What remains hardware-dependent (Stage E):**
* Bare-metal UEFI/Multiboot2 boot, physical NIC driver (sDDF x86_64 provides `virtio-net-pci`), and multi-core hardware C10K measurements (dev host has no KVM; seL4 runs under QEMU TCG, while C10K PERF_001–008 run on the Linux host proxy).
* X.509 certificate authentication uses ECDSA P-256 (key exchange is PQC-hybrid `X25519MLKEM768`; see `docs/SECURITY.md`).
