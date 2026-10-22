# QED Script — untrusted server-side WebAssembly on QEDOS

Status (2026-10-22): **implemented and booted on seL4 + Microkit 2.3.1 (x86_64, QEMU TCG)**, opt-in build (`QEDOS_SCRIPT=1`).
Security claims and their limits are in [SCRIPT_SECURITY.md](SCRIPT_SECURITY.md) and `LAW_013..022` in [LAWS.md](LAWS.md).
Measurements: [SCRIPT_RESULTS.md](SCRIPT_RESULTS.md). Proof-carrying design: [SCRIPT_VERIFICATION.md](SCRIPT_VERIFICATION.md).

## 1. Architecture actually built

```
Internet ─TLS1.3+X25519MLKEM768─▶ tcp_pd ─▶ tls_pd ─▶ http_pd ─▶ policy_pd ──Forward──▶ connector_pd ─▶ tcp_pd (unchanged)
                                                         ▲            │
                                      shm_script_http    │            │ SCRIPT (GET/POST /script/<module>)
                                                         │            ▼ shm_policy_script
                                                       script_pd  (Wasm interpreter + host API + in-PD KV)
```
13 PDs: the 12 of `docs/ARCHITECTURE.md` + `script_pd`. Differences from the logical diagram in the task:
* **Response PD** is not separate: `http_pd` (already the response framer, `forbid(unsafe_code)` parser) frames script output, using fixed header strings, a 3-valued content-type selector and a body length it measures itself.
* **Storage PD** does not exist yet. The KV store is a static object inside `script_pd` (LAW_021 limitation; see SCRIPT_SECURITY.md). Reason it is not split yet: without authentication there is no principal, so every KV call is denied on seL4; a separate PD would add attack surface without a use.
* Separate trust boundaries that *are* separate PDs, and why: `script_pd` (runs attacker-chosen bytecode) vs `tls_pd` (holds the key) vs `policy_pd` (decides routing) vs `http_pd` (parses attacker bytes). A bug in the interpreter must not hand the attacker the key store or the router.
* `script_pd` priority 92 — lower than every other application PD (tcp 97, tls 96, http 95, policy 94, connector 93).

Authority of `script_pd` (all audited by `scripts/check-script-caps.py`): own image; `shm_policy_script` (rw, shared with policy_pd); `shm_script_http` (rw, shared with http_pd); exactly two channels (policy_pd, http_pd). No TLS keystore, signed config, tcp/net/serial/timer region, IRQ, ioport, child PD, VM.

Request path: `http_pd` parses → `policy_pd` runs the usual `pg-policy` hygiene on `/script/<id>` (reusing the Kani-checked `decide`), copies method/target/body into `shm_policy_script`, acks http_pd (so proxy traffic is never blocked), notifies `script_pd`. `script_pd` copies the request into PD-private buffers, runs the module, writes status/content-type/body into `shm_script_http`, notifies `http_pd`, which frames and sends it through `tls_pd`. If `script_pd` is busy or dead, `policy_pd` answers 503 immediately.

## 2. Wasm engine: why a custom subset interpreter (and Wasmi status)

Wasmi was checked, not adopted. `wasmi 2.0.0` (`default-features=false`) **does compile `no_std` for `x86_64-unknown-none`** (checked 2026-10-22), has no JIT, and offers fuel metering and a resource limiter. Against that: ≈ 43 000 lines of Rust plus `wasmparser`, `unsafe` internally, needs a global allocator in the PD, and its behaviour is not something Kani can cover at that size. It was **not** run inside seL4 here. A purpose-built interpreter (`crates/pg-script/src/wasm.rs`, ≈ 1 100 lines incl. comments, `#![no_std]`, `#![forbid(unsafe_code)]`, zero heap) keeps the TCB small enough for the Kani/SMT work below. Trade-off: it implements only a subset and its *conformance to the Wasm spec is untested against a reference engine* (next step: differential fuzzing against Wasmi).

Accepted: sections type/import/function/memory/export/code/data (+ ignored custom); `i32` only; one memory ≤ 16 pages, **no `memory.grow`**; control: `block loop if else br br_if return call unreachable nop`; `drop select local.get/set/tee`; `i32` loads/stores (8/16/32), `memory.size`, `i32.const`, all `i32` comparisons and arithmetic (div/rem trap on 0 and overflow). **Rejected at load:** floats, i64, tables, globals, start function, `call_indirect`, `br_table`, `memory.grow`, bulk memory, SIMD, threads/shared memory, multi-value, any non-function import, imports outside module `qs`. No WASI, no JIT.
Static limits: ≤ 32 functions, 16 imports, 16 locals, 16 nesting levels, 16 call frames, 1024-slot value stack.

## 3. ABI (host API, module `qs`)

| import | signature (all i32) | meaning |
|---|---|---|
| `req_method` | `() -> i32` | 0 GET, 2 POST |
| `req_field` | `(field, ptr, cap) -> len` | copy field (0 path, 1 query, 2 body, 3 content-type, 4 user-agent) to memory; returns full length, -1 on bad field/range |
| `resp_status` | `(code)` | 100..599 else the request fails |
| `resp_content_type` | `(kind)` | 0 json, 1 html, 2 text (fixed set; no free-form headers) |
| `resp_write` | `(ptr, len)` | append to body; exceeding `max_response_bytes` fails the request |
| `kv_get` / `kv_put` / `kv_delete` | `(kptr,klen,vptr,vcap) -> n` / `(kptr,klen,vptr,vlen)` / `(kptr,klen)` | per-principal, per-module, prefix-granted; -1 denied, -2 absent |

Guest entry: exported `handle() -> i32`; 0 = success, non-zero = script-declared failure (HTTP 500, generic body).
The `namespace` argument of the proposed `kv.get(namespace, key)` is deliberately absent: the namespace is `(authenticated principal, module id)`, chosen by the platform, never by the script.

Developer experience today: write the handler in Wasm text/any compiler targeting this subset; `tools/qswasm.py` is a flat-WAT assembler used for the examples. **A TinyGo/Rust SDK was not built**: the Rust `wasm32` toolchain emits i64/globals/tables that this MVP subset rejects, so a compiler-facing SDK needs the subset widened (next step). The JavaScript-style `handle(req)` is not implemented.

## 4. Policy and signing

`app.policy` (text, strict parser, signed): `runtime = qs-wasm/1`, `module`, `version`, `allow = <api>` (repeatable), `kv_read/kv_write = <prefix>`, and all of `max_memory_bytes max_fuel max_stack_depth max_request_bytes max_response_bytes max_host_calls max_exec_us` (platform ceilings: 1 MiB, 5·10⁷, 16, 64 KiB, 64 KiB, 4096, 100 ms). Unknown/duplicate/missing keys, values above ceilings, allow/prefix contradictions → load refused.
`app.sig` = hex Ed25519 over `"QEDOS-QS-CODE-V1\0" ‖ len(runtime) ‖ runtime ‖ be32(len(policy)) ‖ policy ‖ SHA512(wasm) ‖ SHA512(app.proof | ∅)`. Module id, version and every limit are inside the policy, so one signature binds them all. The pinned code-signing key (`config/keys/qs-code-signing-pub.rs`) is distinct from the configuration key. A module that imports anything the signed policy does not allow, or needs more memory than the policy, is refused.

## 5. Developer CLI (`qs`, `crates/pg-script-cli`)
```sh
scripts/qs-ws.sh build --release -p pg-script-cli      # → build/qs/ws/target/release/qs
python3 examples/hello/build.py                        # write app.wasm (assembler)
qs sign --seed config/keys/qs-code-signing-seed.hex examples/hello   # write app.sig
qs verify examples/hello
qs run --method POST --body '{"a":1}' --principal 7 --repeat 3 examples/json-echo
qs bench examples/hello 200000
qs pack bundles.qsb examples/hello examples/json-echo  # QSB1 table for script_pd
qs mkproof FuelBounded examples/hello                  # UNCHECKED proof envelope (see SCRIPT_VERIFICATION.md)
```
Examples: `hello` (fixed JSON), `json-echo` (POST body → uppercased JSON string + length), `params` (URL query), `kv-counter` (ACL-checked KV), `malicious/` (36 hostile modules, `cases.py`).

## 6. Building and running the seL4 image
Toolchain used for the recorded results (Ubuntu 22.04, no root needed except `apt install qemu-system-x86 clang lld`): Microkit SDK 2.3.1 (`third_party/microkit`), sDDF `12f6667` built via `make -C third_party/sddf/examples/echo_server … BUILD_DIR=build/echo`, `sdfgen 0.35` venv, `scripts/build-openssl.sh`, `scripts/build-openssl-sel4.sh`.
```sh
PATH=$PWD/third_party/venv/bin:$PATH QEDOS_SCRIPT=1 scripts/build-sel4.sh   # → build/sel4-script/loader.img (baseline build/sel4 untouched)
python3 tests/test_script_sel4.py                                           # builds with hostile modules + boots + 9 tests
curl --tlsv1.3 --curves X25519MLKEM768 -k https://localhost:18443/script/hello   # with host port-forward as in tests (needs curl+OpenSSL ≥ 3.5)
```
Note: `curl --tlsv1.3 …` alone does **not** show that the post-quantum exchange happened. The tests assert the negotiated group from `openssl s_client` (`Negotiated TLS1.3 group: X25519MLKEM768`) and from the appliance's own log line `TLS_PD: handshake OK … group=X25519MLKEM768`.

## 7. Trusted computing base of a script request
Hardware, seL4 kernel (+ Microkit/CapDL initialiser), `tcp_pd`/`tls_pd` (OpenSSL 3.6.1), `http_pd` + `policy_pd` (+ `pg-http`, `pg-policy`, `pg-config`), `script_pd`: `pg-script` (≈ 1 400 lines), `pg-script-policy` (≈ 600), `pg-script-verify` (≈ 330 + Ed25519/SHA-512 from `pg-config`, ≈ 930), the `sel4/rust_script` shim (≈ 130, `unsafe` C-ABI), `script_pd.c` (≈ 140), libc_shim. **Not** in the TCB for correctness of isolation: the script, its compiler, any proof generator, the `qs` CLI.
