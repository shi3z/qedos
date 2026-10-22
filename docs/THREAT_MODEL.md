# QEDOS threat model (QED Script hardening)

Scope: the x86_64 `QEDOS_SCRIPT=1` Microkit image (seL4 + Microkit 2.3.1), the default image where noted.
Evidence levels used everywhere in this repository: **PROVEN / BOUNDED / TESTED / DESIGNED / UNVERIFIED**
(see `SECURITY_ASSURANCE.md` for the definitions and the per-property assignment).

## Attackers

| | Attacker A — malicious Wasm | Attacker B — fully compromised `script_pd` | Attacker C — network client | Attacker D — malicious backend |
|---|---|---|---|---|
| **Controls** | any Wasm accepted by the loader; inputs; run time | arbitrary native code in `script_pd`; every byte of its address space; every capability it holds | any TCP/TLS/HTTP bytes, timing, fragmentation, concurrency, disconnects | any bytes returned on the internal backend connection |
| **Can write** | its linear memory, response buffer, host-API calls | `shm_policy_script` (rw), `shm_script_http` (rw), its private memory | the NIC (ciphertext) | the backend TCP stream |
| **Can observe** | request fields the policy grants; its own memory | everything in the two regions; serial output of its own debug calls (debug kernel only) | its own TLS stream, response timing | the forwarded request |
| **Holds capabilities** | none (sandboxed inside `script_pd`) | exactly the CNode extracted in `CAPABILITY_AUDIT.md`: signal `policy_pd`, signal `http_pd`, send-only fault endpoint, own notification/reply/VSpace root | none | none |
| **Success condition** | read/write outside linear memory; exceed limits; leak across requests; escape to native code | read or alter TLS key / signed config / TLS PD memory; signal or reconfigure another PD; open a network connection; make any other PD memory-unsafe; stop other services | impersonate, smuggle, desynchronise, exhaust, or reach the backend outside policy | answer with data that injects into another client's response or corrupts the proxy |

Attacker B is the priority: it is Attacker A *after* a Wasm-sandbox escape (or after a bug in the C/Rust glue of `script_pd`).
Nothing in the design may assume the sandbox holds.

## What is assumed (and therefore not established by this work)

1. **seL4 enforces capability and address-space isolation as specified.** The kernel binary in the image is *not*
   shown here to satisfy this. Whether the official seL4 proofs cover this exact configuration
   (x86_64, MCS scheduler, debug build) has to be checked against the seL4 proof configuration list; this repository does not claim it.
2. **Microkit's CapDL initialiser builds exactly what its report says.** Cross-checked against the SDF and against run-time attack tests, not proven.
3. **Hardware**: no physical attacks; no microarchitectural side channels; DMA-capable devices and IOMMU configuration are out of scope for QEMU results (see `HARDENING_RESULTS.md`, hardware section).
4. **Build toolchain and the Ed25519/SHA-512/ML-KEM/OpenSSL implementations are trusted** (not verified here).
5. **The operator keeps the production code-signing key and TLS private key secret.** The development signing seed in the repository must never be trusted by a production image.

## Explicit exclusions of the first verification round

* Timing, cache and other side channels (a compromised `script_pd` shares the CPU and caches with `tls_pd`). **Excluded**, not argued away.
* Covert channels using scheduling (e.g. modulating when `script_pd` consumes CPU) — only coarse availability is analysed.
* A kernel or hardware compromise.

## Security conditions for Attacker B (each is a separate, individually tested/analysed condition)

| id | condition | where it is checked |
|---|---|---|
| B-1 | cannot read the TLS private key | capability graph C1/C8; attack tests |
| B-2 | cannot write `tls_pd` memory | capability graph C1; attack tests |
| B-3 | cannot write arbitrary `http_pd` memory | IPC analysis (`IPC_VERIFICATION.md`), host ASan harness, attack tests |
| B-4 | cannot write arbitrary `policy_pd` memory | same |
| B-5 | cannot obtain `connector_pd`'s capabilities | capability graph C3 |
| B-6 | cannot forge capabilities | kernel (assumed) + capability graph A3 (no Untyped/Frame/TCB caps in any CSpace) |
| B-7 | cannot IPC to an unauthorised PD | capability graph C3, A1/A2 |
| B-8 | cannot open network connections | no NIC/IRQ/I-O-port/driver channel (C3, C4) |
| B-9 | cannot alter the signed config | C1 (not mapped); read-only mapping in `policy_pd` |
| B-10 | cannot stop/reconfigure other PDs | A3 (no TCB/SchedContext caps), A7 (fault endpoint is send-only) |
| B-11 | indirect attacks through shared memory | `IPC_VERIFICATION.md` |
| B-12 | availability: cannot starve or crash the other services | priority analysis + fault-injection tests |
