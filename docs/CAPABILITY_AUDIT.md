# Capability audit (generated-artifact level)

Tool: `scripts/capgraph.py` · intended authority: `security/cap-policy.json` · machine-readable results: `build/script/capgraph-*.json`.

## Method

Primary evidence is not the hand-written `meta_proofgate.py` or the SDF but what the Microkit tool says the
CapDL initialiser will build: `report.txt` lists, for every PD, **every CNode slot (object, rights, badge)**, every TCB with its bound
objects, IRQs and I/O ports. The tool:

1. **A. Artifact consistency** — every SDF channel end must appear as exactly the expected capability
   (notification: `Write`, badge `1<<peer_id`, slot `10+id`; PPC: endpoint `Write+GrantReply`, flagged badge, slot `74+id`);
   no capability may exist that no channel explains; no Frame/PageTable/TCB/SchedContext/CNode/Untyped capability in any CSpace other than the PD's own
   VSpace root; every memory region has exactly `size/4 KiB` kernel frame objects; one CSpace/VSpace/SchedContext per thread;
   fault-endpoint capabilities are send-only with a badge unique to the PD.
2. **B. Intended authority** — each PD's generated authority (signals, endpoints, IRQs, I/O ports, region maps with permissions, priority)
   must equal the hand-reviewed `security/cap-policy.json` in *both* directions. A new grant or a missing one fails the audit.
3. **C. Confinement of a chosen subject** (default `script_pd`, treated as fully compromised) — no mapping of a secret region
   (`tls_keystore`, `shm_signed_config`); no endpoint/Untyped/TCB; signals exactly to `policy_pd` and `http_pd`; no IRQ/I-O port;
   exact memory authority; influence closure computed twice (BFS and Z3 Datalog) and required to agree; **C8**: Z3 Datalog derivation of
   `Reads/Writes(subject, secret region)` and `HardwareAuthority(subject)` (all must be not derivable).
4. **D. Kernel configuration** — the kernel ELF must not contain debug-kernel syscalls.

`--selftest` weakens the extracted model in 15 ways (extra signal cap to `connector_pd`/`tls_pd`, endpoint cap, TCB cap, frame cap,
IRQ, I/O ports, secret-region maps, a *Read* right on the monitor endpoint, raised priority, a second PD mapping the script region,
a dropped or surplus channel capability) and requires every mutant to be caught: **15/15 caught** on the script image.

## What the generated CNode of `script_pd` contains

| slot | object | rights | meaning |
|---|---|---|---|
| 1 | `ntfn_script_pd` | Read | its own inbound notification |
| 2 | `ep_fault_monitor` | Write, GrantReply, badge 0x7 | send-only; the badge is fixed by the initialiser |
| 3 | `pml4_script_pd` | — | its own VSpace root (no paging-structure or frame capabilities exist anywhere to use it with) |
| 4 | `reply_script_pd` | — | MCS reply object |
| 11 | `ntfn_policy_pd` | Write, badge 0x8 | channel to `policy_pd` |
| 12 | `ntfn_http_pd` | Write, badge 0x10 | channel to `http_pd` |

Memory: `shm_policy_script` rw, `shm_script_http` rw, nothing else. No IRQ, no I/O port, no children, no VM. Priority 92 (lowest of all application PDs).

Influence reachability from `script_pd` (hops): `http_pd` 1, `policy_pd` 1, `monitor` 1, `connector_pd` 2, `tls_pd` 2, `tcp_pd` 3, drivers 4–5.
`tls_pd` (the only holder of the key store) is reachable **only through** `http_pd`, i.e. through the byte-level protocols analysed in `IPC_VERIFICATION.md`.

## Findings from this audit

| id | severity | finding | status |
|---|---|---|---|
| CAP-1 | **High (configuration)** | The images are built with `microkit --config debug`; the kernel ELF contains debug-kernel syscalls (`Debug halt syscall`, snapshot, console output). Those syscalls need **no capability**, so *any* PD — including a compromised `script_pd` — could stop the whole machine or write to the serial console. The capability graph cannot express this: it is a kernel build property. | Detected mechanically (check **D1**). Production images must use the release kernel; the debug image stays only for the test serial log and is labelled non-production. See `HARDENING_RESULTS.md` for the release-build status. |
| CAP-2 | Info | Every PD holds a send-only badged endpoint to Microkit's monitor (the fault endpoint). The monitor is therefore part of the attack surface of every PD, including `script_pd`; its message handling is not verified by this work. | UNVERIFIED (monitor is Microkit-supplied); listed under third-party audit items. |
| CAP-4 | Info | The Viper `obl_nohw` obligation (`scripts/viper-capability.py`) exempts a parent PD's TCB-capability check entirely once it has any declared child, rather than checking the capability is for exactly that child — mirrors capgraph's A3 relaxation and has the same gap: it would not catch a parent additionally holding an unrelated PD's TCB cap. | Documented; not tightened this session. |
| CAP-3 | Info | `ethernet_driver` holds I/O ports `0xCF8-0xCFF` (PCI configuration mechanism) — this lets the driver program *any* PCI device on x86, including DMA enable bits. Not reachable from `script_pd` (no path, C3/C4), but relevant to physical-hardware deployment. | Documented for the hardware phase. |

## Assumptions and limits of this audit

* The audit proves statements about the **extracted model**. The model's fidelity to the running system is checked by artifact cross-checks (A), the mutation self-test, and the run-time attack tests — it is **not** itself proven.
* It assumes seL4 enforces the capability semantics. That is an assumption of this repository, not a result of it.
* Memory mappings per PD come from the SDF (the report does not list page-table contents). The frame counts (A4) and the run-time access tests bound this gap; they do not close it.
* Timing and cache side channels are outside the model.
