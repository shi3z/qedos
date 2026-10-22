# Capability audit

* image: `build/sel4-script`
* subject (assumed fully compromised): `script_pd`
* artifacts: `report.txt` sha256 `4a697f5b8b2abf65`, `proofgate.system` sha256 `87d171b3f7c9c1ee`

| id | result | check |
|---|---|---|
| A1 | **PASS** | every SDF channel end appears as exactly the expected notification capability (object, rights, badge) |
| A2 | **PASS** | no notification capability exists that is not explained by an SDF channel |
| A3 | **PASS** | no PD CSpace holds Frame/PageTable/TCB/SchedContext/CNode/Untyped capabilities other than its own VSpace root (nobody can retype or remap) |
| A4 | **PASS** | every memory region has exactly size/4KiB kernel frame objects (no hidden aliasing of region frames) |
| A5 | **PASS** | every PD thread has its own CSpace/VSpace/SchedContext and the fault endpoint bound |
| A6 | **PASS** | no two threads share an address space or CSpace (one TCB per PD VSpace) |
| A7 | **PASS** | fault-endpoint capabilities are send-only and carry a badge unique to their PD |
| B1 | **PASS** | generated authority of every PD equals the intended authority in security/cap-policy.json (both directions) |
| C1 | **PASS** | script_pd has no mapping of any secret/trusted region ['tls_keystore', 'shm_signed_config'] (no direct path to the TLS key or the signed config) |
| C2 | **PASS** | script_pd can neither create nor obtain endpoints: no Untyped/TCB/CNode/Frame caps; its only endpoint is the send-only fault endpoint to its supervisor (or the monitor) |
| C3 | **PASS** | script_pd can signal exactly ['http_pd', 'policy_pd']; in particular no IPC path to connector_pd/tls_pd/tcp_pd or any driver |
| C4 | **PASS** | script_pd holds no IRQ handler or I/O-port capability |
| C5 | **PASS** | script_pd memory authority is exactly the declared set (and nothing is mapped writable twice under different names) |
| C6 | **PASS** | influence closure computed twice (BFS and Z3 Datalog) agrees |
| C7 | **PASS** | every direct influence target of script_pd is a declared script-interface PD; secret-holding PDs are reachable only through them |
| C8 | **PASS** | Z3 Datalog: none of {read secret region, write secret region, hold IRQ/I-O-port authority} is derivable for the subject |
| D1 | **WARN** | kernel binary has no debug syscalls (SysDebugHalt/PutChar/...: any PD may invoke them without a capability) |

## Authority of `script_pd` (from the generated CNode)

```json
{
  "signal": [
    "http_pd",
    "policy_pd"
  ],
  "send": [],
  "call": [
    "supervisor_pd"
  ],
  "irq": [],
  "ioport": [],
  "maps": {
    "shm_policy_script": "rw",
    "shm_script_http": "rw"
  },
  "other_caps": [],
  "priority": 92
}
```

## Influence reachability (hops from the subject)

* `script_pd`: 0
* `http_pd`: 1
* `policy_pd`: 1
* `supervisor_pd`: 1
* `connector_pd`: 2
* `monitor`: 2
* `tls_pd`: 2
* `timer_driver`: 2
* `tcp_pd`: 3
* `net_virt_tx`: 4
* `serial_virt_tx`: 4
* `tcp_net_copier`: 4
* `ethernet_driver`: 5
* `serial_driver`: 5
* `net_virt_rx`: 5

## Evidence

### A1 PASS

```
"18 channels x 2 ends verified against CNode slots 10+id"
```

### A2 PASS

```
"none"
```

### A3 PASS

```
{
 "self_vspace_root_only": [
  "connector_pd",
  "ethernet_driver",
  "http_pd",
  "net_virt_rx",
  "net_virt_tx",
  "policy_pd",
  "script_pd",
  "serial_driver",
  "serial_virt_tx",
  "supervisor_pd",
  "tcp_net_copier",
  "tcp_pd",
  "timer_driver",
  "tls_pd"
 ]
}
```

### A4 PASS

```
"34 regions checked"
```

### A5 PASS

```
"14 TCBs"
```

### A6 PASS

```
"unique"
```

### A7 PASS

```
"13 distinct badges"
```

### B1 PASS

```
"14 PDs identical"
```

### C1 PASS

```
{
 "tls_keystore": [
  "tls_pd"
 ],
 "shm_signed_config": [
  "policy_pd"
 ]
}
```

### C2 PASS

```
{
 "other_caps": [],
 "call": [
  "supervisor_pd"
 ],
 "send": [],
 "parent": "supervisor_pd"
}
```

### C3 PASS

```
{
 "signal": [
  "http_pd",
  "policy_pd"
 ],
 "unexpected": []
}
```

### C4 PASS

```
{
 "irq": [],
 "ioport": []
}
```

### C5 PASS

```
{
 "shm_policy_script": "rw",
 "shm_script_http": "rw"
}
```

### C6 PASS

```
{
 "bfs": {
  "connector_pd": 2,
  "ethernet_driver": 5,
  "http_pd": 1,
  "monitor": 2,
  "net_virt_rx": 5,
  "net_virt_tx": 4,
  "policy_pd": 1,
  "script_pd": 0,
  "serial_driver": 5,
  "serial_virt_tx": 4,
  "supervisor_pd": 1,
  "tcp_net_copier": 4,
  "tcp_pd": 3,
  "timer_driver": 2,
  "tls_pd": 2
 },
 "z3": [
  "connector_pd",
  "ethernet_driver",
  "http_pd",
  "monitor",
  "net_virt_rx",
  "net_virt_tx",
  "policy_pd",
  "script_pd",
  "serial_driver",
  "serial_virt_tx",
  "supervisor_pd",
  "tcp_net_copier",
  "tcp_pd",
  "timer_driver",
  "tls_pd"
 ]
}
```

### C7 PASS

```
{
 "direct": [
  "http_pd",
  "policy_pd",
  "supervisor_pd"
 ],
 "secret_holders_hops": {
  "policy_pd": 1,
  "tls_pd": 2
 }
}
```

### C8 PASS

```
{
 "Reads(script_pd,tls_keystore)": false,
 "Writes(script_pd,tls_keystore)": false,
 "Reads(script_pd,shm_signed_config)": false,
 "Writes(script_pd,shm_signed_config)": false,
 "HardwareAuthority(script_pd)": false
}
```

### D1 WARN

```
"sel4.elf: debug-kernel strings ['Debug halt syscall', 'Debug snapshot', 'halting...']"
```
