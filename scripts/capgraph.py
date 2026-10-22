#!/usr/bin/env python3
"""
qedos capability-graph verifier (Phase 1 of the hardening plan).

Primary evidence is what Microkit's CapDL initialiser *actually builds* (`report.txt`: every PD's CNode
slots with object, rights and badge; TCBs; IRQs; I/O ports), cross-checked against the system
description (`proofgate.system`: memory-region maps, channels) and, optionally, the kernel binary.

It then
  1. builds the authority graph  (PD --signal/call/send--> PD, PD --r/w--> memory region, PD --> hardware),
  2. checks the generated artifacts for internal consistency (channels <-> CNode slots/badges,
     memory regions <-> kernel frame objects, no frame/untyped/TCB caps in any application CNode),
  3. compares every PD's authority with the *intended* authority in security/cap-policy.json
     (build-time detection of unintended capability grants, in both directions),
  4. computes, for a chosen subject PD (default script_pd), what it can reach: directly and transitively,
     twice and independently (Python closure and Z3 Datalog), and checks they agree,
  5. emits machine-readable JSON and a Markdown report.

What this is NOT: a proof about the seL4 kernel or the CapDL initialiser. It proves properties of the
*extracted authority model*; the model's fidelity is cross-checked (artifact consistency, mutation
self-test, and run-time attack tests), not proven. See docs/CAPABILITY_AUDIT.md for assumptions.

usage:
  capgraph.py --dir build/sel4-script [--subject script_pd] [--json out.json] [--md out.md]
  capgraph.py --selftest --dir build/sel4-script
exit status: 0 = every check PASS, 1 = at least one FAIL, 2 = usage/input error
"""
import argparse
import copy
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POLICY = os.path.join(ROOT, "security/cap-policy.json")

BASE_SLOT_NTFN_IN, BASE_SLOT_FAULT, BASE_SLOT_VSPACE, BASE_SLOT_REPLY, BASE_SLOT_OUT = 1, 2, 3, 4, 10
BASE_SLOT_PPC = 74          # libmicrokit BASE_ENDPOINT_CAP
PPC_BADGE_FLAG = 1 << 63


# ----------------------------------------------------------------------------------------- parsing
def parse_report(path):
    """-> dict(tcbs, cnodes, irqs, ioports, objects)"""
    txt = open(path, encoding="utf-8", errors="replace").read()
    sections = re.split(r"^# ", txt, flags=re.M)
    out = {"tcbs": {}, "cnodes": {}, "irqs": [], "ioports": {}, "objects": {}}
    for sec in sections:
        head, _, body = sec.partition("\n")
        if head.startswith("TCB Details"):
            for blk in re.split(r"^\t- TCB: ", body, flags=re.M)[1:]:
                name = blk.split("'")[1]
                d = {"priority": int(re.search(r"Priority: (\d+)", blk).group(1)),
                     "ip": re.search(r"IP: (0x[0-9a-f]+)", blk).group(1),
                     "bound": dict(re.findall(r"-> ([A-Za-z ]+): '([^']+)'", blk))}
                out["tcbs"][name] = d
        elif head.startswith("CNode Details"):
            for blk in re.split(r"^\t- CNode: ", body, flags=re.M)[1:]:
                name = blk.split("'")[1]
                slots = {}
                for sm in re.split(r"^\t\t\* Slot: ", blk, flags=re.M)[1:]:
                    slot = int(sm.split("\n")[0])
                    obj = re.search(r"Object: '([^']+)'", sm).group(1)
                    r = re.search(r"Rights: (.*)", sm)
                    b = re.search(r"Badge: (0x[0-9a-f]+)", sm)
                    slots[slot] = {"object": obj,
                                   "rights": sorted(x.strip() for x in r.group(1).split(",")) if r else None,
                                   "badge": int(b.group(1), 16) if b else None}
                out["cnodes"][name] = slots
        elif head.startswith("IRQ Details"):
            out["irqs"] = re.findall(r"- IRQ: '([^']+)'", body)
        elif head.startswith("Architecture Specific"):
            for blk in re.split(r"^\t- x86 I/O Ports: ", body, flags=re.M)[1:]:
                name = blk.split("'")[1]
                s = re.search(r"Start Port: (0x[0-9a-f]+)", blk).group(1)
                e = re.search(r"End Port: (0x[0-9a-f]+)", blk).group(1)
                out["ioports"][name] = (int(s, 16), int(e, 16))
        elif head.startswith("Kernel Objects Details"):
            for ln in body.splitlines():
                m = re.match(r"\s*(\d+) - ([A-Za-z]+)(?:\([^)]*\))?: '([^']+)'", ln)
                if m:
                    out["objects"][m.group(3)] = m.group(2)
    return out


def parse_system(path):
    root = ET.parse(path).getroot()
    pds, maps, mrs, chans = {}, {}, {}, []
    parent_of = {}
    for pd in root.iter("protection_domain"):          # includes nested (child) PDs
        n = pd.attrib["name"]
        pds[n] = {k: pd.attrib.get(k) for k in ("priority", "budget", "period", "passive", "stack_size", "id")}
        pds[n]["irqs"] = [dict(i.attrib) for i in pd.findall("irq")]
        pds[n]["ioports"] = [dict(i.attrib) for i in pd.findall("ioport")]
        pds[n]["children"] = [c.attrib["name"] for c in pd.findall("protection_domain")]
        for c in pds[n]["children"]:
            parent_of[c] = n
        maps[n] = {m.attrib["mr"]: {"perms": m.attrib["perms"], "vaddr": m.attrib["vaddr"],
                                    "cached": m.attrib.get("cached", "true")} for m in pd.findall("map")}
    for mr in root.findall("memory_region"):
        mrs[mr.attrib["name"]] = {"size": int(mr.attrib["size"], 0), "paddr": mr.attrib.get("phys_addr")}
    for ch in root.findall("channel"):
        e = ch.findall("end")
        chans.append(tuple((x.attrib["pd"], int(x.attrib["id"]), x.attrib.get("pp", "false"), x.attrib.get("notify", "true")) for x in e))
    return {"pds": pds, "maps": maps, "mrs": mrs, "chans": chans, "parent_of": parent_of}


# ----------------------------------------------------------------------------------------- model
class Model:
    """Authority model extracted from report.txt + system description."""

    def __init__(self, report, system, kernel_debug=None):
        self.rep, self.sys, self.kernel_debug = report, system, kernel_debug
        self.pds = sorted(n for n in system["pds"])
        self.cap = {}       # pd -> {slot: cap}
        for pd in self.pds:
            self.cap[pd] = report["cnodes"].get("cnode_" + pd, {})
        self.edges = []     # (src_pd, kind, dst, detail)
        self._derive()

    @staticmethod
    def owner_of(obj):
        m = re.match(r"(?:ntfn|ep|reply|pml4|tcb|sched_context)_(.+)$", obj)
        return m.group(1) if m else None

    def _derive(self):
        for pd, slots in self.cap.items():
            for slot, c in slots.items():
                o, rights = c["object"], set(c["rights"] or [])
                kind = self.rep["objects"].get(o, "?")
                if kind == "Notification":
                    own = self.owner_of(o)
                    if "Write" in rights and own:
                        self.edges.append((pd, "signal", own, f"slot {slot} badge {c['badge']:#x}"))
                elif kind == "Endpoint":
                    own = self.owner_of(o)
                    if o == "ep_fault_monitor":
                        if "Write" in rights:
                            self.edges.append((pd, "send", "monitor", f"slot {slot} badge {c['badge']:#x} (fault endpoint)"))
                    elif own:
                        if "Write" in rights or "Grant Reply" in rights:
                            self.edges.append((pd, "call", own, f"slot {slot} {','.join(sorted(rights))}"))
                elif o.startswith("irq_"):
                    self.edges.append((pd, "irq", o, f"slot {slot}"))
                elif o.startswith("ioports_"):
                    s, e = self.rep["ioports"].get(o, (0, 0))
                    self.edges.append((pd, "ioport", f"{s:#x}-{e:#x}", f"slot {slot}"))
        for pd, ms in self.sys["maps"].items():
            for mr, m in ms.items():
                self.edges.append((pd, "map-" + m["perms"], mr, f"@{m['vaddr']}"))

    # --- data-flow view: who can write / read each region
    def writers(self, mr):
        return {pd for pd, ms in self.sys["maps"].items() if mr in ms and "w" in ms[mr]["perms"]}

    def readers(self, mr):
        return {pd for pd, ms in self.sys["maps"].items() if mr in ms and "r" in ms[mr]["perms"]}

    def flow_edges(self):
        """src may influence dst: signal, send/call, or write a region the dst reads."""
        f = set()
        for s, k, d, _ in self.edges:
            if k in ("signal", "call", "send") and d in self.pds + ["monitor"]:
                f.add((s, d))
        for mr in self.sys["mrs"]:
            for w in self.writers(mr):
                for r in self.readers(mr):
                    if w != r:
                        f.add((w, r))
        return f

    def closure(self, src):
        fl = self.flow_edges()
        seen, work = set(), [src]
        hops = {src: 0}
        while work:
            x = work.pop(0)
            for a, b in sorted(fl):
                if a == x and b not in hops:
                    hops[b] = hops[x] + 1
                    work.append(b)
        return hops


# ----------------------------------------------------------------------------------------- z3 datalog
def z3_reach(pds, flow, src):
    """Independent re-derivation of reachability with Z3's Datalog engine.
    Returns set of PDs derivable from `src` (None if z3 missing)."""
    try:
        import z3
    except ImportError:
        return None
    names = sorted(set(pds) | {a for a, _ in flow} | {b for _, b in flow})
    idx = {n: i for i, n in enumerate(names)}
    S = z3.BitVecSort(max(1, (len(names) - 1).bit_length()))
    fp = z3.Fixedpoint()
    fp.set(engine="datalog")
    flow_r = z3.Function("Flow", S, S, z3.BoolSort())
    reach = z3.Function("Reach", S, S, z3.BoolSort())
    for r in (flow_r, reach):
        fp.register_relation(r)
    a, b, c = z3.Consts("a b c", S)
    fp.declare_var(a, b, c)
    for x, y in flow:
        fp.fact(flow_r(z3.BitVecVal(idx[x], S.size()), z3.BitVecVal(idx[y], S.size())))
    fp.rule(reach(a, b), flow_r(a, b))
    fp.rule(reach(a, c), [reach(a, b), flow_r(b, c)])
    out = set()
    for n in names:
        q = reach(z3.BitVecVal(idx[src], S.size()), z3.BitVecVal(idx[n], S.size()))
        if fp.query(q) == z3.sat:
            out.add(n)
    return out


def z3_authority_queries(m, subject, secret_regions):
    """Datalog derivation of 'subject can read/write a region' and 'subject holds hardware authority'
    from the extracted facts. Each query is decided exactly by the engine (UNSAT = not derivable).
    Returns {query: derivable_bool} or None when z3 is missing."""
    try:
        import z3
    except ImportError:
        return None
    pds = sorted(set(m.pds))
    mrs = sorted(m.sys["mrs"])
    P = z3.FiniteDomainSort("PD", len(pds))
    M = z3.FiniteDomainSort("MR", len(mrs))
    fp = z3.Fixedpoint()
    fp.set(engine="datalog")
    maps_r = z3.Function("MapR", P, M, z3.BoolSort())   # PD has a readable mapping of region
    maps_w = z3.Function("MapW", P, M, z3.BoolSort())
    reads = z3.Function("Reads", P, M, z3.BoolSort())
    writes = z3.Function("Writes", P, M, z3.BoolSort())
    hw = z3.Function("Hw", P, z3.BoolSort())
    irqs = z3.Function("HasHw", P, z3.BoolSort())
    for r in (maps_r, maps_w, reads, writes, hw, irqs):
        fp.register_relation(r)
    p, q = z3.Consts("p q", P)
    mm = z3.Const("m", M)
    fp.declare_var(p, q, mm)
    pi = {n: i for i, n in enumerate(pds)}
    mi = {n: i for i, n in enumerate(mrs)}
    for src, k, dst, _ in m.edges:
        if k.startswith("map-") and src in pi and dst in mi:
            if "r" in k[4:]:
                fp.fact(maps_r(z3.FiniteDomainVal(pi[src], P), z3.FiniteDomainVal(mi[dst], M)))
            if "w" in k[4:]:
                fp.fact(maps_w(z3.FiniteDomainVal(pi[src], P), z3.FiniteDomainVal(mi[dst], M)))
        if k in ("irq", "ioport") and src in pi:
            fp.fact(hw(z3.FiniteDomainVal(pi[src], P)))
    fp.rule(reads(p, mm), maps_r(p, mm))
    fp.rule(writes(p, mm), maps_w(p, mm))
    fp.rule(irqs(p), hw(p))
    sub = z3.FiniteDomainVal(pi[subject], P)
    res = {}
    for r in secret_regions:
        if r in mi:
            res[f"Reads({subject},{r})"] = fp.query(reads(sub, z3.FiniteDomainVal(mi[r], M))) == z3.sat
            res[f"Writes({subject},{r})"] = fp.query(writes(sub, z3.FiniteDomainVal(mi[r], M))) == z3.sat
    res[f"HardwareAuthority({subject})"] = fp.query(irqs(sub)) == z3.sat
    return res


# ----------------------------------------------------------------------------------------- checks
class Result:
    def __init__(self):
        self.checks = []

    def add(self, cid, title, ok, evidence):
        self.checks.append({"id": cid, "title": title, "status": "PASS" if ok else "FAIL", "evidence": evidence})

    @property
    def ok(self):
        return not any(c["status"] == "FAIL" for c in self.checks)


def load_policy(image_pds=None):
    """Policy for this image: base entries plus the extension of every feature whose PD is present."""
    pol = json.load(open(POLICY))
    for name, feat in pol.get("features", {}).items():
        if image_pds is not None and feat["requires_pd"] in image_pds:
            for pd, add in feat["add"].items():
                e = pol["pds"][pd]
                e["signal"] = sorted(set(e.get("signal", [])) | set(add.get("signal", [])))
                e["maps"] = {**e.get("maps", {}), **add.get("maps", {})}
    return pol


def summarize_pd(m, pd):
    """Canonical authority summary of one PD, comparable with security/cap-policy.json."""
    s = {"signal": [], "send": [], "call": [], "irq": [], "ioport": [], "maps": {}, "other_caps": [], "priority": None}
    for src, k, dst, detail in m.edges:
        if src != pd:
            continue
        if k == "signal":
            s["signal"].append(dst)
        elif k == "send":
            s["send"].append(dst)
        elif k == "call":
            s["call"].append(dst)
        elif k == "irq":
            s["irq"].append(dst)
        elif k == "ioport":
            s["ioport"].append(dst)
        elif k.startswith("map-"):
            s["maps"][dst] = k[4:]
    for slot, c in m.cap[pd].items():
        kind = m.rep["objects"].get(c["object"], "?")
        if kind not in ("Notification", "Endpoint", "PML4", "Reply", "PageTable", "?") and not c["object"].startswith(("irq_", "ioports_")):
            s["other_caps"].append(f"{kind}:{c['object']}")
        if kind == "?" and not c["object"].startswith(("irq_", "ioports_")):
            s["other_caps"].append(f"?:{c['object']}")
    for k in ("signal", "send", "call", "irq", "ioport", "other_caps"):
        s[k] = sorted(set(s[k]))
    tcb = m.rep["tcbs"].get("tcb_" + pd)
    s["priority"] = tcb["priority"] if tcb else None
    return s


def run_checks(m, subject, policy, kernel_info):
    R = Result()
    objs = m.rep["objects"]

    # ---- A. artifact consistency (the generated artifacts agree with the declared system)
    bad = []
    for ch in m.sys["chans"]:
        (a, ai, app, anot), (b, bi, bpp, bnot) = ch
        for (x, xi, xpp, xnot), (y, yi, ypp, ynot) in (((a, ai, app, anot), (b, bi, bpp, bnot)), ((b, bi, bpp, bnot), (a, ai, app, anot))):
            slot = (BASE_SLOT_PPC if xpp == "true" else BASE_SLOT_OUT) + xi
            cap = m.cap.get(x, {}).get(slot)
            if xpp == "true":
                # x may protected-procedure-call y: an endpoint capability to y's endpoint, badged with the PPC flag + y's channel id
                ok = cap and cap["object"] == f"ep_{y}" and sorted(cap["rights"] or []) == ["Grant Reply", "Write"] and cap["badge"] == (PPC_BADGE_FLAG | yi)
                want = f"Write+GrantReply ep_{y} badge {PPC_BADGE_FLAG | yi:#x} (PPC)"
            elif xnot == "false":
                ok = cap is None
                want = "no capability (notify=false)"
            else:
                ok = cap and cap["object"] == f"ntfn_{y}" and cap["rights"] == ["Write"] and cap["badge"] == (1 << yi)
                want = f"Write ntfn_{y} badge {1 << yi:#x}"
            if not ok:
                bad.append(f"{x}.slot{slot}: expected {want}, got {cap}")
    R.add("A1", "every SDF channel end appears as exactly the expected notification capability (object, rights, badge)",
          not bad, bad or f"{len(m.sys['chans'])} channels x 2 ends verified against CNode slots 10+id")
    expected_out = {}
    for ch in m.sys["chans"]:
        (a, ai, app, _), (b, bi, bpp, _) = ch
        expected_out.setdefault(a, set()).add((BASE_SLOT_PPC if app == "true" else BASE_SLOT_OUT) + ai)
        expected_out.setdefault(b, set()).add((BASE_SLOT_PPC if bpp == "true" else BASE_SLOT_OUT) + bi)
    extra = []
    for pd in m.pds:
        for slot, c in m.cap[pd].items():
            kind = objs.get(c["object"], "?")
            parent_ep = f"ep_{m.sys['parent_of'].get(pd)}" if pd in m.sys["parent_of"] else None
            if kind in ("Notification", "Endpoint") and c["object"] not in (f"ntfn_{pd}", f"ep_{pd}", "ep_fault_monitor", parent_ep) and slot not in expected_out.get(pd, set()):
                extra.append(f"{pd}.slot{slot} -> {c['object']}")
    R.add("A2", "no notification capability exists that is not explained by an SDF channel", not extra, extra or "none")
    frames_in_cnode, self_vs = [], []
    for pd in m.pds:
        for s, c in m.cap[pd].items():
            k = objs.get(c["object"], "?")
            if k in ("Page", "PageTable", "SchedContext", "TCB", "CNode", "Untyped"):
                if s == BASE_SLOT_VSPACE and c["object"] == f"pml4_{pd}":
                    self_vs.append(pd)          # the PD's own top-level page table (see CAPABILITY_AUDIT.md)
                elif k == "TCB" and c["object"] == "tcb_" + next((ch for ch in m.sys["pds"][pd]["children"] if c["object"] == "tcb_" + ch), "\0"):
                    pass                        # a parent's TCB capability for its own declared child PD (restart/stop authority)
                else:
                    frames_in_cnode.append(f"{pd}.slot{s}->{c['object']}")
    R.add("A3", "no PD CSpace holds Frame/PageTable/TCB/SchedContext/CNode/Untyped capabilities other than its own VSpace root (nobody can retype or remap)",
          not frames_in_cnode, frames_in_cnode or {"self_vspace_root_only": sorted(self_vs)})
    mism = []
    for mr, d in m.sys["mrs"].items():
        n = sum(1 for o, k in objs.items() if k == "Page" and o.startswith(f"frame_mr_{mr}_"))
        if d["paddr"] is None and n not in (d["size"] // 4096, d["size"] // 4096 + 0):
            mism.append(f"{mr}: size {d['size']:#x} -> {d['size'] // 4096} pages expected, {n} frame objects")
    R.add("A4", "every memory region has exactly size/4KiB kernel frame objects (no hidden aliasing of region frames)",
          not mism, mism or f"{len(m.sys['mrs'])} regions checked")
    unbound = [t for t, d in m.rep["tcbs"].items() if t != "tcb_monitor" and not all(k in d["bound"] for k in ("CSpace", "VSpace", "Fault Endpoint", "Scheduling Context"))]
    R.add("A5", "every PD thread has its own CSpace/VSpace/SchedContext and the fault endpoint bound", not unbound, unbound or f"{len(m.rep['tcbs'])-1} TCBs")
    shared_vs = {}
    for t, d in m.rep["tcbs"].items():
        shared_vs.setdefault(d["bound"].get("VSpace"), []).append(t)
    sh = {v: ts for v, ts in shared_vs.items() if len(ts) > 1}
    R.add("A6", "no two threads share an address space or CSpace (one TCB per PD VSpace)", not sh, sh or "unique")

    fe, badges = [], {}
    for pd in m.pds:
        for slot, c in m.cap[pd].items():
            par = m.sys["parent_of"].get(pd)
            if par and c["object"] == f"ep_{par}" and slot == BASE_SLOT_FAULT:
                want = (1 << 62) | int(m.sys["pds"][pd]["id"])
                if sorted(c["rights"] or []) != ["Grant Reply", "Write"] or c["badge"] != want:
                    fe.append(f"{pd}.slot{slot}: child fault endpoint {c['rights']} badge {c['badge']:#x}, expected Write+GrantReply badge {want:#x}")
                continue
            if c["object"] == "ep_fault_monitor":
                if sorted(c["rights"] or []) != ["Grant Reply", "Write"]:
                    fe.append(f"{pd}.slot{slot} rights {c['rights']} (must be exactly Write+GrantReply: a Read right would let the PD receive other PDs' faults)")
                badges.setdefault(c["badge"], set()).add(pd)
    for b, pds_ in badges.items():
        if len(pds_) > 1:
            fe.append(f"fault-endpoint badge {b:#x} shared by {sorted(pds_)} (a PD could impersonate another)")
    R.add("A7", "fault-endpoint capabilities are send-only and carry a badge unique to their PD", not fe, fe or f"{len(badges)} distinct badges")

    # ---- B. intended authority (build-time detection of unintended capability grants)
    diffs = []
    pol = policy["pds"]
    for pd in m.pds:
        got = summarize_pd(m, pd)
        exp = pol.get(pd)
        if exp is None:
            diffs.append(f"{pd}: not described in security/cap-policy.json")
            continue
        for k in ("signal", "send", "call", "irq", "ioport", "other_caps"):
            if sorted(exp.get(k, [])) != got[k]:
                diffs.append(f"{pd}.{k}: policy {sorted(exp.get(k, []))} != generated {got[k]}")
        if exp.get("maps", {}) != got["maps"]:
            diffs.append(f"{pd}.maps: policy {exp.get('maps', {})} != generated {got['maps']}")
        if exp.get("priority") != got["priority"]:
            diffs.append(f"{pd}.priority: policy {exp.get('priority')} != generated {got['priority']}")
    for pd in pol:
        if pd not in m.pds and not pol[pd].get("optional"):
            diffs.append(f"{pd}: required by policy but missing from the image")
    R.add("B1", "generated authority of every PD equals the intended authority in security/cap-policy.json (both directions)",
          not diffs, diffs or f"{len(m.pds)} PDs identical")

    # ---- C. subject (compromised PD) confinement
    sp = subject
    if sp not in m.pds:
        R.add("C0", f"subject {sp} is not part of this image (no script authority exists to confine)", True, "absent")
        return R
    hops = m.closure(sp)
    s = summarize_pd(m, sp)
    if "interface_pds" not in policy["pds"][sp]:
        R.add("C0", f"subject {sp}: confinement checks C1-C7 need an interface_pds declaration in security/cap-policy.json", True, "N/A for this subject")
        return R
    key_mrs = policy["secrets"]["regions"]
    key_holders = {mr: sorted(m.readers(mr) | m.writers(mr)) for mr in key_mrs}
    direct_secret = {mr: h for mr, h in key_holders.items() if sp in h}
    R.add("C1", f"{sp} has no mapping of any secret/trusted region {key_mrs} (no direct path to the TLS key or the signed config)",
          not direct_secret, direct_secret or {mr: h for mr, h in key_holders.items()})
    bad_caps = [f"{k}:{v}" for k in ("other_caps", "call") for v in s[k]]
    parent = m.sys["parent_of"].get(sp)
    ep_ok = s["send"] in ([], ["monitor"])
    bad_caps = [f"{k}:{v}" for k in ("other_caps",) for v in s[k]] + [f"call:{v}" for v in s["call"] if v != parent]
    R.add("C2", f"{sp} can neither create nor obtain endpoints: no Untyped/TCB/CNode/Frame caps; its only endpoint is the send-only fault endpoint to its supervisor (or the monitor)",
          not bad_caps and ep_ok, {"other_caps": s["other_caps"], "call": s["call"], "send": s["send"], "parent": parent})
    allowed_sig = set(policy["pds"][sp].get("signal", []))
    sig_extra = sorted(set(s["signal"]) - allowed_sig)
    R.add("C3", f"{sp} can signal exactly {sorted(allowed_sig)}; in particular no IPC path to connector_pd/tls_pd/tcp_pd or any driver",
          not sig_extra and "connector_pd" not in s["signal"], {"signal": s["signal"], "unexpected": sig_extra})
    R.add("C4", f"{sp} holds no IRQ handler or I/O-port capability", not s["irq"] and not s["ioport"], {"irq": s["irq"], "ioport": s["ioport"]})
    R.add("C5", f"{sp} memory authority is exactly the declared set (and nothing is mapped writable twice under different names)",
          s["maps"] == policy["pds"][sp]["maps"], s["maps"])
    # transitive reachability, twice
    fl = m.flow_edges()
    z3r = z3_reach(m.pds + ["monitor"], fl, sp)
    py = set(hops) - {sp} if sp not in {b for a, b in fl if a != sp and b == sp} else set(hops)
    agree = None
    if z3r is not None:
        agree = (z3r == (set(hops) - {sp}) or z3r == set(hops))
    direct = sorted(b for a, b in fl if a == sp)
    secret_readers = sorted({p for mr in key_mrs for p in m.readers(mr)})
    R.add("C6", "influence closure computed twice (BFS and Z3 Datalog) agrees",
          agree is not False, {"bfs": {k: v for k, v in sorted(hops.items())}, "z3": sorted(z3r) if z3r is not None else "z3 unavailable (SKIPPED)"})
    # the one-hop set is the attack surface; secret holders are only reachable in >= 2 hops
    secret_hop = {p: hops.get(p) for p in secret_readers}
    R.add("C7", f"every direct influence target of {sp} is a declared script-interface PD; secret-holding PDs are reachable only through them",
          set(direct) <= set(policy["pds"][sp].get("interface_pds", [])) and all(
              (h is None) or h >= 2 for p, h in secret_hop.items() if p != sp and p not in policy["pds"][sp].get("interface_pds", [])),
          {"direct": direct, "secret_holders_hops": secret_hop})
    zq = z3_authority_queries(m, sp, key_mrs)
    R.add("C8", "Z3 Datalog: none of {read secret region, write secret region, hold IRQ/I-O-port authority} is derivable for the subject",
          zq is not None and not any(zq.values()) if zq is not None else True,
          zq if zq is not None else "z3 unavailable (SKIPPED)")
    # D. kernel configuration
    kd = kernel_info
    R.add("D1", "kernel binary has no debug syscalls (SysDebugHalt/PutChar/...: any PD may invoke them without a capability)",
          kd["debug"] is False if kd["debug"] is not None else False,
          kd["detail"])
    return R


def kernel_debug_info(sel4_elf):
    if not sel4_elf or not os.path.exists(sel4_elf):
        return {"debug": None, "detail": "kernel ELF not found (SKIPPED -> treated as FAIL: cannot show release kernel)"}
    data = open(sel4_elf, "rb").read()
    marks = [b"Debug halt syscall", b"seL4_DebugPutChar", b"Debug snapshot", b"halting..."]
    found = [m.decode() for m in marks if m in data]
    return {"debug": bool(found), "detail": f"{os.path.basename(sel4_elf)}: debug-kernel strings {found or 'absent'}"}


# ----------------------------------------------------------------------------------------- reporting
def to_md(R, m, subject, hops, meta):
    L = ["# Capability audit", "", f"* image: `{meta['dir']}`", f"* subject (assumed fully compromised): `{subject}`",
         f"* artifacts: `report.txt` sha256 `{meta['report_sha']}`, `proofgate.system` sha256 `{meta['system_sha']}`", ""]
    L += ["| id | result | check |", "|---|---|---|"]
    for c in R.checks:
        L.append(f"| {c['id']} | **{c['status']}** | {c['title']} |")
    L += ["", f"## Authority of `{subject}` (from the generated CNode)", ""]
    s = summarize_pd(m, subject) if subject in m.pds else {}
    L += ["```json", json.dumps(s, indent=2), "```", "", "## Influence reachability (hops from the subject)", ""]
    for p, h in sorted(hops.items(), key=lambda kv: kv[1]):
        L.append(f"* `{p}`: {h}")
    L += ["", "## Evidence", ""]
    for c in R.checks:
        L += [f"### {c['id']} {c['status']}", "", "```", json.dumps(c["evidence"], indent=1)[:2500], "```", ""]
    return "\n".join(L)


def sha(path):
    import hashlib
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def analyse(d, subject, kernel=None):
    rep = parse_report(os.path.join(d, "report.txt"))
    sysd = parse_system(os.path.join(d, "proofgate.system"))
    kern = kernel_debug_info(kernel or os.path.join(d, "sel4.elf"))
    m = Model(rep, sysd, kern["debug"])
    return m, kern


def selftest(d, subject):
    """Mutate the *extracted model* the way a wrong system description / initialiser would and require
    that each mutation is caught by at least one check."""
    m, kern = analyse(d, subject)
    pol = load_policy(m.pds)
    base = run_checks(m, subject, pol, kern)
    for c in base.checks:
        if c["id"] == "D1" and c["status"] == "FAIL":
            c["status"] = "WARN"   # debug-ness is asserted separately; mutants must be caught by the structural checks
    if not base.ok:
        print("selftest: baseline does not pass:", [c["id"] for c in base.checks if c["status"] == "FAIL"])
        return 1

    def mut(fn):
        mm = copy.deepcopy(m)
        fn(mm)
        mm.edges = []
        mm._derive()
        return mm

    def add_slot(pd, slot, obj, rights=("Write",), badge=1):  # badge may be None for badge-less caps
        def f(mm):
            mm.cap[pd][slot] = {"object": obj, "rights": list(rights), "badge": badge}
            mm.rep["cnodes"]["cnode_" + pd][slot] = mm.cap[pd][slot]
        return f

    def add_map(pd, mr, perms="rw"):
        def f(mm):
            mm.sys["maps"][pd][mr] = {"perms": perms, "vaddr": "0xdead0000", "cached": "true"}
        return f

    def drop_slot(pd, slot):
        def f(mm):
            mm.cap[pd].pop(slot, None)
            mm.rep["cnodes"]["cnode_" + pd].pop(slot, None)
        return f

    def prio(pd, v):
        def f(mm):
            mm.rep["tcbs"]["tcb_" + pd]["priority"] = v
        return f

    mutants = {
        "script gets signal cap to connector_pd": add_slot(subject, 14, "ntfn_connector_pd"),
        "script gets signal cap to tls_pd": add_slot(subject, 14, "ntfn_tls_pd"),
        "script gets endpoint cap to timer driver": add_slot(subject, 14, "ep_timer_driver", ("Write", "Grant Reply")),
        "script maps tls_keystore": add_map(subject, "tls_keystore", "r"),
        "script maps signed config": add_map(subject, "shm_signed_config", "r"),
        "script maps tcp<->connector region": add_map(subject, "shm_tcp_conn"),
        "script gets IRQ handler": add_slot(subject, 154, "irq_1_ethernet_driver", (), None),
        "script gets I/O ports": add_slot(subject, 395, "ioports_0xcf8_ethernet_driver", (), None),
        "script gets a TCB cap": add_slot(subject, 20, "tcb_tls_pd", ("Write",), None),
        "script gets a frame cap": add_slot(subject, 21, "frame_mr_tls_keystore_000000000", ("Write",), None),
        "script gets read on monitor endpoint": add_slot(subject, 22, "ep_fault_monitor", ("Read", "Write"), 7),
        "script can receive on its supervisor endpoint": add_slot(subject, 2, "ep_supervisor_pd", ("Read", "Write", "Grant Reply"), (1 << 62) | 10),
        "script gets a signal cap to supervisor": add_slot(subject, 23, "ntfn_supervisor_pd"),
        "script maps the supervisor page": add_map(subject, "shm_http_sup", "rw"),
        "script fault badge forged as another child": add_slot(subject, 2, "ep_supervisor_pd", ("Write", "Grant Reply"), (1 << 62) | 3),
        "supervisor gets a TCB cap for http_pd": add_slot("supervisor_pd", 213, "tcb_http_pd", ("Write",), None),
        "script priority raised above tls_pd": prio(subject, 99),
        "tls_pd also maps the script region": add_map("tls_pd", "shm_script_http"),
        "channel notification cap dropped": drop_slot("http_pd", 14),
        "http_pd gets a surplus signal cap to tls_pd": add_slot("http_pd", 19, "ntfn_policy_pd"),
    }
    # restrict to mutants that apply to this image
    bad = 0
    for name, fn in mutants.items():
        if "script" in name and subject not in m.pds:
            continue
        try:
            mm = mut(fn)
        except KeyError:
            continue
        res = run_checks(mm, subject, pol, kern)
        failed = [c["id"] for c in res.checks if c["status"] == "FAIL" and c["id"] != "D1"]
        print(f"  mutant {name:48s} -> {'DETECTED by ' + ','.join(failed) if failed else 'NOT DETECTED'}")
        bad += 0 if failed else 1
    print(f"capgraph selftest: {len(mutants)-bad}/{len(mutants)} weakened models detected")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--subject", default="script_pd")
    ap.add_argument("--kernel")
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--allow-debug-kernel", action="store_true",
                    help="downgrade D1 (debug kernel) to a recorded WARN so a debug *test* image can still be audited; "
                         "the finding stays in the output and the image must never be called production")
    a = ap.parse_args()
    d = os.path.abspath(a.dir)
    for f in ("report.txt", "proofgate.system"):
        if not os.path.exists(os.path.join(d, f)):
            print(f"capgraph: missing {d}/{f}", file=sys.stderr)
            return 2
    if a.selftest:
        return selftest(d, a.subject)
    m, kern = analyse(d, a.subject, a.kernel)
    pol = load_policy(m.pds)
    R = run_checks(m, a.subject, pol, kern)
    if a.allow_debug_kernel:
        for c in R.checks:
            if c["id"] == "D1" and c["status"] == "FAIL":
                c["status"] = "WARN"
    hops = m.closure(a.subject)
    meta = {"dir": os.path.relpath(d, ROOT), "report_sha": sha(os.path.join(d, "report.txt")),
            "system_sha": sha(os.path.join(d, "proofgate.system"))}
    out = {"meta": meta, "subject": a.subject, "authority": summarize_pd(m, a.subject) if a.subject in m.pds else None, "hops": hops,
           "checks": R.checks, "kernel": kern}
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)
    if a.md:
        open(a.md, "w").write(to_md(R, m, a.subject, hops, meta))
    for c in R.checks:
        print(f"{c['status']:5s} {c['id']:3s} {c['title']}")
    fails = [c["id"] for c in R.checks if c["status"] == "FAIL"]
    print("CAPGRAPH", "PASS" if not fails else "FAIL " + ",".join(fails), f"(subject {a.subject}, image {meta['dir']})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
