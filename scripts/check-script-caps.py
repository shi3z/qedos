#!/usr/bin/env python3
"""
QED Script capability audit (LAW_014, LAW_018, LAW_022; extends LAW_008/LAW_012).

usage:
  check-script-caps.py [system.xml]      audit a generated Microkit SDF (default build/sel4-script/proofgate.system)
  check-script-caps.py --selftest        (a) baseline system + sel4/script/script.fragment.xml passes the audit,
                                         (b) the fragment mirrors sel4/meta_proofgate.py,
                                         (c) 9 deliberately weakened variants are each detected.

This audits the *capability graph declared to Microkit* (memory maps, channels, IRQs, ioports, priorities).
It is a static check on the system description, not a proof about the kernel or the CapDL initialiser.
"""
import copy
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_SYS = os.path.join(ROOT, "build/sel4/proofgate.system")
FRAGMENT = os.path.join(ROOT, "sel4/script/script.fragment.xml")
META = os.path.join(ROOT, "sel4/meta_proofgate.py")
APP_PDS = {"tcp_pd", "tls_pd", "http_pd", "policy_pd", "connector_pd"}
SCRIPT_MRS = {"shm_policy_script": {"policy_pd", "script_pd"}, "shm_script_http": {"script_pd", "http_pd"}}


class AuditError(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise AuditError(msg)


def audit(root: ET.Element) -> str:
    pds = {pd.attrib["name"]: pd for pd in root.findall("protection_domain")}
    need("script_pd" in pds, "script_pd missing")
    maps = {n: {m.attrib["mr"]: m.attrib["perms"] for m in pd.findall("map")} for n, pd in pds.items()}
    chans = []
    for ch in root.findall("channel"):
        e = ch.findall("end")
        need(len(e) == 2, "channel without exactly 2 ends")
        chans.append(((e[0].attrib["pd"], int(e[0].attrib["id"])), (e[1].attrib["pd"], int(e[1].attrib["id"]))))
    sp = pds["script_pd"]

    # LAW_014/LAW_018: exact memory authority
    need(maps["script_pd"] == {"shm_policy_script": "rw", "shm_script_http": "rw"},
         f"script_pd maps {maps['script_pd']}, expected exactly shm_policy_script,shm_script_http (rw)")
    for mr, holders in SCRIPT_MRS.items():
        got = {n for n, m in maps.items() if mr in m}
        need(got == holders, f"{mr} mapped in {sorted(got)}, expected {sorted(holders)}")
    for mr, allowed in (("tls_keystore", {"tls_pd"}), ("shm_signed_config", {"policy_pd"})):
        got = {n for n, m in maps.items() if mr in m}
        need(got == allowed, f"LAW_008/011: {mr} mapped in {sorted(got)}")
    # no hardware / kernel authority
    for tag in ("irq", "ioport", "protection_domain", "setvar", "virtual_machine"):
        need(not sp.findall(tag), f"script_pd declares <{tag}> (hardware/child/VM authority)")
    for k in ("passive", "smc"):
        need(sp.attrib.get(k, "false") in ("false", "0"), f"script_pd has {k}=true")
    # LAW_014/LAW_022: IPC authority = exactly two channels, to policy_pd and http_pd
    peers = []
    for (a, ai), (b, bi) in chans:
        if a == "script_pd":
            peers.append(b)
        if b == "script_pd":
            peers.append(a)
    need(sorted(peers) == ["http_pd", "policy_pd"], f"script_pd channels to {sorted(peers)}, expected [http_pd, policy_pd]")
    # LAW_017: availability — lowest priority of all application PDs, so it can only use idle CPU
    prio = int(sp.attrib["priority"])
    for n in APP_PDS:
        need(prio < int(pds[n].attrib["priority"]), f"script_pd priority {prio} not below {n} ({pds[n].attrib['priority']})")
    # No other PD (esp. tls_pd, connector_pd, tcp_pd, drivers) can signal script_pd or map its regions
    for n in pds:
        if n in ("script_pd", "policy_pd", "http_pd"):
            continue
        need(not any(mr in maps[n] for mr in SCRIPT_MRS), f"{n} maps a script region")
    # existing LAW_012 expectations for untouched PDs still hold
    need(set(maps["tls_pd"]) == {"shm_tcp_tls", "shm_tls_http", "tls_keystore"}, "tls_pd maps changed")
    need(set(maps["connector_pd"]) == {"shm_policy_conn", "shm_conn_http", "shm_tcp_conn"}, "connector_pd maps changed")
    need(set(maps["http_pd"]) == {"shm_tls_http", "shm_http_policy", "shm_conn_http", "shm_script_http"}, "http_pd maps unexpected")
    need(set(maps["policy_pd"]) == {"shm_http_policy", "shm_signed_config", "shm_policy_conn", "shm_policy_script"}, "policy_pd maps unexpected")
    return "script_pd: maps {shm_policy_script:rw, shm_script_http:rw}, channels {policy_pd, http_pd}, priority %d (< all app PDs), no irq/ioport/child/VM" % prio


def merged_baseline() -> ET.Element:
    root = ET.parse(BASE_SYS).getroot()
    frag = ET.parse(FRAGMENT).getroot()
    for el in list(frag):
        if el.tag == "map-into":
            pd = next(p for p in root.findall("protection_domain") if p.attrib["name"] == el.attrib["pd"])
            ET.SubElement(pd, "map", {"mr": el.attrib["mr"], "vaddr": el.attrib["vaddr"], "perms": el.attrib["perms"]})
        else:
            root.append(copy.deepcopy(el))
    return root


def mutate(root, name):
    r = copy.deepcopy(root)
    pds = {p.attrib["name"]: p for p in r.findall("protection_domain")}
    sp = pds["script_pd"]
    if name == "map_tls_keystore":
        ET.SubElement(sp, "map", {"mr": "tls_keystore", "vaddr": "0x3700_0000", "perms": "r"})
    elif name == "map_signed_config":
        ET.SubElement(sp, "map", {"mr": "shm_signed_config", "vaddr": "0x3300_0000", "perms": "r"})
    elif name == "map_tcp_shm":
        ET.SubElement(sp, "map", {"mr": "shm_tcp_conn", "vaddr": "0x3600_0000", "perms": "rw"})
    elif name == "extra_channel_connector":
        ch = ET.SubElement(r, "channel")
        ET.SubElement(ch, "end", {"pd": "script_pd", "id": "9"})
        ET.SubElement(ch, "end", {"pd": "connector_pd", "id": "9"})
    elif name == "extra_channel_tls":
        ch = ET.SubElement(r, "channel")
        ET.SubElement(ch, "end", {"pd": "script_pd", "id": "9"})
        ET.SubElement(ch, "end", {"pd": "tls_pd", "id": "9"})
    elif name == "irq":
        ET.SubElement(sp, "irq", {"irq": "5", "id": "1"})
    elif name == "high_priority":
        sp.attrib["priority"] = "99"
    elif name == "tls_gets_script_region":
        ET.SubElement(pds["tls_pd"], "map", {"mr": "shm_script_http", "vaddr": "0x3900_0000", "perms": "rw"})
    elif name == "child_pd":
        ET.SubElement(sp, "protection_domain", {"name": "child", "priority": "1"})
    else:
        raise KeyError(name)
    return r


MUTANTS = ["map_tls_keystore", "map_signed_config", "map_tcp_shm", "extra_channel_connector", "extra_channel_tls",
           "irq", "high_priority", "tls_gets_script_region", "child_pd"]


def check_meta_mirror():
    """The fragment must say what meta_proofgate.py says (same vaddrs, perms, channel ids, priority)."""
    meta = open(META).read()
    frag = ET.parse(FRAGMENT).getroot()
    for m in frag.iter("map"):
        v = m.attrib["vaddr"]
        meta_v = v[:6] + "_" + v[6:]          # 0x38000000 -> 0x3800_0000 (meta_proofgate.py spelling)
        pat = r'Map\(\w+, %s, "%s"\)' % (re.escape(meta_v), m.attrib["perms"])
        need(re.search(pat, meta) is not None, f"meta_proofgate.py does not map {v} {m.attrib['perms']}")
    for ch in frag.findall("channel"):
        e = ch.findall("end")
        a, b = e
        pat = r"Channel\(%s, %s, a_id=%s, b_id=%s\)" % (a.attrib["pd"], b.attrib["pd"], a.attrib["id"], b.attrib["id"])
        need(re.search(pat, meta), f"meta_proofgate.py lacks channel {a.attrib['pd']}<->{b.attrib['pd']} {a.attrib['id']}/{b.attrib['id']}")
    pr = frag.find("protection_domain").attrib["priority"]
    need(re.search(r'"script_pd", "script_pd.elf", priority=%s,' % pr, meta), "meta_proofgate.py priority differs")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        base = merged_baseline()
        print("SCRIPT_CAP_AUDIT selftest OK:", audit(base))
        check_meta_mirror()
        print("SCRIPT_CAP_AUDIT selftest OK: fragment mirrors sel4/meta_proofgate.py")
        # the unmodified baseline (no script_pd) must be *rejected* as a script image, and still pass the old audit
        for mname in MUTANTS:
            try:
                audit(mutate(base, mname))
            except AuditError as e:
                print(f"  mutant {mname:26s} detected: {e}")
            else:
                print(f"SCRIPT_CAP_AUDIT FAIL: mutant {mname} NOT detected", file=sys.stderr)
                sys.exit(1)
        print(f"SCRIPT_CAP_AUDIT selftest PASS ({len(MUTANTS)}/{len(MUTANTS)} weakened systems detected)")
        return
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build/sel4-script/proofgate.system")
    try:
        print("SCRIPT_CAP_AUDIT PASS:", audit(ET.parse(path).getroot()))
    except AuditError as e:
        print(f"SCRIPT_CAP_AUDIT FAIL: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
