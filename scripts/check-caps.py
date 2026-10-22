#!/usr/bin/env python3
"""
qedos — Formal Capability & Isolation Audit (`LAW_008`, `LAW_011`, `LAW_012`).

Verifies both the Microkit system description (`build/sel4/proofgate.system`),
the Microkit-generated Viper formal invariant models (`build/sel4/viper/*.vpr`),
and the compiled PD ELF binaries (`build/sel4/*.elf`).
"""
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# QEDOS_SEL4_DIR selects the image directory (default build/sel4 = x86_64; e.g. build/sel4-qemu_virt_aarch64).
SEL4_DIR = os.path.abspath(os.environ.get("QEDOS_SEL4_DIR", os.path.join(ROOT, "build/sel4")))
SYS_XML = os.path.join(SEL4_DIR, "proofgate.system")
VIPER_DIR = os.path.join(SEL4_DIR, "viper")

APP_PDS = {"tcp_pd", "tls_pd", "http_pd", "policy_pd", "connector_pd"}  # + script_pd when present
DRIVER_PDS = {"ethernet_driver", "serial_driver", "timer_driver"}


def fail(msg: str) -> None:
    print(f"CAP_AUDIT FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


NON_TLS_PD_ELFS = ["http_pd.elf", "policy_pd.elf", "connector_pd.elf", "tcp_pd.elf"]
# QED Script images also contain script_pd.elf, which must never hold key material either (LAW_018)
if os.path.isfile(os.path.join(SEL4_DIR, "script_pd.elf")):
    NON_TLS_PD_ELFS.append("script_pd.elf")
LOADER_IMG = os.path.join(SEL4_DIR, "loader.img")
KEY_PEM_MARK = b"-----BEGIN PRIVATE KEY-----"
CERT_PEM_MARK = b"-----BEGIN CERTIFICATE-----"
# `.tls_keystore` layout produced by scripts/build-sel4.sh: cert.ljust(2048) + key.ljust(2048)
KEYSTORE_CERT_SLOT = 2048


def read_loader_image() -> bytes:
    """Return the Microkit boot image (`loader.img`), transparently decompressing `loader.img.gz`."""
    if os.path.isfile(LOADER_IMG):
        return open(LOADER_IMG, "rb").read()
    if os.path.isfile(LOADER_IMG + ".gz"):
        import gzip

        with gzip.open(LOADER_IMG + ".gz", "rb") as fh:
            return fh.read()
    fail(f"missing {LOADER_IMG} / {LOADER_IMG}.gz (run scripts/build-sel4.sh first)")
    return b""  # unreachable


def audit_private_key_isolation() -> str:
    """LAW_008: the TLS private key must live only in `tls_pd`'s `.tls_keystore`.

    Full-build mode (Linux dev host after scripts/build-sel4.sh): every non-TLS PD ELF is scanned
    and must not contain PEM private-key material.

    Prebuilt-image mode (e.g. macOS using the committed `loader.img.gz`, where the per-PD ELFs are
    not shipped): the flattened boot image is scanned instead. The PEM private key must occur exactly
    once, and that single occurrence must sit at the `.tls_keystore` layout offset (certificate slot
    followed by key slot), i.e. inside the one region that `proofgate.system` maps only into `tls_pd`.
    """
    present = [e for e in NON_TLS_PD_ELFS if os.path.isfile(os.path.join(SEL4_DIR, e))]
    for elf_name in present:
        blob = open(os.path.join(SEL4_DIR, elf_name), "rb").read()
        if b"BEGIN PRIVATE KEY" in blob:
            fail(f"LAW_008 violated: private key material found inside {elf_name}!")
    if len(present) == len(NON_TLS_PD_ELFS):
        return "pd-elf"

    img = read_loader_image()
    key_offsets = []
    pos = img.find(KEY_PEM_MARK)
    while pos != -1:
        key_offsets.append(pos)
        pos = img.find(KEY_PEM_MARK, pos + 1)
    if len(key_offsets) != 1:
        fail(
            f"LAW_008 violated: expected exactly 1 private-key PEM in loader image "
            f"(tls_pd .tls_keystore), found {len(key_offsets)} at {key_offsets}"
        )
    k = key_offsets[0]
    cert_off = k - KEYSTORE_CERT_SLOT
    if cert_off < 0 or img[cert_off : cert_off + len(CERT_PEM_MARK)] != CERT_PEM_MARK:
        fail(
            "LAW_008 violated: private-key PEM in loader image is not at the tls_pd .tls_keystore "
            f"layout offset (no certificate slot {KEYSTORE_CERT_SLOT} bytes before key at {k})"
        )
    missing = sorted(set(NON_TLS_PD_ELFS) - set(present))
    print(
        f"CAP_AUDIT NOTE: per-PD ELFs {missing} not present; scanned prebuilt loader image "
        f"({len(img)} bytes) instead — private key occurs once, at tls_pd .tls_keystore offset {k}."
    )
    return "loader-image"


def main() -> None:
    if not os.path.isfile(SYS_XML):
        fail(f"missing {SYS_XML} (run scripts/build-sel4.sh first)")

    tree = ET.parse(SYS_XML)
    root = tree.getroot()

    pd_maps: dict[str, dict[str, str]] = {}
    pd_irqs: dict[str, int] = {}
    pd_ioports: dict[str, int] = {}
    channels: list[tuple[str, int, str, int]] = []

    for pd in root.findall("protection_domain"):
        name = pd.attrib["name"]
        pd_maps[name] = {}
        for m in pd.findall("map"):
            pd_maps[name][m.attrib["mr"]] = m.attrib["perms"]
        pd_irqs[name] = len(pd.findall("irq"))
        pd_ioports[name] = len(pd.findall("ioport"))

    for ch in root.findall("channel"):
        ends = ch.findall("end")
        if len(ends) != 2:
            fail("channel does not have exactly 2 ends")
        a_pd, a_id = ends[0].attrib["pd"], int(ends[0].attrib["id"])
        b_pd, b_id = ends[1].attrib["pd"], int(ends[1].attrib["id"])
        channels.append((a_pd, a_id, b_pd, b_id))

    def neighbors(target_pd: str) -> set[str]:
        res = set()
        for a_pd, _, b_pd, _ in channels:
            if a_pd == target_pd:
                res.add(b_pd)
            elif b_pd == target_pd:
                res.add(a_pd)
        return res

    # 1. LAW_008: TLS private key (`tls_keystore`) mapped ONLY in `tls_pd` (read-only)
    keystore_holders = [pd for pd, mrs in pd_maps.items() if "tls_keystore" in mrs]
    if keystore_holders != ["tls_pd"]:
        fail(f"LAW_008 violated: tls_keystore mapped in {keystore_holders}, expected ['tls_pd']")
    if pd_maps["tls_pd"]["tls_keystore"] != "r":
        fail(f"LAW_008 violated: tls_keystore has perms={pd_maps['tls_pd']['tls_keystore']}, expected 'r'")

    # Check compiled PD binaries: private key PEM must NOT appear in any non-TLS PD
    key_scan_mode = audit_private_key_isolation()

    # 2. LAW_011: Signed config (`shm_signed_config`) mapped ONLY in `policy_pd` (read-only)
    cfg_holders = [pd for pd, mrs in pd_maps.items() if "shm_signed_config" in mrs]
    if cfg_holders != ["policy_pd"]:
        fail(f"LAW_011 violated: shm_signed_config mapped in {cfg_holders}, expected ['policy_pd']")
    if pd_maps["policy_pd"]["shm_signed_config"] != "r":
        fail("LAW_011 violated: shm_signed_config must be read-only ('r') in policy_pd")

    # 3. LAW_012: Hardware IRQs and I/O ports restricted strictly to driver PDs
    for pd in APP_PDS:
        if pd_irqs.get(pd, 0) != 0 or pd_ioports.get(pd, 0) != 0 or pd_irqs.get("script_pd", 0) != 0 or pd_ioports.get("script_pd", 0) != 0:
            fail(f"LAW_012 violated: application PD {pd} holds hardware IRQ or ioport capability")

    # 4. LAW_012: Strict PD communication graph topology
    expected_mrs = {
        "tls_pd": {"shm_tcp_tls", "shm_tls_http", "tls_keystore"},
        "http_pd": {"shm_tls_http", "shm_http_policy", "shm_conn_http"},
        "policy_pd": {"shm_http_policy", "shm_signed_config", "shm_policy_conn"},
        "connector_pd": {"shm_policy_conn", "shm_conn_http", "shm_tcp_conn"},
    }
    if "script_pd" in pd_maps:
        # QED Script image (QEDOS_SCRIPT=1): the two script regions are the only additions; script_pd's own
        # authority is audited exhaustively by scripts/check-script-caps.py (LAW_013..LAW_022).
        expected_mrs["http_pd"] = expected_mrs["http_pd"] | {"shm_script_http"}
        expected_mrs["policy_pd"] = expected_mrs["policy_pd"] | {"shm_policy_script"}
        expected_mrs["script_pd"] = {"shm_policy_script", "shm_script_http"}
    for pd, exp in expected_mrs.items():
        actual = set(pd_maps[pd].keys())
        if actual != exp:
            fail(f"LAW_012 violated: {pd} maps {actual}, expected {exp}")

    expected_neighbors = {
        "tls_pd": {"tcp_pd", "http_pd"},
        "http_pd": {"tls_pd", "policy_pd", "connector_pd"},
        "policy_pd": {"http_pd", "connector_pd"},
        "connector_pd": {"policy_pd", "http_pd", "tcp_pd"},
    }
    if "script_pd" in pd_maps:
        expected_neighbors["http_pd"] = expected_neighbors["http_pd"] | {"script_pd"}
        expected_neighbors["policy_pd"] = expected_neighbors["policy_pd"] | {"script_pd"}
        expected_neighbors["script_pd"] = {"policy_pd", "http_pd"}
    for pd, exp in expected_neighbors.items():
        actual = neighbors(pd)
        if actual != exp:
            fail(f"LAW_012 violated: {pd} has channels to {actual}, expected {exp}")

    # 5. Verify Microkit-generated Viper `.vpr` capability models
    for pd in pd_maps:
        vpr_path = os.path.join(VIPER_DIR, f"{pd}.vpr")
        if not os.path.isfile(vpr_path):
            fail(f"missing Viper specification {vpr_path}")
        vpr = open(vpr_path, "r", encoding="utf-8").read()

        if pd != "tls_pd" and "mem_tls_keystore_contains" in vpr:
            fail(f"LAW_008 Viper violation: {pd}.vpr references mem_tls_keystore_contains")
        if pd == "tls_pd":
            if "define mem_tls_keystore_contains(x)" not in vpr:
                fail("LAW_008 Viper violation: tls_pd.vpr missing mem_tls_keystore_contains")
            for line in vpr.splitlines():
                if line.startswith("define mem_writeable(x)") and "mem_tls_keystore_contains" in line:
                    fail("LAW_008 Viper violation: tls_keystore is writeable in tls_pd.vpr")

        if pd in APP_PDS | {"script_pd"}:
            if "define pansel4_has_irq_handler_cap(x) (false)" not in vpr:
                fail(f"LAW_012 Viper violation: {pd}.vpr has IRQ handler cap")
            if "define pansel4_has_ioport_cap(x) (false)" not in vpr:
                fail(f"LAW_012 Viper violation: {pd}.vpr has ioport cap")
            if "define pansel4_has_tcb_cap(x) (false)" not in vpr:
                fail(f"LAW_012 Viper violation: {pd}.vpr has TCB cap")

    print(
        f"CAP_AUDIT PASS: verified {len(pd_maps)} PDs, {len(channels)} channels, "
        f"and {len(pd_maps)} Viper (.vpr) capability models (LAW_008, LAW_011, LAW_012); "
        f"private-key isolation checked via {key_scan_mode}."
    )


if __name__ == "__main__":
    main()
