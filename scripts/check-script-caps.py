#!/usr/bin/env python3
"""
Compatibility wrapper: the QED Script capability audit is now scripts/capgraph.py, which analyses what Microkit's
CapDL initialiser actually builds (report.txt: every CNode slot with rights and badge) against the intended authority in
security/cap-policy.json, and cross-checks the system description. The previous SDF-only audit is superseded.

usage:
  check-script-caps.py [path/to/proofgate.system]   audit the image directory that contains it (subject: script_pd)
  check-script-caps.py --selftest                   capgraph's mutation self-test on build/sel4-script
A debug-kernel image is reported as WARN (D1) and must never be called production; see docs/CAPABILITY_AUDIT.md.
"""
import os, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CG = os.path.join(ROOT, "scripts/capgraph.py")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return subprocess.call([sys.executable, CG, "--dir", os.path.join(ROOT, "build/sel4-script"), "--selftest"])
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build/sel4-script/proofgate.system")
    rc = subprocess.call([sys.executable, CG, "--dir", os.path.dirname(os.path.abspath(path)), "--allow-debug-kernel"])
    print("SCRIPT_CAP_AUDIT", "PASS" if rc == 0 else "FAIL", "(delegated to scripts/capgraph.py)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
