#!/usr/bin/env python3
"""Build + sign every hostile case into examples/malicious/out/<name>/ (app.wasm app.policy app.sig)."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
from cases import CASES
root = os.path.abspath(os.path.join(here, "..", ".."))
QS = os.environ.get("QS", os.path.join(root, "build/qs/ws/target/debug/qs"))
SEED = os.path.join(root, "config/keys/qs-code-signing-seed.hex")
for name, c in CASES.items():
    d = os.path.join(here, "out", name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "app.wasm"), "wb").write(c["wasm"])
    open(os.path.join(d, "app.policy"), "w").write(c["policy"])
    subprocess.run([QS, "sign", "--seed", SEED, d], check=True, stdout=subprocess.DEVNULL)
print(f"built {len(CASES)} hostile modules")
