#!/usr/bin/env python3
"""
Regression corpus for defects found by differential fuzzing / review of the Wasm loader.

tests/wasm-corpus/reject/*.wasm : modules the WebAssembly spec (and V8, checked here as ground truth when node is
available) rejects. They were each ACCEPTED by an earlier version of our loader. They must now be rejected.
Each file is additionally checked with the reference engine so a wrong corpus entry cannot hide a regression.
"""
import os, struct, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QS = os.environ.get("QS", os.path.join(ROOT, "build/qs/ws/target/release/qs"))
D = os.path.join(ROOT, "tests/wasm-corpus/reject")

if not os.path.exists(QS):
    print("SKIPPED: qs binary missing"); sys.exit(2)
names = sorted(os.listdir(D))
frames = b"".join(bytes([1]) + struct.pack("<I", os.path.getsize(os.path.join(D, n))) + open(os.path.join(D, n), "rb").read() for n in names)
tmp = os.path.join(ROOT, "build", "regress-cases.bin")
os.makedirs(os.path.dirname(tmp), exist_ok=True)
open(tmp, "wb").write(frames)
ours = [l.split(" ", 1)[1] for l in subprocess.run([QS, "diff-run", tmp], capture_output=True, text=True).stdout.strip().split("\n")]
fails = 0
have_node = subprocess.run(["node", "--version"], capture_output=True).returncode == 0
for n, o in zip(names, ours):
    ref = "n/a"
    if have_node:
        r = subprocess.run(["node", "-e", f"try{{new WebAssembly.Module(require('fs').readFileSync({os.path.join(D, n)!r}));console.log('accepted')}}catch(e){{console.log('rejected')}}"],
                           capture_output=True, text=True).stdout.strip()
        ref = r
    ok = o.startswith("reject") and ref in ("rejected", "n/a")
    print(("PASS " if ok else "FAIL ") + f"{n}: ours={o} reference={ref}")
    fails += 0 if ok else 1
print(f"{len(names) - fails}/{len(names)} regression modules rejected")
sys.exit(1 if fails else 0)
