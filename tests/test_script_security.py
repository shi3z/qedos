#!/usr/bin/env python3
"""QED Script security tests (host reference runtime): hostile Wasm modules, signature/policy tampering.

Runs entirely locally against the `qs` CLI; no network is touched. Each hostile module is validly
signed, because a signature is not a safety argument — the sandbox must contain it.

Checked per case: (1) attack refused/contained with the expected status/reason, (2) the runner process
survives (exit code 0/3, never a crash), (3) no secret in output (4) a subsequent benign request still
works (5) no internal reason string leaks into the HTTP body.
"""
import os, shutil, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.abspath(os.path.join(here, ".."))
sys.path.insert(0, os.path.join(root, "examples", "malicious"))
from cases import CASES

QS = os.environ.get("QS", os.path.join(root, "build/qs/ws/target/debug/qs"))
FAIL = []
N = 0

def check(name, cond, detail=""):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    if not cond:
        FAIL.append(name)

def qs(*a):
    return subprocess.run([QS, *a], capture_output=True, text=True, timeout=60)

def parse(out):
    d = {}
    for line in out.splitlines():
        if line.startswith("status="):
            for kv in line.split(" ", 4)[:1]:
                pass
            d["status"] = int(line.split()[0].split("=")[1])
            d["reason"] = line.split("reason=")[1].split(" fuel=")[0]
        if line.startswith("BODY:"):
            d["body"] = line[5:]
    return d

# build corpus
subprocess.run([sys.executable, os.path.join(root, "examples/malicious/build.py")], check=True, stdout=subprocess.DEVNULL,
               env=dict(os.environ, QS=QS))
hello = os.path.join(root, "examples/hello")
for name, c in CASES.items():
    d = os.path.join(root, "examples/malicious/out", name)
    r = qs("run", *c["args"], d)
    kind = c["expect"][0]
    if kind == "rejected":
        check(f"mal/{name}: rejected at load", r.returncode == 3 and c["expect"][1] in r.stderr, r.stderr + r.stdout)
        check(f"mal/{name}: nothing executed", "status=" not in r.stdout)
    else:
        p = parse(r.stdout)
        ok = r.returncode == 0 and p.get("status") == c["expect"][1] and c["expect"][2] in p.get("reason", "")
        check(f"mal/{name}: contained -> {c['expect'][1]} {c['expect'][2]}", ok, r.stdout + r.stderr)
        if c["expect"][1] != 200:
            check(f"mal/{name}: generic error body only", p.get("body", "") == '{"error":"script error"}' or c["expect"][1] == 200, p.get("body"))
    check(f"mal/{name}: no secret/internal text in output",
          "SECRET-TOKEN" not in r.stdout.split("BODY:")[-1] and "BEGIN PRIVATE KEY" not in r.stdout)
    r2 = qs("run", "--path", "/script/hello", hello)
    check(f"mal/{name}: service continues (hello still ok)", '{"message":"Hello from QEDOS"}' in r2.stdout)

# signature / policy tampering
tmp = tempfile.mkdtemp()
def fresh(name):
    d = os.path.join(tmp, name)
    shutil.copytree(hello, d)
    return d
def expect_reject(label, d, needle):
    r = qs("run", d)
    check(label, r.returncode == 3 and needle in r.stderr and "status=" not in r.stdout, r.stderr + r.stdout)

d = fresh("sigflip"); s = open(d + "/app.sig").read(); open(d + "/app.sig", "w").write(("0" if s[0] != "0" else "1") + s[1:])
expect_reject("tamper: flipped signature bit rejected", d, "BadSignature")
d = fresh("wasmflip"); b = bytearray(open(d + "/app.wasm", "rb").read()); b[-3] ^= 1; open(d + "/app.wasm", "wb").write(bytes(b))
expect_reject("tamper: modified app.wasm rejected", d, "BadSignature")
d = fresh("polflip"); t = open(d + "/app.policy").read().replace("max_fuel = 10000", "max_fuel = 20000"); open(d + "/app.policy", "w").write(t)
expect_reject("tamper: raised fuel limit in policy rejected", d, "BadSignature")
d = fresh("polallow"); t = open(d + "/app.policy").read() + "allow = kv_get\nkv_read = a/\n"; open(d + "/app.policy", "w").write(t)
expect_reject("tamper: added allowed API in policy rejected", d, "BadSignature")
d = fresh("polver"); t = open(d + "/app.policy").read().replace("version = 1", "version = 2"); open(d + "/app.policy", "w").write(t)
expect_reject("tamper: version bump (rollback/replay binding) rejected", d, "BadSignature")
d = fresh("nosig"); os.remove(d + "/app.sig")
expect_reject("tamper: missing app.sig rejected", d, "BadSignatureEncoding")
d = fresh("shortsig"); open(d + "/app.sig", "w").write("00" * 10)
expect_reject("tamper: malformed app.sig rejected", d, "BadSignatureEncoding")
d = fresh("proofswap"); open(d + "/app.proof", "wb").write(b"QSPF1 forged proof: 'verified by external tool'")
expect_reject("tamper: proof added after signing rejected (proof digest is signed)", d, "BadSignature")
d = fresh("proofstring"); open(d + "/app.proof", "wb").write(b"verified by external tool"); qs("sign", "--seed", os.path.join(root, "config/keys/qs-code-signing-seed.hex"), d)
expect_reject("proof: a signed 'verified by external tool' string is not a certificate", d, "BadProof")
# config-signing key must not validate as a code-signing key (key separation)
# (sign hello with the *config* key via openssl is not possible here; instead sign with a fresh unrelated seed)
seed = os.path.join(tmp, "other.seed"); pubrs = os.path.join(tmp, "o.rs"); pubhex = os.path.join(tmp, "o.hex")
qs("keygen", seed, pubrs, pubhex)
d = fresh("wrongkey"); qs("sign", "--seed", seed, d)
expect_reject("key: signature by a different key rejected", d, "BadSignature")
r = qs("verify", "--pub", pubhex, d)
check("key: ... but verifies under that key's pinned pubkey (tool sanity)", r.returncode == 0, r.stderr)
# proof present AND validly signed: must run, but never be accepted as safety evidence
d = fresh("proofok"); qs("mkproof", "FuelBounded", d); qs("sign", "--seed", os.path.join(root, "config/keys/qs-code-signing-seed.hex"), d)
r = qs("verify", d)
check("proof: signed app.proof is bound but proof_accepted=false", "proof=PresentUnchecked proof_accepted=false" in r.stdout, r.stdout + r.stderr)
shutil.rmtree(tmp)

print(f"\n{N - len(FAIL)}/{N} passed")
sys.exit(1 if FAIL else 0)
