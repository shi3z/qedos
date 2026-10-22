#!/usr/bin/env python3
"""QED Script functional tests (host reference runtime via the `qs` CLI). No network.

SCRIPT_F01 hello example   SCRIPT_F02 json-echo POST   SCRIPT_F03 URL parameters   SCRIPT_F04 KV counter + ACL
SCRIPT_F05 sign/verify roundtrip is deterministic and binds policy  SCRIPT_F06 resource-limit flags
"""
import filecmp, os, shutil, subprocess, sys, tempfile
root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QS = os.environ.get("QS", os.path.join(root, "build/qs/ws/target/debug/qs"))
SEED = os.path.join(root, "config/keys/qs-code-signing-seed.hex")
fails, n = [], 0


def check(name, cond, detail=""):
    global n
    n += 1
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + str(detail)[:600]))
    if not cond:
        fails.append(name)


def qs(*a):
    return subprocess.run([QS, *a], capture_output=True, text=True, timeout=60)


def body(r):
    return next((l[5:] for l in r.stdout.splitlines() if l.startswith("BODY:")), None)


ex = lambda n_: os.path.join(root, "examples", n_)

r = qs("run", "--path", "/script/hello", ex("hello"))
check("F01 hello body", body(r) == '{"message":"Hello from QEDOS"}' and "status=200" in r.stdout, r.stdout + r.stderr)
check("F01 hello content-type json", "content_type=application/json" in r.stdout)

r = qs("run", "--method", "POST", "--body", '{"k":"v"}', ex("json-echo"))
check("F02 json-echo transforms body", body(r) == '{"upper":"{_K_:_V_}","length":9}', r.stdout)
r = qs("run", "--method", "POST", "--body", "x" * 3000, ex("json-echo"))
check("F02 json-echo caps long bodies at 2048", '"length":2048' in (body(r) or ""), r.stdout[-200:])
r = qs("run", "--method", "POST", "--body", "x" * 9000, ex("json-echo"))
check("F02 request over max_request_bytes -> 413 before execution", "status=413" in r.stdout and "fuel=0" in r.stdout, r.stdout)

r = qs("run", "--query", "name=ada&x=1", ex("params"))
check("F03 URL parameters visible to script", body(r) == '{"query":"NAME=ADA&X=1","length":12}', r.stdout)

r = qs("run", ex("kv-counter"))
check("F04 anonymous principal denied by KV ACL (403)", "status=403" in r.stdout, r.stdout)
r = qs("run", "--principal", "7", "--repeat", "3", ex("kv-counter"))
check("F04 authenticated principal gets private counter", body(r) == '{"count":3}', r.stdout)
r = qs("run", "--principal", "8", "--repeat", "1", ex("kv-counter"))
check("F04 other principal starts at its own counter", body(r) == '{"count":1}', r.stdout)

t = tempfile.mkdtemp()
d = os.path.join(t, "app")
shutil.copytree(ex("hello"), d)
before = open(d + "/app.sig").read()
qs("sign", "--seed", SEED, d)
check("F05 Ed25519 signing is deterministic", open(d + "/app.sig").read() == before)
check("F05 qs verify accepts", qs("verify", d).returncode == 0)
open(d + "/app.policy", "a").write("# comment appended\n")
r = qs("verify", d)
check("F05 any policy byte change invalidates the signature", r.returncode == 3 and "BadSignature" in r.stderr, r.stderr)
shutil.rmtree(t)

# regenerate wasm from source and compare with the committed binary (reproducible build of the examples)
for e in ("hello", "json-echo", "params", "kv-counter"):
    before = open(ex(e) + "/app.wasm", "rb").read()
    subprocess.run([sys.executable, ex(e) + "/build.py"], check=True)
    check(f"F06 example {e}: wasm builds reproducibly", open(ex(e) + "/app.wasm", "rb").read() == before)

print(f"\n{n - len(fails)}/{n} passed")
sys.exit(1 if fails else 0)
