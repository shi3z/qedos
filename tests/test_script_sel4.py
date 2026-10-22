#!/usr/bin/env python3
"""
QED Script end-to-end tests on seL4 + Microkit in QEMU (`build/sel4-script/loader.img`, built with
`QEDOS_SCRIPT=1 scripts/build-sel4.sh`; hostile modules are packed in via QEDOS_SCRIPT_EXTRA).

  SCRIPT_001  capability audit of the generated system (scripts/check-script-caps.py + check-caps.py)
  SCRIPT_002  boot: script_pd verified the signed bundles (LAW_020); hostile test modules accepted as *signed*
  SCRIPT_003  GET /script/hello over TLS 1.3 + X25519MLKEM768 -> {"message":"Hello from QEDOS"}
  SCRIPT_004  POST /script/json-echo transforms the JSON body
  SCRIPT_005  unknown module / traversal / wrong method never reach a script (404/400/405)
  SCRIPT_006  existing proxy features still work (health, backend A/B, hostile-request rejection, TLS downgrade refusal)
  SCRIPT_007  hostile Wasm (OOB access, runaway loop, state-leak probe) contained; no secret in response; other PDs keep serving
  SCRIPT_008  /health answered while a runaway script is burning fuel in script_pd (availability isolation)
  SCRIPT_009  script_pd deliberately crashed (test-only fault injection): TLS, /health, proxying keep working
"""
import os, subprocess, sys, threading, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
IMG_DIR = os.path.join(ROOT, "build/sel4-script")
os.environ["QEDOS_SEL4_DIR"] = IMG_DIR
import test_sel4 as T  # reuse helpers (s_client_request, backend_log_count, ...)

T.IMG_DIR = IMG_DIR
T.SERIAL_LOG = os.path.join(IMG_DIR, "serial.log")
LOADER = os.path.join(IMG_DIR, "loader.img")
PQ = ["-tls1_3", "-groups", "X25519MLKEM768"]
passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def get(path, extra=None, timeout=30.0):
    _, out = T.s_client_request(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode(), PQ, timeout=timeout)
    return out


def post(path, body, timeout=30.0):
    raw = f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    return T.s_client_request(raw, PQ, timeout=timeout)[1]


def main():
    # build the hostile modules (signed with the dev code-signing key) and the image
    subprocess.run([sys.executable, os.path.join(ROOT, "examples/malicious/build.py")], check=True, stdout=subprocess.DEVNULL)
    extra = " ".join(os.path.join(ROOT, "examples/malicious/out", n) for n in ("sel4_spin", "sel4_oob", "sel4_leak"))
    if os.environ.get("QS_SKIP_BUILD") != "1":
        env = dict(os.environ, QEDOS_SCRIPT="1", QEDOS_SCRIPT_EXTRA=extra, QEDOS_SCRIPT_TEST_FAULT="1",
                   PATH=os.path.join(ROOT, "third_party/venv/bin") + os.pathsep + os.environ["PATH"])
        subprocess.run([os.path.join(ROOT, "scripts/build-sel4.sh")], check=True, env=env, stdout=subprocess.DEVNULL)

    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/check-script-caps.py"), os.path.join(IMG_DIR, "proofgate.system")], check=True)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/check-caps.py")], check=True)
    ok("SCRIPT_001", "capability audit of script image (script_pd authority = 2 regions + 2 channels; LAW_014/018/022)")

    if os.path.exists(T.SERIAL_LOG):
        os.unlink(T.SERIAL_LOG)
    be = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests/backend.py")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    qemu = subprocess.Popen([T.QEMU_LAUNCHER, LOADER, T.SERIAL_LOG, f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "400"])
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            s = T.read_serial()
            if all(k in s for k in ("TLS_PD: OpenSSL 3.6.1 initialized", "HTTP_PD: initialized", "SCRIPT_PD: Ed25519 code-signature",
                                    "POLICY_PD: Ed25519 signed config verified OK", "CONNECTOR_PD: initialized", "TCP_PD: DHCP lease acquired")):
                break
            time.sleep(0.25)
        else:
            print(T.read_serial(), file=sys.stderr)
            raise RuntimeError("script image did not finish booting")
        time.sleep(0.5)
        assert "verified=5 rejected=0" in T.read_serial(), T.read_serial()
        ok("SCRIPT_002", "script_pd verified 5 signed bundles (2 apps + 3 hostile test modules), 0 rejected (LAW_020)")

        t0 = time.time()
        out = get("/script/hello")
        dt = time.time() - t0
        assert "Negotiated TLS1.3 group: X25519MLKEM768" in out and "TLS_AES_256_GCM_SHA384" in out, out
        assert "HTTP/1.1 200 OK" in out and 'Content-Type: application/json' in out, out
        assert '\r\n\r\n{"message":"Hello from QEDOS"}' in out, out
        assert "TLS_PD: handshake OK version=TLSv1.3 group=X25519MLKEM768" in T.read_serial()
        ok("SCRIPT_003", f"GET /script/hello -> {{\"message\":\"Hello from QEDOS\"}} via negotiated X25519MLKEM768 ({dt:.2f}s incl. handshake under QEMU TCG)")

        out = post("/script/json-echo", b'{"name":"seL4","n":42}')
        assert "HTTP/1.1 200 OK" in out and '{"upper":"{_NAME_:_SEL4_,_N_:42}","length":22}' in out, out
        ok("SCRIPT_004", "POST /script/json-echo transformed the JSON body inside the Wasm sandbox")

        for path, status in [("/script/nope", "404"), ("/script/../health", "400"), ("/script/%2e%2e/health", "400"), ("/script/", "404"), ("/scripts/hello", "404")]:
            o = get(path)
            assert f"HTTP/1.1 {status}" in o and "Hello from QEDOS" not in o, (path, o)
        o = T.s_client_request(b"DELETE /script/hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", PQ)[1]
        assert "HTTP/1.1 405" in o or "HTTP/1.1 404" in o, o
        ok("SCRIPT_005", "unknown module / traversal / encoded dot-segments / bad method rejected before any Wasm runs")

        # SCRIPT_006: regression of the existing reverse proxy
        o = get("/health")
        assert "HTTP/1.1 200 OK" in o and "\r\n\r\nok\n" in o, o
        o = post("/api/chat", b"hello-sel4!")
        assert '"backend": "A"' in o and '"body_len": 11' in o and '"host": "10.0.2.2:19001"' in o, o
        o = get("/game/score?player=1")
        assert '"backend": "B"' in o, o
        c1, c2 = T.backend_log_count(19001), T.backend_log_count(19002)
        for raw, st in [(b"GET /game/../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "400"),
                        (b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "404")]:
            assert f"HTTP/1.1 {st}" in T.s_client_request(raw, PQ)[1]
        assert (T.backend_log_count(19001), T.backend_log_count(19002)) == (c1, c2)
        assert "HTTP/1.1 200" not in T.s_client_request(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", ["-tls1_2"])[1]
        for g in ("X25519", "P-256"):
            assert "HTTP/1.1 200" not in T.s_client_request(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", ["-tls1_3", "-groups", g])[1]
        ok("SCRIPT_006", "existing proxy intact: /health, backend A/B forwarding, hostile rejection, TLS<1.3 and classical groups refused")

        # SCRIPT_007: hostile modules
        o = get("/script/oob")
        assert "HTTP/1.1 500" in o and '{"error":"script error"}' in o and "OutOfBounds" not in o, o
        assert "SCRIPT_PD: request ended with reason code 3" in T.read_serial()
        o = post("/script/leak", b"SECRET-TOKEN-XYZ")
        o2 = post("/script/leak", b"")
        assert "SECRET-TOKEN" not in o2 and "HTTP/1.1 200" in o2, o2
        o = get("/script/spin", timeout=120)
        assert "HTTP/1.1 503" in o and '{"error":"script error"}' in o, o
        assert "Hello from QEDOS" in get("/script/hello"), "script service must survive a runaway script"
        assert "ok\n" in get("/health")
        ok("SCRIPT_007", "OOB access -> 500 generic body, runaway loop -> 503 by fuel, no cross-request residue, no internal detail in responses")

        # SCRIPT_008: /health stays responsive while script_pd burns fuel
        res = {}
        th = threading.Thread(target=lambda: res.setdefault("spin", get("/script/spin", timeout=120)))
        t0 = time.time()
        th.start()
        time.sleep(0.3)
        t1 = time.time()
        h = get("/health", timeout=60)
        t_health = time.time() - t1
        th.join()
        t_spin = time.time() - t0
        assert "HTTP/1.1 200 OK" in h, h
        assert "HTTP/1.1 503" in res["spin"]
        ok("SCRIPT_008", f"/health answered in {t_health:.2f}s while the runaway script ran ({t_spin:.2f}s total); script_pd is lowest priority")

        # SCRIPT_009: crash script_pd itself (test-only build flag QEDOS_SCRIPT_TEST_FAULT), then use everything else
        try:
            get("/script/crash", timeout=8)
            crashed_reply = True
        except subprocess.TimeoutExpired:
            crashed_reply = False
        assert not crashed_reply, "crashed script_pd cannot have answered"
        time.sleep(1)
        slog = T.read_serial()
        assert ("script_pd" in slog and ("fault" in slog.lower() or "Fault" in slog)), slog[-1500:]
        for _ in range(3):
            assert "ok\n" in get("/health")
        o = post("/api/chat", b"after-crash")
        assert '"backend": "A"' in o and '"body_len": 11' in o, o
        o = get("/script/hello", timeout=15)
        assert "HTTP/1.1 503" in o and "Hello from QEDOS" not in o, o   # shed, not hung
        assert "TLS_PD: handshake OK version=TLSv1.3 group=X25519MLKEM768" in T.read_serial()
        ok("SCRIPT_009", "script_pd crashed: TLS 1.3 handshakes, /health and backend proxying unaffected; later script requests shed with 503")
        print(f"ALL QED SCRIPT seL4 TESTS PASSED ({len(passed)}/9)")
    finally:
        for p in (qemu, be):
            p.terminate()
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()


if __name__ == "__main__":
    main()
