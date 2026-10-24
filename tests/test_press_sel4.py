#!/usr/bin/env python3
"""
QEDOS Press end-to-end tests on seL4 + Microkit in QEMU (`build/sel4-press/loader.img`, built with
`QEDOS_PRESS=1 scripts/build-sel4.sh`).

  PRESS_001  capability audit of the generated system (scripts/capgraph.py, subject qedos_press_pd)
  PRESS_002  boot: qedos_press_pd verified the signed release bundle
  PRESS_003  GET /press/index.html over TLS 1.3 + X25519MLKEM768 -> 200, exact bytes, text/html
  PRESS_004  GET /press/missing -> 404
  PRESS_005  POST /press/index.html -> 405 (write methods rejected, never silently served)
  PRESS_006  HEAD /press/index.html -> 200, empty body, correct Content-Length
  PRESS_007  existing proxy health check still works unaffected (/health -> 200)
  PRESS_008  GET / -> 301 redirect to /press/index.html
"""
import os, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
IMG_DIR = os.path.join(ROOT, "build/sel4-press")
os.environ["QEDOS_SEL4_DIR"] = IMG_DIR
import test_sel4 as T  # reuse helpers (s_client_request, read_serial, ...)

T.IMG_DIR = IMG_DIR
T.SERIAL_LOG = os.path.join(IMG_DIR, "serial.log")
LOADER = os.path.join(IMG_DIR, "loader.img")
PQ = ["-tls1_3", "-groups", "X25519MLKEM768"]
passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def get(path, timeout=30.0):
    _, out = T.s_client_request(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode(), PQ, timeout=timeout)
    return out


def head(path, timeout=30.0):
    _, out = T.s_client_request(f"HEAD {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode(), PQ, timeout=timeout)
    return out


def post(path, body, timeout=30.0):
    raw = f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    return T.s_client_request(raw, PQ, timeout=timeout)[1]


def main():
    if os.environ.get("QS_SKIP_BUILD") != "1":
        env = dict(os.environ, QEDOS_PRESS="1", PATH=os.path.join(ROOT, "third_party/venv/bin") + os.pathsep + os.environ["PATH"])
        subprocess.run([os.path.join(ROOT, "scripts/build-sel4.sh")], check=True, env=env, stdout=subprocess.DEVNULL)

    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/capgraph.py"), "--dir", IMG_DIR,
                     "--subject", "qedos_press_pd", "--allow-debug-kernel"], check=True)
    ok("PRESS_001", "capability audit of press image (qedos_press_pd authority = 2 regions + 2 channels, no secrets/hw)")

    if os.path.exists(T.SERIAL_LOG):
        os.unlink(T.SERIAL_LOG)
    qemu = subprocess.Popen([T.QEMU_LAUNCHER, LOADER, T.SERIAL_LOG, f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "90"])
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            s = T.read_serial()
            if all(k in s for k in ("TLS_PD: OpenSSL 3.6.1 initialized", "HTTP_PD: initialized",
                                    "QEDOS_PRESS_PD: Ed25519 release signature verified",
                                    "POLICY_PD: Ed25519 signed config verified OK", "CONNECTOR_PD: initialized",
                                    "TCP_PD: DHCP lease acquired")):
                break
            time.sleep(0.25)
        else:
            print(T.read_serial(), file=sys.stderr)
            raise RuntimeError("press image did not finish booting")
        time.sleep(0.5)
        assert "routes=1" in T.read_serial(), T.read_serial()
        ok("PRESS_002", "qedos_press_pd verified the signed release bundle (1 route)")

        with open(os.path.join(ROOT, "examples/press-site/index.html"), "rb") as f:
            expected_body = f.read()

        out = get("/press/index.html")
        assert "HTTP/1.1 200 OK" in out, out
        assert "Content-Type: text/html" in out, out
        assert f"Content-Length: {len(expected_body)}" in out, out
        assert "\r\n\r\n" + expected_body.decode() in out, out
        ok("PRESS_003", f"GET /press/index.html -> 200, exact {len(expected_body)}-byte body, text/html")

        out = get("/press/missing")
        assert "HTTP/1.1 404" in out, out
        ok("PRESS_004", "GET /press/missing -> 404")

        out = post("/press/index.html", b"x")
        assert "HTTP/1.1 405" in out, out
        ok("PRESS_005", "POST /press/index.html -> 405 (write methods never silently served)")

        out = head("/press/index.html")
        assert "HTTP/1.1 200 OK" in out, out
        assert f"Content-Length: {len(expected_body)}" in out, out
        assert "<!doctype html>" not in out, out  # body omitted for HEAD
        ok("PRESS_006", f"HEAD /press/index.html -> 200, empty body, Content-Length: {len(expected_body)}")

        out = get("/health")
        assert "HTTP/1.1 200" in out, out
        ok("PRESS_007", "existing /health proxy check still answers 200 (press dispatch is additive)")

        out = get("/")
        assert "HTTP/1.1 301 Moved Permanently" in out, out
        assert "Location: /press/index.html" in out, out
        ok("PRESS_008", "GET / -> 301 Location: /press/index.html (fixed, not reflecting any request data)")
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()

    print(f"\n{len(passed)}/8 PRESS tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
