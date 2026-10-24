#!/usr/bin/env python3
"""
QEDOS Press TLS-compatibility end-to-end tests on seL4 + Microkit in QEMU
(`build/sel4-press-compat/loader.img`, built with `QEDOS_PRESS_COMPAT=1 scripts/build-sel4.sh`).

This image links `tls_compat_pd` (see sel4/pds/tls_compat_pd.c, docs/QEDOS_PRESS_TLS_COMPAT.md)
in place of `tls_pd`. Everything else (http_pd, policy_pd, connector_pd, qedos_press_pd) is the
same code, built the same way, as the full-assurance `QEDOS_PRESS=1` image.

  COMPAT_001  capability audit of the generated system (scripts/capgraph.py, subjects
              tls_compat_pd and qedos_press_pd)
  COMPAT_002  a client offering ONLY classical groups (X25519 and P-256, simulating the real
              iPad/WebKit ClientHello captured this session -- no PQ group at all) completes a
              TLS 1.3 handshake and gets the exact GET /press/index.html body
  COMPAT_003  a client offering ONLY X25519MLKEM768 (PQ) still works -- the compat policy is
              additive, not a downgrade of what full-PQ clients get
  COMPAT_004  GET / -> 301 Location: /press/index.html over a classical-group connection too
  COMPAT_005  tls_compat_pd's own group policy is a NAMED, SEPARATE, WIDER allow-list than
              tls_pd's -- this test re-confirms (same assertion as test_sel4.py's SEL4_003) that
              the UNRELATED, UNCHANGED strict image still refuses classical groups, so this
              compat image is additive and never weakens LAW_002/LAW_003 in tls_pd itself
"""
import os, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
IMG_DIR = os.path.join(ROOT, "build/sel4-press-compat")
os.environ["QEDOS_SEL4_DIR"] = IMG_DIR
import test_sel4 as T  # reuse helpers (s_client_request, read_serial, ...)

T.IMG_DIR = IMG_DIR
T.SERIAL_LOG = os.path.join(IMG_DIR, "serial.log")
LOADER = os.path.join(IMG_DIR, "loader.img")
passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def get(path, groups, timeout=30.0):
    extra = ["-tls1_3", "-groups", groups]
    _, out = T.s_client_request(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode(), extra, timeout=timeout)
    return out


def main():
    if os.environ.get("QS_SKIP_BUILD") != "1":
        env = dict(os.environ, QEDOS_PRESS_COMPAT="1", PATH=os.path.join(ROOT, "third_party/venv/bin") + os.pathsep + os.environ["PATH"])
        subprocess.run([os.path.join(ROOT, "scripts/build-sel4.sh")], check=True, env=env, stdout=subprocess.DEVNULL)

    for subject in ("tls_compat_pd", "qedos_press_pd"):
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts/capgraph.py"), "--dir", IMG_DIR,
                         "--subject", subject, "--allow-debug-kernel"], check=True)
    ok("COMPAT_001", "capability audit PASS for both tls_compat_pd and qedos_press_pd (A/B/C checks, only the pre-existing D1 WARN)")

    if os.path.exists(T.SERIAL_LOG):
        os.unlink(T.SERIAL_LOG)
    qemu = subprocess.Popen([T.QEMU_LAUNCHER, LOADER, T.SERIAL_LOG, f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "90"])
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            s = T.read_serial()
            if all(k in s for k in ("TLS_COMPAT_PD: OpenSSL 3.6.1 initialized", "HTTP_PD: initialized",
                                    "QEDOS_PRESS_PD: Ed25519 release signature verified",
                                    "POLICY_PD: Ed25519 signed config verified OK", "CONNECTOR_PD: initialized",
                                    "TCP_PD: DHCP lease acquired")):
                break
            time.sleep(0.25)
        else:
            print(T.read_serial(), file=sys.stderr)
            raise RuntimeError("press-compat image did not finish booting")
        time.sleep(0.5)

        with open(os.path.join(ROOT, "examples/press-site/index.html"), "rb") as f:
            expected_body = f.read()

        out = get("/press/index.html", "X25519:P-256")
        assert "HTTP/1.1 200 OK" in out, out
        assert "\r\n\r\n" + expected_body.decode() in out, out
        assert "TLS_COMPAT_PD: handshake OK" in T.read_serial()
        ok("COMPAT_002", "classical-only client (X25519:P-256, no PQ group -- matches the captured iPad/WebKit ClientHello) -> 200, exact body")

        out = get("/press/index.html", "X25519MLKEM768")
        assert "HTTP/1.1 200 OK" in out, out
        assert "\r\n\r\n" + expected_body.decode() in out, out
        ok("COMPAT_003", "PQ client (X25519MLKEM768 only) still works on the compat endpoint")

        out = get("/", "P-256")
        assert "HTTP/1.1 301 Moved Permanently" in out, out
        assert "Location: /press/index.html" in out, out
        ok("COMPAT_004", "GET / -> 301 Location: /press/index.html over a classical (P-256-only) connection")
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()

    # The unrelated, byte-for-byte-unchanged strict image (QEDOS_PRESS=1, tls_pd) must still
    # refuse classical groups -- this compat PD is additive, never a weakening of tls_pd itself.
    strict_dir = os.path.join(ROOT, "build/sel4-press")
    if os.path.exists(os.path.join(strict_dir, "loader.img")):
        strict_serial = os.path.join(strict_dir, "serial.log")
        if os.path.exists(strict_serial):
            os.unlink(strict_serial)
        qemu = subprocess.Popen([T.QEMU_LAUNCHER, os.path.join(strict_dir, "loader.img"), strict_serial,
                                  f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "60"])
        try:
            deadline = time.time() + 60
            while time.time() < deadline:
                s = ""
                if os.path.exists(strict_serial):
                    with open(strict_serial, "r", encoding="utf-8", errors="replace") as f:
                        s = f.read()
                if all(k in s for k in ("TLS_PD: OpenSSL 3.6.1 initialized", "HTTP_PD: initialized",
                                        "POLICY_PD: Ed25519 signed config verified OK", "CONNECTOR_PD: initialized",
                                        "TCP_PD: DHCP lease acquired")):
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("strict press image (build/sel4-press) did not finish booting for the re-check")
            time.sleep(0.5)
            rc, out = T.s_client_request(b"GET /press/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                                          ["-tls1_3", "-groups", "X25519:P-256"], timeout=10.0)
            assert "HTTP/1.1" not in out, f"strict tls_pd image unexpectedly accepted a classical-only handshake: {out}"
            ok("COMPAT_005", "unrelated, unchanged strict image (tls_pd) still refuses classical groups -- LAW_002/LAW_003 provably unweakened")
        finally:
            qemu.terminate()
            try:
                qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:
                qemu.kill()
    else:
        print("COMPAT_005: SKIPPED (no build/sel4-press image present to re-check)")

    print(f"\n{len(passed)}/5 PRESS-COMPAT tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
