#!/usr/bin/env python3
"""
End-to-end integration test suite for qedos running on seL4 + Microkit in QEMU (`build/sel4/loader.img`).

Tests across the 5 isolated seL4 Protection Domains (`tcp_pd`, `tls_pd`, `http_pd`, `policy_pd`, `connector_pd`):
  - SEL4_001: Boot all 12 PDs, verify Ed25519 signed config in `policy_pd` (LAW_011),
              complete TLS 1.3 + X25519MLKEM768 handshake with `tls_pd` (LAW_002, LAW_003, LAW_008),
              and serve `GET /health` -> 200 OK.
  - SEL4_002: TLS 1.2 connection attempt refused by `tls_pd` (LAW_002).
  - SEL4_003: Classical X25519-only / P-256-only connection attempts refused by `tls_pd` (LAW_003).
  - SEL4_004: End-to-end reverse proxy forwarding through `tcp_pd -> tls_pd -> http_pd -> policy_pd -> connector_pd -> tcp_pd`
              to host backends A (19001) and B (19002), verifying header sanitization and fixed `Host` (LAW_001, LAW_004).
  - SEL4_005: Path traversal (`/game/../etc/passwd`, `/game/%2e%2e/x`), unknown routes (`/admin`), wrong method (`DELETE /health`),
              and malformed HTTP requests rejected with 400/404/405 and zero backend requests leaked (LAW_001, LAW_006, LAW_007).
  - SEL4_006: Capability & Viper formal invariant audit (`scripts/check-caps.py` for LAW_008, LAW_011, LAW_012).
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_OPENSSL_CANDIDATES = [
    os.path.join(ROOT, "third_party/openssl-install/bin/openssl"),
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
]
OPENSSL = next((p for p in _OPENSSL_CANDIDATES if os.path.isfile(p)), "openssl")
OPENSSL_CONF = os.path.join(ROOT, "config/openssl-min.cnf")
# QEDOS_ARCH=aarch64 runs the same suite against the aarch64 image (QEDOS_BOARD, default qemu_virt_aarch64).
ARCH = os.environ.get("QEDOS_ARCH", "x86_64")
if ARCH == "aarch64":
    IMG_DIR = os.path.join(ROOT, "build/sel4-" + os.environ.get("QEDOS_BOARD", "qemu_virt_aarch64"))
    QEMU_LAUNCHER = os.path.join(ROOT, "tools/run-aarch64.sh")
    BOOT_TIMEOUT = 90.0
    QEMU_RUN_SECONDS = "300"
else:
    IMG_DIR = os.path.join(ROOT, "build/sel4")
    QEMU_LAUNCHER = os.path.join(ROOT, "tools/run-echo.sh")
    BOOT_TIMEOUT = 25.0
    QEMU_RUN_SECONDS = "90"
if os.environ.get("QEDOS_IMG_DIR"):  # e.g. an image rebuilt from source into another directory
    IMG_DIR = os.path.abspath(os.environ["QEDOS_IMG_DIR"])
LOADER_IMG_OVERRIDE = IMG_DIR
os.environ["QEDOS_SEL4_DIR"] = IMG_DIR  # consumed by scripts/check-caps.py
LOADER_IMG = os.path.join(IMG_DIR, "loader.img")
SERIAL_LOG = os.path.join(IMG_DIR, "serial.log")
BE1_LOG = os.path.join(IMG_DIR, "be1.log")
BE2_LOG = os.path.join(IMG_DIR, "be2.log")
GUEST_PORT = 18443


def s_client_request(raw_http: bytes, extra_args=None, timeout: float = 10.0) -> tuple[int, str]:
    cmd = [
        OPENSSL,
        "s_client",
        "-connect",
        f"127.0.0.1:{GUEST_PORT}",
        "-ign_eof",
    ]
    if extra_args:
        cmd.extend(extra_args)
    env = dict(os.environ, OPENSSL_CONF=OPENSSL_CONF)
    p = subprocess.run(cmd, input=raw_http, capture_output=True, timeout=timeout, env=env)
    out = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    return p.returncode, out


def read_serial() -> str:
    if not os.path.exists(SERIAL_LOG):
        return ""
    with open(SERIAL_LOG, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def backend_log_count(port: int) -> int:
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/__log__", timeout=3) as r:
        data = json.loads(r.read().decode("utf-8"))
        return len(data["log"])


def main() -> None:
    # 0. Run static capability + Viper audit first (LAW_008, LAW_011, LAW_012)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/check-caps.py")], check=True)
    print("PASS SEL4_006 capability & Viper formal model audit")

    if os.path.exists(SERIAL_LOG):
        os.unlink(SERIAL_LOG)

    be = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tests/backend.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    qemu = subprocess.Popen(
        [
            QEMU_LAUNCHER,
            LOADER_IMG,
            SERIAL_LOG,
            f"hostfwd=tcp::{GUEST_PORT}-10.0.2.15:8443",
            QEMU_RUN_SECONDS,
        ]
    )

    try:
        # Wait for all PDs and DHCP lease in serial.log
        deadline = time.time() + BOOT_TIMEOUT
        ready = False
        while time.time() < deadline:
            slog = read_serial()
            if (
                "TLS_PD: OpenSSL 3.6.1 initialized" in slog
                and "HTTP_PD: initialized" in slog
                and "POLICY_PD: Ed25519 signed config verified OK" in slog
                and "CONNECTOR_PD: initialized" in slog
                and "TCP_PD: DHCP lease acquired" in slog
            ):
                ready = True
                break
            time.sleep(0.25)

        if not ready:
            print("SERIAL LOG:\n" + read_serial(), file=sys.stderr)
            raise RuntimeError("seL4 guest PDs did not finish initializing within timeout")

        time.sleep(0.5)

        # SEL4_001: TLS 1.3 + X25519MLKEM768 + GET /health
        _, out = s_client_request(
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            ["-tls1_3", "-groups", "X25519MLKEM768"],
        )
        assert "Negotiated TLS1.3 group: X25519MLKEM768" in out, out
        assert "TLS_AES_256_GCM_SHA384" in out, out
        assert "HTTP/1.1 200 OK" in out and "\r\n\r\nok\n" in out, out
        assert "TLS_PD: handshake OK version=TLSv1.3 group=X25519MLKEM768 cipher=TLS_AES_256_GCM_SHA384" in read_serial()
        print("PASS SEL4_001 TLS 1.3 + X25519MLKEM768 handshake & GET /health on seL4")

        # SEL4_002: TLS 1.2 refused (LAW_002)
        _, out12 = s_client_request(
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
            ["-tls1_2"],
        )
        assert "HTTP/1.1 200" not in out12, out12
        print("PASS SEL4_002 TLS 1.2 refused by seL4 tls_pd (LAW_002)")

        # SEL4_003: Classical X25519-only & P-256-only refused (LAW_003)
        for grp in ["X25519", "P-256"]:
            _, out_g = s_client_request(
                b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
                ["-tls1_3", "-groups", grp],
            )
            assert "HTTP/1.1 200" not in out_g, out_g
        print("PASS SEL4_003 classical groups (X25519, P-256) refused by seL4 tls_pd (LAW_003)")

        # SEL4_004: Multi-PD forwarding to Backend A (19001) and Backend B (19002)
        _, out_a = s_client_request(
            b"POST /api/chat HTTP/1.1\r\nHost: evil.attacker.example\r\nX-Forwarded-For: 1.2.3.4\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-sel4!",
            ["-tls1_3", "-groups", "X25519MLKEM768"],
        )
        assert "HTTP/1.1 200 OK" in out_a, out_a
        assert '"backend": "A"' in out_a and '"body_len": 11' in out_a, out_a
        assert '"host": "10.0.2.2:19001"' in out_a and "x-forwarded-for" not in out_a, out_a

        _, out_b = s_client_request(
            b"GET /game/score?player=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            ["-tls1_3", "-groups", "X25519MLKEM768"],
        )
        assert "HTTP/1.1 200 OK" in out_b, out_b
        assert '"backend": "B"' in out_b and '"/game/score?player=1"' in out_b, out_b
        print("PASS SEL4_004 5-PD proxying to Backend A & B with header sanitization (LAW_001, LAW_004)")

        # SEL4_005: Rejections (traversal, unknown path, wrong method, malformed HTTP) never touch backends (LAW_001, LAW_006, LAW_007)
        c1_before, c2_before = backend_log_count(19001), backend_log_count(19002)

        probes = [
            (b"GET /game/../etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", "HTTP/1.1 400"),
            (b"GET /game/%2e%2e/secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", "HTTP/1.1 400"),
            (b"GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", "HTTP/1.1 404"),
            (b"DELETE /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", "HTTP/1.1 405"),
            (b"GET /health HTTP/1.1\r\nConnection: close\r\n\r\n", "HTTP/1.1 400"),  # missing Host
        ]
        for req_bytes, expected_status in probes:
            _, out_p = s_client_request(req_bytes, ["-tls1_3", "-groups", "X25519MLKEM768"])
            assert expected_status in out_p, f"expected {expected_status}, got:\n{out_p}"

        assert backend_log_count(19001) == c1_before and backend_log_count(19002) == c2_before
        print("PASS SEL4_005 hostile requests rejected at http_pd/policy_pd with 0 backend leaks (LAW_006, LAW_007)")

        print("ALL seL4 MULTI-PD TESTS PASSED")
    finally:
        for proc in [qemu, be]:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    main()
