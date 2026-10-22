#!/usr/bin/env python3
"""seL4-under-QEMU-TCG latency comparison (NOT hardware numbers; TCG is an emulator).

usage: perf_script.py <image-dir> <label> [N]
Boots <image-dir>/loader.img, then times N sequential full TLS1.3+X25519MLKEM768 request/response
cycles (fresh handshake each, via openssl s_client) for each available path. Output: one JSON line.
"""
import json, os, statistics, subprocess, sys, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
img_dir, label = os.path.abspath(sys.argv[1]), sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 20
os.environ["QEDOS_SEL4_DIR"] = img_dir
import test_sel4 as T
T.SERIAL_LOG = os.path.join(img_dir, "serial.log")
PQ = ["-tls1_3", "-groups", "X25519MLKEM768"]
script = os.path.exists(os.path.join(img_dir, "script_pd.elf"))
if os.path.exists(T.SERIAL_LOG):
    os.unlink(T.SERIAL_LOG)
qemu = subprocess.Popen([T.QEMU_LAUNCHER, os.path.join(img_dir, "loader.img"), T.SERIAL_LOG, f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "600"])
try:
    t0 = time.time()
    while "TCP_PD: DHCP lease acquired" not in T.read_serial() or "POLICY_PD: Ed25519" not in T.read_serial():
        assert time.time() - t0 < 90, "boot timeout"
        time.sleep(0.25)
    boot_s = time.time() - t0
    time.sleep(1)

    def lat(raw, needle):
        xs = []
        for _ in range(N):
            t = time.time()
            _, out = T.s_client_request(raw, PQ, timeout=60)
            xs.append((time.time() - t) * 1000)
            assert needle in out, out[-300:]
        return {"mean_ms": round(statistics.mean(xs), 1), "median_ms": round(statistics.median(xs), 1), "p95_ms": round(sorted(xs)[int(0.95 * (N - 1))], 1)}

    res = {"label": label, "n": N, "boot_to_ready_s": round(boot_s, 1)}
    res["health"] = lat(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "HTTP/1.1 200 OK")
    if script:
        res["script_hello"] = lat(b"GET /script/hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "Hello from QEDOS")
        body = b'{"a":"' + b"x" * 500 + b'"}'
        res["script_json_echo_500B"] = lat(b"POST /script/json-echo HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body, '"length":508')
    print(json.dumps(res))
finally:
    qemu.terminate()
    try: qemu.wait(timeout=3)
    except Exception: qemu.kill()
