#!/usr/bin/env python3
"""
Proves the /press/* concurrency fix: up to PG_MAX_CONNS (4) genuinely simultaneous requests must all
be served correctly, not just the first while the rest are shed (503) or reset. Before this fix,
`shm_policy_press`/`shm_press_http` held one global request/response record, so a second concurrent
request while the first was still in flight was shed by policy_pd's own busy check; now each
connection slot has its own independent record (see sel4/include/pg_shm.h).

  PRESS_CONC_001  2 simultaneous GET /press/index.html -> both get 200 with the exact body
  PRESS_CONC_002  1 simultaneous GET /press/index.html + 1 simultaneous GET /press/missing ->
                  the first gets 200, the other gets 404, neither degraded by the other
  PRESS_CONC_003  4 (PG_MAX_CONNS) truly simultaneous GET /press/index.html -> all 4 get 200 with
                  the exact body, then a second round of 4 in the same boot also all succeed.

A lower-layer bug was found and fixed while this file originally only covered N=2: at N=4, exactly
2 of 4 truly-simultaneous connections hung indefinitely (60s+), regardless of endpoint -- the
identical pattern reproduced on the unmodified, press-unrelated `/health` endpoint, so it was not
caused by the press in-flight-slot fix. Root cause: `http_pd.c`'s `shm_http_policy` (the single
request/response record shared with `policy_pd`, used by every decision including `/health`) is
deliberately single-in-flight, but `check_policy_completion()` only ever retried the one slot that
had just been acknowledged -- any other slot whose request was fully buffered while that channel
was busy was never retried once the channel freed up again. Fixed by having `check_policy_completion()`
re-attempt every slot (`process_slot_requests()`) once it processes an ack, so a starved slot gets
its turn on the next free cycle instead of hanging forever. No capability, region, or shared-memory
layout change was needed. PRESS_CONC_003 proves this at N=4 and across two consecutive rounds in
the same boot (a second, independently-reported anomaly: a second concurrent round sometimes hung
at just N=2 -- same root cause, same fix).
"""
import concurrent.futures
import os
import subprocess
import sys
import time

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


def main():
    if os.environ.get("QS_SKIP_BUILD") != "1":
        env = dict(os.environ, QEDOS_PRESS="1", PATH=os.path.join(ROOT, "third_party/venv/bin") + os.pathsep + os.environ["PATH"])
        subprocess.run([os.path.join(ROOT, "scripts/build-sel4.sh")], check=True, env=env, stdout=subprocess.DEVNULL)

    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/capgraph.py"), "--dir", IMG_DIR,
                     "--subject", "qedos_press_pd", "--allow-debug-kernel"], check=True)

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

        with open(os.path.join(ROOT, "examples/press-site/index.html"), "rb") as f:
            expected_body = f.read()

        # PRESS_CONC_001: 2 simultaneous identical requests, both must succeed. A barrier forces every
        # worker to fire its TLS ClientHello within the same short window, not drift into a sequence.
        N = 2
        barrier = concurrent.futures.ThreadPoolExecutor(max_workers=N)
        start_gate = time.time() + 0.5

        def fire(path):
            while time.time() < start_gate:
                pass
            return get(path, timeout=30.0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
            futs = [ex.submit(fire, "/press/index.html") for _ in range(N)]
            outs = [f.result() for f in futs]
        barrier.shutdown(wait=False)

        for i, out in enumerate(outs):
            assert "HTTP/1.1 200 OK" in out, f"connection {i} did not get 200:\n{out}"
            assert f"Content-Length: {len(expected_body)}" in out, f"connection {i}: {out}"
            assert "\r\n\r\n" + expected_body.decode() in out, f"connection {i}: {out}"
        ok("PRESS_CONC_001", f"{N}/{N} simultaneous GET /press/index.html each got 200 with the exact body (not just the first)")

        # PRESS_CONC_002: a mix -- 1 concurrent hit on a real path, 1 concurrent hit on a missing path.
        # Each connection's own outcome must be correct independent of what the other got.
        start_gate = time.time() + 0.5
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            fut_ok = ex.submit(fire, "/press/index.html")
            fut_404 = ex.submit(fire, "/press/missing")
            out_ok = fut_ok.result()
            out_404 = fut_404.result()

        assert "HTTP/1.1 200 OK" in out_ok, out_ok
        assert "HTTP/1.1 404" in out_404, out_404
        ok("PRESS_CONC_002", "1 simultaneous 200 and 1 simultaneous 404 both correct, independent of each other")

        # PRESS_CONC_003: a full PG_MAX_CONNS (4) round of truly simultaneous requests, twice in the
        # same boot. Before the http_pd.c check_policy_completion() fix, this hung indefinitely for
        # 2 of 4 connections on the first round, and (separately) sometimes on the second round even
        # at N=2.
        def run_round(round_no, n):
            start_gate = time.time() + 0.5

            def fire_r(i):
                while time.time() < start_gate:
                    pass
                return get("/press/index.html", timeout=20.0)

            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
                futs = [ex.submit(fire_r, i) for i in range(n)]
                outs = [f.result() for f in futs]
            for i, out in enumerate(outs):
                assert "HTTP/1.1 200 OK" in out, f"round {round_no} connection {i} did not get 200:\n{out}"
                assert "\r\n\r\n" + expected_body.decode() in out, f"round {round_no} connection {i}: {out}"
            return len(outs)

        n1 = run_round(1, 4)
        time.sleep(1.0)
        n2 = run_round(2, 4)
        ok("PRESS_CONC_003", f"round 1: {n1}/4 and round 2: {n2}/4 simultaneous GET /press/index.html all got 200 with the exact body")
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()

    print(f"\n{len(passed)}/3 PRESS concurrency tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
