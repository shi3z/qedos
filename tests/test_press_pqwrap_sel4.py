#!/usr/bin/env python3
"""
QEDOS Press PQ-wrap end-to-end tests (`build/sel4-press-pq/loader.img`, built with
`QEDOS_PRESS_PQ=1 scripts/build-sel4.sh`, which implies QEDOS_PRESS=1).

Drives POST /press/pq-fetch exactly the way a browser would: fetches the signed ML-KEM-768 public
key asset, encapsulates with the real vendored client library (examples/press-site-pq/vendor/
ml-kem768.bundle.js, via tests/pq_wrap_node_helper.mjs so this test doesn't re-implement ML-KEM-768
in Python), POSTs the capsule, and decrypts the AEAD-wrapped response with the browser's own Web
Crypto algorithms (HKDF-SHA256, AES-256-GCM) -- the same two primitives press_pq_pd.c uses via
OpenSSL, cross-checked for interop before this PD was ever wired up (see
docs/QEDOS_PRESS_PQ_WRAP.md).

  PQWRAP_001  capability audit (press_pq_pd A/B/C0, qedos_press_pd C1-C8 now also covers the new
              pq_keystore secret)
  PQWRAP_002  POST /press/pq-fetch for /press/index.html -> decrypted body byte-for-byte equal to
              the real file
  PQWRAP_003  POST /press/pq-fetch for /press/missing -> appStatus 404 inside the envelope
  PQWRAP_004  the existing plaintext GET /press/index.html still works unchanged (additive, not a
              replacement)
  PQWRAP_005  a correct-length but garbage KEM ciphertext: the server never crashes and returns a
              well-formed envelope, but it fails to authenticate under the (wrong) key the real
              client derives -- clean rejection via AEAD, not a server-side branch (ML-KEM's
              decapsulation has no failure mode of its own -- implicit rejection, FIPS 203)
  PQWRAP_006  a malformed (wrong-length) request body is rejected with a plain 400 before any
              OpenSSL call, no crash
"""
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
IMG_DIR = os.path.join(ROOT, "build/sel4-press-pq")
os.environ["QEDOS_SEL4_DIR"] = IMG_DIR
import test_sel4 as T  # reuse QEMU launch helpers

T.IMG_DIR = IMG_DIR
T.SERIAL_LOG = os.path.join(IMG_DIR, "serial.log")
LOADER = os.path.join(IMG_DIR, "loader.img")
PQ = ["-tls1_3", "-groups", "X25519MLKEM768"]
NODE_HELPER = os.path.join(ROOT, "tests/pq_wrap_node_helper.mjs")
SCRATCH = "/tmp/qedos-pqwrap-test"

passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def raw_tls_request(raw: bytes, timeout: float = 15.0) -> bytes:
    """Like test_sel4.s_client_request, but returns raw bytes (NOT decoded as UTF-8) -- the
    PQ-wrap response body is binary ciphertext, and decoding it as text with errors='replace'
    would corrupt it before this test ever gets to decrypt it. With -quiet, the actual HTTP
    response goes to stdout and openssl's own connection/verify chatter goes to stderr -- keep
    them separate (unlike test_sel4.s_client_request's combined text capture) so the binary body
    is never contaminated by appended diagnostic text."""
    cmd = [T.OPENSSL, "s_client", "-connect", f"127.0.0.1:{T.GUEST_PORT}", "-ign_eof", "-quiet"] + PQ
    env = dict(os.environ, OPENSSL_CONF=T.OPENSSL_CONF)
    p = subprocess.run(cmd, input=raw, capture_output=True, timeout=timeout, env=env)
    return p.stdout


def split_headers_body(raw: bytes):
    idx = raw.find(b"\r\n\r\n")
    assert idx >= 0, raw[:200]
    return raw[:idx].decode("latin1"), raw[idx + 4:]


def node_run(*args):
    subprocess.run(["node", NODE_HELPER, *args], check=True, cwd=ROOT)


def pq_fetch(path: str, garbage_capsule: bool = False):
    os.makedirs(SCRATCH, exist_ok=True)
    pubkey_file = os.path.join(SCRATCH, "pubkey.bin")
    capsule_file = os.path.join(SCRATCH, "capsule.bin")
    secret_file = os.path.join(SCRATCH, "secret.bin")

    req1 = b"GET /press/pqkey.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    head1, body1 = split_headers_body(raw_tls_request(req1))
    assert head1.startswith("HTTP/1.1 200"), head1
    with open(pubkey_file, "wb") as f:
        f.write(body1)

    if garbage_capsule:
        node_run("garbage-capsule", capsule_file)
        node_run("encap", pubkey_file, os.path.join(SCRATCH, "_unused_capsule.bin"), secret_file)
    else:
        node_run("encap", pubkey_file, capsule_file, secret_file)

    with open(capsule_file, "rb") as f:
        capsule = f.read()
    path_bytes = path.encode("utf-8")
    req_body = len(path_bytes).to_bytes(2, "little") + path_bytes + capsule
    req2 = (
        b"POST /press/pq-fetch HTTP/1.1\r\nHost: localhost\r\n"
        b"Content-Type: application/octet-stream\r\n"
        + f"Content-Length: {len(req_body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + req_body
    )
    head2, body2 = split_headers_body(raw_tls_request(req2))
    if not head2.startswith("HTTP/1.1 200"):
        return {"http_status": head2.splitlines()[0], "app_status": None}

    app_status = (body2[0] << 8) | body2[1]
    nonce = body2[2:14]
    ciphertext = body2[14:]
    nonce_file = os.path.join(SCRATCH, "nonce.bin")
    ct_file = os.path.join(SCRATCH, "ct.bin")
    plain_file = os.path.join(SCRATCH, "plain.bin")
    with open(nonce_file, "wb") as f:
        f.write(nonce)
    with open(ct_file, "wb") as f:
        f.write(ciphertext)
    out = subprocess.run(
        ["node", NODE_HELPER, "decrypt", secret_file, nonce_file, ct_file, plain_file],
        check=True, cwd=ROOT, capture_output=True, text=True,
    )
    decrypt_ok = out.stdout.strip() == "OK"
    body = None
    if decrypt_ok:
        with open(plain_file, "rb") as f:
            body = f.read()
    return {"http_status": head2.splitlines()[0], "app_status": app_status, "decrypt_ok": decrypt_ok, "body": body}


def main():
    if os.environ.get("QS_SKIP_BUILD") != "1":
        env = dict(os.environ, QEDOS_PRESS_PQ="1", PATH=os.path.join(ROOT, "third_party/venv/bin") + os.pathsep + os.environ["PATH"])
        subprocess.run([os.path.join(ROOT, "scripts/build-sel4.sh")], check=True, env=env, stdout=subprocess.DEVNULL)

    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/capgraph.py"), "--dir", IMG_DIR,
                     "--subject", "press_pq_pd", "--allow-debug-kernel"], check=True)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts/capgraph.py"), "--dir", IMG_DIR,
                     "--subject", "qedos_press_pd", "--allow-debug-kernel"], check=True)
    ok("PQWRAP_001", "capability audit PASS for press_pq_pd and qedos_press_pd (the latter now also provably cannot reach pq_keystore)")

    if os.path.exists(T.SERIAL_LOG):
        os.unlink(T.SERIAL_LOG)
    qemu = subprocess.Popen([T.QEMU_LAUNCHER, LOADER, T.SERIAL_LOG, f"hostfwd=tcp::{T.GUEST_PORT}-10.0.2.15:8443", "90"])
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            s = T.read_serial()
            if all(k in s for k in ("TLS_PD: OpenSSL 3.6.1 initialized", "HTTP_PD: initialized",
                                    "QEDOS_PRESS_PD: Ed25519 release signature verified",
                                    "PRESS_PQ_PD: ML-KEM-768 private key loaded",
                                    "POLICY_PD: Ed25519 signed config verified OK", "CONNECTOR_PD: initialized",
                                    "TCP_PD: DHCP lease acquired")):
                break
            time.sleep(0.25)
        else:
            print(T.read_serial(), file=sys.stderr)
            raise RuntimeError("press-pq image did not finish booting")
        time.sleep(0.5)

        with open(os.path.join(ROOT, "examples/press-site-pq/index.html"), "rb") as f:
            expected_body = f.read()

        r = pq_fetch("/press/index.html")
        assert r["app_status"] == 200, r
        assert r["decrypt_ok"], r
        assert r["body"] == expected_body, "decrypted body does not match the real index.html"
        ok("PQWRAP_002", f"POST /press/pq-fetch index.html -> decrypted body byte-for-byte equal ({len(expected_body)} bytes)")

        r = pq_fetch("/press/missing")
        assert r["app_status"] == 404, r
        ok("PQWRAP_003", "POST /press/pq-fetch missing path -> appStatus 404 inside the envelope")

        req = b"GET /press/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        head, body = split_headers_body(raw_tls_request(req))
        assert head.startswith("HTTP/1.1 200"), head
        assert body == expected_body
        ok("PQWRAP_004", "existing plaintext GET /press/index.html still works unchanged (additive)")

        r = pq_fetch("/press/index.html", garbage_capsule=True)
        assert r["app_status"] == 200, r  # the server itself "succeeded" -- implicit rejection
        assert r["decrypt_ok"] is False, r
        ok("PQWRAP_005", "garbage-but-correct-length KEM ciphertext: server returns a well-formed envelope, our (wrong) derived key fails AEAD authentication -- clean rejection, no crash")

        req_body = (5).to_bytes(2, "little") + b"short" + bytes([1, 2, 3])  # way too short "capsule"
        req = (
            b"POST /press/pq-fetch HTTP/1.1\r\nHost: localhost\r\n"
            + f"Content-Length: {len(req_body)}\r\n".encode()
            + b"Connection: close\r\n\r\n" + req_body
        )
        head, _ = split_headers_body(raw_tls_request(req))
        assert head.startswith("HTTP/1.1 400"), head
        ok("PQWRAP_006", "malformed (wrong-length) capsule rejected with 400 before any OpenSSL call, no crash")
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()

    print(f"\n{len(passed)}/6 PQ-WRAP tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
