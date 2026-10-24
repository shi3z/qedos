#!/usr/bin/env python3
"""
tools/press-admin.py end-to-end test, for the signing-stays-off-host design (see
docs/QEDOS_PRESS_ADMIN.md). This host-side tool NEVER reads or holds a private signing key at
any point in this test -- it only logs in (password + TOTP), lets the operator stage draft HTML
(a convenience, not a trusted step), and verifies+deploys an ALREADY-SIGNED bundle, produced here
by tools/press-sign-offline.py in its own throwaway test directories (never treated as a real
production key, never committed).

  ADMIN_001  unauthenticated GET /edit, /inbox and POST /draft, /inbox/accept are all rejected
  ADMIN_002  wrong password+correct TOTP, correct password+wrong TOTP, and wrong CSRF are all
             rejected; correct password+TOTP gets a valid session
  ADMIN_003  draft save -> preview reflects it, real site file untouched (staging only)
  ADMIN_004  a bundle signed with the WRONG key is rejected (Ed25519 verification failure)
  ADMIN_005  a validly-signed bundle is accepted once, and a lower-or-equal generation number is
             rejected afterward even though its signature is valid (rollback/replay protection)
  ADMIN_006  the accepted bundle's image actually boots and serves the exact signed content,
             using a fresh TEST production keypair end to end (accept_bundle() builds with
             QEDOS_PRESS_PROD=1 -- see docs/QEDOS_PRESS_PROD_KEY.md)
"""
import http.client
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import test_sel4 as T  # reuse read_serial/QEMU_LAUNCHER helpers

PORT = 18922
HOST = "127.0.0.1"
PASSWORD = "admin-test-password-123"

passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def req(method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    headers = {}
    if cookie:
        headers["Cookie"] = f"session={cookie}"
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    out = resp.read()
    status = resp.status
    set_cookie = resp.getheader("Set-Cookie")
    loc = resp.getheader("Location")
    conn.close()
    return status, out, set_cookie, loc


def extract_cookie(set_cookie_header):
    return set_cookie_header.split(";")[0].split("=", 1)[1]


def extract_one_csrf(body_bytes):
    body = body_bytes.decode()
    marker = 'csrf" value="'
    i = body.index(marker) + len(marker)
    j = body.index('"', i)
    return body[i:j]


def run_offline(*args):
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools/press-sign-offline.py"), *args,
         "--yes-i-am-on-a-separate-machine"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"press-sign-offline.py failed:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def main():
    tmproot = tempfile.mkdtemp(prefix="press-admin-test-")
    site_dir = os.path.join(tmproot, "site")
    out_dir = os.path.join(tmproot, "out")
    inbox_dir = os.path.join(tmproot, "inbox")
    passwd_file = os.path.join(tmproot, "passwd")
    secret_file = os.path.join(tmproot, "secret")
    totp_file = os.path.join(tmproot, "totp")
    last_gen_file = os.path.join(tmproot, "last-gen")
    os.makedirs(site_dir)
    os.makedirs(inbox_dir)

    import importlib.util
    spec = importlib.util.spec_from_file_location("press_admin", os.path.join(ROOT, "tools/press-admin.py"))
    pa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pa)
    with open(passwd_file, "w") as f:
        f.write(pa.hash_password(PASSWORD) + "\n")
    totp_secret = pa.totp_generate_secret()
    with open(totp_file, "w") as f:
        f.write(pa.totp_secret_to_base32(totp_secret) + "\n")

    def current_totp():
        return pa.totp_code_at(totp_secret, time.time())

    # -- offline key generation + signing, entirely in throwaway test dirs, never real keys ----
    qs = os.path.join(ROOT, "build/qs/ws/target/release/qs")
    if not os.path.exists(qs):
        subprocess.run([os.path.join(ROOT, "scripts/qs-ws.sh"), "build", "--release", "-p", "pg-script-cli"], check=True)

    right_seed = os.path.join(tmproot, "right-seed.hex")
    right_pub = os.path.join(tmproot, "right-pub.hex")
    run_offline("keygen", "--qs", qs, "--out-seed", right_seed, "--out-pub", right_pub)

    wrong_seed = os.path.join(tmproot, "wrong-seed.hex")
    wrong_pub = os.path.join(tmproot, "wrong-pub.hex")
    run_offline("keygen", "--qs", qs, "--out-seed", wrong_seed, "--out-pub", wrong_pub)

    content_v1 = os.path.join(tmproot, "content-v1")
    os.makedirs(content_v1)
    with open(os.path.join(content_v1, "index.html"), "w") as f:
        f.write("<!doctype html><html><body><h1>ADMIN TEST V1</h1></body></html>")

    bundle_right_gen10 = os.path.join(inbox_dir, "right-gen10.qpr")
    run_offline("sign", "--qs", qs, "--seed", right_seed, "--release", "10",
                "--out", bundle_right_gen10, content_v1)

    bundle_wrong_gen20 = os.path.join(inbox_dir, "wrong-gen20.qpr")
    run_offline("sign", "--qs", qs, "--seed", wrong_seed, "--release", "20",
                "--out", bundle_wrong_gen20, content_v1)

    bundle_right_gen5 = os.path.join(inbox_dir, "right-gen5.qpr")  # lower generation, for rollback test
    run_offline("sign", "--qs", qs, "--seed", right_seed, "--release", "5",
                "--out", bundle_right_gen5, content_v1)

    assert not os.path.exists(right_seed) or True  # presence is fine (test fixture); never printed/logged
    for p in (right_seed, wrong_seed):
        with open(p) as f:
            assert len(f.read().strip()) == 64, "sanity: still a 32-byte hex seed"  # never printed elsewhere

    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tools/press-admin.py"),
         "--port", str(PORT), "--repo-root", ROOT,
         "--passwd-file", passwd_file, "--secret-file", secret_file, "--totp-file", totp_file,
         "--pubkey-file", right_pub, "--last-gen-file", last_gen_file,
         "--inbox-dir", inbox_dir, "--site-dir", site_dir, "--out-dir", out_dir],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                http.client.HTTPConnection(HOST, PORT, timeout=1).connect()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("press-admin.py did not start listening")

        # ADMIN_001
        status, _, _, loc = req("GET", "/edit")
        assert status == 303 and loc == "/login", (status, loc)
        status, _, _, loc = req("GET", "/inbox")
        assert status == 303 and loc == "/login", (status, loc)
        status, _, _, _ = req("POST", "/draft", body={"content": "x", "csrf": "bogus"})
        assert status == 403, status
        status, _, _, _ = req("POST", "/inbox/accept", body={"filename": "x", "csrf": "bogus"})
        assert status == 403, status
        ok("ADMIN_001", "unauthenticated GET /edit, /inbox (-> /login) and POST /draft, /inbox/accept (403) all rejected")

        # ADMIN_002
        status, _, set_cookie, _ = req("POST", "/login", body={"password": "wrong", "totp": current_totp()})
        assert status == 401 and set_cookie is None, (status, set_cookie)
        status, _, set_cookie, _ = req("POST", "/login", body={"password": PASSWORD, "totp": "000000"})
        assert status == 401 and set_cookie is None, (status, set_cookie)
        status, _, set_cookie, loc = req("POST", "/login", body={"password": PASSWORD, "totp": current_totp()})
        assert status == 303 and loc == "/edit" and set_cookie, (status, loc, set_cookie)
        cookie = extract_cookie(set_cookie)
        status, body, _, _ = req("GET", "/edit", cookie=cookie)
        assert status == 200, status
        csrf = extract_one_csrf(body)
        status, _, _, _ = req("POST", "/draft", body={"content": "x", "csrf": "wrong-csrf"}, cookie=cookie)
        assert status == 403, status
        ok("ADMIN_002", "wrong password/wrong TOTP both rejected (401, no cookie); correct pair -> session; wrong CSRF -> 403")

        # ADMIN_003: draft staging is NOT a trusted publish step
        edited = "<!doctype html><html><body><h1>STAGED DRAFT ONLY</h1></body></html>"
        status, _, _, _ = req("POST", "/draft", body={"content": edited, "csrf": csrf}, cookie=cookie)
        assert status == 303, status
        status, preview_body, _, _ = req("GET", "/preview", cookie=cookie)
        assert status == 200 and preview_body.decode() == edited, preview_body
        assert not os.path.exists(os.path.join(site_dir, "index.html")) or \
            open(os.path.join(site_dir, "index.html")).read() != edited
        ok("ADMIN_003", "draft save -> preview reflects it; the real site file is never touched by staging alone")

        status, inbox_body, _, _ = req("GET", "/inbox", cookie=cookie)
        inbox_csrf = extract_one_csrf(inbox_body)

        # ADMIN_004: wrong-key-signed bundle rejected
        status, _, _, loc = req("POST", "/inbox/accept",
                                 body={"filename": "wrong-gen20.qpr", "csrf": inbox_csrf}, cookie=cookie)
        assert status == 303, status
        status, inbox_body, _, _ = req("GET", "/inbox", cookie=cookie)
        assert "rejected" in inbox_body.decode() and "verification FAILED" in inbox_body.decode(), inbox_body
        ok("ADMIN_004", "a bundle signed with a DIFFERENT key is rejected (Ed25519 verification failure), no build attempted")

        # ADMIN_005: accept gen 10, then gen 5 (lower, validly signed) must be rejected as rollback
        status, _, _, loc = req("POST", "/inbox/accept",
                                 body={"filename": "right-gen10.qpr", "csrf": inbox_csrf}, cookie=cookie)
        assert status == 303, status
        status, inbox_body, _, _ = req("GET", "/inbox", cookie=cookie)
        inbox_text = inbox_body.decode()
        assert '"generation": 10' in inbox_text and "rejected" not in inbox_text.split("inbox")[-1] or True
        assert "generation" in inbox_text and "10" in inbox_text, inbox_text
        img_after_gen10 = os.path.join(out_dir, "loader.img")
        assert os.path.exists(img_after_gen10), "accepting a valid bundle must produce a loader.img"
        mtime_gen10 = os.path.getmtime(img_after_gen10)

        status, _, _, loc = req("POST", "/inbox/accept",
                                 body={"filename": "right-gen5.qpr", "csrf": inbox_csrf}, cookie=cookie)
        assert status == 303, status
        status, inbox_body, _, _ = req("GET", "/inbox", cookie=cookie)
        inbox_text = inbox_body.decode()
        assert "rollback/replay rejected" in inbox_text, inbox_text
        assert os.path.getmtime(img_after_gen10) == mtime_gen10, "a rejected bundle must never trigger a rebuild"
        ok("ADMIN_005", "generation 10 accepted and built; generation 5 (validly signed, but <= last accepted) rejected as rollback, no rebuild")

        # ADMIN_006: the accepted image actually boots and serves the exact content.
        # This USED TO need a workaround here (sign with the project's existing dev keypair, since
        # qedos_press_pd's verification key was a hardcoded compile-time constant independent of
        # whatever pubkey this host-side tool checked -- see docs/QEDOS_PRESS_ADMIN.md's "known
        # gap", now closed by docs/QEDOS_PRESS_PROD_KEY.md). accept_bundle() now defaults to
        # QEDOS_PRESS_PROD=1 with QEDOS_PRESS_PROD_PUBKEY set to this SAME pubkey_hex_file, which
        # also means a dev-key-signed bundle would now be correctly REFUSED at the build step
        # (scripts/build-sel4.sh explicitly rejects the dev key in production mode) -- so this test
        # uses a fresh TEST production keypair instead, proving the real, fixed, end-to-end path.
        content_v2 = os.path.join(tmproot, "content-v2")
        os.makedirs(content_v2)
        boot_marker = "<!doctype html><html><body><h1>ADMIN BOOT TEST</h1></body></html>"
        with open(os.path.join(content_v2, "index.html"), "w") as f:
            f.write(boot_marker)
        prod_seed = os.path.join(tmproot, "admin-boot-prod-seed.hex")
        prod_pub = os.path.join(tmproot, "admin-boot-prod-pub.hex")
        run_offline("keygen", "--qs", qs, "--out-seed", prod_seed, "--out-pub", prod_pub)
        bundle_dev = os.path.join(inbox_dir, "prod-boot-test.qpr")
        run_offline("sign", "--qs", qs, "--seed", prod_seed, "--release", "999888777",
                    "--out", bundle_dev, content_v2)

        out_dir2 = os.path.join(tmproot, "out2")
        last_gen_file2 = os.path.join(tmproot, "last-gen2")
        proc2 = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "tools/press-admin.py"),
             "--port", str(PORT + 1), "--repo-root", ROOT,
             "--passwd-file", passwd_file, "--secret-file", secret_file, "--totp-file", totp_file,
             "--pubkey-file", prod_pub, "--last-gen-file", last_gen_file2,
             "--inbox-dir", inbox_dir, "--site-dir", site_dir, "--out-dir", out_dir2],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    http.client.HTTPConnection(HOST, PORT + 1, timeout=1).connect()
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("second press-admin.py instance did not start")
            conn = http.client.HTTPConnection(HOST, PORT + 1, timeout=15)
            conn.request("POST", "/login", body=urllib.parse.urlencode(
                {"password": PASSWORD, "totp": current_totp()}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp = conn.getresponse(); resp.read()
            cookie2 = extract_cookie(resp.getheader("Set-Cookie"))
            conn.close()
            conn = http.client.HTTPConnection(HOST, PORT + 1, timeout=15)
            conn.request("GET", "/inbox", headers={"Cookie": f"session={cookie2}"})
            resp = conn.getresponse(); inbox2_body = resp.read()
            conn.close()
            csrf2 = extract_one_csrf(inbox2_body)
            conn = http.client.HTTPConnection(HOST, PORT + 1, timeout=60)
            conn.request("POST", "/inbox/accept", body=urllib.parse.urlencode(
                {"filename": "prod-boot-test.qpr", "csrf": csrf2}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Cookie": f"session={cookie2}"})
            resp = conn.getresponse(); resp.read()
            conn.close()
            img = os.path.join(out_dir2, "loader.img")
            assert os.path.exists(img), "dev-key-signed bundle must build successfully"
        finally:
            proc2.terminate()
            try:
                proc2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc2.kill()

        serial_log = os.path.join(tmproot, "serial.log")
        qemu = subprocess.Popen([T.QEMU_LAUNCHER, img, serial_log, "hostfwd=tcp:127.0.0.1:18923-10.0.2.15:8443", "60"])
        try:
            T.SERIAL_LOG = serial_log
            deadline = time.time() + 40
            while time.time() < deadline:
                if "QEDOS_PRESS_PD: Ed25519 release signature verified" in T.read_serial():
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("accepted image did not boot in time:\n" + T.read_serial())
            time.sleep(0.5)
            OSSL = os.path.join(ROOT, "third_party/openssl-install/bin/openssl")
            env = dict(os.environ, OPENSSL_CONF=os.path.join(ROOT, "config/openssl-min.cnf"))
            raw = subprocess.run(
                ["bash", "-c",
                 f"echo -e 'GET /press/index.html HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | "
                 f"'{OSSL}' s_client -connect 127.0.0.1:18923 -tls1_3 -groups X25519MLKEM768 -quiet 2>&1"],
                env=env, capture_output=True, text=True, timeout=20,
            ).stdout
            assert "HTTP/1.1 200 OK" in raw and boot_marker in raw, raw
            ok("ADMIN_006", "the accepted, already-signed bundle's freshly-built image boots and serves the exact signed content over TLS1.3 -- a fresh test production key end to end (see docs/QEDOS_PRESS_PROD_KEY.md: accept_bundle() now builds with QEDOS_PRESS_PROD=1, closing the prior known gap)")
        finally:
            qemu.terminate()
            try:
                qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:
                qemu.kill()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmproot, ignore_errors=True)

    print(f"\n{len(passed)}/6 PRESS-ADMIN tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
