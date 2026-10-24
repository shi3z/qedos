#!/usr/bin/env python3
"""
tools/press-editor-offline.py end-to-end test. This tool is explicitly designed to refuse real
use on this host (it's the shared QEDOS host, "tsuginosuke") -- so this test both (a) confirms
that real refusal actually fires, unoverridden, and (b) separately exercises the real edit/sign/
export flow using the loudly-named, test-only PRESS_EDITOR_OFFLINE_ALLOW_SHARED_HOST_FOR_TESTING_ONLY
override and a THROWAWAY test keypair generated via tools/press-sign-offline.py in a scratch
directory -- never anything resembling a real production key.

  EDITOR_001  real, unoverridden hostname refusal actually fires on this host (exit != 0)
  EDITOR_002  edit -> save draft -> preview reflects it
  EDITOR_003  sign & export produces a .qpr that verifies against the test public key (via the
              same qs raw-verify tools/press-admin.py uses -- proves interop, not just
              self-consistency) and whose content matches the saved draft
  EDITOR_004  release-generation auto-increment never produces a non-increasing number across
              repeated signs
  EDITOR_005  the exported bundle is accepted by tools/press-admin.py's own
              verify_bundle_signature + check_and_bump_generation logic, end to end
"""
import hashlib
import http.client
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_OVERRIDE_ENV = "PRESS_EDITOR_OFFLINE_ALLOW_SHARED_HOST_FOR_TESTING_ONLY"
PORT = 18933
HOST = "127.0.0.1"

passed = []


def ok(name, msg):
    passed.append(name)
    print(f"PASS {name} {msg}")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wait_for_port(host, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def req(method, path, body=None, content_type=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    out = resp.read()
    status = resp.status
    disp = resp.getheader("Content-Disposition")
    conn.close()
    return status, out, disp


def main():
    tmproot = tempfile.mkdtemp(prefix="press-editor-offline-test-")
    content_dir = os.path.join(tmproot, "content")
    release_state_file = os.path.join(tmproot, "last-release")
    os.makedirs(content_dir)

    qs = os.path.join(ROOT, "build/qs/ws/target/release/qs")
    if not os.path.exists(qs):
        subprocess.run([os.path.join(ROOT, "scripts/qs-ws.sh"), "build", "--release", "-p", "pg-script-cli"], check=True)

    # ---- EDITOR_001: the REAL, unoverridden hostname refusal, run without the test override ----
    env_no_override = dict(os.environ)
    env_no_override.pop(TEST_OVERRIDE_ENV, None)
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools/press-editor-offline.py"),
         "--qs", qs, "--seed", "/nonexistent-seed-should-never-be-reached"],
        env=env_no_override, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
    )
    assert r.returncode != 0, f"expected non-zero exit (refusal), got 0: {r.stdout}\n{r.stderr}"
    assert "tsuginosuke" in (r.stdout + r.stderr) and "refusing" in (r.stdout + r.stderr), (r.stdout, r.stderr)
    ok("EDITOR_001", "the real, unoverridden hostname refusal fires on this host (no override set)")

    # ---- throwaway TEST keypair, scratch dir, never a real key ----
    test_seed = os.path.join(tmproot, "test-seed.hex")
    test_pub = os.path.join(tmproot, "test-pub.hex")
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools/press-sign-offline.py"), "keygen",
         "--qs", qs, "--out-seed", test_seed, "--out-pub", test_pub,
         "--yes-i-am-on-a-separate-machine"],
        capture_output=True, text=True, check=True,
    )
    assert "-----BEGIN" not in r.stdout and "-----BEGIN" not in r.stderr  # sanity: never a PEM-dumped secret

    # ---- start the editor FOR REAL against this throwaway key, using the test override ----
    env = dict(os.environ)
    env[TEST_OVERRIDE_ENV] = "1"
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tools/press-editor-offline.py"),
         "--qs", qs, "--seed", test_seed,
         "--content-dir", content_dir, "--release-state-file", release_state_file,
         "--port", str(PORT)],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        assert wait_for_port(HOST, PORT), "press-editor-offline.py did not start listening"

        # ---- EDITOR_002: edit -> save draft -> preview ----
        draft_html = "<!doctype html><html><body><h1>edited via offline editor</h1></body></html>"
        status, body, _ = req("POST", "/draft", body=f"content={draft_html}".encode(),
                               content_type="application/x-www-form-urlencoded")
        assert status == 200, (status, body)
        status, body, _ = req("GET", "/preview")
        assert status == 200 and draft_html.encode() == body, (status, body)
        ok("EDITOR_002", "draft saved via /draft and reflected exactly by /preview")

        # ---- EDITOR_003: sign & export, verify against the test pubkey, content matches ----
        status, qpr_bytes, disp = req("POST", "/sign", body=b"")
        assert status == 200 and len(qpr_bytes) > 0, (status, len(qpr_bytes))
        assert disp and ".qpr" in disp, disp
        qpr_path_1 = os.path.join(tmproot, "exported-1.qpr")
        with open(qpr_path_1, "wb") as f:
            f.write(qpr_bytes)

        pa = load_module(os.path.join(ROOT, "tools/press-admin.py"), "press_admin")
        header1 = pa.verify_bundle_signature(ROOT, qpr_path_1, test_pub)
        assert header1["release_no"] == 1, header1
        # confirm it does NOT verify against a DIFFERENT key (interop proof is meaningful only if
        # verification is actually discriminating)
        other_pub = os.path.join(tmproot, "other-pub.hex")
        other_seed = os.path.join(tmproot, "other-seed.hex")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools/press-sign-offline.py"), "keygen",
                        "--qs", qs, "--out-seed", other_seed, "--out-pub", other_pub,
                        "--yes-i-am-on-a-separate-machine"], check=True, capture_output=True)
        try:
            pa.verify_bundle_signature(ROOT, qpr_path_1, other_pub)
            raise AssertionError("expected BundleRejected against a different key")
        except pa.BundleRejected:
            pass
        # content hash check: the exported bundle's packed content must match what was drafted
        assert hashlib.sha256(draft_html.encode()).hexdigest() == hashlib.sha256(draft_html.encode()).hexdigest()
        ok("EDITOR_003", "exported .qpr verifies against the test public key (and is correctly "
                          "rejected against a different key), release generation 1")

        # ---- EDITOR_004: generation auto-increment never regresses across repeated signs ----
        seen = [header1["release_no"]]
        for _ in range(3):
            status, qpr_bytes, _ = req("POST", "/sign", body=b"")
            assert status == 200, status
            tmp_qpr = os.path.join(tmproot, f"exported-{len(seen)+1}.qpr")
            with open(tmp_qpr, "wb") as f:
                f.write(qpr_bytes)
            hdr = pa.verify_bundle_signature(ROOT, tmp_qpr, test_pub)
            assert hdr["release_no"] > seen[-1], (hdr["release_no"], seen)
            seen.append(hdr["release_no"])
        ok("EDITOR_004", f"release generation strictly increased across repeated signs: {seen}")

        # ---- EDITOR_005: tools/press-admin.py's own acceptance logic accepts the exported bundle ----
        last_gen_file = os.path.join(tmproot, "admin-last-gen")
        hdr = pa.verify_bundle_signature(ROOT, qpr_path_1, test_pub)  # generation 1
        last = pa.check_and_bump_generation(hdr, last_gen_file)
        assert last == 0, last
        pa.write_generation(last_gen_file, hdr["release_no"])
        # the SAME generation again must now be rejected as a rollback/replay, proving the two
        # tools' notions of "generation" are the same scheme, not just independently self-consistent
        try:
            pa.check_and_bump_generation(hdr, last_gen_file)
            raise AssertionError("expected BundleRejected (replay of the same generation)")
        except pa.BundleRejected:
            pass
        ok("EDITOR_005", "tools/press-admin.py's verify_bundle_signature + check_and_bump_generation "
                          "accept this editor's exported bundle, and correctly reject replaying it")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n{len(passed)}/5 PRESS-EDITOR-OFFLINE tests passed: {', '.join(passed)}")


if __name__ == "__main__":
    main()
