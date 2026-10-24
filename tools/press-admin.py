#!/usr/bin/env python3
"""
QEDOS Press admin tool -- login, edit, preview, and publish the ONE static page QEDOS Press
serves (examples/press-site/index.html), WITHOUT adding any authentication, write path, or
persistent storage inside the seL4 image. This is intentional: qedos_press_pd stays exactly as
read-only and minimal as it is documented in docs/QEDOS_PRESS_CMS.md ("no write path of any
kind"). Everything "CMS" (login, draft, publish) happens here, in an ordinary host process,
entirely outside the seL4 TCB -- see docs/QEDOS_PRESS_ADMIN.md.

This host NEVER reads, holds, or uses any Ed25519 signing private key, in any form -- that
boundary was a deliberate, user-mandated design correction (see docs/QEDOS_PRESS_ADMIN.md's
"signing-key boundary" section). The `/edit` page only stages a draft for preview; it never signs
or publishes anything. The real "publish" action is `/inbox`: verify an ALREADY-SIGNED `.qpr`
bundle (signed elsewhere, on a separate machine, with tools/press-sign-offline.py) against the
configured production PUBLIC key, check its release-generation number against the highest ever
previously accepted (rollback/replay protection), and only then build a fresh seL4 image from the
verbatim bytes via scripts/build-sel4.sh with QEDOS_PRESS_PROD=1 -- the same public-key file used
for both the host-side check and the seL4 image's own compile-time-embedded trust key (see
docs/QEDOS_PRESS_PROD_KEY.md). This does NOT touch any running QEMU instance, firewall rule, or
socat relay; deploying the freshly-built image (swapping it in for whatever is currently live) is
a separate, deliberate operator action.

stdlib only. No new pip dependency.

Usage:
  python3 tools/press-admin.py --set-password         interactive: set/replace the admin password
  python3 tools/press-admin.py --enroll-totp           interactive: enroll a TOTP 2FA secret
  python3 tools/press-admin.py --show-pubkey-fingerprint   print the sha256 fingerprint of the
      configured production public key file, for cross-checking against the fingerprint
      scripts/build-sel4.sh prints for the same file during a QEDOS_PRESS_PROD=1 build
  python3 tools/press-admin.py [--bind 127.0.0.1] [--port 8900] [--passwd-file PATH]
                                [--site-dir PATH] [--repo-root PATH]
      runs the admin web UI (loopback-only by default; never bind a public interface here --
      reaching this tool from outside the operator's own access, e.g. via Tailscale/SSH tunnel,
      is the operator's choice, not something this tool automates).
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import shutil
import socketserver
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

REPO_ROOT_DEFAULT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SESSION_TTL_SECONDS = 2 * 3600
PBKDF2_ITERS = 310_000
PBKDF2_ALGO = "sha256"
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW_STEPS = 1  # tolerate +/- 1 step (30s) of clock skew, no wider


# ---------------------------------------------------------------------------
# TOTP (RFC 6238 / RFC 4226), stdlib-only: HMAC-SHA1, 30s step, 6 digits -- the exact algorithm
# every standard authenticator app (Google Authenticator, Authy, 1Password, ...) implements, so
# the operator enrolls with whatever app they already use. No custom scheme.
# ---------------------------------------------------------------------------

def totp_generate_secret() -> bytes:
    return secrets.token_bytes(20)  # 160 bits, the RFC 4226-recommended HOTP/TOTP secret size


def totp_code_at(secret: bytes, for_time: float, period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS) -> str:
    counter = int(for_time // period)
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret: bytes, code: str, for_time: float = None, window: int = TOTP_WINDOW_STEPS) -> bool:
    if for_time is None:
        for_time = time.time()
    code = (code or "").strip()
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    accepted = False
    for delta in range(-window, window + 1):
        candidate = totp_code_at(secret, for_time + delta * TOTP_PERIOD)
        if hmac.compare_digest(candidate, code):
            accepted = True
    return accepted


def totp_secret_to_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def totp_secret_from_base32(b32: str) -> bytes:
    pad = "=" * ((8 - len(b32) % 8) % 8)
    return base64.b32decode(b32 + pad)


def totp_enroll_uri(secret: bytes, account: str = "admin", issuer: str = "QEDOS Press") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode({
        "secret": totp_secret_to_base32(secret),
        "issuer": issuer,
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
        "algorithm": "SHA1",
    })
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Password hashing (stdlib hashlib.pbkdf2_hmac, random salt, constant-time compare)
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode("utf-8"), salt, PBKDF2_ITERS)
    return f"pbkdf2_{PBKDF2_ALGO}${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo_part, iters_s, salt_hex, dk_hex = stored.split("$")
        algo = algo_part.split("_", 1)[1]
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(actual, expected)


def set_password_interactive(passwd_file: str) -> None:
    os.makedirs(os.path.dirname(passwd_file), exist_ok=True)
    pw1 = getpass.getpass("New press-admin password: ")
    pw2 = getpass.getpass("Confirm: ")
    if pw1 != pw2:
        sys.exit("passwords did not match")
    if len(pw1) < 8:
        sys.exit("password must be at least 8 characters")
    with open(passwd_file, "w") as f:
        f.write(hash_password(pw1) + "\n")
    os.chmod(passwd_file, 0o600)
    print(f"wrote {passwd_file}")


QR_ENROLL_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>QEDOS Press Admin -- TOTP enrollment</title>
<script src="{qrcode_js}"></script></head>
<body style="font-family:sans-serif;max-width:40em;margin:4em auto;text-align:center">
<h1>Scan with your authenticator app</h1>
<div id="qr" style="display:inline-block"></div>
<p style="word-break:break-all;font-family:monospace;font-size:0.8em">{uri}</p>
<p>This file is local-only and not served by any network listener. Close it once enrolled.</p>
<script>
var qr = qrcode(0, 'M');
qr.addData({uri_json});
qr.make();
document.getElementById('qr').innerHTML = qr.createSvgTag(6);
</script>
</body></html>"""


def enroll_totp_interactive(totp_file: str, repo_root: str) -> None:
    os.makedirs(os.path.dirname(totp_file), exist_ok=True)
    secret = totp_generate_secret()
    with open(totp_file, "w") as f:
        f.write(totp_secret_to_base32(secret) + "\n")
    os.chmod(totp_file, 0o600)
    uri = totp_enroll_uri(secret)
    print(f"wrote {totp_file}")
    print(f"otpauth URI (manual entry fallback):\n  {uri}")

    qrcode_js = os.path.join(repo_root, "third_party/qrcode-generator/qrcode.js")
    out_html = os.path.join(tempfile.mkdtemp(prefix="press-admin-totp-enroll-"), "enroll.html")
    with open(out_html, "w") as f:
        f.write(QR_ENROLL_HTML.format(
            qrcode_js=html.escape(qrcode_js), uri=html.escape(uri), uri_json=json.dumps(uri)))
    print(f"wrote a local-only QR enrollment page: {out_html}")
    print("Open that file in a browser on this machine (not served over any network) and scan "
          "the QR code with your authenticator app (Google Authenticator / Authy / 1Password / "
          "any standard TOTP app), then delete the file.")


# ---------------------------------------------------------------------------
# Signed session cookie: HMAC-SHA256(server_secret, "v1:<expiry>") , no server-side session store.
# The server secret itself is generated once and stored alongside the password hash file, so
# restarting the admin tool doesn't necessarily invalidate every session, but losing/rotating that
# file does (acceptable for a one-operator demo CMS).
# ---------------------------------------------------------------------------

def load_or_create_secret(secret_file: str) -> bytes:
    if os.path.exists(secret_file):
        with open(secret_file, "rb") as f:
            return f.read()
    os.makedirs(os.path.dirname(secret_file), exist_ok=True)
    secret = secrets.token_bytes(32)
    with open(secret_file, "wb") as f:
        f.write(secret)
    os.chmod(secret_file, 0o600)
    return secret


def make_session_cookie(secret: bytes) -> str:
    expiry = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"v1:{expiry}"
    sig = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_cookie(secret: bytes, cookie_val: str) -> bool:
    try:
        v, expiry_s, sig_hex = cookie_val.split(":")
        payload = f"{v}:{expiry_s}"
        expected = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_hex):
            return False
        return int(expiry_s) >= int(time.time())
    except Exception:
        return False


def make_csrf_token(secret: bytes, session_cookie_val: str) -> str:
    return hmac.new(secret, ("csrf:" + session_cookie_val).encode("ascii"), hashlib.sha256).hexdigest()


def verify_csrf_token(secret: bytes, session_cookie_val: str, token: str) -> bool:
    expected = make_csrf_token(secret, session_cookie_val)
    return hmac.compare_digest(expected, token or "")


# ---------------------------------------------------------------------------
# Bundle verification + rollback protection. NO PRIVATE KEY MATERIAL OF ANY KIND is read, held, or
# touched anywhere in this file or on this host as part of this flow -- that was the explicit,
# binding redesign decision (see docs/QEDOS_PRESS_ADMIN.md): this host must hold no Ed25519
# signing private key, plaintext or encrypted, because this host's own compromise must be in the
# threat model. Signing happens entirely on a separate, independent, operator-controlled machine
# (tools/press-sign-offline.py), producing an already-signed .qpr this host only ever VERIFIES.
#
# Ed25519 verification itself is done by shelling out to `qs raw-verify` (crates/pg-script-cli),
# which calls the existing, already-relied-upon pg_config::verify_ed25519 -- Python stdlib has no
# Ed25519 either, and the standing rule is no new pip dependency and no reimplementing crypto.
# ---------------------------------------------------------------------------

QPR_HEADER_LEN = 24
QPR_ENTRY_LEN = 136
QPR_SIG_LEN = 64


class BundleRejected(Exception):
    pass


def parse_qpr_header(blob: bytes):
    if len(blob) < QPR_HEADER_LEN + QPR_SIG_LEN:
        raise BundleRejected("file too short to be a QPR1 bundle")
    if blob[0:4] != b"QPR1":
        raise BundleRejected("bad magic (not a QPR1 bundle)")
    version = blob[4]
    n_routes = blob[5]
    site_id, release_no, publish_ts, content_len = struct.unpack("<IIII", blob[8:24])
    expected_len = QPR_HEADER_LEN + n_routes * QPR_ENTRY_LEN + content_len + QPR_SIG_LEN
    if len(blob) != expected_len:
        raise BundleRejected(f"length mismatch: header declares {expected_len} bytes, file is {len(blob)}")
    return {"version": version, "n_routes": n_routes, "site_id": site_id,
            "release_no": release_no, "publish_ts": publish_ts, "content_len": content_len}


def pubkey_fingerprint(pubkey_hex_file: str) -> str:
    """SHA-256 of the raw 32 pubkey bytes, hex. Lets an operator visually confirm this host's
    verification key and the key scripts/build-sel4.sh's QEDOS_PRESS_PROD=1 mode embeds into the
    seL4 image are the identical bytes (both print this same fingerprint for the same file) --
    see docs/QEDOS_PRESS_PROD_KEY.md requirement 2. Returns None if the file doesn't exist yet."""
    if not os.path.exists(pubkey_hex_file):
        return None
    hexstr = open(pubkey_hex_file).read().strip()
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return "INVALID (not valid hex)"
    if len(raw) != 32:
        return f"INVALID (expected 32 bytes, got {len(raw)})"
    return hashlib.sha256(raw).hexdigest()


def ensure_qs(repo_root: str) -> str:
    qs = os.path.join(repo_root, "build/qs/ws/target/release/qs")
    if not os.path.exists(qs):
        subprocess.run([os.path.join(repo_root, "scripts/qs-ws.sh"), "build", "--release",
                        "-p", "pg-script-cli"], check=True, cwd=repo_root)
    return qs


def verify_bundle_signature(repo_root: str, qpr_path: str, pubkey_hex_file: str) -> None:
    """Raises BundleRejected if the signature does not verify against pubkey_hex_file, or if that
    public-key file does not exist yet (no production key configured)."""
    if not os.path.exists(pubkey_hex_file):
        raise BundleRejected(
            f"no production public key configured at {pubkey_hex_file} -- generate a keypair "
            f"with tools/press-sign-offline.py on a SEPARATE machine and copy only the PUBLIC "
            f"key here")
    qs = ensure_qs(repo_root)
    with open(qpr_path, "rb") as f:
        blob = f.read()
    header = parse_qpr_header(blob)  # raises BundleRejected on malformed input
    payload, sig = blob[:-QPR_SIG_LEN], blob[-QPR_SIG_LEN:]
    tmpdir = tempfile.mkdtemp(prefix="press-admin-verify-")
    try:
        payload_path = os.path.join(tmpdir, "payload.bin")
        sig_path = os.path.join(tmpdir, "sig.hex")
        with open(payload_path, "wb") as f:
            f.write(payload)
        with open(sig_path, "w") as f:
            f.write(sig.hex() + "\n")
        r = subprocess.run([qs, "raw-verify", "--pub", pubkey_hex_file, "--sig", sig_path, payload_path],
                            capture_output=True, text=True)
        if r.returncode != 0:
            raise BundleRejected(f"Ed25519 signature verification FAILED: {r.stderr.strip() or r.stdout.strip()}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return header


def check_and_bump_generation(header: dict, last_gen_file: str) -> int:
    """Rollback/replay protection: reject any bundle whose release_no (generation) is not
    strictly greater than the highest ever previously accepted, even with a valid signature.
    Only mutates last_gen_file on success (the caller must only call this AFTER the signature
    has already verified, and should only persist the file once the rest of accept() succeeds --
    see accept_bundle())."""
    last = 0
    if os.path.exists(last_gen_file):
        with open(last_gen_file) as f:
            last = int(f.read().strip() or "0")
    if header["release_no"] <= last:
        raise BundleRejected(
            f"rollback/replay rejected: bundle generation {header['release_no']} <= last "
            f"accepted generation {last} (this does NOT mean the signature was invalid -- it "
            f"was valid, but this exact or an older release was already accepted before)")
    return last


def write_generation(last_gen_file: str, generation: int) -> None:
    os.makedirs(os.path.dirname(last_gen_file), exist_ok=True)
    tmp = last_gen_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(generation) + "\n")
    os.replace(tmp, last_gen_file)


def accept_bundle(repo_root: str, qpr_path: str, pubkey_hex_file: str, last_gen_file: str,
                   cert: str = None, key: str = None, out_dir: str = None,
                   build_flags: dict = None) -> dict:
    """The actual trusted 'publish' step: verify signature -> check/bump generation -> stage the
    ALREADY-SIGNED bytes verbatim (never re-signed, never re-packed) -> build a seL4 image from
    them. No private key is read or used anywhere in this function.

    The build defaults to QEDOS_PRESS_PROD=1 with QEDOS_PRESS_PROD_PUBKEY set to this SAME
    pubkey_hex_file -- the exact file this function just verified the signature against -- so the
    seL4 image's own compile-time-embedded trust key and this host's host-side verification key
    are, by construction, the identical bytes, never two independently-configured values that
    could silently drift apart. See docs/QEDOS_PRESS_PROD_KEY.md. scripts/build-sel4.sh fails
    closed (non-zero exit, no image produced) if pubkey_hex_file is malformed or equals the dev
    key, which surfaces here as a RuntimeError from the failed build, same as any other build
    failure."""
    header = verify_bundle_signature(repo_root, qpr_path, pubkey_hex_file)
    last = check_and_bump_generation(header, last_gen_file)

    staged_qpr = os.path.join(tempfile.mkdtemp(prefix="press-admin-accepted-"), "press-release.qpr")
    shutil.copy(qpr_path, staged_qpr)

    env = dict(os.environ)
    env["PATH"] = os.path.join(repo_root, "third_party/venv/bin") + os.pathsep + env.get("PATH", "")
    default_flags = {"QEDOS_PRESS_COMPAT": "1", "QEDOS_PRESS_PROD": "1",
                      "QEDOS_PRESS_PROD_PUBKEY": pubkey_hex_file}
    for k, v in (build_flags if build_flags is not None else default_flags).items():
        env[k] = v
    env["QEDOS_PRESS_QPR"] = staged_qpr
    if cert:
        env["QEDOS_TLS_CERT"] = cert
    if key:
        env["QEDOS_TLS_KEY"] = key
    if out_dir:
        env["QEDOS_OUT"] = out_dir
    r = subprocess.run([os.path.join(repo_root, "scripts/build-sel4.sh")],
                        cwd=repo_root, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"build-sel4.sh failed:\n{r.stdout[-4000:]}\n{r.stderr[-4000:]}")

    # Only now, after the build actually succeeded, persist the new accepted generation -- a
    # failed build must not consume the generation number.
    write_generation(last_gen_file, header["release_no"])

    final_out = out_dir or os.path.join(repo_root, "build/sel4-press-compat")
    return {"qpr": staged_qpr, "image": os.path.join(final_out, "loader.img"),
            "generation": header["release_no"], "previous_generation": last,
            "log": r.stdout[-2000:]}


# ---------------------------------------------------------------------------
# HTTP app
# ---------------------------------------------------------------------------

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>QEDOS Press Admin</title></head>
<body style="font-family:sans-serif;max-width:40em;margin:4em auto">
<h1>QEDOS Press Admin</h1>
{error}
<form method="POST" action="/login">
<p><input name="password" type="password" placeholder="password" autofocus style="width:100%"></p>
<p><input name="totp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="6-digit authenticator code" style="width:100%"></p>
<p><button type="submit">Log in</button></p>
</form>
</body></html>"""

EDIT_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>QEDOS Press Admin -- Edit</title></head>
<body style="font-family:sans-serif;max-width:60em;margin:2em auto">
<h1>QEDOS Press Admin</h1>
<p><a href="/logout">log out</a> | <a href="/inbox">signed-bundle inbox</a></p>
{message}
<p><b>Draft editing here is STAGING ONLY</b> -- it never signs or publishes anything by itself.
Save a draft, preview it, then <a href="/export-draft">export it</a> and sign it on your separate,
offline machine with <code>tools/press-sign-offline.py</code>. Copy the resulting <code>.qpr</code>
file into the inbox directory on this host, then use the <a href="/inbox">inbox page</a> to verify
and deploy it. This host never holds, reads, or uses any signing private key.</p>
<form method="POST" action="/draft">
<input type="hidden" name="csrf" value="{csrf}">
<p><textarea name="content" rows="20" style="width:100%;font-family:monospace">{content}</textarea></p>
<p><button type="submit">Save Draft</button></p>
</form>
{preview_block}
<p><a href="/export-draft">export current draft (for signing elsewhere)</a></p>
</body></html>"""

INBOX_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>QEDOS Press Admin -- Signed-bundle inbox</title></head>
<body style="font-family:sans-serif;max-width:60em;margin:2em auto">
<h1>Signed-bundle inbox</h1>
<p><a href="/edit">back to draft editor</a> | <a href="/logout">log out</a></p>
<p>Files found in <code>{inbox_dir}</code>. Each is verified against the configured production
public key ({pubkey_file}{pubkey_missing}) and checked against the last-accepted release
generation before any build happens. <b>No private key is read or used by this host at any
point.</b></p>
<p>Public key fingerprint (sha256): <code>{fingerprint}</code><br>
Accepting a bundle builds the seL4 image with <code>QEDOS_PRESS_PROD=1</code> against this exact
file, so this fingerprint is also what gets embedded as the image's own compile-time trust key --
compare it against the fingerprint <code>scripts/build-sel4.sh</code> printed for the same file if
you want an independent cross-check rather than trusting "same file path" alone.</p>
{message}
{rows}
</body></html>"""

INBOX_ROW = """<form method="POST" action="/inbox/accept" style="border:1px solid #ccc;padding:0.5em;margin:0.5em 0">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="filename" value="{filename}">
<b>{filename}</b> ({size} bytes)
<button type="submit" onclick="return confirm('Verify and deploy {filename}? This builds a new seL4 image from this ALREADY-SIGNED bundle.');">Verify &amp; Build</button>
</form>"""


class AdminState:
    def __init__(self, repo_root, site_dir, passwd_file, secret_file, totp_file,
                 pubkey_file, last_gen_file, inbox_dir, cert, key, out_dir):
        self.repo_root = repo_root
        self.site_dir = site_dir
        self.live_file = os.path.join(site_dir, "index.html")
        self.passwd_file = passwd_file
        self.totp_file = totp_file
        self.pubkey_file = pubkey_file
        self.last_gen_file = last_gen_file
        self.inbox_dir = inbox_dir
        os.makedirs(inbox_dir, exist_ok=True)
        self.secret = load_or_create_secret(secret_file)
        self.cert = cert
        self.key = key
        self.out_dir = out_dir
        self.draft_dir = tempfile.mkdtemp(prefix="press-admin-draft-")
        self.draft_file = os.path.join(self.draft_dir, "index.html")
        if os.path.exists(self.live_file):
            shutil.copy(self.live_file, self.draft_file)
        self.last_accept = None

    def stored_hash(self):
        with open(self.passwd_file) as f:
            return f.read().strip()

    def totp_secret(self):
        with open(self.totp_file) as f:
            return totp_secret_from_base32(f.read().strip())

    def draft_content(self):
        if os.path.exists(self.draft_file):
            with open(self.draft_file, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        return ""


class Handler(http.server.BaseHTTPRequestHandler):
    state: AdminState = None  # set by server factory

    def log_message(self, fmt, *args):
        pass  # keep stdout quiet; standard http.server would print every request

    # -- helpers -----------------------------------------------------------
    def _cookies(self):
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v
        return out

    def _session_valid(self):
        cookies = self._cookies()
        val = cookies.get("session")
        if not val:
            return False, None
        return verify_session_cookie(self.state.secret, val), val

    def _send(self, status, body: bytes, content_type="text/html; charset=utf-8", set_cookie=None, clear_cookie=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if set_cookie:
            self.send_header("Set-Cookie", f"session={set_cookie}; HttpOnly; SameSite=Strict; Path=/")
        if clear_cookie:
            self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        self.end_headers()
        self.wfile.write(body)

    def _read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()}

    def _redirect(self, path, set_cookie=None, clear_cookie=False):
        self.send_response(303)
        self.send_header("Location", path)
        if set_cookie:
            self.send_header("Set-Cookie", f"session={set_cookie}; HttpOnly; SameSite=Strict; Path=/")
        if clear_cookie:
            self.send_header("Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- routes --------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        ok, session_val = self._session_valid()
        if path == "/login":
            self._send(200, LOGIN_PAGE.format(error="").encode())
            return
        if path == "/logout":
            self._redirect("/login", clear_cookie=True)
            return
        if not ok:
            self._redirect("/login")
            return
        if path == "/" or path == "/edit":
            msg = ""
            if self.state.last_accept:
                msg = f"<p style='color:green'>{html.escape(json.dumps(self.state.last_accept))}</p>"
            csrf = make_csrf_token(self.state.secret, session_val)
            body = EDIT_PAGE.format(
                message=msg,
                csrf=csrf,
                content=html.escape(self.state.draft_content()),
                preview_block="<p><a href='/preview' target='_blank'>preview draft</a></p>",
            ).encode()
            self._send(200, body)
            return
        if path == "/preview":
            with open(self.state.draft_file, "rb") as f:
                self._send(200, f.read())
            return
        if path == "/export-draft":
            self._send(200, self.state.draft_content().encode(),
                        content_type="text/html; charset=utf-8")
            return
        if path == "/inbox":
            csrf = make_csrf_token(self.state.secret, session_val)
            rows = []
            try:
                names = sorted(n for n in os.listdir(self.state.inbox_dir) if n.endswith(".qpr"))
            except OSError:
                names = []
            for name in names:
                full = os.path.join(self.state.inbox_dir, name)
                rows.append(INBOX_ROW.format(csrf=csrf, filename=html.escape(name),
                                              size=os.path.getsize(full)))
            msg = ""
            if self.state.last_accept:
                msg = f"<p style='color:green'>{html.escape(json.dumps(self.state.last_accept))}</p>"
            pubkey_missing = "" if os.path.exists(self.state.pubkey_file) else " -- MISSING, nothing can be accepted"
            fp = pubkey_fingerprint(self.state.pubkey_file) or "(no key configured yet)"
            body = INBOX_PAGE.format(
                inbox_dir=html.escape(self.state.inbox_dir),
                pubkey_file=html.escape(self.state.pubkey_file),
                pubkey_missing=pubkey_missing,
                fingerprint=html.escape(fp),
                message=msg,
                rows="".join(rows) or "<p>(no .qpr files found)</p>",
            ).encode()
            self._send(200, body)
            return
        self._send(404, b"not found")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            form = self._read_form()
            pw = form.get("password", "")
            totp_code = form.get("totp", "")
            if not os.path.exists(self.state.passwd_file):
                self._send(500, b"no password configured; run --set-password first")
                return
            if not os.path.exists(self.state.totp_file):
                self._send(500, b"no TOTP enrolled; run --enroll-totp first")
                return
            pw_ok = verify_password(pw, self.state.stored_hash())
            totp_ok = totp_verify(self.state.totp_secret(), totp_code)
            if pw_ok and totp_ok:
                cookie = make_session_cookie(self.state.secret)
                self._redirect("/edit", set_cookie=cookie)
            else:
                time.sleep(0.3)  # crude timing-attack / brute-force friction
                self._send(401, LOGIN_PAGE.format(
                    error="<p style='color:red'>invalid password or authenticator code</p>").encode())
            return

        ok, session_val = self._session_valid()
        if not ok:
            self._send(403, b"forbidden: no valid session")
            return
        form = self._read_form()
        if not verify_csrf_token(self.state.secret, session_val, form.get("csrf", "")):
            self._send(403, b"forbidden: bad csrf token")
            return

        if path == "/draft":
            content = form.get("content", "")
            with open(self.state.draft_file, "w", encoding="utf-8") as f:
                f.write(content)
            self._redirect("/edit")
            return

        if path == "/inbox/accept":
            filename = form.get("filename", "")
            # Never let a request pick a path outside the inbox directory.
            safe_name = os.path.basename(filename)
            full = os.path.join(self.state.inbox_dir, safe_name)
            if not safe_name.endswith(".qpr") or not os.path.isfile(full) or \
               os.path.realpath(full) != os.path.join(os.path.realpath(self.state.inbox_dir), safe_name):
                self.state.last_accept = {"error": "invalid or missing inbox file"}
                self._redirect("/inbox")
                return
            try:
                result = accept_bundle(self.state.repo_root, full, self.state.pubkey_file,
                                        self.state.last_gen_file, cert=self.state.cert,
                                        key=self.state.key, out_dir=self.state.out_dir)
                self.state.last_accept = result
            except BundleRejected as e:
                self.state.last_accept = {"rejected": str(e)}
            except Exception as e:
                self.state.last_accept = {"error": str(e)[-2000:]}
            self._redirect("/inbox")
            return

        self._send(404, b"not found")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def run_server(bind, port, state: AdminState):
    Handler.state = state
    srv = ThreadingHTTPServer((bind, port), Handler)
    print(f"press-admin listening on http://{bind}:{port} (loopback-only unless you changed --bind)")
    srv.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-password", action="store_true")
    ap.add_argument("--enroll-totp", action="store_true")
    ap.add_argument("--show-pubkey-fingerprint", action="store_true",
                     help="print the sha256 fingerprint of --pubkey-file and exit")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--repo-root", default=REPO_ROOT_DEFAULT)
    ap.add_argument("--site-dir", default=None)
    ap.add_argument("--passwd-file", default=None)
    ap.add_argument("--secret-file", default=None)
    ap.add_argument("--totp-file", default=None)
    ap.add_argument("--pubkey-file", default=None,
                     help="production Ed25519 PUBLIC key hex (generated elsewhere by "
                          "tools/press-sign-offline.py; this host never holds the private key)")
    ap.add_argument("--last-gen-file", default=None)
    ap.add_argument("--inbox-dir", default=None,
                     help="directory where already-signed .qpr files are dropped for this host to verify+deploy")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--out-dir", default=None, help="override build output dir (QEDOS_OUT)")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    passwd_file = args.passwd_file or os.path.join(repo_root, "config/local/press-admin-passwd")
    secret_file = args.secret_file or os.path.join(repo_root, "config/local/press-admin-secret")
    totp_file = args.totp_file or os.path.join(repo_root, "config/local/press-admin-totp")
    pubkey_file = args.pubkey_file or os.path.join(repo_root, "config/keys/qedos-press-prod-pub.hex")
    last_gen_file = args.last_gen_file or os.path.join(repo_root, "config/local/press-admin-last-generation")
    inbox_dir = args.inbox_dir or os.path.join(repo_root, "config/local/press-inbox")
    site_dir = args.site_dir or os.path.join(repo_root, "examples/press-site")

    if args.set_password:
        set_password_interactive(passwd_file)
        return
    if args.enroll_totp:
        enroll_totp_interactive(totp_file, repo_root)
        return
    if args.show_pubkey_fingerprint:
        fp = pubkey_fingerprint(pubkey_file)
        if fp is None:
            sys.exit(f"no public key file at {pubkey_file}")
        print(f"{pubkey_file}: sha256={fp}")
        return

    if not os.path.exists(passwd_file):
        sys.exit(f"no password file at {passwd_file}; run: python3 {sys.argv[0]} --set-password")
    if not os.path.exists(totp_file):
        sys.exit(f"no TOTP enrolled at {totp_file}; run: python3 {sys.argv[0]} --enroll-totp")

    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: binding to a non-loopback address. This tool controls which already-"
              "signed bundle gets deployed; exposing it beyond the operator's own access (e.g. "
              "outside a Tailscale/SSH tunnel) was never intended -- see docs/QEDOS_PRESS_ADMIN.md.",
              file=sys.stderr)
    if not os.path.exists(pubkey_file):
        print(f"NOTE: no production public key at {pubkey_file} yet -- the inbox page will show "
              f"every bundle as un-acceptable until one is generated elsewhere "
              f"(tools/press-sign-offline.py) and its PUBLIC half is copied here.", file=sys.stderr)

    state = AdminState(repo_root, site_dir, passwd_file, secret_file, totp_file,
                        pubkey_file, last_gen_file, inbox_dir, args.cert, args.key, args.out_dir)
    run_server(args.bind, args.port, state)


if __name__ == "__main__":
    main()
