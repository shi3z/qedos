#!/usr/bin/env python3
"""
A simple web-based content editor for QEDOS Press, meant to run on the SAME separate,
operator-controlled machine that holds the real Ed25519 signing private key (generated via
tools/press-keygen.sh / tools/press-sign-offline.py keygen) -- never on the shared, public,
multi-tenant QEDOS host ("tsuginosuke"). See docs/QEDOS_PRESS_ADMIN.md and
docs/QEDOS_PRESS_PROD_KEY.md for the full architecture this fits into:

    separate machine (this tool runs here)              shared QEDOS host
    tools/press-keygen.sh (once)  -> prod-seed.hex, prod-pub.hex
    tools/press-editor-offline.py (day to day):
      - edit content in a browser, save drafts, preview
      - "Sign & Export" -> calls tools/press-sign-offline.py's existing signing logic
        (never reimplemented here) -> downloads a signed release.qpr
    operator copies release.qpr to the shared host's config/local/press-inbox/  ------>
                                                                    tools/press-admin.py's /inbox
                                                                    verifies (PUBLIC key only) and
                                                                    deploys. No private key ever
                                                                    touches the shared host.

This tool itself touches the real private key (to sign), so it has the SAME safety nets as
tools/press-keygen.sh and tools/press-sign-offline.py:
  1. Refuses to start at all if it detects it is running on the known shared host (by hostname),
     unless the loudly-named test-only override below is set.
  2. Requires the SAME interactive "type yes" confirmation as press-sign-offline.py before it will
     perform any real sign operation -- asked ONCE, interactively, at process startup (before the
     web server starts accepting requests), not per-request (a long-running server re-prompting on
     every HTTP request would make no sense). Once confirmed for this process, every "Sign &
     Export" click in the browser invokes press-sign-offline.py's own sign logic with
     --yes-i-am-on-a-separate-machine, because the human has already confirmed once, for this
     process, that this is the separate machine; asking again per-click would be pure friction
     with no additional safety, and press-sign-offline.py's own confirmation gate is designed to
     be satisfiable by a deliberate human action exactly once per use, not re-litigated by an
     already-running server process.

stdlib only. No new pip dependency. Binds to 127.0.0.1 by default; never bind a public interface.

Test-only override (NEVER set this for real use, NEVER on the shared host for anything but an
automated test of this file's own logic):
  PRESS_EDITOR_OFFLINE_ALLOW_SHARED_HOST_FOR_TESTING_ONLY=1

Usage:
  python3 tools/press-editor-offline.py --qs PATH/qs --seed prod-seed.hex \\
      [--content-dir DIR] [--release-state-file FILE] [--bind 127.0.0.1] [--port 8901]
"""
import argparse
import html
import http.server
import importlib.util
import os
import socketserver
import subprocess
import sys
import tempfile
import urllib.parse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KNOWN_SHARED_HOST = "tsuginosuke"
TEST_OVERRIDE_ENV = "PRESS_EDITOR_OFFLINE_ALLOW_SHARED_HOST_FOR_TESTING_ONLY"


def _load_sign_offline_module():
    """Import tools/press-sign-offline.py as a module (hyphenated filename, so plain `import`
    doesn't work -- same importlib pattern tests/test_press_admin.py already uses). Reused so the
    confirmation banner/prompt text never drifts out of sync between the two tools."""
    path = os.path.join(REPO_ROOT, "tools", "press-sign-offline.py")
    spec = importlib.util.spec_from_file_location("press_sign_offline", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def refuse_if_shared_host() -> None:
    if os.environ.get(TEST_OVERRIDE_ENV) == "1":
        print(f"WARNING: {TEST_OVERRIDE_ENV}=1 is set -- shared-host refusal is BYPASSED. "
              f"This must only ever be set by this project's own test harness, never for real "
              f"use.", file=sys.stderr)
        return
    actual = ""
    try:
        actual = os.uname().nodename
    except Exception:
        pass
    if actual == KNOWN_SHARED_HOST:
        sys.exit(
            f"press-editor-offline.py: refusing to run -- this looks like the shared QEDOS host "
            f"({KNOWN_SHARED_HOST}). This tool touches the real signing private key and must "
            f"only run on a SEPARATE machine you control. Copy this repository there instead.")


# ---------------------------------------------------------------------------
# Release-generation bookkeeping: tools/press-admin.py's check_and_bump_generation on the shared
# host requires every accepted bundle's release_no to be STRICTLY greater than the last one it
# ever accepted (re-deploying the exact same generation is also rejected -- see
# docs/QEDOS_PRESS_PROD_KEY.md). This editor auto-increments a local counter on every successful
# sign so the operator never has to remember or manually bump a number themselves. This is
# per-editor-instance/per-state-file state, not shared with the host's own last-accepted-generation
# file (which is the actual authority, host-side) -- if the operator runs two editor instances
# against two different state files, or resets this file, they could produce a generation the host
# has already seen; that would simply be rejected by the host as a rollback, same as any other
# duplicate/old generation, not a security hole, just a usability edge case. Documented here and in
# docs/QEDOS_PRESS_PROD_KEY.md rather than solved with cross-machine coordination, which is out of
# scope for a simple offline editor.
# ---------------------------------------------------------------------------

def next_release_number(state_file: str) -> int:
    last = 0
    if os.path.exists(state_file):
        with open(state_file) as f:
            last = int((f.read().strip() or "0"))
    return last + 1


def record_release_number(state_file: str, n: int) -> None:
    os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
    tmp = state_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(n) + "\n")
    os.replace(tmp, state_file)


# ---------------------------------------------------------------------------
# HTTP app. No login/session: unlike tools/press-admin.py (which runs on a SHARED host reachable
# by more than just the operator), this tool is meant to run only on a machine the operator
# already fully controls, bound to loopback only -- the operating system's own user-account
# boundary is the access control here, same trust level as e.g. running a local text editor.
# ---------------------------------------------------------------------------

EDIT_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>QEDOS Press -- offline editor</title></head>
<body style="font-family:sans-serif;max-width:60em;margin:2em auto">
<h1>QEDOS Press -- offline content editor</h1>
<p style="background:#fffae0;border:1px solid #e0d080;padding:0.5em">
This tool runs on your SEPARATE signing machine and never touches the shared QEDOS host directly.
"Sign &amp; Export" produces a signed <code>.qpr</code> file for you to download and copy to the
shared host's <code>config/local/press-inbox/</code> yourself.</p>
{message}
<form method="POST" action="/draft">
<p><textarea name="content" rows="20" style="width:100%;font-family:monospace">{content}</textarea></p>
<p><button type="submit">Save Draft</button></p>
</form>
<p><a href="/preview" target="_blank">preview draft</a></p>
<form method="POST" action="/sign">
<p>Next release generation (auto): <b>{next_release}</b></p>
<p><button type="submit">Sign &amp; Export (downloads a .qpr file)</button></p>
</form>
</body></html>"""


class EditorState:
    def __init__(self, qs: str, seed: str, content_dir: str, release_state_file: str, confirmed: bool):
        self.qs = qs
        self.seed = seed
        self.content_dir = content_dir
        self.index_file = os.path.join(content_dir, "index.html")
        self.release_state_file = release_state_file
        self.confirmed = confirmed  # set True once, interactively, at process startup

    def draft_content(self) -> str:
        if os.path.exists(self.index_file):
            with open(self.index_file, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        return ""


class Handler(http.server.BaseHTTPRequestHandler):
    state: EditorState = None  # set by server factory

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body: bytes, content_type="text/html; charset=utf-8", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()}

    def _render_edit(self, message=""):
        next_release = next_release_number(self.state.release_state_file)
        body = EDIT_PAGE.format(
            message=message,
            content=html.escape(self.state.draft_content()),
            next_release=next_release,
        ).encode()
        self._send(200, body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/edit"):
            self._render_edit()
            return
        if path == "/preview":
            os.makedirs(self.state.content_dir, exist_ok=True)
            if not os.path.exists(self.state.index_file):
                self._send(200, b"<!doctype html><p>(no draft yet)</p>")
                return
            with open(self.state.index_file, "rb") as f:
                self._send(200, f.read())
            return
        self._send(404, b"not found")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        form = self._read_form()

        if path == "/draft":
            os.makedirs(self.state.content_dir, exist_ok=True)
            with open(self.state.index_file, "w", encoding="utf-8") as f:
                f.write(form.get("content", ""))
            self._render_edit(message="<p style='color:green'>draft saved</p>")
            return

        if path == "/sign":
            if not self.state.confirmed:
                # Should be unreachable in normal operation (confirmation happens before the
                # server starts accepting connections at all) -- kept as a defensive fail-closed
                # check in case of a future refactor that starts the server earlier.
                self._send(403, b"not confirmed as running on a separate machine; restart this tool")
                return
            release_no = next_release_number(self.state.release_state_file)
            out_dir = tempfile.mkdtemp(prefix="press-editor-offline-sign-")
            out_qpr = os.path.join(out_dir, "release.qpr")
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "tools", "press-sign-offline.py"), "sign",
                 "--qs", self.state.qs, "--seed", self.state.seed,
                 "--release", str(release_no), "--out", out_qpr, self.state.content_dir,
                 "--yes-i-am-on-a-separate-machine"],
                capture_output=True, text=True,
            )
            if r.returncode != 0 or not os.path.exists(out_qpr):
                # r.stdout/stderr from press-sign-offline.py's cmd_sign never include private key
                # bytes (it only ever prints the release number and output path on success); still
                # truncate defensively before surfacing to the browser.
                err = (r.stderr or r.stdout or "sign failed")[-2000:]
                self._render_edit(message=f"<p style='color:red'>sign failed: {html.escape(err)}</p>")
                return
            record_release_number(self.state.release_state_file, release_no)
            with open(out_qpr, "rb") as f:
                data = f.read()
            self._send(200, data, content_type="application/octet-stream", extra_headers={
                "Content-Disposition": f'attachment; filename="press-release-gen{release_no}.qpr"',
            })
            return

        self._send(404, b"not found")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qs", required=True, help="path to the built `qs` CLI binary")
    ap.add_argument("--seed", required=True, help="path to the real production Ed25519 private seed (NEVER copy this file anywhere else)")
    ap.add_argument("--content-dir", default=os.path.join(REPO_ROOT, "press-editor-content"))
    ap.add_argument("--release-state-file", default=os.path.join(REPO_ROOT, "press-editor-last-release"))
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8901)
    args = ap.parse_args()

    refuse_if_shared_host()

    if not os.path.exists(args.seed):
        sys.exit(f"press-editor-offline.py: no seed file at {args.seed} -- generate one first "
                  f"with tools/press-keygen.sh on this machine.")

    # One interactive confirmation for this whole process, reusing press-sign-offline.py's own
    # banner/prompt text so it never drifts out of sync between the two tools.
    sign_offline = _load_sign_offline_module()
    print(sign_offline.BANNER, file=sys.stderr)
    if os.environ.get(TEST_OVERRIDE_ENV) == "1":
        confirmed = True
        print(f"({TEST_OVERRIDE_ENV}=1 set -- skipping the interactive prompt for automated testing only)",
              file=sys.stderr)
    elif not sys.stdin.isatty():
        sys.exit("press-editor-offline.py: refusing to start non-interactively without a TTY to "
                 "confirm on (this tool signs real content with a real private key; it must be "
                 "started by a human, in a real terminal, on their own separate machine)")
    else:
        reply = input("Type 'yes' to confirm you are running this on a SEPARATE machine, not the "
                      "shared QEDOS host, and that you will keep the private seed only here: ")
        if reply.strip().lower() != "yes":
            sys.exit("not confirmed; aborting")
        confirmed = True

    os.makedirs(args.content_dir, exist_ok=True)

    state = EditorState(args.qs, args.seed, args.content_dir, args.release_state_file, confirmed)
    Handler.state = state
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"press-editor-offline listening on http://{args.bind}:{args.port} (loopback-only unless you changed --bind)")
    print(f"content dir: {args.content_dir}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
