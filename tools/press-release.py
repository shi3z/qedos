#!/usr/bin/env python3
"""
Pack a directory of static files into a signed QEDOS Press release bundle (format "QPR1").

This is a build-time, offline tool: the release is immutable once packed (online/updatable releases
are explicitly out of scope for this phase -- see docs/QEDOS_PRESS_CMS.md). The private signing seed
never leaves the host; only the detached signature (via `qs raw-sign`) is embedded in the bundle.

Usage:
  tools/press-release.py --site-id N --release N --qs PATH/qs --seed SEED.hex --out OUT.qpr CONTENT_DIR

Format (see crates/pg-press/src/lib.rs for the authoritative parser):
  header[24]: magic("QPR1") version[1] n_routes[1] reserved[2] site_id[4] release_no[4]
              publish_ts[4] content_len[4]   (all integers little-endian)
  route table: n_routes * entry[136]
    entry: path_len[1] ctype[1] reserved[2] offset[4] length[4] path[60] hash[64](SHA-512 of file bytes)
  content: content_len bytes (concatenated file bytes, in route order)
  signature[64]: Ed25519 over everything above (header + table + content), via `qs raw-sign`
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import time

MAGIC = b"QPR1"
VERSION = 1
HEADER_LEN = 24
ENTRY_LEN = 136
MAX_PATH_LEN = 60
MAX_ROUTES = 24
SIG_LEN = 64

CTYPE_HTML, CTYPE_CSS, CTYPE_JS, CTYPE_JSON, CTYPE_PLAIN, CTYPE_OCTET = range(6)

EXT_CTYPE = {
    ".html": CTYPE_HTML, ".htm": CTYPE_HTML,
    ".css": CTYPE_CSS,
    ".js": CTYPE_JS, ".mjs": CTYPE_JS,
    ".json": CTYPE_JSON,
    ".txt": CTYPE_PLAIN, ".md": CTYPE_PLAIN,
}


def ctype_for(path: str) -> int:
    _, ext = os.path.splitext(path)
    return EXT_CTYPE.get(ext.lower(), CTYPE_OCTET)


def collect_files(content_dir: str):
    files = []
    for root, _dirs, names in os.walk(content_dir):
        for name in sorted(names):
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, content_dir).replace(os.sep, "/")
            route = "/" + rel
            files.append((route, full))
    files.sort(key=lambda t: t[0])
    return files


def build_unsigned(site_id: int, release_no: int, files) -> bytes:
    if len(files) > MAX_ROUTES:
        sys.exit(f"press-release: {len(files)} files exceeds MAX_ROUTES={MAX_ROUTES}")

    entries = []
    content = bytearray()
    for route, full in files:
        path_bytes = route.encode("utf-8")
        if len(path_bytes) > MAX_PATH_LEN:
            sys.exit(f"press-release: route {route!r} exceeds MAX_PATH_LEN={MAX_PATH_LEN}")
        with open(full, "rb") as f:
            data = f.read()
        offset = len(content)
        length = len(data)
        content.extend(data)
        file_hash = hashlib.sha512(data).digest()
        entry = bytearray(ENTRY_LEN)
        entry[0] = len(path_bytes)
        entry[1] = ctype_for(route)
        entry[4:8] = struct.pack("<I", offset)
        entry[8:12] = struct.pack("<I", length)
        entry[12:12 + len(path_bytes)] = path_bytes
        entry[72:136] = file_hash
        entries.append(bytes(entry))

    header = bytearray(HEADER_LEN)
    header[0:4] = MAGIC
    header[4] = VERSION
    header[5] = len(files)
    header[8:12] = struct.pack("<I", site_id)
    header[12:16] = struct.pack("<I", release_no)
    header[16:20] = struct.pack("<I", int(time.time()) & 0xFFFFFFFF)
    header[20:24] = struct.pack("<I", len(content))

    return bytes(header) + b"".join(entries) + bytes(content)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-id", type=int, required=True)
    ap.add_argument("--release", type=int, required=True)
    ap.add_argument("--qs", required=True, help="path to the built `qs` CLI binary")
    ap.add_argument("--seed", required=True, help="path to the Ed25519 dev signing seed (hex)")
    ap.add_argument("--out", required=True)
    ap.add_argument("content_dir")
    args = ap.parse_args()

    files = collect_files(args.content_dir)
    if not files:
        sys.exit(f"press-release: no files found under {args.content_dir}")
    unsigned = build_unsigned(args.site_id, args.release, files)

    tmp_payload = args.out + ".payload.tmp"
    with open(tmp_payload, "wb") as f:
        f.write(unsigned)
    try:
        subprocess.run([args.qs, "raw-sign", "--seed", args.seed, tmp_payload], check=True)
        with open(tmp_payload + ".sig") as f:
            sig_hex = f.read().strip()
        sig = bytes.fromhex(sig_hex)
        if len(sig) != SIG_LEN:
            sys.exit(f"press-release: unexpected signature length {len(sig)}")
    finally:
        for p in (tmp_payload, tmp_payload + ".sig"):
            if os.path.exists(p):
                os.remove(p)

    with open(args.out, "wb") as f:
        f.write(unsigned)
        f.write(sig)
    print(f"wrote {args.out} ({len(unsigned) + SIG_LEN} bytes, {len(files)} route(s))")
    for route, _full in files:
        print(f"  {route}")


if __name__ == "__main__":
    main()
