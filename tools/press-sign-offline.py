#!/usr/bin/env python3
"""
================================================================================================
 DO NOT RUN THIS ON THE SHARED PUBLIC QEDOS HOST. DO NOT RUN THIS AS PART OF ANY AUTOMATION ON
 THAT HOST. This script exists to be COPIED to, and run ONLY on, a SEPARATE, independent machine
 the operator personally controls -- a laptop, an air-gapped box, anything that is NOT the
 shared, multi-tenant, internet-facing Ubuntu host QEDOS Press runs on.

 Why: the host-side admin tool (tools/press-admin.py) was deliberately redesigned to hold NO
 Ed25519 signing private key material at all, in any form (plaintext or encrypted), because that
 host's own compromise must be part of the threat model -- see docs/QEDOS_PRESS_ADMIN.md. Every
 private key this script generates or uses belongs ONLY on the separate machine you run it on.
 Never copy a private key (a "seed.hex" file) back onto the shared host. Only the PUBLIC key
 (pub.hex) is safe to put there.
================================================================================================

Requires a copy of this repository (or at minimum its built `qs` CLI at
build/qs/ws/target/release/qs and tools/press-release.py) on the SAME separate machine you run
this on -- it is a thin, deliberately non-cryptographic wrapper around that EXISTING, already-
verified Ed25519 signing logic (crates/pg-config via `qs keygen`/`qs raw-sign`), not a
reimplementation. "Portable" here means "a separate file meant to run elsewhere", not "has no
dependency on the rest of this repo".

Modes:
  tools/press-sign-offline.py keygen --qs PATH/qs --out-seed seed.hex --out-pub pub.hex [--out-pub-rs pub.rs]
      Generate a fresh Ed25519 keypair. Prints the public key (safe to share/copy to the shared
      host); NEVER prints or logs the private seed.

  tools/press-sign-offline.py sign --qs PATH/qs --seed seed.hex --release N --out release.qpr CONTENT_DIR
      Sign CONTENT_DIR into a QPR1 release bundle with release-generation number N (must be
      strictly greater than any generation you have ever published before -- the host-side
      verifier rejects anything <= the last one it accepted, even with a valid signature). If
      --release is omitted, defaults to the current unix timestamp, which is monotonic across
      real-world uses seconds apart; pass an explicit --release for anything else (e.g. several
      releases signed within the same second, or a deliberate versioning scheme).

Refuses to run non-interactively (no TTY) without --yes-i-am-on-a-separate-machine, specifically
so it cannot be silently invoked by scripted automation on the shared host by accident; the
primary session that builds this project must never pass that flag for a real key.
"""
import argparse
import os
import subprocess
import sys
import time

BANNER = """
################################################################################
#  WARNING: this generates/uses an Ed25519 SIGNING PRIVATE KEY.              #
#  Run this ONLY on a separate machine you personally control.               #
#  NEVER on the shared public QEDOS host. NEVER as part of this project's    #
#  own automation. See the module docstring in this file.                   #
################################################################################
"""


def require_confirmation(args) -> None:
    print(BANNER, file=sys.stderr)
    if args.yes_i_am_on_a_separate_machine:
        return
    if not sys.stdin.isatty():
        sys.exit("refusing to run non-interactively without --yes-i-am-on-a-separate-machine "
                 "(this exists specifically so no script can invoke real key generation/signing "
                 "by accident -- pass that flag only when you, a human, are deliberately running "
                 "this on your own separate machine, e.g. from a test harness in a scratch dir)")
    reply = input("Type 'yes' to confirm you are running this on a SEPARATE machine, not the "
                  "shared QEDOS host: ")
    if reply.strip().lower() != "yes":
        sys.exit("not confirmed; aborting")


def cmd_keygen(args) -> None:
    require_confirmation(args)
    if os.path.exists(args.out_seed):
        sys.exit(f"refusing to overwrite existing {args.out_seed}")
    pub_rs = args.out_pub_rs or (args.out_pub + ".rs.tmp")
    subprocess.run([args.qs, "keygen", args.out_seed, pub_rs, args.out_pub], check=True)
    if not args.out_pub_rs and os.path.exists(pub_rs):
        os.remove(pub_rs)
    os.chmod(args.out_seed, 0o600)
    with open(args.out_pub) as f:
        pub_hex = f.read().strip()
    print(f"\nprivate seed written to {args.out_seed} (chmod 600) -- KEEP THIS ONLY ON THIS MACHINE")
    print(f"public key (safe to copy to the shared host as config/keys/qedos-press-prod-pub.hex):")
    print(f"  {pub_hex}")


def cmd_sign(args) -> None:
    require_confirmation(args)
    if not os.path.exists(args.seed):
        sys.exit(f"no seed file at {args.seed}")
    release = args.release if args.release is not None else int(time.time())
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    press_release_py = os.path.join(repo_root, "tools/press-release.py")
    subprocess.run([
        sys.executable, press_release_py,
        "--site-id", str(args.site_id), "--release", str(release),
        "--qs", args.qs, "--seed", args.seed, "--out", args.out, args.content_dir,
    ], check=True)
    print(f"\nsigned release generation {release} written to {args.out}")
    print("Copy this .qpr file to the shared host's press-admin inbox directory "
          "(config/local/press-inbox/ by default) for verification and deployment. "
          "The private seed never needs to leave this machine.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    kg = sub.add_parser("keygen")
    kg.add_argument("--qs", required=True, help="path to the built `qs` CLI binary")
    kg.add_argument("--out-seed", required=True)
    kg.add_argument("--out-pub", required=True)
    kg.add_argument("--out-pub-rs", default=None)
    kg.add_argument("--yes-i-am-on-a-separate-machine", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    sg = sub.add_parser("sign")
    sg.add_argument("--qs", required=True)
    sg.add_argument("--seed", required=True)
    sg.add_argument("--site-id", type=int, default=1)
    sg.add_argument("--release", type=int, default=None)
    sg.add_argument("--out", required=True)
    sg.add_argument("content_dir")
    sg.add_argument("--yes-i-am-on-a-separate-machine", action="store_true")
    sg.set_defaults(func=cmd_sign)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
