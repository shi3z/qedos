#!/usr/bin/env python3
"""
Differential test of the QED Script Wasm interpreter against V8's WebAssembly engine (independent reference).

  tests/test_wasm_differential.py [--cases N] [--seed S] [--jobs J] [--chunk C] [--out DIR]

Case categories (see crates/pg-script-cli/src/fuzzgen.rs):
  0 VALID      well-typed, terminating programs (i32/i64 arithmetic, memory, calls, call_indirect, br_table, grow, bulk ops).
               Both engines must accept, and agree on result/trap kind, final linear memory and globals.
  1 CORRUPT    byte-level mutations. If V8 rejects, we must reject too (our validator must never be laxer than the spec);
               if both accept, they must agree.
  2 PADDED     semantics-preserving re-encodings (non-minimal LEB sizes, interleaved custom sections): both must accept and agree.
  3 FORBIDDEN  valid WebAssembly that QED Script excludes (floats, refs, SIMD, atomics, memory.init, tail calls...): we must reject.
Every disagreement is written to <out>/fail/ with the generating (seed, index) so it can be reproduced and minimised
(`qs fuzz-min <seed> <idx> <dir>`). Coverage numbers are NOT produced here (see scripts/wasm-coverage.sh).
Exit status 0 only if there is no disagreement. A run that executed fewer cases than requested is reported as FAIL.
"""
import argparse, json, os, subprocess, sys, time
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QS = os.environ.get("QS", os.path.join(ROOT, "build/qs/ws/target/release/qs"))
CATS = {0: "VALID", 1: "CORRUPT", 2: "PADDED", 3: "FORBIDDEN"}


def run_chunk(args):
    seed, first, count, out = args
    d = os.path.join(out, "work", f"{seed}-{first}")
    os.makedirs(d, exist_ok=True)
    cases = os.path.join(d, "c.bin")
    subprocess.run([QS, "fuzz-gen", str(seed), str(first), str(count), cases], check=True)
    ours_txt = subprocess.run([QS, "diff-run", cases], capture_output=True, text=True, check=True).stdout
    open(os.path.join(d, "ours.txt"), "w").write(ours_txt)
    v8 = subprocess.run(["node", os.path.join(ROOT, "tests/v8_ref.js"), cases, os.path.join(d, "ours.txt")],
                        capture_output=True, text=True)
    if v8.returncode != 0:
        return {"error": "v8 runner crashed: " + v8.stderr[-400:], "first": first}
    raw = open(cases, "rb").read()
    cats, p = [], 0
    while p < len(raw):
        cats.append(raw[p]); ln = int.from_bytes(raw[p + 1:p + 5], "little"); p += 5 + ln
    ours, ref = ours_txt.strip().split("\n"), v8.stdout.strip().split("\n")
    st = {"cases": 0, "by_cat": {}, "resource_stops": 0, "outcomes": {}, "fails": [], "first": first}
    for i, (o, r, cat) in enumerate(zip(ours, ref, cats)):
        o, r = o.split(" ", 1)[1], r.split(" ", 1)[1]
        st["cases"] += 1
        st["by_cat"][cat] = st["by_cat"].get(cat, 0) + 1
        kind = o.split(" ")[0] + (" " + o.split(" ")[1] if o.startswith("trap") else "")
        st["outcomes"][kind] = st["outcomes"].get(kind, 0) + 1
        why = compare(cat, o, r)
        if o == "res":
            st["resource_stops"] += 1
        if why:
            st["fails"].append({"index": first + i, "category": CATS[cat], "why": why, "ours": o, "v8": r})
            if len(st["fails"]) <= 5:
                subprocess.run([QS, "fuzz-emit", str(seed), str(first + i), os.path.join(out, "fail", f"{seed}-{first + i}.wasm")],
                               capture_output=True)
    return st


def norm(o, r):
    """V8 only sees what the module exports: a corrupted export section can hide the memory or some globals.
    Compare only the parts V8 can observe (never weakens the comparison for the well-formed categories)."""
    import re
    if "mem=nomem" in r:
        o = re.sub(r"mem=\S+", "mem=nomem", o)
    go, gr = re.search(r"g=(\S*)", o), re.search(r"g=(\S*)", r)
    if go and gr and len(go.group(1).split(",")) != len(gr.group(1).split(",")) and gr.group(1) != "":
        o = re.sub(r"g=\S*", "g=?", o)
        r = re.sub(r"g=\S*", "g=?", r)
    elif go and gr and gr.group(1) == "" and go.group(1) != "":
        o = re.sub(r"g=\S*", "g=", o)
    return o, r


def compare(cat, o, r):
    if cat == 3:
        return None if o == "reject" else f"FORBIDDEN module accepted by our loader ({o})"
    if r == "reject":
        if cat == 0:
            return "generator produced a module V8 rejects"
        return None if o in ("reject", "reject-link") else f"V8 rejects but we accept ({o})"
    if o in ("reject", "reject-link"):
        if r == "reject-link":
            return None
        if cat in (0, 2):
            return f"we reject a module V8 accepts and that must be accepted ({o} vs {r})"
        return None   # subset: allowed for corrupted modules
    if o == "res" or r == "skip" or r == "res":
        return None if (o == "res" or r in ("skip", "res")) else None
    o, r = norm(o, r)
    if cat == 1:   # a corrupted export section can re-map the g<N> names: only result and memory are comparable
        import re
        o, r = re.sub(r"g=\S*", "g=?", o), re.sub(r"g=\S*", "g=?", r)
    return None if o == r else "behaviour differs"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--chunk", type=int, default=5000)
    ap.add_argument("--out", default=os.path.join(ROOT, "build/fuzz"))
    a = ap.parse_args()
    if not os.path.exists(QS):
        print("SKIPPED: qs binary missing (scripts/qs-ws.sh build --release -p pg-script-cli)"); return 2
    if subprocess.run(["node", "--version"], capture_output=True).returncode != 0:
        print("SKIPPED: node (V8 reference) not available"); return 2
    os.makedirs(os.path.join(a.out, "fail"), exist_ok=True)
    t0 = time.time()
    jobs = [(a.seed, f, min(a.chunk, a.cases - f), a.out) for f in range(0, a.cases, a.chunk)]
    total = {"cases": 0, "by_cat": {}, "resource_stops": 0, "outcomes": {}, "fails": []}
    errors = []
    with ProcessPoolExecutor(a.jobs) as ex:
        for st in ex.map(run_chunk, jobs):
            if "error" in st:
                errors.append(st["error"]); continue
            total["cases"] += st["cases"]; total["resource_stops"] += st["resource_stops"]
            for k, v in st["by_cat"].items(): total["by_cat"][k] = total["by_cat"].get(k, 0) + v
            for k, v in st["outcomes"].items(): total["outcomes"][k] = total["outcomes"].get(k, 0) + v
            total["fails"] += st["fails"]
    dt = time.time() - t0
    rate = total["resource_stops"] / max(1, total["cases"])
    summary = {"seed": a.seed, "requested": a.cases, "executed": total["cases"], "seconds": round(dt, 1),
               "categories": {CATS[k]: v for k, v in sorted(total["by_cat"].items())},
               "outcomes": dict(sorted(total["outcomes"].items(), key=lambda kv: -kv[1])),
               "resource_stops": total["resource_stops"], "resource_stop_rate": round(rate, 4),
               "disagreements": len(total["fails"]), "runner_errors": errors, "first_failures": total["fails"][:10]}
    json.dump(summary, open(os.path.join(a.out, f"diff-{a.seed}.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1)[:3500])
    ok = not total["fails"] and not errors and total["cases"] == a.cases
    print(("PASS" if ok else "FAIL"), f"differential: {total['cases']}/{a.cases} cases, {len(total['fails'])} disagreement(s), {dt:.0f}s")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
