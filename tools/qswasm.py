#!/usr/bin/env python3
"""Tiny flat-WAT-style assembler for the QED Script Wasm subset (i32/i64 integer core).

Used to build the example, malicious and differential-fuzz modules without a Wasm toolchain.
Generates plain WebAssembly 1.0 (+ sign-extension, bulk-memory copy/fill) binaries; it performs NO
validation (the point of the malicious corpus is to feed the loader invalid/hostile input). The
authoritative validators are pg-script's Module::parse and, independently, V8 (tests/v8_ref.js).
"""
import struct

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not b & 0x40) or (n == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)

VT = {"i32": 0x7F, "i64": 0x7E}

OPS = {"unreachable": 0x00, "nop": 0x01, "else": 0x05, "end": 0x0B, "return": 0x0F, "drop": 0x1A, "select": 0x1B}

_I32_NAMES = ["eqz", "eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u"]
for _i, _n in enumerate(_I32_NAMES):
    OPS["i32." + _n] = 0x45 + _i
    OPS["i64." + _n] = 0x50 + _i
_ARITH = ["clz", "ctz", "popcnt", "add", "sub", "mul", "div_s", "div_u", "rem_s", "rem_u", "and", "or", "xor",
          "shl", "shr_s", "shr_u", "rotl", "rotr"]
for _i, _n in enumerate(_ARITH):
    OPS["i32." + _n] = 0x67 + _i
    OPS["i64." + _n] = 0x79 + _i
OPS.update({"i32.wrap_i64": 0xA7, "i64.extend_i32_s": 0xAC, "i64.extend_i32_u": 0xAD,
            "i32.extend8_s": 0xC0, "i32.extend16_s": 0xC1,
            "i64.extend8_s": 0xC2, "i64.extend16_s": 0xC3, "i64.extend32_s": 0xC4})

# mnemonic -> (opcode, natural alignment log2)
MEMOPS = {
    "i32.load": (0x28, 2), "i64.load": (0x29, 3),
    "i32.load8_s": (0x2C, 0), "i32.load8_u": (0x2D, 0), "i32.load16_s": (0x2E, 1), "i32.load16_u": (0x2F, 1),
    "i64.load8_s": (0x30, 0), "i64.load8_u": (0x31, 0), "i64.load16_s": (0x32, 1), "i64.load16_u": (0x33, 1),
    "i64.load32_s": (0x34, 2), "i64.load32_u": (0x35, 2),
    "i32.store": (0x36, 2), "i64.store": (0x37, 3), "i32.store8": (0x3A, 0), "i32.store16": (0x3B, 1),
    "i64.store8": (0x3C, 0), "i64.store16": (0x3D, 1), "i64.store32": (0x3E, 2),
}
LEBOPS = {"br": 0x0C, "br_if": 0x0D, "local.get": 0x20, "local.set": 0x21, "local.tee": 0x22,
          "global.get": 0x23, "global.set": 0x24}
BLOCKS = {"block": 0x02, "loop": 0x03, "if": 0x04}


def _vts(x):
    """int N -> N x i32; list of 'i32'/'i64' -> as is."""
    if isinstance(x, int):
        return ["i32"] * x
    return list(x)


class Module:
    def __init__(self, memory_pages=1, memory_max=None):
        self.types = []
        self.imports = []   # (module, name, type_idx)
        self.funcs = []     # (type_idx, local types, body)
        self.exports = []   # (name, kind, idx)
        self.data = []      # (offset, bytes)
        self.globals = []   # (valtype, mutable, init)
        self.table = None   # (min, max|None)
        self.elems = []     # (offset, [func idx])
        self.memory_pages = memory_pages
        self.memory_max = memory_max
        self.names = {}
        self.no_memory = False
        self.export_memory = False

    def type(self, params, results):
        t = (tuple(_vts(params)), tuple(_vts(results)))
        if t not in self.types:
            self.types.append(t)
        return self.types.index(t)

    def import_func(self, name, np, nr, module="qs"):
        self.names[name] = len(self.imports)
        self.imports.append((module, name, self.type(np, nr)))

    def func(self, name, np, nr, nlocals, asm, export=None):
        idx = len(self.imports) + len(self.funcs)
        self.names[name] = idx
        self.funcs.append((self.type(np, nr), _vts(nlocals), asm))
        if export:
            self.exports.append((export, 0, idx))
        return idx

    def global_(self, ty, mutable, init):
        self.globals.append((ty, mutable, init))
        return len(self.globals) - 1

    def set_table(self, size, maxsize=None):
        self.table = (size, maxsize)

    def elem(self, offset, funcs):
        self.elems.append((offset, funcs))

    def assemble(self, asm):
        out = bytearray()
        for raw in asm.split("\n"):
            line = raw.split(";;")[0].strip()
            if not line:
                continue
            parts = line.split()
            m = parts[0]
            if m in OPS:
                out.append(OPS[m])
            elif m in LEBOPS:
                out.append(LEBOPS[m]); out += uleb(int(parts[1]))
            elif m in BLOCKS:
                out.append(BLOCKS[m])
                bt = parts[1] if len(parts) > 1 else None
                out.append(VT[bt] if bt in VT else 0x40)
            elif m == "i32.const":
                out.append(0x41); out += sleb(int(parts[1], 0))
            elif m == "i64.const":
                out.append(0x42); out += sleb(int(parts[1], 0))
            elif m == "br_table":
                targets = [int(x) for x in parts[1:]]
                out.append(0x0E); out += uleb(len(targets) - 1)
                for t in targets:
                    out += uleb(t)
            elif m == "call":
                t = parts[1]
                idx = self.names[t[1:]] if t.startswith("$") else int(t)
                out.append(0x10); out += uleb(idx)
            elif m == "call_indirect":
                out.append(0x11); out += uleb(int(parts[1])); out += b"\x00"
            elif m in MEMOPS:
                opc, nat = MEMOPS[m]
                off = int(parts[1]) if len(parts) > 1 else 0
                align = int(parts[2]) if len(parts) > 2 else nat
                out.append(opc); out += uleb(align); out += uleb(off)
            elif m == "memory.size":
                out += b"\x3f\x00"
            elif m == "memory.grow":
                out += b"\x40\x00"
            elif m == "memory.copy":
                out += b"\xfc\x0a\x00\x00"
            elif m == "memory.fill":
                out += b"\xfc\x0b\x00"
            elif m == "byte":
                out.append(int(parts[1], 0))
            else:
                raise SystemExit(f"qswasm: unknown mnemonic {m!r}")
        return bytes(out)

    def build(self):
        def sec(i, body):
            return bytes([i]) + uleb(len(body)) + body
        def vec(items):
            return uleb(len(items)) + b"".join(items)
        def ftype(p, r):
            return b"\x60" + uleb(len(p)) + bytes(VT[x] for x in p) + uleb(len(r)) + bytes(VT[x] for x in r)
        def cexpr(ty, v):
            return (b"\x41" + sleb(v) if ty == "i32" else b"\x42" + sleb(v)) + b"\x0b"
        out = b"\0asm\x01\x00\x00\x00"
        out += sec(1, vec([ftype(p, r) for p, r in self.types]))
        if self.imports:
            out += sec(2, vec([uleb(len(m)) + m.encode() + uleb(len(n)) + n.encode() + b"\x00" + uleb(t)
                               for m, n, t in self.imports]))
        out += sec(3, vec([uleb(t) for t, _, _ in self.funcs]))
        if self.table:
            mn, mx = self.table
            lim = b"\x00" + uleb(mn) if mx is None else b"\x01" + uleb(mn) + uleb(mx)
            out += sec(4, vec([b"\x70" + lim]))
        if not self.no_memory:
            if self.memory_max is None:
                out += sec(5, b"\x01\x00" + uleb(self.memory_pages))
            else:
                out += sec(5, b"\x01\x01" + uleb(self.memory_pages) + uleb(self.memory_max))
        if self.globals:
            out += sec(6, vec([bytes([VT[t], 1 if mut else 0]) + cexpr(t, v) for t, mut, v in self.globals]))
        exports = list(self.exports)
        if self.export_memory:
            exports.append(("memory", 2, 0))
        out += sec(7, vec([uleb(len(n)) + n.encode() + bytes([k]) + uleb(i) for n, k, i in exports]))
        if self.elems:
            out += sec(9, vec([b"\x00\x41" + sleb(o) + b"\x0b" + uleb(len(fs)) + b"".join(uleb(f) for f in fs)
                               for o, fs in self.elems]))
        bodies = []
        for t, lt, asm in self.funcs:
            groups = []
            for ty in lt:                       # run-length encode local declarations
                if groups and groups[-1][1] == ty:
                    groups[-1][0] += 1
                else:
                    groups.append([1, ty])
            code = uleb(len(groups)) + b"".join(uleb(c) + bytes([VT[ty]]) for c, ty in groups) + self.assemble(asm)
            bodies.append(uleb(len(code)) + code)
        out += sec(10, vec(bodies))
        if self.data:
            out += sec(11, vec([b"\x00\x41" + sleb(o) + b"\x0b" + uleb(len(b)) + b for o, b in self.data]))
        return out
