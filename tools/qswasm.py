#!/usr/bin/env python3
"""Tiny flat-WAT-style assembler for the QED Script Wasm subset (i32 only).

Used to build the example and malicious modules without a Wasm toolchain. Generates plain
WebAssembly 1.0 binaries; it performs NO validation (the point of the malicious corpus is to feed
the loader invalid/hostile input). The authoritative validator is pg-script's Module::parse.
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

OPS = {
    "unreachable": 0x00, "nop": 0x01, "else": 0x05, "end": 0x0B, "return": 0x0F, "drop": 0x1A, "select": 0x1B,
    "i32.eqz": 0x45, "i32.eq": 0x46, "i32.ne": 0x47, "i32.lt_s": 0x48, "i32.lt_u": 0x49, "i32.gt_s": 0x4A,
    "i32.gt_u": 0x4B, "i32.le_s": 0x4C, "i32.le_u": 0x4D, "i32.ge_s": 0x4E, "i32.ge_u": 0x4F,
    "i32.add": 0x6A, "i32.sub": 0x6B, "i32.mul": 0x6C, "i32.div_s": 0x6D, "i32.div_u": 0x6E,
    "i32.rem_s": 0x6F, "i32.rem_u": 0x70, "i32.and": 0x71, "i32.or": 0x72, "i32.xor": 0x73,
    "i32.shl": 0x74, "i32.shr_s": 0x75, "i32.shr_u": 0x76,
}
MEMOPS = {"i32.load": 0x28, "i32.load8_s": 0x2C, "i32.load8_u": 0x2D, "i32.load16_s": 0x2E, "i32.load16_u": 0x2F,
          "i32.store": 0x36, "i32.store8": 0x3A, "i32.store16": 0x3B}
LEBOPS = {"br": 0x0C, "br_if": 0x0D, "local.get": 0x20, "local.set": 0x21, "local.tee": 0x22}
BLOCKS = {"block": 0x02, "loop": 0x03, "if": 0x04}


class Module:
    def __init__(self, memory_pages=1):
        self.types = []
        self.imports = []   # (module, name, type_idx)
        self.funcs = []     # (type_idx, nlocals_extra, body)
        self.exports = []
        self.data = []      # (offset, bytes)
        self.memory_pages = memory_pages
        self.names = {}

    def type(self, np, nr):
        t = (np, nr)
        if t not in self.types:
            self.types.append(t)
        return self.types.index(t)

    def import_func(self, name, np, nr, module="qs"):
        self.names[name] = len(self.imports)
        self.imports.append((module, name, self.type(np, nr)))

    def func(self, name, np, nr, nlocals, asm, export=None):
        idx = len(self.imports) + len(self.funcs)
        self.names[name] = idx
        self.funcs.append((self.type(np, nr), nlocals, asm))
        if export:
            self.exports.append((export, idx))
        return idx

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
                out.append(BLOCKS[m]); out.append(0x7F if len(parts) > 1 and parts[1] == "i32" else 0x40)
            elif m == "i32.const":
                out.append(0x41); out += sleb(int(parts[1], 0))
            elif m == "call":
                t = parts[1]
                idx = self.names[t[1:]] if t.startswith("$") else int(t)
                out.append(0x10); out += uleb(idx)
            elif m in MEMOPS:
                off = int(parts[1]) if len(parts) > 1 else 0
                out.append(MEMOPS[m]); out += uleb(2); out += uleb(off)
            elif m == "memory.size":
                out += b"\x3f\x00"
            elif m == "memory.grow":
                out += b"\x40\x00"
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
        out = b"\0asm\x01\x00\x00\x00"
        out += sec(1, vec([b"\x60" + uleb(np) + b"\x7f" * np + uleb(nr) + b"\x7f" * nr for np, nr in self.types]))
        if self.imports:
            out += sec(2, vec([uleb(len(m)) + m.encode() + uleb(len(n)) + n.encode() + b"\x00" + uleb(t)
                               for m, n, t in self.imports]))
        out += sec(3, vec([uleb(t) for t, _, _ in self.funcs]))
        out += sec(5, b"\x01\x00" + uleb(self.memory_pages))
        out += sec(7, vec([uleb(len(n)) + n.encode() + b"\x00" + uleb(i) for n, i in self.exports]))
        bodies = []
        for t, nl, asm in self.funcs:
            code = (uleb(1) + uleb(nl) + b"\x7f" if nl else uleb(0)) + self.assemble(asm)
            bodies.append(uleb(len(code)) + code)
        out += sec(10, vec(bodies))
        if self.data:
            out += sec(11, vec([b"\x00\x41" + sleb(o) + b"\x0b" + uleb(len(b)) + b for o, b in self.data]))
        return out
