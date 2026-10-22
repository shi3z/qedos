#!/usr/bin/env node
// Reference engine for differential testing: V8's WebAssembly implementation (independent of qedos).
//   node tests/v8_ref.js <cases.bin> <ours.txt>   -> one line per case on stdout:  "<idx> <result>"
// cases.bin frames: [cat:u8][len:u32le][module bytes]...; ours.txt: the interpreter's lines (used only to skip
// cases our interpreter stopped by a resource limit, where V8 could legitimately run much longer).
// Result grammar (identical to `qs diff-run`):
//   reject | reject-link | ok <i32> mem=<pages>:<hash8> g=<hex,..> | trap <Kind> mem=.. g=.. | res | skip
'use strict';
const fs = require('fs');
const vm = require('vm');
const [,, casesPath, oursPath] = process.argv;
const buf = fs.readFileSync(casesPath);
const ours = fs.readFileSync(oursPath, 'utf8').split('\n');
const oursByIdx = new Map();
for (const l of ours) { const i = l.indexOf(' '); if (i > 0) oursByIdx.set(l.slice(0, i), l.slice(i + 1)); }

function memHash(mem) {
  if (!(mem instanceof WebAssembly.Memory)) return 'nomem';
  const u8 = new Uint8Array(mem.buffer);
  let h = 0x811C9DC5 | 0;
  for (let i = 0; i < u8.length; i++) {
    const b = u8[i];
    if (b !== 0) h = (Math.imul(h ^ (i + 1), 0x9E3779B1) + b) | 0;
  }
  return `${u8.length / 65536}:${(h >>> 0).toString(16).padStart(8, '0')}`;
}
function trapKind(e) {
  const m = String(e && e.message || e);
  if (e instanceof RangeError) return 'res';
  if (/unreachable/.test(m)) return 'Unreachable';
  if (/divide by zero|remainder by zero/.test(m)) return 'DivByZero';
  if (/unrepresentable|integer overflow/.test(m)) return 'IntOverflow';
  if (/out of bounds/.test(m) && /table/.test(m)) return 'IndirectCall';
  if (/memory access out of bounds|data segment|out of bounds/.test(m)) return 'OutOfBounds';
  if (/null function|signature mismatch|indirect/.test(m)) return 'IndirectCall';
  return 'Other(' + m.slice(0, 60) + ')';
}
function globalsOf(inst) {
  const out = [];
  for (let i = 0; ; i++) {
    const g = inst.exports['g' + i];
    if (!g) break;
    const v = g.value;
    out.push(typeof v === 'bigint' ? BigInt.asUintN(64, v).toString(16) : (v >>> 0).toString(16));
  }
  return 'g=' + out.join(',');
}

let p = 0, idx = 0;
const lines = [];
while (p < buf.length) {
  const len = buf.readUInt32LE(p + 1);
  const bytes = buf.subarray(p + 5, p + 5 + len);
  p += 5 + len;
  const o = oursByIdx.get(String(idx)) || '';
  let res;
  let mod = null;
  try { mod = new WebAssembly.Module(bytes); } catch (e) { res = 'reject'; }
  if (mod) {
    if (o.startsWith('res')) res = 'skip';
    else if (o.startsWith('reject')) res = 'accepted-unrun';   // V8 accepts; never execute what our loader refused (may not terminate)
    else {
      let inst = null;
      try { inst = new WebAssembly.Instance(mod, {}); } catch (e) {
        res = /out of bounds|data segment|segment/i.test(String(e.message)) ? 'reject-link' : 'reject-link';
      }
      if (inst) {
        const mem = inst.exports.memory;
        try {
          // vm timeout interrupts a runaway wasm loop (a divergence from our interpreter would otherwise hang the run)
          const r = vm.runInNewContext('inst.exports.handle()', { inst }, { timeout: 3000 });
          res = `ok ${r | 0} mem=${memHash(mem)} ${globalsOf(inst)}`;
        } catch (e) {
          const k = (e && e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') ? 'TIMEOUT' : trapKind(e);
          res = k === 'res' ? 'res' : k === 'TIMEOUT' ? 'timeout' : `trap ${k} mem=${memHash(mem)} ${globalsOf(inst)}`;
        }
      }
    }
  }
  lines.push(`${idx} ${res}`);
  idx++;
}
process.stdout.write(lines.join('\n') + '\n');
