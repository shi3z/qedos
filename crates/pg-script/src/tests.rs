use super::wasm::*;
use super::*;
use pg_script_policy::{Kv, Limits, Policy};
use std::vec::Vec;

const HELLO_WASM: &[u8] = include_bytes!("../../../examples/hello/app.wasm");
const HELLO_POL: &[u8] = include_bytes!("../../../examples/hello/app.policy");
const ECHO_WASM: &[u8] = include_bytes!("../../../examples/json-echo/app.wasm");
const ECHO_POL: &[u8] = include_bytes!("../../../examples/json-echo/app.policy");

fn uleb(mut n: u32, o: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            o.push(b);
            return;
        }
        o.push(b | 0x80);
    }
}
fn sec(id: u8, body: &[u8], o: &mut Vec<u8>) {
    o.push(id);
    uleb(body.len() as u32, o);
    o.extend_from_slice(body);
}

/// Minimal module: `handle() -> i32` with `body` (instruction bytes incl. final end), one page of memory,
/// optional imports `(name, nparams, nresults)` from module "qs".
fn build(body: &[u8], nlocals: u8, imports: &[(&str, u8, u8)]) -> Vec<u8> {
    let mut m = std::vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    let mut types = std::vec![1 + imports.len() as u8];
    types.extend_from_slice(&[0x60, 0, 1, 0x7f]);
    for (_, p, r) in imports {
        types.extend_from_slice(&[0x60, *p]);
        types.extend(core::iter::repeat(0x7f).take(*p as usize));
        types.push(*r);
        if *r == 1 {
            types.push(0x7f);
        }
    }
    sec(1, &types, &mut m);
    if !imports.is_empty() {
        let mut im = std::vec![imports.len() as u8];
        for (i, (n, _, _)) in imports.iter().enumerate() {
            im.extend_from_slice(&[2, b'q', b's', n.len() as u8]);
            im.extend_from_slice(n.as_bytes());
            im.extend_from_slice(&[0, (i + 1) as u8]);
        }
        sec(2, &im, &mut m);
    }
    sec(3, &[1, 0], &mut m);
    sec(5, &[1, 0, 1], &mut m);
    let idx = imports.len() as u8;
    let mut ex = std::vec![1, 6];
    ex.extend_from_slice(b"handle");
    ex.extend_from_slice(&[0, idx]);
    sec(7, &ex, &mut m);
    let mut code = std::vec::Vec::new();
    if nlocals > 0 {
        code.extend_from_slice(&[1, nlocals, 0x7f]);
    } else {
        code.push(0);
    }
    code.extend_from_slice(body);
    let mut cs = std::vec![1];
    uleb(code.len() as u32, &mut cs);
    cs.extend_from_slice(&code);
    sec(10, &cs, &mut m);
    m
}

fn limits() -> Limits {
    Limits {
        max_memory_bytes: 65536,
        max_fuel: 100_000,
        max_stack_depth: 8,
        max_request_bytes: 4096,
        max_response_bytes: 1024,
        max_host_calls: 100,
        max_exec_us: 1_000_000,
    }
}

struct NullHost;
impl Host for NullHost {
    fn call(&mut self, _id: u8, _a: &[i32], _m: &mut Memory<'_>) -> Result<Option<i32>, Trap> {
        Ok(Some(0))
    }
}

fn run_bytes(wasm: &[u8], mem: &mut [u8], l: Limits) -> Result<Result<i32, Trap>, LoadError> {
    let m = Module::parse(wasm)?;
    let mut inst = Instance::new(&m, mem, l, |_, _, _| Some(0))?;
    Ok(inst.call_handle(&mut NullHost))
}

#[test]
fn leb_u32_canonical() {
    assert_eq!(leb_u32(&[0x7f], 0), Some((127, 1)));
    assert_eq!(leb_u32(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0), Some((u32::MAX, 5)));
    assert_eq!(leb_u32(&[0xff, 0xff, 0xff, 0xff, 0x1f], 0), None, "bits above 32");
    assert_eq!(leb_u32(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 0), None, "6 bytes");
    assert_eq!(leb_u32(&[0x80], 0), None, "truncated");
}

#[test]
fn leb_i32_edges() {
    assert_eq!(leb_i32(&[0x7f], 0), Some((-1, 1)));
    assert_eq!(leb_i32(&[0x80, 0x80, 0x80, 0x80, 0x78], 0), Some((i32::MIN, 5)));
    assert_eq!(leb_i32(&[0xff, 0xff, 0xff, 0xff, 0x07], 0), Some((i32::MAX, 5)));
    assert_eq!(leb_i32(&[0xff, 0xff, 0xff, 0xff, 0x17], 0), None, "non sign-extended high bits");
    assert_eq!(leb_i32(&[0x80, 0x80, 0x80, 0x80, 0x80], 0), None);
}

#[test]
fn checked_range_never_admits_out_of_bounds() {
    let vals = [0u32, 1, 2, 3, 4, 255, 65531, 65532, 65533, 65535, 65536, 0x7fff_ffff, 0x8000_0000, 0xffff_fffc, 0xffff_ffff];
    for len in [0usize, 1, 4, 65536, 1 << 20] {
        for &b in &vals {
            for &o in &vals {
                for sz in [1u32, 2, 4] {
                    match checked_range(len, b, o, sz) {
                        Some(s) => assert!(s as u64 + sz as u64 <= len as u64 && s as u64 == b as u64 + o as u64),
                        None => assert!(b as u64 + o as u64 + sz as u64 > len as u64),
                    }
                }
            }
        }
    }
}

#[test]
fn basic_arithmetic_and_control() {
    // (2+3)*4 == 20; if/else; loop sum 1..=10
    let b = [0x41, 2, 0x41, 3, 0x6a, 0x41, 4, 0x6c, 0x0b];
    let mut mem = [0u8; 65536];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(20));
    // local0 = 0; local1 = 10; block loop (br_if 1 (local1==0)); local0 += local1; local1 -= 1; br 0 end end; local0
    let b = [
        0x41, 10, 0x21, 1, 0x02, 0x40, 0x03, 0x40, 0x20, 1, 0x45, 0x0d, 1, 0x20, 0, 0x20, 1, 0x6a, 0x21, 0, 0x20, 1,
        0x41, 1, 0x6b, 0x21, 1, 0x0c, 0, 0x0b, 0x0b, 0x20, 0, 0x0b,
    ];
    assert_eq!(run_bytes(&build(&b, 2, &[]), &mut mem, limits()).unwrap(), Ok(55));
    // if/else with result
    let b = [0x41, 1, 0x04, 0x7f, 0x41, 7, 0x05, 0x41, 9, 0x0b, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(7));
    let b = [0x41, 0, 0x04, 0x7f, 0x41, 7, 0x05, 0x41, 9, 0x0b, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(9));
}

#[test]
fn fuel_is_exact_and_bounds_infinite_loops() {
    let b = [0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b];
    let mut mem = [0u8; 65536];
    let m_bytes = build(&b, 0, &[]);
    let m = Module::parse(&m_bytes).unwrap();
    let l = Limits { max_fuel: 1000, ..limits() };
    let mut inst = Instance::new(&m, &mut mem, l, |_, _, _| Some(0)).unwrap();
    assert_eq!(inst.call_handle(&mut NullHost), Err(Trap::OutOfFuel));
    assert_eq!(inst.fuel_used(), 1000);
}

#[test]
fn memory_ops_trap_out_of_bounds_and_never_wrap() {
    let mut mem = [0u8; 65536];
    for addr in [65533i32, 65535, 65536, -1, -4, i32::MIN] {
        let mut b = std::vec![0x41];
        b.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x78]); // placeholder replaced below
        b.clear();
        // i32.const addr (signed LEB via simple encoder)
        b.push(0x41);
        let mut v = addr as i64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
                b.push(byte);
                break;
            }
            b.push(byte | 0x80);
        }
        b.extend_from_slice(&[0x28, 2, 0, 0x0b]); // i32.load; end  (value left on stack as result)
        assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Err(Trap::OutOfBounds), "addr {addr}");
    }
    // offset immediate near u32::MAX with base 0 / base 1: must trap, not wrap
    let b = [0x41, 1, 0x28, 2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Err(Trap::OutOfBounds));
    // last valid word
    let b = [0x41, 0xfc, 0xff, 0x03, 0x28, 2, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(0));
}

#[test]
fn rejects_unsupported_constructs() {
    // f32.const, f64.const, ref.null, table.get, SIMD prefix, atomics prefix, memory.init, tail call,
    // call_indirect without a table, global.get without globals, br_table with a missing operand
    for body in [
        &[0x43, 0, 0, 0, 0, 0x0b][..],
        &[0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b],
        &[0xd0, 0x70, 0x0b],
        &[0x25, 0, 0x0b],
        &[0xfd, 0x0c, 0x0b],
        &[0xfe, 0x00, 0x0b],
        &[0xfc, 0x08, 0, 0, 0x0b],
        &[0x12, 0, 0x0b],
        &[0x41, 0, 0x11, 0, 0, 0x0b],
        &[0x23, 0, 0x0b],
        &[0x0e, 0, 0, 0x0b],
    ] {
        assert!(Module::parse(&build(body, 0, &[])).is_err(), "{body:?}");
    }
    // unbalanced / trailing garbage
    assert!(Module::parse(&build(&[0x41, 0, 0x0b, 0x0b], 0, &[])).is_err());
    assert!(Module::parse(&build(&[0x02, 0x40, 0x41, 0, 0x0b], 0, &[])).is_err());
    assert!(Module::parse(&build(&[0x0c, 5, 0x41, 0, 0x0b], 0, &[])).is_err(), "branch depth");
    assert!(Module::parse(&build(&[0x20, 3, 0x0b], 0, &[])).is_err(), "local index");
    assert!(Module::parse(&build(&[0x10, 9, 0x0b], 0, &[])).is_err(), "call index");
}

/// The validator is a real type checker: operand-type confusion, stack underflow, missing results and
/// over-aligned accesses are all load-time errors (not run-time surprises).
#[test]
fn validator_rejects_type_errors() {
    let bad: &[(&str, &[u8])] = &[
        ("i64 where i32 expected", &[0x42, 1, 0x41, 1, 0x6a, 0x0b]),
        ("i32 result expected, none left", &[0x0b]),
        ("extra value left on stack", &[0x41, 1, 0x41, 2, 0x0b]),
        ("underflow", &[0x6a, 0x0b]),
        ("if with result and no else", &[0x41, 1, 0x04, 0x7f, 0x41, 1, 0x0b, 0x0b]),
        ("if/else result mismatch", &[0x41, 1, 0x04, 0x7f, 0x41, 1, 0x05, 0x42, 1, 0x0b, 0x0b]),
        ("br value type", &[0x02, 0x7f, 0x42, 1, 0x0c, 0, 0x0b, 0x0b]),
        ("select operand mismatch", &[0x41, 1, 0x42, 2, 0x41, 0, 0x1b, 0x0b]),
        ("load over-aligned (8-bit load, align 2)", &[0x41, 0, 0x2d, 2, 0, 0x0b]),
        ("i64.store with i32 value", &[0x41, 0, 0x41, 1, 0x37, 3, 0, 0x41, 0, 0x0b]),
        ("local.set type", &[0x42, 1, 0x21, 0, 0x41, 0, 0x0b]),
    ];
    for (why, body) in bad {
        assert!(Module::parse(&build(body, 1, &[])).is_err(), "should reject: {why}");
    }
    let good: &[&[u8]] = &[
        &[0x42, 5, 0x42, 7, 0x7c, 0xa7, 0x0b],                               // i32.wrap(i64.add)
        &[0x41, 1, 0x04, 0x7f, 0x41, 7, 0x05, 0x41, 9, 0x0b, 0x0b],           // if/else result
        &[0x00, 0x0b],                                                        // unreachable is polymorphic
        &[0x02, 0x7f, 0x41, 3, 0x0c, 0, 0x0b, 0x0b],                          // br with value
        &[0x41, 0, 0x2d, 0, 0, 0x0b],                                         // natural alignment
    ];
    for body in good {
        Module::parse(&build(body, 1, &[])).unwrap_or_else(|e| panic!("should accept {body:?}: {e:?}"));
    }
}

#[test]
fn i64_arithmetic_conversions_and_sign_extension() {
    let mut mem = [0u8; 65536];
    let run = |body: &[u8], mem: &mut [u8]| run_bytes(&build(body, 0, &[]), mem, limits()).unwrap();
    // (1<<40) >> 32 == 256, via i64 ops then wrap
    assert_eq!(run(&[0x42, 1, 0x42, 40, 0x86, 0x42, 32, 0x88, 0xa7, 0x0b], &mut mem), Ok(256));
    // i64.extend_i32_s(-1) == -1 ; i64.extend_i32_u(-1) == 0xffffffff ; compare via i64.eq-free wrap/shift
    assert_eq!(run(&[0x41, 0x7f, 0xac, 0x42, 32, 0x88, 0xa7, 0x0b], &mut mem), Ok(-1));
    assert_eq!(run(&[0x41, 0x7f, 0xad, 0x42, 32, 0x88, 0xa7, 0x0b], &mut mem), Ok(0));
    // sign extension: i32.extend8_s(0x80) == -128 ; i64.extend32_s(0x80000000) < 0
    assert_eq!(run(&[0x41, 0x80, 0x01, 0xc0, 0x0b], &mut mem), Ok(-128));
    assert_eq!(run(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x08, 0xc4, 0x42, 0, 0x53, 0x0b], &mut mem), Ok(1));
    // clz/ctz/popcnt/rotl
    assert_eq!(run(&[0x41, 1, 0x67, 0x0b], &mut mem), Ok(31));
    assert_eq!(run(&[0x42, 8, 0x7a, 0xa7, 0x0b], &mut mem), Ok(3));
    assert_eq!(run(&[0x41, 0x7f, 0x69, 0x0b], &mut mem), Ok(32));
    assert_eq!(run(&[0x41, 0x81, 0x80, 0x80, 0x80, 0x78, 0x41, 4, 0x77, 0x0b], &mut mem), Ok(0x18));
    // i64 division traps
    assert_eq!(run(&[0x42, 1, 0x42, 0, 0x7f, 0xa7, 0x0b], &mut mem), Err(Trap::DivByZero));
    assert_eq!(run(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f, 0x42, 0x7f, 0x7f, 0xa7, 0x0b], &mut mem), Err(Trap::IntOverflow));
    // i64 memory round trip incl. a 32-bit zero-extending load
    let b = [0x41, 8, 0x42, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x37, 3, 0, 0x41, 8, 0x35, 2, 0, 0x42, 32, 0x88, 0xa7, 0x0b];
    assert_eq!(run(&b, &mut mem), Ok(0));
}

#[test]
fn br_table_selects_target_and_defaults() {
    // block block block (br_table 0 1 2 default=2 on local0) ... each exit returns a distinct value
    // (func param is not available for handle, so the selector is a constant per run)
    let mut mem = [0u8; 65536];
    for (sel, want) in [(0u8, 10), (1, 20), (2, 30), (3, 30), (100, 30)] {
        let b = [
            0x02, 0x40, 0x02, 0x40, 0x02, 0x40, 0x41, sel, 0x0e, 2, 0, 1, 2, 0x0b, // innermost: br_table
            0x41, 10, 0x0f, 0x0b, 0x41, 20, 0x0f, 0x0b, 0x41, 30, 0x0b,
        ];
        assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(want), "sel {sel}");
    }
}

#[test]
fn globals_are_per_instance_and_immutables_cannot_be_set() {
    // global 0: mut i32 = 5 ; handle: global.set 0 (global.get 0 + 1) ; global.get 0
    let mk = |mutable: u8| {
        let mut m = std::vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
        sec(1, &[1, 0x60, 0, 1, 0x7f], &mut m);
        sec(3, &[1, 0], &mut m);
        sec(5, &[1, 0, 1], &mut m);
        sec(6, &[1, 0x7f, mutable, 0x41, 5, 0x0b], &mut m);
        let mut ex = std::vec![1, 6];
        ex.extend_from_slice(b"handle");
        ex.extend_from_slice(&[0, 0]);
        sec(7, &ex, &mut m);
        let f = [0u8, 0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x23, 0, 0x0b];
        let mut cs = std::vec![1, f.len() as u8];
        cs.extend_from_slice(&f);
        sec(10, &cs, &mut m);
        m
    };
    let mut mem = [0u8; 65536];
    let m = mk(1);
    // fresh instance every time: always 6, never 7 (LAW_019)
    assert_eq!(run_bytes(&m, &mut mem, limits()).unwrap(), Ok(6));
    assert_eq!(run_bytes(&m, &mut mem, limits()).unwrap(), Ok(6));
    assert!(Module::parse(&mk(0)).is_err(), "global.set on an immutable global");
}

#[test]
fn memory_grow_is_bounded_and_zeroed() {
    let mut mem = std::vec![0xEEu8; 4 * 65536];
    // memory.grow(1) returns old size (1); the new page reads as zero even though the scratch was dirty
    let b = [0x41, 1, 0x40, 0, 0x1a, 0x41, 0x80, 0x80, 0x04, 0x28, 2, 0, 0x0b];
    let l = Limits { max_memory_bytes: 3 * 65536, ..limits() };
    // declared memory has no max => hard cap, then Limits cap (3 pages) applies
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, l).unwrap(), Ok(0));
    // growing past the policy limit fails with -1 (not a trap)
    let b = [0x41, 5, 0x40, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, l).unwrap(), Ok(-1));
    // after the instance is dropped the grown region is scrubbed again
    assert!(mem.iter().take(3 * 65536).all(|b| *b == 0 || *b == 0xEE));
    let b = [0x41, 2, 0x40, 0, 0x1a, 0x41, 0x80, 0x80, 0x08, 0x41, 0x7b, 0x36, 2, 0, 0x41, 0, 0x0b];
    let _ = run_bytes(&build(&b, 0, &[]), &mut mem, l);
    assert!(mem[65536..3 * 65536].iter().all(|b| *b != 0x7b), "grown pages are scrubbed on drop");
}

#[test]
fn bulk_memory_copy_and_fill() {
    let mut mem = [0u8; 65536];
    // fill [16,16+8) with 0xAB, copy 8 bytes 16 -> 20 (overlapping), read word at 20
    let b = [
        0x41, 16, 0x41, 0xab, 0x01, 0x41, 8, 0xfc, 0x0b, 0, 0x41, 20, 0x41, 16, 0x41, 8, 0xfc, 0x0a, 0, 0, 0x41, 20, 0x28, 2, 0, 0x0b,
    ];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(0xABABABABu32 as i32));
    // out-of-range copy/fill trap even when only the far end is outside
    let b = [0x41, 0xfc, 0xff, 0x03, 0x41, 0, 0x41, 8, 0xfc, 0x0b, 0, 0x41, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Err(Trap::OutOfBounds));
    let b = [0x41, 0, 0x41, 0xfc, 0xff, 0x03, 0x41, 8, 0xfc, 0x0a, 0, 0, 0x41, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Err(Trap::OutOfBounds));
    // zero-length at the very end is fine; one past the end is not
    let b = [0x41, 0x80, 0x80, 0x04, 0x41, 0, 0x41, 0, 0xfc, 0x0b, 0, 0x41, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Ok(0));
    let b = [0x41, 0x81, 0x80, 0x04, 0x41, 0, 0x41, 0, 0xfc, 0x0b, 0, 0x41, 0, 0x0b];
    assert_eq!(run_bytes(&build(&b, 0, &[]), &mut mem, limits()).unwrap(), Err(Trap::OutOfBounds));
}

/// Module with a 4-slot table [f1, f2, f3, f4]; handle calls table[sel] with type `() -> i32`.
/// f3 optionally has a different signature `(i32) -> i32` to exercise the structural type check.
fn indirect_module(sel: u8, third_type_ok: bool) -> Vec<u8> {
    let mut m = std::vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    sec(1, &[2, 0x60, 0, 1, 0x7f, 0x60, 1, 0x7f, 1, 0x7f], &mut m);
    sec(3, &[5, 0, 0, 0, if third_type_ok { 0 } else { 1 }, 0], &mut m);
    sec(4, &[1, 0x70, 0, 4], &mut m);
    sec(5, &[1, 0, 1], &mut m);
    let mut ex = std::vec![1, 6];
    ex.extend_from_slice(b"handle");
    ex.extend_from_slice(&[0, 0]);
    sec(7, &ex, &mut m);
    sec(9, &[1, 0, 0x41, 0, 0x0b, 4, 1, 2, 3, 4], &mut m); // slots 0..3 = funcs 1,2,3,4 (own idx space)
    let mut f0 = std::vec![0u8, 0x41];
    sleb(sel as i64, &mut f0);
    f0.extend_from_slice(&[0x11, 0, 0, 0x0b]);
    let f1 = [0u8, 0x41, 11, 0x0b];
    let f2 = [0u8, 0x41, 22, 0x0b];
    let f3: &[u8] = if third_type_ok { &[0, 0x41, 33, 0x0b] } else { &[0, 0x20, 0, 0x0b] };
    let f4 = [0u8, 0x41, 44, 0x0b];
    let mut cs = std::vec![5];
    for f in [&f0[..], &f1[..], &f2[..], f3, &f4[..]] {
        cs.push(f.len() as u8);
        cs.extend_from_slice(f);
    }
    sec(10, &cs, &mut m);
    m
}

#[test]
fn call_indirect_dispatch_and_traps() {
    let mut mem = [0u8; 65536];
    for (sel, want) in [(0u8, Ok(11)), (1, Ok(22)), (3, Ok(44)), (4, Err(Trap::IndirectCall)), (200, Err(Trap::IndirectCall))] {
        assert_eq!(run_bytes(&indirect_module(sel, true), &mut mem, limits()).unwrap(), want, "slot {sel}");
    }
    // slot 2 holds a function with a different signature: structural type check traps
    assert_eq!(run_bytes(&indirect_module(2, false), &mut mem, limits()).unwrap(), Err(Trap::IndirectCall));
}

#[test]
fn recursion_is_bounded_by_depth_limit() {
    // two functions: handle calls f1; f1 calls f1
    let mut m = std::vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    sec(1, &[2, 0x60, 0, 1, 0x7f, 0x60, 0, 0], &mut m);
    sec(3, &[2, 0, 1], &mut m);
    sec(5, &[1, 0, 1], &mut m);
    let mut ex = std::vec![1, 6];
    ex.extend_from_slice(b"handle");
    ex.extend_from_slice(&[0, 0]);
    sec(7, &ex, &mut m);
    let f0 = [0u8, 0x10, 1, 0x41, 0, 0x0b];
    let f1 = [0u8, 0x10, 1, 0x0b];
    let mut cs = std::vec![2, f0.len() as u8];
    cs.extend_from_slice(&f0);
    cs.push(f1.len() as u8);
    cs.extend_from_slice(&f1);
    sec(10, &cs, &mut m);
    let mut mem = [0u8; 65536];
    assert_eq!(run_bytes(&m, &mut mem, limits()).unwrap(), Err(Trap::CallDepth));
    let l = Limits { max_stack_depth: 2, ..limits() };
    assert_eq!(run_bytes(&m, &mut mem, l).unwrap(), Err(Trap::CallDepth));
}

#[test]
fn memory_declaration_respects_limits() {
    let m = build(&[0x41, 0, 0x0b], 0, &[]);
    let mut mem = [0u8; 65536];
    let l = Limits { max_memory_bytes: 1024, ..limits() };
    assert!(matches!(run_bytes(&m, &mut mem, l), Err(LoadError::MemoryTooLarge)));
    let mut small = [0u8; 100];
    assert!(matches!(run_bytes(&m, &mut small, limits()), Err(LoadError::MemoryTooLarge)));
}

#[test]
fn unresolved_import_fails_link() {
    let m = build(&[0x41, 0, 0x0b], 0, &[("evil", 0, 0)]);
    let module = Module::parse(&m).unwrap();
    let mut mem = [0u8; 65536];
    let r = Instance::new(&module, &mut mem, limits(), |_, _, _| None);
    assert!(matches!(r, Err(LoadError::UnresolvedImport)));
}

fn req<'a>(path: &'a [u8], body: &'a [u8], principal: u32) -> Request<'a> {
    Request {
        method: if body.is_empty() { Method::Get } else { Method::Post },
        path,
        query: b"",
        content_type: b"",
        user_agent: b"",
        body,
        principal,
    }
}

#[test]
fn hello_example_returns_expected_body() {
    let m = Module::parse(HELLO_WASM).unwrap();
    let p = Policy::parse(HELLO_POL).unwrap();
    let mut kv = Kv::new();
    let (mut mem, mut out) = ([0u8; 65536], [0u8; 4096]);
    let o = execute(&m, &p, &req(b"/script/hello", b"", 0), &mut kv, &mut mem, &mut out, NoClock);
    assert_eq!((o.status, o.reason), (200, Reason::Ok));
    assert_eq!(&out[..o.body_len], br#"{"message":"Hello from QEDOS"}"#);
}

#[test]
fn json_echo_transforms_post_body() {
    let m = Module::parse(ECHO_WASM).unwrap();
    let p = Policy::parse(ECHO_POL).unwrap();
    let mut kv = Kv::new();
    let (mut mem, mut out) = ([0u8; 65536], [0u8; 8192]);
    let o = execute(&m, &p, &req(b"/script/echo", br#"{"a":"hi"}"#, 0), &mut kv, &mut mem, &mut out, NoClock);
    assert_eq!(o.status, 200);
    assert_eq!(&out[..o.body_len], br#"{"upper":"{_A_:_HI_}","length":10}"#);
}

#[test]
fn oversize_request_rejected_before_execution() {
    let m = Module::parse(HELLO_WASM).unwrap();
    let p = Policy::parse(HELLO_POL).unwrap();
    let mut kv = Kv::new();
    let (mut mem, mut out) = ([0u8; 65536], [0u8; 4096]);
    let big = [b'a'; 5000];
    let o = execute(&m, &p, &req(b"/", &big, 0), &mut kv, &mut mem, &mut out, NoClock);
    assert_eq!((o.status, o.reason, o.fuel_used), (413, Reason::RequestTooLarge, 0));
}

/// LAW_019: data one request leaves in linear memory / the output buffer is never visible to the next.
#[test]
fn no_state_survives_between_requests() {
    let m = Module::parse(ECHO_WASM).unwrap();
    let p = Policy::parse(ECHO_POL).unwrap();
    let mut kv = Kv::new();
    let (mut mem, mut out) = ([0u8; 65536], [0u8; 8192]);
    let o = execute(&m, &p, &req(b"/", b"TOP-SECRET-1234", 9), &mut kv, &mut mem, &mut out, NoClock);
    assert_eq!(o.status, 200);
    // after the instance dropped, scratch memory is scrubbed
    assert!(mem.iter().all(|b| *b == 0), "linear memory scrubbed on drop");
    // the next request starts from zeroed memory and a zeroed output buffer
    let o2 = execute(&m, &p, &req(b"/", b"", 0), &mut kv, &mut mem, &mut out, NoClock);
    assert_eq!(&out[..o2.body_len], br#"{"upper":"","length":0}"#);
    assert!(!out.windows(10).any(|w| w == b"TOP-SECRET"));
}

#[test]
fn concurrent_requests_do_not_interfere() {
    let m = Module::parse(ECHO_WASM).unwrap();
    let p = Policy::parse(ECHO_POL).unwrap();
    std::thread::scope(|s| {
        for t in 0..8u8 {
            let (m, p) = (&m, &p);
            s.spawn(move || {
                let mut kv = Kv::new();
                let (mut mem, mut out) = (std::vec![0u8; 65536], std::vec![0u8; 8192]);
                for i in 0..200u32 {
                    let body = std::format!("t{t}-{i}");
                    let o = execute(m, p, &req(b"/", body.as_bytes(), 0), &mut kv, &mut mem, &mut out, NoClock);
                    let want = std::format!(r#"{{"upper":"{}","length":{}}}"#, body.to_uppercase(), body.len());
                    assert_eq!(&out[..o.body_len], want.as_bytes());
                }
            });
        }
    });
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn sleb(mut v: i64, o: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
            o.push(byte);
            return;
        }
        o.push(byte | 0x80);
    }
}

/// Random *well-typed* expression of type i32 (`want64 == false`) or i64.
fn gen_expr(rng: &mut Rng, want64: bool, depth: u32, o: &mut Vec<u8>) {
    let pick = if depth == 0 { rng.next() % 2 } else { rng.next() % 11 };
    let big = |rng: &mut Rng| match rng.next() % 6 {
        0 => 0i64,
        1 => -1,
        2 => i64::MIN,
        3 => i64::MAX,
        4 => (rng.next() % 70000) as i64,
        _ => rng.next() as i64,
    };
    match pick {
        0 => {
            o.push(if want64 { 0x42 } else { 0x41 });
            let v = big(rng);
            sleb(if want64 { v } else { v as i32 as i64 }, o);
        }
        1 => {
            if want64 {
                o.push(0x42);
                sleb(big(rng), o);
            } else {
                o.extend_from_slice(&[0x20, (rng.next() % 2) as u8]);
            }
        }
        2..=4 => {
            // binary op of the wanted type
            gen_expr(rng, want64, depth - 1, o);
            gen_expr(rng, want64, depth - 1, o);
            let (lo, n) = if want64 { (0x7c, 15) } else { (0x6a, 15) };
            o.push(lo + (rng.next() % n) as u8);
        }
        5 => {
            // unary op
            gen_expr(rng, want64, depth - 1, o);
            o.push(if want64 { [0x79, 0x7a, 0x7b, 0xc2, 0xc3, 0xc4][(rng.next() % 6) as usize] } else { [0x67, 0x68, 0x69, 0xc0, 0xc1][(rng.next() % 5) as usize] });
        }
        6 => {
            // comparison (yields i32) possibly widened
            let w = rng.next() % 2 == 0;
            gen_expr(rng, w, depth - 1, o);
            if rng.next() % 5 != 0 {
                gen_expr(rng, w, depth - 1, o);
                o.push(if w { 0x51 + (rng.next() % 10) as u8 } else { 0x46 + (rng.next() % 10) as u8 });
            } else {
                o.push(if w { 0x50 } else { 0x45 });
            }
            if want64 {
                o.push(0xad);
            }
        }
        7 => {
            // load at a random (sometimes out-of-range) address
            o.push(0x41);
            sleb(match rng.next() % 4 { 0 => 65530, 1 => -1, _ => (rng.next() % 65000) as i64 }, o);
            if want64 {
                let (opc, al) = [(0x29u8, 3u8), (0x30, 0), (0x33, 1), (0x35, 2)][(rng.next() % 4) as usize];
                o.extend_from_slice(&[opc, al, (rng.next() % 8) as u8]);
            } else {
                let (opc, al) = [(0x28u8, 2u8), (0x2d, 0), (0x2e, 1)][(rng.next() % 3) as usize];
                o.extend_from_slice(&[opc, al, (rng.next() % 8) as u8]);
            }
        }
        8 => {
            // if/else with result
            gen_expr(rng, false, depth - 1, o);
            o.extend_from_slice(&[0x04, if want64 { 0x7e } else { 0x7f }]);
            gen_expr(rng, want64, depth - 1, o);
            o.push(0x05);
            gen_expr(rng, want64, depth - 1, o);
            o.push(0x0b);
        }
        9 => {
            gen_expr(rng, want64, depth - 1, o);
            gen_expr(rng, want64, depth - 1, o);
            gen_expr(rng, false, depth - 1, o);
            o.push(0x1b);
        }
        _ => {
            // conversion
            if want64 {
                gen_expr(rng, false, depth - 1, o);
                o.push(0xac + (rng.next() % 2) as u8);
            } else {
                gen_expr(rng, true, depth - 1, o);
                o.push(0xa7);
            }
        }
    }
}

/// Fuzz: random well-typed programs (loops, branches, stores, grows, bulk ops). Everything must load,
/// execute without panicking, stay within fuel, and never touch bytes outside the instance's memory.
#[test]
fn fuzz_random_programs_stay_confined() {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let (mut loaded, mut ran_ok, mut trapped) = (0u32, 0u32, 0u32);
    for _ in 0..30_000 {
        let mut body = Vec::new();
        for _ in 0..(1 + rng.next() % 5) {
            match rng.next() % 6 {
                0 => {
                    gen_expr(&mut rng, false, 3, &mut body);
                    body.extend_from_slice(&[0x21, (rng.next() % 2) as u8]);
                }
                1 => {
                    // store i32 / i64 at a random address
                    body.push(0x41);
                    sleb(match rng.next() % 3 { 0 => 65534, 1 => -4, _ => (rng.next() % 65000) as i64 }, &mut body);
                    if rng.next() % 2 == 0 {
                        gen_expr(&mut rng, false, 2, &mut body);
                        body.extend_from_slice(&[0x36, 2, 0]);
                    } else {
                        gen_expr(&mut rng, true, 2, &mut body);
                        body.extend_from_slice(&[0x37, 3, 0]);
                    }
                }
                2 => {
                    // bounded loop: local1 = n; loop { ...; local1 -= 1; br_if local1 }
                    body.extend_from_slice(&[0x41, (rng.next() % 20) as u8 + 1, 0x21, 1, 0x03, 0x40]);
                    gen_expr(&mut rng, false, 2, &mut body);
                    body.extend_from_slice(&[0x21, 0, 0x20, 1, 0x41, 1, 0x6b, 0x22, 1, 0x0d, 0]);
                    body.push(0x0b);
                }
                3 => {
                    // memory.grow + bulk fill/copy at random places
                    gen_expr(&mut rng, false, 1, &mut body);
                    body.extend_from_slice(&[0x41, 3, 0x71, 0x40, 0, 0x21, 0]);
                    for (d, v, n) in [(rng.next() % 70000, rng.next() % 256, rng.next() % 300)] {
                        body.push(0x41);
                        sleb(d as i64, &mut body);
                        body.push(0x41);
                        sleb(v as i64, &mut body);
                        body.push(0x41);
                        sleb(n as i64, &mut body);
                        body.extend_from_slice(&[0xfc, 0x0b, 0]);
                    }
                }
                4 => {
                    gen_expr(&mut rng, true, 3, &mut body);
                    body.push(0x1a);
                }
                _ => {
                    // br_table over nested blocks
                    body.extend_from_slice(&[0x02, 0x40, 0x02, 0x40]);
                    gen_expr(&mut rng, false, 2, &mut body);
                    body.extend_from_slice(&[0x0e, 2, 0, 1, 1, 0x0b, 0x0b]);
                }
            }
        }
        gen_expr(&mut rng, false, 3, &mut body);
        body.push(0x0b);
        let wasm = build(&body, 2, &[]);
        let module = Module::parse(&wasm).unwrap_or_else(|e| panic!("generator produced an invalid module ({e:?}): {body:?}"));
        loaded += 1;
        // memory sits between two guard regions
        let mut region = std::vec![0xA5u8; 4 * 65536 + 2 * 256];
        let (guard_lo, rest) = region.split_at_mut(256);
        let (mem, guard_hi) = rest.split_at_mut(4 * 65536);
        let l = Limits { max_fuel: 5000, max_memory_bytes: 4 * 65536, ..limits() };
        {
            let mut inst = Instance::new(&module, mem, l, |_, _, _| Some(0)).unwrap();
            let r = inst.call_handle(&mut NullHost);
            assert!(inst.fuel_used() <= 5000);
            match r {
                Ok(_) => ran_ok += 1,
                Err(_) => trapped += 1,
            }
        }
        assert!(guard_lo.iter().all(|b| *b == 0xA5), "write below memory: {body:?}");
        assert!(guard_hi.iter().all(|b| *b == 0xA5), "write above memory: {body:?}");
        assert!(mem.iter().all(|b| *b == 0 || *b == 0xA5), "scratch not scrubbed after the instance dropped: {body:?}");
    }
    std::eprintln!("fuzz: loaded={loaded} ok={ran_ok} trapped={trapped}");
    assert!(loaded == 30_000 && ran_ok > 1000 && trapped > 1000, "fuzzer should reach both outcomes");
}

/// Fuzz: random byte mutations of valid modules. The loader must never panic.
#[test]
fn fuzz_mutated_binaries_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for base in [HELLO_WASM, ECHO_WASM] {
        for _ in 0..30_000 {
            let mut w = base.to_vec();
            for _ in 0..(1 + rng.next() % 4) {
                let i = (rng.next() % w.len() as u64) as usize;
                match rng.next() % 3 {
                    0 => w[i] ^= 1 << (rng.next() % 8),
                    1 => w[i] = rng.next() as u8,
                    _ => {
                        let cut = (rng.next() % w.len() as u64) as usize;
                        w.truncate(cut.max(1));
                    }
                }
            }
            if let Ok(m) = Module::parse(&w) {
                let mut mem = std::vec![0u8; 65536];
                let r = Instance::new(&m, &mut mem, Limits { max_fuel: 3000, ..limits() }, |_, _, _| Some(0));
                if let Ok(mut inst) = r {
                    let _ = inst.call_handle(&mut NullHost);
                }
            }
        }
    }
}

struct JumpClock(u64);
impl Clock for JumpClock {
    fn elapsed_us(&mut self) -> u64 {
        self.0 += 1000;
        self.0
    }
}

#[test]
fn wall_clock_limit_stops_execution() {
    let wasm = build(&[0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b], 0, &[]);
    let m = Module::parse(&wasm).unwrap();
    let pol = std::string::String::from_utf8_lossy(HELLO_POL).replace("max_fuel = 10000", "max_fuel = 50000000").replace("max_exec_us = 10000", "max_exec_us = 5000");
    let p = Policy::parse(pol.as_bytes()).unwrap();
    let mut kv = Kv::new();
    let (mut mem, mut out) = ([0u8; 65536], [0u8; 4096]);
    let o = execute(&m, &p, &req(b"/", b"", 0), &mut kv, &mut mem, &mut out, JumpClock(0));
    assert_eq!((o.status, o.reason), (503, Reason::Trap(Trap::Timeout)));
    assert!(o.fuel_used < 5000, "stopped by the clock long before fuel ran out: {}", o.fuel_used);
}
