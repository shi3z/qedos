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
    // memory.grow, float const, call_indirect, br_table, global.get
    for body in [&[0x41, 1, 0x40, 0, 0x0b][..], &[0x43, 0, 0, 0, 0, 0x0b], &[0x11, 0, 0, 0x0b], &[0x0e, 0, 0, 0x0b], &[0x23, 0, 0x0b]] {
        assert!(Module::parse(&build(body, 0, &[])).is_err(), "{body:?}");
    }
    // unbalanced / trailing garbage
    assert!(Module::parse(&build(&[0x41, 0, 0x0b, 0x0b], 0, &[])).is_err());
    assert!(Module::parse(&build(&[0x02, 0x40, 0x41, 0, 0x0b], 0, &[])).is_err());
    assert!(Module::parse(&build(&[0x0c, 5, 0x41, 0, 0x0b], 0, &[])).is_err(), "branch depth");
    assert!(Module::parse(&build(&[0x20, 3, 0x0b], 0, &[])).is_err(), "local index");
    assert!(Module::parse(&build(&[0x10, 9, 0x0b], 0, &[])).is_err(), "call index");
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

/// Fuzz: random instruction streams. Whatever the loader accepts must execute without panicking,
/// stay within fuel, and never touch bytes outside the instance's memory (guard canaries).
#[test]
fn fuzz_random_programs_stay_confined() {
    let alphabet: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x1a, 0x1b, 0x20, 0x21, 0x22, 0x28, 0x2d, 0x36, 0x3a,
        0x3f, 0x41, 0x45, 0x46, 0x48, 0x4f, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x74, 0x75, 0x76,
    ];
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let (mut loaded, mut ran_ok, mut trapped) = (0u32, 0u32, 0u32);
    for _ in 0..60_000 {
        let n = 1 + (rng.next() % 40) as usize;
        let mut body = Vec::new();
        for _ in 0..n {
            let op = alphabet[(rng.next() % alphabet.len() as u64) as usize];
            body.push(op);
            // plausible immediates
            match op {
                0x02 | 0x03 | 0x04 => body.push(if rng.next() % 2 == 0 { 0x40 } else { 0x7f }),
                0x0c | 0x0d | 0x10 | 0x20 | 0x21 | 0x22 => body.push((rng.next() % 4) as u8),
                0x28 | 0x2d | 0x36 | 0x3a => {
                    body.push(2);
                    body.push((rng.next() % 3) as u8 * 100)
                }
                0x3f => body.push(0),
                0x41 => {
                    let v = rng.next();
                    match v % 4 {
                        0 => body.push((v >> 8) as u8 & 0x3f),
                        1 => body.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x07]),
                        2 => body.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x78]),
                        _ => body.extend_from_slice(&[0xfc, 0xff, 0x03]),
                    }
                }
                _ => {}
            }
        }
        body.push(0x0b);
        let wasm = build(&body, 2, &[]);
        let module = match Module::parse(&wasm) {
            Ok(m) => m,
            Err(_) => continue,
        };
        loaded += 1;
        // memory sits between two guard regions
        let mut region = std::vec![0xA5u8; 65536 + 2 * 256];
        let (guard_lo, rest) = region.split_at_mut(256);
        let (mem, guard_hi) = rest.split_at_mut(65536);
        let l = Limits { max_fuel: 5000, ..limits() };
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
    }
    std::eprintln!("fuzz: loaded={loaded} ok={ran_ok} trapped={trapped}");
    assert!(loaded > 1000 && ran_ok > 50 && trapped > 50, "fuzzer should reach both outcomes");
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
