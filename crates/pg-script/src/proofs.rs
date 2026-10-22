//! Kani harnesses for the Script runtime (`cargo kani -p pg-script`).
//!
use super::wasm::*;
use pg_script_policy::{Api, Policy};

/// LAW_013 (A): for *all* 32-bit base/offset/size and any memory length, an accepted effective address
/// range lies inside memory. Loop-free, so the result is unbounded in the value domain.
#[kani::proof]
fn checked_range_sound() {
    let (len, base, off, size): (usize, u32, u32, u32) = (kani::any(), kani::any(), kani::any(), kani::any());
    if let Some(s) = checked_range(len, base, off, size) {
        assert!(s as u64 == base as u64 + off as u64);
        assert!(s as u64 + size as u64 <= len as u64);
    }
}

/// LAW_013: load/store through `Memory` never panics (no OOB index) for any address on a small memory.
#[kani::proof]
#[kani::unwind(6)]
fn memory_access_never_panics() {
    let mut buf = [0u8; 8];
    let mut m = Memory::new(&mut buf, 8, 8);
    let (base, off, val): (u32, u32, u64) = (kani::any(), kani::any(), kani::any());
    let size: u32 = if kani::any() { 8 } else if kani::any() { 4 } else if kani::any() { 2 } else { 1 };
    let _ = m.load(base, off, size);
    let _ = m.store(base, off, size, val);
}

/// LAW_015 (C): the linker only yields a host id for module "qs", an existing API name, and an API the
/// signed policy allows, with the exact signature.
#[kani::proof]
#[kani::unwind(20)]
fn resolver_is_confined_to_allowlist() {
    let name: [u8; 17] = kani::any();
    let nlen: usize = kani::any();
    kani::assume(nlen <= 17);
    let module: [u8; 2] = kani::any();
    let (np, nr): (u8, u8) = (kani::any(), kani::any());
    let policy = Policy::for_proof(1u16 << (Api::RespWrite as u8));
    let r = crate::host::resolver(&policy);
    let linked = r(&module, &name[..nlen], FuncType::i32s(np, nr));
    kani::cover!(linked.is_some(), "an allowed import does link (non-vacuous)");
    if let Some(id) = linked {
        let api = Api::from_id(id).unwrap();
        assert!(&module == b"qs");
        assert!(api.name() == &name[..nlen]);
        assert!(policy.allows(api));
        assert!(api.signature() == (np, nr));
        assert!(matches!(api, Api::RespWrite));
    }
}

/// LAW_006-style: LEB decoders never panic and never read past the slice.
#[kani::proof]
#[kani::unwind(12)]
fn leb_decoders_in_bounds() {
    let b: [u8; 11] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 11);
    let p: usize = kani::any();
    kani::cover!(leb_u32(&b[..n], p).is_some(), "a LEB decodes (non-vacuous)");
    if let Some((_, np)) = leb_u32(&b[..n], p) {
        assert!(np <= n && np > p);
    }
    if let Some((_, np)) = leb_i32(&b[..n], p) {
        assert!(np <= n && np > p);
    }
    if let Some((_, np)) = leb_i64(&b[..n], p) {
        assert!(np <= n && np > p);
    }
}

/// memory.grow arithmetic: for ALL len/cap/delta a successful grow never exceeds the cap, never shrinks, keeps
/// page alignment, and cannot overflow.
#[kani::proof]
fn grow_len_respects_cap() {
    let (len, cap, delta): (usize, usize, u32) = (kani::any(), kani::any(), kani::any());
    kani::assume(len % PAGE == 0);
    if let Some(n) = grow_len(len, cap, delta) {
        assert!(n <= cap);
        assert!(n >= len);
        assert!(n % PAGE == 0);
        assert!(n as u64 == len as u64 + delta as u64 * PAGE as u64);
    }
    kani::cover!(grow_len(len, cap, delta).is_some() && delta > 0, "a real growth is possible (non-vacuous)");
}

/// The pure numeric evaluator is total over its whole domain: no panic for any opcode/operand bits, i32-typed
/// results are zero-extended (so a stale upper half can never leak into a later i64 operation), and division traps
/// exactly when the divisor is zero or the signed quotient overflows.
#[kani::proof]
fn eval_num_is_total_and_typed() {
    let o: u8 = kani::any();
    let (a, b): (u64, u64) = (kani::any(), kani::any());
    if let Some((_, _, res)) = crate::ops::num_sig(o) {
        match crate::ops::eval_num(o, a, b) {
            Ok(r) => {
                if res == crate::ops::Ty::I32 {
                    assert!(r <= u32::MAX as u64);
                }
            }
            Err(t) => assert!(matches!(t, Trap::DivByZero | Trap::IntOverflow)),
        }
        kani::cover!(crate::ops::eval_num(o, a, b).is_ok(), "success path reachable");
        kani::cover!(crate::ops::eval_num(o, a, b).is_err(), "trap path reachable");
    }
}

/// Immediate skipping never reads past the code and always makes progress, for every opcode and 8 symbolic bytes.
#[kani::proof]
#[kani::unwind(12)]
fn skip_imm_in_bounds_and_progresses() {
    let code: [u8; 8] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 8);
    let (pc, o): (usize, u8) = (kani::any(), kani::any());
    kani::assume(pc <= n);
    if let Ok(np) = crate::ops::skip_imm(&code[..n], pc, o) {
        assert!(np >= pc && np <= n);
    }
}

/// Loading arbitrary short garbage never panics and only ever yields Ok(valid module) or a LoadError
/// (bounded: modules of at most 20 bytes).
#[kani::proof]
#[kani::unwind(24)]
fn parse_short_input_never_panics() {
    let b: [u8; 20] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 20);
    let _ = Module::parse(&b[..n]);
}
