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
    let (base, off, val): (u32, u32, u32) = (kani::any(), kani::any(), kani::any());
    let size: u32 = if kani::any() { 4 } else if kani::any() { 2 } else { 1 };
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
