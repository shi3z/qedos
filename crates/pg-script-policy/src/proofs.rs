//! Kani harnesses for the policy crate (`cargo kani -p pg-script-policy`). NOT executed in the
//! development environment that produced this commit (no Kani toolchain); see docs/LAWS.md.
use super::*;

/// LAW_021: with no authenticated principal, every KV authorization decision is a denial.
#[kani::proof]
#[kani::unwind(34)]
fn anonymous_never_authorized() {
    let key: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let p = fixed_policy();
    let op = if kani::any() { KvOp::Read } else { KvOp::Write };
    assert!(kv_authorize(&p, 0, op, &key[..len]).is_err());
}

/// LAW_021: an authorized key always starts with a prefix granted for that operation.
#[kani::proof]
#[kani::unwind(34)]
fn authorized_key_has_granted_prefix() {
    let key: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 6);
    let principal: u32 = kani::any();
    let p = fixed_policy();
    let ok = kv_authorize(&p, principal, KvOp::Read, &key[..len]).is_ok();
    kani::cover!(ok, "an authorized key exists (non-vacuous)");
    if ok {
        assert!(principal != 0);
        assert!(key[..len].starts_with(b"a/"));
    }
}

/// LAW_021: different (principal, key) pairs under the same module map to different storage keys.
#[kani::proof]
#[kani::unwind(40)]
fn namespaced_key_injective_in_principal_and_key() {
    let (p1, p2): (u32, u32) = (kani::any(), kani::any());
    let (k1, k2): ([u8; 3], [u8; 3]) = (kani::any(), kani::any());
    kani::assume(k1.iter().chain(k2.iter()).all(|b| *b != 0));
    kani::assume(p1 != p2 || k1 != k2);
    let (mut o1, mut o2) = ([0u8; NS_KEY_LEN], [0u8; NS_KEY_LEN]);
    let n1 = namespaced_key(p1, b"mod", &k1, &mut o1);
    let n2 = namespaced_key(p2, b"mod", &k2, &mut o2);
    assert!(n1 != n2 || o1[..n1] != o2[..n2]);
}

/// Built directly (not via `Policy::parse`, whose text loop is covered by unit tests) so the harnesses
/// below stay loop-light.
fn fixed_policy() -> Policy<'static> {
    let mut kv_read = [&b""[..]; MAX_PREFIXES];
    kv_read[0] = b"a/";
    Policy {
        module_id: b"m",
        version: 1,
        allow: 0b0110_0000,
        limits: Limits {
            max_memory_bytes: 1,
            max_fuel: 1,
            max_stack_depth: 1,
            max_request_bytes: 1,
            max_response_bytes: 1,
            max_host_calls: 1,
            max_exec_us: 1,
        },
        kv_read,
        n_read: 1,
        kv_write: kv_read,
        n_write: 1,
    }
}
