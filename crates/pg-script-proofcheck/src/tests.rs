use super::*;
use pg_script_policy::Limits;
extern crate std;
use std::vec::Vec;

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

/// `handle() -> i32` with the given body and optional `(name, nparams)` imports (all `qs.<name>(i32*) -> i32`).
fn build(body: &[u8], imports: &[&str]) -> Vec<u8> {
    let mut m = std::vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    let mut types = std::vec![1 + imports.len() as u8];
    types.extend_from_slice(&[0x60, 0, 1, 0x7f]); // handle: () -> i32
    for _ in imports {
        types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // (i32) -> ()  (resp_status / resp_content_type signature)

    }
    sec(1, &types, &mut m);
    if !imports.is_empty() {
        let mut im = std::vec![imports.len() as u8];
        for (i, n) in imports.iter().enumerate() {
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
    let mut code = std::vec![0];
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
        max_fuel: 1_000_000,
        max_stack_depth: 8,
        max_request_bytes: 4096,
        max_response_bytes: 1024,
        max_host_calls: 64,
        max_exec_us: 10_000,
    }
}

fn mkenv(claim: Claim, checker_id: u16, wasm: &[u8], policy: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = std::vec![0u8; 1024];
    let n = proof::build(claim, checker_id, wasm, policy, payload, &mut buf);
    buf.truncate(n);
    buf
}

#[test]
fn host_api_subset_accepts_an_allowed_import_and_rejects_a_disallowed_one() {
    let pol_ok: &[u8] = b"runtime = qs-wasm/1\nmodule = m\nversion = 1\nallow = resp_status\nmax_memory_bytes = 65536\nmax_fuel = 1000000\nmax_stack_depth = 8\nmax_request_bytes = 4096\nmax_response_bytes = 1024\nmax_host_calls = 64\nmax_exec_us = 10000\n";
    let pol_bad: &[u8] = b"runtime = qs-wasm/1\nmodule = m\nversion = 1\nallow = resp_write\nmax_memory_bytes = 65536\nmax_fuel = 1000000\nmax_stack_depth = 8\nmax_request_bytes = 4096\nmax_response_bytes = 1024\nmax_host_calls = 64\nmax_exec_us = 10000\n";
    let wasm = build(&[0x41, 0, 0x0b], &["resp_status"]);
    for (pol, ok) in [(pol_ok, true), (pol_bad, false)] {
        let policy = Policy::parse(pol).unwrap();
        let module = Module::parse(&wasm).unwrap();
        let proof = mkenv(Claim::HostApiSubset, CHECKER_ID, &wasm, pol, &[]);
        assert_eq!(check(&proof, &wasm, pol, &module, &policy), if ok { Checked::Accepted } else { Checked::Rejected("an import is not resolved by the signed policy") });
    }
    let _ = limits();
}

#[test]
fn fuel_bounded_accepts_loop_free_within_bound_and_rejects_over_bound_or_loops() {
    let pol: &[u8] = b"runtime = qs-wasm/1\nmodule = m\nversion = 1\nmax_memory_bytes = 65536\nmax_fuel = 1000000\nmax_stack_depth = 8\nmax_request_bytes = 4096\nmax_response_bytes = 1024\nmax_host_calls = 64\nmax_exec_us = 10000\n";
    let policy = Policy::parse(pol).unwrap();
    // straight-line: i32.const 1; i32.const 2; i32.add  (3 instrs) + implicit end not counted (end closes handle)
    let wasm = build(&[0x41, 1, 0x41, 2, 0x6a, 0x0b], &[]);
    let module = Module::parse(&wasm).unwrap();
    let proof_ok = mkenv(Claim::FuelBounded, CHECKER_ID, &wasm, pol, &10u64.to_be_bytes());
    assert_eq!(check(&proof_ok, &wasm, pol, &module, &policy), Checked::Accepted);
    let proof_low = mkenv(Claim::FuelBounded, CHECKER_ID, &wasm, pol, &1u64.to_be_bytes());
    assert_eq!(check(&proof_low, &wasm, pol, &module, &policy), Checked::Rejected("re-derived instruction count exceeds the claimed bound"));

    // a loop makes the module ineligible regardless of the claimed bound
    let wasm_loop = build(&[0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b], &[]);
    let module_loop = Module::parse(&wasm_loop).unwrap();
    let proof_huge = mkenv(Claim::FuelBounded, CHECKER_ID, &wasm_loop, pol, &u64::MAX.to_be_bytes());
    assert_eq!(check(&proof_huge, &wasm_loop, pol, &module_loop, &policy), Checked::Rejected("contains a loop: outside the supported subset"));
}

#[test]
fn tampering_with_the_binding_is_rejected() {
    let pol: &[u8] = b"runtime = qs-wasm/1\nmodule = m\nversion = 1\nmax_memory_bytes = 65536\nmax_fuel = 1000000\nmax_stack_depth = 8\nmax_request_bytes = 4096\nmax_response_bytes = 1024\nmax_host_calls = 64\nmax_exec_us = 10000\n";
    let policy = Policy::parse(pol).unwrap();
    let wasm = build(&[0x41, 1, 0x0b], &[]);
    let module = Module::parse(&wasm).unwrap();
    let proof = mkenv(Claim::FuelBounded, CHECKER_ID, &wasm, pol, &100u64.to_be_bytes());
    // bound to a DIFFERENT wasm: NotBoundToBundle
    let other = build(&[0x41, 2, 0x0b], &[]);
    assert_eq!(check(&proof, &other, pol, &module, &policy), Checked::Malformed(ProofError::NotBoundToBundle));
    // truncated envelope
    assert_eq!(check(&proof[..5], &wasm, pol, &module, &policy), Checked::Malformed(ProofError::TooShort));
    // wrong checker id
    let proof_wrong_checker = mkenv(Claim::FuelBounded, CHECKER_ID + 1, &wasm, pol, &100u64.to_be_bytes());
    assert_eq!(check(&proof_wrong_checker, &wasm, pol, &module, &policy), Checked::Malformed(ProofError::UnknownClaim));
}

/// Fuzz: random byte strings fed to the parser used by `check` must never panic.
#[test]
fn fuzz_proof_parsing_never_panics() {
    let pol: &[u8] = b"runtime = qs-wasm/1\nmodule = m\nversion = 1\nmax_memory_bytes = 65536\nmax_fuel = 1000000\nmax_stack_depth = 8\nmax_request_bytes = 4096\nmax_response_bytes = 1024\nmax_host_calls = 64\nmax_exec_us = 10000\n";
    let policy = Policy::parse(pol).unwrap();
    let wasm = build(&[0x41, 1, 0x0b], &[]);
    let module = Module::parse(&wasm).unwrap();
    let mut state = 0x2545F4914F6CDD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..200_000 {
        let n = 1 + (next() % 300) as usize;
        let buf: Vec<u8> = (0..n).map(|_| next() as u8).collect();
        let _ = check(&buf, &wasm, pol, &module, &policy); // must not panic
    }
}

#[test]
fn debug_branch_depth_combos() {
    use super::op;
    for depth_opens in 0u8..=3 {
        for target in 0u8..=3 {
            let mut code = [op::END; 12];
            let mut p = 0usize;
            for _ in 0..depth_opens {
                code[p] = op::BLOCK;
                code[p + 1] = 0x40;
                p += 2;
            }
            code[p] = op::BR;
            code[p + 1] = target;
            p += 2;
            for _ in 0..depth_opens {
                code[p] = op::END;
                p += 1;
            }
            code[p] = op::END;
            let r = straight_line_instr_count(&code[..p + 1]);
            std::println!("depth_opens={depth_opens} target={target} -> {r:?}");
        }
    }
}
