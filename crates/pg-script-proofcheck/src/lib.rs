//! Independent Proof-Carrying Script checker.
//!
//! This is the ONLY place that may turn a claim in an `app.proof` envelope into [`Checked::Accepted`]. It is
//! deliberately separate from whoever produced the proof (human, tool, or AI): every claim is **re-derived from
//! the module and policy bytes themselves**, not taken on trust from the certificate's payload. A signed proof
//! says "the signer shipped this claim"; only a pass through this crate says the claim is actually true of this
//! module.
//!
//! `#![forbid(unsafe_code)]`, no heap, deterministic, and bounded: every check walks each instruction of each
//! function at most once, so run time is linear in the module size with no risk of non-termination (this crate
//! has no loops over anything but fixed, already-bounded module tables).
//!
//! Two claims are supported, the two named in docs/LAWS.md as the first targets:
//!
//! * **HostApiSubset**: every host import the module declares is an API the signed policy allows. This DOES NOT
//!   re-implement policy-checking from scratch (the module/policy parsers and the allow-list are the same ones
//!   the runtime uses — duplicating a parser would just add a second place to get wrong); what makes this an
//!   independent *checker* rather than a restatement of the loader is that it is driven only by the claim's
//!   binding (module+policy hashes) and never by the proof's own payload bytes.
//! * **FuelBounded**: restricted, for now, to the loop-free subset described in docs/LAWS.md — modules whose
//!   functions contain no `loop`, no backward `br`/`br_if`/`br_table`, and no `call`/`call_indirect` (so no
//!   recursion and no unbounded iteration is reachable at all). For such a module every instruction executes at
//!   most once per call to `handle`, so the worst-case fuel is a static instruction count — computed here by
//!   walking the same bytes the interpreter runs, not trusted from the proof payload's claimed bound.
#![no_std]
#![forbid(unsafe_code)]

use pg_script::ops::{op, skip_imm};
use pg_script::{LoadError, Module};
use pg_script_policy::{Api, Policy};
use pg_script_verify::proof::{self, Claim, Envelope, ProofError};

/// What this checker concluded about one claim. Only `Accepted` may be treated as a safety property; every
/// other variant means the certificate proves nothing (it is never an error to present an unaccepted proof —
/// the runtime simply falls back to sandboxing alone, as it always has).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checked {
    /// The claim was re-derived from the module/policy bytes and holds.
    Accepted,
    /// The envelope itself is malformed, not bound to this module/policy, or names an unsupported claim/checker id.
    Malformed(ProofError),
    /// The envelope is well-formed and bound correctly, but the claim does not hold for this module (e.g. the
    /// module is not in the loop-free subset FuelBounded supports, or it imports something the policy forbids).
    Rejected(&'static str),
}

/// The checker id this crate implements. A proof naming a different `checker_id` is reported `Malformed`
/// (`UnknownClaim`-equivalent at the envelope level is `checker_id` mismatch here), never silently accepted.
pub const CHECKER_ID: u16 = 1;

/// Verify `proof` against the exact `wasm`/`policy_bytes` of a bundle, and the already-parsed [`Module`]/[`Policy`]
/// (so this crate never re-implements the parsers; see the module doc comment).
pub fn check(proof: &[u8], wasm: &[u8], policy_bytes: &[u8], module: &Module<'_>, policy: &Policy<'_>) -> Checked {
    let env = match proof::parse(proof, wasm, policy_bytes) {
        Ok(e) => e,
        Err(e) => return Checked::Malformed(e),
    };
    if env.checker_id != CHECKER_ID {
        return Checked::Malformed(ProofError::UnknownClaim);
    }
    match env.claim {
        Claim::HostApiSubset => check_host_api_subset(module, policy),
        Claim::FuelBounded => check_fuel_bounded(&env, module),
        Claim::MemorySafe => Checked::Rejected("MemorySafe has no checker in this version"),
    }
}

/// HostApiSubset: every import the module declares resolves under the policy. Re-derived from `module.imports()`
/// directly (the same data the runtime's linker consults), independent of anything the proof payload claims.
fn check_host_api_subset(module: &Module<'_>, policy: &Policy<'_>) -> Checked {
    let resolver = pg_script::resolver(policy);
    let mut i = 0;
    while i < module.imports().len() {
        let im = module.imports()[i];
        if resolver(im.module, im.name, im.ty).is_none() {
            return Checked::Rejected("an import is not resolved by the signed policy");
        }
        i += 1;
    }
    Checked::Accepted
}

/// A function is in the loop-free subset iff it contains no LOOP, no CALL/CALL_INDIRECT, and every BR/BR_IF/
/// BR_TABLE target is a label that is still open at that point (i.e. a forward or enclosing exit — never the
/// function's own re-entry, since there are no loops to re-enter: this is exactly "no backward control flow").
/// Within that subset, `handle`'s own worst-case instruction count is returned; this crate never has to run
/// the module to know a bound exists.
fn straight_line_instr_count(code: &[u8]) -> Result<u32, &'static str> {
    let mut pc = 0usize;
    let mut depth: u32 = 0; // open BLOCK/IF frames (LOOP is rejected outright, so no re-entrant frames exist)
    let mut n: u32 = 0;
    loop {
        let o = *code.get(pc).ok_or("truncated function body")?;
        let np = skip_imm(code, pc + 1, o).map_err(|_: LoadError| "unrecognised instruction")?;
        n = n.checked_add(1).ok_or("function too large to bound")?;
        match o {
            op::LOOP => return Err("contains a loop: outside the supported subset"),
            op::CALL | op::CALL_INDIRECT => return Err("contains a call: outside the supported subset"),
            op::BLOCK | op::IF => depth += 1,
            op::END => {
                if depth == 0 {
                    return Ok(n);
                }
                depth -= 1;
            }
            op::BR | op::BR_IF => {
                let (d, _) = skip_target(code, pc + 1)?;
                if d > depth {
                    return Err("branch target out of range");
                }
                // every target is an *enclosing* label (br exits outward, never re-enters): structurally forward.
            }
            op::BR_TABLE => {
                let (n_targets, mut p) = pg_script::wasm::leb_u32(code, pc + 1).ok_or("bad br_table")?;
                let mut k = 0u32;
                while k <= n_targets {
                    let (d, q) = pg_script::wasm::leb_u32(code, p).ok_or("bad br_table")?;
                    if d > depth {
                        return Err("branch target out of range");
                    }
                    p = q;
                    k += 1;
                }
            }
            _ => {}
        }
        pc = np;
    }
}

fn skip_target(code: &[u8], pc: usize) -> Result<(u32, usize), &'static str> {
    pg_script::wasm::leb_u32(code, pc).ok_or("bad branch target")
}

fn check_fuel_bounded(env: &Envelope<'_>, module: &Module<'_>) -> Checked {
    // the claimed bound is READ but never trusted: it only selects which outcome we report, the arithmetic that
    // decides Accepted/Rejected is entirely re-derived below.
    let claimed: u64 = {
        if env.payload.len() < 8 {
            return Checked::Rejected("FuelBounded payload must carry an 8-byte big-endian bound");
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&env.payload[..8]);
        u64::from_be_bytes(b)
    };
    let mut total: u64 = 0;
    let mut i = 0;
    while i < module.n_funcs() {
        match straight_line_instr_count(module.func_code(i)) {
            Ok(n) => total = total.saturating_add(n as u64),
            Err(why) => return Checked::Rejected(why),
        }
        i += 1;
    }
    // worst case: `handle` runs its own body once (no loops, no calls reachable from it in this subset, so no
    // other function body can execute as part of one request) — summing every function is a deliberate
    // over-approximation that stays sound even though only `handle`'s own body actually runs.
    let _ = module.handle_index();
    if total <= claimed {
        Checked::Accepted
    } else {
        Checked::Rejected("re-derived instruction count exceeds the claimed bound")
    }
}

/// Tooling helper: the exact bound `check` would accept for this module under FuelBounded, or `None` if the
/// module is outside the loop-free subset. NOT used by `check` itself (which always re-derives from scratch);
/// exists so `qs mkproof` can generate a proof payload without a second, divergent implementation of the count.
pub fn fuel_bound_hint(module: &Module<'_>) -> Option<u64> {
    let mut total: u64 = 0;
    let mut i = 0;
    while i < module.n_funcs() {
        total = total.saturating_add(straight_line_instr_count(module.func_code(i)).ok()? as u64);
        i += 1;
    }
    Some(total)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
#[cfg(kani)]
mod proofs;
