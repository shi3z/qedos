//! `app.proof` envelope — the *container* for future Proof-Carrying Script certificates.
//!
//! What exists today: a strict envelope parser and the binding check (the certificate names the exact
//! SHA-512 of the Wasm module and policy it talks about). What does NOT exist: any proof checker.
//! Therefore [`check`] always answers [`ProofVerdict::NoCheckerAvailable`] and the loader never treats a
//! certificate as safety evidence (see `VerifiedScript::proof_accepted`). A signature over a bundle that
//! contains a proof says "the signer shipped this file", never "this file is a valid proof".
//!
//! Envelope layout (all big-endian):
//! `"QSPF1\0" | claim:u8 | checker_id:u16 | sha512(wasm)[64] | sha512(policy)[64] | payload_len:u32 | payload`
use crate::sha512;

pub const MAGIC: &[u8; 6] = b"QSPF1\0";
pub const HEADER_LEN: usize = 6 + 1 + 2 + 64 + 64 + 4;

/// Claims a future checker could certify. Numeric values are part of the format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// every memory access of every execution stays inside linear memory
    MemorySafe = 1,
    /// every execution consumes at most `N` fuel (N is in the payload)
    FuelBounded = 2,
    /// only the listed host APIs can be called (list in the payload)
    HostApiSubset = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    TooShort,
    BadMagic,
    UnknownClaim,
    LengthMismatch,
    /// certificate talks about a different module or policy than the one in the bundle
    NotBoundToBundle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerdict {
    /// No checker for this (claim, checker_id) is built into this runtime, so the certificate proves nothing to us.
    NoCheckerAvailable,
}

pub struct Envelope<'a> {
    pub claim: Claim,
    pub checker_id: u16,
    pub payload: &'a [u8],
}

pub fn parse<'a>(proof: &'a [u8], wasm: &[u8], policy: &[u8]) -> Result<Envelope<'a>, ProofError> {
    if proof.len() < HEADER_LEN {
        return Err(ProofError::TooShort);
    }
    if &proof[..6] != MAGIC {
        return Err(ProofError::BadMagic);
    }
    let claim = match proof[6] {
        1 => Claim::MemorySafe,
        2 => Claim::FuelBounded,
        3 => Claim::HostApiSubset,
        _ => return Err(ProofError::UnknownClaim),
    };
    let checker_id = u16::from_be_bytes([proof[7], proof[8]]);
    if proof[9..73] != sha512(wasm) || proof[73..137] != sha512(policy) {
        return Err(ProofError::NotBoundToBundle);
    }
    let n = u32::from_be_bytes([proof[137], proof[138], proof[139], proof[140]]) as usize;
    if proof.len() != HEADER_LEN + n {
        return Err(ProofError::LengthMismatch);
    }
    Ok(Envelope { claim, checker_id, payload: &proof[HEADER_LEN..] })
}

/// Placeholder for the independent proof checker. Deliberately has no "accepted" outcome yet.
pub fn check(_env: &Envelope<'_>) -> ProofVerdict {
    ProofVerdict::NoCheckerAvailable
}

/// Build an envelope (used by tooling and tests; generating a certificate is NOT trusted by the runtime).
pub fn build(claim: Claim, checker_id: u16, wasm: &[u8], policy: &[u8], payload: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8], n: &mut usize| {
        out[*n..*n + b.len()].copy_from_slice(b);
        *n += b.len();
    };
    put(MAGIC, &mut n);
    put(&[claim as u8], &mut n);
    put(&checker_id.to_be_bytes(), &mut n);
    put(&sha512(wasm), &mut n);
    put(&sha512(policy), &mut n);
    put(&(payload.len() as u32).to_be_bytes(), &mut n);
    put(payload, &mut n);
    n
}
