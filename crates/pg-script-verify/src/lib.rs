//! QED Script bundle admission: Ed25519 code signature (LAW_020) + policy/module cross-checks +
//! proof-certificate admission policy.
//!
//! The only way to obtain a [`VerifiedScript`] is [`load`], which verifies the signature *before*
//! parsing any untrusted byte of the policy or Wasm module.
//!
//! Key separation: scripts are verified against a *code-signing* key that is distinct from the
//! configuration-signing key (`pg_config::PUBLIC_KEY`), and the signed message carries a domain tag
//! so a configuration signature can never validate as a code signature (and vice versa).
//!
//! `app.proof` is **never** accepted as evidence of safety in this version: no proof checker exists
//! yet, so a present certificate is bound/hashed into the signature but ignored for admission
//! (see [`Admission`]).
#![no_std]
#![forbid(unsafe_code)]

use pg_config::{parse_hex_sig, verify_ed25519, Sha512};
use pg_script::{Module, LoadError};
use pg_script_policy::{Policy, PolicyError, MAX_POLICY_LEN, RUNTIME_ID};

/// Domain separation tag for code signatures.
pub const DOMAIN: &[u8; 17] = b"QEDOS-QS-CODE-V1\0";
pub const MAX_WASM_LEN: usize = 256 * 1024;
pub const MAX_PROOF_LEN: usize = 64 * 1024;

/// Pinned Ed25519 public key for script signing (`config/keys/qs-code-signing-pub.hex`).
/// Distinct from `pg_config::PUBLIC_KEY`. Development key: the seed is in the repository.
pub const CODE_SIGNING_PUBLIC_KEY: [u8; 32] = include!("../../../config/keys/qs-code-signing-pub.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    TooLarge,
    BadSignatureEncoding,
    BadSignature,
    Policy(PolicyError),
    Module(LoadError),
    /// The module imports something the signed policy does not allow, or that does not exist.
    UnsupportedImport,
    /// `app.proof` present but malformed or not bound to this module+policy (fail closed).
    BadProof(proof::ProofError),
    /// Module needs more memory than the signed policy allows.
    MemoryExceedsPolicy,
}

/// What entitled this script to run. There is deliberately no variant for "proof-checked" yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Signed by the pinned code-signing key; safety rests on the sandbox, not on any proof.
    SignedSandboxed,
}

/// Status of an attached `app.proof`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofStatus {
    Absent,
    /// Present, hashed into the signature, but NOT checked and NOT relied upon (no checker exists).
    PresentUnchecked,
}

pub struct VerifiedScript<'a> {
    module: Module<'a>,
    policy: Policy<'a>,
    admission: Admission,
    proof: ProofStatus,
}

impl<'a> VerifiedScript<'a> {
    pub fn module(&self) -> &Module<'a> {
        &self.module
    }
    pub fn policy(&self) -> &Policy<'a> {
        &self.policy
    }
    pub fn admission(&self) -> Admission {
        self.admission
    }
    pub fn proof_status(&self) -> ProofStatus {
        self.proof
    }
    /// Always `false` in this version: a proof certificate is never accepted as a safety argument.
    pub fn proof_accepted(&self) -> bool {
        false
    }
}

pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

pub const MSG_MAX: usize = 17 + 1 + 16 + 4 + MAX_POLICY_LEN + 64 + 64;

/// Build the signed message:
/// `DOMAIN || len(runtime) || runtime || u32_be(len(policy)) || policy || SHA512(wasm) || SHA512(proof | empty)`.
/// Module id, version and allowed APIs/limits are inside `policy`, so one signature binds them all
/// to this exact Wasm byte string, this runtime, and this (possibly empty) proof.
pub fn signed_message(policy: &[u8], wasm: &[u8], proof: Option<&[u8]>, out: &mut [u8; MSG_MAX]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8], n: &mut usize| {
        out[*n..*n + b.len()].copy_from_slice(b);
        *n += b.len();
    };
    put(DOMAIN, &mut n);
    put(&[RUNTIME_ID.len() as u8], &mut n);
    put(RUNTIME_ID, &mut n);
    put(&(policy.len() as u32).to_be_bytes(), &mut n);
    put(policy, &mut n);
    put(&sha512(wasm), &mut n);
    put(&sha512(proof.unwrap_or(&[])), &mut n);
    n
}

/// Verify and admit a script bundle (`app.wasm`, `app.policy`, `app.sig` [, `app.proof`]).
pub fn load<'a>(
    wasm: &'a [u8],
    policy_bytes: &'a [u8],
    sig_text: &[u8],
    proof: Option<&[u8]>,
    pubkey: &[u8; 32],
) -> Result<VerifiedScript<'a>, VerifyError> {
    if wasm.len() > MAX_WASM_LEN || policy_bytes.len() > MAX_POLICY_LEN || proof.map_or(false, |p| p.len() > MAX_PROOF_LEN) {
        return Err(VerifyError::TooLarge);
    }
    // trim trailing whitespace of the hex signature file
    let mut t = sig_text;
    while let [rest @ .., l] = t {
        if l.is_ascii_whitespace() {
            t = rest;
        } else {
            break;
        }
    }
    let sig = parse_hex_sig(t).ok_or(VerifyError::BadSignatureEncoding)?;
    let mut msg = [0u8; MSG_MAX];
    let n = signed_message(policy_bytes, wasm, proof, &mut msg);
    // 1. Signature first: nothing below runs on unauthenticated bytes.
    if !verify_ed25519(pubkey, &msg[..n], &sig) {
        return Err(VerifyError::BadSignature);
    }
    // 2. Policy, module, cross-checks.
    let policy = Policy::parse(policy_bytes).map_err(VerifyError::Policy)?;
    let module = Module::parse(wasm).map_err(VerifyError::Module)?;
    if module.memory_bytes() > policy.limits.max_memory_bytes as usize {
        return Err(VerifyError::MemoryExceedsPolicy);
    }
    if let Some(p) = proof {
        let env = proof::parse(p, wasm, policy_bytes).map_err(VerifyError::BadProof)?;
        // Run the (currently empty) checker registry so the code path exists; its verdict never grants anything.
        let _ = proof::check(&env);
    }
    let res = pg_script::resolver(&policy);
    for im in module.imports() {
        if res(im.module, im.name, im.ty).is_none() {
            return Err(VerifyError::UnsupportedImport);
        }
    }
    Ok(VerifiedScript {
        module,
        policy,
        admission: Admission::SignedSandboxed,
        proof: if proof.is_some() { ProofStatus::PresentUnchecked } else { ProofStatus::Absent },
    })
}

pub mod bundles;
pub mod proof;

#[cfg(test)]
mod tests;
