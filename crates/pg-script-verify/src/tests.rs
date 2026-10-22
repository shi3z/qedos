extern crate std;
use super::*;
use pg_config::{public_key_from_seed, sign_ed25519, PUBLIC_KEY};
use std::string::String;
use std::vec::Vec;

const SEED_HEX: &str = include_str!("../../../config/keys/qs-code-signing-seed.hex");
const WASM: &[u8] = include_bytes!("../../../examples/hello/app.wasm");
const POLICY: &[u8] = include_bytes!("../../../examples/hello/app.policy");

fn seed() -> [u8; 32] {
    let s = SEED_HEX.trim();
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| std::format!("{:02x}", x)).collect()
}
fn sign(policy: &[u8], wasm: &[u8], proof: Option<&[u8]>) -> String {
    let mut m = [0u8; MSG_MAX];
    let n = signed_message(policy, wasm, proof, &mut m);
    hex(&sign_ed25519(&seed(), &m[..n]))
}

#[test]
fn pinned_code_key_matches_dev_seed_and_differs_from_config_key() {
    assert_eq!(public_key_from_seed(&seed()), CODE_SIGNING_PUBLIC_KEY);
    assert_ne!(CODE_SIGNING_PUBLIC_KEY, PUBLIC_KEY);
}

#[test]
fn example_bundle_loads() {
    let sig = sign(POLICY, WASM, None);
    let v = load(WASM, POLICY, sig.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).unwrap();
    assert_eq!(v.admission(), Admission::SignedSandboxed);
    assert_eq!(v.proof_status(), ProofStatus::Absent);
    assert!(!v.proof_accepted());
}

#[test]
fn every_bound_component_is_covered_by_the_signature() {
    let sig = sign(POLICY, WASM, None);
    let ok = |w: &[u8], p: &[u8], pr: Option<&[u8]>| load(w, p, sig.as_bytes(), pr, &CODE_SIGNING_PUBLIC_KEY).is_ok();
    assert!(ok(WASM, POLICY, None));
    // flip each single byte of policy and wasm -> always rejected
    for i in 0..POLICY.len() {
        let mut p = POLICY.to_vec();
        p[i] ^= 0x01;
        assert!(!ok(WASM, &p, None), "policy byte {i}");
    }
    for i in 0..WASM.len() {
        let mut w = WASM.to_vec();
        w[i] ^= 0x01;
        assert!(!ok(&w, POLICY, None), "wasm byte {i}");
    }
    assert!(!ok(WASM, POLICY, Some(b"proof")), "proof added after signing");
    // signature bit flips
    for i in 0..128 {
        let mut s = sig.clone().into_bytes();
        s[i] = if s[i] == b'0' { b'1' } else { b'0' };
        assert!(load(WASM, POLICY, &s, None, &CODE_SIGNING_PUBLIC_KEY).is_err(), "sig nibble {i}");
    }
}

#[test]
fn config_key_signature_is_not_a_code_signature() {
    // Sign the identical bytes (without the domain tag) as a config signature would; and sign the correct
    // message with a key that is not the pinned code key.
    let sig_other_key = {
        let mut m = [0u8; MSG_MAX];
        let n = signed_message(POLICY, WASM, None, &mut m);
        hex(&sign_ed25519(&[7u8; 32], &m[..n]))
    };
    assert_eq!(
        load(WASM, POLICY, sig_other_key.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).err(),
        Some(VerifyError::BadSignature)
    );
    // no-domain message signed by the right seed
    let mut raw = Vec::new();
    raw.extend_from_slice(POLICY);
    raw.extend_from_slice(WASM);
    let s = hex(&sign_ed25519(&seed(), &raw));
    assert_eq!(load(WASM, POLICY, s.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).err(), Some(VerifyError::BadSignature));
}

#[test]
fn signature_is_checked_before_untrusted_parsing() {
    // garbage wasm + garbage policy with a bad signature => BadSignature, not a Module/Policy error
    let r = load(b"\x00asm junk", b"not a policy", &[b'0'; 128], None, &CODE_SIGNING_PUBLIC_KEY);
    assert_eq!(r.err(), Some(VerifyError::BadSignature));
}

#[test]
fn signed_but_inconsistent_bundles_are_refused() {
    // validly signed policy that denies an API the module imports
    let pol = String::from_utf8_lossy(POLICY).replace("allow = resp_write\n", "");
    let sig = sign(pol.as_bytes(), WASM, None);
    assert_eq!(
        load(WASM, pol.as_bytes(), sig.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).err(),
        Some(VerifyError::UnsupportedImport)
    );
    // validly signed policy with memory limit below the module's declaration
    let pol = String::from_utf8_lossy(POLICY).replace("max_memory_bytes = 65536", "max_memory_bytes = 4096");
    let sig = sign(pol.as_bytes(), WASM, None);
    assert_eq!(
        load(WASM, pol.as_bytes(), sig.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).err(),
        Some(VerifyError::MemoryExceedsPolicy)
    );
    // wrong runtime id
    let pol = String::from_utf8_lossy(POLICY).replace("qs-wasm/1", "qs-wasm/9");
    let sig = sign(pol.as_bytes(), WASM, None);
    assert_eq!(
        load(WASM, pol.as_bytes(), sig.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).err(),
        Some(VerifyError::Policy(PolicyError::BadRuntime))
    );
}

#[test]
fn proof_is_bound_but_never_accepted_as_safety_evidence() {
    let mut buf = [0u8; 512];
    let n = proof::build(proof::Claim::MemorySafe, 1, WASM, POLICY, b"opaque checker-specific bytes", &mut buf);
    let proof = &buf[..n];
    let sig = sign(POLICY, WASM, Some(proof));
    let v = load(WASM, POLICY, sig.as_bytes(), Some(proof), &CODE_SIGNING_PUBLIC_KEY).unwrap();
    assert_eq!(v.proof_status(), ProofStatus::PresentUnchecked);
    assert!(!v.proof_accepted());
    let env = proof::parse(proof, WASM, POLICY).unwrap();
    assert_eq!(proof::check(&env), proof::ProofVerdict::NoCheckerAvailable);
    // swapping the proof afterwards breaks the signature
    assert!(load(WASM, POLICY, sig.as_bytes(), Some(b"other"), &CODE_SIGNING_PUBLIC_KEY).is_err());
    assert!(load(WASM, POLICY, sig.as_bytes(), None, &CODE_SIGNING_PUBLIC_KEY).is_err());
}

#[test]
fn malformed_or_unbound_proofs_are_refused_even_when_signed() {
    use proof::ProofError::*;
    let signed_load = |p: &[u8]| {
        let sig = sign(POLICY, WASM, Some(p));
        load(WASM, POLICY, sig.as_bytes(), Some(p), &CODE_SIGNING_PUBLIC_KEY).err()
    };
    // "verified by external tool" strings are not certificates
    assert_eq!(signed_load(b"verified by external tool"), Some(VerifyError::BadProof(TooShort)));
    let mut buf = [0u8; 512];
    let n = proof::build(proof::Claim::FuelBounded, 1, WASM, POLICY, b"", &mut buf);
    // certificate about another module
    let mut other = [0u8; 512];
    let n2b = proof::build(proof::Claim::FuelBounded, 1, b"other module", POLICY, b"", &mut other);
    assert_eq!(signed_load(&other[..n2b]), Some(VerifyError::BadProof(NotBoundToBundle)));
    let mut bad = buf;
    bad[0] = b'X';
    assert_eq!(signed_load(&bad[..n]), Some(VerifyError::BadProof(BadMagic)));
    let mut bad = buf;
    bad[6] = 99;
    assert_eq!(signed_load(&bad[..n]), Some(VerifyError::BadProof(UnknownClaim)));
    assert_eq!(signed_load(&buf[..n].iter().copied().chain([0u8]).collect::<Vec<u8>>()), Some(VerifyError::BadProof(LengthMismatch)));
}

fn pack(entries: &[(&[u8], &[u8], String)]) -> Vec<u8> {
    let mut out = b"QSB1".to_vec();
    out.push(entries.len() as u8);
    for (w, p, s) in entries {
        for l in [w.len(), p.len(), 0] {
            out.extend_from_slice(&(l as u32).to_be_bytes());
        }
        out.extend_from_slice(s.as_bytes());
        out.extend_from_slice(w);
        out.extend_from_slice(p);
    }
    out
}

#[test]
fn bundle_table_verifies_each_entry_and_fails_closed() {
    use crate::bundles::ScriptSet;
    const EW: &[u8] = include_bytes!("../../../examples/json-echo/app.wasm");
    const EP: &[u8] = include_bytes!("../../../examples/json-echo/app.policy");
    let good_h = sign(POLICY, WASM, None);
    let good_e = sign(EP, EW, None);
    let blob = pack(&[(WASM, POLICY, good_h.clone()), (EW, EP, good_e.clone())]);
    let set = ScriptSet::load(&blob, &CODE_SIGNING_PUBLIC_KEY).unwrap();
    assert_eq!((set.len(), set.rejected), (2, 0));
    assert!(set.find(b"hello").is_some() && set.find(b"json-echo").is_some());
    assert!(set.find(b"nope").is_none() && set.find(b"").is_none());
    // one tampered entry is dropped, the other still serves
    let mut bad = good_e.clone().into_bytes();
    bad[3] = if bad[3] == b'0' { b'1' } else { b'0' };
    let blob = pack(&[(WASM, POLICY, good_h.clone()), (EW, EP, String::from_utf8(bad).unwrap())]);
    let set = ScriptSet::load(&blob, &CODE_SIGNING_PUBLIC_KEY).unwrap();
    assert_eq!((set.len(), set.rejected), (1, 1));
    assert!(set.find(b"json-echo").is_none());
    // duplicate module id: second one rejected
    let blob = pack(&[(WASM, POLICY, good_h.clone()), (WASM, POLICY, good_h)]);
    let set = ScriptSet::load(&blob, &CODE_SIGNING_PUBLIC_KEY).unwrap();
    assert_eq!((set.len(), set.rejected), (1, 1));
    // truncated / trailing garbage containers are refused wholesale
    let blob = pack(&[(WASM, POLICY, sign(POLICY, WASM, None))]);
    assert!(ScriptSet::load(&blob[..blob.len() - 1], &CODE_SIGNING_PUBLIC_KEY).is_err());
    let mut t = blob.clone();
    t.extend_from_slice(&[0u8; 100]); // zero padding (as in the PD image section) is fine
    assert_eq!(ScriptSet::load(&t, &CODE_SIGNING_PUBLIC_KEY).unwrap().len(), 1);
    t.push(1); // non-zero trailing garbage is not
    assert!(ScriptSet::load(&t, &CODE_SIGNING_PUBLIC_KEY).is_err());
}
