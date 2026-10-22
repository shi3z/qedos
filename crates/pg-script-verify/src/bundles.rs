//! `QSB1` bundle table: the read-only blob embedded in the Script PD image. Every entry is verified
//! with [`crate::load`] at boot; a module that fails verification is simply absent (fail closed).
//!
//! Layout: `"QSB1" | count:u8 | entries`, entry =
//! `wasm_len:u32be | policy_len:u32be | proof_len:u32be | sig_hex[128] | wasm | policy | proof`.
use crate::{load, VerifiedScript, VerifyError};

pub const MAX_SCRIPTS: usize = 8;
pub const MAGIC: &[u8; 4] = b"QSB1";

pub struct ScriptSet<'a> {
    scripts: [Option<VerifiedScript<'a>>; MAX_SCRIPTS],
    pub rejected: usize,
}

fn be32(b: &[u8]) -> Option<usize> {
    let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(a) as usize)
}

impl<'a> ScriptSet<'a> {
    /// Parse the container and verify every entry. Returns the set of *verified* scripts; entries that
    /// fail are counted in `rejected` and never become executable.
    pub fn load(blob: &'a [u8], pubkey: &[u8; 32]) -> Result<ScriptSet<'a>, VerifyError> {
        if blob.len() < 5 || &blob[..4] != MAGIC {
            return Err(VerifyError::TooLarge);
        }
        let count = blob[4] as usize;
        if count > MAX_SCRIPTS {
            return Err(VerifyError::TooLarge);
        }
        let mut set = ScriptSet { scripts: core::array::from_fn(|_| None), rejected: 0 };
        let mut pos = 5usize;
        for i in 0..count {
            let wl = be32(blob.get(pos..).ok_or(VerifyError::TooLarge)?).ok_or(VerifyError::TooLarge)?;
            let pl = be32(blob.get(pos + 4..).ok_or(VerifyError::TooLarge)?).ok_or(VerifyError::TooLarge)?;
            let xl = be32(blob.get(pos + 8..).ok_or(VerifyError::TooLarge)?).ok_or(VerifyError::TooLarge)?;
            pos += 12;
            let sig = blob.get(pos..pos.checked_add(128).ok_or(VerifyError::TooLarge)?).ok_or(VerifyError::TooLarge)?;
            pos += 128;
            let total = wl.checked_add(pl).and_then(|v| v.checked_add(xl)).ok_or(VerifyError::TooLarge)?;
            let body = blob.get(pos..pos.checked_add(total).ok_or(VerifyError::TooLarge)?).ok_or(VerifyError::TooLarge)?;
            pos += total;
            let (wasm, rest) = body.split_at(wl);
            let (pol, proof) = rest.split_at(pl);
            match load(wasm, pol, sig, if xl > 0 { Some(proof) } else { None }, pubkey) {
                Ok(v) => {
                    // module ids must be unique, otherwise dispatch would be ambiguous
                    let dup = set.scripts.iter().flatten().any(|s| s.policy().module_id == v.policy().module_id);
                    if dup {
                        set.rejected += 1;
                    } else {
                        set.scripts[i] = Some(v);
                    }
                }
                Err(_) => set.rejected += 1,
            }
        }
        // The section in the PD image is zero-padded; anything non-zero after the last entry is garbage.
        if blob[pos..].iter().any(|b| *b != 0) {
            return Err(VerifyError::TooLarge);
        }
        Ok(set)
    }

    pub fn find(&self, module_id: &[u8]) -> Option<&VerifiedScript<'a>> {
        self.scripts.iter().flatten().find(|s| s.policy().module_id == module_id)
    }

    pub fn len(&self) -> usize {
        self.scripts.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
