//! QEDOS Press — signed static-content release bundle format ("QPR1").
//!
//! `#![no_std]`, zero allocation, `#![forbid(unsafe_code)]`. This crate parses and verifies a release
//! bundle (manifest + concatenated file bytes + one trailing Ed25519 signature over the whole blob) and
//! answers GET/HEAD lookups against it. It does not itself touch any shared memory or capability — that
//! is the job of the PD glue (`sel4/pds/qedos_press_pd.c` + `sel4/rust_press`) that calls into this crate.
//!
//! Deliberately out of scope for this crate (see `docs/QEDOS_PRESS_CMS.md`): online/updatable releases,
//! authentication, anti-rollback. A release is a single immutable, boot-time-verified blob.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub use pg_config::{verify_ed25519, Sha512};

/// Bundle magic ("QPR1" = QEDOS Press Release v1).
pub const MAGIC: [u8; 4] = *b"QPR1";
pub const VERSION: u8 = 1;

/// Header: magic[4] version[1] n_routes[1] reserved[2] site_id[4] release_no[4] publish_ts[4] content_len[4].
pub const HEADER_LEN: usize = 24;
/// Per-route entry: path_len[1] ctype[1] reserved[2] offset[4] length[4] path[60] hash[64] (SHA-512).
pub const ENTRY_LEN: usize = 136;
pub const MAX_PATH_LEN: usize = 60;
/// Upper bound on routes in one bundle (a static-content CMS release, not a filesystem).
pub const MAX_ROUTES: usize = 24;
pub const SIG_LEN: usize = 64;

/// Content-type tags understood by the PD-side HTTP response formatter (`pg_rust_format_press_response`).
pub const CTYPE_HTML: u8 = 0;
pub const CTYPE_CSS: u8 = 1;
pub const CTYPE_JS: u8 = 2;
pub const CTYPE_JSON: u8 = 3;
pub const CTYPE_PLAIN: u8 = 4;
pub const CTYPE_OCTET: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PressError {
    TooShort,
    BadMagic,
    BadVersion,
    TooManyRoutes,
    Malformed,
    BadSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Other,
}

pub fn method_from_u8(m: u8) -> Method {
    match m {
        0 => Method::Get,
        1 => Method::Head,
        _ => Method::Other,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(usize),
    NotFound,
    MethodNotAllowed,
}

/// One parsed, bounds-checked route entry (bytes stay in the original blob; only fixed-size scalars
/// and a capped path buffer are copied, so this type is `Copy` and needs no lifetime).
#[derive(Clone, Copy)]
struct RouteEntry {
    path: [u8; MAX_PATH_LEN],
    path_len: u8,
    ctype: u8,
    offset: u32,
    length: u32,
    hash: [u8; 64],
}

/// A verified bundle. Holds a reference to the original blob (for content bytes) plus the parsed,
/// bounds-checked route table (fixed-size, `Copy`, no allocation).
pub struct Manifest<'a> {
    blob: &'a [u8],
    content_start: usize,
    routes: [RouteEntry; MAX_ROUTES],
    n_routes: usize,
    pub site_id: u32,
    pub release_no: u32,
    pub publish_ts: u32,
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Verify the signed bundle's trailing 64-byte Ed25519 signature against `pubkey`, then parse and
/// bounds-check every route entry. `blob` may be *larger* than the bundle itself (e.g. a fixed-size,
/// zero-padded ELF section, as `script_bundles_section` also is) -- only the declared `content_len`
/// determines the bundle's true length; any trailing bytes in `blob` beyond that are ignored, never
/// signed, never served. Fails closed: any malformed entry (bad length, out-of-bounds offset, path
/// too long) rejects the *whole* bundle, matching `pg_script_init`'s "all or nothing" convention.
pub fn verify_and_load<'a>(blob: &'a [u8], pubkey: &[u8; 32]) -> Result<Manifest<'a>, PressError> {
    if blob.len() < HEADER_LEN + SIG_LEN {
        return Err(PressError::TooShort);
    }
    if blob[0..4] != MAGIC {
        return Err(PressError::BadMagic);
    }
    if blob[4] != VERSION {
        return Err(PressError::BadVersion);
    }
    let n_routes = blob[5] as usize;
    if n_routes > MAX_ROUTES {
        return Err(PressError::TooManyRoutes);
    }
    let site_id = u32_le(blob, 8);
    let release_no = u32_le(blob, 12);
    let publish_ts = u32_le(blob, 16);
    let content_len = u32_le(blob, 20) as usize;

    let table_start = HEADER_LEN;
    let table_len = n_routes
        .checked_mul(ENTRY_LEN)
        .ok_or(PressError::Malformed)?;
    let content_start = table_start.checked_add(table_len).ok_or(PressError::Malformed)?;
    let content_end = content_start.checked_add(content_len).ok_or(PressError::Malformed)?;
    let bundle_len = content_end.checked_add(SIG_LEN).ok_or(PressError::Malformed)?;
    if bundle_len > blob.len() {
        return Err(PressError::Malformed);
    }
    let blob = &blob[..bundle_len]; // ignore any trailing padding beyond the declared bundle length

    // Signature covers everything except itself (same convention as pg_config::verify_and_parse_with).
    let payload = &blob[..blob.len() - SIG_LEN];
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&blob[blob.len() - SIG_LEN..]);
    if !verify_ed25519(pubkey, payload, &sig) {
        return Err(PressError::BadSignature);
    }

    let mut routes = [RouteEntry {
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
        ctype: 0,
        offset: 0,
        length: 0,
        hash: [0u8; 64],
    }; MAX_ROUTES];

    for i in 0..n_routes {
        let e = &blob[table_start + i * ENTRY_LEN..table_start + (i + 1) * ENTRY_LEN];
        let path_len = e[0];
        if path_len as usize > MAX_PATH_LEN {
            return Err(PressError::Malformed);
        }
        let ctype = e[1];
        if ctype > CTYPE_OCTET {
            return Err(PressError::Malformed);
        }
        let offset = u32_le(e, 4);
        let length = u32_le(e, 8);
        let end = (offset as u64).checked_add(length as u64).ok_or(PressError::Malformed)?;
        if end > content_len as u64 {
            return Err(PressError::Malformed);
        }
        let mut path = [0u8; MAX_PATH_LEN];
        path[..path_len as usize].copy_from_slice(&e[12..12 + path_len as usize]);
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&e[72..136]);
        routes[i] = RouteEntry { path, path_len, ctype, offset, length, hash };
    }

    Ok(Manifest { blob, content_start, routes, n_routes, site_id, release_no, publish_ts })
}

impl<'a> Manifest<'a> {
    pub fn len(&self) -> usize {
        self.n_routes
    }

    pub fn is_empty(&self) -> bool {
        self.n_routes == 0
    }

    /// Look up `path` (already stripped of any `/press` mount prefix by the caller) for `method`.
    /// GET/HEAD against a known path => `Found(index)`; unknown path => `NotFound`; any other method,
    /// even against a known path => `MethodNotAllowed` (never silently treated as GET).
    pub fn lookup(&self, method: Method, path: &[u8]) -> Lookup {
        let mut path_exists = false;
        for i in 0..self.n_routes {
            let r = &self.routes[i];
            if &r.path[..r.path_len as usize] == path {
                path_exists = true;
                if matches!(method, Method::Get | Method::Head) {
                    return Lookup::Found(i);
                }
            }
        }
        if path_exists {
            Lookup::MethodNotAllowed
        } else {
            Lookup::NotFound
        }
    }

    pub fn ctype(&self, idx: usize) -> u8 {
        self.routes[idx].ctype
    }

    /// Recompute SHA-512 over the route's content bytes and compare against the manifest's stored
    /// hash. Defense in depth against the content region being corrupted *after* the one boot-time
    /// signature check (e.g. a bit flip) — every serve re-checks, not just the first.
    pub fn verify_and_get_bytes(&self, idx: usize) -> Option<&'a [u8]> {
        let r = &self.routes[idx];
        let start = self.content_start.checked_add(r.offset as usize)?;
        let end = start.checked_add(r.length as usize)?;
        let bytes = self.blob.get(start..end)?;
        let mut h = Sha512::new();
        h.update(bytes);
        if h.finalize() == r.hash {
            Some(bytes)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pg_config::{public_key_from_seed, sign_ed25519};
    use std::{vec, vec::Vec};

    fn build_bundle(seed: &[u8; 32], files: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
        // files: (path, ctype, content)
        let mut content = Vec::new();
        let mut entries = Vec::new();
        for (path, ctype, bytes) in files {
            let offset = content.len() as u32;
            let length = bytes.len() as u32;
            content.extend_from_slice(bytes);
            let mut h = Sha512::new();
            h.update(bytes);
            let hash = h.finalize();
            let mut entry = vec![0u8; ENTRY_LEN];
            entry[0] = path.len() as u8;
            entry[1] = *ctype;
            entry[4..8].copy_from_slice(&offset.to_le_bytes());
            entry[8..12].copy_from_slice(&length.to_le_bytes());
            entry[12..12 + path.len()].copy_from_slice(path);
            entry[72..136].copy_from_slice(&hash);
            entries.push(entry);
        }
        let mut blob = vec![0u8; HEADER_LEN];
        blob[0..4].copy_from_slice(&MAGIC);
        blob[4] = VERSION;
        blob[5] = files.len() as u8;
        blob[8..12].copy_from_slice(&1u32.to_le_bytes());
        blob[12..16].copy_from_slice(&1u32.to_le_bytes());
        blob[16..20].copy_from_slice(&0u32.to_le_bytes());
        blob[20..24].copy_from_slice(&(content.len() as u32).to_le_bytes());
        for e in entries {
            blob.extend_from_slice(&e);
        }
        blob.extend_from_slice(&content);
        let pubk = public_key_from_seed(seed);
        let _ = pubk;
        let sig = sign_ed25519(seed, &blob);
        blob.extend_from_slice(&sig);
        blob
    }

    #[test]
    fn verifies_and_looks_up() {
        let seed = [7u8; 32];
        let pubk = public_key_from_seed(&seed);
        let blob = build_bundle(&seed, &[(b"/index.html", CTYPE_HTML, b"<h1>hi</h1>")]);
        let m = verify_and_load(&blob, &pubk).unwrap();
        match m.lookup(Method::Get, b"/index.html") {
            Lookup::Found(i) => {
                assert_eq!(m.verify_and_get_bytes(i).unwrap(), b"<h1>hi</h1>");
                assert_eq!(m.ctype(i), CTYPE_HTML);
            }
            _ => panic!("expected Found"),
        }
        assert_eq!(m.lookup(Method::Get, b"/missing"), Lookup::NotFound);
    }

    #[test]
    fn method_not_allowed_on_known_path() {
        let seed = [9u8; 32];
        let pubk = public_key_from_seed(&seed);
        let blob = build_bundle(&seed, &[(b"/a", CTYPE_PLAIN, b"x")]);
        let m = verify_and_load(&blob, &pubk).unwrap();
        assert_eq!(m.lookup(Method::Other, b"/a"), Lookup::MethodNotAllowed);
    }

    #[test]
    fn rejects_bad_signature() {
        let seed = [1u8; 32];
        let other_seed = [2u8; 32];
        let pubk = public_key_from_seed(&other_seed); // wrong key
        let blob = build_bundle(&seed, &[(b"/a", CTYPE_PLAIN, b"x")]);
        assert_eq!(verify_and_load(&blob, &pubk).err(), Some(PressError::BadSignature));
    }

    #[test]
    fn rejects_truncated() {
        let seed = [3u8; 32];
        let pubk = public_key_from_seed(&seed);
        let mut blob = build_bundle(&seed, &[(b"/a", CTYPE_PLAIN, b"x")]);
        blob.truncate(blob.len() - 1);
        assert_eq!(verify_and_load(&blob, &pubk).err(), Some(PressError::Malformed));
    }

    /// Integration check against a real bundle produced by `tools/press-release.py` + `qs raw-sign`
    /// (not the in-test `build_bundle` helper above) -- run manually via:
    ///   PRESS_BUNDLE=/tmp/press-test.qpr PRESS_PUBKEY=<hex> cargo test -p pg-press -- --ignored
    /// Ignored by default since it depends on an external file/env this crate's own CI doesn't produce.
    #[test]
    #[ignore]
    fn verifies_real_packed_bundle() {
        let path = std::env::var("PRESS_BUNDLE").expect("set PRESS_BUNDLE");
        let pubkey_hex = std::env::var("PRESS_PUBKEY").expect("set PRESS_PUBKEY");
        let blob = std::fs::read(path).unwrap();
        let mut pubkey = [0u8; 32];
        for i in 0..32 {
            pubkey[i] = u8::from_str_radix(&pubkey_hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let m = verify_and_load(&blob, &pubkey).expect("bundle should verify");
        match m.lookup(Method::Get, b"/index.html") {
            Lookup::Found(i) => {
                let bytes = m.verify_and_get_bytes(i).expect("hash recheck should pass");
                assert!(bytes.starts_with(b"<!doctype html>"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_content_fails_hash_recheck_even_after_valid_signature() {
        // A bundle whose content was corrupted AFTER signing (simulating in-memory corruption after
        // the one boot-time signature check) must still be rejected per-file at serve time.
        let seed = [4u8; 32];
        let pubk = public_key_from_seed(&seed);
        let mut blob = build_bundle(&seed, &[(b"/a", CTYPE_PLAIN, b"original")]);
        // Flip a content byte without re-signing (simulates post-verification corruption, not a
        // re-signed malicious bundle -- the signature over the old bytes would now mismatch too,
        // but this test specifically exercises the independent per-file hash recheck).
        let content_start = HEADER_LEN + ENTRY_LEN;
        blob[content_start] ^= 0xff;
        // Signature now also fails to verify (expected -- the whole blob is signed); the hash
        // recheck is a *second* independent layer and is exercised via verify_and_get_bytes directly
        // against a manifest parsed from the uncorrupted blob but with a hand-corrupted hash field,
        // which we construct separately below.
        assert!(verify_and_load(&blob, &pubk).is_err());

        let mut blob2 = build_bundle(&seed, &[(b"/a", CTYPE_PLAIN, b"original")]);
        // Corrupt only the stored hash field (not the signed payload's content bytes), re-sign over
        // the corrupted header+table+content so verify_and_load's signature check passes, to isolate
        // the per-file hash recheck as the thing that must still catch the mismatch.
        let hash_field_off = HEADER_LEN + 72;
        blob2[hash_field_off] ^= 0xff;
        let sig_start = blob2.len() - SIG_LEN;
        let new_sig = sign_ed25519(&seed, &blob2[..sig_start]);
        blob2[sig_start..].copy_from_slice(&new_sig);
        let m = verify_and_load(&blob2, &pubk).unwrap();
        match m.lookup(Method::Get, b"/a") {
            Lookup::Found(i) => assert_eq!(m.verify_and_get_bytes(i), None),
            _ => panic!("expected Found"),
        }
    }
}
