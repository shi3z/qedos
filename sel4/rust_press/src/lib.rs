//! `#![no_std]` glue for the QEDOS Press Protection Domain (`qedos_press_pd`).
//!
//! Linked ONLY into `qedos_press_pd.elf`. Contains the signed-bundle verifier and lookup logic
//! (`pg-press`, `#![forbid(unsafe_code)]`); the C-ABI shims below are the only `unsafe` code, and they
//! are thin raw-pointer wrappers with no logic of their own.
#![no_std]

use core::panic::PanicInfo;
use pg_press::{method_from_u8, verify_and_load, Lookup, Manifest};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Pinned Ed25519 public key for QEDOS Press releases (dev key; see `config/keys/qedos-press-dev-*`
/// and `docs/QEDOS_PRESS_CMS.md` — NOT production-grade, generated in this repo for development only).
pub const PRESS_PUBLIC_KEY: [u8; 32] = [
    0x06, 0x5f, 0x8b, 0xa3, 0x5f, 0x97, 0x48, 0x05, 0xa2, 0xa6, 0x9c, 0xba, 0xcc, 0x32, 0x27, 0x07,
    0xe2, 0x74, 0xd6, 0xdd, 0x65, 0x5e, 0xc9, 0x49, 0xd9, 0xc0, 0xa6, 0x4c, 0xaa, 0xea, 0x69, 0x50,
];

static mut MANIFEST: Option<Manifest<'static>> = None;

/// Forget any loaded manifest. Called first in `init()` so a restarted PD never serves a manifest
/// left behind by a previous incarnation (not that one is expected -- see `docs/QEDOS_PRESS_CMS.md`'s
/// gap note: this PD has no supervisor/restart wiring in this phase, unlike `script_pd`).
#[no_mangle]
pub unsafe extern "C" fn pg_press_reset() {
    MANIFEST = None;
}

/// Verify the embedded signed release bundle. Returns the number of routes (>= 0) on success, or a
/// negative value if the bundle is malformed or its signature does not verify (fail closed: no route
/// is ever served from an unverified bundle).
#[no_mangle]
pub unsafe extern "C" fn pg_press_init(blob_ptr: *const u8, blob_len: usize) -> i32 {
    if blob_ptr.is_null() {
        return -1;
    }
    let blob: &'static [u8] = core::slice::from_raw_parts(blob_ptr, blob_len);
    match verify_and_load(blob, &PRESS_PUBLIC_KEY) {
        Ok(m) => {
            let n = m.len() as i32;
            MANIFEST = Some(m);
            n
        }
        Err(_) => -2,
    }
}

/// Handle one request. `status_out`/`ctype_out` are always set; the return value is the number of body
/// bytes copied into `out_ptr` (0 for HEAD or for any non-2xx outcome). GET/HEAD against a known path
/// re-verifies that file's SHA-512 against the manifest before copying any byte out (defense in depth
/// against post-boot corruption of the content region, independent of the one boot-time signature
/// check) -- a mismatch is served as 503, never as the mismatched bytes.
#[no_mangle]
pub unsafe extern "C" fn pg_press_handle(
    method_u8: u8,
    target_ptr: *const u8,
    target_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    status_out: *mut u16,
    ctype_out: *mut u8,
    content_len_out: *mut u32,
) -> usize {
    *content_len_out = 0;
    let method = method_from_u8(method_u8);
    let target = if target_len == 0 { &[][..] } else { core::slice::from_raw_parts(target_ptr, target_len) };
    // policy_pd forwards the request target unchanged (e.g. "/press/index.html"); the manifest's own
    // routes are mount-point-relative (e.g. "/index.html"). Strip the "/press" prefix here, at the PD
    // glue boundary -- pg-press's manifest format itself knows nothing about HTTP mount points.
    let path: &[u8] = match target.strip_prefix(b"/press") {
        Some(rest) if rest.is_empty() => b"/",
        Some(rest) if rest[0] == b'/' => rest,
        _ => {
            *status_out = 404;
            *ctype_out = 0;
            return 0;
        }
    };
    #[allow(static_mut_refs)]
    let m = match MANIFEST.as_ref() {
        Some(m) => m,
        None => {
            *status_out = 503;
            *ctype_out = 0;
            return 0;
        }
    };
    let idx = match m.lookup(method, path) {
        Lookup::Found(i) => i,
        Lookup::NotFound => {
            *status_out = 404;
            *ctype_out = 0;
            return 0;
        }
        Lookup::MethodNotAllowed => {
            *status_out = 405;
            *ctype_out = 0;
            return 0;
        }
    };
    let ctype = m.ctype(idx);
    *ctype_out = ctype;
    let bytes = match m.verify_and_get_bytes(idx) {
        Some(b) => b,
        None => {
            *status_out = 503;
            return 0;
        }
    };
    *status_out = 200;
    *content_len_out = bytes.len() as u32;
    if matches!(method, pg_press::Method::Head) {
        return 0; // body omitted for HEAD; content_len_out carries the true Content-Length.
    }
    let n = bytes.len().min(out_cap);
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    out[..n].copy_from_slice(&bytes[..n]);
    n
}
