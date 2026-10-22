//! `#![no_std]` glue for the QED Script Protection Domain (`script_pd`).
//!
//! This staticlib is linked ONLY into `script_pd.elf`. It contains the Wasm interpreter, the signed
//! bundle verifier and the policy/KV code — none of which is linked into any other PD, so a bug in the
//! interpreter cannot corrupt `tls_pd`'s key store even before the MMU is considered.
//!
//! Trust note: the C-ABI shims below are `unsafe` (raw pointers from the C PD glue); all logic they call
//! lives in `#![forbid(unsafe_code)]` crates.
#![no_std]

use core::panic::PanicInfo;
use pg_http::Method;
use pg_script::{execute, Method as SMethod, NoClock, Reason, Request};
use pg_script_policy::{route::script_route, Kv};
use pg_script_verify::{bundles::ScriptSet, CODE_SIGNING_PUBLIC_KEY};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // A panic (should be unreachable: overflow-checks on, forbid(unsafe) logic) parks the PD. The kernel
    // keeps scheduling every other PD; script requests are answered 503 by policy_pd's busy gate.
    loop {
        core::hint::spin_loop();
    }
}

static mut SET: Option<ScriptSet<'static>> = None;
static mut KV: Kv = Kv::new();

/// Forget every verified script and all KV state. Called first in `init()` so that a restarted PD (after a fault or a
/// watchdog restart, where .data/.bss are NOT reloaded) never runs on state left behind by the previous incarnation.
#[no_mangle]
pub unsafe extern "C" fn pg_script_reset() {
    SET = None;
    KV = Kv::new();
}

/// Verify the embedded `QSB1` bundle table. Returns the number of *verified* scripts (>= 0), or a
/// negative value if the container is malformed. Unverified entries never become executable.
#[no_mangle]
pub unsafe extern "C" fn pg_script_init(blob_ptr: *const u8, blob_len: usize, rejected_out: *mut u32) -> i32 {
    if blob_ptr.is_null() {
        return -1;
    }
    let blob: &'static [u8] = core::slice::from_raw_parts(blob_ptr, blob_len);
    match ScriptSet::load(blob, &CODE_SIGNING_PUBLIC_KEY) {
        Ok(set) => {
            let n = set.len() as i32;
            if !rejected_out.is_null() {
                *rejected_out = set.rejected as u32;
            }
            SET = Some(set);
            n
        }
        Err(_) => -2,
    }
}

/// Handle one request. Returns the response body length written to `out_ptr`; `status_out`,
/// `ctype_out` (0 json, 1 html, 2 text) and `reason_out` (internal diagnostic code, for the serial log
/// only; never sent to clients) are filled. Unknown module => 404, no module executed.
#[no_mangle]
pub unsafe extern "C" fn pg_script_handle(
    method_u8: u8,
    target_ptr: *const u8,
    target_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    mem_ptr: *mut u8,
    mem_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    status_out: *mut u16,
    ctype_out: *mut u8,
    reason_out: *mut u32,
) -> usize {
    let (method, smethod) = match method_u8 {
        0 => (Method::Get, SMethod::Get),
        2 => (Method::Post, SMethod::Post),
        _ => {
            *status_out = 405;
            return 0;
        }
    };
    let target = core::slice::from_raw_parts(target_ptr, target_len);
    let body: &[u8] = if body_len == 0 { &[] } else { core::slice::from_raw_parts(body_ptr, body_len) };
    let mem = core::slice::from_raw_parts_mut(mem_ptr, mem_len);
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);

    let st = match script_route(method, target) {
        Some(t) => t,
        None => {
            *status_out = 404;
            return 0;
        }
    };
    #[allow(static_mut_refs)]
    let set = match SET.as_ref() {
        Some(s) => s,
        None => {
            *status_out = 503;
            return 0;
        }
    };
    let script = match set.find(st.module) {
        Some(s) => s,
        None => {
            *status_out = 404;
            return 0;
        }
    };
    let req = Request {
        method: smethod,
        path: st.path,
        query: st.query,
        content_type: b"",
        user_agent: b"",
        body,
        principal: 0, // authentication is a later stage: scripts see an anonymous principal => KV denied
    };
    #[allow(static_mut_refs)]
    let kv = &mut KV;
    let o = execute(script.module(), script.policy(), &req, kv, mem, out, NoClock);
    *status_out = o.status;
    *ctype_out = o.content_type;
    *reason_out = match o.reason {
        Reason::Ok => 0,
        Reason::RequestTooLarge => 1,
        Reason::Load(_) => 2,
        Reason::Trap(_) => 3,
        Reason::ScriptExit(_) => 4,
        Reason::ResponseTooLarge => 5,
        Reason::BadStatus => 6,
    };
    o.body_len
}
