// C-ABI shims over pg-ipc. This file is `include!`d (not compiled as a crate) by sel4/rust_pds (the PD image)
// and by tests/ipc/hostffi (the ASan host harness), so both run the SAME wrapper code.
// All decisions live in the `#![forbid(unsafe_code)]` crate `pg_ipc`; the only `unsafe` here is dereferencing the
// pointers the C glue passes (non-null is checked, lengths are fixed by the types).
use pg_ipc::{InFlight, ScriptHeader, MAX_CONNS};

#[no_mangle]
pub unsafe extern "C" fn pg_ipc_inflight_init(f: *mut InFlight) {
    if !f.is_null() {
        *f = InFlight::new();
    }
}

/// `ids` points at `MAX_CONNS` u32 connection generations. Returns 1 if armed.
#[no_mangle]
pub unsafe extern "C" fn pg_ipc_inflight_record(f: *mut InFlight, slot: u8, ids: *const u32) -> u8 {
    if f.is_null() || ids.is_null() {
        return 0;
    }
    let ids: &[u32; MAX_CONNS] = &*(ids as *const [u32; MAX_CONNS]);
    (*f).record(slot, ids) as u8
}

/// Returns 1 iff the response for `slot` may be delivered now (and consumes the in-flight request).
#[no_mangle]
pub unsafe extern "C" fn pg_ipc_inflight_accept(f: *mut InFlight, slot: u8, ids: *const u32) -> u8 {
    if f.is_null() || ids.is_null() {
        return 0;
    }
    let ids: &[u32; MAX_CONNS] = &*(ids as *const [u32; MAX_CONNS]);
    (*f).accept(slot, ids) as u8
}

#[no_mangle]
pub unsafe extern "C" fn pg_ipc_inflight_cancel_slot(f: *mut InFlight, slot: u8) {
    if !f.is_null() {
        (*f).cancel_slot(slot);
    }
}

#[no_mangle]
pub extern "C" fn pg_ipc_ring_can_write(head: u32, tail: u32, cap: u32, len: u32) -> u8 {
    pg_ipc::ring_can_write(head, tail, cap, len) as u8
}

#[no_mangle]
pub extern "C" fn pg_ipc_script_header_ok(status: u16, ctype: u8, body_len: u32, max_body: u32) -> u8 {
    pg_ipc::script_header_ok(&ScriptHeader { status, ctype, body_len }, max_body) as u8
}
