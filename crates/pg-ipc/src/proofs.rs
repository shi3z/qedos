//! Kani harnesses for pg-ipc. All inputs are fully symbolic (every u8/u16/u32 bit pattern); there are no loops,
//! so no unwinding bound limits these results. Scope: the Rust functions in this crate. The C glue that calls
//! them (copying shared-memory scalars into locals, performing the delivery) is NOT covered by these proofs.
use super::*;

fn any_inflight() -> InFlight {
    InFlight { active: kani::any(), slot: kani::any(), _pad: [0; 2], conn_id: kani::any() }
}
fn any_ids() -> [u32; MAX_CONNS] {
    kani::any()
}

/// accept() = true implies: a request was armed, the claimed slot is the armed slot, in range, its connection
/// generation is non-zero and unchanged; and the request is consumed.
#[kani::proof]
fn accept_true_implies_matching_live_request() {
    let mut f = any_inflight();
    let before = f;
    let (s, ids): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
    if f.accept(s, &ids) {
        assert!(before.active != 0);
        assert!(s == before.slot);
        assert!((s as usize) < MAX_CONNS);
        assert!(ids[s as usize] != 0 && ids[s as usize] == before.conn_id);
        assert!(f.active == 0);
    }
    kani::cover!(f.active == 0 && before.active != 0, "a delivery is reachable (non-vacuous)");
}

/// accept() = false never changes the state.
#[kani::proof]
fn accept_false_is_a_no_op() {
    let mut f = any_inflight();
    let before = f;
    let (s, ids): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
    if !f.accept(s, &ids) {
        assert!(f == before);
    }
}

/// One-shot: after a successful accept, no input (same or different) is accepted again until re-armed.
#[kani::proof]
fn accept_is_one_shot() {
    let mut f = any_inflight();
    let (s, ids): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
    if f.accept(s, &ids) {
        let (s2, ids2): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
        assert!(!f.accept(s2, &ids2));
    }
}

/// record() arms only a valid, live slot, and arms it exactly; otherwise nothing changes.
#[kani::proof]
fn record_arms_exactly_the_requested_live_slot() {
    let mut f = any_inflight();
    let before = f;
    let (s, ids): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
    if f.record(s, &ids) {
        assert!((s as usize) < MAX_CONNS && ids[s as usize] != 0);
        assert!(f.active == 1 && f.slot == s && f.conn_id == ids[s as usize]);
    } else {
        assert!(f == before);
    }
}

/// A response for a slot whose connection was replaced (generation changed) is never accepted.
#[kani::proof]
fn replaced_connection_never_receives_stale_response() {
    let mut f = InFlight::new();
    let (s, mut ids): (u8, [u32; MAX_CONNS]) = (kani::any(), any_ids());
    if f.record(s, &ids) {
        let new_id: u32 = kani::any();
        kani::assume(new_id != ids[s as usize]);
        ids[s as usize] = new_id;
        assert!(!f.accept(s, &ids));
    }
}

/// Ring arithmetic: for every (peer-controlled) head/tail pair and every capacity, a permitted write never
/// exceeds the free space, so it cannot overwrite unread bytes; inconsistent states refuse every write.
#[kani::proof]
fn ring_write_never_overruns() {
    let (head, tail, cap, len): (u32, u32, u32, u32) = (kani::any(), kani::any(), kani::any(), kani::any());
    if ring_can_write(head, tail, cap, len) {
        let used = head.wrapping_sub(tail);
        assert!(used <= cap);
        assert!(len as u64 + used as u64 <= cap as u64);
    }
    if head.wrapping_sub(tail) > cap {
        assert!(!ring_can_write(head, tail, cap, len));
    }
    kani::cover!(ring_can_write(head, tail, cap, len) && len > 0, "a non-empty write is permitted");
}

/// Every ring position is inside the buffer (cap > 0), for every u32 index.
#[kani::proof]
fn ring_pos_in_bounds() {
    let (idx, cap): (u32, u32) = (kani::any(), kani::any());
    kani::assume(cap > 0);
    assert!(ring_pos(idx, cap) < cap);
}

/// A copy of `n` bytes starting at the position of `head` in a power-of-two ring stays inside the buffer when
/// split at the wrap point (the usual two-memcpy scheme).
#[kani::proof]
fn ring_two_part_copy_in_bounds() {
    let (head, n): (u32, u32) = (kani::any(), kani::any());
    let cap: u32 = 1u32 << kani::any_where(|s: &u32| *s <= 20);
    kani::assume(n <= cap);
    let pos = ring_pos(head, cap);
    let first = core::cmp::min(n, cap - pos);
    let second = n - first;
    assert!(pos as u64 + first as u64 <= cap as u64);
    assert!(second <= pos); // the wrapped remainder ends at or before the start position: no overlap with itself
}

/// clamp_len never exceeds its bound and is the identity below it.
#[kani::proof]
fn clamp_len_is_a_clamp() {
    let (len, max): (u32, u32) = (kani::any(), kani::any());
    let c = clamp_len(len, max);
    assert!(c <= max || len <= max && c == len);
    assert!(c <= len);
    if len <= max {
        assert!(c == len);
    }
}

/// Script header validation: acceptance implies every property the HTTP framing relies on.
#[kani::proof]
fn script_header_acceptance_implies_safe_framing() {
    let h = ScriptHeader { status: kani::any(), ctype: kani::any(), body_len: kani::any() };
    let max: u32 = kani::any();
    if script_header_ok(&h, max) {
        assert!(h.status >= 200 && h.status <= 599);
        assert!(h.ctype <= 2);
        assert!(h.body_len <= max);
        assert!(!((h.status == 204 || h.status == 205 || h.status == 304) && h.body_len > 0));
    }
    kani::cover!(script_header_ok(&h, max), "an acceptable header exists (non-vacuous)");
}
