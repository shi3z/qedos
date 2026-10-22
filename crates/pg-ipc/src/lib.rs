//! IPC decision logic shared by the C protection-domain glue (via `sel4/rust_pds`).
//!
//! Every value that arrives through shared memory is untrusted (the writer may be a compromised PD). The C
//! glue copies such values ONCE into locals and asks these functions what to do; the functions are total (they
//! accept every possible bit pattern), `#![forbid(unsafe_code)]`, allocation-free, and verified with Kani over the
//! whole input domain (`proofs.rs`, no length or unwinding bound is needed because nothing here loops over data).
//!
//! Protocol model (see docs/IPC_VERIFICATION.md): one request is in flight per downstream service. The requesting
//! PD (`http_pd`) records `(slot, connection generation)` when the policy decision hands the request over, and
//! accepts exactly one response for exactly that pair; anything else is dropped.
#![no_std]
#![forbid(unsafe_code)]

pub const MAX_CONNS: usize = 4;

/// The single in-flight downstream request as seen by the requester. `repr(C)` so the C glue can hold it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InFlight {
    pub active: u8,
    pub slot: u8,
    pub _pad: [u8; 2],
    pub conn_id: u32,
}

impl InFlight {
    pub const fn new() -> InFlight {
        InFlight { active: 0, slot: 0, _pad: [0; 2], conn_id: 0 }
    }

    /// Arm for `slot`. Refuses (returns false, state unchanged) for an out-of-range slot or an unused
    /// connection (generation 0): there is nothing a response could legitimately be addressed to.
    pub fn record(&mut self, slot: u8, conn_ids: &[u32; MAX_CONNS]) -> bool {
        if (slot as usize) >= MAX_CONNS || conn_ids[slot as usize] == 0 {
            return false;
        }
        self.active = 1;
        self.slot = slot;
        self.conn_id = conn_ids[slot as usize];
        true
    }

    /// May a response claiming `slot` be delivered right now? If yes the request is consumed (one-shot).
    /// Every other input leaves the state untouched.
    pub fn accept(&mut self, slot: u8, conn_ids: &[u32; MAX_CONNS]) -> bool {
        if self.active == 0
            || slot != self.slot
            || (slot as usize) >= MAX_CONNS
            || conn_ids[slot as usize] == 0
            || conn_ids[slot as usize] != self.conn_id
        {
            return false;
        }
        self.active = 0;
        true
    }

    /// The connection in `slot` went away: forget the request addressed to it.
    pub fn cancel_slot(&mut self, slot: u8) {
        if self.active != 0 && self.slot == slot {
            self.active = 0;
        }
    }
}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes currently held in a free-running-index ring (indices are u32 and wrap). A peer-controlled index pair
/// can claim more than `cap` bytes; such an inconsistent state is reported as `None`.
pub fn ring_used(head: u32, tail: u32, cap: u32) -> Option<u32> {
    let used = head.wrapping_sub(tail);
    if used > cap {
        None
    } else {
        Some(used)
    }
}

/// May `len` bytes be appended at `head` without overwriting unread data? False for inconsistent index pairs.
pub fn ring_can_write(head: u32, tail: u32, cap: u32, len: u32) -> bool {
    match ring_used(head, tail, cap) {
        Some(used) => len <= cap - used,
        None => false,
    }
}

/// Position of free-running index `idx` inside a buffer of `cap` bytes. `cap` must be non-zero.
pub fn ring_pos(idx: u32, cap: u32) -> u32 {
    if cap == 0 {
        0
    } else {
        idx % cap
    }
}

/// Clamp a length that came from shared memory to the size of the buffer it indexes.
pub fn clamp_len(len: u32, max: u32) -> u32 {
    if len > max {
        max
    } else {
        len
    }
}

/// Header of a script result as read (once) from `shm_script_http`.
#[derive(Clone, Copy, Debug)]
pub struct ScriptHeader {
    pub status: u16,
    pub ctype: u8,
    pub body_len: u32,
}

/// Is this a response the requester is willing to frame? Statuses 1xx would desynchronise the client's HTTP
/// parser; 204/205/304 must not carry a body; content types are a 3-valued selector.
pub fn script_header_ok(h: &ScriptHeader, max_body: u32) -> bool {
    (200..=599).contains(&h.status)
        && h.ctype <= 2
        && h.body_len <= max_body
        && !(matches!(h.status, 204 | 205 | 304) && h.body_len > 0)
}

/// What the supervisor must do after looking at the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchAction {
    /// nothing to do
    Nothing,
    /// arm a one-shot timer that fires after the given number of nanoseconds, then call `step` again
    ArmTimer(u64),
    /// the watched request is overdue (or the child faulted): restart the script PD and abort the request
    Restart,
}

/// Wall-clock watchdog for the single script request that may be in flight.
///
/// Inputs come from a shared page written by `http_pd` (`armed_seq`, `done_seq`: a request is pending iff they
/// differ) and from a monotonic clock. Every input is untrusted bits; the only conclusions drawn are "pending or not",
/// "is this the request I started the clock for", and "is the deadline reached". A compromised `script_pd` cannot reach
/// these inputs at all (it has no mapping of the page and no channel to the supervisor).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watchdog {
    pub watching: u8,
    pub seq: u32,
    pub deadline_ns: u64,
}

impl Watchdog {
    pub const fn new() -> Watchdog {
        Watchdog { watching: 0, seq: 0, deadline_ns: 0 }
    }

    pub fn is_watching(&self) -> bool {
        self.watching != 0
    }

    /// Re-evaluate after any event (new request armed, request finished, timer fired, spurious wake-up).
    pub fn step(&mut self, armed_seq: u32, done_seq: u32, now_ns: u64, timeout_ns: u64) -> WatchAction {
        if armed_seq == done_seq {
            self.watching = 0; // nothing pending: stop the clock
            return WatchAction::Nothing;
        }
        if self.watching == 0 || self.seq != armed_seq {
            // a (new) request is pending: start its clock
            self.watching = 1;
            self.seq = armed_seq;
            self.deadline_ns = now_ns.saturating_add(timeout_ns);
            return WatchAction::ArmTimer(timeout_ns);
        }
        if now_ns >= self.deadline_ns {
            self.watching = 0;
            return WatchAction::Restart;
        }
        WatchAction::ArmTimer(self.deadline_ns - now_ns) // still pending, not yet due: re-arm for the remainder
    }

    /// The child faulted: restart regardless of timers; forget the request that was being watched.
    pub fn on_fault(&mut self) -> WatchAction {
        self.watching = 0;
        WatchAction::Restart
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_and_slot_bound() {
        let ids = [7, 0, 9, 0];
        let mut f = InFlight::new();
        assert!(!f.accept(0, &ids), "nothing in flight");
        assert!(f.record(2, &ids));
        assert!(!f.accept(0, &ids));
        assert!(!f.accept(200, &ids));
        assert!(f.accept(2, &ids));
        assert!(!f.accept(2, &ids), "second delivery refused");
        assert!(!f.record(1, &ids), "slot with generation 0 cannot be armed");
        assert!(!f.record(9, &ids));
    }

    #[test]
    fn generation_change_invalidates() {
        let mut f = InFlight::new();
        assert!(f.record(1, &[0, 5, 0, 0]));
        assert!(!f.accept(1, &[0, 6, 0, 0]), "slot reused by another connection");
        assert!(f.accept(1, &[0, 5, 0, 0]));
    }

    #[test]
    fn ring_arithmetic_wraps() {
        assert_eq!(ring_used(5, u32::MAX - 2, 16), Some(8));
        assert!(ring_can_write(5, u32::MAX - 2, 16, 8));
        assert!(!ring_can_write(5, u32::MAX - 2, 16, 9));
        assert!(!ring_can_write(100, 0, 16, 0), "inconsistent indices refuse even zero-length writes");
        assert_eq!(ring_pos(u32::MAX, 16384), 16383);
    }

    #[test]
    fn watchdog_restarts_only_overdue_pending_requests() {
        let mut w = Watchdog::new();
        assert_eq!(w.step(5, 5, 0, 100), WatchAction::Nothing, "idle");
        assert_eq!(w.step(6, 5, 1000, 100), WatchAction::ArmTimer(100), "request 6 pending: start clock");
        assert_eq!(w.step(6, 5, 1050, 100), WatchAction::ArmTimer(50), "early spurious wake-up: no restart");
        assert_eq!(w.step(6, 5, 1100, 100), WatchAction::Restart, "deadline reached");
        assert!(!w.is_watching());
        assert_eq!(w.step(6, 6, 1200, 100), WatchAction::Nothing, "restart marked the request done");
        // a slow request that completes in time is never restarted, even if a stale timer fires later
        assert_eq!(w.step(7, 6, 2000, 100), WatchAction::ArmTimer(100));
        assert_eq!(w.step(7, 7, 2050, 100), WatchAction::Nothing);
        assert_eq!(w.step(7, 7, 2500, 100), WatchAction::Nothing, "stale timer after completion");
        // saturation: absurd timeout never overflows
        assert_eq!(w.step(9, 7, u64::MAX - 1, u64::MAX), WatchAction::ArmTimer(u64::MAX));
        assert_eq!(w.on_fault(), WatchAction::Restart);
    }

    #[test]
    fn script_header_rules() {
        let ok = |status, ctype, body_len| script_header_ok(&ScriptHeader { status, ctype, body_len }, 16);
        assert!(ok(200, 0, 5) && ok(404, 2, 0) && ok(204, 0, 0));
        assert!(!ok(100, 0, 0) && !ok(99, 0, 0) && !ok(600, 0, 0) && !ok(204, 0, 1) && !ok(200, 3, 0) && !ok(200, 0, 17));
    }
}

#[cfg(kani)]
mod proofs;
