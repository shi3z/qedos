//! Kani harnesses for pg-script-proofcheck.
use super::*;

/// The first instruction being LOOP/CALL/CALL_INDIRECT always rejects, in a single pass (no need to unwind the
/// outer scan loop at all: the function returns on its very first iteration).
#[kani::proof]
#[kani::unwind(5)]
fn first_instruction_loop_or_call_rejects_immediately() {
    let next: u8 = kani::any(); // byte right after the opcode; only CALL/CALL_INDIRECT read it (as a LEB start)
    for o in [op::LOOP, op::CALL, op::CALL_INDIRECT] {
        let code = [o, next, 0x00, 0x0B];
        assert!(straight_line_instr_count(&code).is_err());
    }
}

/// A single already-closed BLOCK whose contents are plain numeric ops (no LOOP/CALL and all branch targets
/// trivially in range) is accepted with the exact instruction count. Fixed-shape input: this checks the
/// counting arithmetic itself, not the general scan (that is exercised by the fuzz test in tests.rs and by the
/// end-to-end differential run against V8 on modules built the normal way).
#[kani::proof]
#[kani::unwind(5)]
fn flat_block_count_is_exact() {
    // BLOCK(void) ; I32_CONST <next> ; END ; END   == 4 instructions (BLOCK, CONST, END, outer END-of-handle)
    // `next` is restricted to i32.const's single-byte LEB range so the immediate does not spill into the
    // following END byte (a 2-byte-LEB `next` is exercised instead by the fuzz test in tests.rs, on real modules).
    let next: i8 = kani::any();
    kani::assume(next >= 0); // next as u8 must have its high bit clear (single-byte LEB)
    let code = [op::BLOCK, 0x40, op::I32_CONST, next as u8, op::END, op::END];
    assert_eq!(straight_line_instr_count(&code), Ok(4));
}

/// A BR whose target depth exceeds the currently open block nesting is rejected (the out-of-range check), for
/// nesting depth 0 or 1 and target 0 or 1 (the full 0..3 x 0..3 sweep is checked cheaply by a plain Rust loop
/// in tests::debug_branch_depth_combos instead; CBMC's cost grows too fast with this function's branching to
/// cover the wider range here).
#[kani::proof]
#[kani::unwind(6)]
fn branch_depth_is_checked() {
    let depth_opens: u8 = kani::any_where(|d: &u8| *d <= 1);
    let target: u8 = kani::any_where(|t: &u8| *t <= 1);
    // `depth_opens` nested BLOCKs, then BR <target>, then matching ENDs, then the function's own END.
    let mut code = [op::END; 12];
    let mut p = 0;
    for _ in 0..depth_opens {
        code[p] = op::BLOCK;
        code[p + 1] = 0x40;
        p += 2;
    }
    code[p] = op::BR;
    code[p + 1] = target;
    p += 2;
    for _ in 0..depth_opens {
        code[p] = op::END;
        p += 1;
    }
    code[p] = op::END; // handle's own end
    let r = straight_line_instr_count(&code[..p + 1]);
    if target as u32 > depth_opens as u32 {
        assert!(r.is_err());
    } else {
        assert!(r.is_ok());
    }
}
