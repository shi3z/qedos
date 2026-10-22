; LAW_013: the effective-address check used by pg-script (wasm.rs::checked_range) is sound.
; Model: base, off, size are u32 (BV32), len is a usize (BV64). The code computes in 64 bits.
; Claim: if (zext(base)+zext(off)+zext(size) <= len) then start+size does not overflow 64 bits and
;        [start, start+size) is inside [0, len).  We assert the NEGATION; expected result: unsat.
(set-logic QF_BV)
(declare-const base (_ BitVec 32))
(declare-const off  (_ BitVec 32))
(declare-const size (_ BitVec 32))
(declare-const len  (_ BitVec 64))
(define-fun start () (_ BitVec 64) (bvadd ((_ zero_extend 32) base) ((_ zero_extend 32) off)))
(define-fun end   () (_ BitVec 64) (bvadd start ((_ zero_extend 32) size)))
(define-fun accepted () Bool (bvule end len))
; wrap-around of the 64-bit adds is impossible since each operand < 2^32:
(define-fun no_wrap () Bool (and (bvule start end) (bvule ((_ zero_extend 32) base) start)))
(assert (and accepted (not (and no_wrap (bvule end len) (bvule start end)))))
(check-sat)
