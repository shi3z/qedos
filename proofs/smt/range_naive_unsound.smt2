; Control experiment: the *naive* 32-bit check (what a buggy runtime might do) IS unsound.
; Expected result: sat (a wrap-around counterexample exists), demonstrating why checked_range uses 64 bits.
(set-logic QF_BV)
(declare-const base (_ BitVec 32))
(declare-const off  (_ BitVec 32))
(declare-const size (_ BitVec 32))
(declare-const len  (_ BitVec 32))
(define-fun end32 () (_ BitVec 32) (bvadd (bvadd base off) size))
(assert (bvule end32 len))
; ...yet the true (unbounded) end lies beyond len:
(assert (bvugt (bvadd (bvadd ((_ zero_extend 32) base) ((_ zero_extend 32) off)) ((_ zero_extend 32) size)) ((_ zero_extend 32) len)))
(check-sat)
