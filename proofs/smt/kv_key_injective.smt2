; LAW_021: namespaced storage key = principal(4 BE) || module(<=?, no 0x00) || 0x00 || key (no 0x00).
; Model: fixed-size layout, module and key each 3 bytes (bounded SMT model; variable-length ambiguity is covered by the exhaustive test namespaced_keys_injective_exhaustive_small_alphabet, not by this file).
; Claim: two distinct (principal, key) pairs with the same module produce different storage keys. Expected: unsat.
(set-logic QF_BV)
(declare-const p1 (_ BitVec 32)) (declare-const p2 (_ BitVec 32))
(declare-const k1 (_ BitVec 24)) (declare-const k2 (_ BitVec 24))
(declare-const m  (_ BitVec 24))
(define-fun nz ((x (_ BitVec 24))) Bool
  (and (distinct ((_ extract 7 0) x) #x00) (distinct ((_ extract 15 8) x) #x00) (distinct ((_ extract 23 16) x) #x00)))
(assert (and (nz k1) (nz k2) (nz m)))
(assert (or (distinct p1 p2) (distinct k1 k2)))
(define-fun sk ((p (_ BitVec 32)) (k (_ BitVec 24))) (_ BitVec 88) (concat p m #x00 k))
(assert (= (sk p1 k1) (sk p2 k2)))
(check-sat)
