(set-logic QF_BV)
(declare-const p (_ BitVec 32))
(declare-const q (_ BitVec 32))
(assert (= q (bvadd p #x00000001)))
