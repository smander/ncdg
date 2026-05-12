(set-logic QF_BV)
(declare-const v (_ BitVec 32))
(declare-const u (_ BitVec 32))
(assert (= u (bvadd v #x00000001)))
