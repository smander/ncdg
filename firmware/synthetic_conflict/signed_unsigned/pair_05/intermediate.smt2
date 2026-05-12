(set-logic QF_BV)
(declare-const v (_ BitVec 64))
(declare-const w (_ BitVec 64))
(assert (= w (bvadd v #x0000000000000001)))
