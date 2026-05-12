(set-logic QF_BV)
(declare-const s (_ BitVec 64))
(declare-const t (_ BitVec 64))
(assert (= t (bvadd s #x0000000000000001)))
