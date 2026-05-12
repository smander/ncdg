(set-logic QF_BV)
(declare-const c (_ BitVec 8))
(declare-const d (_ BitVec 8))
(assert (= d (bvadd c #x01)))
