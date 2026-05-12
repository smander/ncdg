(set-logic QF_BV)
(declare-const len (_ BitVec 32))
(declare-const off (_ BitVec 32))
(assert (= off (bvmul len #x00000004)))
