(set-logic QF_BV)
(declare-const ptr (_ BitVec 64))
(declare-const ptr2 (_ BitVec 64))
(assert (= ptr2 (bvadd ptr #x0000000000000008)))
