import numpy as np

from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.predictor import UnsatPredictor


def _node(formula, skeleton, cwe=CWEClass.CWE_787, embedding=None):
    n = ConstraintNode(
        node_id="",
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=cwe,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
        variables={"x"},
        var_types={"x": "bv32"},
    )
    n.embedding = embedding
    return n


def test_predictor_lazy_loads():
    p = UnsatPredictor(NeuralConfig())
    assert p._model is None


def test_predict_returns_probability_in_unit_interval():
    g = CDG()
    n = _node("len > 65535", "(VAR > CONST)",
              embedding=np.zeros(384, dtype=np.float32))
    nid = g.store(n, [])
    p = UnsatPredictor(NeuralConfig())
    prob = p.predict(g.nodes[nid], g)
    assert 0.0 <= prob <= 1.0


def test_predict_handles_node_without_embedding():
    """When the node lacks a precomputed embedding, predictor should still work."""
    g = CDG()
    n = _node("len > 65535", "(VAR > CONST)", embedding=None)
    nid = g.store(n, [])
    p = UnsatPredictor(NeuralConfig())
    prob = p.predict(g.nodes[nid], g)
    assert 0.0 <= prob <= 1.0


def test_predict_handles_isolated_node():
    g = CDG()
    n = _node("x", "(VAR)", embedding=np.zeros(384, dtype=np.float32))
    nid = g.store(n, [])
    p = UnsatPredictor(NeuralConfig())
    prob = p.predict(g.nodes[nid], g)
    assert 0.0 <= prob <= 1.0
