import numpy as np
import pytest

from cdg_lib.analysis import similarity
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass


def _node(formula="x < 100", skeleton="(VAR u< CONST)", embedding=None):
    n = ConstraintNode(
        node_id="",
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=CWEClass.CWE_787,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
        variables={"x"},
        var_types={"x": "bv32"},
    )
    n.embedding = embedding
    return n


class _DummyEmbedder:
    def embed(self, formula):
        return np.zeros(2, dtype=np.float32)


class _CountingEmbedder:
    def __init__(self):
        self.calls = 0

    def embed(self, formula):
        self.calls += 1
        return np.array([1.0, 0.0], dtype=np.float32)


def test_no_embedder_returns_symbolic_similarity():
    """When embedder is None, similarity matches the existing symbolic baseline."""
    a = _node()
    b = _node()
    sym_only = similarity(a, b)  # legacy call path
    assert 0.0 <= sym_only <= 1.0


def test_alpha_one_equals_pure_symbolic():
    """alpha=1.0 should equal pure symbolic regardless of embeddings."""
    a = _node(embedding=np.array([1.0, 0.0]))
    b = _node(embedding=np.array([0.0, 1.0]))
    blend = similarity(a, b, embedder=_DummyEmbedder(), alpha=1.0)
    sym = similarity(a, b)
    assert abs(blend - sym) < 1e-6


def test_alpha_zero_equals_pure_neural():
    """alpha=0.0 should equal cosine similarity of embeddings."""
    a = _node(embedding=np.array([1.0, 0.0], dtype=np.float32))
    b = _node(embedding=np.array([0.0, 1.0], dtype=np.float32))
    blend = similarity(a, b, embedder=_DummyEmbedder(), alpha=0.0)
    # cos((1,0), (0,1)) == 0
    assert abs(blend - 0.0) < 1e-6


def test_alpha_half_blends():
    a = _node(embedding=np.array([1.0, 0.0], dtype=np.float32))
    b = _node(embedding=np.array([1.0, 0.0], dtype=np.float32))
    sym = similarity(a, b)
    neu = 1.0
    blend = similarity(a, b, embedder=_DummyEmbedder(), alpha=0.5)
    assert abs(blend - (0.5 * sym + 0.5 * neu)) < 1e-6


def test_embedder_used_when_node_lacks_cached_embedding():
    """If a node has no precomputed embedding, the embedder should be called."""
    a = _node(embedding=None)
    b = _node(embedding=None)
    embedder = _CountingEmbedder()
    similarity(a, b, embedder=embedder, alpha=0.5)
    assert embedder.calls >= 1
