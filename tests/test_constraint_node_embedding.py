import numpy as np

from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass


def _make_node():
    return ConstraintNode(
        node_id="c_1",
        formula="x < 100",
        formula_skeleton="(VAR u< CONST)",
        cwe_class=CWEClass.CWE_787,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1.0",
    )


def test_default_embedding_is_none():
    node = _make_node()
    assert node.embedding is None


def test_embedding_stores_numpy_array():
    node = _make_node()
    node.embedding = np.zeros(384, dtype=np.float32)
    assert node.embedding is not None
    assert node.embedding.shape == (384,)
    assert node.embedding.dtype == np.float32


def test_embedding_does_not_affect_skeleton_hash():
    """The hash that drives symbolic similarity must NOT depend on embedding."""
    a = _make_node()
    b = _make_node()
    a.embedding = np.zeros(384)
    assert a.skeleton_hash == b.skeleton_hash
