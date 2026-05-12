import numpy as np

from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, EdgeLabel


class _FakeEmbedder:
    """Deterministic mapping: equal formulas -> equal vectors.

    Uses an explicit lookup table so cosine similarity between different
    formulas is provably 0 (orthogonal one-hots), not subject to Python's
    randomized string hash.
    """

    _SLOTS = {}

    def embed(self, formula):
        if formula not in self._SLOTS:
            # Each unique formula gets its own slot, no collisions.
            self._SLOTS[formula] = len(self._SLOTS)
        idx = self._SLOTS[formula]
        v = np.zeros(64, dtype=np.float32)
        v[idx % 64] = 1.0
        return v


def _node(formula, node_id="", cwe=CWEClass.UNKNOWN):
    # Use a unique skeleton per node so the existing skeleton-based
    # similarity (CDG._compute_similarity_edges) does NOT add SIM edges.
    # We're testing the NEW neural-embedding path explicitly.
    return ConstraintNode(
        node_id=node_id,
        formula=formula,
        formula_skeleton=f"unique:{formula}",
        cwe_class=cwe,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
    )


def test_identical_formulas_get_sim_edge():
    g = CDG()
    a = g.store(_node("x < 100", node_id="a"), [])
    b = g.store(_node("x < 100", node_id="b"), [])
    g.compute_neural_sim_edges(_FakeEmbedder(), tau_sim=0.5)
    assert any(e.label == EdgeLabel.SIM for e in g._adj.get(a, []))


def test_different_formulas_no_sim_edge():
    g = CDG()
    a = g.store(_node("x < 100", node_id="a"), [])
    b = g.store(_node("y > 200", node_id="b"), [])
    g.compute_neural_sim_edges(_FakeEmbedder(), tau_sim=0.5)
    sim_edges = [e for e in g._adj.get(a, []) if e.label == EdgeLabel.SIM]
    # Likely no SIM edge since their fake embeddings differ in slot 1
    # (could collide via hash but with 8 slots collisions are rare).
    assert sim_edges == [] or any(e.target_id == b for e in sim_edges) is False


def test_threshold_zero_connects_all_pairs():
    g = CDG()
    a = g.store(_node("x", node_id="a"), [])
    b = g.store(_node("y", node_id="b"), [])
    g.compute_neural_sim_edges(_FakeEmbedder(), tau_sim=-1.0)
    # tau=-1.0 means everything passes (cosine >= -1 always)
    a_sim = [e for e in g._adj.get(a, []) if e.label == EdgeLabel.SIM]
    assert len(a_sim) >= 1


def test_does_not_create_self_loops():
    g = CDG()
    a = g.store(_node("x < 100", node_id="a"), [])
    g.compute_neural_sim_edges(_FakeEmbedder(), tau_sim=-1.0)
    self_loops = [e for e in g._adj.get(a, [])
                  if e.label == EdgeLabel.SIM and e.target_id == a]
    assert self_loops == []


def test_no_embedder_is_noop():
    """When embedder is None, compute_neural_sim_edges does NOT add edges.

    Use formulas with distinct skeletons so the legacy skeleton-match
    SIM-edge path doesn't add edges either.
    """
    g = CDG()
    a = g.store(_node("x < 100", node_id="a"), [])
    b = g.store(_node("y > 200", node_id="b"), [])
    edges_before = len(g.edges)
    added = g.compute_neural_sim_edges(None, tau_sim=0.5)
    assert added == 0
    assert len(g.edges) == edges_before
