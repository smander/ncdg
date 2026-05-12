import numpy as np
import pytest

from cdg_lib.neural.index import FaissIndex


def _norm_rows(x: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(x, axis=1, keepdims=True)
    n[n == 0] = 1
    return x / n


def test_build_and_search_returns_self_first():
    rng = np.random.default_rng(0)
    vecs = _norm_rows(rng.standard_normal((20, 384)).astype(np.float32))
    idx = FaissIndex(dim=384)
    idx.build(vecs)
    distances, indices = idx.search(vecs[0], k=3)
    assert indices[0] == 0   # closest to itself


def test_search_returns_k_results():
    rng = np.random.default_rng(1)
    vecs = _norm_rows(rng.standard_normal((50, 384)).astype(np.float32))
    idx = FaissIndex(dim=384)
    idx.build(vecs)
    _, indices = idx.search(vecs[10], k=5)
    assert len(indices) == 5


def test_persist_and_load(tmp_path):
    rng = np.random.default_rng(2)
    vecs = _norm_rows(rng.standard_normal((30, 384)).astype(np.float32))
    idx = FaissIndex(dim=384)
    idx.build(vecs)
    out = tmp_path / "test.faiss"
    idx.save(out)
    idx2 = FaissIndex(dim=384)
    idx2.load(out)
    _, ind1 = idx.search(vecs[0], k=3)
    _, ind2 = idx2.search(vecs[0], k=3)
    assert list(ind1) == list(ind2)


def test_search_on_empty_index_returns_empty():
    idx = FaissIndex(dim=384)
    distances, indices = idx.search(np.zeros(384, dtype=np.float32), k=5)
    assert len(indices) == 0
