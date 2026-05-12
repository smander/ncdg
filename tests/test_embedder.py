import numpy as np
import pytest

from cdg_lib.neural.embedder import Embedder
from cdg_lib.neural.config import NeuralConfig


def test_embedder_lazy_loads():
    """Constructor must not load the underlying model."""
    cfg = NeuralConfig()
    e = Embedder(cfg)
    assert e._model is None  # not loaded yet


def test_embed_returns_correct_shape():
    cfg = NeuralConfig()
    e = Embedder(cfg)
    vec = e.embed("x < 100")
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (cfg.embedding_dim,)


def test_embed_caches_result():
    cfg = NeuralConfig()
    e = Embedder(cfg)
    v1 = e.embed("x < 100")
    v2 = e.embed("x < 100")
    # Cached -> same array (object identity OK; values must match)
    assert np.array_equal(v1, v2)


def test_embed_different_strings_differ():
    cfg = NeuralConfig()
    e = Embedder(cfg)
    a = e.embed("x < 100")
    b = e.embed("y > 200")
    assert not np.array_equal(a, b)


def test_embed_handles_empty_string():
    cfg = NeuralConfig()
    e = Embedder(cfg)
    vec = e.embed("")
    assert vec.shape == (cfg.embedding_dim,)
