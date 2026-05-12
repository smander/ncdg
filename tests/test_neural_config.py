from pathlib import Path

from cdg_lib.neural.config import NeuralConfig


def test_default_config_values():
    cfg = NeuralConfig()
    assert cfg.alpha == 0.5
    assert cfg.tau_sim == 0.6
    assert cfg.embedding_dim == 384
    assert cfg.max_seq_len == 256
    assert cfg.nn_search_k == 20
    assert cfg.enable_neural is True


def test_paths_are_path_objects():
    cfg = NeuralConfig()
    assert isinstance(cfg.embedder_path, Path)
    assert isinstance(cfg.faiss_index_path, Path)


def test_config_is_frozen():
    """NeuralConfig is immutable so it can be safely shared across modules."""
    import pytest
    cfg = NeuralConfig()
    with pytest.raises((AttributeError, TypeError)):
        cfg.alpha = 0.9


def test_alpha_in_range_when_constructed():
    cfg = NeuralConfig(alpha=0.0)
    assert cfg.alpha == 0.0
    cfg = NeuralConfig(alpha=1.0)
    assert cfg.alpha == 1.0
