"""f_theta: similarity embedder.

Lazy-loads a Sentence-Transformer (default `all-MiniLM-L6-v2`, 384-dim) and
embeds raw formula strings into the embedding space. Includes a per-instance
LRU cache (small) so repeated lookups avoid re-encoding.
"""

from collections import OrderedDict
from typing import Any, Optional

import numpy as np

from cdg_lib.neural.config import NeuralConfig


class Embedder:
    """Sentence-Transformer-based formula embedder."""

    def __init__(self, config: NeuralConfig, cache_size: int = 4096):
        self.config = config
        self._model: Optional[Any] = None
        self._cache: "OrderedDict[str, np.ndarray]" = OrderedDict()
        self._cache_size = cache_size

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        # Prefer fine-tuned local checkpoint when present; fall back to base.
        if self.config.embedder_path.is_file():
            self._model = SentenceTransformer(str(self.config.embedder_path.parent))
        else:
            self._model = SentenceTransformer(self.config.base_model)

    def embed(self, formula: str) -> np.ndarray:
        """Return the embedding for `formula` as a 1-D float32 numpy array."""
        if formula in self._cache:
            self._cache.move_to_end(formula)
            return self._cache[formula]
        self._ensure_loaded()
        vec = self._model.encode(
            formula or " ",  # avoid empty-string edge case in the underlying model
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        if len(self._cache) >= self._cache_size:
            self._cache.popitem(last=False)
        vec = np.asarray(vec, dtype=np.float32)
        self._cache[formula] = vec
        return vec

    def clear_cache(self) -> None:
        self._cache.clear()
