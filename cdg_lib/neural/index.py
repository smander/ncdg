"""FAISS wrapper for nearest-neighbor search over formula embeddings.

Uses IndexFlatIP (inner product). Inputs are expected to be L2-normalized
upstream so inner product equals cosine similarity.
"""

from pathlib import Path
from typing import Tuple

import numpy as np


class FaissIndex:
    """Thin wrapper over faiss.IndexFlatIP."""

    def __init__(self, dim: int):
        self.dim = dim
        self._index = None  # lazy import for faster module load

    def _new_index(self):
        import faiss
        return faiss.IndexFlatIP(self.dim)

    def build(self, vectors: np.ndarray) -> None:
        """Build the index over `vectors`. Replaces any existing data."""
        if vectors.ndim != 2 or vectors.shape[1] != self.dim:
            raise ValueError(
                f"expected (n, {self.dim}) array, got shape {vectors.shape}"
            )
        self._index = self._new_index()
        # FAISS requires float32 contiguous.
        v = np.ascontiguousarray(vectors.astype(np.float32))
        self._index.add(v)

    def search(self, query: np.ndarray, k: int = 20) -> Tuple[np.ndarray, np.ndarray]:
        """Return (distances, indices) for the top-k matches."""
        if self._index is None or self._index.ntotal == 0:
            return np.array([]), np.array([], dtype=np.int64)
        q = np.ascontiguousarray(query.astype(np.float32).reshape(1, self.dim))
        d, i = self._index.search(q, min(k, self._index.ntotal))
        return d[0], i[0]

    def save(self, path: Path) -> None:
        import faiss
        if self._index is None:
            raise RuntimeError("index not built")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self._index, str(path))

    def load(self, path: Path) -> None:
        import faiss
        self._index = faiss.read_index(str(path))
        self.dim = self._index.d
