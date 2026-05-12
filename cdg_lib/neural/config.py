"""Configuration dataclass for NS-CDG neural components.

All hyperparameters live here. The Sentence-Transformer model name and the
FAISS index location are fixed; alpha (similarity blend), tau_sim, and
tau_unsat (Plan 2) are tunable.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NeuralConfig:
    embedder_path: Path = Path("models/embedder.pt")
    faiss_index_path: Path = Path("models/embedder.faiss")
    predictor_path: Path = Path("models/predictor.pt")  # Plan 2

    # Hyperparameters
    alpha: float = 0.5            # similarity blend: alpha * symbolic + (1-alpha) * neural
    tau_sim: float = 0.6          # SIM-edge threshold (symbolic baseline)
    tau_unsat: float = 0.95       # Plan 2
    nn_search_k: int = 20
    embedding_dim: int = 384
    max_seq_len: int = 256

    # Kill-switch — when False, all neural calls become no-ops and similarity
    # falls back to symbolic. Set via CLI flag --no-neural.
    enable_neural: bool = True

    # Sentence-Transformer base model (fine-tuned in scripts/train_embedder.py)
    base_model: str = "sentence-transformers/all-MiniLM-L6-v2"
