"""Small GNN for UNSAT prediction over CDG neighborhoods.

Architecture: 3-layer GCN with ReLU activations, followed by a 2-layer MLP
head that produces a single P(UNSAT) probability via sigmoid. Designed for
CPU-only inference at runtime; training is on GPU when available.

Input per node: feature vector of dim FEATURE_DIM (default 384 + 4 + 3 = 391):
    [f_theta_embedding (384), cwe_onehot (4), formula_len_norm (1),
     var_count_norm (1), is_trigger (1)]

Note: this module is the pure model. The wrapper that consumes a CDG
neighborhood and packages features lives in `predictor.py`.
"""

from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F


# Feature layout:
#   - embedding: 384
#   - cwe one-hot (CWE_125, CWE_787, CWE_416, CWE_190): 4
#   - formula_len_normalized: 1
#   - var_count_normalized: 1
#   - is_trigger (1.0 if has_trigger_pattern else 0.0): 1
FEATURE_DIM = 384 + 4 + 1 + 1 + 1   # = 391


class _GCNLayer(nn.Module):
    """Plain message-passing layer: aggregate neighbors via mean, then linear."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        # x: (N, in_dim) ; adj: (N, N) symmetric, includes self-loops
        deg = adj.sum(dim=1, keepdim=True).clamp(min=1)
        agg = (adj @ x) / deg
        return self.linear(agg)


class UnsatGNN(nn.Module):
    """3-layer GCN with classifier head."""

    def __init__(self, hidden_dim: int = 128, in_dim: int = FEATURE_DIM):
        super().__init__()
        self.gcn1 = _GCNLayer(in_dim, hidden_dim)
        self.gcn2 = _GCNLayer(hidden_dim, hidden_dim)
        self.gcn3 = _GCNLayer(hidden_dim, hidden_dim)
        self.fc1 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.fc2 = nn.Linear(hidden_dim // 2, 1)

    def forward(self, x: torch.Tensor, adj: torch.Tensor,
                target_idx: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Return P(UNSAT) for each node (or only target_idx subset)."""
        h = F.relu(self.gcn1(x, adj))
        h = F.relu(self.gcn2(h, adj))
        h = F.relu(self.gcn3(h, adj))
        if target_idx is not None:
            h = h[target_idx]
        h = F.relu(self.fc1(h))
        out = torch.sigmoid(self.fc2(h)).squeeze(-1)
        return out


def count_params(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters() if p.requires_grad)
