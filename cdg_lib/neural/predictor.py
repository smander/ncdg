"""g_phi: UNSAT predictor wrapper.

Lazy-loads the GNN, packages the local 1-hop CDG neighborhood as
(features, adj) tensors, returns P(UNSAT) in [0, 1].

Feature layout (per node):
    [f_theta_embedding (384), cwe_onehot (4), formula_len_norm (1),
     var_count_norm (1), is_trigger (1)]

When the node has no precomputed `embedding`, the predictor zero-pads that
slot — at inference time you typically pre-populate embeddings via the
Embedder so this path is rare.
"""

from typing import List, Optional

import numpy as np

from cdg_lib.types import CWEClass, EdgeLabel
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.gnn_model import FEATURE_DIM, UnsatGNN
from cdg_lib.neural.reachability import has_trigger_pattern


_CWE_ORDER = [CWEClass.CWE_125, CWEClass.CWE_787, CWEClass.CWE_416, CWEClass.CWE_190]


def _cwe_onehot(cwe: CWEClass) -> np.ndarray:
    vec = np.zeros(len(_CWE_ORDER), dtype=np.float32)
    if cwe in _CWE_ORDER:
        vec[_CWE_ORDER.index(cwe)] = 1.0
    return vec


def _node_features(node) -> np.ndarray:
    if node.embedding is not None:
        emb = np.asarray(node.embedding, dtype=np.float32)
        if emb.shape[0] != 384:
            emb = np.zeros(384, dtype=np.float32)
    else:
        emb = np.zeros(384, dtype=np.float32)
    cwe = _cwe_onehot(node.cwe_class)
    formula_len = float(min(len(node.formula or ""), 1000)) / 1000.0
    var_count = float(min(len(node.variables or set()), 50)) / 50.0
    trigger = 1.0 if has_trigger_pattern(node) else 0.0
    feats = np.concatenate([
        emb, cwe,
        np.array([formula_len, var_count, trigger], dtype=np.float32),
    ])
    return feats


class UnsatPredictor:
    """g_phi: predicts P(UNSAT) over a CDG node's 1-hop neighborhood."""

    def __init__(self, config: NeuralConfig):
        self.config = config
        self._model: Optional[UnsatGNN] = None

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        import torch
        self._model = UnsatGNN()
        if self.config.predictor_path.is_file():
            state = torch.load(str(self.config.predictor_path), map_location="cpu")
            self._model.load_state_dict(state)
        self._model.eval()

    def _build_neighborhood(self, node, graph):
        """Return (feature_matrix, adj_matrix, target_index)."""
        node_id = node.node_id
        # 1-hop in either direction over DEP/SIM
        neighbors: List = [node_id]
        seen = {node_id}
        for edge in graph._adj.get(node_id, []) + graph._radj.get(node_id, []):
            if edge.label not in (EdgeLabel.DEP, EdgeLabel.SIM):
                continue
            other_id = edge.target_id if edge.source_id == node_id else edge.source_id
            if other_id not in seen and other_id in graph.nodes:
                seen.add(other_id)
                neighbors.append(other_id)

        feats = np.stack([_node_features(graph.nodes[nid]) for nid in neighbors])
        n = len(neighbors)
        adj = np.eye(n, dtype=np.float32)
        idx_of = {nid: i for i, nid in enumerate(neighbors)}
        for i, nid in enumerate(neighbors):
            for edge in graph._adj.get(nid, []):
                if edge.label not in (EdgeLabel.DEP, EdgeLabel.SIM):
                    continue
                if edge.target_id in idx_of:
                    j = idx_of[edge.target_id]
                    adj[i, j] = 1.0
                    adj[j, i] = 1.0
        return feats, adj, 0  # target node is always at index 0

    def predict(self, node, graph) -> float:
        """Return P(UNSAT) for `node` given its 1-hop CDG neighborhood."""
        self._ensure_loaded()
        import torch
        feats, adj, target_idx = self._build_neighborhood(node, graph)
        with torch.no_grad():
            x = torch.from_numpy(feats)
            a = torch.from_numpy(adj)
            target = torch.tensor([target_idx], dtype=torch.long)
            prob = self._model(x, a, target_idx=target)
        return float(prob.item())
