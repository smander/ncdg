"""
Constraint Dependency Graph: pure data container.

G = (C, E, Lambda) where:
  C = set of constraint nodes
  E subset C x C x Lambda = labeled edge set
  Lambda = {dep, con, sim}
"""

from typing import Optional, Set, Dict, List
from collections import defaultdict

from cdg_lib.types import EdgeLabel
from cdg_lib.models import ConstraintNode, CDGEdge


class CDG:
    """
    Constraint Dependency Graph — pure data container.

    Core operations:
      store(node, dep_sources) -> node_id   : Insert with induced edges
      _add_edge(src, tgt, label, meta)      : Add labeled edge (idempotent)
      _subgraph(node_ids) -> CDG            : Extract induced subgraph
    """

    def __init__(self, name: str = "cdg"):
        self.name = name
        self.nodes: Dict[str, ConstraintNode] = {}
        self.edges: List[CDGEdge] = []
        self._adj: Dict[str, List[CDGEdge]] = defaultdict(list)
        self._radj: Dict[str, List[CDGEdge]] = defaultdict(list)
        self._skeleton_index: Dict[str, Set[str]] = defaultdict(set)
        self._solve_cache: Dict[str, tuple] = {}
        self._node_counter = 0

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def _next_id(self) -> str:
        self._node_counter += 1
        return f"c_{self._node_counter:04d}"

    def store(self, node: ConstraintNode,
              dep_sources: Optional[List[str]] = None) -> str:
        """
        Store a constraint node in the CDG with induced edges.

        Returns the node_id.

        Property: Monotonicity — |C'| >= |C|, |E'| >= |E|
        """
        if not node.node_id:
            node.node_id = self._next_id()

        self.nodes[node.node_id] = node
        self._skeleton_index[node.skeleton_hash].add(node.node_id)

        if dep_sources:
            for src_id in dep_sources:
                if src_id in self.nodes:
                    self._add_edge(src_id, node.node_id, EdgeLabel.DEP)

        self._compute_similarity_edges(node)

        return node.node_id

    def _add_edge(self, src: str, tgt: str, label: EdgeLabel,
                  metadata: Optional[Dict] = None):
        """Add a labeled edge. Idempotent."""
        for e in self._adj[src]:
            if e.target_id == tgt and e.label == label:
                return

        edge = CDGEdge(src, tgt, label, metadata or {})
        self.edges.append(edge)
        self._adj[src].append(edge)
        self._radj[tgt].append(edge)

    def _compute_similarity_edges(self, node: ConstraintNode):
        """Find nodes with matching skeleton and add SIM edges."""
        # Import at function level to avoid circular dependency
        from cdg_lib.analysis import similarity

        matching_ids = self._skeleton_index.get(node.skeleton_hash, set())
        for other_id in matching_ids:
            if other_id != node.node_id:
                other = self.nodes[other_id]
                sim_score = similarity(node, other)
                if sim_score >= 0.8:
                    self._add_edge(node.node_id, other_id, EdgeLabel.SIM,
                                   {"sim_score": sim_score})
                    self._add_edge(other_id, node.node_id, EdgeLabel.SIM,
                                   {"sim_score": sim_score})

    def compute_neural_sim_edges(self, embedder, tau_sim: float = 0.6,
                                  max_pairs: int = 100000) -> int:
        """Add SIM edges between every node pair whose cosine similarity
        (over `embedder`-produced embeddings) exceeds `tau_sim`.

        Pairs are bidirectional. Self-loops are excluded. When `embedder` is
        None, this is a no-op (returns 0).

        Returns the number of SIM edges added.

        Note: O(N^2) over node pairs. For large graphs (N > sqrt(max_pairs))
        callers should use a FAISS-backed variant (build_faiss_index +
        nearest-neighbor search). This method is intentionally simple for
        small/medium graphs and tests.
        """
        import numpy as np
        if embedder is None:
            return 0

        node_ids = list(self.nodes.keys())
        if len(node_ids) > max_pairs ** 0.5:
            # Refuse to do the O(N^2) pass; callers should use FAISS.
            return 0

        # Cache embeddings once
        embeds = {}
        for nid in node_ids:
            node = self.nodes[nid]
            if node.embedding is None:
                node.embedding = embedder.embed(node.formula)
            embeds[nid] = np.asarray(node.embedding, dtype=np.float32)

        added = 0
        for i, a_id in enumerate(node_ids):
            ea = embeds[a_id]
            na = float(np.linalg.norm(ea))
            if na == 0.0:
                continue
            for b_id in node_ids[i + 1:]:
                eb = embeds[b_id]
                nb = float(np.linalg.norm(eb))
                if nb == 0.0:
                    continue
                cos = float(np.dot(ea, eb) / (na * nb))
                if cos >= tau_sim:
                    self._add_edge(a_id, b_id, EdgeLabel.SIM,
                                   metadata={"weight": cos})
                    self._add_edge(b_id, a_id, EdgeLabel.SIM,
                                   metadata={"weight": cos})
                    added += 2
        return added

    def _subgraph(self, node_ids: Set[str]) -> 'CDG':
        """Extract subgraph containing only specified nodes."""
        sub = CDG(name=f"{self.name}_slice")
        for nid in node_ids:
            if nid in self.nodes:
                sub.nodes[nid] = self.nodes[nid]
        for edge in self.edges:
            if edge.source_id in node_ids and edge.target_id in node_ids:
                sub.edges.append(edge)
                sub._adj[edge.source_id].append(edge)
                sub._radj[edge.target_id].append(edge)
        return sub

    def __repr__(self):
        return f"CDG(name={self.name}, nodes={self.node_count}, edges={self.edge_count})"
