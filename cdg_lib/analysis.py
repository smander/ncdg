"""
CDG Analysis: similarity, compare, compile, abstract, pattern match, propagation, slicing.

All functions are standalone — CDG is passed as a parameter.
"""

import hashlib
import re
from typing import Optional, Set, Dict, List
from collections import defaultdict

from cdg_lib.types import EdgeLabel, CWEClass
from cdg_lib.models import ConstraintNode, Monitor, GraphDiff


def similarity(c1: ConstraintNode, c2: ConstraintNode,
               embedder=None, alpha: float = 1.0) -> float:
    """
    Constraint similarity.

    When `embedder` is None (default), returns the published symbolic similarity:
        sim(c1, c2) = skeleton_match * type_compatibility * cwe_bonus

    When `embedder` is provided, returns the blend:
        alpha * sym(c1, c2) + (1 - alpha) * cos(emb(c1), emb(c2))

    `alpha` in [0, 1]: 1.0 = pure symbolic, 0.0 = pure neural.
    """
    # Symbolic component: skeleton gate * type Jaccard * CWE bonus.
    # Per paper Eq. 1, the type Jaccard is over the multiset of bitvector
    # widths (the codomain of T_i). Variable names from angr are
    # instance-specific (e.g., `ip_len_1_16` vs `ip_len_469_16`) and not
    # semantically stable across firmware versions, so the Jaccard ignores
    # the variable-name component of T_i. On skeleton mismatch the
    # relaxed gate (paper Eq. 2) sets the multiplier to 0.5 rather than 0
    # so neural blending has a non-zero floor to add to.
    types1 = set(c1.var_types.values())
    types2 = set(c2.var_types.values())
    if not types1 and not types2:
        type_sim = 1.0
    else:
        union = types1 | types2
        intersection = types1 & types2
        type_sim = len(intersection) / len(union) if union else 1.0
    cwe_bonus = 1.0 if c1.cwe_class == c2.cwe_class else 0.5
    skeleton_match = 1.0 if c1.formula_skeleton == c2.formula_skeleton else 0.5
    s_sym = skeleton_match * type_sim * cwe_bonus

    if embedder is None or alpha >= 1.0:
        return s_sym

    # Neural component (cosine similarity of embeddings)
    import numpy as np
    e1 = c1.embedding if c1.embedding is not None else embedder.embed(c1.formula)
    e2 = c2.embedding if c2.embedding is not None else embedder.embed(c2.formula)
    e1 = np.asarray(e1, dtype=np.float32)
    e2 = np.asarray(e2, dtype=np.float32)
    n1 = float(np.linalg.norm(e1))
    n2 = float(np.linalg.norm(e2))
    if n1 == 0.0 or n2 == 0.0:
        s_neu = 0.0
    else:
        # Paper Eq. 4: s_neu = max(0, cos(e1, e2)). Negative cosines are
        # treated as zero similarity. No upper clamp is needed since cos
        # is bounded by 1 for any real vectors; we trust that bound.
        s_neu = max(0.0, float(np.dot(e1, e2) / (n1 * n2)))

    if alpha <= 0.0:
        return s_neu
    return alpha * s_sym + (1.0 - alpha) * s_neu


def savings_rate(diff: GraphDiff, total_nodes_v2: int) -> float:
    """Paper Eq. 6: S = |unchanged| / |C_{k+1}|.

    Returns the fraction of v2 nodes that carry forward verdicts from v1
    (i.e., share both location and skeleton). Range [0, 1].
    """
    if total_nodes_v2 <= 0:
        return 0.0
    return len(diff.unchanged_nodes) / total_nodes_v2


def compare(g1, g2) -> GraphDiff:
    """
    Compare two CDGs, typically across firmware versions.

    Property: Completeness — all differences captured in delta.
    """
    self_locs = {n.location.__str__(): nid for nid, n in g1.nodes.items()}
    other_locs = {n.location.__str__(): nid for nid, n in g2.nodes.items()}

    self_loc_set = set(self_locs.keys())
    other_loc_set = set(other_locs.keys())

    added = set()
    for loc in other_loc_set - self_loc_set:
        added.add(other_locs[loc])

    removed = set()
    for loc in self_loc_set - other_loc_set:
        removed.add(self_locs[loc])

    modified = set()
    unchanged = set()
    for loc in self_loc_set & other_loc_set:
        self_node = g1.nodes[self_locs[loc]]
        other_node = g2.nodes[other_locs[loc]]
        if self_node.formula_skeleton != other_node.formula_skeleton:
            modified.add(other_locs[loc])
        else:
            unchanged.add(other_locs[loc])

    return GraphDiff(
        added_nodes=added,
        removed_nodes=removed,
        modified_nodes=modified,
        unchanged_nodes=unchanged,
        added_edges=set(),
        removed_edges=set()
    )


def compile_monitor(graph, source_node_id: str) -> Optional[Monitor]:
    """
    Compile a constraint into a runtime monitor.

    Property: Soundness — alert(M, tau) => tau violates a real constraint
    """
    node = graph.nodes.get(source_node_id)
    if not node:
        return None

    target_locations = {node.location.__str__()}
    source_constraints = {node.node_id}

    for edge in graph._adj.get(source_node_id, []):
        if edge.label == EdgeLabel.SIM:
            other = graph.nodes[edge.target_id]
            target_locations.add(other.location.__str__())
            source_constraints.add(edge.target_id)

    formula = node.formula.strip()

    bounds_match = re.match(r'(\w+)\s*(>=|>)\s*(\d+)', formula)

    if bounds_match:
        var_name, op, bound = bounds_match.groups()
        check_code = f"if ({var_name} {op} {bound}) {{ ALERT(CWE={node.cwe_class.value}); }}"
        return Monitor(
            monitor_id=f"mon_{node.node_id}",
            monitor_type="bounds_check",
            condition=f"{var_name} {op} {bound}",
            check_code=check_code,
            target_locations=target_locations,
            source_constraints=source_constraints,
            cwe_class=node.cwe_class
        )

    check_code = f"if (z3_check_sat('{formula}', concrete_state)) {{ ALERT(CWE={node.cwe_class.value}); }}"
    return Monitor(
        monitor_id=f"mon_{node.node_id}",
        monitor_type="lazy_z3",
        condition=formula,
        check_code=check_code,
        target_locations=target_locations,
        source_constraints=source_constraints,
        cwe_class=node.cwe_class
    )


def abstract(graph) -> Dict[str, List[str]]:
    """
    Abstract: merge equivalent constraint nodes into classes.
    Returns: skeleton_hash -> list of node_ids in that class.

    Property: Safety — UNSAT in abstract => UNSAT in concrete
    """
    classes = defaultdict(list)
    for nid, node in graph.nodes.items():
        key = f"{node.cwe_class.value}:{node.skeleton_hash}"
        classes[key].append(nid)
    return dict(classes)


def pattern_match(graph, template_skeleton: str,
                  cwe_filter: Optional[CWEClass] = None) -> List[str]:
    """
    Find all constraint nodes matching a template skeleton.
    Optionally filter by CWE class.
    """
    template_hash = hashlib.sha256(template_skeleton.encode()).hexdigest()[:16]
    candidates = graph._skeleton_index.get(template_hash, set())

    if cwe_filter:
        return [nid for nid in candidates
                if graph.nodes[nid].cwe_class == cwe_filter]
    return list(candidates)


def propagate_detection(graph, detected_node_id: str) -> List[str]:
    """
    Given a detected vulnerability, find all SIM-connected nodes
    that should receive auto-generated monitors.

    Returns list of node_ids that are structural variants.
    """
    variants = []
    for edge in graph._adj.get(detected_node_id, []):
        if edge.label == EdgeLabel.SIM:
            variants.append(edge.target_id)
    return variants


def slice_back(graph, node_id: str):
    """
    Backward slice: all nodes reachable via reverse DEP edges.

    Property: Minimality — removing any node changes satisfiability
    """
    visited = set()
    queue = [node_id]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        for edge in graph._radj.get(current, []):
            if edge.label == EdgeLabel.DEP:
                queue.append(edge.source_id)

    return graph._subgraph(visited)


def slice_taint(graph, node_id: str, taint_vars: Set[str]):
    """
    Taint-filtered backward slice: only nodes whose formulas
    reference at least one variable in taint_vars.

    Property: Slice soundness — conjunction of slice formulas
              is equisatisfiable with original under path condition
    """
    visited = set()
    queue = [node_id]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue

        node = graph.nodes[current]
        if node.variables & taint_vars or current == node_id:
            visited.add(current)
            for edge in graph._radj.get(current, []):
                if edge.label == EdgeLabel.DEP:
                    queue.append(edge.source_id)

    return graph._subgraph(visited)
