"""
CDG Serialization: convert CDG to dictionary for JSON export.
"""

from typing import Dict
from collections import defaultdict


def to_dict(graph) -> dict:
    """Serialize CDG to dictionary."""
    return {
        "name": graph.name,
        "nodes": {
            nid: {
                "formula": n.formula,
                "skeleton": n.formula_skeleton,
                "cwe": n.cwe_class.value,
                "location": str(n.location),
                "version": n.version,
                "outcome": n.outcome.value,
                "variables": list(n.variables),
                "var_types": n.var_types,
            }
            for nid, n in graph.nodes.items()
        },
        "edges": [
            {"src": e.source_id, "tgt": e.target_id,
             "label": e.label.value, "meta": e.metadata}
            for e in graph.edges
        ],
        "stats": {
            "node_count": graph.node_count,
            "edge_count": graph.edge_count,
            "cwe_distribution": _cwe_distribution(graph),
            "skeleton_classes": len(graph._skeleton_index),
        }
    }


def _cwe_distribution(graph) -> Dict[str, int]:
    dist = defaultdict(int)
    for n in graph.nodes.values():
        dist[n.cwe_class.value] += 1
    return dict(dist)
