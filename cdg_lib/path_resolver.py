"""Path-condition resolution for the conflict-pruning shortcut.

Three sources are supported, matching paper §IV-B:
  'i'   - DEP-derived BFS over the graph
  'ii'  - caller-supplied explicit path
  'iii' - caller-supplied if present, else fall back to DEP-derived
"""

from typing import List, Optional

from cdg_lib.types import EdgeLabel


def _dep_bfs(graph, node_id: str) -> List[str]:
    """Return all DEP-ancestors of node_id (excluding node_id itself)."""
    visited = set()
    frontier = [node_id]
    while frontier:
        current = frontier.pop()
        for edge in graph._radj.get(current, []):
            if edge.label != EdgeLabel.DEP:
                continue
            pred = edge.source_id
            if pred in visited or pred == node_id:
                continue
            visited.add(pred)
            frontier.append(pred)
    return list(visited)


def resolve_path(
    graph,
    node_id: str,
    source: str,
    path_condition: Optional[List[str]] = None,
) -> List[str]:
    """Resolve the path condition for node_id under the given source.

    - 'i'   : DEP-derived BFS. Ignores path_condition.
    - 'ii'  : Returns path_condition. Raises ValueError if None.
    - 'iii' : Uses path_condition if not None, else DEP-derived.
    """
    if source == "i":
        return _dep_bfs(graph, node_id)
    if source == "ii":
        if path_condition is None:
            raise ValueError(
                "path_source='ii' requires an explicit path_condition"
            )
        return list(path_condition)
    if source == "iii":
        if path_condition is not None:
            return list(path_condition)
        return _dep_bfs(graph, node_id)
    raise ValueError(f"Unknown path source: {source!r}")
