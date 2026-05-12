"""Symbolic reachability filter for the NS-CDG solver shortcut.

Pure-symbolic. No neural, no Z3. BFS from a node over DEP and SIM edges,
returning True iff any reachable node has a CWE-tagged trigger pattern.

Design contract:
- Conservative: a node is a "trigger" iff cwe_class is non-UNKNOWN AND its
  formula contains a comparison operator. False positives are safe — they
  just mean we call Z3 instead of letting the neural predictor short-circuit.
- The filter is the soundness gate: when reachable_to_vuln(c) is True, the
  caller must invoke Z3 directly, never the neural shortcut.
"""

from typing import Set

from cdg_lib.types import CWEClass, EdgeLabel


_TRIGGER_OPS = (
    "<", "<=", ">", ">=",
    "u<", "u<=", "u>", "u>=",
    "s<", "s<=", "s>", "s>=",
)


def has_trigger_pattern(node) -> bool:
    """Return True iff `node` looks like a vulnerability trigger.

    Conservative rule: cwe_class is a known CWE AND formula contains any
    comparison operator. Equality alone (==, !=) does not count.
    """
    if node.cwe_class == CWEClass.UNKNOWN:
        return False
    formula = node.formula or ""
    for op in _TRIGGER_OPS:
        if op in formula:
            return True
    return False


def reachable_to_vuln(node, graph) -> bool:
    """BFS over DEP+SIM edges. Return True iff any reachable node is a trigger.

    The starting node itself counts (a CWE-tagged comparison constraint is
    its own trigger).
    """
    if has_trigger_pattern(node):
        return True

    visited: Set[str] = {node.node_id}
    queue = [node.node_id]
    while queue:
        current_id = queue.pop()
        for edge in graph._adj.get(current_id, []):
            if edge.label not in (EdgeLabel.DEP, EdgeLabel.SIM):
                continue
            target_id = edge.target_id
            if target_id in visited:
                continue
            visited.add(target_id)
            target = graph.nodes.get(target_id)
            if target is None:
                continue
            if has_trigger_pattern(target):
                return True
            queue.append(target_id)
    return False
