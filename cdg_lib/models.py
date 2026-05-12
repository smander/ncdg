"""
CDG data models: dataclasses for constraint nodes, edges, monitors, and diffs.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, Tuple, Any

from cdg_lib.types import SolverOutcome, EdgeLabel, CWEClass


@dataclass(frozen=True)
class BinaryLocation:
    """Location in the binary: (function, basic_block, instruction_addr)"""
    function: str
    basic_block: int
    instruction_addr: int

    def __str__(self):
        return f"{self.function}:bb{self.basic_block}:0x{self.instruction_addr:x}"


@dataclass
class ConstraintNode:
    """
    A node in the CDG: c = (phi, kappa, ell, v, sigma)

    phi (formula):     SMT formula as string (SMT-LIB2 or Z3 Python repr)
    kappa (cwe_class): CWE vulnerability class
    ell (location):    Binary location triple
    v (version):       Firmware/binary version identifier
    sigma (outcome):   Solver outcome
    """
    node_id: str
    formula: str
    formula_skeleton: str
    cwe_class: CWEClass
    location: BinaryLocation
    version: str
    outcome: SolverOutcome = SolverOutcome.UNKNOWN
    variables: Set[str] = field(default_factory=set)
    var_types: Dict[str, str] = field(default_factory=dict)
    model: Optional[Dict[str, Any]] = None
    embedding: Optional[Any] = None  # numpy.ndarray when populated by f_theta

    @property
    def skeleton_hash(self) -> str:
        """Hash of the formula skeleton for fast similarity lookup."""
        return hashlib.sha256(self.formula_skeleton.encode()).hexdigest()[:16]


@dataclass
class CDGEdge:
    """Labeled edge in the CDG."""
    source_id: str
    target_id: str
    label: EdgeLabel
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Monitor:
    """
    Compiled runtime monitor from a constraint subgraph.

    monitor_type: 'bounds_check' | 'fsm' | 'lazy_z3'
    condition:    Human-readable condition string
    check_code:   Pseudocode/Python for the runtime check
    target_locations: Set of binary locations where this monitor should be deployed
    source_constraints: Set of constraint IDs this monitor was compiled from
    """
    monitor_id: str
    monitor_type: str
    condition: str
    check_code: str
    target_locations: Set[str]
    source_constraints: Set[str]
    cwe_class: CWEClass


@dataclass
class GraphDiff:
    """Result of compare(G1, G2)."""
    added_nodes: Set[str]
    removed_nodes: Set[str]
    modified_nodes: Set[str]
    unchanged_nodes: Set[str]
    added_edges: Set[Tuple[str, str, str]]
    removed_edges: Set[Tuple[str, str, str]]


def make_constraint(formula: str, skeleton: str, cwe: CWEClass,
                    func: str, bb: int, addr: int, version: str,
                    variables: Set[str] = None,
                    var_types: Dict[str, str] = None) -> ConstraintNode:
    """Factory function for creating constraint nodes."""
    return ConstraintNode(
        node_id="",
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=cwe,
        location=BinaryLocation(func, bb, addr),
        version=version,
        variables=variables or set(),
        var_types=var_types or {},
    )
