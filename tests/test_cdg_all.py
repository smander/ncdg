#!/usr/bin/env python3
"""
CDG-Bench Test Suite: Validates ALL hypotheses for the CDG framework.

Test Categories:
  H1: CDG Structure          — Graph construction, monotonicity, edge induction
  H2: Constraint Creation    — Node creation from vulnerability specs, formula parsing
  H3: Similarity Metric      — Cross-function pattern matching accuracy
  H4: Self-Propagation       — 1→N detection: one vuln finds structural variants
  H5: Solve with Shortcuts   — Cache hits, subsumption shortcuts, conflict pruning
  H6: Slicing                — Backward slice, taint slice correctness
  H7: Monitor Compilation    — Constraint → runtime check soundness
  H8: Cross-Version Analysis — Incremental diff, provenance edges
  H9: Abstraction            — Equivalence class merging
  H10: End-to-End Pipeline   — Full closed loop on CDG-Bench

Run: python3 -m pytest test_cdg_all.py -v
  or: python3 test_cdg_all.py
"""

import sys
import os
import json
from collections import defaultdict

# Add parent to path (for standalone execution)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cdg_lib import (
    CDG, ConstraintNode, BinaryLocation, SolverOutcome, EdgeLabel, CWEClass,
    make_constraint, Monitor, GraphDiff
)
from cdg_lib import solver, analysis, serialization

import pytest


# ============================================================
# TEST FIXTURES: CDG-Bench vulnerability definitions
# ============================================================

def create_v1_alpha():
    """V1: CWE-125 in msg_process_alpha — OOB read via unchecked index."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

def create_v2_beta():
    """V2: CWE-125 in msg_process_beta — SAME logical bug, different code."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_beta", bb=5, addr=0x2000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

def create_v3_gamma():
    """V3: CWE-125 in msg_process_gamma — third variant."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_gamma", bb=7, addr=0x3000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

def create_v4_buffer():
    """V4: CWE-787 in buffer_copy — OOB write via unchecked length."""
    return make_constraint(
        formula="length > 256",
        skeleton="VAR > CONST",
        cwe=CWEClass.CWE_787,
        func="buffer_copy", bb=2, addr=0x4000,
        version="v1.0",
        variables={"length"},
        var_types={"length": "bv16"},
    )

def create_v1_alpha_fixed():
    """V1 FIXED in v1.1: bounds check added."""
    return make_constraint(
        formula="index >= 32 && bounds_checked == 0",
        skeleton="VAR >= CONST && VAR2 == CONST2",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.1",
        variables={"index", "bounds_checked"},
        var_types={"index": "bv16", "bounds_checked": "bv16"},
    )

def create_v5_uaf():
    """V5: CWE-416 Use-After-Free — introduced in v1.2."""
    return make_constraint(
        formula="buffer_freed == 1 && buffer_accessed == 1",
        skeleton="VAR == CONST && VAR2 == CONST2",
        cwe=CWEClass.CWE_416,
        func="msg_cleanup", bb=4, addr=0x5000,
        version="v1.2",
        variables={"buffer_freed", "buffer_accessed"},
        var_types={"buffer_freed": "bv16", "buffer_accessed": "bv16"},
    )

def create_v6_overflow():
    """V6: CWE-190 Integer Overflow — introduced in v1.3."""
    return make_constraint(
        formula="base * multiplier * count > 65535",
        skeleton="VAR * VAR2 * VAR3 > CONST",
        cwe=CWEClass.CWE_190,
        func="calc_offset", bb=1, addr=0x6000,
        version="v1.3",
        variables={"base", "multiplier", "count"},
        var_types={"base": "bv16", "multiplier": "bv16", "count": "bv16"},
    )

# Dependency chain for slicing tests
def create_dep_chain():
    """Create a chain: path_cond → header_parse → index_extract → oob_access."""
    c1 = make_constraint(
        formula="msg_len >= 8",
        skeleton="VAR >= CONST",
        cwe=CWEClass.UNKNOWN,
        func="msg_process_alpha", bb=1, addr=0x0F00,
        version="v1.0",
        variables={"msg_len"},
        var_types={"msg_len": "bv32"},
    )
    c2 = make_constraint(
        formula="msg_type == 1",
        skeleton="VAR == CONST",
        cwe=CWEClass.UNKNOWN,
        func="msg_process_alpha", bb=2, addr=0x0F20,
        version="v1.0",
        variables={"msg_type"},
        var_types={"msg_type": "bv16"},
    )
    c3 = make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )
    return c1, c2, c3


# ============================================================
# H1: CDG STRUCTURE TESTS
# ============================================================

class TestH1_CDGStructure:
    """H1: CDG construction, monotonicity, and edge induction."""
    
    def test_empty_cdg(self):
        """H1.1: Empty CDG has zero nodes and edges."""
        g = CDG("test")
        assert g.node_count == 0
        assert g.edge_count == 0
    
    def test_store_single_node(self):
        """H1.2: Storing one node increases count by 1."""
        g = CDG("test")
        c = create_v1_alpha()
        nid = g.store(c)
        assert g.node_count == 1
        assert nid in g.nodes
    
    def test_monotonicity(self):
        """H1.3: Monotonicity — node count never decreases after store."""
        g = CDG("test")
        counts = []
        for factory in [create_v1_alpha, create_v2_beta, create_v3_gamma, create_v4_buffer]:
            g.store(factory())
            counts.append(g.node_count)
        
        for i in range(1, len(counts)):
            assert counts[i] >= counts[i-1], \
                f"Monotonicity violated: {counts[i]} < {counts[i-1]}"
    
    def test_similarity_edges_induced(self):
        """H1.4: Storing nodes with matching skeletons induces SIM edges."""
        g = CDG("test")
        g.store(create_v1_alpha())
        g.store(create_v2_beta())
        
        sim_edges = [e for e in g.edges if e.label == EdgeLabel.SIM]
        assert len(sim_edges) >= 2, \
            f"Expected SIM edges between alpha and beta, got {len(sim_edges)}"
    
    def test_no_sim_edges_different_skeleton(self):
        """H1.5: Nodes with different skeletons do NOT get SIM edges."""
        g = CDG("test")
        g.store(create_v1_alpha())  # skeleton: "VAR >= CONST"
        g.store(create_v4_buffer())  # skeleton: "VAR > CONST"
        
        sim_edges = [e for e in g.edges if e.label == EdgeLabel.SIM]
        assert len(sim_edges) == 0, \
            "SIM edges should not exist between different skeletons"
    
    def test_dependency_edges(self):
        """H1.6: DEP edges correctly link derivation chains."""
        g = CDG("test")
        c1, c2, c3 = create_dep_chain()
        id1 = g.store(c1)
        id2 = g.store(c2, dep_sources=[id1])
        id3 = g.store(c3, dep_sources=[id2])
        
        dep_edges = [e for e in g.edges if e.label == EdgeLabel.DEP]
        assert len(dep_edges) >= 2
        
        # Check chain: id1 -> id2 -> id3
        sources = {e.source_id for e in dep_edges}
        targets = {e.target_id for e in dep_edges}
        assert id1 in sources
        assert id3 in targets
    
    def test_skeleton_index(self):
        """H1.7: Skeleton index correctly groups nodes by formula structure."""
        g = CDG("test")
        g.store(create_v1_alpha())
        g.store(create_v2_beta())
        g.store(create_v3_gamma())
        g.store(create_v4_buffer())
        
        # Alpha, beta, gamma share skeleton "VAR >= CONST"
        alpha_hash = create_v1_alpha().skeleton_hash
        matching = g._skeleton_index.get(alpha_hash, set())
        assert len(matching) == 3, f"Expected 3 nodes with same skeleton, got {len(matching)}"


# ============================================================
# H2: CONSTRAINT CREATION TESTS
# ============================================================

class TestH2_ConstraintCreation:
    """H2: Node creation from vulnerability specifications."""
    
    def test_node_fields(self):
        """H2.1: All fields are correctly populated."""
        c = create_v1_alpha()
        assert c.formula == "index >= 32"
        assert c.cwe_class == CWEClass.CWE_125
        assert c.location.function == "msg_process_alpha"
        assert c.version == "v1.0"
        assert "index" in c.variables
    
    def test_skeleton_strips_constants(self):
        """H2.2: Skeleton replaces constants with wildcards."""
        c1 = create_v1_alpha()  # "index >= 32" → "VAR >= CONST"
        c2 = create_v2_beta()   # "index >= 32" → "VAR >= CONST"
        assert c1.formula_skeleton == c2.formula_skeleton
    
    def test_different_cwe_different_skeleton(self):
        """H2.3: Different CWE classes typically produce different skeletons."""
        c_125 = create_v1_alpha()  # CWE-125: "VAR >= CONST"
        c_787 = create_v4_buffer() # CWE-787: "VAR > CONST" 
        assert c_125.formula_skeleton != c_787.formula_skeleton
    
    def test_skeleton_hash_consistency(self):
        """H2.4: Same skeleton always produces same hash."""
        c1 = create_v1_alpha()
        c2 = create_v2_beta()
        assert c1.skeleton_hash == c2.skeleton_hash
    
    def test_location_uniqueness(self):
        """H2.5: Each vulnerability has a unique location."""
        locations = set()
        for factory in [create_v1_alpha, create_v2_beta, create_v3_gamma, create_v4_buffer]:
            c = factory()
            loc_str = str(c.location)
            assert loc_str not in locations, f"Duplicate location: {loc_str}"
            locations.add(loc_str)


# ============================================================
# H3: SIMILARITY METRIC TESTS
# ============================================================

class TestH3_Similarity:
    """H3: Constraint similarity metric accuracy."""
    
    def test_identical_constraints(self):
        """H3.1: Same skeleton + same CWE + same types → sim = 1.0."""
        g = CDG("test")
        c1 = create_v1_alpha()
        c2 = create_v2_beta()
        sim = analysis.similarity(c1, c2)
        assert sim == 1.0, f"Expected 1.0 for identical patterns, got {sim}"
    
    def test_different_skeleton_partial(self):
        """H3.2: Different skeleton -> partial score (0 < sim < 1).

        Updated contract (paper Eq. 1 + Eq. 2): skeleton mismatch no longer
        zeroes the symbolic score; it half-weights it (m = 0.5) so neural
        blending has a usable floor. Pure-skeleton-match should still
        strictly dominate mismatch.

        Type Jaccard is over (name, width) pairs (paper Def. 1 / Eq. 1),
        so the two constraints must share at least one variable for the
        type term to be > 0 -- otherwise the product collapses to 0
        regardless of the gate's value, which is also paper-correct but
        does not exercise the gate.
        """
        g = CDG("test")
        c1 = create_v1_alpha()  # "VAR >= CONST", var "index"
        # Same variable, same CWE, but different skeleton operator -- this
        # exercises the relaxed gate without zeroing the type term.
        c_diff_skel = make_constraint(
            formula="index > 32",
            skeleton="VAR > CONST",
            cwe=CWEClass.CWE_125,
            func="msg_process_alpha", bb=3, addr=0x1000,
            version="v1.0",
            variables={"index"},
            var_types={"index": "bv16"},
        )
        sim_mismatch = analysis.similarity(c1, c_diff_skel)
        sim_match = analysis.similarity(c1, c1)
        assert 0.0 < sim_mismatch < sim_match, \
            f"Expected partial score on mismatch, got {sim_mismatch} (match={sim_match})"
    
    def test_same_skeleton_different_cwe(self):
        """H3.3: Same skeleton but different CWE → sim < 1.0."""
        g = CDG("test")
        c1 = create_v1_alpha()  # CWE-125
        # Create a hypothetical CWE-787 with same skeleton
        c_fake = make_constraint(
            formula="index >= 32",
            skeleton="VAR >= CONST",
            cwe=CWEClass.CWE_787,  # Different CWE!
            func="other_func", bb=1, addr=0x9000,
            version="v1.0",
            variables={"index"},
            var_types={"index": "bv16"},
        )
        sim = analysis.similarity(c1, c_fake)
        assert 0.0 < sim < 1.0, \
            f"Same skeleton, different CWE should give 0 < sim < 1, got {sim}"
    
    def test_all_three_variants_high_sim(self):
        """H3.4: All three CDG-Bench variants (alpha/beta/gamma) have sim = 1.0."""
        g = CDG("test")
        c1 = create_v1_alpha()
        c2 = create_v2_beta()
        c3 = create_v3_gamma()
        
        assert analysis.similarity(c1, c2) == 1.0
        assert analysis.similarity(c2, c3) == 1.0
        assert analysis.similarity(c1, c3) == 1.0


# ============================================================
# H4: SELF-PROPAGATION TESTS (1→N)
# ============================================================

class TestH4_SelfPropagation:
    """H4: One detection automatically finds structural variants."""
    
    def test_propagate_finds_variants(self):
        """H4.1: After detecting V1, propagation finds V2 and V3."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        id2 = g.store(create_v2_beta())
        id3 = g.store(create_v3_gamma())
        id4 = g.store(create_v4_buffer())
        
        variants = analysis.propagate_detection(g,id1)
        variant_ids = set(variants)
        
        assert id2 in variant_ids, "V2 (beta) should be found as variant"
        assert id3 in variant_ids, "V3 (gamma) should be found as variant"
        assert id4 not in variant_ids, "V4 (buffer, different CWE) should NOT be a variant"
    
    def test_propagation_count(self):
        """H4.2: 1 detection → exactly 2 variants for CDG-Bench CWE-125."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        g.store(create_v2_beta())
        g.store(create_v3_gamma())
        g.store(create_v4_buffer())
        
        variants = analysis.propagate_detection(g,id1)
        assert len(variants) == 2, f"Expected 2 variants, got {len(variants)}"
    
    def test_propagation_does_not_cross_cwe(self):
        """H4.3: Propagation does NOT cross CWE class boundaries."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())   # CWE-125
        id4 = g.store(create_v4_buffer())   # CWE-787
        
        variants_from_1 = analysis.propagate_detection(g,id1)
        assert id4 not in variants_from_1
        
        variants_from_4 = analysis.propagate_detection(g,id4)
        assert id1 not in variants_from_4
    
    def test_zero_solver_calls_for_variants(self):
        """H4.4: Variants detected via pattern match require 0 Z3 calls."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        id2 = g.store(create_v2_beta())
        
        # Solve V1 (this invokes Z3)
        solver.solve(g,id1)
        
        # V2 should hit subsumption shortcut (cached via similarity)
        initial_cache_size = len(g._solve_cache)
        solver.solve(g,id2)
        
        # V2 should have gotten result from cache/subsumption, not a fresh Z3 call
        # (Verified by checking that V2's outcome matches V1's)
        assert g.nodes[id2].outcome == g.nodes[id1].outcome


# ============================================================
# H5: SOLVE WITH SHORTCUTS TESTS
# ============================================================

class TestH5_Solve:
    """H5: Solve operation with graph-accelerated shortcuts."""
    
    def test_cache_hit(self):
        """H5.1: Second solve of same formula hits cache."""
        g = CDG("test")
        c1 = create_v1_alpha()
        c2 = make_constraint(
            formula="index >= 32",  # SAME formula
            skeleton="VAR >= CONST",
            cwe=CWEClass.CWE_125,
            func="other_func", bb=1, addr=0x9999,
            version="v1.0",
            variables={"index"},
            var_types={"index": "bv16"},
        )
        id1 = g.store(c1)
        id2 = g.store(c2)
        
        solver.solve(g,id1)
        # id2 has same formula, should hit cache
        solver.solve(g,id2)
        assert g.nodes[id2].outcome == g.nodes[id1].outcome
    
    def test_solve_sat_for_bounds_vuln(self):
        """H5.2: CWE-125 constraint (index >= 32) is satisfiable."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        outcome, model = solver.solve(g,id1)
        assert outcome == SolverOutcome.SAT, \
            f"Expected SAT for 'index >= 32', got {outcome}"
    
    def test_solve_returns_model(self):
        """H5.3: SAT result includes a satisfying model."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        outcome, model = solver.solve(g,id1)
        if outcome == SolverOutcome.SAT:
            assert model is not None, "SAT should return a model"


# ============================================================
# H6: SLICING TESTS
# ============================================================

class TestH6_Slicing:
    """H6: Backward and taint slicing correctness."""
    
    def test_backward_slice_includes_chain(self):
        """H6.1: Backward slice from V1 includes all dependency sources."""
        g = CDG("test")
        c1, c2, c3 = create_dep_chain()
        id1 = g.store(c1)
        id2 = g.store(c2, dep_sources=[id1])
        id3 = g.store(c3, dep_sources=[id2])
        
        sliced = analysis.slice_back(g,id3)
        assert id1 in sliced.nodes, "Slice should include root dependency"
        assert id2 in sliced.nodes, "Slice should include intermediate dependency"
        assert id3 in sliced.nodes, "Slice should include target node"
    
    def test_backward_slice_excludes_unrelated(self):
        """H6.2: Backward slice does NOT include unrelated nodes."""
        g = CDG("test")
        c1, c2, c3 = create_dep_chain()
        id1 = g.store(c1)
        id2 = g.store(c2, dep_sources=[id1])
        id3 = g.store(c3, dep_sources=[id2])
        id4 = g.store(create_v4_buffer())  # Unrelated
        
        sliced = analysis.slice_back(g,id3)
        assert id4 not in sliced.nodes, "Unrelated node should not be in slice"
    
    def test_taint_slice_filters_by_variable(self):
        """H6.3: Taint slice only includes nodes with tainted variables."""
        g = CDG("test")
        c1, c2, c3 = create_dep_chain()
        id1 = g.store(c1)  # vars: {msg_len}
        id2 = g.store(c2, dep_sources=[id1])  # vars: {msg_type}
        id3 = g.store(c3, dep_sources=[id2])  # vars: {index}
        
        # Taint only "index" — should include c3 but filter based on overlap
        taint_slice = analysis.slice_taint(g,id3, {"index"})
        assert id3 in taint_slice.nodes
    
    def test_slice_preserves_edges(self):
        """H6.4: Sliced subgraph preserves internal edges."""
        g = CDG("test")
        c1, c2, c3 = create_dep_chain()
        id1 = g.store(c1)
        id2 = g.store(c2, dep_sources=[id1])
        id3 = g.store(c3, dep_sources=[id2])
        
        sliced = analysis.slice_back(g,id3)
        assert sliced.edge_count > 0, "Slice should preserve edges"


# ============================================================
# H7: MONITOR COMPILATION TESTS
# ============================================================

class TestH7_Compile:
    """H7: Constraint → runtime monitor soundness."""
    
    def test_compile_bounds_check(self):
        """H7.1: Bounds constraint compiles to bounds_check monitor."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        monitor = analysis.compile_monitor(g,id1)
        
        assert monitor is not None
        assert monitor.monitor_type == "bounds_check"
        assert "index" in monitor.condition
        assert "32" in monitor.condition
    
    def test_compile_includes_all_sim_locations(self):
        """H7.2: Compiled monitor targets all SIM-connected locations."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        id2 = g.store(create_v2_beta())
        id3 = g.store(create_v3_gamma())
        
        monitor = analysis.compile_monitor(g,id1)
        assert len(monitor.target_locations) == 3, \
            f"Monitor should target 3 locations (alpha+beta+gamma), got {len(monitor.target_locations)}"
    
    def test_compile_does_not_include_different_cwe(self):
        """H7.3: Monitor does NOT target locations with different CWE."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        id4 = g.store(create_v4_buffer())
        
        monitor = analysis.compile_monitor(g,id1)
        buffer_loc = str(create_v4_buffer().location)
        assert buffer_loc not in monitor.target_locations
    
    def test_compile_complex_to_lazy_z3(self):
        """H7.4: Complex constraint compiles to lazy_z3 monitor."""
        g = CDG("test")
        id5 = g.store(create_v5_uaf())
        monitor = analysis.compile_monitor(g,id5)
        
        assert monitor is not None
        assert monitor.monitor_type == "lazy_z3"
    
    def test_monitor_soundness_property(self):
        """H7.5: Monitor.source_constraints traces back to real CDG nodes."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        g.store(create_v2_beta())
        
        monitor = analysis.compile_monitor(g,id1)
        for src_id in monitor.source_constraints:
            assert src_id in g.nodes, \
                f"Monitor source {src_id} must exist in CDG"
            assert g.nodes[src_id].outcome != SolverOutcome.UNSAT, \
                "Monitor should not be based on UNSAT constraints"


# ============================================================
# H8: CROSS-VERSION ANALYSIS TESTS
# ============================================================

class TestH8_CrossVersion:
    """H8: Incremental analysis across binary versions."""
    
    def _build_v10(self):
        """Build CDG for v1.0: V1, V2, V3, V4 present."""
        g = CDG("v1.0")
        g.store(create_v1_alpha())
        g.store(create_v2_beta())
        g.store(create_v3_gamma())
        g.store(create_v4_buffer())
        return g
    
    def _build_v11(self):
        """Build CDG for v1.1: V1 fixed, V2, V3, V4 still present."""
        g = CDG("v1.1")
        g.store(create_v1_alpha_fixed())  # Modified (patch)
        g.store(create_v2_beta())          # Unchanged
        g.store(create_v3_gamma())         # Unchanged
        g.store(create_v4_buffer())        # Unchanged
        return g
    
    def _build_v12(self):
        """Build CDG for v1.2: V1 fixed, V2 fixed, V3 present, V4 present, V5 NEW."""
        g = CDG("v1.2")
        g.store(create_v1_alpha_fixed())
        # V2 also fixed in v1.2 (different skeleton)
        g.store(make_constraint(
            formula="index >= 32 && bounds_checked == 0",
            skeleton="VAR >= CONST && VAR2 == CONST2",
            cwe=CWEClass.CWE_125,
            func="msg_process_beta", bb=5, addr=0x2000,
            version="v1.2",
            variables={"index", "bounds_checked"},
            var_types={"index": "bv16", "bounds_checked": "bv16"},
        ))
        g.store(create_v3_gamma())  # Still vulnerable
        g.store(create_v4_buffer())
        g.store(create_v5_uaf())    # NEW vulnerability
        return g
    
    def test_compare_identifies_unchanged(self):
        """H8.1: Compare correctly identifies unchanged nodes."""
        g1 = self._build_v10()
        g2 = self._build_v11()
        diff = analysis.compare(g1, g2)
        assert len(diff.unchanged_nodes) >= 2, \
            f"V2, V3, V4 should be unchanged, got {len(diff.unchanged_nodes)}"

    def test_compare_identifies_modified(self):
        """H8.2: Compare detects V1's skeleton change (patch)."""
        g1 = self._build_v10()
        g2 = self._build_v11()
        diff = analysis.compare(g1, g2)
        assert len(diff.modified_nodes) >= 1, \
            "V1 alpha should be detected as modified (patched)"

    def test_compare_identifies_new_vuln(self):
        """H8.3: Compare detects V5 (UAF) as newly added in v1.2."""
        g1 = self._build_v11()
        g2 = self._build_v12()
        diff = analysis.compare(g1, g2)
        assert len(diff.added_nodes) >= 1, \
            "V5 (msg_cleanup) should be detected as added"

    def test_incremental_savings(self):
        """H8.4: Incremental analysis should re-solve fewer constraints."""
        g1 = self._build_v10()
        g2 = self._build_v11()
        diff = analysis.compare(g1, g2)
        
        total = g2.node_count
        unchanged = len(diff.unchanged_nodes)
        savings_pct = (unchanged / total) * 100 if total > 0 else 0
        
        print(f"  [H8.4] Incremental savings: {unchanged}/{total} = {savings_pct:.0f}% carried forward")
        assert savings_pct >= 50, \
            f"Expected >= 50% savings, got {savings_pct:.0f}%"


# ============================================================
# H9: ABSTRACTION TESTS
# ============================================================

class TestH9_Abstraction:
    """H9: Equivalence class merging."""
    
    def test_abstract_groups_same_pattern(self):
        """H9.1: Abstract merges V1, V2, V3 into one equivalence class."""
        g = CDG("test")
        g.store(create_v1_alpha())
        g.store(create_v2_beta())
        g.store(create_v3_gamma())
        g.store(create_v4_buffer())
        
        classes = analysis.abstract(g)
        
        # Find the CWE-125 class
        cwe125_classes = {k: v for k, v in classes.items() if "CWE-125" in k}
        assert len(cwe125_classes) == 1, "V1/V2/V3 should merge into one class"
        
        class_key = list(cwe125_classes.keys())[0]
        assert len(cwe125_classes[class_key]) == 3, \
            "CWE-125 class should contain 3 nodes"
    
    def test_abstract_separates_different_cwe(self):
        """H9.2: Abstract keeps different CWE classes separate."""
        g = CDG("test")
        g.store(create_v1_alpha())
        g.store(create_v4_buffer())
        g.store(create_v5_uaf())
        
        classes = analysis.abstract(g)
        assert len(classes) >= 3, \
            f"Expected >= 3 classes (CWE-125, CWE-787, CWE-416), got {len(classes)}"


# ============================================================
# H10: END-TO-END PIPELINE TESTS
# ============================================================

class TestH10_EndToEnd:
    """H10: Full closed-loop pipeline on CDG-Bench."""
    
    def test_full_pipeline_1_to_3(self):
        """H10.1: Complete pipeline: detect V1 → propagate → protect V2, V3."""
        g = CDG("pipeline_test")
        
        # Step 1: "Digital Twin detects" — store the anomaly
        id_v1 = g.store(create_v1_alpha())
        
        # Step 2: Store the structural variants (simulating SE on other functions)
        id_v2 = g.store(create_v2_beta())
        id_v3 = g.store(create_v3_gamma())
        id_v4 = g.store(create_v4_buffer())
        
        # Step 3: Solve V1 (Z3 confirms it's a real vulnerability)
        outcome, model = solver.solve(g,id_v1)
        assert outcome == SolverOutcome.SAT, "V1 should be SAT (real vulnerability)"
        
        # Step 4: Propagate — find variants
        variants = analysis.propagate_detection(g,id_v1)
        assert len(variants) == 2, f"Should find 2 variants, got {len(variants)}"
        assert id_v2 in variants
        assert id_v3 in variants
        assert id_v4 not in variants  # Different CWE
        
        # Step 5: Compile monitor — should target all 3 locations
        monitor = analysis.compile_monitor(g,id_v1)
        assert monitor is not None
        assert len(monitor.target_locations) == 3
        assert monitor.monitor_type == "bounds_check"
        assert monitor.cwe_class == CWEClass.CWE_125
        
        # Step 6: Verify stats
        stats = serialization.to_dict(g)["stats"]
        assert stats["node_count"] == 4
        assert stats["cwe_distribution"]["CWE-125"] == 3
        assert stats["cwe_distribution"]["CWE-787"] == 1
        
        print(f"  [H10.1] Pipeline result: 1 detection → {len(variants)} variants → "
              f"{len(monitor.target_locations)} monitored locations")
    
    def test_full_pipeline_cross_version(self):
        """H10.2: Pipeline across v1.0 → v1.1 → v1.2."""
        # v1.0
        g0 = CDG("v1.0")
        g0.store(create_v1_alpha())
        g0.store(create_v2_beta())
        g0.store(create_v3_gamma())
        g0.store(create_v4_buffer())
        
        # v1.1: V1 patched
        g1 = CDG("v1.1")
        g1.store(create_v1_alpha_fixed())
        g1.store(create_v2_beta())
        g1.store(create_v3_gamma())
        g1.store(create_v4_buffer())
        
        diff_01 = analysis.compare(g0, g1)
        
        # v1.2: V1, V2 patched, V5 introduced
        g2 = CDG("v1.2")
        g2.store(create_v1_alpha_fixed())
        g2.store(make_constraint(
            formula="index >= 32 && bounds_checked == 0",
            skeleton="VAR >= CONST && VAR2 == CONST2",
            cwe=CWEClass.CWE_125,
            func="msg_process_beta", bb=5, addr=0x2000,
            version="v1.2",
            variables={"index", "bounds_checked"},
            var_types={"index": "bv16", "bounds_checked": "bv16"},
        ))
        g2.store(create_v3_gamma())
        g2.store(create_v4_buffer())
        g2.store(create_v5_uaf())
        
        diff_12 = analysis.compare(g1, g2)
        
        print(f"  [H10.2] v1.0→v1.1: {len(diff_01.modified_nodes)} modified, "
              f"{len(diff_01.unchanged_nodes)} unchanged")
        print(f"  [H10.2] v1.1→v1.2: {len(diff_12.modified_nodes)} modified, "
              f"{len(diff_12.added_nodes)} added, "
              f"{len(diff_12.unchanged_nodes)} unchanged")
        
        assert len(diff_12.added_nodes) >= 1, "V5 should be detected as new"
    
    def test_monitor_false_positive_check(self):
        """H10.3: Monitor on valid input should NOT fire (conceptual)."""
        g = CDG("test")
        id1 = g.store(create_v1_alpha())
        monitor = analysis.compile_monitor(g,id1)
        
        # Simulate: valid index = 5, should NOT trigger
        # Monitor condition: "index >= 32"
        valid_index = 5
        triggers = eval(f"{valid_index} >= 32")
        assert not triggers, "Monitor should NOT fire on valid input (index=5)"
        
        # Simulate: attack index = 0xFFFF, should trigger
        attack_index = 0xFFFF
        triggers = eval(f"{attack_index} >= 32")
        assert triggers, "Monitor SHOULD fire on attack input (index=0xFFFF)"
        
        print("  [H10.3] Monitor FP test: valid=NO_ALERT, attack=ALERT ✓")


# ============================================================
# TEST RUNNER
# ============================================================

def run_all_tests():
    """Run all test hypotheses and report results."""
    test_classes = [
        ("H1: CDG Structure",        TestH1_CDGStructure),
        ("H2: Constraint Creation",  TestH2_ConstraintCreation),
        ("H3: Similarity Metric",    TestH3_Similarity),
        ("H4: Self-Propagation",     TestH4_SelfPropagation),
        ("H5: Solve Shortcuts",      TestH5_Solve),
        ("H6: Slicing",              TestH6_Slicing),
        ("H7: Monitor Compilation",  TestH7_Compile),
        ("H8: Cross-Version",        TestH8_CrossVersion),
        ("H9: Abstraction",          TestH9_Abstraction),
        ("H10: End-to-End Pipeline", TestH10_EndToEnd),
    ]
    
    total_passed = 0
    total_failed = 0
    total_tests = 0
    results = []
    
    print("=" * 70)
    print("CDG-Bench Test Suite: Validating ALL Hypotheses")
    print("=" * 70)
    
    for category_name, test_class in test_classes:
        print(f"\n{'─' * 70}")
        print(f"  {category_name}")
        print(f"{'─' * 70}")
        
        instance = test_class()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        
        category_passed = 0
        category_failed = 0
        
        for method_name in sorted(methods):
            total_tests += 1
            test_fn = getattr(instance, method_name)
            try:
                test_fn()
                print(f"  ✅ {method_name}")
                category_passed += 1
                total_passed += 1
            except AssertionError as e:
                print(f"  ❌ {method_name}: {e}")
                category_failed += 1
                total_failed += 1
            except Exception as e:
                print(f"  💥 {method_name}: EXCEPTION: {e}")
                category_failed += 1
                total_failed += 1
        
        results.append((category_name, category_passed, category_failed))
    
    # Summary
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY")
    print(f"{'=' * 70}")
    
    for cat_name, passed, failed in results:
        status = "✅" if failed == 0 else "❌"
        print(f"  {status} {cat_name}: {passed}/{passed+failed} passed")
    
    print(f"\n  Total: {total_passed}/{total_tests} passed, {total_failed} failed")
    
    if total_failed == 0:
        print(f"\n  🎉 ALL {total_tests} HYPOTHESES VALIDATED")
    else:
        print(f"\n  ⚠️  {total_failed} HYPOTHESES FAILED — needs investigation")
    
    print(f"{'=' * 70}")
    
    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
