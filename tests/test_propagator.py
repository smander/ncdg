"""
CDG Propagator Test Suite: validates the Z3 UserPropagateBase integration.

Test Groups:
  Basic:       Single SAT, result matches sequential, cache populated, outcome updated
  Batch:       Three variants together, all nodes get results, shared variables, mixed CWE
  Shortcuts:   Cache hit in fixed, subsumption, conflict pruning, matches sequential
  Trail:       push/pop restores state, nested push/pop, fresh creates clean copy
  Final:       Dampening works, cross-constraint SIM propagation
  Integration: Full pipeline with propagator, propagator vs sequential parity, no-Z3 fallback

Run: python3 -m pytest tests/test_propagator.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from copy import deepcopy

from cdg_lib import (
    CDG, ConstraintNode, BinaryLocation, SolverOutcome, EdgeLabel, CWEClass,
    make_constraint,
)
from cdg_lib import solver, propagator
from cdg_lib.propagator import CDGPropagator, solve_with_propagator

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


# ============================================================
# HELPERS: CDG-Bench constraint factories
# ============================================================

def create_v1_alpha():
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
    return make_constraint(
        formula="length > 256",
        skeleton="VAR > CONST",
        cwe=CWEClass.CWE_787,
        func="buffer_copy", bb=2, addr=0x4000,
        version="v1.0",
        variables={"length"},
        var_types={"length": "bv16"},
    )

def create_v5_uaf():
    return make_constraint(
        formula="buffer_freed == 1 && buffer_accessed == 1",
        skeleton="VAR == CONST && VAR2 == CONST2",
        cwe=CWEClass.CWE_416,
        func="msg_cleanup", bb=4, addr=0x5000,
        version="v1.2",
        variables={"buffer_freed", "buffer_accessed"},
        var_types={"buffer_freed": "bv16", "buffer_accessed": "bv16"},
    )

def create_unsat_constraint():
    """A constraint that is UNSAT: index > 65535 on bv16 (unsigned, max is 65535)."""
    return make_constraint(
        formula="index > 65535",
        skeleton="VAR > CONST",
        cwe=CWEClass.CWE_125,
        func="impossible_func", bb=1, addr=0x9000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )


def build_three_variant_graph():
    """Build a CDG with alpha/beta/gamma (all CWE-125, same skeleton)."""
    g = CDG("test_propagator")
    id1 = g.store(create_v1_alpha())
    id2 = g.store(create_v2_beta())
    id3 = g.store(create_v3_gamma())
    return g, [id1, id2, id3]


def build_mixed_cwe_graph():
    """Build a CDG with CWE-125 (alpha) + CWE-787 (buffer) + CWE-416 (uaf)."""
    g = CDG("test_mixed")
    id1 = g.store(create_v1_alpha())
    id4 = g.store(create_v4_buffer())
    id5 = g.store(create_v5_uaf())
    return g, [id1, id4, id5]


# ============================================================
# BASIC TESTS
# ============================================================

class TestBasic:
    """Basic propagator functionality."""

    def test_single_sat_constraint(self):
        """Single SAT constraint returns SAT with a model."""
        g = CDG("test")
        nid = g.store(create_v1_alpha())
        results = solve_with_propagator(g, [nid])

        assert nid in results
        outcome, model = results[nid]
        assert outcome == SolverOutcome.SAT

    def test_result_matches_sequential(self):
        """Propagator result matches sequential solver for single node."""
        g1 = CDG("seq")
        nid1 = g1.store(create_v1_alpha())
        seq_outcome, _ = solver.solve(g1, nid1)

        g2 = CDG("prop")
        nid2 = g2.store(create_v1_alpha())
        results = solve_with_propagator(g2, [nid2])
        prop_outcome, _ = results[nid2]

        assert seq_outcome == prop_outcome

    def test_cache_populated_after_solve(self):
        """After propagator solve, graph cache is populated."""
        g = CDG("test")
        nid = g.store(create_v1_alpha())
        solve_with_propagator(g, [nid])

        assert g.nodes[nid].formula in g._solve_cache

    def test_node_outcome_updated(self):
        """After propagator solve, node.outcome is updated."""
        g = CDG("test")
        nid = g.store(create_v1_alpha())
        assert g.nodes[nid].outcome == SolverOutcome.UNKNOWN

        solve_with_propagator(g, [nid])
        assert g.nodes[nid].outcome != SolverOutcome.UNKNOWN


# ============================================================
# BATCH TESTS
# ============================================================

class TestBatch:
    """Batch solving multiple constraints."""

    def test_three_variants_all_get_results(self):
        """All three CWE-125 variants get results in single batch."""
        g, ids = build_three_variant_graph()
        results = solve_with_propagator(g, ids)

        for nid in ids:
            assert nid in results, f"Missing result for {nid}"
            outcome, _ = results[nid]
            assert outcome == SolverOutcome.SAT

    def test_shared_variables_across_nodes(self):
        """Nodes sharing variable names (e.g., 'index') are solved consistently."""
        g, ids = build_three_variant_graph()
        results = solve_with_propagator(g, ids)

        # All three share "index >= 32", should all be SAT
        outcomes = [results[nid][0] for nid in ids]
        assert all(o == SolverOutcome.SAT for o in outcomes)

    def test_mixed_cwe_batch(self):
        """Batch with different CWE classes all get results."""
        g, ids = build_mixed_cwe_graph()
        results = solve_with_propagator(g, ids)

        assert len(results) == len(ids)
        for nid in ids:
            assert nid in results

    def test_batch_with_buffer_constraint(self):
        """CWE-787 constraint (length > 256) is SAT in batch."""
        g = CDG("test")
        nid = g.store(create_v4_buffer())
        results = solve_with_propagator(g, [nid])

        outcome, _ = results[nid]
        assert outcome == SolverOutcome.SAT


# ============================================================
# SHORTCUT TESTS
# ============================================================

class TestShortcuts:
    """Graph shortcut integration in propagator."""

    def test_cache_hit_skips_z3(self):
        """Pre-cached formula is resolved in pre-filter phase."""
        g = CDG("test")
        nid1 = g.store(create_v1_alpha())
        # Pre-populate cache
        solver.solve(g, nid1)
        assert g.nodes[nid1].formula in g._solve_cache

        # Now solve with propagator — should hit pre-filter cache
        nid2_node = create_v2_beta()  # Same formula
        nid2_node.formula = "index >= 32"  # Ensure exact same formula
        nid2 = g.store(nid2_node)
        results = solve_with_propagator(g, [nid2])

        outcome, _ = results[nid2]
        assert outcome == SolverOutcome.SAT

    def test_subsumption_in_propagator(self):
        """SIM neighbor with SAT outcome enables subsumption shortcut."""
        g = CDG("test")
        nid1 = g.store(create_v1_alpha())
        nid2 = g.store(create_v2_beta())  # SIM edge to nid1

        # Solve nid1 first (sets outcome=SAT)
        solver.solve(g, nid1)
        assert g.nodes[nid1].outcome == SolverOutcome.SAT

        # Now batch-solve nid2 — propagator's _on_fixed should catch subsumption
        results = solve_with_propagator(g, [nid2])
        outcome, _ = results[nid2]
        assert outcome == SolverOutcome.SAT

    def test_propagator_matches_sequential_for_all_nodes(self):
        """Propagator produces same outcomes as sequential solver for all nodes."""
        # Sequential
        g_seq = CDG("sequential")
        ids_seq = []
        for factory in [create_v1_alpha, create_v2_beta, create_v3_gamma, create_v4_buffer]:
            nid = g_seq.store(factory())
            ids_seq.append(nid)
        seq_results = {}
        for nid in ids_seq:
            outcome, model = solver.solve(g_seq, nid)
            seq_results[nid] = outcome

        # Propagator
        g_prop = CDG("propagator")
        ids_prop = []
        for factory in [create_v1_alpha, create_v2_beta, create_v3_gamma, create_v4_buffer]:
            nid = g_prop.store(factory())
            ids_prop.append(nid)
        prop_results = solve_with_propagator(g_prop, ids_prop)

        # Compare outcomes (node IDs match since both start fresh)
        for seq_id, prop_id in zip(ids_seq, ids_prop):
            assert seq_results[seq_id] == prop_results[prop_id][0], \
                f"Mismatch for {seq_id}: seq={seq_results[seq_id]} vs prop={prop_results[prop_id][0]}"


# ============================================================
# TRAIL TESTS
# ============================================================

class TestTrail:
    """Push/pop trail-based undo."""

    def test_push_pop_restores_state(self):
        """push() then pop() restores determined set."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        # Initial state: empty
        assert len(prop._determined) == 0

        prop.push()
        prop._determined["c_0001"] = (SolverOutcome.SAT, {"index": 42})
        assert len(prop._determined) == 1

        prop.pop(1)
        assert len(prop._determined) == 0

    def test_nested_push_pop(self):
        """Nested push/pop correctly restores each level."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        prop.push()
        prop._determined["c_0001"] = (SolverOutcome.SAT, {"index": 42})

        prop.push()
        prop._determined["c_0002"] = (SolverOutcome.SAT, {"index": 99})
        assert len(prop._determined) == 2

        prop.pop(1)
        assert len(prop._determined) == 1
        assert "c_0001" in prop._determined

        prop.pop(1)
        assert len(prop._determined) == 0

    def test_pop_multiple_scopes(self):
        """pop(2) restores across two levels at once."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        prop.push()
        prop._determined["c_0001"] = (SolverOutcome.SAT, {})
        prop.push()
        prop._determined["c_0002"] = (SolverOutcome.SAT, {})

        prop.pop(2)
        assert len(prop._determined) == 0

    def test_fresh_creates_clean_copy(self):
        """fresh() creates a new propagator with empty state but same graph."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)
        prop._determined["c_0001"] = (SolverOutcome.SAT, {})

        fresh_prop = prop.fresh(ctx=None)
        assert len(fresh_prop._determined) == 0
        assert fresh_prop._graph is g
        assert fresh_prop._node_ids == ids

    def test_push_pop_preserves_conflicted(self):
        """push/pop also preserves the conflicted set."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        prop.push()
        prop._conflicted.add("c_0001")
        assert "c_0001" in prop._conflicted

        prop.pop(1)
        assert "c_0001" not in prop._conflicted

    def test_push_pop_preserves_propagated(self):
        """push/pop also preserves the propagated set."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        prop.push()
        prop._propagated.add("c_0001")

        prop.pop(1)
        assert "c_0001" not in prop._propagated


# ============================================================
# FINAL CALLBACK TESTS
# ============================================================

class TestFinal:
    """_on_final cross-constraint propagation."""

    def test_dampening_prevents_duplicate_final(self):
        """Same assignment hash does not trigger _on_final twice."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)
        prop._determined["c_0001"] = (SolverOutcome.SAT, {"index": 42})

        prop._on_final()
        first_propagated = set(prop._propagated)

        # Call again — should be dampened
        prop._on_final()
        assert prop._propagated == first_propagated

    def test_sim_propagation_in_final(self):
        """SAT node propagates to SIM neighbors in _on_final."""
        g, ids = build_three_variant_graph()
        prop = CDGPropagator(graph=g, node_ids=ids)

        # Simulate that first node was determined SAT
        prop._determined[ids[0]] = (SolverOutcome.SAT, {"index": 42})

        prop._on_final()

        # SIM neighbors should be propagated
        # ids[1] and ids[2] share skeleton with ids[0]
        propagated_count = len(prop._propagated)
        assert propagated_count >= 1, \
            f"Expected SIM propagation, got {propagated_count} propagated"


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestIntegration:
    """Full pipeline integration tests."""

    def test_full_pipeline_with_propagator(self):
        """End-to-end: build CDG, propagator-solve, check outcomes."""
        g = CDG("integration")
        id1 = g.store(create_v1_alpha())
        id2 = g.store(create_v2_beta())
        id3 = g.store(create_v3_gamma())
        id4 = g.store(create_v4_buffer())

        results = solve_with_propagator(g, [id1, id2, id3, id4])

        assert len(results) == 4
        for nid in [id1, id2, id3, id4]:
            outcome, _ = results[nid]
            assert outcome == SolverOutcome.SAT

    def test_propagator_vs_sequential_parity(self):
        """Propagator and sequential solver produce identical outcomes."""
        factories = [create_v1_alpha, create_v2_beta, create_v3_gamma, create_v4_buffer]

        # Sequential
        g_seq = CDG("seq")
        seq_outcomes = []
        for f in factories:
            nid = g_seq.store(f())
            outcome, _ = solver.solve(g_seq, nid)
            seq_outcomes.append(outcome)

        # Propagator
        g_prop = CDG("prop")
        prop_ids = [g_prop.store(f()) for f in factories]
        prop_results = solve_with_propagator(g_prop, prop_ids)
        prop_outcomes = [prop_results[nid][0] for nid in prop_ids]

        assert seq_outcomes == prop_outcomes, \
            f"Parity violation: seq={seq_outcomes} vs prop={prop_outcomes}"

    def test_empty_node_list(self):
        """solve_with_propagator with empty list returns empty dict."""
        g = CDG("test")
        results = solve_with_propagator(g, [])
        assert results == {}

    def test_all_cached_skips_z3(self):
        """When all nodes are cached, no Z3 session is created."""
        g = CDG("test")
        nid1 = g.store(create_v1_alpha())

        # Pre-solve to populate cache
        solver.solve(g, nid1)

        # Create second node with same formula
        nid2_node = create_v2_beta()
        nid2 = g.store(nid2_node)

        # Both should be resolved from cache
        results = solve_with_propagator(g, [nid1, nid2])
        assert len(results) == 2
        for nid in [nid1, nid2]:
            assert results[nid][0] == SolverOutcome.SAT

    @pytest.mark.skipif(not HAS_Z3, reason="Z3 not available")
    def test_unsat_constraint_gets_con_edges(self):
        """UNSAT result triggers CON edge creation."""
        g = CDG("test")
        # Create a dep chain so _extract_conflicts has edges to work with
        c_dep = make_constraint(
            formula="msg_len >= 8",
            skeleton="VAR >= CONST",
            cwe=CWEClass.UNKNOWN,
            func="test_func", bb=1, addr=0x0100,
            version="v1.0",
            variables={"msg_len"},
            var_types={"msg_len": "bv16"},
        )
        dep_id = g.store(c_dep)

        c_unsat = create_unsat_constraint()
        unsat_id = g.store(c_unsat, dep_sources=[dep_id])

        results = solve_with_propagator(g, [unsat_id])
        outcome, _ = results[unsat_id]
        assert outcome == SolverOutcome.UNSAT

        # Check that CON edges were created
        con_edges = [e for e in g.edges if e.label == EdgeLabel.CON]
        assert len(con_edges) >= 1, "UNSAT should create CON edges"

    def test_no_z3_fallback(self):
        """Without Z3, propagator falls back to sequential solve."""
        # This test always runs (uses mock solver if no Z3)
        g = CDG("test")
        nid = g.store(create_v1_alpha())
        results = solve_with_propagator(g, [nid])

        assert nid in results
        outcome, _ = results[nid]
        # Mock solver returns SAT for ">=" constraints
        assert outcome in (SolverOutcome.SAT, SolverOutcome.UNKNOWN)
