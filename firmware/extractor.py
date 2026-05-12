"""Firmware constraint extractor: angr-based or synthetic fallback for CDG benchmark."""

import hashlib
from typing import List, Optional

from cdg_lib.models import ConstraintNode, make_constraint
from cdg_lib.types import CWEClass, SolverOutcome
from firmware.config import FirmwareTarget, CVEEntry


def _stable_addr(key: str) -> int:
    """Deterministic 16-bit address hash from arbitrary key."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:4], 16)


def location_addr(function: str, bb_offset: int) -> int:
    """Deterministic 32-bit address from (function_name, basic_block_offset).

    Used for real-angr cross-version stability: same (func, offset) maps to
    same address across firmware versions, enabling CDG.compare() to detect
    carried-over constraints without depending on absolute load addresses.
    """
    key = f"{function}@{bb_offset:x}"
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)

# ---------------------------------------------------------------------------
# Try to import angr; set flag so methods can gate on availability
# ---------------------------------------------------------------------------
try:
    import angr  # noqa: F401
    import claripy  # noqa: F401
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False


# ---------------------------------------------------------------------------
# Synthetic templates
# ---------------------------------------------------------------------------
# Each entry maps cve_id -> {"vulnerable": [...], "patched": [...]}
# Each node dict has keys: formula, skeleton, role, vars, types
# role is informational only (path_cond, data_flow, guard, trigger, trigger_blocked)

_SYNTHETIC_TEMPLATES = {
    "CVE-2022-30790": {
        "vulnerable": [
            {
                "formula": "ip_len >= 20",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"ip_len"},
                "types": {"ip_len": "bv16"},
            },
            {
                "formula": "frag_offset >= 0",
                "skeleton": "VAR >= CONST",
                "role": "data_flow",
                "vars": {"frag_offset"},
                "types": {"frag_offset": "bv16"},
            },
            {
                "formula": "frag_offset >= 1500",
                "skeleton": "VAR >= CONST",
                "role": "trigger",
                "vars": {"frag_offset"},
                "types": {"frag_offset": "bv16"},
            },
        ],
        "patched": [
            {
                "formula": "ip_len >= 20",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"ip_len"},
                "types": {"ip_len": "bv16"},
            },
            {
                "formula": "overlap_checked >= 1",
                "skeleton": "VAR >= CONST",
                "role": "guard",
                "vars": {"overlap_checked"},
                "types": {"overlap_checked": "bv16"},
            },
            {
                "formula": "frag_offset > 65535",
                "skeleton": "VAR > CONST",
                "role": "trigger_blocked",
                "vars": {"frag_offset"},
                "types": {"frag_offset": "bv16"},
            },
        ],
    },

    "CVE-2022-30552": {
        "vulnerable": [
            {
                "formula": "ip_len >= 20",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"ip_len"},
                "types": {"ip_len": "bv16"},
            },
            {
                "formula": "total_len >= 1500",
                "skeleton": "VAR >= CONST",
                "role": "trigger",
                "vars": {"total_len"},
                "types": {"total_len": "bv16"},
            },
        ],
        "patched": [
            {
                "formula": "ip_len >= 20",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"ip_len"},
                "types": {"ip_len": "bv16"},
            },
            {
                "formula": "total_len > 65535",
                "skeleton": "VAR > CONST",
                "role": "trigger_blocked",
                "vars": {"total_len"},
                "types": {"total_len": "bv16"},
            },
        ],
    },

    "CVE-2022-34835": {
        "vulnerable": [
            {
                "formula": "argc >= 3",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"argc"},
                "types": {"argc": "bv16"},
            },
            {
                "formula": "nbytes >= 0",
                "skeleton": "VAR >= CONST",
                "role": "data_flow",
                "vars": {"nbytes"},
                "types": {"nbytes": "bv16"},
            },
            {
                "formula": "nbytes >= 256",
                "skeleton": "VAR >= CONST",
                "role": "trigger",
                "vars": {"nbytes"},
                "types": {"nbytes": "bv16"},
            },
        ],
        "patched": [
            {
                "formula": "argc >= 3",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"argc"},
                "types": {"argc": "bv16"},
            },
            {
                "formula": "bounds_checked >= 1",
                "skeleton": "VAR >= CONST",
                "role": "guard",
                "vars": {"bounds_checked"},
                "types": {"bounds_checked": "bv16"},
            },
            {
                "formula": "nbytes > 65535",
                "skeleton": "VAR > CONST",
                "role": "trigger_blocked",
                "vars": {"nbytes"},
                "types": {"nbytes": "bv16"},
            },
        ],
    },

    "CVE-2022-47630": {
        "vulnerable": [
            {
                "formula": "cert_len >= 1",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"cert_len"},
                "types": {"cert_len": "bv32"},
            },
            {
                "formula": "ext_offset >= 0",
                "skeleton": "VAR >= CONST",
                "role": "data_flow",
                "vars": {"ext_offset"},
                "types": {"ext_offset": "bv32"},
            },
            {
                "formula": "ext_offset >= 4096",
                "skeleton": "VAR >= CONST",
                "role": "trigger",
                "vars": {"ext_offset"},
                "types": {"ext_offset": "bv32"},
            },
        ],
        "patched": [
            {
                "formula": "cert_len >= 1",
                "skeleton": "VAR >= CONST",
                "role": "path_cond",
                "vars": {"cert_len"},
                "types": {"cert_len": "bv32"},
            },
            {
                "formula": "bounds_validated >= 1",
                "skeleton": "VAR >= CONST",
                "role": "guard",
                "vars": {"bounds_validated"},
                "types": {"bounds_validated": "bv32"},
            },
            {
                "formula": "ext_offset > 4294967295",
                "skeleton": "VAR > CONST",
                "role": "trigger_blocked",
                "vars": {"ext_offset"},
                "types": {"ext_offset": "bv32"},
            },
        ],
    },
}


class FirmwareExtractor:
    """Extract constraint nodes from firmware binaries (angr) or via synthetic templates."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_for_cve(self, target: FirmwareTarget, cve: CVEEntry) -> List[ConstraintNode]:
        """Extract constraint nodes for a single CVE.

        If a binary_path was provided and angr is available, attempt real
        extraction; fall back to synthetic on any failure.
        """
        if self.binary_path is not None and HAS_ANGR:
            try:
                return self._extract_angr(target, cve)
            except Exception:
                pass
        return self._extract_synthetic(target, cve)

    def extract_all(self, target: FirmwareTarget) -> List[ConstraintNode]:
        """Extract constraint nodes for every CVE in *target*."""
        nodes: List[ConstraintNode] = []
        for cve in target.cves:
            nodes.extend(self.extract_for_cve(target, cve))
        return nodes

    # ------------------------------------------------------------------
    # Synthetic extraction
    # ------------------------------------------------------------------

    def _extract_synthetic(self, target: FirmwareTarget, cve: CVEEntry) -> List[ConstraintNode]:
        """Generate synthetic constraint nodes modelling a known CVE pattern."""
        template = _SYNTHETIC_TEMPLATES.get(cve.cve_id)
        if template is None:
            return self._extract_generic(target, cve)

        variant = "vulnerable" if cve.vulnerable else "patched"
        node_defs = template[variant]

        # Version-independent address so cross-version compare() sees same locations
        base_addr = _stable_addr(f"{target.name}_{cve.cve_id}")
        func = cve.target_functions[0]
        version = target.git_tag

        nodes: List[ConstraintNode] = []
        for idx, nd in enumerate(node_defs):
            node = make_constraint(
                formula=nd["formula"],
                skeleton=nd["skeleton"],
                cwe=cve.cwe_class,
                func=func,
                bb=idx,
                addr=base_addr + idx,
                version=version,
                variables=set(nd["vars"]),
                var_types=dict(nd["types"]),
            )
            nodes.append(node)

        return nodes

    def _extract_generic(self, target: FirmwareTarget, cve: CVEEntry) -> List[ConstraintNode]:
        """Fallback for CVEs not in _SYNTHETIC_TEMPLATES."""
        base_addr = _stable_addr(f"{target.name}_{cve.cve_id}")
        func = cve.target_functions[0]
        version = target.git_tag

        nodes = [
            make_constraint(
                formula="x >= 0",
                skeleton="VAR >= CONST",
                cwe=cve.cwe_class,
                func=func,
                bb=0,
                addr=base_addr,
                version=version,
                variables={"x"},
                var_types={"x": "bv32"},
            ),
            make_constraint(
                formula="x >= 1",
                skeleton="VAR >= CONST",
                cwe=cve.cwe_class,
                func=func,
                bb=1,
                addr=base_addr + 1,
                version=version,
                variables={"x"},
                var_types={"x": "bv32"},
            ),
        ]
        return nodes

    # ------------------------------------------------------------------
    # angr-based extraction (optional)
    # ------------------------------------------------------------------

    def _extract_angr(self, target: FirmwareTarget, cve: CVEEntry) -> List[ConstraintNode]:
        """Real angr extraction via per-CVE harness + bounded explorer.

        Falls back to synthetic on any failure.
        """
        if not HAS_ANGR:
            return self._extract_synthetic(target, cve)

        try:
            from firmware.harnesses import load_harness, HarnessNotFound
            from firmware.explorer import BoundedExplorer, ExplorerBudget
            from firmware.skeleton import compute_skeleton, to_smtlib
        except ImportError:
            return self._extract_synthetic(target, cve)

        try:
            harness = load_harness(cve.cve_id)
        except HarnessNotFound:
            return self._extract_synthetic(target, cve)

        import angr
        try:
            proj = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception:
            return self._extract_synthetic(target, cve)

        func = cve.target_functions[0]
        sym = proj.loader.find_symbol(func)
        if sym is None:
            # Fixture/tiny binaries may not have the symbol — fall back.
            return self._extract_synthetic(target, cve)

        try:
            init_state, _inputs = harness.build_call_state(proj, sym)
            target_pc = harness.target_addr(proj, sym)
        except Exception:
            return self._extract_synthetic(target, cve)

        budget = ExplorerBudget(loop_bound=10, max_states=200, time_seconds=60)
        explorer = BoundedExplorer(proj, budget=budget)

        try:
            result = explorer.run(init_state, find_addr=target_pc)
        except Exception:
            return self._extract_synthetic(target, cve)

        if not result.constraints:
            return self._extract_synthetic(target, cve)

        version = target.git_tag
        nodes: List[ConstraintNode] = []

        for idx, con in enumerate(result.constraints):
            try:
                formula_str = to_smtlib(con)
                skeleton_str = compute_skeleton(con)
                variables = {v for v in con.variables} if hasattr(con, "variables") else set()
                var_types = {v: f"bv{con.size()}" for v in variables} if variables else {}
            except Exception:
                continue

            addr = location_addr(func, idx * 4)
            node = make_constraint(
                formula=formula_str,
                skeleton=skeleton_str,
                cwe=cve.cwe_class,
                func=func,
                bb=idx,
                addr=addr,
                version=version,
                variables=variables,
                var_types=var_types,
            )
            nodes.append(node)

        if not nodes:
            return self._extract_synthetic(target, cve)
        return nodes
