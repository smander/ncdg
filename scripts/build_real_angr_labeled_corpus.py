"""Build a Z3-labeled real-angr corpus by labeling each claripy AST in-flight.

Key idea: at extraction time we have the original claripy AST, not just its
str() repr. We use claripy.Solver() to check satisfiability directly. This
bypasses the lossy str(ast) -> regex-parser path that produced vacuous-SAT
labels in build_predictor_corpus.py.

Output records (JSONL):
  formula  : str(claripy_ast)        # for human inspection / training input
  outcome  : "SAT" | "UNSAT" | "UNKNOWN"
  vars, var_types, cwe, function, version, target, cve_id

Usage:
    python -m scripts.build_real_angr_labeled_corpus \\
        --out data/real_angr_labeled.jsonl
"""

import argparse
import json
import sys
from pathlib import Path

from cdg_lib.types import CWEClass


def _resolve_binary(target_name: str, version: str):
    fname = "u-boot" if target_name == "uboot" else "bl2.elf"
    p = Path("firmware/binaries") / target_name / version / fname
    return p if p.is_file() else None


def _label_via_claripy(ast) -> str:
    """Label an AST via claripy's solver. Returns 'SAT' | 'UNSAT' | 'UNKNOWN'."""
    try:
        import claripy
        s = claripy.Solver()
        s.add(ast)
        if s.satisfiable():
            return "SAT"
        return "UNSAT"
    except Exception:
        return "UNKNOWN"


def build_corpus(out_path: Path) -> int:
    """Walk all binaries, run extraction, label each AST in-flight."""
    from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
    from firmware.harnesses import load_harness, HarnessNotFound
    from firmware.explorer import BoundedExplorer, ExplorerBudget
    from firmware.skeleton import compute_skeleton

    import angr

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    label_dist: dict = {}

    with out_path.open("w") as fout:
        for target in UBOOT_VERSIONS + TFA_VERSIONS:
            binary = _resolve_binary(target.name, target.git_tag)
            if binary is None:
                print(f"[skip] no binary for {target.name} {target.git_tag}", file=sys.stderr)
                continue

            for cve in target.cves:
                print(f"=== {target.name} {target.git_tag} {cve.cve_id} ===", file=sys.stderr)
                try:
                    harness = load_harness(cve.cve_id)
                except HarnessNotFound:
                    print(f"  no harness; skip", file=sys.stderr)
                    continue

                func = cve.target_functions[0]
                try:
                    proj = angr.Project(str(binary), auto_load_libs=False)
                except Exception as e:
                    print(f"  angr load failed: {e}", file=sys.stderr)
                    continue

                sym = proj.loader.find_symbol(func)
                if sym is None:
                    print(f"  symbol {func} not found; skip", file=sys.stderr)
                    continue

                try:
                    init_state, _ = harness.build_call_state(proj, sym)
                    target_pc = harness.target_addr(proj, sym)
                except Exception as e:
                    print(f"  harness failed: {e}", file=sys.stderr)
                    continue

                budget = ExplorerBudget(loop_bound=10, max_states=200, time_seconds=60)
                explorer = BoundedExplorer(proj, budget=budget)
                try:
                    result = explorer.run(init_state, find_addr=target_pc)
                except Exception as e:
                    print(f"  explorer failed: {e}", file=sys.stderr)
                    continue

                cwe_str = (cve.cwe_class.value if isinstance(cve.cwe_class, CWEClass)
                           else str(cve.cwe_class))
                version = target.git_tag

                cve_n = 0
                for ast in result.constraints:
                    try:
                        label = _label_via_claripy(ast)
                        formula_str = str(ast)
                        skeleton = compute_skeleton(ast)
                        variables = list(ast.variables) if hasattr(ast, "variables") else []
                        var_types = {v: f"bv{ast.size()}" for v in variables} if variables else {}
                    except Exception:
                        continue

                    rec = {
                        "formula": formula_str,
                        "skeleton": skeleton,
                        "cwe": cwe_str,
                        "vars": variables,
                        "var_types": var_types,
                        "outcome": label,
                        "cve_id": cve.cve_id,
                        "version": version,
                        "target": target.name,
                        "function": func,
                    }
                    fout.write(json.dumps(rec) + "\n")
                    n += 1
                    cve_n += 1
                    label_dist[label] = label_dist.get(label, 0) + 1

                print(f"  wrote {cve_n} records (running total: {n})", file=sys.stderr)

    print(f"\nTotal: {n} records", file=sys.stderr)
    print(f"Label distribution: {label_dist}", file=sys.stderr)
    return n


def _main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    n = build_corpus(args.out)
    print(f"wrote {n} records to {args.out}")


if __name__ == "__main__":
    _main()
