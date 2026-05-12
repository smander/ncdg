# Neural Constraint-Dependency Graphs for the Automated Security Analysis of Embedded Firmware

Reference implementation of the **Neural Constraint-Dependency Graph (N-CDG)** — a graph-accelerated SMT-constraint cache that reuses cross-version security-analysis verdicts on compiler-varied firmware via a tunable blend of symbolic skeleton match and neural cosine similarity.

## Overview

The N-CDG organises constraints extracted by symbolic execution into a directed graph with three edge types (dependency, similarity, conflict) and attaches a Sentence-Transformer embedding to each constraint node. Cross-version equivalence is decided by a tunable convex blend of skeleton match and neural cosine similarity. Soundness is preserved by construction: a cached SAT/UNSAT verdict is admitted only when the candidate formula is byte-equal to a previously solved formula up to variable renaming.

Evaluated on three U-Boot CVEs spanning v2022.04 and v2022.07 (`CVE-2022-30790`, `CVE-2022-30552`, `CVE-2022-34835`), the blend eliminates all 34 residual Z3 calls in the cross-version analysis phase and yields a median 3.0× (peak 135.8×) speedup over the symbolic baseline.

## Repository Layout

```
cdg_lib/                  Core library: graph model, similarity, solver, neural encoder.
firmware/                 Firmware extraction (angr-based), version metadata, synthetic benchmarks.
experiments/              Experiment runners + canonical result JSONs (Tables I–II, ablation).
scripts/                  Build, training, and verification scripts.
src/                      Synthetic multi-version C benchmarks (v1.0–v1.3).
tests/                    Pytest suite (~340 tests).
Dockerfile                Pinned-toolchain image for reproducible execution.
```

## Requirements

- Python 3.13
- Z3 ≥ 4.12
- `sentence-transformers`, `torch`, `faiss-cpu`, `angr` (see `requirements.txt`)

A Dockerfile with a pinned toolchain is provided for reproducibility.

## Quick Start

```bash
pip install -r requirements.txt
pip install -e .
python -m pytest tests/ -q
```

To reproduce the headline experiments:

```bash
python -m experiments.run_rq_speed         # Table I: cross-version speedup
python -m experiments.run_rq_alpha_sweep   # Table II: α-sensitivity sweep
python -m experiments.run_rq_conflict      # Conflict-pruning ablation
```

Result JSONs are written to `experiments/*.json`.

## Docker

```bash
docker build -t cdg-bench:latest .
bash scripts/verify_in_docker.sh
```

## Citation

If you use this code, please cite the accompanying paper:

```bibtex
@inproceedings{mostovyi2026ncdg,
  author    = {Oleksandr Mostovyi},
  title     = {Neural Constraint-Dependency Graphs for the Automated Security Analysis of Embedded Firmware},
  booktitle = {Proc. IEEE Int. Conf. on Dependable Systems, Services and Technologies (DESSERT)},
  year      = {2026}
}
```

## Author

**Oleksandr Mostovyi** — `adsmander@gmail.com`

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for full terms.
