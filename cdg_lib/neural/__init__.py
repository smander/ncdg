"""Neural components for NS-CDG: similarity embedder and (Plan 2) UNSAT predictor.

Pure-symbolic operation is preserved: when `NeuralConfig.enable_neural` is False
or when no embedder is loaded, all functions degrade to the published symbolic
baseline.
"""

from cdg_lib.neural.config import NeuralConfig

__all__ = ["NeuralConfig"]
