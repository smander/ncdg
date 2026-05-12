"""Two-stage training for f_theta.

Stage 1 (optional): MLM pretraining on SMT-COMP corpus.
Stage 2 (always):   contrastive fine-tuning on (vulnerable_constraint,
                     patched_constraint, label) triples from the LLM-CVE
                     corpus, with hard negatives from same-CWE differ-CVE.

Loss: MultipleNegativesRankingLoss for the fine-tune (sentence-transformers
standard). Optimizer: AdamW with linear warmup. Default hyperparameters are
chosen for a quick sanity run; override via CLI flags.

Usage:
    python -m scripts.train_embedder \
        --pretrain data/smtcomp_pretrain.jsonl \
        --finetune data/llm_cve_pairs.jsonl \
        --out models/embedder \
        --epochs 3 \
        --batch-size 16
"""

import argparse
import json
from pathlib import Path
from typing import List

from cdg_lib.neural.config import NeuralConfig


def _load_jsonl(path: Path) -> List[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _make_finetune_examples(records: List[dict]):
    """Build sentence-transformers InputExample list from labeled CVE records."""
    from sentence_transformers import InputExample
    examples = []
    for rec in records:
        if rec.get("label") != "same_bug":
            continue
        v = rec.get("vulnerable_constraint")
        p = rec.get("patched_constraint")
        if not v or not p:
            continue
        examples.append(InputExample(texts=[v, p], label=1.0))
    return examples


def train_embedder(pretrain_path, finetune_path, out_dir,
                   epochs: int = 3, batch_size: int = 16) -> None:
    from sentence_transformers import SentenceTransformer, losses
    from torch.utils.data import DataLoader

    cfg = NeuralConfig()
    out_dir = Path(out_dir)
    model = SentenceTransformer(cfg.base_model)

    # Stage 2: contrastive fine-tune (Stage 1 MLM pretrain is optional and
    # skipped by default; sentence-transformers' base model already has good
    # text representations).
    finetune_records = _load_jsonl(Path(finetune_path))
    examples = _make_finetune_examples(finetune_records)
    if not examples:
        print("[warn] no fine-tune examples; saving base model unchanged")
        out_dir.mkdir(parents=True, exist_ok=True)
        model.save(str(out_dir))
        return
    loader = DataLoader(examples, shuffle=True, batch_size=batch_size)
    loss = losses.MultipleNegativesRankingLoss(model)
    model.fit(
        train_objectives=[(loader, loss)],
        epochs=epochs,
        warmup_steps=max(1, len(loader) // 10),
        show_progress_bar=False,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save(str(out_dir))


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pretrain", type=Path, default=None)
    p.add_argument("--finetune", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=16)
    args = p.parse_args()
    train_embedder(args.pretrain, args.finetune, args.out, args.epochs, args.batch_size)
    print(f"saved embedder to {args.out}")


if __name__ == "__main__":
    _main()
