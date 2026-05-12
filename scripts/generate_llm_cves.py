"""Generate labeled CVE constraint pairs via Claude.

When ANTHROPIC_API_KEY is set, this calls the Anthropic API for each NVD CVE
descriptor and asks Claude to produce a constraint-pair record matching the
JSONL schema in tests/fixtures/sample_llm_cves.jsonl.

When ANTHROPIC_API_KEY is unset, this falls back to copying the fixture file
as a stand-in. This keeps the training pipeline runnable in CI/offline.

Usage:
    python -m scripts.generate_llm_cves <nvd_descriptors.json> <out.jsonl>
"""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import List


SYSTEM_PROMPT = """You generate constraint pairs for firmware vulnerability
research. Given a CVE description, output a single JSON object with these
fields:

  cve_id: the CVE identifier
  cwe: the CWE class (e.g., CWE-787)
  vulnerable_constraint: a Python expression over bitvector variables that is
      satisfiable when the vulnerability is triggered
  patched_constraint: the corresponding constraint after the patch; should be
      unsatisfiable (e.g., a bv16 variable > 65535)
  vars: dict mapping variable names to bvN type strings
  label: "same_bug"

Output ONLY the JSON object, no surrounding prose, no code fences.
"""


def _call_claude(descriptor: dict):
    """Call Claude. Return parsed JSON record or None on failure."""
    try:
        import anthropic
    except ImportError:
        return None
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"CVE: {descriptor.get('cve_id')}\nDescription: {descriptor.get('description')}",
        }],
    )
    text = msg.content[0].text if msg.content else ""
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return None


def generate_corpus(descriptors_path: Path, out_path: Path) -> int:
    """Generate corpus. Returns number of records written.

    Falls back to copying the test fixture when ANTHROPIC_API_KEY is unset.
    """
    descriptors_path = Path(descriptors_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        # Offline mode — copy fixture for reproducibility in CI.
        fixture = Path("tests/fixtures/sample_llm_cves.jsonl")
        if fixture.exists():
            shutil.copy(fixture, out_path)
            return sum(1 for _ in out_path.open())
        out_path.write_text("")
        return 0

    descriptors: List[dict] = json.loads(descriptors_path.read_text())
    n = 0
    with out_path.open("w") as f:
        for desc in descriptors:
            rec = _call_claude(desc)
            if rec is None:
                continue
            f.write(json.dumps(rec) + "\n")
            n += 1
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m scripts.generate_llm_cves <descriptors.json> <out.jsonl>",
              file=sys.stderr)
        sys.exit(2)
    n = generate_corpus(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"wrote {n} records to {sys.argv[2]}")
