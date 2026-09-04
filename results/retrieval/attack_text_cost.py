"""What ATT&CK's own technique text would cost in the narration prompt.

Stage 5 carried "retrieval over ATT&CK text" as an open item. There are two
things that phrase can mean and they have opposite risk profiles:

  (A) put ATT&CK's description of each matched technique into the *prompt*, so
      the model explains the technique in ATT&CK's terms;
  (B) render that description from the pinned index *beside* the narrative, so
      the analyst reads ATT&CK's words directly and no model is involved.

This script measures what (A) would cost, because that is the half that can be
measured without a judge. Run it from the repo root:

    uv run python results/retrieval/attack_text_cost.py

It needs the 54MB bundle at data/external/enterprise-attack-<version>.json,
which is gitignored -- fetch it with `uv run logdet-attack --refresh`.
"""

import json
from pathlib import Path

import pandas as pd

from logdet.attack import ATTACK_VERSION, summarise
from logdet.config import PROCESSED_DATA_DIR, PROJECT_ROOT
from logdet.llm_narrative import build_structured_prompt
from logdet.mitre_mapping import authored_technique_ids

BUNDLE = PROJECT_ROOT / "data" / "external" / f"enterprise-attack-{ATTACK_VERSION}.json"
INCIDENTS = Path(PROCESSED_DATA_DIR) / "incidents.json"


def full_descriptions() -> dict[str, str]:
    """The untrimmed description ATT&CK ships for each technique we can emit."""
    ours = set(authored_technique_ids())
    out = {}
    for obj in json.loads(BUNDLE.read_text())["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in ours:
                out[ref["external_id"]] = obj.get("description", "")
    return out


def main() -> None:
    full = full_descriptions()
    short = {tid: summarise(text) for tid, text in full.items()}

    print(f"ATT&CK {ATTACK_VERSION}, {len(full)} techniques this system can emit\n")
    print(f"{'technique':12s} {'full':>7s} {'first sentence':>15s}")
    for tid in sorted(full):
        print(f"{tid:12s} {len(full[tid]):7d} {len(short[tid]):15d}")
    print(f"{'TOTAL':12s} {sum(map(len, full.values())):7d} "
          f"{sum(map(len, short.values())):15d}  characters")

    # What it would do to a real prompt. Characters, not tokens: the tokeniser
    # is the model's, but ~4 characters per token is close enough to size the
    # decision and does not pretend to a precision this does not have.
    incidents = json.loads(INCIDENTS.read_text()) if INCIDENTS.exists() else []
    matched = [i for i in incidents if i.get("mitre_techniques")]
    if not matched:
        print("\nNo incidents.json with matches -- run logdet-pipeline --no-llm first.")
        return

    grew_full, grew_short, base = [], [], []
    for entry in matched:
        prompt = build_structured_prompt(pd.DataFrame(entry["events"]))
        ids = [t["technique_id"] for t in entry["mitre_techniques"]]
        base.append(len(prompt))
        grew_full.append(sum(len(full.get(t, "")) for t in ids))
        grew_short.append(sum(len(short.get(t, "")) for t in ids))

    n = len(matched)
    print(f"\n{n} incidents carry at least one technique.")
    print(f"  median prompt now:                      {sorted(base)[n // 2]:6d} chars")
    print(f"  median growth, full ATT&CK text:        {sorted(grew_full)[n // 2]:6d} chars "
          f"(+{sorted(grew_full)[n // 2] / sorted(base)[n // 2]:.0%})")
    print(f"  median growth, first sentence only:     {sorted(grew_short)[n // 2]:6d} chars "
          f"(+{sorted(grew_short)[n // 2] / sorted(base)[n // 2]:.0%})")
    print(f"  worst case, full ATT&CK text:           {max(grew_full):6d} chars")


if __name__ == "__main__":
    main()
