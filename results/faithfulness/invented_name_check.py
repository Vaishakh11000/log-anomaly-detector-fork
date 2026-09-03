"""
Why the shipped `technique_name` check reads 0 wrong names.

The checker only validates a name attached to an ID the incident was actually
handed, because the committed ATT&CK index carries just the 11 techniques this
system can emit -- there is nothing offline to check a foreign ID's name
against. Measured that way, phi3 never misnames a technique it was given.

The wrong names in the corpus are all attached to *invented* IDs, and this
one-off says so by checking them against the full pinned bundle (54MB,
gitignored; fetch with `logdet-attack --refresh`). It is a diagnostic, not part
of the pipeline: nothing here runs at inference time.

    uv run python results/faithfulness/invented_name_check.py
"""

import json
from pathlib import Path

from logdet.attack import BUNDLE_PATH, parse_bundle
from logdet_eval.faithfulness import _normalise_name, extract_claims

RUNS = {
    "synthetic": "results/faithfulness/faithfulness.json",
    "kill-point OpenSSH": "results/faithfulness/killpoint/faithfulness.json",
}


def main() -> None:
    if not BUNDLE_PATH.exists():
        raise SystemExit(f"{BUNDLE_PATH} missing -- run `logdet-attack --refresh` first.")
    bundle = parse_bundle()["techniques"]

    for label, path in RUNS.items():
        payload = json.loads(Path(path).read_text())
        checked = wrong = unknown_id = 0
        examples = []
        for check in payload["checks"]:
            handed = {c["value"] for c in check["claims"] if c["kind"] == "technique"} \
                     - {c["value"] for c in check["ungrounded"] if c["kind"] == "technique"}
            for claim in extract_claims(check["narrative"]):
                if claim.kind != "technique_name":
                    continue
                technique_id, _, phrase = claim.value.partition(": ")
                if technique_id in handed:
                    continue                       # the shipped check covers these
                entry = bundle.get(technique_id)
                if entry is None:
                    unknown_id += 1
                    continue
                checked += 1
                correct = {_normalise_name(entry["name"])}
                correct |= {_normalise_name(p) for p in entry["name"].split(":")}
                correct |= {_normalise_name(t) for t in entry["tactics"]}
                wanted = _normalise_name(phrase)
                if not any(wanted in name or name in wanted for name in correct if name):
                    wrong += 1
                    examples.append(f'{claim.value}  (ATT&CK: {entry["name"]})')

        print(f"\n{label}")
        print(f"  names beside an invented ID, checked against the bundle: {checked}")
        print(f"  ...wrong: {wrong}")
        print(f"  IDs the bundle does not carry at all: {unknown_id}")
        for example in sorted(set(examples))[:12]:
            print(f"    - {example}")


if __name__ == "__main__":
    main()
