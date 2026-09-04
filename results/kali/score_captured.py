"""
score_captured.py
Score authentic Kali-captured attack corpora on the analyzer.

This is the analyzer half of the offline Stage 6 path (CLAUDE.md section 2c: the
boxes are not cabled yet, so instead of shipping over the link, `attack_runner`
writes a corpus.log + ground_truth.csv on Kali and those files are carried back
here). It runs this project's real detection chain over each captured pair and
reports instance/line detection through `logdet_eval.scoring` -- the same scorer
the kill point and the adaptive runs use, so a captured number is comparable to
an injected-synthetic one.

Pass one or more (corpus.log, ground_truth.csv) pairs. Pairs of the same
scenario are pooled through the kill point's own pooler, because with a handful
of instances a single one moves instance detection in coarse steps (section 4).

    uv run python results/kali/score_captured.py \
        capture/A_1.log:capture/A_1_gt.csv \
        capture/A_2.log:capture/A_2_gt.csv

Real tool output is the base; only the camouflage layer (if any was applied on
Kali) is authored -- see attack_runner/KALI_RUNBOOK.md.
"""

import sys

import pandas as pd

from logdet_eval import scoring
from logdet_eval.adversarial import detect_on_log


def score_pair(corpus: str, gt: str, year: int) -> dict:
    scored = detect_on_log(corpus, corpus + ".parsed.csv", year=year)
    flagged = {i + 1 for i, flag in enumerate(scored["is_anomaly"].tolist()) if flag}
    total = sum(1 for _ in open(corpus))
    return scoring.measure_lines(flagged, pd.read_csv(gt), total_lines=total)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    year = 2026
    pairs = []
    for arg in argv:
        if arg.startswith("--year="):
            year = int(arg.split("=", 1)[1])
            continue
        corpus, _, gt = arg.partition(":")
        if not gt:
            print(f"expected corpus.log:ground_truth.csv, got {arg!r}", file=sys.stderr)
            return 2
        pairs.append((corpus, gt))

    per_scenario_runs: dict[str, list[dict]] = {}
    for corpus, gt in pairs:
        result = score_pair(corpus, gt, year)
        overall = result["overall"]
        print(f"{corpus}: instance {overall['instance_detection_rate']:.0%} "
              f"line {overall['line_detection_rate']:.0%} "
              f"({overall['attack_lines']} attack lines, "
              f"{overall['total_flagged_lines']} flagged)")
        for scenario in result["per_scenario"]:
            per_scenario_runs.setdefault(scenario, []).append(
                {"overall": overall, "per_scenario":
                 {scenario: result["per_scenario"][scenario]}})

    if len(pairs) > 1:
        print("\nPooled by scenario (kill point's pooler, rates from summed counts):")
        for scenario, runs in sorted(per_scenario_runs.items()):
            pooled = scoring.pool_runs(runs)["overall"]
            print(f"  scenario {scenario}: instance "
                  f"{pooled['instance_detection_rate']:.0%} "
                  f"line {pooled['line_detection_rate']:.0%} "
                  f"over {pooled['instances']} instance(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
