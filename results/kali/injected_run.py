"""
injected_run.py
The comparable measurement for the authentic Kali attacks.

`results/kali/notes.md` records that the first authentic attacks were scored
*standalone* -- a ~100-line capture that is almost entirely the attack itself --
and that the resulting 0%/33% instance detection is not comparable to the
synthetic corpus's 100%, because an attacked account with no benign history in
the corpus has no per-user baseline for the burst to be anomalous against. This
script is the measurement that removes that confound.

Two arms, on the *same* real OpenSSH background, at the same ambient ratio and
the same seeds, scored by the same scorer:

  authentic  captured hydra/ssh lines injected by corpus_captured.py
  synthetic  the scenario generators corpus_openssh.build_killpoint_corpus uses

Only the origin of the attack lines differs, so a gap between the arms is a
property of authentic attack traffic rather than of the corpus or the scorer.
Reported per scenario and pooled over seeds through the kill point's own
pooler, which recomputes rates from summed counts rather than averaging them
(CLAUDE.md section 4: a single seed moves instance detection in 33% steps with
3 instances).

    uv run python results/kali/injected_run.py --seeds 5

This is evaluation only -- nothing here touches detection, grouping or scoring
code, so section 4's re-run obligation does not apply to it.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

from logdet_eval import scoring
from logdet_eval.adversarial import detect_on_log
from logdet_eval.corpus_captured import (
    build_captured_corpus,
    load_captures,
    parse_pairs,
)
from logdet_eval.corpus_openssh import CORPUS_HOST, build_killpoint_corpus
from logdet_eval.generate_logs import write_outputs

CAPTURE_DIR = Path(__file__).resolve().parent / "capture"
DEFAULT_CAPTURES = ["A_1", "A_2", "A_3", "C_1", "C_2", "C_3"]

# The corpus is written with real OpenSSH dates, which start in December 2015
# and roll into January; `load_events` reconstructs the rollover, so the year
# handed to the parser here only has to match the year the corpus was written
# with.
CORPUS_YEAR = 2015


def score_corpus(events: list[dict], workdir: Path, tag: str) -> dict:
    """Write a corpus out and run the real detection chain over it."""
    workdir.mkdir(parents=True, exist_ok=True)
    log_path = workdir / f"{tag}.log"
    gt_path = workdir / f"{tag}_gt.csv"
    write_outputs(events, str(log_path), str(gt_path), host=CORPUS_HOST)

    scored = detect_on_log(str(log_path), str(workdir / f"{tag}_parsed.csv"),
                           year=CORPUS_YEAR)
    flagged = {i + 1 for i, flag in enumerate(scored["is_anomaly"].tolist()) if flag}
    total = sum(1 for _ in open(log_path))
    return scoring.measure_lines(flagged, pd.read_csv(gt_path), total_lines=total)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, default=5,
                        help="number of seeds, starting at --seed-start")
    parser.add_argument("--seed-start", type=int, default=42)
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--captures", nargs="*", default=None,
                        metavar="corpus.log:ground_truth.csv")
    parser.add_argument("--output", default="results/kali/injected")
    parser.add_argument("--workdir", default="data/processed/kali_injected/runs")
    args = parser.parse_args(argv)

    if args.captures:
        pairs = parse_pairs(args.captures)
    else:
        pairs = [(str(CAPTURE_DIR / f"{name}.log"),
                  str(CAPTURE_DIR / f"{name}_gt.csv")) for name in DEFAULT_CAPTURES]

    captures = load_captures(pairs)
    seeds = list(range(args.seed_start, args.seed_start + args.seeds))
    workdir = Path(args.workdir)
    started = time.time()

    runs: dict[str, list[dict]] = {"authentic": [], "synthetic": []}
    manifests: list[dict] = []

    for seed in seeds:
        events, manifest = build_captured_corpus(
            captures, ambient_ratio=args.ambient_ratio, seed=seed)
        manifests.append(manifest)
        result = score_corpus(events, workdir, f"authentic_seed{seed}")
        runs["authentic"].append(result)
        print(f"authentic seed {seed}: "
              f"instance {result['overall']['instance_detection_rate']:.0%} "
              f"line {result['overall']['line_detection_rate']:.0%} "
              f"({result['overall']['total_flagged_lines']} flagged of "
              f"{result['overall']['total_lines']})", flush=True)

        events, _ = build_killpoint_corpus(
            instances_per_scenario=3, ambient_ratio=args.ambient_ratio, seed=seed)
        result = score_corpus(events, workdir, f"synthetic_seed{seed}")
        runs["synthetic"].append(result)
        print(f"synthetic seed {seed}: "
              f"instance {result['overall']['instance_detection_rate']:.0%} "
              f"line {result['overall']['line_detection_rate']:.0%} "
              f"({result['overall']['total_flagged_lines']} flagged of "
              f"{result['overall']['total_lines']})", flush=True)

    pooled = {arm: scoring.pool_runs(results) for arm, results in runs.items()}

    payload = {
        "seeds": seeds,
        "ambient_ratio": args.ambient_ratio,
        "elapsed_seconds": round(time.time() - started, 1),
        "captures": manifests[0]["captures"],
        "corpus_lines": {arm: results[0]["overall"]["total_lines"]
                         for arm, results in runs.items()},
        "pooled": pooled,
        "per_seed": runs,
    }

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "injected.json").write_text(json.dumps(payload, indent=2))
    (out / "injected.md").write_text(render(payload))
    print("\n" + render(payload))
    return 0


def render(payload: dict) -> str:
    lines = [
        "# Authentic Kali attacks injected into the real OpenSSH background",
        "",
        f"Seeds: {payload['seeds']}  |  ambient ratio: {payload['ambient_ratio']}"
        f"  |  {payload['elapsed_seconds']}s",
        "",
        "Both arms use the identical background, ambient ratio, seeds and scorer.",
        "Only the origin of the attack lines differs.",
        "",
        "## Pooled over seeds (rates recomputed from summed counts)",
        "",
        "| arm | scenario | instance detection | line detection | attack lines |",
        "|---|---|---|---|---|",
    ]
    for arm in ("authentic", "synthetic"):
        pooled = payload["pooled"][arm]
        for scenario in sorted(pooled["per_scenario"]):
            row = pooled["per_scenario"][scenario]
            lines.append(
                f"| {arm} | {scenario} | "
                f"{row['instance_detection_rate']:.1%} "
                f"({row['instances_detected']}/{row['instances']}) | "
                f"{row['line_detection_rate']:.1%} "
                f"({row['lines_detected']}/{row['attack_lines']}) | "
                f"{row['attack_lines']} |")
        overall = pooled["overall"]
        lines.append(
            f"| {arm} | **all** | **{overall['instance_detection_rate']:.1%}** | "
            f"**{overall['line_detection_rate']:.1%}** | "
            f"{overall['attack_lines']} |")

    lines += [
        "",
        "Scenario B (impossible travel) appears in the synthetic arm only: its",
        "distant leg needs a second geographic IP and stays synthetic by",
        "necessity (CLAUDE.md section 2d), so no authentic capture exists for",
        "it. Compare A against A and C against C; the `all` rows differ in",
        "composition as well as in origin.",
        "",
        "## Alert volume",
        "",
        "| arm | corpus lines | flagged lines (mean over seeds) |",
        "|---|---|---|",
    ]
    for arm in ("authentic", "synthetic"):
        results = payload["per_seed"][arm]
        mean_flagged = sum(r["overall"]["total_flagged_lines"] for r in results) / len(results)
        lines.append(f"| {arm} | {payload['corpus_lines'][arm]} | {mean_flagged:.0f} |")

    lines += ["", "## Per seed", "",
              "| arm | seed | instance | line | flagged |", "|---|---|---|---|---|"]
    for arm in ("authentic", "synthetic"):
        for seed, result in zip(payload["seeds"], payload["per_seed"][arm]):
            overall = result["overall"]
            lines.append(
                f"| {arm} | {seed} | {overall['instance_detection_rate']:.1%} | "
                f"{overall['line_detection_rate']:.1%} | "
                f"{overall['total_flagged_lines']} |")

    lines += ["", "The captured instances injected:", "",
              "| scenario | instance | lines | span (s) | description |",
              "|---|---|---|---|---|"]
    for capture in payload["captures"]:
        lines.append(f"| {capture['scenario']} | {capture['instance']} | "
                     f"{capture['lines']} | {capture['span_seconds']} | "
                     f"{capture['description']} |")

    lines += ["", "Interpretation is authored and lives in "
              "`results/kali/injected_notes.md`, not in this generator.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
