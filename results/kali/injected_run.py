"""
injected_run.py
The comparable measurement for the authentic Kali attacks, now under camouflage.

`results/kali/notes.md` records that the first authentic attacks were scored
*standalone* -- a ~100-line capture that is almost entirely the attack itself --
and that the resulting 0%/33% instance detection is not comparable to the
synthetic corpus's 100%, because an attacked account with no benign history in
the corpus has no per-user baseline for the burst to be anomalous against.
`results/kali/injected_notes.md` records the fix: injected into the real
OpenSSH benign background both arms read 100% at baseline.

This script now carries the next arm CLAUDE.md section 4 asks for -- instance
detection *under camouflage* (item 3), pooled over >= 5 seeds. Both arms, on
the *same* real OpenSSH background, at the same ambient ratio and the same
seeds, are camouflaged by the *same shared library code*:

  authentic  captured hydra/ssh lines injected by corpus_captured.py
  synthetic  the scenario generators corpus_openssh.build_killpoint_corpus uses

The camouflage is `logdet_eval.camouflage`, the one source of truth the fixed
recipes and the adaptive adversary already use, applied to the attack lines
only (benign background is untouched -- an attacker controls their own traffic).
So this is a *runner* change: no transform is authored here, camouflage.py is
imported not reimplemented, and the authentic and synthetic arms apply
byte-identical transforms so a gap between them is a property of authentic
attack traffic and not of the camouflage.

Reported per scenario and pooled over seeds through the kill point's own
pooler, which recomputes rates from summed counts rather than averaging them
(CLAUDE.md section 4: a single seed moves instance detection in 33% steps with
3 instances).

    uv run python results/kali/injected_run.py --seeds 5            # full 9 conditions
    uv run python results/kali/injected_run.py --seeds 1 \
        --conditions baseline rephrase slow realistic-combo         # smoke pass

This is evaluation only -- nothing here touches detection, grouping or scoring
code, so section 4's re-run obligation does not apply to it.
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import pandas as pd

from logdet_eval import camouflage, scoring
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

# The same nine conditions the synthetic adversarial suite runs (adversarial.py):
# baseline, each strategy alone, and the hand-picked strongest realistic combo.
CONDITIONS = (
    [("baseline", [])]
    + [(s, [s]) for s in camouflage.STRATEGIES]
    + [("realistic-combo", list(camouflage.REALISTIC_COMBO))]
)
CONDITION_STRATEGIES = dict(CONDITIONS)


def make_pid_fn(seed: int):
    """A deterministic PID source for a camouflage arm's noise filler.

    camouflage.default_pid draws from the *global* `random` module and a module
    global counter, which is fine for the synthetic track (it seeds the global
    RNG) but would make an injected run non-reproducible, since this script
    seeds only local Random instances. A closure over its own Random keeps the
    arm reproducible per seed.
    """
    rng = random.Random(seed ^ 0x9E3779B9)
    counter = [1000]

    def pid() -> int:
        counter[0] += rng.randint(1, 9)
        return counter[0]

    return pid


def apply_camouflage(events: list[dict], strategies: list[str], seed: int,
                     users: list[str]) -> list[dict]:
    """Camouflage the attack lines in a combined corpus, benign left untouched.

    Baseline (no strategies) returns the events unchanged, so a baseline arm is
    byte-identical to the un-camouflaged injected run rather than merely equal
    after a re-sort.
    """
    if not strategies:
        return events
    return camouflage.camouflage_events(
        events, strategies, seed, users=users, pid_fn=make_pid_fn(seed))


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
    parser.add_argument("--conditions", nargs="*", default=None,
                        metavar="NAME",
                        help="subset of camouflage conditions to run "
                             f"(default all {len(CONDITIONS)}); choose from: "
                             + ", ".join(name for name, _ in CONDITIONS))
    parser.add_argument("--captures", nargs="*", default=None,
                        metavar="corpus.log:ground_truth.csv")
    parser.add_argument("--output", default="results/kali/injected")
    parser.add_argument("--workdir", default="data/processed/kali_injected/runs")
    args = parser.parse_args(argv)

    if args.conditions:
        unknown = [c for c in args.conditions if c not in CONDITION_STRATEGIES]
        if unknown:
            parser.error(f"unknown conditions: {unknown}; choose from "
                         + ", ".join(name for name, _ in CONDITIONS))
        conditions = [(name, CONDITION_STRATEGIES[name]) for name in args.conditions]
    else:
        conditions = CONDITIONS

    if args.captures:
        pairs = parse_pairs(args.captures)
    else:
        pairs = [(str(CAPTURE_DIR / f"{name}.log"),
                  str(CAPTURE_DIR / f"{name}_gt.csv")) for name in DEFAULT_CAPTURES]

    captures = load_captures(pairs)
    seeds = list(range(args.seed_start, args.seed_start + args.seeds))
    workdir = Path(args.workdir)
    started = time.time()

    # runs[arm][condition] -> list of per-seed results
    runs: dict[str, dict[str, list[dict]]] = {
        arm: {name: [] for name, _ in conditions}
        for arm in ("authentic", "synthetic")
    }
    manifests: list[dict] = []

    for seed in seeds:
        print(f"\n########## seed {seed} ##########", flush=True)
        auth_events, manifest = build_captured_corpus(
            captures, ambient_ratio=args.ambient_ratio, seed=seed)
        manifests.append(manifest)
        users = manifest["real_users"]

        syn_events, _ = build_killpoint_corpus(
            instances_per_scenario=3, ambient_ratio=args.ambient_ratio, seed=seed)

        arms = {"authentic": auth_events, "synthetic": syn_events}
        for name, strategies in conditions:
            for arm, base_events in arms.items():
                cam = apply_camouflage(base_events, strategies, seed, users)
                result = score_corpus(cam, workdir, f"{arm}_{name}_seed{seed}")
                runs[arm][name].append(result)
                o = result["overall"]
                print(f"  {arm:<10} {name:<16} "
                      f"instance {o['instance_detection_rate']:.0%} "
                      f"line {o['line_detection_rate']:.0%} "
                      f"({o['total_flagged_lines']} flagged of {o['total_lines']})",
                      flush=True)

    pooled = {
        arm: {name: scoring.pool_runs(runs[arm][name]) for name, _ in conditions}
        for arm in ("authentic", "synthetic")
    }

    payload = {
        "seeds": seeds,
        "ambient_ratio": args.ambient_ratio,
        "elapsed_seconds": round(time.time() - started, 1),
        "conditions": [name for name, _ in conditions],
        "captures": manifests[0]["captures"],
        "pooled": pooled,
        "per_seed": runs,
    }

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "injected.json").write_text(json.dumps(payload, indent=2))
    (out / "injected.md").write_text(render(payload))
    print("\n" + render(payload))
    return 0


def _delta(pooled: dict, name: str, baseline: dict | None, key: str) -> str:
    """Signed point delta of an overall rate vs the baseline condition."""
    if baseline is None or name == "baseline":
        return ""
    gap = (pooled[name]["overall"][key] - baseline["overall"][key]) * 100
    return f" ({gap:+.1f})"


def render(payload: dict) -> str:
    conditions = payload["conditions"]
    lines = [
        "# Authentic Kali attacks under camouflage, in the real OpenSSH background",
        "",
        f"Seeds: {payload['seeds']}  |  ambient ratio: {payload['ambient_ratio']}"
        f"  |  {payload['elapsed_seconds']}s",
        "",
        "Both arms use the identical background, ambient ratio, seeds and scorer,",
        "and the identical camouflage transforms (`logdet_eval.camouflage`)",
        "applied to the attack lines only. Only the origin of the attack lines",
        "differs: authentic captured hydra/ssh output, or the synthetic scenario",
        "generators.",
        "",
        "## Instance detection, pooled over seeds (rates from summed counts)",
        "",
        "| arm | condition | instance detection | line detection | attack lines |",
        "|---|---|---|---|---|",
    ]
    for arm in ("authentic", "synthetic"):
        baseline = payload["pooled"][arm].get("baseline")
        baseline_overall = baseline["overall"] if baseline else None
        base = {"overall": baseline_overall} if baseline_overall else None
        for name in conditions:
            o = payload["pooled"][arm][name]["overall"]
            di = _delta(payload["pooled"][arm], name, base, "instance_detection_rate")
            dl = _delta(payload["pooled"][arm], name, base, "line_detection_rate")
            lines.append(
                f"| {arm} | {name} | "
                f"{o['instance_detection_rate']:.1%}{di} "
                f"({o['instances_detected']}/{o['instances']}) | "
                f"{o['line_detection_rate']:.1%}{dl} | "
                f"{o['attack_lines']} |")

    lines += [
        "",
        "## Per scenario (instance detection, pooled)",
        "",
        "| arm | condition | A brute force | C enumeration |",
        "|---|---|---|---|",
    ]
    for arm in ("authentic", "synthetic"):
        for name in conditions:
            per = payload["pooled"][arm][name]["per_scenario"]
            cells = []
            for scenario in ("A", "C"):
                if scenario in per:
                    row = per[scenario]
                    cells.append(f"{row['instance_detection_rate']:.0%} "
                                 f"({row['instances_detected']}/{row['instances']})")
                else:
                    cells.append("--")
            lines.append(f"| {arm} | {name} | {cells[0]} | {cells[1]} |")

    lines += [
        "",
        "Scenario B (impossible travel) appears in the synthetic arm only: its",
        "distant leg needs a second geographic IP and stays synthetic by",
        "necessity (CLAUDE.md section 2d), so no authentic capture exists for it.",
        "",
        "## Alert volume (mean flagged lines over seeds)",
        "",
        "| arm | condition | flagged lines | corpus lines |",
        "|---|---|---|---|",
    ]
    for arm in ("authentic", "synthetic"):
        for name in conditions:
            results = payload["per_seed"][arm][name]
            mean_flagged = sum(r["overall"]["total_flagged_lines"]
                               for r in results) / len(results)
            mean_total = sum(r["overall"]["total_lines"]
                             for r in results) / len(results)
            lines.append(f"| {arm} | {name} | {mean_flagged:.0f} | {mean_total:.0f} |")

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
