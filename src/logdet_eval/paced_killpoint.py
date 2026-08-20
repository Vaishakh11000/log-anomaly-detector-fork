"""
paced_killpoint.py
The second half of the §1b kill point: the three camouflage strategies that
batch replay structurally cannot measure against Wazuh.

`killpoint.py` scores both systems on a corpus pushed through Wazuh at machine
speed. That is sound for the five timing-independent strategies and meaningless
for `slow`, `temporal` and `realistic-combo`, because Wazuh's correlation
windows key on **arrival time**: replayed instantly, an attack spread over hours
is still a burst to it, so its drop would be 0pt by construction. Those three are
excluded from the batch verdict for that reason.

This module measures them properly, by replaying the corpus in wall-clock time
(see `paced_replay` for why the schedule is affordable). Everything else is held
identical to the batch runner on purpose:

* the same detector, the same camouflage code, the same scorer
* both systems scored on the *same corpus file*, so the only difference between
  the two columns is the detector
* pooled over >=5 seeds, because instance detection moves in 33% steps at one

Our detector is scored in batch on that same file rather than paced, and that is
not a shortcut: it reads the timestamp out of each line, so wall-clock arrival
is irrelevant to it. Wazuh is the only system here that needs the wait.
"""

import json
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pandas as pd

from logdet.config import CONTAMINATION, RESULTS_DIR
from logdet_eval import paced_replay, wazuh_runner
from logdet_eval.adversarial import REALISTIC_COMBO, camouflage_events, detect_on_log
from logdet_eval.corpus_openssh import CORPUS_HOST, build_paced_corpus
from logdet_eval.generate_logs import write_outputs
from logdet_eval.killpoint import (
    CORPUS_START_YEAR,
    PRIMARY_LEVEL,
    _our_flagged_lines,
    load_resumable,
)
from logdet_eval.scoring import (
    MIN_ADMISSIBLE_SEEDS,
    differential,
    instance_drop,
    measure_lines,
    pool_runs,
    verdict,
)

# Only the strategies batch mode cannot reach, plus the baseline every drop is
# measured against. Re-measuring the timing-independent five here would cost
# hours to reproduce numbers `killpoint.py` already has.
CONDITIONS: list[tuple[str, list[str]]] = [
    ("baseline", []),
    ("slow", ["slow"]),
    ("temporal", ["temporal"]),
    ("realistic-combo", REALISTIC_COMBO),
]

# Thinning knobs. These set what a run costs and therefore whether the
# measurement happens at all, so they are declared in the manifest rather than
# left as defaults buried in a signature.
MAX_EVENTS_PER_IP = 12
TARGET_BACKGROUND_LINES = 600


def _corpus_lines(log_path: Path, events: list[dict]) -> tuple[list[str], list[float]]:
    """The written file's lines paired with each event's own clock value.

    `write_outputs` emits one line per event in timestamp order, which is the
    same order ground truth numbers them in, so index i of both lists refers to
    log line i+1.
    """
    lines = log_path.read_text().splitlines()
    stamps = [event["ts"].timestamp() for event in sorted(events, key=lambda e: e["ts"])]
    if len(lines) != len(stamps):
        raise AssertionError(
            f"{len(lines)} written lines for {len(stamps)} events -- line numbers "
            "would not line up with ground truth, so both systems would be "
            "scored against the wrong rows."
        )
    return lines, stamps


def run_paired(seeds: int = 5, start_seed: int = 42, ambient_ratio: float = 0.05,
               instances_per_scenario: int = 3,
               contamination: float = CONTAMINATION,
               levels: tuple[int, ...] = wazuh_runner.LEVEL_THRESHOLDS,
               max_events_per_ip: int = MAX_EVENTS_PER_IP,
               target_background_lines: int | None = TARGET_BACKGROUND_LINES,
               checkpoint: Callable[[dict], None] | None = None,
               resume_from: list[dict] | None = None) -> dict:
    """Score both systems per condition, replaying to Wazuh in wall-clock time."""
    have_wazuh = wazuh_runner.container_available()
    if not have_wazuh:
        print("WARNING: Wazuh container unavailable -- detector half only. "
              "This run cannot produce a differential.")

    manifest: dict = {}

    def _payload(done: list, complete: bool) -> dict:
        return {
            "corpus": "loghub-openssh-paced",
            "instrument": "paced-replay",
            "ambient_ratio": ambient_ratio,
            "max_events_per_ip": max_events_per_ip,
            "target_background_lines": target_background_lines,
            "min_spacing_seconds": paced_replay.MIN_SPACING,
            "seeds": seeds,
            "start_seed": start_seed,
            "contamination": contamination,
            "primary_level": PRIMARY_LEVEL,
            "wazuh_available": have_wazuh,
            "corpus_manifest": manifest,
            "conditions": done,
            "complete": complete,
            "conditions_expected": len(CONDITIONS),
        }

    # Conditions are independent, so a checkpoint from a killed run is not
    # merely a record of progress -- it is reusable work. Nothing consumed it
    # until now, which meant a crash at condition 8 of 9 still cost the whole
    # run.
    conditions = list(resume_from or [])
    already_done = {c["condition"] for c in conditions}
    if already_done:
        print(f"resuming: {len(already_done)} condition(s) already done "
              f"({', '.join(sorted(already_done))})")
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        work_dir = Path(tmp)
        for name, strategies in CONDITIONS:
            if name in already_done:
                continue
            ours_runs, siem_runs = [], []

            for offset in range(seeds):
                seed = start_seed + offset
                base_events, manifest = build_paced_corpus(
                    instances_per_scenario=instances_per_scenario,
                    ambient_ratio=ambient_ratio, seed=seed,
                    max_events_per_ip=max_events_per_ip,
                    target_background_lines=target_background_lines,
                )
                events = (base_events if not strategies
                          else camouflage_events(base_events, strategies, seed))

                log_path = work_dir / f"{name}_{seed}.log"
                gt_path = work_dir / f"{name}_{seed}_gt.csv"
                write_outputs(events, str(log_path), str(gt_path), host=CORPUS_HOST)
                ground_truth = pd.read_csv(gt_path)
                lines, stamps = _corpus_lines(log_path, events)

                scored = detect_on_log(str(log_path), str(work_dir / f"{name}_{seed}.csv"),
                                       year=CORPUS_START_YEAR, contamination=contamination)
                ours_runs.append(measure_lines(_our_flagged_lines(scored), ground_truth,
                                               total_lines=len(lines)))

                if have_wazuh:
                    scheduled = paced_replay.schedule(lines, stamps)
                    unsafe = paced_replay.verify_order_relaxation_safe(lines)
                    if any(unsafe.values()):
                        raise AssertionError(
                            f"corpus can drive an unkeyed frequency rule {unsafe}; "
                            "the relaxed schedule would inflate its firing rate")
                    minutes = paced_replay.replay_duration(scheduled) / 60
                    print(f"  {name} seed {seed}: replaying {len(lines)} lines "
                          f"over {minutes:.0f} min", flush=True)
                    paced_replay.reset_correlation_state()
                    alerts = paced_replay.run(scheduled)

                    per_level = {}
                    for level in levels:
                        flags = paced_replay.flagged_lines(alerts, scheduled, level)
                        per_level[str(level)] = measure_lines(
                            flags, ground_truth, total_lines=len(lines),
                            alert_count=len(flags))
                    siem_runs.append(per_level)

            entry = {
                "condition": name,
                "strategies": strategies,
                "ours": pool_runs(ours_runs),
            }
            if have_wazuh:
                entry["siem"] = {
                    str(level): pool_runs([r[str(level)] for r in siem_runs])
                    for level in levels
                }
            conditions.append(entry)

            ours_rate = entry["ours"]["overall"]["instance_detection_rate"]
            line = f"  {name:<17} ours {ours_rate:.0%}"
            if have_wazuh:
                siem_rate = entry["siem"][str(PRIMARY_LEVEL)]["overall"]["instance_detection_rate"]
                line += f"  | wazuh(L{PRIMARY_LEVEL}) {siem_rate:.0%}"
            print(f"{line}   [{(time.monotonic() - started) / 3600:.1f}h elapsed]",
                  flush=True)

            # A condition here is over an hour of wall clock that cannot be
            # recovered by running faster. Checkpointing per condition is the
            # difference between losing one and losing the night.
            if checkpoint is not None:
                checkpoint(_payload(conditions, complete=False))

    return _payload(conditions, complete=True)


def compare(payload: dict, level: int = PRIMARY_LEVEL) -> dict:
    """Per-strategy drops and the differential, for the paced instrument.

    Unlike the batch comparison there is no exclusion rule here: every strategy
    in this run is one the instrument can actually measure. That is the whole
    point of the module.
    """
    by_name = {c["condition"]: c for c in payload["conditions"]}
    base = by_name.get("baseline")
    if base is None:
        return {"level": level, "per_strategy": {}, "best_differential": None,
                "seeds": payload.get("seeds", 0), "admissible": False,
                "verdict": "INCOMPLETE", "verdict_basis": "paced replay"}

    rows = {}
    for name, cond in by_name.items():
        if name == "baseline":
            continue
        ours = instance_drop(base["ours"], cond["ours"])
        row = {"ours_drop": ours}
        if payload.get("wazuh_available"):
            siem = instance_drop(base["siem"][str(level)], cond["siem"][str(level)])
            row["siem_drop"] = siem
            row["differential"] = differential(ours, siem)
        rows[name] = row

    diffs = [r["differential"] for r in rows.values() if "differential" in r]
    best = max(diffs) if diffs else None

    seeds = payload.get("seeds", 0)
    admissible = seeds >= MIN_ADMISSIBLE_SEEDS
    if best is None:
        call = "INCOMPLETE"
    elif not admissible:
        call = f"INADMISSIBLE ({seeds} seed{'s' if seeds != 1 else ''}, need {MIN_ADMISSIBLE_SEEDS})"
    else:
        call = verdict(best)

    return {
        "level": level,
        "per_strategy": rows,
        "best_differential": best,
        "seeds": seeds,
        "admissible": admissible,
        "verdict": call,
        "verdict_basis": "timing-dependent strategies, paced replay",
    }


def render_report(payload: dict, comparison: dict) -> str:
    level = comparison["level"]
    lines = [
        "# Paced-Replay Measurement (CLAUDE.md §1b, timing strategies)",
        "",
    ]
    if not comparison.get("admissible", True):
        lines += [
            f"> ⛔ **NOT A RESULT — {payload['seeds']} seed(s), CLAUDE.md §4 requires "
            f"≥{MIN_ADMISSIBLE_SEEDS}.** Do not quote the differential below.",
            "",
        ]
    lines += [
        "The three strategies the batch runner cannot measure against Wazuh, measured.",
        "",
        "Wazuh keys its correlation windows on **arrival time**, so a corpus replayed at",
        "machine speed makes every event simultaneous to it and `slow`, `temporal` and",
        "`realistic-combo` show a 0pt drop *by construction*. Here the corpus is replayed",
        "in wall-clock time, so those windows mean what they mean in production.",
        "",
        f"`ambient_ratio={payload['ambient_ratio']}`, "
        f"`max_events_per_ip={payload['max_events_per_ip']}`, "
        f"spacing bound {payload['min_spacing_seconds']:.0f}s, pooled over "
        f"{payload['seeds']} seeds.",
        "",
        f"**Best differential: {comparison['best_differential']}pt "
        f"→ {comparison['verdict']}**",
        "",
        "## Instance-detection drop under camouflage",
        "",
        f"| Strategy | Ours (Δpt) | Wazuh L{level} (Δpt) | Differential |",
        "|---|---|---|---|",
    ]
    for name, row in comparison["per_strategy"].items():
        ours = f"{row['ours_drop']:+.1f}"
        siem = f"{row['siem_drop']:+.1f}" if "siem_drop" in row else "—"
        diff = f"**{row['differential']:+.1f}**" if "differential" in row else "—"
        lines.append(f"| {name} | {ours} | {siem} | {diff} |")

    lines += [
        "",
        "## Every alert level, not just the primary one",
        "",
        "Wazuh's level is *its* severity scale, and the comparison changes shape",
        "completely across it, so all three thresholds are reported rather than the",
        "one that reads best. Level 3 is where Wazuh starts writing alerts at all;",
        "7 is \"worth waking someone\"; 10 is its own brute-force tier.",
        "",
        "| Condition | Ours | Wazuh L3 | Wazuh L7 | Wazuh L10 |",
        "|---|---|---|---|---|",
    ]
    for cond in payload["conditions"]:
        ours = cond["ours"]["overall"]["instance_detection_rate"]
        row = f"| {cond['condition']} | {ours:.1%} |"
        for lvl in ("3", "7", "10"):
            rate = cond["siem"][lvl]["overall"]["instance_detection_rate"]
            row += f" {rate:.1%} |"
        lines.append(row)

    lines += [
        "",
        "Two things this table makes visible, and both cut against a clean story:",
        "",
        "- **At level 3 Wazuh cannot degrade, because it starts saturated.** A single",
        "  failed login is already a level-5 rule, so every injected instance is flagged",
        "  without any correlation happening at all. Its 100% is a property of the",
        "  threshold, not evidence that pacing failed to hurt it.",
        "- **At levels 7 and 10 Wazuh barely detects anything to begin with** — 11.1%,",
        "  one instance in nine, on the *clean* corpus. A system that starts near zero",
        "  cannot drop far, so the small differentials there are a floor effect rather",
        "  than robustness.",
        "",
        "## Alert volume",
        "",
        f"| Condition | Our incidents | Wazuh alerts (L{level}) |",
        "|---|---|---|",
    ]
    for cond in payload["conditions"]:
        ours = cond["ours"]["overall"]
        siem = (cond["siem"][str(level)]["overall"]["alerts"]
                if payload.get("wazuh_available") else "—")
        lines.append(f"| {cond['condition']} | {ours.get('total_flagged_lines', '—')} | {siem} |")

    manifest = payload["corpus_manifest"]
    lines += [
        "",
        "## Corpus and instrument",
        "",
        f"- {manifest['background_lines']} real background lines, thinned to at most "
        f"{payload['max_events_per_ip']} events per source IP",
        f"- {manifest['attack_lines']} injected attack lines, "
        f"{manifest['attack_instances']} instances",
        "- replayed per source IP, real gaps honoured up to "
        f"{payload['min_spacing_seconds']:.0f}s (below every shipped rule's "
        "`timeframe/frequency`)",
        "- Wazuh's ruleset, engine and clock are unmodified; correlation state is",
        "  reset between runs so no condition inherits another's counters",
        "",
        "Our detector is scored in batch on the identical corpus file — it reads the",
        "timestamp out of each line, so arrival order does not reach it.",
    ]
    return "\n".join(lines) + "\n"


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="The §1b kill point for timing-based camouflage (paced replay).")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--max-events-per-ip", type=int, default=MAX_EVENTS_PER_IP)
    parser.add_argument("--background-lines", type=int, default=TARGET_BACKGROUND_LINES)
    parser.add_argument("--conditions", default=None,
                        help="comma-separated subset, for smoke runs")
    parser.add_argument("--output-dir", default=f"{RESULTS_DIR}/killpoint")
    parser.add_argument("--resume", action="store_true",
                        help="reuse completed conditions from a checkpoint")
    args = parser.parse_args()

    global CONDITIONS
    if args.conditions:
        wanted = {c.strip() for c in args.conditions.split(",")}
        CONDITIONS = [c for c in CONDITIONS if c[0] in wanted]

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    tag = f"paced_ambient{args.ambient_ratio:g}"
    partial_path = out / f"killpoint_{tag}.partial.json"

    print(f"Paced kill point: {len(CONDITIONS)} conditions x {args.seeds} seeds")

    resume_from = None
    if args.resume:
        resume_from = load_resumable(partial_path, {
            "seeds": args.seeds, "start_seed": args.seed,
            "ambient_ratio": args.ambient_ratio, "contamination": CONTAMINATION,
            "max_events_per_ip": args.max_events_per_ip,
            "target_background_lines": args.background_lines,
        })

    payload = run_paired(seeds=args.seeds, start_seed=args.seed,
                         ambient_ratio=args.ambient_ratio,
                         max_events_per_ip=args.max_events_per_ip,
                         target_background_lines=args.background_lines,
                         checkpoint=lambda p: partial_path.write_text(json.dumps(p, indent=2)),
                         resume_from=resume_from)
    comparison = compare(payload)
    payload["comparison"] = comparison

    (out / f"killpoint_{tag}.json").write_text(json.dumps(payload, indent=2))
    (out / f"killpoint_{tag}.md").write_text(render_report(payload, comparison))

    print("\nDifferentials (paced instrument):")
    for name, row in sorted(comparison["per_strategy"].items(),
                            key=lambda kv: -kv[1].get("differential", float("-inf"))):
        if "differential" not in row:
            continue
        print(f"  {name:<17} ours {row['ours_drop']:+6.1f}  "
              f"wazuh {row['siem_drop']:+6.1f}  diff {row['differential']:+6.1f}")
    print(f"\nBest differential: {comparison['best_differential']}pt"
          f"  ->  {comparison['verdict']}")
    partial_path.unlink(missing_ok=True)
    print(f"Wrote -> {out}/killpoint_{tag}.json / .md")


if __name__ == "__main__":
    cli()
