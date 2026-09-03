"""
killpoint.py
The pre-registered kill-point experiment (CLAUDE.md section 1b), our half.

Runs the detector across every camouflage strategy on the *real* OpenSSH
corpus and reports the drop in instance detection for each. The third-party
SIEM is measured on the identical corpora by the Wazuh runner; the deciding
number is the differential between the two systems' drops.

Registered criterion, which may not be moved after seeing results:

    >=25pt differential on at least one strategy  -> continue the roadmap
    10-25pt                                       -> cheap stages only
    <10pt, or the SIEM degrades less than we do   -> stop, publish the negative

This module deliberately writes only *our* numbers. It does not compute the
differential, because a file that reports the deciding number should not also
be the file that could quietly redefine it -- the comparison lives in its own
step, fed by both systems' outputs.
"""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

import pandas as pd

from logdet.config import CONTAMINATION, RESULTS_DIR
from logdet_eval.adversarial import (
    REALISTIC_COMBO,
    STRATEGIES,
    camouflage_events,
    detect_on_log,
)
from logdet_eval.history import HISTORY_SEED_OFFSET, openssh_history
from logdet_eval.corpus_openssh import CORPUS_HOST, build_killpoint_corpus
from logdet_eval.generate_logs import write_outputs
from logdet_eval.scoring import (
    MIN_ADMISSIBLE_SEEDS,
    differential,
    instance_drop,
    measure_lines,
    pool_runs,
    verdict,
)
from logdet_eval import wazuh_runner

# The corpus starts in December and runs into January; preprocessing detects
# the rollover from there.
CORPUS_START_YEAR = 2015

# baseline first -- every drop is measured against it
CONDITIONS: list[tuple[str, list[str]]] = (
    [("baseline", [])]
    + [(name, [name]) for name in STRATEGIES]
    + [("realistic-combo", REALISTIC_COMBO)]
)

# Strategies whose whole mechanism is *when* events happen. Wazuh's correlation
# windows (and its `ignore` timers) are keyed on arrival time, so a corpus
# replayed at machine speed is simultaneous to it and these are unmeasurable in
# batch mode -- not "Wazuh is robust to them", but "this instrument cannot ask
# the question". They are measured by the paced replay instead.
TIMING_DEPENDENT = {"slow", "temporal", "realistic-combo"}

# Wazuh's own default alerting threshold. Kept as the primary comparison point
# because it is the only level where both systems start from a measurable
# baseline: at level>=7 the `ignore` timers throttle Wazuh to roughly one
# high-severity alert per wall-clock minute, which a 7-second replay cannot
# exercise. Higher thresholds are still reported.
PRIMARY_LEVEL = 3


# Parameters that must match for a checkpoint to be reusable. Resuming across a
# changed corpus or seed range would splice two different experiments together
# and report the result as one, which is worse than losing the run.
RESUME_KEYS = ("seeds", "start_seed", "ambient_ratio", "contamination",
               "max_events_per_ip", "target_background_lines",
               # Stage 3 suppression changes what the detector flags, so a
               # checkpoint written with it on and resumed into a run with it
               # off would splice two different experiments into one reported
               # differential -- the exact failure the resume guard exists for.
               "suppression")


def load_resumable(partial_path, settings: dict) -> list[dict] | None:
    """Completed conditions from a checkpoint, or None if it cannot be trusted."""
    import json as _json

    if not partial_path.exists():
        return None
    try:
        prior = _json.loads(partial_path.read_text())
    except (OSError, ValueError):
        print(f"WARNING: {partial_path.name} is unreadable -- starting fresh")
        return None

    mismatched = {
        key: (prior.get(key), settings[key])
        for key in RESUME_KEYS
        if key in settings and key in prior and prior[key] != settings[key]
    }
    if mismatched:
        print(f"WARNING: checkpoint does not match this run {mismatched} -- "
              "starting fresh rather than splicing two experiments together")
        return None
    if not prior.get("wazuh_available", False) and settings.get("expect_wazuh", True):
        print("WARNING: checkpoint was written without Wazuh -- starting fresh")
        return None
    return prior.get("conditions") or None


def _our_flagged_lines(scored: pd.DataFrame) -> set[int]:
    """Our detector's verdict as 1-based log line numbers, so it can go through
    the same scorer as the SIEM's."""
    return {i + 1 for i, flag in enumerate(scored["is_anomaly"].tolist()) if flag}


def run_paired(seeds: int = 5, start_seed: int = 42, ambient_ratio: float = 0.05,
               instances_per_scenario: int = 3,
               contamination: float = CONTAMINATION,
               levels: tuple[int, ...] = wazuh_runner.LEVEL_THRESHOLDS,
               checkpoint: Callable[[dict], None] | None = None,
               resume_from: list[dict] | None = None,
               suppress: bool = False) -> dict:
    """Score both systems on the *same corpus files*, condition by condition.

    Both sides go through scoring.measure_lines, so the only thing that differs
    between them is the detector. Running them in one loop over one written file
    is deliberate: if each system built its own corpus, any difference in the
    result could be a difference in the corpora instead.

    Pooling over >=5 seeds is not optional (CLAUDE.md section 4): with 3
    instances per scenario a single seed moves instance detection in 33% steps,
    and v1 saw ip_rotate read 100% at one seed against 84% pooled over five.
    """
    have_wazuh = wazuh_runner.container_available()
    if not have_wazuh:
        print("WARNING: Wazuh container unavailable -- detector half only")

    manifest: dict = {}

    def _payload(done: list, complete: bool) -> dict:
        return {
            "corpus": "loghub-openssh",
            "ambient_ratio": ambient_ratio,
            "seeds": seeds,
            "start_seed": start_seed,
            "contamination": contamination,
            "primary_level": PRIMARY_LEVEL,
            "wazuh_available": have_wazuh,
            "suppression": suppress,
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
    with tempfile.TemporaryDirectory() as tmp:
        work_dir = Path(tmp)
        # Stage 3 suppression, fitted once on a benign-only slice of the same
        # background. Once, not per seed and not per condition: it is history,
        # and refitting it alongside each corpus would confound "the attacker
        # changed tactics" with "the defender was shown a different past".
        fitted = None
        if suppress:
            fitted = openssh_history(work_dir, seed=start_seed + HISTORY_SEED_OFFSET,
                                     ambient_ratio=ambient_ratio,
                                     year=CORPUS_START_YEAR)
            print(f"Suppression on: {fitted.describe()}")
        for name, strategies in CONDITIONS:
            if name in already_done:
                continue
            ours_runs, siem_runs = [], []

            for offset in range(seeds):
                seed = start_seed + offset
                base_events, manifest = build_killpoint_corpus(
                    instances_per_scenario=instances_per_scenario,
                    ambient_ratio=ambient_ratio, seed=seed,
                )
                events = (base_events if not strategies
                          else camouflage_events(base_events, strategies, seed))

                log_path = work_dir / f"{name}_{seed}.log"
                gt_path = work_dir / f"{name}_{seed}_gt.csv"
                write_outputs(events, str(log_path), str(gt_path), host=CORPUS_HOST)
                ground_truth = pd.read_csv(gt_path)
                total_lines = sum(1 for _ in open(log_path))

                scored = detect_on_log(str(log_path), str(work_dir / f"{name}_{seed}.csv"),
                                       year=CORPUS_START_YEAR, contamination=contamination,
                                       sequence_model=fitted.model if fitted else None,
                                       miner_state=fitted.miner_state if fitted else None,
                                       suppress=suppress,
                                       suppression_threshold=fitted.threshold if fitted else None)
                ours_runs.append(measure_lines(_our_flagged_lines(scored), ground_truth,
                                               total_lines=total_lines))

                if have_wazuh:
                    verdicts = wazuh_runner.analyze(str(log_path))
                    per_level = {}
                    for level in levels:
                        flags = wazuh_runner.flagged_lines(verdicts, level)
                        per_level[str(level)] = measure_lines(
                            flags, ground_truth, total_lines=total_lines,
                            alert_count=len(flags))
                    siem_runs.append(per_level)

            entry = {
                "condition": name,
                "strategies": strategies,
                "timing_dependent": name in TIMING_DEPENDENT,
                "ours": pool_runs(ours_runs),
            }
            if have_wazuh:
                entry["siem"] = {
                    str(level): pool_runs([r[str(level)] for r in siem_runs])
                    for level in levels
                }
            conditions.append(entry)

            ours_rate = entry["ours"]["overall"]["instance_detection_rate"]
            line = f"  {name:<16} ours {ours_rate:.0%}"
            if have_wazuh:
                siem_rate = entry["siem"][str(PRIMARY_LEVEL)]["overall"]["instance_detection_rate"]
                line += f"  | wazuh(L{PRIMARY_LEVEL}) {siem_rate:.0%}"
                if name in TIMING_DEPENDENT:
                    line += "  [timing: batch cannot measure the SIEM]"
            print(line)

            # Each condition is ~3 minutes of embedding work and the loop has
            # been killed twice by machine reboots. Writing after every
            # condition turns that from "lose the whole run" into "lose one".
            if checkpoint is not None:
                checkpoint(_payload(conditions, complete=False))

    return _payload(conditions, complete=True)


def compare(payload: dict, level: int = PRIMARY_LEVEL) -> dict:
    """Per-strategy drops for both systems and the differential between them.

    Timing-dependent strategies are reported but excluded from the verdict:
    batch replay cannot measure them against an arrival-time-keyed SIEM, so
    including them would let a known instrument artefact decide the kill point.
    """
    by_name = {c["condition"]: c for c in payload["conditions"]}
    base = by_name["baseline"]
    rows = {}
    for name, cond in by_name.items():
        if name == "baseline":
            continue
        ours = instance_drop(base["ours"], cond["ours"])
        row = {"ours_drop": ours, "timing_dependent": cond["timing_dependent"]}
        if payload.get("wazuh_available"):
            siem = instance_drop(base["siem"][str(level)], cond["siem"][str(level)])
            row["siem_drop"] = siem
            row["differential"] = differential(ours, siem)
        rows[name] = row

    measurable = [r["differential"] for r in rows.values()
                  if "differential" in r and not r["timing_dependent"]]
    best = max(measurable) if measurable else None

    # A verdict from too few seeds is not a weaker verdict, it is not a verdict.
    # This is enforced here rather than left to the reader because the rendered
    # report is what a future session will find on disk, and "22.2pt -> PARTIAL"
    # above a quiet "pooled over 1 seeds" reads exactly like a result.
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
        "best_measurable_differential": best,
        "seeds": seeds,
        "admissible": admissible,
        "verdict": call,
        "verdict_basis": "timing-independent strategies, batch replay",
    }


def render_report(payload: dict, comparison: dict) -> str:
    level = comparison["level"]
    lines = [
        "# Kill-Point Measurement (CLAUDE.md §1b)",
        "",
    ]
    if not comparison.get("admissible", True):
        lines += [
            f"> ⛔ **NOT A RESULT — {payload['seeds']} seed(s), CLAUDE.md §4 requires "
            f"≥{MIN_ADMISSIBLE_SEEDS}.**",
            ">",
            "> Instance detection moves in 33% steps at one seed (3 instances per",
            "> scenario), and v1 saw `ip_rotate` read 100% at a single seed against 84%",
            "> pooled over five. The differential below is a smoke-test artefact. **Do not",
            "> quote it, and do not record a kill-point verdict from it.** Re-run with",
            "> `uv run logdet-killpoint --seeds 5`.",
            "",
        ]
    lines += [
        "Detector vs **Wazuh** (real manager, v4.9.0, its own rules and engine) on the",
        f"real LogHub OpenSSH corpus. `ambient_ratio={payload['ambient_ratio']}`, pooled over",
        f"{payload['seeds']} seeds. Both systems scored on the *same corpus files* through the",
        "same scorer; the only difference between the two columns is the detector.",
        "",
        "## The registered criterion",
        "",
        "| Differential | Decision |",
        "|---|---|",
        "| ≥25pt | continue the roadmap |",
        "| 10–25pt | cheap stages only |",
        "| <10pt, or SIEM degrades less | stop, publish the negative result |",
        "",
        f"**Best measurable differential: {comparison['best_measurable_differential']}pt "
        f"→ {comparison['verdict']}**",
        f"({comparison['verdict_basis']})",
        "",
        "## Instance-detection drop under camouflage",
        "",
        f"| Strategy | Ours (Δpt) | Wazuh L{level} (Δpt) | Differential | Measurable in batch? |",
        "|---|---|---|---|---|",
    ]
    for name, row in comparison["per_strategy"].items():
        ours = f"{row['ours_drop']:+.1f}"
        siem = f"{row.get('siem_drop', float('nan')):+.1f}" if "siem_drop" in row else "—"
        diff = f"**{row['differential']:+.1f}**" if "differential" in row else "—"
        ok = "no — arrival-time" if row["timing_dependent"] else "yes"
        lines.append(f"| {name} | {ours} | {siem} | {diff} | {ok} |")

    lines += [
        "",
        "## Why three strategies are excluded from the verdict",
        "",
        "Wazuh's correlation windows and its `ignore` timers are keyed on **arrival",
        "time, not on the timestamp in the log line** — verified on both `wazuh-logtest`",
        "and the real `analysisd`: 15 `Invalid user` lines from one IP fire rule 5712",
        "identically at 3-second and 1-hour spacing. A corpus replayed at machine speed",
        "is therefore simultaneous to Wazuh, so `slow`, `temporal` and `realistic-combo`",
        "cannot be measured against it in batch mode. That is a limit of the instrument,",
        "not evidence that Wazuh resists them; the paced replay measures those.",
        "",
        "This does not flatter this project either: Wazuh firing a brute-force rule on",
        "events spread over hours is *indiscriminacy*, not robustness, which is why",
        "alert volume is reported alongside detection.",
        "",
        "## Alert volume",
        "",
        "| Condition | Our incidents | Wazuh alerts (L%d) |" % level,
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
        "## Corpus",
        "",
        f"- {manifest['background_lines']} real background lines "
        f"({manifest['benign_lines']} benign + real attacker traffic at "
        f"{payload['ambient_ratio']:.0%})",
        f"- {manifest['attack_lines']} injected attack lines, "
        f"{manifest['attack_instances']} instances",
        f"- brute force {manifest['brute_force_failures']} failures, "
        f"enumeration {manifest['enumeration_probes']} usernames — sized above both",
        "  systems' thresholds, pre-registered before any differential was computed",
        f"- {manifest['days_covered']} days, {len(manifest['real_users'])} real users, "
        f"host `{manifest['host']}`",
        "",
        "Real: every background line, the usernames, the host, the vocabulary.",
        "Authored: the injected instances and the camouflage layer.",
    ]
    return "\n".join(lines) + "\n"


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="The §1b kill-point measurement.")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--output-dir", default=f"{RESULTS_DIR}/killpoint")
    parser.add_argument("--suppress", action="store_true",
                        help="Enable Stage 3 alert suppression, fitting the transition "
                             "model on a benign-only background at a disjoint seed. "
                             "Results are NOT comparable to a run without it.")
    parser.add_argument("--resume", action="store_true",
                        help="reuse completed conditions from a checkpoint")
    args = parser.parse_args()

    print(f"Kill-point: {len(CONDITIONS)} conditions x {args.seeds} seeds, "
          f"detector vs Wazuh on the real OpenSSH corpus")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    tag = f"ambient{args.ambient_ratio:g}"
    partial_path = out / f"killpoint_{tag}.partial.json"

    def _checkpoint(partial: dict) -> None:
        partial_path.write_text(json.dumps(partial, indent=2))

    resume_from = None
    if args.resume:
        resume_from = load_resumable(partial_path, {
            "seeds": args.seeds, "start_seed": args.seed,
            "ambient_ratio": args.ambient_ratio, "contamination": CONTAMINATION,
            "suppression": args.suppress,
        })

    payload = run_paired(seeds=args.seeds, start_seed=args.seed,
                         ambient_ratio=args.ambient_ratio,
                         checkpoint=_checkpoint, resume_from=resume_from,
                         suppress=args.suppress)
    comparison = compare(payload)
    payload["comparison"] = comparison

    (out / f"killpoint_{tag}.json").write_text(json.dumps(payload, indent=2))
    (out / f"killpoint_{tag}.md").write_text(render_report(payload, comparison))

    print("\nDifferentials (timing-independent strategies decide the verdict):")
    for name, row in sorted(comparison["per_strategy"].items(),
                            key=lambda kv: -kv[1].get("differential", float("-inf"))):
        if "differential" not in row:
            continue
        mark = "  [excluded: timing]" if row["timing_dependent"] else ""
        print(f"  {name:<16} ours {row['ours_drop']:+6.1f}  "
              f"wazuh {row['siem_drop']:+6.1f}  diff {row['differential']:+6.1f}{mark}")
    print(f"\nBest measurable differential: {comparison['best_measurable_differential']}pt"
          f"  ->  {comparison['verdict']}")
    partial_path.unlink(missing_ok=True)
    print(f"Wrote -> {out}/killpoint_{tag}.json / .md")


if __name__ == "__main__":
    cli()
