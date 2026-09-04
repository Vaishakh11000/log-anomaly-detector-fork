"""
adversarial.py
Phase 5 -- the robustness evaluation. Generates "camouflaged" variants of the
synthetic attack scenarios and measures how far detection degrades, per
scenario and per camouflage strategy.

This is an evaluation track, not production pipeline code: it *calls* the real
detection stack rather than reimplementing any of it, so the numbers describe
the system that actually ships.

The seven camouflage strategies themselves live in `camouflage.py`, which is
stdlib-only so the Kali adversary box can vendor that one file and apply the
identical transforms to real tool output (CLAUDE.md section 2d). This module
re-exports them, so every existing `from logdet_eval.adversarial import ...`
keeps working, and adds the evaluation around them: both the original and the
camouflaged corpus go through the identical preprocess -> embed -> detect
chain, and detection is measured only over ground-truth attack lines.

Usage:
    python src/adversarial.py
    python src/adversarial.py --output-dir results
"""

import argparse
import copy
import json
import random
import re
from pathlib import Path

import pandas as pd

from logdet.config import (
    CONTAMINATION,
    INCIDENT_WINDOW_MINUTES,
    PROCESSED_DATA_DIR,
    RESULTS_DIR,
    SEQUENCE_SUPPRESSION_QUANTILE,
    SUPPRESSION_FLAGGED_SHARE,
    SUPPRESSION_LONENESS,
)
from logdet_eval.config import (
    SYNTHETIC_HOST,
    SYNTHETIC_SEED,
    SYNTHETIC_YEAR,
    SYNTHETIC_USERS,
)
# Re-exported so existing importers of this module are unaffected by the split.
from logdet_eval.camouflage import (  # noqa: F401
    CamouflagePlan,
    IP_RE,
    MIMICRY_MAP,
    NOISE_TEMPLATES,
    REALISTIC_COMBO,
    REPHRASE_MAP,
    ROTATION_SUBNETS,
    STRATEGIES,
    make_noise_events,
    mimic_message,
    reduce_volume,
    rephrase_message,
    rotate_ip,
    spread_timestamps,
)
from logdet_eval import camouflage as _camouflage
from logdet_eval.generate_logs import build_dataset, write_outputs, next_pid
from logdet_eval.history import HISTORY_SEED_OFFSET, synthetic_history
from logdet.preprocessing import preprocess_file
from logdet.embedding import add_embeddings_to_df
from logdet.anomaly_detection import run_anomaly_detection
from logdet.sequence_grouping import group_anomalies
from logdet.suppression import LONENESS_MODES
from logdet.sequence_model import TransitionModel
from logdet.templating import TemplateMiner

from datetime import timedelta

# --- Camouflage ------------------------------------------------------------

def camouflage_events(events: list[dict], strategies: list[str], seed: int) -> list[dict]:
    """Camouflage the synthetic corpus, bound to that corpus's own generators.

    `camouflage.camouflage_events` is population-agnostic; this binds it to the
    synthetic track's user list and PID counter. `next_pid` is passed rather
    than left to default because it draws from generate_logs' counter and the
    global `random` state the rest of that corpus was built from -- swapping it
    for an independent one renumbers every noise PID and changes the corpus
    byte for byte, which `tests/test_camouflage.py` pins.
    """
    return _camouflage.camouflage_events(events, strategies, seed,
                                         users=SYNTHETIC_USERS, pid_fn=next_pid)


def camouflage_plan_events(events: list[dict], plan: CamouflagePlan,
                           seed: int) -> list[dict]:
    """The same binding, for a searched plan rather than a fixed recipe.

    Stage 6's adaptive adversary varies the magnitudes as well as the strategy
    set, and it must reach the corpus through *this* binding -- same user list,
    same PID counter, same global random state -- or its corpora would not be
    comparable with the fixed-recipe ones it is being scored against.
    """
    return _camouflage.apply_plan(events, plan, seed,
                                  users=SYNTHETIC_USERS, pid_fn=next_pid)


# --- Evaluation ------------------------------------------------------------

def detect_on_log(log_path: str, parsed_csv: str, year: int = SYNTHETIC_YEAR,
                  contamination: float = CONTAMINATION,
                  sequence_model=None, miner_state: str | None = None,
                  suppress: bool = False,
                  suppression_threshold: float | None = None,
                  suppression_loneness: str = SUPPRESSION_LONENESS,
                  suppression_share: float = SUPPRESSION_FLAGGED_SHARE) -> pd.DataFrame:
    """Run the real detection chain over a log file.

    `contamination` is exposed so Phase 7's proposed retune can be tested under
    camouflage before it is adopted -- a setting that looks good on clean data
    has to survive here first.

    `sequence_model` + `miner_state` + `suppress` are the Stage 3 alert
    suppression path, and the three travel together for a reason. The model is
    keyed on Drain3 cluster ids, which only mean anything relative to the miner
    that assigned them, so the corpus has to be mined by a miner restored from
    the *same* state the model was fitted against. Starting a fresh miner here
    would renumber the vocabulary and every transition would be looked up under
    the wrong template -- silently, with plausible-looking numbers out the
    other end. Omitting all three keeps the v1 chain exactly as it was.
    """
    miner = None
    if miner_state is not None:
        miner = TemplateMiner()
        miner.load(miner_state)
    df = preprocess_file(log_path, parsed_csv, year=year, miner=miner,
                         mine_templates=miner is not None)
    df = add_embeddings_to_df(df, template_col="template")
    return run_anomaly_detection(df, contamination=contamination,
                                 sequence_model=sequence_model, suppress=suppress,
                                 suppression_threshold=suppression_threshold,
                                 suppression_loneness=suppression_loneness,
                                 suppression_share=suppression_share)


def measure(scored: pd.DataFrame, ground_truth: pd.DataFrame, log_path: str) -> dict:
    """Detection rates over ground-truth attack lines only.

    Reports line-level and instance-level separately on purpose: an analyst
    cares whether the attack was caught *at all* (instance level), while the
    line-level rate shows how much of the evidence survived.
    """
    n_lines = sum(1 for _ in open(log_path))
    if len(scored) != n_lines:
        raise AssertionError(
            f"{len(scored)} parsed rows vs {n_lines} log lines -- ground-truth "
            "line numbers would be misaligned")

    # ground truth line_number is 1-based into the log file
    scored = scored.reset_index(drop=True)
    gt = ground_truth.copy()
    gt["is_anomaly"] = gt["line_number"].map(lambda n: bool(scored.loc[n - 1, "is_anomaly"]))
    gt["impossible_travel"] = gt["line_number"].map(
        lambda n: bool(scored.loc[n - 1, "impossible_travel"]))

    per_scenario = {}
    for scenario, rows in gt.groupby("scenario"):
        instances = rows.groupby("instance")["is_anomaly"].any()
        per_scenario[scenario] = {
            "attack_lines": int(len(rows)),
            "lines_detected": int(rows["is_anomaly"].sum()),
            "line_detection_rate": round(float(rows["is_anomaly"].mean()), 3),
            "instances": int(len(instances)),
            "instances_detected": int(instances.sum()),
            "instance_detection_rate": round(float(instances.mean()), 3),
            "impossible_travel_hits": int(rows["impossible_travel"].sum()),
        }

    all_instances = gt.groupby(["scenario", "instance"])["is_anomaly"].any()
    overall = {
        "attack_lines": int(len(gt)),
        "line_detection_rate": round(float(gt["is_anomaly"].mean()), 3),
        "instance_detection_rate": round(float(all_instances.mean()), 3),
        "total_flagged_lines": int(scored["is_anomaly"].sum()),
        "incidents": len(group_anomalies(scored)),
    }
    if "suppressed" in scored.columns:
        # How many alerts the Stage 3 rule withdrew, and how many of those were
        # attack lines. The second number is the one that decides whether the
        # rule is safe: alert volume can always be cut by removing detections.
        overall["suppressed_lines"] = int(scored["suppressed"].sum())
        overall["suppressed_attack_lines"] = int(
            sum(1 for n in gt["line_number"] if bool(scored.loc[n - 1, "suppressed"])))
    return {
        "overall": overall,
        "per_scenario": per_scenario,
    }


def run_condition(name: str, strategies: list[str], base_events: list[dict],
                  work_dir: Path, seed: int,
                  contamination: float = CONTAMINATION,
                  host: str = SYNTHETIC_HOST,
                  year: int = SYNTHETIC_YEAR,
                  sequence_model=None, miner_state: str | None = None,
                  suppress: bool = False,
                  suppression_threshold: float | None = None,
                  suppression_loneness: str = SUPPRESSION_LONENESS,
                  suppression_share: float = SUPPRESSION_FLAGGED_SHARE,
                  plan: CamouflagePlan | None = None) -> dict:
    """Build one camouflaged corpus, detect on it, and measure.

    `host` and `year` are parameters so the identical camouflage code can run
    over the real OpenSSH corpus (LabSZ, spanning 2015->2016) as well as the
    synthetic one. Sharing this function is the point: the two evaluation tracks
    must apply the *same* transforms or their results are not comparable.
    """
    if plan is not None:
        # A searched plan overrides the strategy list. Deliberately the same
        # function that scores the fixed recipes: the adaptive adversary's
        # result is only comparable to `realistic-combo` if both were measured
        # by identical code on identically built corpora.
        events = camouflage_plan_events(base_events, plan, seed)
        strategies = list(plan.sorted_strategies)
    elif not strategies:
        events = base_events
    else:
        events = camouflage_events(base_events, strategies, seed)

    log_path = work_dir / f"{name}.log"
    gt_path = work_dir / f"{name}_ground_truth.csv"
    write_outputs(events, str(log_path), str(gt_path), host=host)

    scored = detect_on_log(str(log_path), str(work_dir / f"{name}_parsed.csv"),
                           year=year, contamination=contamination,
                           sequence_model=sequence_model, miner_state=miner_state,
                           suppress=suppress, suppression_threshold=suppression_threshold,
                           suppression_loneness=suppression_loneness,
                           suppression_share=suppression_share)
    result = measure(scored, pd.read_csv(gt_path), str(log_path))
    result["condition"] = name
    result["strategies"] = strategies
    if plan is not None:
        result["plan"] = plan.as_dict()
    return result


_POOLED_COUNTS = ["attack_lines", "lines_detected", "instances", "instances_detected",
                  "impossible_travel_hits"]


def pool(runs: list[dict]) -> dict:
    """Pool per-seed runs of one condition into a single result.

    Rates are recomputed from summed counts rather than averaged, so a seed
    that happens to produce fewer attack lines doesn't get equal weight.
    """
    scenarios = sorted({s for r in runs for s in r["per_scenario"]})
    per_scenario = {}
    for scenario in scenarios:
        rows = [r["per_scenario"][scenario] for r in runs if scenario in r["per_scenario"]]
        totals = {k: sum(row[k] for row in rows) for k in _POOLED_COUNTS}
        per_scenario[scenario] = {
            **totals,
            "line_detection_rate": round(totals["lines_detected"] / max(totals["attack_lines"], 1), 3),
            "instance_detection_rate": round(
                totals["instances_detected"] / max(totals["instances"], 1), 3),
        }

    attack_lines = sum(r["overall"]["attack_lines"] for r in runs)
    lines_detected = sum(s["lines_detected"] for s in per_scenario.values())
    instances = sum(s["instances"] for s in per_scenario.values())
    instances_detected = sum(s["instances_detected"] for s in per_scenario.values())

    return {
        "condition": runs[0]["condition"],
        "strategies": runs[0]["strategies"],
        "seeds": len(runs),
        "overall": {
            "attack_lines": attack_lines,
            "line_detection_rate": round(lines_detected / max(attack_lines, 1), 3),
            "instance_detection_rate": round(instances_detected / max(instances, 1), 3),
            "instances": instances,
            "instances_detected": instances_detected,
            "total_flagged_lines": sum(r["overall"]["total_flagged_lines"] for r in runs),
            "incidents": sum(r["overall"]["incidents"] for r in runs),
            **({"suppressed_lines": sum(r["overall"]["suppressed_lines"] for r in runs),
                "suppressed_attack_lines": sum(
                    r["overall"]["suppressed_attack_lines"] for r in runs)}
               if "suppressed_lines" in runs[0]["overall"] else {}),
        },
        "per_scenario": per_scenario,
        "per_seed_instance_rate": [r["overall"]["instance_detection_rate"] for r in runs],
    }


MECHANISM_NOTES = {
    "temporal": "Gaps of 8-20 min stay inside the 30-min grouping window, and timestamps "
                "are never embedded, so this changes nothing. It is the control condition.",
    "slow": "Gaps of 35-90 min exceed both the 30-min grouping window and the 60-min "
            "impossible-travel window. Scenario B is detectable *only* by the physics "
            "rule (its two legs are textually identical once IPs are masked), so pushing "
            "the legs outside that window makes B effectively invisible.",
    "rephrase": "Novel wording backfires: rare templates are precisely what an outlier "
                "detector flags, so detection goes *up*. It does defeat the keyword-based "
                "impossible-travel rule, but the embedding layer then catches what the "
                "rule lost -- defence in depth, by accident rather than design.",
    "mimicry": "The most effective *line-level* attack (biggest drop in evidence retained), "
               "because rewriting escalation lines as the dominant benign template moves "
               "them toward the centre of the learned distribution instead of away from it. "
               "It never hides a whole instance, though: enough sibling lines still fire.",
    "noise": "Ineffective by construction: `contamination` fixes the *proportion* of lines "
             "flagged, so padding the corpus raises the absolute number of alerts rather "
             "than hiding the attack among them.",
    "volume": "Fewer repeated lines means less evidence, but the pivotal first and last "
              "events remain and are the ones that carry the anomaly.",
    "ip_rotate": "Also lands on Scenario B, and for a specific reason: rotating *both* legs "
                 "into the documentation ranges frequently puts them in the same /16, and "
                 "the impossible-travel check compares only the first two octets -- so it "
                 "sees no change and stays silent. A probabilistic defeat of the rule, not "
                 "an attack on the embeddings.",
}


def render_report(results: list[dict], n_seeds: int = 1) -> str:
    baseline = results[0]["overall"]

    ranked = sorted(
        (r for r in results if r["strategies"]),
        key=lambda r: (r["overall"]["instance_detection_rate"] - baseline["instance_detection_rate"],
                       r["overall"]["line_detection_rate"] - baseline["line_detection_rate"]),
    )

    lines = [
        "# Adversarial Robustness Evaluation",
        "",
        "Generated by `src/adversarial.py`. Each condition rebuilds the synthetic",
        "corpus with camouflage applied to the attack lines only, then runs the",
        "identical preprocess -> embed -> detect chain. Detection is measured over",
        "ground-truth attack lines.",
        "",
        f"Pooled over **{n_seeds} seed(s)**; each seed varies both the corpus and the",
        "camouflage draw. Rates are computed from summed counts, not averaged rates.",
        "",
        "**Line detection rate** = share of attack lines flagged. ",
        "**Instance detection rate** = share of attack instances where at least",
        "one line was flagged -- i.e. would an analyst see the attack at all.",
        "",
        "## Which camouflage worked best",
        "",
        "Ranked by drop in instance detection (most effective evasion first). The line",
        "column is shown alongside because the two rank differently -- `mimicry` destroys",
        "the most evidence without ever hiding a whole attack.",
        "",
        "| Rank | Strategy | Instance detection (Δ) | Line detection (Δ) | Why |",
        "|---|---|---|---|---|",
    ]
    for i, r in enumerate(ranked, start=1):
        o = r["overall"]
        gap = o["instance_detection_rate"] - baseline["instance_detection_rate"]
        line_gap = o["line_detection_rate"] - baseline["line_detection_rate"]
        note = MECHANISM_NOTES.get(r["condition"], "Combination of the strategies above.")
        lines.append(f"| {i} | {r['condition']} | {o['instance_detection_rate']:.0%} ({gap:+.0%}) "
                     f"| {o['line_detection_rate']:.0%} ({line_gap:+.0%}) | {note} |")

    # The headline finding, derived rather than asserted: check whether every
    # instance-level loss is confined to one scenario, and whether that
    # scenario's detection tracks the impossible-travel rule one-for-one.
    lossy = {}
    for r in results:
        for scenario, v in r["per_scenario"].items():
            base_v = results[0]["per_scenario"][scenario]
            if v["instance_detection_rate"] < base_v["instance_detection_rate"]:
                lossy.setdefault(scenario, []).append(r["condition"])

    lines += ["", "## Headline finding", ""]
    if len(lossy) == 1:
        scenario = next(iter(lossy))
        # Where does detection of this scenario exceed what the rule alone explains?
        # Those are the conditions in which the embedding layer is compensating.
        compensating = [r["condition"] for r in results
                        if r["per_scenario"][scenario]["instances_detected"]
                        > r["per_scenario"][scenario]["impossible_travel_hits"]]
        rule_bound = len(compensating) < len(results)
        lines += [
            f"Every instance-level detection loss is confined to **scenario {scenario}** "
            f"(via {', '.join(sorted(lossy[scenario]))}). Scenarios "
            f"{', '.join(s for s in sorted(results[0]['per_scenario']) if s != scenario)} "
            "are never fully hidden by any camouflage tested -- their instance detection "
            "stays at 100%.",
            "",
        ]
        if rule_bound:
            lines += [
                f"In most conditions, scenario {scenario} detection does not exceed the "
                "number of impossible-travel rule hits -- it is carried by **the rule, not "
                "the embeddings**. That follows from the design: the two legs of the login "
                "are textually identical once IPs are masked, so they embed to the same "
                "vector and the outlier detector cannot separate them. Every effective "
                "evasion found here works by stepping outside that rule's 60-minute window "
                "(`slow`) or fooling its two-octet subnet comparison (`ip_rotate`).",
                "",
                "That is the honest weak point of this system: the embedding layer is "
                "robust to every camouflage tested at instance level, and the single "
                "hand-written rule is where the fragility lives.",
                "",
            ]
            if compensating:
                lines += [
                    f"The exception is **{', '.join(sorted(compensating))}**, where detection "
                    "exceeds the rule's hits -- the rule is defeated outright (novel wording "
                    "no longer matches its \"accepted password\" keyword) yet the attack is "
                    "still caught, because unusual phrasing is exactly what an outlier "
                    "detector responds to. The two layers fail on opposite inputs, which is "
                    "the one genuinely reassuring result here.",
                    "",
                ]
    else:
        lines += ["Instance-level losses are spread across scenarios "
                  f"{', '.join(sorted(lossy))}.", ""]

    lines += [
        "## Overall",
        "",
        "| Condition | Line detection | Δ vs baseline | Instance detection | Δ vs baseline |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        o = r["overall"]
        line_gap = o["line_detection_rate"] - baseline["line_detection_rate"]
        inst_gap = o["instance_detection_rate"] - baseline["instance_detection_rate"]
        lines.append(
            f"| {r['condition']} | {o['line_detection_rate']:.0%} | {line_gap:+.0%} "
            f"| {o['instance_detection_rate']:.0%} | {inst_gap:+.0%} |")

    for label, key in (("line detection rate", "line_detection_rate"),
                       ("instance detection rate", "instance_detection_rate")):
        lines += ["", f"## Per scenario ({label})", "",
                  "| Condition | A: brute force | B: impossible travel | C: enumeration |",
                  "|---|---|---|---|"]
        for r in results:
            cells = []
            for s in ("A", "B", "C"):
                v = r["per_scenario"].get(s)
                cells.append(f"{v[key]:.0%}" if v else "n/a")
            lines.append(f"| {r['condition']} | " + " | ".join(cells) + " |")

    lines += ["", "## Impossible-travel rule hits (scenario B)", "",
              "The physics check keys off the literal phrase \"accepted password\",",
              "so it is a rule, not a semantic signal -- this row shows how it holds up.",
              "",
              "| Condition | B lines flagged by the rule |", "|---|---|"]
    for r in results:
        b = r["per_scenario"].get("B")
        lines.append(f"| {r['condition']} | {b['impossible_travel_hits'] if b else 'n/a'} |")

    lines += ["", "## Noise", "",
              "| Condition | Total lines flagged | Incidents formed |", "|---|---|---|"]
    for r in results:
        o = r["overall"]
        lines.append(f"| {r['condition']} | {o['total_flagged_lines']} | {o['incidents']} |")

    lines.append("")
    return "\n".join(lines)


def main(output_dir: str, seed: int, n_seeds: int,
         contamination: float = CONTAMINATION,
         suppress: bool = False,
         suppression_quantile: float = SEQUENCE_SUPPRESSION_QUANTILE,
         suppression_loneness: str = SUPPRESSION_LONENESS,
         suppression_share: float = SUPPRESSION_FLAGGED_SHARE) -> list[dict]:
    work_dir = Path(PROCESSED_DATA_DIR) / "adversarial"
    work_dir.mkdir(parents=True, exist_ok=True)

    # History is fitted once, not per seed: it is history. Varying it with the
    # evaluation seed would confound "the attacker changed tactics" with "the
    # defender was shown a different past".
    fitted = None
    if suppress:
        fitted = synthetic_history(work_dir, seed=seed + HISTORY_SEED_OFFSET,
                                   quantile=suppression_quantile)
        print(f"Suppression on: {fitted.describe()}, loneness "
              f"{suppression_loneness}"
              + (f" (share <= {suppression_share})"
                 if suppression_loneness == "share" else ""))

    conditions = ([("baseline", [])]
                  + [(s, [s]) for s in STRATEGIES]
                  + [("realistic-combo", REALISTIC_COMBO)])

    # Each seed varies both the corpus and the camouflage draw. With only 3
    # instances per scenario a single seed moves in 33% steps, which is far too
    # coarse to call a detection gap -- so pool over several.
    runs: dict[str, list[dict]] = {name: [] for name, _ in conditions}
    for s in range(seed, seed + n_seeds):
        print(f"\n########## seed {s} ##########")
        base_events = build_dataset(seed=s)
        for name, strategies in conditions:
            result = run_condition(name, strategies, base_events, work_dir, s,
                                   contamination=contamination,
                                   sequence_model=fitted.model if fitted else None,
                                   miner_state=fitted.miner_state if fitted else None,
                                   suppress=suppress,
                                   suppression_threshold=fitted.threshold if fitted else None,
                                   suppression_loneness=suppression_loneness,
                                   suppression_share=suppression_share)
            runs[name].append(result)
            o = result["overall"]
            print(f"  {name:<16} line {o['line_detection_rate']:.0%} | "
                  f"instance {o['instance_detection_rate']:.0%}")

    results = [pool(runs[name]) for name, _ in conditions]

    print(f"\n=== pooled over {n_seeds} seeds ===")
    for r in results:
        o = r["overall"]
        print(f"  {r['condition']:<16} line {o['line_detection_rate']:.0%} | "
              f"instance {o['instance_detection_rate']:.0%} "
              f"({o['instances_detected']}/{o['instances']} instances)")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "adversarial_results.json").write_text(json.dumps(results, indent=2))
    (out / "adversarial_results.md").write_text(render_report(results, n_seeds))
    print(f"\nWrote {out}/adversarial_results.md and .json")
    return results


def cli() -> None:
    parser = argparse.ArgumentParser(description="Run the adversarial robustness evaluation.")
    parser.add_argument("--output-dir", default=RESULTS_DIR)
    parser.add_argument("--seed", type=int, default=SYNTHETIC_SEED)
    parser.add_argument("--seeds", type=int, default=5,
                        help="How many consecutive seeds to pool over")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help="Override the detector's contamination (Phase 7 retune check)")
    parser.add_argument("--suppression-quantile", type=float,
                        default=SEQUENCE_SUPPRESSION_QUANTILE,
                        help="Quantile of the fitted history a lone flagged line must "
                             "exceed to survive. The default is the config value; other "
                             "values are for the sweep, not for shopping.")
    parser.add_argument("--suppression-loneness", default=SUPPRESSION_LONENESS,
                        choices=LONENESS_MODES,
                        help="Which loneness test decides a flagged line is "
                             "uncorroborated. 'incident' is grouping's own answer "
                             "(flagged rows only); 'share' and 'quiet' ask the entity "
                             "graph over the whole frame. See logdet/config.py.")
    parser.add_argument("--suppression-share", type=float,
                        default=SUPPRESSION_FLAGGED_SHARE,
                        help="Only read with --suppression-loneness share: the flagged "
                             "share of a line's entity neighbourhood at or below which "
                             "it counts as lone. 0.0 reproduces 'incident'.")
    parser.add_argument("--suppress", action="store_true",
                        help="Enable Stage 3 alert suppression (fits a transition model on a "
                             "separate benign-only history corpus first). This is the arm "
                             "CLAUDE.md section 4 compares against the default one.")
    args = parser.parse_args()

    main(args.output_dir, args.seed, args.seeds, contamination=args.contamination,
         suppress=args.suppress, suppression_quantile=args.suppression_quantile,
         suppression_loneness=args.suppression_loneness,
         suppression_share=args.suppression_share)


if __name__ == "__main__":
    cli()
