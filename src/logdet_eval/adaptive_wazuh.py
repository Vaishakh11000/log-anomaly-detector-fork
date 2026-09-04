"""
adaptive_wazuh.py
The Stage 6 adaptive adversary, pointed at Wazuh as well as at this detector.

Why this exists. The kill point (CLAUDE.md section 1b) returned CONTINUE on a
single surviving win: `rephrase`, +31.1pt, where Wazuh's sshd rules stop
matching a reworded line while an embedding of it stays near the original. That
number was measured against a **fixed** attacker -- eight hand-authored recipes
at magnitudes chosen once. An attacker that *optimises* is the fairest available
re-test of it, and this module runs the identical search
(`adaptive.search`, `adaptive.hill_climb`, `adaptive.ValidityRule`) against each
system in turn, on the same real OpenSSH corpus the kill point used.

Two properties decide whether the answer means anything, and both are enforced
in code.

1. **`slow` and `temporal` are removed from the search space, for both sides.**
   Wazuh's correlation windows are keyed on *arrival* time, not on the timestamp
   in the log line (Decision Log 2026-08-18), so a batch-replayed corpus is
   simultaneous to it and its drop under a timing strategy is 0pt **by
   construction**. An optimiser let loose on that space would find the
   instrument artefact immediately and report a spectacular differential that
   measures the harness. `WazuhOracle` refuses such a plan outright rather than
   scoring it. The cost is real and is stated in the report: this removes
   `slow`, which is half of the strongest plan the detector-side search found on
   the synthetic corpus, so the restricted space is *not* a fair statement of
   how bad camouflage can get for us -- only of how the two systems compare
   where both can be measured.

2. **The search is run against each system separately, and the conservative
   differential is the one that counts.** An attacker optimising against Wazuh
   finds the plan that hurts Wazuh most, which flatters us; an attacker
   optimising against this detector finds the plan that hurts us most, which
   does the opposite. Reporting only the first would be choosing the answer, so
   both are reported and the smaller differential is named as the claim.

Everything else is inherited: the same `Oracle` contract, the same validity
floor that stops the optimiser "evading" by deleting the attack, and the same
refusal to report a result on a seed the search was fitted to.

Usage:
    docker start wazuh                  # and give analysisd ~30s (Known Issues)
    logdet-adaptive-wazuh               # both searches + paired held-out run
    logdet-adaptive-wazuh --skip-detector-search   # the Wazuh arm only (~15 min)
"""

import argparse
import contextlib
import io
import json
import time
from pathlib import Path

import pandas as pd

from logdet.config import CONTAMINATION, PROCESSED_DATA_DIR, RESULTS_DIR
from logdet_eval import scoring, wazuh_runner
from logdet_eval.adaptive import (
    HOLDOUT_SEEDS,
    BudgetExhausted,
    SEARCH_SEEDS,
    Oracle,
    SearchResult,
    ValidityRule,
    budget_curve,
    search,
)
from logdet_eval.adversarial import camouflage_plan_events, detect_on_log
from logdet_eval.camouflage import STRATEGIES, CamouflagePlan
from logdet_eval.corpus_openssh import CORPUS_HOST, build_killpoint_corpus
from logdet_eval.generate_logs import write_outputs
from logdet_eval.killpoint import CORPUS_START_YEAR, PRIMARY_LEVEL

# Strategies whose whole mechanism is *when* events happen. Batch replay cannot
# measure them against an arrival-time-keyed SIEM, so they are out of the search
# space on both sides -- see the module docstring, and killpoint.TIMING_DEPENDENT
# for the same exclusion applied to the fixed recipes.
TIMING_DEPENDENT = ("slow", "temporal")
SEARCH_UNIVERSE = tuple(s for s in STRATEGIES if s not in TIMING_DEPENDENT)

# The number this arm re-tests. Measured 2026-08-19 over 5 seeds at
# ambient_ratio=0.05 against a fixed attacker.
REGISTERED_REPHRASE_DIFFERENTIAL = 31.1

# Per query, measured on the demo box over the 2,592-line kill-point corpus:
# ~29s for the detector (preprocess, embed, fit, score, group) against ~1.6s for
# `wazuh-logtest`. The two budgets differ by roughly that ratio on purpose --
# equal budgets would spend a whole afternoon on the expensive side to no
# purpose, since the cheap side exhausts its space long before.
# 90 detector queries bounds the expensive arm at ~45 minutes, which is a
# kill-point run's worth of CPU (Known Issues: do not run the test suite
# alongside it, it competes for the same cores).
DETECTOR_BUDGET = 90
WAZUH_BUDGET = 600


# --- One corpus, scored by both systems ------------------------------------

class PairedCorpus:
    """Builds a camouflaged kill-point corpus once and lets both systems read it.

    This is the kill point's central guarantee carried into the adaptive run: if
    each system built its own corpus, a difference between the two columns could
    be a difference in the corpora instead of in the detectors. Files are cached
    per (plan, seed), so the detector search and the Wazuh search share every
    corpus they both visit.
    """

    def __init__(self, work_dir: Path, ambient_ratio: float = 0.05,
                 instances_per_scenario: int = 3):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.ambient_ratio = ambient_ratio
        self.instances_per_scenario = instances_per_scenario
        self._events: dict[int, list[dict]] = {}
        self._written: dict[tuple, tuple[Path, pd.DataFrame, int]] = {}
        self.manifest: dict = {}

    def base_events(self, seed: int) -> list[dict]:
        if seed not in self._events:
            events, self.manifest = build_killpoint_corpus(
                instances_per_scenario=self.instances_per_scenario,
                ambient_ratio=self.ambient_ratio, seed=seed)
            self._events[seed] = events
        return self._events[seed]

    def write(self, plan: CamouflagePlan, seed: int) -> tuple[Path, pd.DataFrame, int]:
        """(log path, ground truth, total lines) for one attacker configuration."""
        key = (plan, seed)
        if key in self._written:
            return self._written[key]

        events = self.base_events(seed)
        if plan.strategies:
            # The synthetic-bound binding, exactly as killpoint.py uses for the
            # fixed recipes: same noise user list, same PID counter, same global
            # random state. A different binding would renumber the filler and
            # make these corpora incomparable with the published ones.
            events = camouflage_plan_events(events, plan, seed)

        stem = f"s{seed}_{abs(hash((plan, seed))):x}"
        log_path = self.work_dir / f"{stem}.log"
        gt_path = self.work_dir / f"{stem}_gt.csv"
        # `write_outputs` announces every file it writes, and a 32-subset
        # search writes hundreds -- the progress that matters is the oracle's.
        with contextlib.redirect_stdout(io.StringIO()):
            write_outputs(events, str(log_path), str(gt_path), host=CORPUS_HOST)
        ground_truth = pd.read_csv(gt_path)
        total_lines = sum(1 for _ in open(log_path))
        self._written[key] = (log_path, ground_truth, total_lines)
        return self._written[key]


class KillpointOracle(Oracle):
    """An `adaptive.Oracle` over the real OpenSSH corpus.

    Pools through `scoring.pool_runs` -- the kill point's own pooler, which
    recomputes rates from summed counts -- so that both systems' numbers here
    are produced by exactly the code that produced the published kill-point
    numbers, and remain comparable with them.
    """

    system = "unnamed"

    def __init__(self, corpus: PairedCorpus, budget: int,
                 contamination: float = CONTAMINATION, verbose: bool = True):
        super().__init__(corpus.work_dir, budget=budget,
                         contamination=contamination, verbose=verbose)
        self.corpus = corpus

    def base_events(self, seed: int) -> list[dict]:
        return self.corpus.base_events(seed)

    def pool_runs(self, runs: list[dict], plan: CamouflagePlan) -> dict:
        return scoring.pool_runs(runs)["overall"]

    def _score(self, log_path: Path, ground_truth: pd.DataFrame,
               total_lines: int) -> dict:
        raise NotImplementedError

    def _run(self, plan: CamouflagePlan, seed: int) -> dict:
        cache_key = (plan, seed)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if self.queries >= self.budget:
            raise BudgetExhausted(f"query budget {self.budget} spent")
        self.queries += 1
        self.seeds_used.add(seed)
        log_path, ground_truth, total_lines = self.corpus.write(plan, seed)
        result = self._score(log_path, ground_truth, total_lines)
        self._cache[cache_key] = result
        return result


class DetectorOracle(KillpointOracle):
    """This project's detector, as the attacker sees it."""

    system = "ours"

    def _score(self, log_path, ground_truth, total_lines):
        scored = detect_on_log(str(log_path), str(log_path.with_suffix(".parsed.csv")),
                               year=CORPUS_START_YEAR, contamination=self.contamination)
        flagged = {i + 1 for i, flag in enumerate(scored["is_anomaly"].tolist()) if flag}
        return scoring.measure_lines(flagged, ground_truth, total_lines=total_lines)


class WazuhOracle(KillpointOracle):
    """The real Wazuh manager, as the attacker sees it.

    Refuses a timing-based plan instead of scoring one. That refusal is the
    honesty guard of this whole module: `wazuh-logtest` reads a batch-replayed
    corpus as simultaneous, so it cannot lose an instance to `slow` however the
    gaps are set, and an optimiser handed that space would converge on it in a
    handful of queries and call a harness limitation a robustness gap.
    """

    system = "wazuh"

    def __init__(self, corpus: PairedCorpus, budget: int,
                 level: int = PRIMARY_LEVEL, **kwargs):
        super().__init__(corpus, budget, **kwargs)
        self.level = level

    def _score(self, log_path, ground_truth, total_lines):
        verdicts = wazuh_runner.analyze(str(log_path))
        flagged = wazuh_runner.flagged_lines(verdicts, self.level)
        return scoring.measure_lines(flagged, ground_truth, total_lines=total_lines,
                                     alert_count=len(flagged))

    def _run(self, plan: CamouflagePlan, seed: int) -> dict:
        reject_timing_plan(plan)
        return super()._run(plan, seed)


def reject_timing_plan(plan: CamouflagePlan) -> None:
    timing = sorted(set(plan.strategies) & set(TIMING_DEPENDENT))
    if timing:
        raise ValueError(
            f"{timing} is timing-based, and Wazuh's correlation windows are keyed "
            "on arrival time -- a batch-replayed corpus is simultaneous to it, so "
            "its drop here would be 0pt by construction. Measure those with "
            "logdet-paced-killpoint instead.")


# --- The paired held-out run ------------------------------------------------

def score_both(corpus: PairedCorpus, plan: CamouflagePlan, seed: int,
               level: int, contamination: float) -> dict:
    """Both systems on the *same* corpus file, through the same scorer."""
    log_path, ground_truth, total_lines = corpus.write(plan, seed)

    scored = detect_on_log(str(log_path), str(log_path.with_suffix(".parsed.csv")),
                           year=CORPUS_START_YEAR, contamination=contamination)
    ours_flagged = {i + 1 for i, flag in enumerate(scored["is_anomaly"].tolist()) if flag}
    ours = scoring.measure_lines(ours_flagged, ground_truth, total_lines=total_lines)

    verdicts = wazuh_runner.analyze(str(log_path))
    siem_flagged = wazuh_runner.flagged_lines(verdicts, level)
    siem = scoring.measure_lines(siem_flagged, ground_truth, total_lines=total_lines,
                                 alert_count=len(siem_flagged))
    return {"ours": ours, "siem": siem}


def paired_holdout(conditions: list[tuple[str, CamouflagePlan]],
                   corpus: PairedCorpus, searched_seeds: set[int],
                   seeds: tuple[int, ...] = HOLDOUT_SEEDS,
                   level: int = PRIMARY_LEVEL,
                   contamination: float = CONTAMINATION) -> list[dict]:
    """Score every condition on seeds the search never saw, on both systems.

    The overlap check is the same one `adaptive.evaluate_holdout` makes and for
    the same reason: a differential computed on the corpus the plan was fitted
    to would describe the fit, not the attack.
    """
    overlap = sorted(set(seeds) & searched_seeds)
    if overlap:
        raise ValueError(
            f"held-out seeds {overlap} were used during the search; the adaptive "
            "differential would be reported on the data it was fitted to")

    runs: dict[str, dict[str, list[dict]]] = {
        name: {"ours": [], "siem": []} for name, _ in conditions}
    for seed in seeds:
        for name, plan in conditions:
            scored = score_both(corpus, plan, seed, level, contamination)
            runs[name]["ours"].append(scored["ours"])
            runs[name]["siem"].append(scored["siem"])
            print(f"  seed {seed} {name:<22} "
                  f"ours {scored['ours']['overall']['instance_detection_rate']:.0%} "
                  f"| wazuh(L{level}) "
                  f"{scored['siem']['overall']['instance_detection_rate']:.0%}")

    return [{"condition": name,
             "plan": plan.as_dict(),
             "label": plan.label(),
             "ours": scoring.pool_runs(runs[name]["ours"]),
             "siem": scoring.pool_runs(runs[name]["siem"])}
            for name, plan in conditions]


def compare(holdout: list[dict]) -> dict:
    """Per-condition drops for both systems, and the differential between them.

    Same sign convention as `killpoint.compare`: positive means the SIEM lost
    more ground to the camouflage than this system did.
    """
    by_name = {row["condition"]: row for row in holdout}
    base = by_name["baseline"]
    rows = {}
    for name, row in by_name.items():
        if name == "baseline":
            continue
        ours = scoring.instance_drop(base["ours"], row["ours"])
        siem = scoring.instance_drop(base["siem"], row["siem"])
        rows[name] = {
            "label": row["label"],
            "ours_drop": ours,
            "siem_drop": siem,
            "differential": scoring.differential(ours, siem),
            "ours_line_rate": row["ours"]["overall"]["line_detection_rate"],
            "siem_line_rate": row["siem"]["overall"]["line_detection_rate"],
            "ours_flagged": row["ours"]["overall"]["total_flagged_lines"],
            "siem_alerts": row["siem"]["overall"]["alerts"],
        }
    adaptive_rows = [r for name, r in rows.items() if name.startswith("adaptive")]
    return {
        "per_condition": rows,
        # The conservative reading: an attacker optimising against Wazuh
        # flatters us, one optimising against the detector does the opposite,
        # and the claim this project may make is the weaker of the two.
        "conservative_differential": (min(r["differential"] for r in adaptive_rows)
                                      if adaptive_rows else None),
        "rephrase_differential": rows.get("rephrase", {}).get("differential"),
        "registered_rephrase_differential": REGISTERED_REPHRASE_DIFFERENTIAL,
    }


# --- Reporting --------------------------------------------------------------

def render_report(arms: dict[str, SearchResult], holdout: list[dict],
                  comparison: dict, rule: ValidityRule, seeds: dict,
                  elapsed: float, level: int) -> str:
    rows = comparison["per_condition"]
    lines = [
        "# Adaptive Adversary vs Wazuh",
        "",
        "Generated by `logdet-adaptive-wazuh` (`src/logdet_eval/adaptive_wazuh.py`).",
        "",
        "The kill point (CLAUDE.md §1b) returned CONTINUE on one surviving win --",
        f"`rephrase`, **+{REGISTERED_REPHRASE_DIFFERENTIAL}pt** -- measured against a",
        "**fixed** attacker applying eight hand-authored recipes. This run points the",
        "identical search (`adaptive.search`) at each system in turn, on the same real",
        "LogHub OpenSSH corpus, and re-measures the differential under an attacker that",
        "optimises.",
        "",
        "## What the search space is, and what was taken out of it",
        "",
        "`slow` and `temporal` are **excluded on both sides**. Wazuh's correlation",
        "windows are keyed on *arrival* time, not on the timestamp in the log line, so a",
        "batch-replayed corpus is simultaneous to it and its drop under a timing strategy",
        "is 0pt **by construction** (Decision Log 2026-08-18). An optimiser given that",
        "space finds the artefact, not a property of either system. `WazuhOracle` refuses",
        "such a plan rather than scoring it.",
        "",
        "**This costs us the stronger half of our own worst case** -- the detector-side",
        "search on the synthetic corpus found `slow+mimicry` -- so the table below is not",
        "a statement of how bad camouflage gets for this detector. It is a statement of",
        "how the two systems compare *where both can be measured in batch*. The timing",
        "half is `logdet-paced-killpoint`'s, and it is a loss for us.",
        "",
        f"Search universe: `{'`, `'.join(SEARCH_UNIVERSE)}`",
        "",
        "## What it cost",
        "",
    ]
    for name, result in arms.items():
        lines.append(f"- **{name}**: {result.queries} queries, "
                     f"best on the search seeds `{result.best.plan.label()}` "
                     f"(instance {result.best.instance_rate:.1%}, "
                     f"line {result.best.line_rate:.1%})")
    lines += [
        f"- {elapsed / 60:.1f} minutes of CPU",
        f"- Search seeds: {list(seeds['search'])}; held-out seeds: "
        f"{list(seeds['holdout'])} -- **never seen by either search**",
        f"- A plan is rejected before it costs a query if any instance keeps fewer "
        f"than {rule.min_lines} lines or under {rule.min_share:.0%} of its original "
        "lines, so the optimiser cannot 'evade' by deleting the attack.",
        "",
        "## The result, on seeds neither search saw",
        "",
        f"Instance detection, pooled over {len(seeds['holdout'])} held-out seeds. Wazuh at",
        f"level >={level}. Both systems scored on the *same corpus files* through the same",
        "scorer, so the only difference between the two columns is the detector.",
        "",
        "| Condition | Ours (Δpt) | Wazuh (Δpt) | Differential |",
        "|---|---|---|---|",
    ]
    for name, row in rows.items():
        lines.append(f"| {name} — `{row['label']}` | {row['ours_drop']:+.1f} "
                     f"| {row['siem_drop']:+.1f} | **{row['differential']:+.1f}** |")

    fixed = comparison["rephrase_differential"]
    conservative = comparison["conservative_differential"]
    lines += [
        "",
        f"`rephrase` under the fixed attacker read **+{REGISTERED_REPHRASE_DIFFERENTIAL}pt** "
        f"when the kill point measured it; it reads **{fixed:+.1f}pt** here.",
        "",
        f"**The conservative differential under an optimising attacker is "
        f"{conservative:+.1f}pt.** That is the smaller of the two adaptive rows, and it is",
        "the number this project may quote: an attacker optimising against Wazuh finds the",
        "plan that hurts Wazuh most, which flatters us, and an attacker optimising against",
        "this detector does the opposite. Quoting only the friendlier of the two would be",
        "choosing the answer.",
        "",
        "## Line detection and alert volume, same run",
        "",
        "| Condition | Ours (lines) | Wazuh (lines) | Our flagged lines | Wazuh alerts |",
        "|---|---|---|---|---|",
    ]
    base = next(r for r in holdout if r["condition"] == "baseline")
    lines.append(f"| baseline | {base['ours']['overall']['line_detection_rate']:.1%} "
                 f"| {base['siem']['overall']['line_detection_rate']:.1%} "
                 f"| {base['ours']['overall']['total_flagged_lines']} "
                 f"| {base['siem']['overall']['alerts']} |")
    for name, row in rows.items():
        lines.append(f"| {name} | {row['ours_line_rate']:.1%} | {row['siem_line_rate']:.1%} "
                     f"| {row['ours_flagged']} | {row['siem_alerts']} |")

    for name, result in arms.items():
        ranked = sorted(result.exhaustive, key=lambda e: e.key)
        lines += [
            "",
            f"## Every strategy subset ranked against **{name}** "
            f"(search seed {result.seeds_searched[0]})",
            "",
            "| Rank | Strategies | Instance detection | Line detection |",
            "|---|---|---|---|",
        ]
        for i, evaluation in enumerate(ranked[:10], start=1):
            lines.append(f"| {i} | `{evaluation.plan.label()}` "
                         f"| {evaluation.instance_rate:.1%} | {evaluation.line_rate:.1%} |")

    lines += [
        "",
        "## Limits",
        "",
        "- Each oracle hands the attacker the true detection rates over *labelled*",
        "  attack lines. Upper bound on evasion for both systems, not a field estimate.",
        "- `slow` and `temporal` are outside the space for the instrument reason above,",
        "  so this says nothing about timing camouflage. That is measured, and it is a",
        "  loss for us: `results/killpoint/killpoint_paced_ambient0.05.md`.",
        "- The space is the shipped transforms and their magnitudes. A plateau means",
        "  *these transforms are exhausted*, never *this system is robust*.",
        f"- Wazuh is read at level >={level} only. The kill point reports L3/L7/L10 and",
        "  the higher levels are a floor effect on this corpus (11.1% on clean data).",
        "- Instance detection over 9 instances moves in 11-point steps; the line rate is",
        "  the finer signal and is reported beside it.",
        "",
    ]
    return "\n".join(lines) + "\n"


# --- Entry point ------------------------------------------------------------

def main(output_dir: str = str(Path(RESULTS_DIR) / "adaptive_wazuh"),
         detector_budget: int = DETECTOR_BUDGET,
         wazuh_budget: int = WAZUH_BUDGET,
         search_seeds: tuple[int, ...] = SEARCH_SEEDS,
         holdout_seeds: tuple[int, ...] = HOLDOUT_SEEDS,
         ambient_ratio: float = 0.05,
         level: int = PRIMARY_LEVEL,
         contamination: float = CONTAMINATION,
         skip_detector_search: bool = False) -> dict:
    if not wazuh_runner.container_available():
        raise SystemExit(
            "Wazuh container is not answering. `docker start wazuh` and give "
            "analysisd ~30s (CLAUDE.md Known Issues). Refusing to run rather "
            "than producing a one-contestant table.")

    work_dir = Path(PROCESSED_DATA_DIR) / "adaptive_wazuh"
    corpus = PairedCorpus(work_dir, ambient_ratio=ambient_ratio)
    rule = ValidityRule()
    started = time.time()

    arms: dict[str, SearchResult] = {}
    searched_seeds: set[int] = set()

    print(f"=== Searching against Wazuh (L{level}) ===")
    wazuh_oracle = WazuhOracle(corpus, budget=wazuh_budget, level=level,
                               contamination=contamination)
    arms["wazuh"] = search(wazuh_oracle, rule, seeds=search_seeds,
                           universe=SEARCH_UNIVERSE)
    searched_seeds |= wazuh_oracle.seeds_used

    conditions = [("baseline", CamouflagePlan()),
                  ("rephrase", CamouflagePlan(strategies=("rephrase",))),
                  ("adaptive-vs-wazuh", arms["wazuh"].best.plan)]

    if not skip_detector_search:
        print("\n=== Searching against this detector (same space, same code) ===")
        detector_oracle = DetectorOracle(corpus, budget=detector_budget,
                                         contamination=contamination)
        arms["ours"] = search(detector_oracle, rule, seeds=search_seeds,
                              universe=SEARCH_UNIVERSE)
        searched_seeds |= detector_oracle.seeds_used
        conditions.append(("adaptive-vs-ours", arms["ours"].best.plan))

    print(f"\n=== Held-out paired evaluation on seeds {list(holdout_seeds)} ===")
    holdout = paired_holdout(conditions, corpus, searched_seeds,
                             seeds=holdout_seeds, level=level,
                             contamination=contamination)
    comparison = compare(holdout)
    elapsed = time.time() - started

    payload = {
        "corpus": "loghub-openssh",
        "ambient_ratio": ambient_ratio,
        "level": level,
        "search_universe": list(SEARCH_UNIVERSE),
        "excluded_strategies": list(TIMING_DEPENDENT),
        "search_seeds": list(search_seeds),
        "holdout_seeds": list(holdout_seeds),
        "seconds": round(elapsed, 1),
        "validity_rule": {"min_lines": rule.min_lines, "min_share": rule.min_share},
        "corpus_manifest": corpus.manifest,
        "arms": {
            name: {
                "queries": result.queries,
                "best_plan": result.best.plan.as_dict(),
                "best_on_search_seeds": result.best.as_dict(),
                "rejected_plans": len(result.rejected),
                "budget_curve": budget_curve(result.exhaustive + result.climb),
                "exhaustive": [e.as_dict() for e in
                               sorted(result.exhaustive, key=lambda e: e.key)],
                "climb": [e.as_dict() for e in result.climb],
            } for name, result in arms.items()},
        "holdout": holdout,
        "comparison": comparison,
    }

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "adaptive_wazuh.json").write_text(json.dumps(payload, indent=2))
    (out / "adaptive_wazuh.md").write_text(
        render_report(arms, holdout, comparison, rule,
                      {"search": search_seeds, "holdout": holdout_seeds},
                      elapsed, level))

    print("\nDifferentials on the held-out seeds "
          "(positive = Wazuh degraded more than we did):")
    for name, row in comparison["per_condition"].items():
        print(f"  {name:<22} ours {row['ours_drop']:+6.1f}  "
              f"wazuh {row['siem_drop']:+6.1f}  diff {row['differential']:+6.1f}")
    print(f"\nConservative differential under an optimising attacker: "
          f"{comparison['conservative_differential']:+.1f}pt "
          f"(fixed-attacker rephrase was +{REGISTERED_REPHRASE_DIFFERENTIAL}pt)")
    print(f"Wrote -> {out}/adaptive_wazuh.md and .json")
    return payload


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Point the adaptive search at Wazuh as well as at this detector.")
    parser.add_argument("--output-dir", default=str(Path(RESULTS_DIR) / "adaptive_wazuh"))
    parser.add_argument("--detector-budget", type=int, default=DETECTOR_BUDGET,
                        help="detector queries the attacker may spend (~29s each)")
    parser.add_argument("--wazuh-budget", type=int, default=WAZUH_BUDGET,
                        help="Wazuh queries the attacker may spend (~2s each)")
    parser.add_argument("--search-seeds", type=int, nargs="+", default=list(SEARCH_SEEDS))
    parser.add_argument("--holdout-seeds", type=int, nargs="+", default=list(HOLDOUT_SEEDS))
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--level", type=int, default=PRIMARY_LEVEL,
                        help="Wazuh alert level counted as a detection")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION)
    parser.add_argument("--skip-detector-search", action="store_true",
                        help="Wazuh arm only. Cheaper, and the differential is then "
                             "one-sided in our favour -- the report says so.")
    args = parser.parse_args()
    main(args.output_dir, detector_budget=args.detector_budget,
         wazuh_budget=args.wazuh_budget,
         search_seeds=tuple(args.search_seeds),
         holdout_seeds=tuple(args.holdout_seeds),
         ambient_ratio=args.ambient_ratio, level=args.level,
         contamination=args.contamination,
         skip_detector_search=args.skip_detector_search)


if __name__ == "__main__":
    cli()
