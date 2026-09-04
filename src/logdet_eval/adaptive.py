"""
adaptive.py
Stage 6's adaptive adversary: an attacker that *searches* camouflage settings
against this detector instead of applying seven fixed recipes.

Why this exists (CLAUDE.md section 1, section 6). Every adversarial number this
project reports so far comes from eight hand-authored conditions -- seven single
strategies plus one hand-picked combination -- at magnitudes chosen once and
never varied. That measures robustness against *the transforms their author
thought of*, which is the same methodological hole section 1b closed for rules
and section 2d closes for attacks. An adversary that optimises removes it: the
question stops being "does this survive my seven ideas" and becomes "how much
survives an attacker allowed N attempts".

Three properties make the result honest, and each is enforced in code rather
than promised.

1. **It reuses the shipped transforms.** The search space is
   `camouflage.CamouflagePlan` -- which of the seven strategies, and how hard
   each is turned -- applied through `adversarial.camouflage_plan_events`, the
   same binding the fixed recipes use. A parallel set of transforms would make
   the adaptive and fixed results incomparable, which is the one thing this must
   not do.

2. **The attack must stay an attack.** An optimiser handed `volume` alone would
   "evade" by thinning an instance to nothing, which is not evasion but
   surrender. `ValidityRule` rejects such plans *before* they cost a query, so
   the budget accounting stays clean too.

3. **Searched seeds and reported seeds are disjoint, and that is checked.**
   Reporting the attacker's own best search score would be the clean-data-tuning
   mistake section 4 warns about, one level up: the number would describe how
   well the search overfitted one corpus draw. `Oracle` records every seed it
   touched and `evaluate_holdout` refuses to score on any of them.

The threat model is deliberately the strongest one available, and the report
says so: the oracle returns the detector's true detection rates over *labelled*
attack lines. A real attacker sees nothing of the kind. So what this produces is
an upper bound on evasion, not a field estimate.

Usage:
    logdet-adaptive                     # full search + held-out evaluation
    logdet-adaptive --budget 40 --holdout-seeds 2   # quick pass while iterating
"""

import argparse
import itertools
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from logdet.config import CONTAMINATION, PROCESSED_DATA_DIR, RESULTS_DIR
from logdet_eval.adversarial import camouflage_plan_events, pool, run_condition
from logdet_eval.camouflage import (
    KNOBS_BY_STRATEGY,
    REALISTIC_COMBO,
    STRATEGIES,
    CamouflagePlan,
)
from logdet_eval.generate_logs import build_dataset

# Seeds the search may look at, and seeds it may not. Kept apart here rather
# than passed around, so the disjointness is a property of the module.
SEARCH_SEEDS = (42, 43)
HOLDOUT_SEEDS = (44, 45, 46, 47, 48)

# One detector query is ~7s on the CPU floor (751-line corpus: preprocess,
# embed, fit, score, group). The default budget is therefore ~25 minutes.
DEFAULT_BUDGET = 260

# Values the hill climb is allowed to try for each knob. Coarse on purpose: the
# oracle is noisy and expensive, so a fine grid spends the budget resolving
# differences smaller than the seed-to-seed variation.
KNOB_GRID = {
    "gap_min_minutes": [2, 5, 8, 15, 25, 31],
    "gap_max_minutes": [10, 20, 29, 45, 70],
    "slow_gap_min_minutes": [31, 35, 45, 61, 90, 120],
    "slow_gap_max_minutes": [45, 60, 90, 120, 180, 240],
    "noise_ratio": [0.0, 0.5, 1.5, 3.0, 6.0, 10.0],
    "volume_keep": [0.1, 0.25, 0.5, 0.75, 1.0],
}


# --- Keeping the attack an attack ------------------------------------------

@dataclass(frozen=True)
class ValidityRule:
    """How much of an attack must survive for a plan to count as evasion.

    `volume` is the only strategy that deletes attack lines, so this is the only
    place the optimiser could cheat -- and it would, immediately: dropping every
    line but two scores as perfect evasion while performing no attack. The floor
    is expressed both absolutely and as a share, because scenario B (impossible
    travel) is only two lines long and a flat "keep 3" would rule it out
    entirely.
    """

    min_lines: int = 3
    min_share: float = 0.4

    def instance_floor(self, original_lines: int) -> int:
        return max(1, min(self.min_lines, original_lines),
                   int(round(self.min_share * original_lines)))

    def check(self, base_events: list[dict], plan: CamouflagePlan,
              seed: int) -> tuple[bool, str]:
        """Cheap: camouflages the event list but never runs the detector."""
        camouflaged = camouflage_plan_events(base_events, plan, seed)
        before = _instance_sizes(base_events)
        after = _instance_sizes(camouflaged)
        for key, original in before.items():
            kept = after.get(key, 0)
            floor = self.instance_floor(original)
            if kept < floor:
                return False, (f"instance {key[0]}{key[1]} kept {kept} of {original} "
                               f"lines, floor {floor}")
        return True, ""


def _instance_sizes(events: list[dict]) -> dict[tuple, int]:
    sizes: dict[tuple, int] = {}
    for event in events:
        if event.get("scenario"):
            key = (event["scenario"], event["instance"])
            sizes[key] = sizes.get(key, 0) + 1
    return sizes


# --- The oracle ------------------------------------------------------------

@dataclass(frozen=True)
class Evaluation:
    """What the attacker learns from one probe of the detector."""

    plan: CamouflagePlan
    seeds: tuple[int, ...]
    instance_rate: float
    line_rate: float
    incidents: int
    attack_lines: int
    queries_after: int

    @property
    def key(self) -> tuple[float, float]:
        """What the attacker minimises.

        Instance detection first, because that is the registered metric and the
        one an analyst experiences ("was the attack seen at all"). Line
        detection breaks ties, and it has to: with 9 instances the instance rate
        moves in 11-point steps, so most candidate pairs are tied on it.
        """
        return (self.instance_rate, self.line_rate)

    def as_dict(self) -> dict:
        return {"plan": self.plan.as_dict(), "label": self.plan.label(),
                "seeds": list(self.seeds), "instance_rate": self.instance_rate,
                "line_rate": self.line_rate, "incidents": self.incidents,
                "attack_lines": self.attack_lines, "queries_after": self.queries_after}


class BudgetExhausted(RuntimeError):
    pass


class Oracle:
    """The detector, as the attacker sees it: plan in, detection rates out.

    Calls the same `run_condition` the published adversarial suite calls, so a
    searched plan and a fixed recipe are measured by identical code. Results are
    cached per (plan, seed): a repeated probe is the attacker's own memory, not
    a new observation, so it does not spend budget.
    """

    def __init__(self, work_dir: Path, budget: int = DEFAULT_BUDGET,
                 contamination: float = CONTAMINATION, verbose: bool = True):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.contamination = contamination
        self.verbose = verbose
        self.queries = 0
        self.seeds_used: set[int] = set()
        self._corpus: dict[int, list[dict]] = {}
        self._cache: dict[tuple, dict] = {}
        self.trace: list[Evaluation] = []

    def base_events(self, seed: int) -> list[dict]:
        if seed not in self._corpus:
            self._corpus[seed] = build_dataset(seed=seed)
        return self._corpus[seed]

    def _run(self, plan: CamouflagePlan, seed: int) -> dict:
        cache_key = (plan, seed)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if self.queries >= self.budget:
            raise BudgetExhausted(f"query budget {self.budget} spent")
        self.queries += 1
        self.seeds_used.add(seed)
        result = run_condition(f"probe{self.queries}", [], self.base_events(seed),
                               self.work_dir, seed,
                               contamination=self.contamination, plan=plan)
        self._cache[cache_key] = result
        return result

    def pool_runs(self, runs: list[dict], plan: CamouflagePlan) -> dict:
        """Pool per-seed results into one `overall` block.

        A hook rather than a call so a subclass scoring a different system can
        pool through that system's scorer while reusing every other part of the
        search. `alerts` is this system's volume: incidents for ours, alerts for
        a SIEM.
        """
        pooled = pool([{**r, "condition": plan.label()} for r in runs])["overall"]
        return {**pooled, "alerts": pooled["incidents"]}

    def evaluate(self, plan: CamouflagePlan,
                 seeds: tuple[int, ...] = SEARCH_SEEDS) -> Evaluation:
        """Score one plan over several seeds, pooled from summed counts.

        Pooled rather than averaged, and over more than one seed, for the reason
        section 4 gives: with 3 instances per scenario a single seed moves the
        instance rate in 33% steps, so a single-seed win is mostly a draw of the
        corpus.
        """
        runs = [self._run(plan, seed) for seed in seeds]
        pooled = self.pool_runs(runs, plan)
        evaluation = Evaluation(
            plan=plan, seeds=tuple(seeds),
            instance_rate=pooled["instance_detection_rate"],
            line_rate=pooled["line_detection_rate"],
            incidents=pooled["alerts"], attack_lines=pooled["attack_lines"],
            queries_after=self.queries)
        self.trace.append(evaluation)
        if self.verbose:
            print(f"  [{self.queries:>3}/{self.budget}] {plan.label():<64} "
                  f"instance {evaluation.instance_rate:.1%} line {evaluation.line_rate:.1%}")
        return evaluation


# --- The search ------------------------------------------------------------

@dataclass
class SearchResult:
    best: Evaluation
    exhaustive: list[Evaluation] = field(default_factory=list)
    climb: list[Evaluation] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    queries: int = 0
    seeds_searched: tuple[int, ...] = ()


def subsets_of_strategies(universe: tuple[str, ...] = tuple(STRATEGIES)
                         ) -> list[tuple[str, ...]]:
    """All 2^n combinations of the universe, shortest first.

    The published suite tests 8 of the 128 available here. Enumerating the rest
    is the cheapest honest thing an adaptive adversary can do, and it is itself
    a result: it says whether the hand-picked `realistic-combo` was actually the
    strongest fixed recipe or merely a plausible one.

    `universe` is a parameter because a *smaller* space is sometimes forced by
    the instrument rather than chosen: batch replay cannot measure timing-based
    camouflage against an arrival-time-keyed SIEM (Decision Log 2026-08-18), so
    a search that compares the two systems must exclude `slow` and `temporal`
    from both sides or it would be optimising an artefact.
    """
    combos: list[tuple[str, ...]] = []
    universe = tuple(s for s in STRATEGIES if s in universe)
    for size in range(len(universe) + 1):
        combos.extend(itertools.combinations(universe, size))
    return combos


def exhaustive_stage(oracle: Oracle, rule: ValidityRule, seed: int,
                     result: SearchResult,
                     universe: tuple[str, ...] = tuple(STRATEGIES)) -> list[Evaluation]:
    """Every strategy subset at published magnitudes, on one search seed."""
    evaluations = []
    for combo in subsets_of_strategies(universe):
        plan = CamouflagePlan(strategies=combo)
        ok, why = rule.check(oracle.base_events(seed), plan, seed)
        if not ok:
            result.rejected.append((plan.label(), why))
            continue
        try:
            evaluations.append(oracle.evaluate(plan, seeds=(seed,)))
        except BudgetExhausted:
            print("  budget exhausted during the exhaustive stage")
            break
    return evaluations


def neighbours(plan: CamouflagePlan) -> list[CamouflagePlan]:
    """One-knob-at-a-time variations, restricted to knobs a strategy reads.

    Varying `noise_ratio` on a plan with no `noise` produces a byte-identical
    corpus, so an unrestricted neighbourhood would spend real queries
    re-measuring the same thing.
    """
    # `slow` and `temporal` are exclusive in `apply_plan` (slow wins), so on a
    # plan carrying both, the temporal gap knobs are dead and varying them would
    # buy an identical corpus at the price of a real query.
    active = set(plan.strategies)
    if "slow" in active:
        active.discard("temporal")
    live = {knob for s in active for knob in KNOBS_BY_STRATEGY[s]}
    out = []
    for knob in live:
        for value in KNOB_GRID[knob]:
            if value == getattr(plan, knob):
                continue
            try:
                out.append(plan.with_knob(knob, value))
            except ValueError:
                continue    # min above max, etc -- not a plan
    return out


def hill_climb(oracle: Oracle, rule: ValidityRule, start: Evaluation,
               seeds: tuple[int, ...], result: SearchResult,
               max_rounds: int = 4) -> Evaluation:
    """Greedy descent on the magnitudes, from the best subset found.

    Hill climbing rather than a genetic algorithm or anything gradient-shaped:
    each probe costs ~7 seconds of CPU, the objective is noisy and mostly flat
    (an 11-point step on the headline metric), and there is no gradient to
    follow through a discrete strategy set. A population method would spend the
    whole budget on one generation.
    """
    best = start
    for round_index in range(max_rounds):
        improved = None
        for candidate in neighbours(best.plan):
            ok, why = rule.check(oracle.base_events(seeds[0]), candidate, seeds[0])
            if not ok:
                result.rejected.append((candidate.label(), why))
                continue
            try:
                evaluation = oracle.evaluate(candidate, seeds=seeds)
            except BudgetExhausted:
                print("  budget exhausted during hill climbing")
                return best
            result.climb.append(evaluation)
            if evaluation.key < best.key and (improved is None
                                              or evaluation.key < improved.key):
                improved = evaluation
        if improved is None:
            print(f"  no improving neighbour in round {round_index + 1}; stopping")
            return best
        best = improved
        print(f"  round {round_index + 1}: {best.plan.label()} "
              f"-> instance {best.instance_rate:.1%} line {best.line_rate:.1%}")
    return best


def search(oracle: Oracle, rule: ValidityRule | None = None,
           seeds: tuple[int, ...] = SEARCH_SEEDS, top_k: int = 5,
           universe: tuple[str, ...] = tuple(STRATEGIES)) -> SearchResult:
    """Exhaustive over strategy subsets, then hill climb the magnitudes."""
    rule = rule or ValidityRule()
    result = SearchResult(best=None, seeds_searched=tuple(seeds))  # type: ignore[arg-type]

    print(f"Stage A: all {len(subsets_of_strategies(universe))} strategy subsets "
          f"on seed {seeds[0]}")
    result.exhaustive = exhaustive_stage(oracle, rule, seeds[0], result, universe)
    if not result.exhaustive:
        raise RuntimeError("no valid plan was evaluated")
    ranked = sorted(result.exhaustive, key=lambda e: e.key)

    print(f"\nStage B: re-scoring the top {top_k} subsets on all search seeds "
          "(a one-seed win is mostly a corpus draw)")
    confirmed = []
    for evaluation in ranked[:top_k]:
        try:
            confirmed.append(oracle.evaluate(evaluation.plan, seeds=seeds))
        except BudgetExhausted:
            break
    best = min(confirmed or ranked, key=lambda e: e.key)

    print(f"\nStage C: hill climbing magnitudes from {best.plan.label()}")
    result.best = hill_climb(oracle, rule, best, seeds, result)
    result.queries = oracle.queries
    return result


# --- Held-out evaluation ---------------------------------------------------

def evaluate_holdout(plan: CamouflagePlan, work_dir: Path,
                     searched_seeds: set[int],
                     seeds: tuple[int, ...] = HOLDOUT_SEEDS,
                     contamination: float = CONTAMINATION) -> list[dict]:
    """Score the discovered plan against the published conditions, on fresh seeds.

    Refuses to run on a seed the search touched. That check is the whole point
    of the function: an adaptive result reported on its own search seeds
    measures how well the optimiser fitted one corpus, not how well the attack
    transfers.
    """
    overlap = sorted(set(seeds) & searched_seeds)
    if overlap:
        raise ValueError(
            f"held-out seeds {overlap} were used during the search; the "
            "adaptive result would be reported on the data it was fitted to")

    conditions = [("baseline", [], None),
                  ("realistic-combo", REALISTIC_COMBO, None),
                  ("adaptive", list(plan.sorted_strategies), plan)]
    runs: dict[str, list[dict]] = {name: [] for name, _, _ in conditions}
    for seed in seeds:
        base_events = build_dataset(seed=seed)
        for name, strategies, condition_plan in conditions:
            result = run_condition(f"holdout_{name}", strategies, base_events,
                                   work_dir, seed, contamination=contamination,
                                   plan=condition_plan)
            result["condition"] = name
            runs[name].append(result)
            o = result["overall"]
            print(f"  seed {seed} {name:<16} instance {o['instance_detection_rate']:.0%} "
                  f"line {o['line_detection_rate']:.0%}")
    return [pool(runs[name]) for name, _, _ in conditions]


# --- Reporting -------------------------------------------------------------

def budget_curve(trace: list[Evaluation]) -> list[tuple[int, float, float]]:
    """Best-so-far detection against queries spent.

    This is the shape of the finding: robustness as a function of how many
    attempts the attacker is allowed, rather than a single adjective.
    """
    curve = []
    best: tuple[float, float] | None = None
    for evaluation in trace:
        if best is None or evaluation.key < best:
            best = evaluation.key
            curve.append((evaluation.queries_after, best[0], best[1]))
    return curve


def render_report(result: SearchResult, holdout: list[dict],
                  rule: ValidityRule, elapsed: float) -> str:
    by_name = {r["condition"]: r["overall"] for r in holdout}
    baseline, combo, adaptive = (by_name["baseline"], by_name["realistic-combo"],
                                 by_name["adaptive"])
    ranked = sorted(result.exhaustive, key=lambda e: e.key)

    def delta(value: float, reference: float) -> str:
        return f"{value:.1%} ({value - reference:+.1%})"

    lines = [
        "# Adaptive Adversary",
        "",
        "Generated by `logdet-adaptive` (`src/logdet_eval/adaptive.py`).",
        "",
        "An attacker that **searches** camouflage settings against this detector,",
        "instead of applying the seven fixed recipes the published adversarial",
        "suite uses. The search space is the shipped transforms",
        "(`logdet_eval/camouflage.py`) -- which strategies, and how hard each is",
        "turned -- so an adaptive result and a fixed-recipe result are measured on",
        "corpora built by identical code.",
        "",
        "## Threat model -- read this before the numbers",
        "",
        "The attacker here is **stronger than any real one**. Each probe returns",
        "the detector's true detection rates over *labelled* attack lines: it is",
        "told exactly how much of its attack was caught. A real attacker sees a",
        "log they do not own and an analyst who may or may not respond.",
        "",
        "So this measures an **upper bound on evasion** -- what is achievable with",
        "perfect feedback -- not what an attacker in the wild would achieve.",
        "",
        f"The attack must remain an attack: a plan is rejected before it costs a",
        f"query if any instance keeps fewer than {rule.min_lines} lines or under",
        f"{rule.min_share:.0%} of its original lines. Without that floor the",
        "optimiser 'evades' by deleting the attack, which is surrender, not evasion.",
        f"{len(result.rejected)} candidate plans were rejected this way.",
        "",
        "## What it cost",
        "",
        f"- **{result.queries} detector queries**, {elapsed / 60:.1f} minutes of CPU",
        f"- Search seeds: {list(result.seeds_searched)}",
        f"- Held-out seeds: {[r for r in HOLDOUT_SEEDS]} -- **never seen during the search**",
        "",
        "## The result, on seeds the search never saw",
        "",
        "This is the only table that may be quoted as a robustness figure. The",
        "search's own best score is reported further down and is **not comparable**:",
        "it is the score the plan was selected for, on the corpus it was fitted to.",
        "",
        "| Condition | Instance detection | Line detection | Incidents |",
        "|---|---|---|---|",
        f"| baseline (no camouflage) | {baseline['instance_detection_rate']:.1%} "
        f"| {baseline['line_detection_rate']:.1%} | {baseline['incidents']} |",
        f"| realistic-combo (published) | {delta(combo['instance_detection_rate'], baseline['instance_detection_rate'])} "
        f"| {delta(combo['line_detection_rate'], baseline['line_detection_rate'])} "
        f"| {combo['incidents']} |",
        f"| **adaptive** (`{result.best.plan.label()}`) "
        f"| {delta(adaptive['instance_detection_rate'], baseline['instance_detection_rate'])} "
        f"| {delta(adaptive['line_detection_rate'], baseline['line_detection_rate'])} "
        f"| {adaptive['incidents']} |",
        "",
    ]

    gain = combo["instance_detection_rate"] - adaptive["instance_detection_rate"]
    line_gain = combo["line_detection_rate"] - adaptive["line_detection_rate"]
    if gain > 0.001:
        verdict = (f"**The search beat the hand-picked combination by "
                   f"{gain:.1%} of instance detection.** The seven fixed recipes "
                   "were not the strongest attack available from their own transforms.")
    elif line_gain > 0.001:
        verdict = (f"**The search did not beat `realistic-combo` on instance "
                   f"detection** (the registered metric), but it removed "
                   f"{line_gain:.1%} more of the attack's lines. Less evidence "
                   "reaches the analyst; the attack is still seen.")
    else:
        verdict = ("**The search found nothing better than the hand-picked "
                   "`realistic-combo`.** Recorded as measured. That is a result "
                   "about this search space, not proof that no better attack "
                   "exists -- see the limits below.")
    lines += [verdict, ""]

    lines += [
        "## Robustness as a function of the attacker's budget",
        "",
        "Best detection rate the attacker had achieved after N queries, on the",
        "search seeds. A flat curve means extra probes bought nothing.",
        "",
        "| Queries spent | Best instance detection | Best line detection | Plan |",
        "|---|---|---|---|",
    ]
    by_queries = {e.queries_after: e for e in result.exhaustive + result.climb}
    for queries, instance_rate, line_rate in budget_curve(result.exhaustive + result.climb):
        plan = by_queries[queries].plan.label()
        lines.append(f"| {queries} | {instance_rate:.1%} | {line_rate:.1%} | `{plan}` |")

    lines += [
        "",
        f"## All {len(result.exhaustive)} strategy subsets, ranked (search seed "
        f"{result.seeds_searched[0]}, published magnitudes)",
        "",
        "The published suite measures 8 of the 128 possible combinations. Ranking",
        "all of them says whether the hand-picked `realistic-combo` was the",
        "strongest fixed recipe or just a plausible one.",
        "",
        "| Rank | Strategies | Instance detection | Line detection |",
        "|---|---|---|---|",
    ]
    for i, evaluation in enumerate(ranked[:15], start=1):
        lines.append(f"| {i} | `{evaluation.plan.label()}` "
                     f"| {evaluation.instance_rate:.1%} | {evaluation.line_rate:.1%} |")

    combo_rank = next((i for i, e in enumerate(ranked, start=1)
                       if set(e.plan.strategies) == set(REALISTIC_COMBO)), None)
    if combo_rank:
        lines += ["", f"`realistic-combo` ranks **{combo_rank} of {len(ranked)}** "
                      "on the search seed."]

    lines += [
        "",
        "## Limits",
        "",
        "- The oracle gives the attacker labelled ground truth. Upper bound, not estimate.",
        "- The search space is the seven shipped transforms and their magnitudes.",
        "  An attacker who invents an eighth transform is outside it, and the",
        "  honest reading of a flat result is *these transforms are exhausted*,",
        "  not *this detector is robust*.",
        "- Instance detection over 9 instances moves in 11-point steps. Line",
        "  detection is the finer signal and is reported beside it throughout.",
        "- Detection only. Nothing here re-measures alert volume against Wazuh;",
        "  the same search against a third-party ruleset is the natural next arm",
        "  and needs the container up.",
        "",
    ]
    return "\n".join(lines)


# --- Entry point -----------------------------------------------------------

def main(output_dir: str = str(Path(RESULTS_DIR) / "adaptive"),
         budget: int = DEFAULT_BUDGET,
         holdout_seeds: tuple[int, ...] = HOLDOUT_SEEDS,
         search_seeds: tuple[int, ...] = SEARCH_SEEDS,
         contamination: float = CONTAMINATION) -> dict:
    work_dir = Path(PROCESSED_DATA_DIR) / "adaptive"
    rule = ValidityRule()
    oracle = Oracle(work_dir, budget=budget, contamination=contamination)

    started = time.time()
    result = search(oracle, rule, seeds=search_seeds)
    elapsed = time.time() - started

    print(f"\nBest plan on the search seeds: {result.best.plan.label()} "
          f"(instance {result.best.instance_rate:.1%}, line {result.best.line_rate:.1%})")
    print(f"\nHeld-out evaluation on seeds {list(holdout_seeds)} "
          "(never seen by the search)")
    holdout = evaluate_holdout(result.best.plan, work_dir, oracle.seeds_used,
                               seeds=holdout_seeds, contamination=contamination)

    payload = {
        "queries": result.queries,
        "seconds": round(elapsed, 1),
        "search_seeds": list(search_seeds),
        "holdout_seeds": list(holdout_seeds),
        "validity_rule": {"min_lines": rule.min_lines, "min_share": rule.min_share},
        "rejected_plans": len(result.rejected),
        # The full list, not just the count: which plans the validity floor
        # refused is itself a finding (see results/adaptive/notes.md -- on this
        # corpus they are all `volume` plans, i.e. the published `volume`
        # condition sometimes thins an instance below the floor).
        "rejected": [{"plan": label, "why": why} for label, why in result.rejected],
        "best_plan": result.best.plan.as_dict(),
        "best_on_search_seeds": result.best.as_dict(),
        "budget_curve": budget_curve(result.exhaustive + result.climb),
        "exhaustive": [e.as_dict() for e in sorted(result.exhaustive, key=lambda e: e.key)],
        "climb": [e.as_dict() for e in result.climb],
        "holdout": holdout,
    }

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "adaptive.json").write_text(json.dumps(payload, indent=2))
    (out / "adaptive.md").write_text(render_report(result, holdout, rule, elapsed))
    print(f"\nWrote {out}/adaptive.md and .json")
    return payload


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Search camouflage settings against the detector (Stage 6).")
    parser.add_argument("--output-dir", default=str(Path(RESULTS_DIR) / "adaptive"))
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET,
                        help="Maximum detector queries the attacker may spend "
                             "(~7s each on the CPU floor)")
    parser.add_argument("--search-seeds", type=int, nargs="+", default=list(SEARCH_SEEDS))
    parser.add_argument("--holdout-seeds", type=int, nargs="+", default=list(HOLDOUT_SEEDS),
                        help="Seeds the search may not touch. The reported result "
                             "comes from these.")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION)
    args = parser.parse_args()
    main(args.output_dir, budget=args.budget,
         holdout_seeds=tuple(args.holdout_seeds),
         search_seeds=tuple(args.search_seeds),
         contamination=args.contamination)


if __name__ == "__main__":
    cli()
