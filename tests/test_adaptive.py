"""
The adaptive adversary, pinned.

Three properties carry the credibility of Stage 6's headline number and each is
asserted here rather than trusted:

  * a plan at default magnitudes is the published fixed recipe, byte for byte
    (`tests/test_camouflage.py` holds the corpus-level version of this);
  * the optimiser cannot "evade" by deleting the attack;
  * the reported result cannot be measured on a seed the search fitted to.

The oracle is stubbed throughout, so these run in milliseconds and need no
embedding model. What the stub cannot check -- that the detector actually
behaves this way -- is what the real run in `results/adaptive/` is for.
"""

import pytest

from logdet_eval.adaptive import (
    BudgetExhausted,
    Evaluation,
    Oracle,
    ValidityRule,
    budget_curve,
    evaluate_holdout,
    hill_climb,
    neighbours,
    render_report,
    search,
    subsets_of_strategies,
)
from logdet_eval import camouflage
from logdet_eval.adversarial import camouflage_events
from logdet_eval.camouflage import STRATEGIES, CamouflagePlan
from logdet_eval.generate_logs import build_dataset


# --- The plan is the recipe ------------------------------------------------

def test_default_plan_knobs_are_the_published_constants():
    plan = CamouflagePlan()
    assert plan.gap_min_minutes == camouflage.CAMOUFLAGE_MIN_GAP_MINUTES
    assert plan.gap_max_minutes == camouflage.CAMOUFLAGE_MAX_GAP_MINUTES
    assert plan.slow_gap_min_minutes == camouflage.CAMOUFLAGE_SLOW_MIN_GAP_MINUTES
    assert plan.slow_gap_max_minutes == camouflage.CAMOUFLAGE_SLOW_MAX_GAP_MINUTES
    assert plan.noise_ratio == camouflage.CAMOUFLAGE_NOISE_RATIO
    assert plan.volume_keep == camouflage.CAMOUFLAGE_VOLUME_KEEP


@pytest.mark.parametrize("strategies", [[], ["mimicry"], ["slow", "noise", "volume"],
                                        camouflage.REALISTIC_COMBO])
def test_apply_plan_at_defaults_equals_the_fixed_recipe(strategies):
    """The search space contains the published conditions exactly, not nearly."""
    events = build_dataset(seed=7)
    fixed = camouflage_events(events, strategies, 7)
    planned = camouflage.apply_plan(events, CamouflagePlan(strategies=tuple(strategies)), 7)
    assert [(e["ts"], e["message"]) for e in fixed] == [
        (e["ts"], e["message"]) for e in planned]


def test_plan_rejects_an_unknown_strategy():
    with pytest.raises(ValueError):
        CamouflagePlan(strategies=("teleport",))


def test_plan_label_hides_default_magnitudes_and_shows_changed_ones():
    assert CamouflagePlan(strategies=("volume",)).label() == "volume"
    assert "volume_keep=0.1" in CamouflagePlan(
        strategies=("volume",), volume_keep=0.1).label()


# --- The attack must stay an attack ----------------------------------------

def test_validity_rule_accepts_the_published_recipes():
    events = build_dataset(seed=7)
    rule = ValidityRule()
    ok, why = rule.check(events, CamouflagePlan(strategies=tuple(camouflage.REALISTIC_COMBO)), 7)
    assert ok, why


def test_validity_rule_rejects_a_plan_that_deletes_the_attack():
    """The optimiser's cheapest cheat, blocked before it can cost a query."""
    events = build_dataset(seed=7)
    ok, why = ValidityRule().check(
        events, CamouflagePlan(strategies=("volume",), volume_keep=0.0), 7)
    assert not ok
    assert "kept" in why


def test_two_line_instances_are_not_ruled_out_by_the_absolute_floor():
    """Scenario B is two lines long; a flat 'keep 3' would ban every plan."""
    assert ValidityRule(min_lines=3, min_share=0.4).instance_floor(2) == 2


# --- The search space ------------------------------------------------------

def test_all_128_strategy_subsets_are_enumerated():
    combos = subsets_of_strategies()
    assert len(combos) == 2 ** len(STRATEGIES) == 128
    assert len(set(combos)) == 128


def test_neighbours_only_vary_knobs_an_active_strategy_reads():
    """A knob no strategy consumes produces an identical corpus for a real query."""
    varied = {knob for plan in neighbours(CamouflagePlan(strategies=("volume",)))
              for knob in camouflage.KNOB_NAMES
              if getattr(plan, knob) != getattr(CamouflagePlan(), knob)}
    assert varied == {"volume_keep"}


def test_neighbours_skip_impossible_plans():
    """min above max is not a plan; the grid contains such pairs."""
    for plan in neighbours(CamouflagePlan(strategies=("temporal",))):
        assert plan.gap_min_minutes <= plan.gap_max_minutes


# --- The oracle ------------------------------------------------------------

class StubOracle(Oracle):
    """Scores a plan by a fixed rule instead of running the detector.

    `scores` maps a strategy tuple to (instance_rate, line_rate); anything
    unlisted scores as fully detected.
    """

    def __init__(self, tmp_path, scores=None, budget=1000):
        super().__init__(tmp_path, budget=budget, verbose=False)
        self.scores = scores or {}
        self.corpus_calls = 0

    def base_events(self, seed):
        self.corpus_calls += 1
        return []

    def _run(self, plan, seed):
        cache_key = (plan, seed)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if self.queries >= self.budget:
            raise BudgetExhausted(f"query budget {self.budget} spent")
        self.queries += 1
        self.seeds_used.add(seed)
        instance_rate, line_rate = self.scores.get(plan.sorted_strategies, (1.0, 1.0))
        result = {
            "condition": plan.label(), "strategies": list(plan.sorted_strategies),
            "per_scenario": {"A": {"attack_lines": 100,
                                   "lines_detected": int(100 * line_rate),
                                   "instances": 9,
                                   "instances_detected": int(round(9 * instance_rate)),
                                   "impossible_travel_hits": 0}},
            "overall": {"attack_lines": 100, "total_flagged_lines": 10, "incidents": 20,
                        "instance_detection_rate": instance_rate,
                        "line_detection_rate": line_rate},
        }
        self._cache[cache_key] = result
        return result


def test_a_repeated_probe_is_memory_not_a_new_query(tmp_path):
    oracle = StubOracle(tmp_path)
    plan = CamouflagePlan(strategies=("mimicry",))
    oracle.evaluate(plan, seeds=(1,))
    oracle.evaluate(plan, seeds=(1,))
    assert oracle.queries == 1


def test_the_budget_is_enforced(tmp_path):
    oracle = StubOracle(tmp_path, budget=2)
    oracle.evaluate(CamouflagePlan(strategies=("mimicry",)), seeds=(1,))
    oracle.evaluate(CamouflagePlan(strategies=("volume",)), seeds=(1,))
    with pytest.raises(BudgetExhausted):
        oracle.evaluate(CamouflagePlan(strategies=("noise",)), seeds=(1,))


def test_the_oracle_records_every_seed_it_touched(tmp_path):
    oracle = StubOracle(tmp_path)
    oracle.evaluate(CamouflagePlan(strategies=("mimicry",)), seeds=(3, 4))
    assert oracle.seeds_used == {3, 4}


def test_evaluation_ranks_on_instance_detection_then_line_detection():
    weaker = Evaluation(CamouflagePlan(), (1,), 0.9, 0.1, 1, 1, 1)
    stronger = Evaluation(CamouflagePlan(), (1,), 0.8, 0.9, 1, 1, 1)
    assert stronger.key < weaker.key


# --- Search behaviour ------------------------------------------------------

def test_hill_climb_stops_when_no_neighbour_improves(tmp_path):
    from logdet_eval.adaptive import SearchResult

    oracle = StubOracle(tmp_path)
    start = oracle.evaluate(CamouflagePlan(strategies=("volume",)), seeds=(1,))
    result = SearchResult(best=start)
    best = hill_climb(oracle, ValidityRule(), start, (1,), result)
    assert best.plan == start.plan


def test_hill_climb_follows_an_improving_knob(tmp_path):
    from logdet_eval.adaptive import SearchResult

    class KnobOracle(StubOracle):
        def _run(self, plan, seed):
            result = super()._run(plan, seed)
            # Thinner volume evades, in this stub's world.
            result["overall"]["instance_detection_rate"] = plan.volume_keep
            result["per_scenario"]["A"]["instances_detected"] = int(round(9 * plan.volume_keep))
            return result

    oracle = KnobOracle(tmp_path)
    start = oracle.evaluate(CamouflagePlan(strategies=("volume",)), seeds=(1,))
    result = SearchResult(best=start)
    best = hill_climb(oracle, ValidityRule(min_lines=0, min_share=0.0), start, (1,), result)
    assert best.plan.volume_keep < start.plan.volume_keep


def test_search_prefers_the_strongest_subset(tmp_path):
    oracle = StubOracle(tmp_path, scores={("mimicry", "volume"): (0.2, 0.3)})
    result = search(oracle, ValidityRule(), seeds=(1,), top_k=3)
    assert set(result.best.plan.strategies) == {"mimicry", "volume"}
    assert len(result.exhaustive) == 128


def test_budget_curve_is_best_so_far_and_never_worsens():
    trace = [Evaluation(CamouflagePlan(), (1,), r, r, 1, 1, i)
             for i, r in enumerate([1.0, 0.8, 0.9, 0.5], start=1)]
    curve = budget_curve(trace)
    assert [q for q, _, _ in curve] == [1, 2, 4]
    assert [round(r, 3) for _, r, _ in curve] == [1.0, 0.8, 0.5]


# --- The honesty guard -----------------------------------------------------

def test_holdout_refuses_a_seed_the_search_touched(tmp_path):
    with pytest.raises(ValueError, match="fitted"):
        evaluate_holdout(CamouflagePlan(), tmp_path, searched_seeds={42, 43},
                         seeds=(43, 44))


def test_report_says_the_search_score_is_not_a_robustness_figure(tmp_path):
    from logdet_eval.adaptive import SearchResult

    oracle = StubOracle(tmp_path, scores={("mimicry",): (0.4, 0.4)})
    result = SearchResult(best=oracle.evaluate(CamouflagePlan(strategies=("mimicry",)),
                                               seeds=(1,)),
                          seeds_searched=(1,))
    result.exhaustive = list(oracle.trace)
    holdout = [{"condition": name,
                "overall": {"instance_detection_rate": rate, "line_detection_rate": rate,
                            "incidents": 10}}
               for name, rate in (("baseline", 1.0), ("realistic-combo", 0.9),
                                  ("adaptive", 0.6))]
    text = render_report(result, holdout, ValidityRule(), 60.0)
    assert "upper bound on evasion" in text
    assert "not comparable" in text
    assert "beat the hand-picked combination" in text


def test_report_states_a_null_result_plainly(tmp_path):
    from logdet_eval.adaptive import SearchResult

    oracle = StubOracle(tmp_path)
    result = SearchResult(best=oracle.evaluate(CamouflagePlan(), seeds=(1,)),
                          seeds_searched=(1,))
    result.exhaustive = list(oracle.trace)
    holdout = [{"condition": name,
                "overall": {"instance_detection_rate": rate, "line_detection_rate": rate,
                            "incidents": 10}}
               for name, rate in (("baseline", 1.0), ("realistic-combo", 0.9),
                                  ("adaptive", 0.9))]
    text = render_report(result, holdout, ValidityRule(), 60.0)
    assert "found nothing better" in text


def test_slow_shadows_temporal_in_the_neighbourhood():
    """`apply_plan` ignores temporal when slow is present; the search must too."""
    plan = CamouflagePlan(strategies=("slow", "temporal"))
    varied = {knob for candidate in neighbours(plan) for knob in camouflage.KNOB_NAMES
              if getattr(candidate, knob) != getattr(plan, knob)}
    assert varied == {"slow_gap_min_minutes", "slow_gap_max_minutes"}
