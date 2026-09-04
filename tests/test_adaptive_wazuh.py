"""
The adaptive search pointed at Wazuh, pinned.

This arm re-tests the kill point's one surviving win (`rephrase`, +31.1pt)
against an attacker that optimises instead of one that applies fixed recipes,
so two things carry its credibility and both are asserted here rather than
trusted:

  * the search space excludes `slow` and `temporal` on **both** sides, because
    Wazuh's correlation windows are keyed on arrival time and a batch-replayed
    corpus is simultaneous to it -- an optimiser let loose there would find the
    instrument, not the system;
  * the differential is reported from the *weaker* of the two adaptive rows, so
    an attacker optimising against Wazuh cannot be quoted alone.

Both oracles are stubbed, so these run in milliseconds and need neither the
embedding model nor a Wazuh container.
"""

import pytest

from logdet_eval import scoring
from logdet_eval.adaptive import Oracle, ValidityRule, search
from logdet_eval.adaptive_wazuh import (
    SEARCH_UNIVERSE,
    TIMING_DEPENDENT,
    WazuhOracle,
    compare,
    reject_timing_plan,
    render_report,
)
from logdet_eval.camouflage import STRATEGIES, CamouflagePlan


# --- The instrument limit is enforced, not documented -----------------------

def test_timing_strategies_are_outside_the_search_space():
    assert set(SEARCH_UNIVERSE) == set(STRATEGIES) - set(TIMING_DEPENDENT)
    assert "slow" not in SEARCH_UNIVERSE and "temporal" not in SEARCH_UNIVERSE


@pytest.mark.parametrize("strategies", [("slow",), ("temporal",),
                                        ("slow", "mimicry"), ("rephrase", "temporal")])
def test_a_timing_plan_is_refused_rather_than_scored(strategies):
    """Wazuh cannot lose an instance to `slow` in batch, so a score for one
    would be an artefact of the harness reported as a robustness gap."""
    with pytest.raises(ValueError, match="arrival time"):
        reject_timing_plan(CamouflagePlan(strategies=strategies))


def test_a_timing_free_plan_is_accepted():
    reject_timing_plan(CamouflagePlan(strategies=("rephrase", "mimicry", "volume")))


def test_the_search_never_offers_the_wazuh_oracle_a_timing_plan():
    from logdet_eval.adaptive import subsets_of_strategies

    for combo in subsets_of_strategies(SEARCH_UNIVERSE):
        reject_timing_plan(CamouflagePlan(strategies=combo))


class StubWazuhOracle(WazuhOracle):
    """Scores by a fixed table, but keeps the real timing refusal."""

    def __init__(self, tmp_path, scores=None):
        Oracle.__init__(self, tmp_path, budget=1000, verbose=False)
        self.scores = scores or {}

    def base_events(self, seed):
        return []

    def pool_runs(self, runs, plan):
        return scoring.pool_runs(runs)["overall"]

    def _score(self, log_path, ground_truth, total_lines):  # pragma: no cover
        raise AssertionError("the stub should not reach the container")

    def _run(self, plan, seed):
        reject_timing_plan(plan)
        instance_rate, line_rate = self.scores.get(plan.sorted_strategies, (1.0, 1.0))
        self.queries += 1
        self.seeds_used.add(seed)
        return {
            "overall": {"attack_lines": 100, "total_flagged_lines": 10, "alerts": 10},
            "per_scenario": {"A": {"attack_lines": 100,
                                   "lines_detected": int(100 * line_rate),
                                   "instances": 9,
                                   "instances_detected": int(round(9 * instance_rate))}},
        }


def test_the_wazuh_oracle_refuses_a_timing_plan_even_when_asked_directly(tmp_path):
    oracle = StubWazuhOracle(tmp_path)
    with pytest.raises(ValueError, match="arrival time"):
        oracle.evaluate(CamouflagePlan(strategies=("slow",)), seeds=(1,))


def test_the_search_runs_over_the_restricted_space(tmp_path):
    """32 subsets, not 128, and `rephrase` wins because it is what breaks a
    signature engine -- the mechanism the kill point measured."""
    oracle = StubWazuhOracle(tmp_path, scores={("rephrase",): (0.2, 0.3)})
    result = search(oracle, ValidityRule(), seeds=(1, 2), universe=SEARCH_UNIVERSE)
    assert len(result.exhaustive) == 32
    assert result.best.plan.sorted_strategies == ("rephrase",)


# --- The differential may not be quoted from the friendlier side ------------

def _holdout(ours_rates, siem_rates):
    """Two systems' pooled results for baseline + two adaptive conditions."""
    def block(instance_rate):
        return {"overall": {"attack_lines": 90, "instance_detection_rate": instance_rate,
                            "line_detection_rate": instance_rate,
                            "total_flagged_lines": 100, "alerts": 100}}
    names = ["baseline", "adaptive-vs-wazuh", "adaptive-vs-ours"]
    return [{"condition": name, "label": name, "plan": {},
             "ours": block(ours_rates[i]), "siem": block(siem_rates[i])}
            for i, name in enumerate(names)]


def test_the_conservative_differential_is_the_weaker_adaptive_row():
    # vs-wazuh: we drop 0pt, Wazuh drops 40pt   -> +40
    # vs-ours:  we drop 30pt, Wazuh drops 0pt   -> -30
    holdout = _holdout(ours_rates=[1.0, 1.0, 0.7], siem_rates=[1.0, 0.6, 1.0])
    comparison = compare(holdout)
    assert comparison["per_condition"]["adaptive-vs-wazuh"]["differential"] == 40.0
    assert comparison["per_condition"]["adaptive-vs-ours"]["differential"] == -30.0
    assert comparison["conservative_differential"] == -30.0


def test_the_differential_keeps_its_sign_when_we_are_the_weaker_system():
    """No branch may quietly reinterpret an unfavourable result."""
    holdout = _holdout(ours_rates=[1.0, 0.5, 0.5], siem_rates=[1.0, 1.0, 1.0])
    comparison = compare(holdout)
    assert comparison["conservative_differential"] == -50.0


def test_report_names_the_excluded_strategies_and_the_conservative_number(tmp_path):
    oracle = StubWazuhOracle(tmp_path, scores={("rephrase",): (0.2, 0.3)})
    result = search(oracle, ValidityRule(), seeds=(1, 2), universe=SEARCH_UNIVERSE)
    holdout = _holdout(ours_rates=[1.0, 1.0, 0.7], siem_rates=[1.0, 0.6, 1.0])
    holdout.insert(1, {"condition": "rephrase", "label": "rephrase", "plan": {},
                       "ours": holdout[0]["ours"], "siem": holdout[1]["siem"]})
    text = render_report({"wazuh": result}, holdout, compare(holdout), ValidityRule(),
                         {"search": (1, 2), "holdout": (44, 45)}, 61.0, 3)
    assert "slow" in text and "arrival" in text
    assert "-30.0pt" in text
    assert "31.1pt" in text
