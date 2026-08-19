"""Tests for the section 1b kill-point comparison.

This module decides the single most consequential number in the project, so
what is asserted here is not arithmetic but *integrity*: that the verdict is
computed only from strategies the instrument can actually measure, and that the
pre-registered thresholds behave exactly as registered. A bug in compare() would
not crash anything -- it would quietly return a different roadmap decision.
"""

import pytest

from logdet_eval.killpoint import (
    CONDITIONS, TIMING_DEPENDENT, PRIMARY_LEVEL, compare, render_report)
from logdet_eval.scoring import MIN_ADMISSIBLE_SEEDS


def _side(rate: float) -> dict:
    return {"overall": {"instance_detection_rate": rate,
                        "instances": 9, "instances_detected": round(rate * 9),
                        "alerts": 100}}


def _payload(conditions: dict[str, tuple[float, float]],
             wazuh: bool = True, seeds: int = MIN_ADMISSIBLE_SEEDS) -> dict:
    """conditions maps name -> (our_rate, siem_rate)."""
    return {
        "wazuh_available": wazuh,
        "seeds": seeds,
        "ambient_ratio": 0.05,
        "conditions": [
            {
                "condition": name,
                "strategies": [] if name == "baseline" else [name],
                "timing_dependent": name in TIMING_DEPENDENT,
                "ours": _side(ours),
                "siem": {str(PRIMARY_LEVEL): _side(siem)},
            }
            for name, (ours, siem) in conditions.items()
        ],
    }


def test_drops_and_differential_signs():
    """Positive differential means the SIEM lost more ground than we did."""
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "rephrase": (1.0, 0.67),   # we hold, Wazuh falls 33pt
    }))
    row = out["per_strategy"]["rephrase"]
    assert row["ours_drop"] == 0.0
    assert row["siem_drop"] == 33.0
    assert row["differential"] == 33.0
    assert out["verdict"] == "CONTINUE"


def test_timing_dependent_strategy_cannot_inflate_the_verdict():
    """A timing strategy showing a huge gap must not count toward the verdict.

    Batch replay cannot measure an arrival-time-keyed SIEM, so if this were
    included a known instrument artefact would return CONTINUE on its own.
    """
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "mimicry": (1.0, 0.89),      # measurable: 11pt
        "realistic-combo": (1.0, 0.0),  # timing: would be 100pt
    }))
    assert out["per_strategy"]["realistic-combo"]["timing_dependent"] is True
    assert out["per_strategy"]["realistic-combo"]["differential"] == 100.0
    # the excluded strategy is reported but does not decide anything
    assert out["best_measurable_differential"] == 11.0
    assert out["verdict"] == "PARTIAL"


def test_timing_dependent_strategy_cannot_depress_the_verdict():
    """The real observed case: slow reads -22pt purely as an artefact.

    Wazuh's windows ignore log timestamps, so its drop under slow is 0 by
    construction while ours is real. Letting that in would return STOP on the
    strength of a measurement error.
    """
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "rephrase": (1.0, 0.67),   # measurable: +33pt
        "slow": (0.78, 1.0),       # timing artefact: -22pt
    }))
    assert out["per_strategy"]["slow"]["differential"] == -22.0
    assert out["best_measurable_differential"] == 33.0
    assert out["verdict"] == "CONTINUE"


@pytest.mark.parametrize("siem_rate,expected", [
    (0.75, "CONTINUE"),   # 25.0pt exactly -- the registered boundary
    (0.76, "PARTIAL"),    # 24.0pt
    (0.90, "PARTIAL"),    # 10.0pt exactly
    (0.91, "STOP"),       # 9.0pt
    (1.00, "STOP"),       # no differential at all
])
def test_registered_thresholds_at_the_boundaries(siem_rate, expected):
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "mimicry": (1.0, siem_rate),
    }))
    assert out["verdict"] == expected


def test_siem_degrading_less_than_us_is_a_stop():
    """Section 1b: if the SIEM degrades less than this system, that is STOP."""
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "mimicry": (0.60, 1.0),   # we collapse, Wazuh holds
    }))
    assert out["per_strategy"]["mimicry"]["differential"] == -40.0
    assert out["verdict"] == "STOP"


def test_no_wazuh_yields_incomplete_not_a_verdict():
    """A detector-only run must never produce a kill-point verdict."""
    out = compare(_payload({"baseline": (1.0, 1.0), "mimicry": (0.9, 1.0)},
                           wazuh=False))
    assert out["best_measurable_differential"] is None
    assert out["verdict"] == "INCOMPLETE"
    assert "differential" not in out["per_strategy"]["mimicry"]


def test_conditions_cover_baseline_and_all_timing_strategies():
    names = [name for name, _ in CONDITIONS]
    assert names[0] == "baseline"
    assert TIMING_DEPENDENT.issubset(set(names)), (
        "TIMING_DEPENDENT names a strategy that is never run")
    assert len(names) == len(set(names)), "duplicate condition name"


# --- the seed floor (CLAUDE.md section 4) --------------------------------------

@pytest.mark.parametrize("seeds", [0, 1, 2, 4])
def test_below_the_seed_floor_there_is_no_verdict(seeds):
    """A differential from too few seeds must not be labelled CONTINUE/PARTIAL/STOP.

    The 1-seed smoke pass read +22.2pt, which would render as "PARTIAL" and be
    indistinguishable from a measured result to anyone reading the file later.
    """
    out = compare(_payload({
        "baseline": (1.0, 1.0),
        "rephrase": (1.0, 0.67),   # +33pt, would otherwise be CONTINUE
    }, seeds=seeds))
    assert out["admissible"] is False
    assert out["verdict"].startswith("INADMISSIBLE")
    assert str(seeds) in out["verdict"]
    # the number is still reported -- it is the *verdict* that is withheld
    assert out["best_measurable_differential"] == 33.0
    for word in ("CONTINUE", "PARTIAL", "STOP"):
        assert word not in out["verdict"]


def test_at_the_seed_floor_a_verdict_is_produced():
    out = compare(_payload({"baseline": (1.0, 1.0), "rephrase": (1.0, 0.67)},
                           seeds=MIN_ADMISSIBLE_SEEDS))
    assert out["admissible"] is True
    assert out["verdict"] == "CONTINUE"


def test_inadmissible_report_carries_a_refusal_banner():
    """The rendered Markdown is what a future session finds on disk."""
    payload = _payload({"baseline": (1.0, 1.0), "rephrase": (1.0, 0.67)}, seeds=1)
    payload["corpus_manifest"] = {
        "background_lines": 2483, "benign_lines": 2365, "attack_lines": 111,
        "attack_instances": 9, "brute_force_failures": [15, 25],
        "enumeration_probes": [10, 12], "days_covered": 25,
        "real_users": ["a"], "host": "LabSZ",
    }
    text = render_report(payload, compare(payload))
    assert "NOT A RESULT" in text
    assert "INADMISSIBLE" in text
    assert "--seeds 5" in text
