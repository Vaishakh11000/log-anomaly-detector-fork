"""Tests for the paced-replay half of the §1b kill point.

The batch runner excludes `slow`, `temporal` and `realistic-combo` because it
cannot measure them; this module is what lifts that exclusion, so its verdict
logic carries the same weight and is pinned the same way. The thresholds are
the pre-registered ones and must not drift.
"""

import pytest

from logdet_eval.killpoint import PRIMARY_LEVEL
from logdet_eval.paced_killpoint import CONDITIONS, compare, render_report
from logdet_eval.scoring import MIN_ADMISSIBLE_SEEDS


def _side(rate: float, alerts: int = 100) -> dict:
    return {"overall": {"instance_detection_rate": rate,
                        "instances": 9, "instances_detected": round(rate * 9),
                        "alerts": alerts, "total_flagged_lines": alerts}}


def _payload(conditions: dict[str, tuple[float, float]],
             wazuh: bool = True, seeds: int = MIN_ADMISSIBLE_SEEDS) -> dict:
    """conditions maps name -> (our_rate, siem_rate)."""
    return {
        "wazuh_available": wazuh,
        "seeds": seeds,
        "ambient_ratio": 0.05,
        "max_events_per_ip": 12,
        "min_spacing_seconds": 75.0,
        "corpus_manifest": {"background_lines": 600, "attack_lines": 115,
                            "attack_instances": 9},
        "conditions": [
            {
                "condition": name,
                "strategies": [] if name == "baseline" else [name],
                "ours": _side(ours),
                # every level is rendered, so the fixture carries all three
                "siem": {"3": _side(siem), "7": _side(siem), "10": _side(siem)},
            }
            for name, (ours, siem) in conditions.items()
        ],
    }


class TestConditions:
    def test_covers_exactly_the_strategies_batch_cannot_measure(self):
        """If this drifts, either the paced run stops covering a strategy the
        batch verdict excludes, or it burns hours re-measuring one it doesn't."""
        assert [name for name, _ in CONDITIONS] == [
            "baseline", "slow", "temporal", "realistic-combo"]

    def test_baseline_is_first(self):
        assert CONDITIONS[0] == ("baseline", [])


class TestVerdict:
    def test_no_exclusion_rule_applies_here(self):
        """Every strategy in this run is measurable by this instrument, so all
        of them count toward the verdict -- unlike the batch runner."""
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, 0.0),
                            "temporal": (1.0, 1.0), "realistic-combo": (1.0, 1.0)})
        result = compare(payload)
        assert result["best_differential"] == pytest.approx(100.0)
        assert result["verdict"] == "CONTINUE"

    @pytest.mark.parametrize("siem_rate,expected", [
        (0.75, "CONTINUE"),    # 25.0pt exactly -- the registered boundary
        (0.76, "PARTIAL"),
        (0.90, "PARTIAL"),     # 10.0pt exactly
        (0.91, "STOP"),
    ])
    def test_registered_thresholds_at_their_boundaries(self, siem_rate, expected):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, siem_rate)})
        assert compare(payload)["verdict"] == expected

    def test_siem_degrading_less_than_us_is_stop(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (0.5, 1.0)})
        result = compare(payload)
        assert result["best_differential"] < 0
        assert result["verdict"] == "STOP"

    def test_below_the_seed_floor_is_not_a_verdict(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, 0.0)}, seeds=1)
        result = compare(payload)
        assert result["admissible"] is False
        assert result["verdict"].startswith("INADMISSIBLE")

    def test_detector_only_run_returns_incomplete(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (0.8, 0.0)}, wazuh=False)
        result = compare(payload)
        assert result["best_differential"] is None
        assert result["verdict"] == "INCOMPLETE"

    def test_missing_baseline_returns_incomplete_rather_than_raising(self):
        payload = _payload({"slow": (1.0, 0.0)})
        assert compare(payload)["verdict"] == "INCOMPLETE"

    def test_verdict_takes_the_best_strategy(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, 0.95),
                            "temporal": (1.0, 0.6)})
        assert compare(payload)["best_differential"] == pytest.approx(40.0)


class TestReport:
    def test_inadmissible_run_is_marked_not_a_result(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, 0.0)}, seeds=1)
        text = render_report(payload, compare(payload))
        assert "NOT A RESULT" in text

    def test_report_names_the_instrument_and_its_reason(self):
        payload = _payload({"baseline": (1.0, 1.0), "slow": (1.0, 0.5)})
        text = render_report(payload, compare(payload))
        assert "arrival time" in text
        assert "unmodified" in text
