"""
The scorer both systems are measured through.

If this drifts from the scorer used for our own detector, the kill-point
differential stops being a property of the systems and becomes an artefact of
the measurement code.
"""

import pandas as pd
import pytest

from logdet_eval.scoring import (
    differential,
    instance_drop,
    measure_lines,
    verdict,
)

GT = pd.DataFrame([
    {"line_number": 10, "scenario": "A", "instance": 1},
    {"line_number": 11, "scenario": "A", "instance": 1},
    {"line_number": 50, "scenario": "A", "instance": 2},
    {"line_number": 80, "scenario": "B", "instance": 1},
])


def test_one_flagged_line_detects_the_whole_instance():
    """Instance level asks 'would an analyst see this at all', so partial
    evidence still counts as caught."""
    result = measure_lines({10}, GT, total_lines=100)
    assert result["per_scenario"]["A"]["instance_detection_rate"] == 0.5
    assert result["per_scenario"]["A"]["line_detection_rate"] == round(1 / 3, 3)


def test_detecting_nothing_scores_zero():
    result = measure_lines(set(), GT, total_lines=100)
    assert result["overall"]["instance_detection_rate"] == 0.0


def test_detecting_every_instance_scores_one():
    result = measure_lines({10, 50, 80}, GT, total_lines=100)
    assert result["overall"]["instance_detection_rate"] == 1.0


def test_unlabelled_flags_are_not_counted_against_a_system():
    """The real corpus contains genuine attacks nobody labelled. Counting a
    flag on one as a false positive would punish a system for being right."""
    a = measure_lines({10}, GT, total_lines=100)
    b = measure_lines({10, 999, 1000}, GT, total_lines=100)
    assert a["overall"]["instance_detection_rate"] == b["overall"]["instance_detection_rate"]


def test_alert_volume_is_reported_separately_from_detection():
    result = measure_lines({10}, GT, total_lines=100, alert_count=57)
    assert result["overall"]["alerts"] == 57
    assert result["overall"]["total_flagged_lines"] == 1


def test_instance_drop_is_in_percentage_points():
    base = measure_lines({10, 50, 80}, GT, total_lines=100)
    hidden = measure_lines({10}, GT, total_lines=100)
    assert instance_drop(base, hidden) == pytest.approx(66.7, abs=0.1)


def test_differential_sign_convention():
    """Positive = the SIEM lost more than we did, the direction the roadmap's
    premise needs. The unfavourable case must report with the same convention."""
    assert differential(ours_drop=10.0, siem_drop=60.0) == 50.0
    assert differential(ours_drop=60.0, siem_drop=10.0) == -50.0


@pytest.mark.parametrize("value, expected", [
    (87.0, "CONTINUE"), (25.0, "CONTINUE"), (24.9, "PARTIAL"),
    (10.0, "PARTIAL"), (9.9, "STOP"), (0.0, "STOP"), (-30.0, "STOP"),
])
def test_the_registered_criterion_is_applied_exactly(value, expected):
    """The §1b thresholds, pinned. A kill point you can move is not a kill
    point, so these boundaries are asserted rather than trusted."""
    assert verdict(value) == expected


def test_agrees_with_the_scorer_used_for_our_own_detector(tmp_path):
    """The cross-check that keeps the comparison honest.

    adversarial.measure() scores our detector from a dataframe; measure_lines()
    scores a SIEM from a set of line numbers. If they disagree on identical
    input, the kill-point differential is partly an artefact of which scorer
    each side happened to go through.
    """
    from logdet_eval.adversarial import measure

    n_lines = 20
    log = tmp_path / "corpus.log"
    log.write_text("\n".join(f"line {i}" for i in range(1, n_lines + 1)) + "\n")

    flagged = {3, 4, 12}
    scored = pd.DataFrame({
        "is_anomaly": [i in flagged for i in range(1, n_lines + 1)],
        "impossible_travel": [False] * n_lines,
        "user": ["alice"] * n_lines,
        "source_ip": ["10.0.0.5"] * n_lines,
        "timestamp": pd.date_range("2026-07-18", periods=n_lines, freq="min"),
    })
    gt = pd.DataFrame([
        {"line_number": 3, "scenario": "A", "instance": 1},
        {"line_number": 4, "scenario": "A", "instance": 1},
        {"line_number": 9, "scenario": "A", "instance": 2},
        {"line_number": 12, "scenario": "C", "instance": 1},
    ])

    theirs = measure(scored, gt, str(log))
    ours = measure_lines(flagged, gt, total_lines=n_lines)

    assert ours["overall"]["instance_detection_rate"] == theirs["overall"]["instance_detection_rate"]
    assert ours["overall"]["line_detection_rate"] == theirs["overall"]["line_detection_rate"]
    for scenario in theirs["per_scenario"]:
        for field in ("attack_lines", "lines_detected", "line_detection_rate",
                      "instances", "instances_detected", "instance_detection_rate"):
            assert ours["per_scenario"][scenario][field] == theirs["per_scenario"][scenario][field], \
                f"{scenario}.{field} disagrees"
