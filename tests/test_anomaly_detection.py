"""
Detection stack: per-user Isolation Forest, the impossible-travel physics
check, and severity tiering. Fake embeddings throughout -- these assert the
plumbing and the rule, not the quality of a sentence-transformer.
"""

import numpy as np
import pandas as pd
import pytest

from logdet.anomaly_detection import (
    PerUserAnomalyDetector,
    assign_severity,
    detect_impossible_travel,
    highest_severity,
    run_anomaly_detection,
)
from logdet.config import MIN_SAMPLES_PER_USER


# --- per-user baselines ---

def test_users_with_enough_history_get_their_own_model(embedded_frame):
    detector = PerUserAnomalyDetector().fit(embedded_frame)
    assert "alice" in detector.models


def test_sparse_users_fall_back_to_the_global_model(embedded_frame):
    """Cold start: bob has fewer than MIN_SAMPLES_PER_USER rows, so fitting a
    baseline on him would be fitting noise."""
    assert (embedded_frame["user"] == "bob").sum() < MIN_SAMPLES_PER_USER
    detector = PerUserAnomalyDetector().fit(embedded_frame)
    assert "bob" not in detector.models
    assert detector.global_model is not None


def test_scoring_flags_the_off_manifold_rows(embedded_frame):
    detector = PerUserAnomalyDetector().fit(embedded_frame)
    scored = detector.score(embedded_frame)
    assert {"anomaly_score", "is_anomaly"} <= set(scored.columns)
    # the two planted outliers sit at the tail of the frame
    assert scored["is_anomaly"].iloc[-2:].all()


def test_scoring_does_not_mutate_the_input(embedded_frame):
    before = list(embedded_frame.columns)
    PerUserAnomalyDetector().fit(embedded_frame).score(embedded_frame)
    assert list(embedded_frame.columns) == before


# --- impossible travel ---

def travel_frame(rows: list[tuple[str, str, str, str]]) -> pd.DataFrame:
    return pd.DataFrame(
        [{"timestamp": pd.Timestamp(t), "user": u, "source_ip": ip, "message": m}
         for t, u, ip, m in rows]
    )


def test_same_user_different_subnet_within_the_window_is_flagged():
    df = travel_frame([
        ("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice from 10.0.0.5"),
        ("2026-07-18 10:20:00", "alice", "203.0.113.9", "Accepted password for alice from 203.0.113.9"),
    ])
    assert detect_impossible_travel(df)["impossible_travel"].tolist() == [False, True]


def test_same_subnet_is_not_impossible_travel():
    df = travel_frame([
        ("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice from 10.0.0.5"),
        ("2026-07-18 10:20:00", "alice", "10.0.4.7", "Accepted password for alice from 10.0.4.7"),
    ])
    assert not detect_impossible_travel(df)["impossible_travel"].any()


def test_a_wide_enough_gap_is_ordinary_travel():
    df = travel_frame([
        ("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice from 10.0.0.5"),
        ("2026-07-18 18:00:00", "alice", "203.0.113.9", "Accepted password for alice from 203.0.113.9"),
    ])
    assert not detect_impossible_travel(df)["impossible_travel"].any()


def test_failed_logins_do_not_count_as_travel():
    """It is a physics check on real logins. A failed attempt means nobody
    arrived anywhere."""
    df = travel_frame([
        ("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice from 10.0.0.5"),
        ("2026-07-18 10:20:00", "alice", "203.0.113.9", "Failed password for alice from 203.0.113.9"),
    ])
    assert not detect_impossible_travel(df)["impossible_travel"].any()


def test_two_different_users_are_not_travel():
    df = travel_frame([
        ("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice from 10.0.0.5"),
        ("2026-07-18 10:20:00", "bob", "203.0.113.9", "Accepted password for bob from 203.0.113.9"),
    ])
    assert not detect_impossible_travel(df)["impossible_travel"].any()


# --- severity ---

@pytest.mark.parametrize("score, expected", [(-0.30, "high"), (-0.08, "medium"), (-0.01, "low")])
def test_severity_tiers_follow_the_configured_thresholds(score, expected):
    df = pd.DataFrame([{"anomaly_score": score, "is_anomaly": True}])
    assert assign_severity(df)["severity"].iloc[0] == expected


def test_non_anomalies_get_no_severity():
    df = pd.DataFrame([{"anomaly_score": -0.30, "is_anomaly": False}])
    assert assign_severity(df)["severity"].iloc[0] == "none"


def test_impossible_travel_overrides_a_weak_ml_score():
    """A confirmed physics signal outranks a soft semantic one."""
    df = pd.DataFrame([{"anomaly_score": 0.5, "is_anomaly": True, "impossible_travel": True}])
    assert assign_severity(df)["severity"].iloc[0] == "high"


def test_highest_severity_reduces_a_mixed_incident():
    assert highest_severity(pd.Series(["low", "high", "medium"])) == "high"
    assert highest_severity(pd.Series(["none", "low"])) == "low"


# --- the combined entry point ---

def test_run_anomaly_detection_keeps_the_ml_verdict_separate_from_the_rule(rng):
    """Evaluation has to attribute each detection to the model or the rule, so
    'ml_anomaly' must survive alongside the OR-ed 'is_anomaly'."""
    rows = []
    for i in range(12):
        rows.append({"timestamp": pd.Timestamp("2026-07-18 09:00:00") + pd.Timedelta(minutes=i),
                     "user": "alice", "source_ip": "10.0.0.5",
                     "message": "Failed password for alice from 10.0.0.5",
                     "embedding": rng.normal(0, 1, 384)})
    rows += [
        {"timestamp": pd.Timestamp("2026-07-18 10:00:00"), "user": "alice", "source_ip": "10.0.0.5",
         "message": "Accepted password for alice from 10.0.0.5", "embedding": rng.normal(0, 1, 384)},
        {"timestamp": pd.Timestamp("2026-07-18 10:20:00"), "user": "alice", "source_ip": "203.0.113.9",
         "message": "Accepted password for alice from 203.0.113.9", "embedding": rng.normal(0, 1, 384)},
    ]
    scored = run_anomaly_detection(pd.DataFrame(rows))

    assert {"ml_anomaly", "is_anomaly", "impossible_travel", "severity"} <= set(scored.columns)
    assert scored["impossible_travel"].iloc[-1]
    assert scored["is_anomaly"].iloc[-1]
    assert scored["severity"].iloc[-1] == "high"
    # is_anomaly is the union of the two signals, never narrower than either
    assert (scored["is_anomaly"] == (scored["ml_anomaly"] | scored["impossible_travel"])).all()
