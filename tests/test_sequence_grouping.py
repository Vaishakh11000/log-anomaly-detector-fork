"""
Incident grouping. This layer decides alert volume -- v1 reported 94 incidents
for 9 real attacks -- so its joining rules are worth pinning down exactly.
"""

import pandas as pd

from conftest import event
from logdet.sequence_grouping import describe_incident, group_anomalies


def frame(*rows: dict) -> pd.DataFrame:
    return pd.DataFrame(list(rows))


def test_same_user_inside_the_window_is_one_incident():
    df = frame(
        event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Failed password for alice"),
        event("2026-07-18 10:05:00", "alice", "10.0.0.5", "Failed password for alice"),
    )
    assert len(group_anomalies(df, window_minutes=30)) == 1


def test_same_user_beyond_the_window_splits():
    df = frame(
        event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Failed password for alice"),
        event("2026-07-18 11:30:00", "alice", "10.0.0.5", "Failed password for alice"),
    )
    assert len(group_anomalies(df, window_minutes=30)) == 2


def test_enumeration_groups_by_source_ip_despite_a_new_username_each_line():
    """Account enumeration varies the username by design. Grouping on user
    alone scattered it into N singleton alerts -- the v1 Phase 4 fix."""
    df = frame(
        event("2026-07-18 14:00:00", "root", "203.0.113.7", "Failed password for root"),
        event("2026-07-18 14:01:00", "test", "203.0.113.7", "Failed password for test"),
        event("2026-07-18 14:02:00", "guest", "203.0.113.7", "Failed password for guest"),
    )
    incidents = group_anomalies(df, window_minutes=30, group_by_source_ip=True)
    assert len(incidents) == 1
    assert len(incidents[0]) == 3


def test_source_ip_grouping_can_be_disabled():
    df = frame(
        event("2026-07-18 14:00:00", "root", "203.0.113.7", "Failed password for root"),
        event("2026-07-18 14:01:00", "test", "203.0.113.7", "Failed password for test"),
    )
    assert len(group_anomalies(df, window_minutes=30, group_by_source_ip=False)) == 2


def test_placeholder_identities_never_join_unrelated_rows():
    """'unknown' is the parser saying it found no user. Joining on it would
    merge unrelated systemd noise into one fabricated incident."""
    df = frame(
        event("2026-07-18 10:00:00", "unknown", None, "systemd: Started Session 1"),
        event("2026-07-18 10:01:00", "unknown", None, "systemd: Started Session 2"),
    )
    assert len(group_anomalies(df, window_minutes=30)) == 2


def test_linking_is_transitive_across_different_identity_types():
    """A links to B by user, B links to C by IP -> all three are one story."""
    df = frame(
        event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Failed password for alice"),
        event("2026-07-18 10:05:00", "alice", "203.0.113.7", "Accepted password for alice"),
        event("2026-07-18 10:10:00", "carol", "203.0.113.7", "Failed password for carol"),
    )
    incidents = group_anomalies(df, window_minutes=30)
    assert len(incidents) == 1
    assert len(incidents[0]) == 3


def test_benign_rows_are_excluded():
    rows = [
        event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Failed password for alice"),
        event("2026-07-18 10:05:00", "bob", "10.0.0.9", "Accepted password for bob"),
    ]
    rows[1]["is_anomaly"] = False
    incidents = group_anomalies(frame(*rows))
    assert len(incidents) == 1
    assert incidents[0]["user"].tolist() == ["alice"]


def test_no_anomalies_yields_no_incidents():
    row = event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Accepted password for alice")
    row["is_anomaly"] = False
    assert group_anomalies(frame(row)) == []


def test_describe_incident_summarises_users_and_ips():
    df = frame(
        event("2026-07-18 10:00:00", "alice", "10.0.0.5", "Failed password for alice"),
        event("2026-07-18 10:01:00", "alice", "10.0.0.5", "Failed password for alice"),
    )
    summary = describe_incident(df)
    assert "2 events" in summary and "alice" in summary and "10.0.0.5" in summary
