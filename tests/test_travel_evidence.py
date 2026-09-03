"""
Tests for the impossible-travel evidence carried into an incident (Stage 4).

The Known Issue this closes: the travel check compares a login against that
user's previous login, the previous one is benign, so the incident asserted
"impossible travel" while showing only one of the two logins involved.

The constraint that matters as much as the fix: evidence must not become a
detection. A benign line carried into `events` would be counted by
`event_count`, ranked by triage, and attributed as a flagged line by the
bake-off's `ours_flagged` -- i.e. a display fix would silently manufacture a
false positive.
"""

import pandas as pd
import pytest

from logdet.anomaly_detection import (assign_severity, detect_impossible_travel,
                                      travel_evidence)
from logdet.llm_narrative import PROMPT_TEMPLATE, build_prompt, format_incident_for_prompt
from logdet.pipeline import build_incident_entry
from logdet.sequence_grouping import group_anomalies


@pytest.fixture
def scored():
    """Alice logs in from home, then from another subnet 15 minutes later."""
    frame = pd.DataFrame({
        "user": ["alice", "bob", "alice"],
        "source_ip": ["10.0.0.12", "10.0.0.30", "203.0.113.44"],
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00",
                                     "2026-07-18 10:05:00",
                                     "2026-07-18 10:15:00"]),
        "message": [
            "Accepted password for alice from 10.0.0.12 port 51000 ssh2",
            "Accepted password for bob from 10.0.0.30 port 51005 ssh2",
            "Accepted password for alice from 203.0.113.44 port 51010 ssh2",
        ],
        "anomaly_score": [0.1, 0.1, 0.1],
        "is_anomaly": [False, False, False],
    })
    frame = detect_impossible_travel(frame)
    frame["ml_anomaly"] = frame["is_anomaly"]
    frame["is_anomaly"] = frame["ml_anomaly"] | frame["impossible_travel"]
    return assign_severity(frame)


def test_the_incident_holds_only_the_arriving_login(scored):
    """The gap being fixed, asserted so the fix is visibly a fix."""
    incidents = group_anomalies(scored)
    assert len(incidents) == 1
    assert list(incidents[0]["source_ip"]) == ["203.0.113.44"]


def test_evidence_is_the_login_that_was_compared_against(scored):
    incident = group_anomalies(scored)[0]
    evidence = travel_evidence(incident, scored)
    assert list(evidence["source_ip"]) == ["10.0.0.12"]
    assert list(evidence["user"]) == ["alice"]


def test_evidence_ignores_other_users_logins(scored):
    """bob logged in between the two legs and is not evidence for alice."""
    incident = group_anomalies(scored)[0]
    evidence = travel_evidence(incident, scored)
    assert "bob" not in set(evidence["user"])


def test_no_evidence_without_a_travel_hit(scored):
    plain = scored.copy()
    plain["impossible_travel"] = False
    plain["is_anomaly"] = True
    incident = group_anomalies(plain)[0]
    assert travel_evidence(incident, plain).empty


def test_evidence_outside_the_travel_window_is_not_retrieved(scored):
    far = scored.copy()
    far.loc[0, "timestamp"] = pd.Timestamp("2026-07-18 06:00:00")
    incident = group_anomalies(far)[0]
    assert travel_evidence(incident, far, window_minutes=60).empty


def test_context_events_are_separate_from_events_and_counts(scored):
    """Evidence must not inflate what the rest of the system treats as alerts."""
    incident = group_anomalies(scored)[0]
    entry = build_incident_entry(0, incident, context=scored)

    assert len(entry["context_events"]) == 1
    assert entry["context_events"][0]["source_ip"] == "10.0.0.12"
    assert entry["context_events"][0]["role"] == "prior login compared against"

    # ...and nothing a downstream consumer counts has moved.
    assert entry["event_count"] == 1
    assert len(entry["events"]) == 1
    assert [e["source_ip"] for e in entry["events"]] == ["203.0.113.44"]
    assert entry["source_ips"] == ["203.0.113.44"]


def test_entry_without_context_is_unchanged(scored):
    """Every caller that passes no context gets exactly the old entry, plus an
    empty list -- which is what keeps the pinned regression numbers valid."""
    incident = group_anomalies(scored)[0]
    with_context = build_incident_entry(0, incident, context=scored)
    without = build_incident_entry(0, incident)

    assert without["context_events"] == []
    assert {k: v for k, v in without.items() if k != "context_events"} == \
           {k: v for k, v in with_context.items() if k != "context_events"}


def test_prompt_is_byte_identical_when_there_is_no_evidence(scored):
    """The narration-latency figures in CLAUDE.md section 2c were measured on a
    592-token prompt; an unconditional context block would silently invalidate
    them."""
    incident = group_anomalies(scored)[0]
    events_str, mitre_str = format_incident_for_prompt(incident)
    from logdet.config import NARRATIVE_SENTENCE_RANGE
    from logdet.llm_narrative import summarise_incident

    expected = PROMPT_TEMPLATE.format(summary=summarise_incident(incident),
                                      events=events_str, mitre_matches=mitre_str,
                                      sentences=NARRATIVE_SENTENCE_RANGE)
    assert build_prompt(incident) == expected
    assert build_prompt(incident, []) == expected


def test_prompt_labels_evidence_as_not_an_anomaly(scored):
    incident = group_anomalies(scored)[0]
    entry = build_incident_entry(0, incident, context=scored)
    prompt = build_prompt(incident, entry["context_events"])

    assert "10.0.0.12" in prompt
    assert "NOT anomalies" in prompt
    # the evidence block precedes the grounded MITRE block, not the event list
    assert prompt.index("Incident events") < prompt.index("NOT anomalies")
    assert prompt.index("NOT anomalies") < prompt.index("Matched MITRE")
