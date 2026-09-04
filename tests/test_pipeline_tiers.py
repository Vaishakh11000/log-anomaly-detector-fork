"""
Which incidents get which narration tier (Stage 5 model routing).

Detection is stubbed out here on purpose: what is under test is the budget
policy -- a full narrative for what `should_narrate` selects, a one-sentence
triage line for the rest, and never both for one incident. The numbers those
incidents carry are the regression locks' business, not this file's.
"""

import json

import pandas as pd
import pytest

from logdet import pipeline


@pytest.fixture
def stub_detection(monkeypatch):
    """Three incidents: one notable (3 events, high), two singletons."""
    frame = pd.DataFrame({
        "user": ["alice", "bob", "carol"],
        "source_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 11:00:00",
                                     "2026-07-18 12:00:00"]),
        "message": ["Failed password for alice from 10.0.0.1 port 1 ssh2",
                    "session opened for user bob", "session opened for user carol"],
        "is_anomaly": [True, True, True],
        "impossible_travel": [False, False, False],
        "anomaly_score": [-0.4, -0.1, -0.1],
        "severity": ["high", "low", "low"],
    })
    monkeypatch.setattr(pipeline, "add_embeddings_to_df", lambda df, **kw: df)
    monkeypatch.setattr(pipeline, "run_anomaly_detection",
                        lambda df, **kw: frame)
    monkeypatch.setattr(pipeline, "group_anomalies",
                        lambda scored: [frame.iloc[[0]], frame.iloc[[1]],
                                        frame.iloc[[2]]])
    monkeypatch.setattr(pipeline, "should_narrate",
                        lambda severity, event_count: severity == "high")
    monkeypatch.setattr(pipeline, "generate_narrative",
                        lambda incident, **kw: "full narrative")

    class Line:
        line, dropped = "one sentence", []

    monkeypatch.setattr(pipeline, "generate_triage", lambda incident, **kw: Line())
    return frame


def _run(tmp_path, csv_source, **kwargs) -> list[dict]:
    out = tmp_path / "incidents.json"
    pipeline.run_pipeline(str(csv_source), str(out), **kwargs)
    return json.loads(out.read_text())


@pytest.fixture
def csv_source(tmp_path, stub_detection):
    path = tmp_path / "parsed.csv"
    stub_detection.to_csv(path, index=False)
    return path


def test_the_cheap_tier_only_covers_what_the_budget_left_unnarrated(
        tmp_path, csv_source):
    results = _run(tmp_path, csv_source, use_llm=True, triage_lines=True)

    narrated = [r for r in results if r["narrative"]]
    triaged = [r for r in results if r["triage_line"]]
    assert len(narrated) == 1 and len(triaged) == 2
    # never both: a triage line must not read as a narrative that was written
    assert all(not (r["narrative"] and r["triage_line"]) for r in results)


def test_without_the_flag_every_triage_line_is_none(tmp_path, csv_source):
    results = _run(tmp_path, csv_source, use_llm=True)
    assert [r["triage_line"] for r in results] == [None, None, None]


def test_a_failing_triage_call_is_recorded_not_raised(tmp_path, csv_source,
                                                      monkeypatch):
    def boom(incident, **kwargs):
        raise RuntimeError("ollama down")

    monkeypatch.setattr(pipeline, "generate_triage", boom)
    results = _run(tmp_path, csv_source, use_llm=True, triage_lines=True)
    failed = [r for r in results if not r["narrative"]]
    assert failed and all("triage line generation failed" in r["triage_line"]
                          for r in failed)
