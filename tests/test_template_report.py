"""Tests for the Drain3 template inventory report.

The report is the thing that decides whether mined ids are safe for detection
to read, so what is pinned here is the diagnostic, not the prose: that a merge
which absorbed a *word* is separated from one that absorbed an identifier, and
that the report never claims mining changed a result.
"""

import json

import pytest

from logdet_eval.template_report import (
    build_report,
    mine_corpus,
    semantic_merges,
    summarise_disagreements,
    varying_positions,
)


def write_log(tmp_path, messages, host="labsz", process="sshd"):
    lines = [
        f"Dec 10 06:55:{i % 60:02d} {host} {process}[{1000 + i}]: {message}"
        for i, message in enumerate(messages)
    ]
    path = tmp_path / "corpus.log"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


FAILED = [f"Failed password for root from 10.0.0.{i} port 2200{i} ssh2" for i in range(1, 9)]
ACCEPTED = [f"Accepted password for alice from 10.0.1.{i} port 900{i} ssh2" for i in range(1, 5)]


def test_mine_corpus_counts_both_templaters(tmp_path):
    result = mine_corpus(write_log(tmp_path, FAILED + ACCEPTED), year=2026)
    assert result["parsed_lines"] == len(FAILED) + len(ACCEPTED)
    assert result["parse_rate"] == 1.0
    # The regex leaves the username in; Drain3 does not, but it must still keep
    # a failure and a success apart.
    assert result["mined_clusters"] == 2
    assert result["regex_templates"] == 2


def test_username_variation_merges_but_stays_one_event(tmp_path):
    messages = [f"Failed password for user{i} from 10.0.0.{i} port 2200{i} ssh2"
                for i in range(1, 9)]
    result = mine_corpus(write_log(tmp_path, messages), year=2026)
    disagreements = summarise_disagreements(result)

    assert result["mined_clusters"] == 1
    assert result["regex_templates"] == 8
    assert len(disagreements["merges"]) == 1
    assert disagreements["splits"] == []


def test_varying_positions_finds_the_token_that_differs():
    positions = varying_positions([
        "Failed password for invalid user <IP>",
        "Failed none for invalid user <IP>",
    ])
    assert positions == [{"position": 1, "values": ["none", "password"], "cardinality": 2}]


def test_varying_positions_reports_a_length_difference():
    positions = varying_positions(["a b c", "a b c d"])
    assert positions[0]["position"] is None
    assert positions[0]["cardinality"] == 2


def test_high_cardinality_merge_is_not_flagged_as_semantic(tmp_path):
    """Collapsing a hundred usernames is templating working, not a lost meaning."""
    messages = [f"Failed password for user{i} from 10.0.0.1 port 22 ssh2"
                for i in range(1, 40)]
    result = mine_corpus(write_log(tmp_path, messages), year=2026)
    flagged = semantic_merges(result, summarise_disagreements(result)["merges"])
    assert flagged == []


def test_low_cardinality_merge_is_flagged(tmp_path):
    """`Failed password` and `Failed none` are different events; if they share a
    mined id, the report has to say so."""
    messages = ([f"Failed password for invalid user bob from 10.0.0.{i} port 22 ssh2"
                 for i in range(1, 6)]
                + [f"Failed none for invalid user bob from 10.0.1.{i} port 22 ssh2"
                   for i in range(1, 6)])
    result = mine_corpus(write_log(tmp_path, messages), year=2026)
    flagged = semantic_merges(result, summarise_disagreements(result)["merges"])

    assert len(flagged) == 1
    values = flagged[0]["positions"][0]["values"]
    assert values == ["none", "password"]


def test_limit_stops_reading_early(tmp_path):
    result = mine_corpus(write_log(tmp_path, FAILED + ACCEPTED), limit=4, year=2026)
    assert result["total_lines"] == 4


def test_growth_always_records_the_final_count(tmp_path):
    result = mine_corpus(write_log(tmp_path, FAILED), year=2026)
    assert result["growth"][-1] == (len(FAILED), result["mined_clusters"])


def test_unparseable_lines_are_counted_but_not_mined(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(
        "Dec 10 06:55:01 labsz sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n"
        "this line is not syslog at all\n"
    )
    result = mine_corpus(str(path), year=2026)
    assert result["total_lines"] == 2
    assert result["parsed_lines"] == 1
    assert result["mined_clusters"] == 1


def test_build_report_writes_both_artifacts(tmp_path):
    log = write_log(tmp_path, FAILED + ACCEPTED)
    out = tmp_path / "report"
    report = build_report(log, str(out), year=2026)

    text = report.read_text()
    assert "# Drain3 template inventory" in text
    assert "section 4 was not triggered" in text

    payload = json.loads((out / "templates.json").read_text())
    assert payload["mined_clusters"] == 2
    assert payload["splits"] == 0


def test_build_report_can_persist_the_mined_state(tmp_path):
    from logdet.templating import TemplateMiner

    log = write_log(tmp_path, FAILED + ACCEPTED)
    state = tmp_path / "state.json"
    build_report(log, str(tmp_path / "report"), year=2026, state_path=str(state))

    restored = TemplateMiner()
    restored.load(state)
    assert restored.cluster_count == 2
