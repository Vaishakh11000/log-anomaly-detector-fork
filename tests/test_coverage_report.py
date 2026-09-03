"""
The coverage matrix: what the denominator is, and what a cell means.

The number this report exists to produce is "N of M techniques", and M is the
part that can lie. These tests pin that M is computed from ATT&CK's own
detection strategies rather than chosen, that the two denominators stay apart,
and that a cell which cannot be answered says so instead of printing a zero.
"""

import json

import pytest

from logdet_eval import coverage_report as cov

STRICT = "linux:syslog"
EQUIVALENT = "auditd:USER_LOGIN"


def _parsed(techniques: dict) -> dict:
    return {"attack_version": "test", "matrix_order": ["credential-access"],
            "tactics": {}, "techniques": techniques}


def _technique(technique_id: str, log_sources: list[str], **overrides) -> dict:
    entry = {
        "technique_id": technique_id, "name": f"Technique {technique_id}",
        "tactics": ["Credential Access"], "tactic_ids": ["TA0006"], "kill_chain": [8],
        "platforms": ["Linux"], "log_sources": log_sources,
        "deprecated": False, "revoked": False,
        "url": f"https://attack.mitre.org/techniques/{technique_id}",
    }
    entry.update(overrides)
    return entry


def test_the_universe_is_techniques_attack_itself_links_to_our_log_sources():
    parsed = _parsed({
        "T0001": _technique("T0001", [STRICT]),
        "T0002": _technique("T0002", ["WinEventLog:Sysmon"]),
    })
    universe = cov.visible_universe(parsed, cov.DECLARED_LOG_SOURCES)
    assert set(universe) == {"T0001"}


def test_the_two_denominators_stay_apart():
    """auditd records the same authentication events from another subsystem, so
    counting it is an authored claim -- it must never silently widen the strict
    figure."""
    parsed = _parsed({
        "T0001": _technique("T0001", [STRICT]),
        "T0002": _technique("T0002", [EQUIVALENT]),
    })
    strict = cov.visible_universe(parsed, cov.DECLARED_LOG_SOURCES)
    wider = cov.visible_universe(parsed,
                                 cov.DECLARED_LOG_SOURCES | cov.EQUIVALENT_LOG_SOURCES)
    assert set(strict) == {"T0001"}
    assert set(wider) == {"T0001", "T0002"}


def test_a_withdrawn_technique_never_inflates_the_denominator():
    parsed = _parsed({
        "T0001": _technique("T0001", [STRICT]),
        "T0002": _technique("T0002", [STRICT], deprecated=True),
        "T0003": _technique("T0003", [STRICT], revoked=True),
    })
    assert set(cov.visible_universe(parsed, cov.DECLARED_LOG_SOURCES)) == {"T0001"}


def test_the_matrix_carries_mapped_techniques_attack_does_not_credit():
    """Most of what the table maps, ATT&CK credits to auditd or Sysmon rather
    than syslog. Dropping those rows would hide the honest half of the result."""
    parsed = _parsed({
        "T1110": _technique("T1110", ["auditd:SYSCALL"]),
        "T0002": _technique("T0002", [STRICT]),
    })
    rows = cov.build_matrix(parsed, {})
    brute = next(r for r in rows if r["technique_id"] == "T1110")
    assert brute["mapped_by"] == "keyword"
    assert not brute["in_strict_universe"] and not brute["in_wider_universe"]
    assert cov.summarise(rows)["mapped_outside_universe"] == 1


def test_rows_are_ordered_by_kill_chain_position():
    parsed = _parsed({
        "T0001": _technique("T0001", [STRICT], kill_chain=[9]),
        "T0002": _technique("T0002", [STRICT], kill_chain=[2]),
    })
    assert [r["technique_id"] for r in cov.build_matrix(parsed, {})] == ["T0002", "T0001"]


def test_a_signal_technique_reads_n_a_in_a_line_level_column():
    """Impossible travel exists only across an incident. A 0 there would read
    as 'this corpus never triggered it' when it means 'not askable per line'."""
    parsed = _parsed({"T1021.004": _technique("T1021.004", [STRICT])})
    corpora = {"synthetic": {"_lines": 751}}
    rows = cov.build_matrix(parsed, corpora)
    rendered = cov.render(rows, cov.summarise(rows), corpora)
    line = next(l for l in rendered.splitlines() if "T1021.004" in l and "|" in l)
    assert "n/a" in line and " 0 " not in line


def test_a_mapped_but_unobserved_technique_is_counted_as_a_claim():
    parsed = _parsed({
        "T1110": _technique("T1110", [STRICT]),
        "T1053": _technique("T1053", [STRICT]),
    })
    corpora = {"synthetic": {"_lines": 751, "T1110": 78}}
    summary = cov.summarise(cov.build_matrix(parsed, corpora))
    assert summary["mapped_and_observed"] == 1
    assert summary["mapped_never_observed"] == 1


def test_incident_observation_counts_techniques_per_incident(tmp_path):
    path = tmp_path / "incidents.json"
    path.write_text(json.dumps([
        {"incident_id": 1, "mitre_techniques": [{"technique_id": "T1110"}]},
        {"incident_id": 2, "mitre_techniques": [{"technique_id": "T1110"},
                                                {"technique_id": "T1087"}]},
    ]))
    counts = cov.observe_incidents(path)
    assert counts["T1110"] == 2 and counts["T1087"] == 1 and counts["_incidents"] == 2


def test_observation_counts_the_message_field_not_the_raw_line(tmp_path):
    """A raw line also carries host and process, so grepping it would attribute
    a technique the pipeline itself would never attach."""
    log = tmp_path / "auth.log"
    log.write_text(
        "Jul 18 14:00:00 host sudo[1]: Server listening on 0.0.0.0 port 22.\n"
        "Jul 18 14:00:01 host sshd[2]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
    )
    counts = cov.observe_corpus(log, year=2026)
    assert counts["_lines"] == 2
    assert counts.get("T1110") == 1
    assert "T1548" not in counts, "the sudo process field must not map the line"
