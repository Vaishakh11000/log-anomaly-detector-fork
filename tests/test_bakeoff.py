"""
Stage 2b's live bake-off harness.

The part worth testing is not the wall-clock pacing, it is the bookkeeping the
numbers rest on: that both systems are written the identical stream, that a
burst of twenty identical lines attributes to twenty line numbers rather than
one, that a condition is scored against its own ground truth and not the whole
session's, and that a time-compressed firing is never reported as a
measurement. Every one of those fails silently if it is wrong.

Nothing here starts a service, a container or a clock -- the sinks, the readers
and the sleeper are all injected.
"""

import re
from datetime import datetime, timedelta

import pandas as pd
import pytest

from logdet_eval import bakeoff


def make_session(**kwargs) -> tuple[bakeoff.Session, list[bakeoff.ListSink]]:
    sinks = [bakeoff.ListSink(), bakeoff.ListSink()]
    session = bakeoff.Session(fanout=bakeoff.Fanout(list(sinks)), **kwargs)
    session.sleeper = lambda seconds: None
    return session, sinks


def attack_event(ts: datetime, message: str, instance: int = 1) -> dict:
    return {"ts": ts, "process": "sshd", "pid": 100, "message": message,
            "scenario": "A", "instance": instance, "user": "alice",
            "description": "test"}


# --- the stream both systems read -----------------------------------------

def test_fanout_writes_identical_lines_to_every_sink():
    session, sinks = make_session()
    session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1), "Failed password for alice"))
    session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 2), "Accepted password for alice"))

    assert sinks[0].lines == sinks[1].lines
    assert len(sinks[0].lines) == 2
    assert "Failed password for alice" in sinks[0].lines[0]


def test_file_sink_flushes_each_line(tmp_path):
    """The tailer reads by byte offset; a buffered writer hands it half a line."""
    path = tmp_path / "live.log"
    sink = bakeoff.FileSink(path)
    sink.write("Jan 01 00:00:01 server1 sshd[1]: hello")
    assert path.read_text() == "Jan 01 00:00:01 server1 sshd[1]: hello\n"
    sink.close()


def test_manifest_numbers_lines_from_one_and_labels_only_attacks():
    session, _ = make_session()
    session.emit({"ts": datetime(2026, 1, 1), "process": "CRON", "pid": 1,
                  "message": "(root) CMD (run-parts)"})
    session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1), "Failed password for alice"))

    truth = session.manifest.ground_truth()
    assert list(truth["line_number"]) == [2]
    assert list(truth.columns) == ["line_number", "timestamp", "user",
                                   "scenario", "instance", "description"]


# --- attribution ----------------------------------------------------------

def test_repeated_identical_lines_attribute_one_per_alert():
    """A brute force is the same line twenty times. Collapsing duplicates would
    score a twenty-line burst as one detected line."""
    session, sinks = make_session()
    for _ in range(20):
        session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1),
                                  "Failed password for alice from 10.0.0.1 port 1 ssh2"))

    alerts = [{"rule": {"level": 5}, "full_log": sinks[0].lines[0]} for _ in range(20)]
    assert len(bakeoff.wazuh_flagged(alerts, session.manifest)) == 20


def test_wazuh_alerts_below_the_level_are_not_detections():
    session, sinks = make_session()
    session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1), "Failed password for alice"))
    low = [{"rule": {"level": 2}, "full_log": sinks[0].lines[0]}]
    assert bakeoff.wazuh_flagged(low, session.manifest) == set()


def test_our_incidents_attribute_by_second_and_message():
    session, _ = make_session()
    line = session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1),
                                     "Failed password for alice"))
    incidents = [{"events": [{"timestamp": "2026-01-01 00:00:01",
                              "message": "Failed password for alice"}]}]
    assert bakeoff.ours_flagged(incidents, session.manifest) == {line.line_number}


def test_our_incidents_ignore_unknown_and_unparseable_events():
    session, _ = make_session()
    session.emit(attack_event(datetime(2026, 1, 1, 0, 0, 1), "Failed password for alice"))
    incidents = [{"events": [
        {"timestamp": "2026-01-01 00:00:01", "message": "a line nobody wrote"},
        {"timestamp": "", "message": "Failed password for alice"},
        {"timestamp": "not a timestamp", "message": "Failed password for alice"},
    ]}]
    assert bakeoff.ours_flagged(incidents, session.manifest) == set()


# --- restamping -----------------------------------------------------------

def test_restamp_preserves_spacing_at_compress_one():
    base = datetime(2026, 1, 1)
    events = [attack_event(base, "a"), attack_event(base + timedelta(seconds=30), "b")]
    start = datetime(2026, 8, 30, 12, 0, 0)
    moved = bakeoff.restamp(events, start)
    assert moved[0]["ts"] == start
    assert (moved[1]["ts"] - moved[0]["ts"]).total_seconds() == 30


def test_restamp_compresses_gaps():
    base = datetime(2026, 1, 1)
    events = [attack_event(base, "a"), attack_event(base + timedelta(minutes=60), "b")]
    moved = bakeoff.restamp(events, datetime(2026, 8, 30), compress=60.0)
    assert (moved[1]["ts"] - moved[0]["ts"]).total_seconds() == 60


def test_restamp_of_nothing_is_nothing():
    assert bakeoff.restamp([], datetime(2026, 8, 30)) == []


# --- the grid -------------------------------------------------------------

def test_unknown_grid_cells_are_refused():
    with pytest.raises(ValueError):
        bakeoff.build_attack("ransomware", "none", 1)
    with pytest.raises(ValueError):
        bakeoff.build_attack("brute_force", "invisible", 1)


def test_brute_force_clears_wazuhs_threshold():
    """Wazuh rule 5763 needs 8 failures in 120s. An attack below that would
    judge the ruleset on something it was never built to see."""
    events = bakeoff.build_attack("brute_force", "none", 1)
    failures = [e for e in events if e["message"].startswith("Failed password")]
    assert len(failures) >= 8


def test_rephrase_changes_the_wording_and_ip_rotate_changes_the_source():
    plain = bakeoff.build_attack("enumeration", "none", 7)
    reworded = bakeoff.build_attack("enumeration", "rephrase", 7)
    assert not any(e["message"].startswith("Failed password") for e in reworded)
    assert any(e["message"].startswith("Failed password") for e in plain)

    rotated = bakeoff.build_attack("enumeration", "ip_rotate", 7)
    ips = set()
    for event in rotated:
        found = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", event["message"])
        if found:
            ips.add(found.group())
    assert len(ips) > 1


def test_every_attack_produces_labelled_events():
    for attack in bakeoff.ATTACKS:
        events = bakeoff.build_attack(attack, "none", 3)
        assert events
        assert all(e["scenario"] == bakeoff.ATTACKS[attack] for e in events)


# --- scoring a condition --------------------------------------------------

def perfect_readers(session: bakeoff.Session) -> bakeoff.Readers:
    """A detector that flags every attack line, and a Wazuh that flags none."""

    def incidents():
        return [{"events": [
            {"timestamp": line.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
             "message": line.message}
            for line in session.manifest.lines if line.scenario]}]

    return bakeoff.Readers(incidents=incidents,
                           wazuh_mark=lambda: 0,
                           wazuh_since=lambda mark: [])


def test_a_condition_is_scored_against_its_own_lines_only():
    """The manifest grows across conditions because line numbers are positions
    in one stream; the second condition must not inherit the first's ground
    truth, or every later cell would score against a growing corpus."""
    session, _ = make_session()
    readers = perfect_readers(session)

    first = bakeoff.run_condition(session, "brute_force", "none", 1, readers, settle=0)
    second = bakeoff.run_condition(session, "enumeration", "none", 1, readers, settle=0)

    assert first["ours"]["overall"]["attack_lines"] < len(session.manifest)
    assert set(second["ours"]["per_scenario"]) == {"C"}
    assert second["ours"]["overall"]["instance_detection_rate"] == 1.0


def test_a_blind_detector_scores_zero():
    session, _ = make_session()
    readers = bakeoff.Readers(incidents=lambda: [])
    result = bakeoff.run_condition(session, "brute_force", "none", 1, readers, settle=0)
    assert result["ours"]["overall"]["instance_detection_rate"] == 0.0
    assert result["wazuh"]["overall"]["instance_detection_rate"] == 0.0


def test_repeat_fires_distinct_instances():
    session, _ = make_session()
    readers = perfect_readers(session)
    result = bakeoff.run_condition(session, "brute_force", "none", 1, readers,
                                   repeat=3, settle=0)
    assert result["ours"]["per_scenario"]["A"]["instances"] == 3


def test_background_traffic_is_written_during_a_firing():
    session, sinks = make_session()
    session.clock = _fixed_clock()
    events = [attack_event(datetime(2026, 1, 1), "a"),
              attack_event(datetime(2026, 1, 1, 0, 0, 10), "b")]
    session.fire(events, benign_rate=1.0)
    assert len(sinks[0].lines) > 2      # two attack lines plus background


def _fixed_clock():
    """A clock that advances only when the code asks what time it is, so a
    scheduled firing runs instantly without changing the ordering logic."""
    state = {"now": datetime(2026, 8, 30, 12, 0, 0)}

    def now():
        current = state["now"]
        state["now"] += timedelta(seconds=1)
        return current

    return now


# --- what may be called a measurement -------------------------------------

def test_time_compression_marks_a_run_as_illustration():
    session, _ = make_session()
    readers = perfect_readers(session)
    result = bakeoff.run_condition(session, "brute_force", "none", 1, readers,
                                   compress=60.0, settle=0)
    assert result["measured"] is False


def test_timing_based_camouflage_is_never_a_measurement():
    """Wazuh correlates on arrival time, so its drop under `slow` is fixed by
    the harness. Reporting that as a result would be the instrument talking."""
    session, _ = make_session()
    readers = perfect_readers(session)
    result = bakeoff.run_condition(session, "brute_force", "slow", 1, readers,
                                   compress=1.0, settle=0)
    assert result["measured"] is False
    assert bakeoff.TIMING_DEPENDENT == {"slow", "temporal", "realistic-combo"}


def test_real_time_timing_independent_runs_are_measurements():
    session, _ = make_session()
    readers = perfect_readers(session)
    result = bakeoff.run_condition(session, "brute_force", "rephrase", 1, readers,
                                   settle=0)
    assert result["measured"] is True


def test_no_differential_is_computed_from_an_unmeasured_run():
    baseline = {"measured": True, "ours": _score(1.0), "wazuh": _score(1.0)}
    illustration = {"measured": False, "ours": _score(0.0), "wazuh": _score(0.0)}
    assert bakeoff.differential_vs_baseline(baseline, illustration) is None
    assert bakeoff.differential_vs_baseline(illustration, baseline) is None


def test_differential_is_the_gap_between_the_two_drops():
    baseline = {"measured": True, "ours": _score(1.0), "wazuh": _score(1.0)}
    condition = {"measured": True, "ours": _score(1.0), "wazuh": _score(0.0)}
    assert bakeoff.differential_vs_baseline(baseline, condition) == 100.0


def _score(rate: float) -> dict:
    return {"overall": {"instance_detection_rate": rate}}


def test_report_marks_illustration_rows_and_cites_the_measured_source():
    results = [
        {"attack": "brute_force", "level": "none", "measured": True,
         "ours": _volume(1.0, 3), "wazuh": _volume(1.0, 9)},
        {"attack": "brute_force", "level": "slow", "measured": False,
         "ours": _volume(0.0, 1), "wazuh": _volume(1.0, 9)},
    ]
    report = bakeoff.render_report(results)
    assert "illustration" in report
    assert "killpoint_paced_ambient0.05.md" in report
    assert "`slow`" in report


def _volume(rate: float, alerts: int, line_rate: float | None = None) -> dict:
    return {"overall": {"instance_detection_rate": rate, "alerts": alerts,
                        "line_detection_rate": rate if line_rate is None else line_rate}}


def test_report_shows_the_line_rate_beside_the_instance_rate():
    """One live instance reads 0% or 100% and nothing between, so the table has
    to carry the finer number or it hides what the firing actually showed."""
    results = [
        {"attack": "brute_force", "level": "none", "measured": True,
         "ours": _volume(1.0, 36, line_rate=1.0), "wazuh": _volume(1.0, 54, line_rate=0.923)},
        {"attack": "brute_force", "level": "rephrase", "measured": True,
         "ours": _volume(1.0, 66, line_rate=1.0), "wazuh": _volume(1.0, 37, line_rate=0.269)},
    ]
    report = bakeoff.render_report(results)
    assert "92%" in report and "27%" in report
    assert "saturates" in report


# --- the scorer is the kill point's, not a second opinion ------------------

def test_conditions_are_scored_by_the_shared_scorer():
    """Two scorers would turn the live differential into an artefact of this
    module. The schema `run_condition` emits has to be the one section 1b's
    scoring produces."""
    session, _ = make_session()
    result = bakeoff.run_condition(session, "brute_force", "none", 1,
                                   perfect_readers(session), settle=0)
    for system in ("ours", "wazuh"):
        assert set(result[system]) == {"overall", "per_scenario"}
        assert "instance_detection_rate" in result[system]["overall"]


# --- reading our side over HTTP -------------------------------------------

class PagingClient:
    """Stands in for the service. `GET /incidents` caps a page at 10000, and a
    run long enough to exceed that would otherwise score its own tail as
    undetected."""

    def __init__(self, total: int):
        self.all = [{"incident_id": i, "events": []} for i in range(total)]
        self.calls = 0

    def incidents(self, limit: int, offset: int = 0) -> list[dict]:
        """Returns a list, like `ApiClient.incidents` does. The first version of
        this stub returned the service's raw payload dict instead, which is a
        different shape -- so the test passed and the live run crashed."""
        self.calls += 1
        assert limit <= 10000, "the service refuses a larger page"
        return self.all[offset:offset + limit]


def test_incidents_are_paged_not_asked_for_all_at_once():
    client = PagingClient(total=25)
    assert len(bakeoff.all_incidents(client, page_size=10)) == 25
    assert client.calls == 3          # 10, 10, 5


def test_a_single_short_page_ends_the_walk():
    client = PagingClient(total=3)
    assert len(bakeoff.all_incidents(client, page_size=10)) == 3
    assert client.calls == 1
