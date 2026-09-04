"""Tests for the two-box live bake-off scorer (logdet_eval/live_bakeoff.py).

All stubbed: no ssh, no Wazuh container, no running service. The scoring path
is exercised by rebuilding a manifest from a temp collector file and feeding
fake incidents / Wazuh alerts, exactly as bakeoff.Readers lets the single-box
path be tested without a service.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from logdet_eval import live_bakeoff as lb


YEAR = 2026


def _line(ts: str, msg: str) -> str:
    return f"{ts} kali sshd[123]: {msg}"


# Three attack lines (one brute-force instance) plus two benign lines.
ATTACK_LINES = [
    _line("Sep  4 23:29:49", "Failed password for root from 127.0.0.1 port 4444 ssh2"),
    _line("Sep  4 23:29:50", "Failed password for root from 127.0.0.1 port 4445 ssh2"),
    _line("Sep  4 23:29:51", "Failed password for root from 127.0.0.1 port 4446 ssh2"),
]
BENIGN_LINES = [
    _line("Sep  4 23:29:40", "Accepted password for alice from 10.0.0.5 port 2200 ssh2"),
    _line("Sep  4 23:29:41", "pam_unix(sshd:session): session opened for user alice"),
]


def _write_collector(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "collector.log"
    path.write_text("\n".join(lines) + "\n")
    return path


def test_ground_truth_offset_shift():
    gt = lb.GroundTruth()
    gt.add_fire([{"line_number": 1, "scenario": "A", "instance": 1, "user": "root"}], offset=0)
    gt.add_fire([{"line_number": 1, "scenario": "A", "instance": 2, "user": "root"}], offset=95)
    assert set(gt.by_line) == {1, 96}
    assert gt.by_line[96]["instance"] == 2


def test_build_manifest_numbers_and_labels(tmp_path):
    # benign, benign, attack, attack, attack  ->  attack lines are 3,4,5
    path = _write_collector(tmp_path, BENIGN_LINES + ATTACK_LINES)
    gt = lb.GroundTruth()
    gt.add_fire([{"line_number": i, "scenario": "A", "instance": 1, "user": "root"}
                 for i in (3, 4, 5)], offset=0)
    manifest = lb.build_manifest(path, gt, year=YEAR)
    assert len(manifest) == 5
    truth = manifest.ground_truth()
    assert sorted(truth["line_number"]) == [3, 4, 5]
    assert set(truth["scenario"]) == {"A"}


def test_score_live_detector_catches_wazuh_misses(tmp_path):
    path = _write_collector(tmp_path, BENIGN_LINES + ATTACK_LINES)
    gt = lb.GroundTruth()
    gt.add_fire([{"line_number": i, "scenario": "A", "instance": 1, "user": "root"}
                 for i in (3, 4, 5)], offset=0)

    # Detector flags all three attack lines (events carry parsed message + ts).
    incidents = [{"events": [
        {"timestamp": "2026-09-04 23:29:49",
         "message": "Failed password for root from 127.0.0.1 port 4444 ssh2"},
        {"timestamp": "2026-09-04 23:29:50",
         "message": "Failed password for root from 127.0.0.1 port 4445 ssh2"},
        {"timestamp": "2026-09-04 23:29:51",
         "message": "Failed password for root from 127.0.0.1 port 4446 ssh2"},
    ]}]
    # Wazuh raises no alert at or above the primary level.
    alerts: list[dict] = []

    result = lb.score_live(path, gt, incidents, alerts, year=YEAR)
    assert result["lines"] == 5
    assert result["ours"]["overall"]["instance_detection_rate"] == 1.0
    assert result["ours"]["overall"]["lines_detected"] == 3
    assert result["wazuh"]["overall"]["instance_detection_rate"] == 0.0


def test_score_live_wazuh_by_full_log(tmp_path):
    path = _write_collector(tmp_path, ATTACK_LINES)
    gt = lb.GroundTruth()
    gt.add_fire([{"line_number": i, "scenario": "A", "instance": 1, "user": "root"}
                 for i in (1, 2, 3)], offset=0)
    alerts = [{"rule": {"level": 10}, "full_log": ATTACK_LINES[0]}]
    result = lb.score_live(path, gt, [], alerts, year=YEAR)
    # One of the three attack lines matched -> instance detected, 1 line.
    assert result["wazuh"]["overall"]["instances_detected"] == 1
    assert result["wazuh"]["overall"]["lines_detected"] == 1
    assert result["wazuh_alerts"] == 1


def test_score_live_below_primary_level_ignored(tmp_path):
    path = _write_collector(tmp_path, ATTACK_LINES)
    gt = lb.GroundTruth()
    gt.add_fire([{"line_number": 1, "scenario": "A", "instance": 1, "user": "root"}],
                offset=0)
    alerts = [{"rule": {"level": 1}, "full_log": ATTACK_LINES[0]}]
    result = lb.score_live(path, gt, [], alerts, year=YEAR)
    assert result["wazuh"]["overall"]["lines_detected"] == 0


def test_collector_line_count_ignores_blanks(tmp_path):
    path = tmp_path / "c.log"
    path.write_text("a\n\nb\n  \nc\n")
    assert lb.collector_line_count(path) == 3


def test_wazuh_mirror_complete_lines_only(tmp_path):
    path = tmp_path / "collector.log"
    path.write_text("one\ntwo\npar")  # trailing partial line, no newline
    sink = bakeoff_list_sink()
    mirror = lb.WazuhMirror(path, sink)
    assert mirror.catch_up() == 2
    assert sink.lines == ["one", "two"]
    # partial completes and a new line arrives
    with path.open("a") as handle:
        handle.write("tial\nthree\n")
    assert mirror.catch_up() == 2
    assert sink.lines == ["one", "two", "partial", "three"]
    assert mirror.mirrored == 4


def test_wait_stable_returns_when_growth_stops(tmp_path):
    path = tmp_path / "c.log"
    path.write_text("a\nb\n")
    count = lb.wait_stable(path, settle=0.3, poll=0.1, timeout=5)
    assert count == 2


def test_run_live_end_to_end_stubbed(tmp_path):
    path = tmp_path / "collector.log"
    path.write_text("")
    sink = bakeoff_list_sink()

    def fire(cell):
        # Simulate Kali shipping this instance's lines into the collector file.
        with path.open("a") as handle:
            for line in ATTACK_LINES:
                handle.write(line + "\n")
        return [{"line_number": i, "scenario": "A", "instance": cell["instance"],
                 "user": "root"} for i in (1, 2, 3)]

    def incidents():
        return [{"events": [{"timestamp": "2026-09-04 23:29:49",
                             "message": "Failed password for root from 127.0.0.1 "
                                        "port 4444 ssh2"}]}]

    result = lb.run_live(
        [{"attack": "brute_force", "level": "none", "instance": 1}],
        fire, incidents, wazuh_mark=lambda: 0, wazuh_since=lambda m: [],
        collector_path=path, sink=sink, reset=None, settle=0.3, year=YEAR)

    assert result["lines"] == 3
    assert result["ours"]["overall"]["instances_detected"] == 1
    # The mirror fed Wazuh every line the collector received.
    assert result["mirrored"] == 3
    assert sink.lines == ATTACK_LINES


def test_kali_firer_command_shape():
    firer = lb.KaliFirer("kali", "http://10.10.10.2:8000/", year=2026, attempts=15)
    bf = firer._remote_command({"attack": "brute_force", "level": "none", "instance": 1})
    assert "attack_runner.cli brute_force" in bf
    assert "--peer http://10.10.10.2:8000" in bf
    assert "--source-ip 127.0.0.1" in bf
    assert "--attempts 15" in bf
    assert "--camouflage" not in bf

    enum = firer._remote_command({"attack": "enumeration", "level": "rephrase", "instance": 2})
    # enumeration binds a distinct loopback source per instance
    assert "--source-ip 127.0.0.12" in enum
    assert "--camouflage rephrase" in enum
    assert "--users" in enum


def bakeoff_list_sink():
    class _Sink:
        def __init__(self):
            self.lines = []

        def write(self, text):
            self.lines.append(text)

        def close(self):
            pass

    return _Sink()
