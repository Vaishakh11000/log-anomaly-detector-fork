"""
Injecting authentic captured attack lines into the real OpenSSH background.

`results/kali/notes.md` records why this path exists: a standalone Kali capture
gives the attacked account no benign baseline, so its 0%/33% instance detection
is a property of the corpus rather than of the detector. This module makes the
comparable measurement possible, and the properties pinned here are the ones
that would silently invalidate it -- attack lines arriving verbatim, spacing
preserved, ground truth renumbered against the combined file, and two capture
files' instances not collapsing into one.

Fixtures are written to tmp_path: the real background is a 73MB download and
these are unit tests.
"""

import csv
from datetime import datetime, timedelta

import pytest

from logdet_eval.corpus_captured import (
    CapturedInstance,
    load_capture,
    load_captures,
    parse_pairs,
    place,
)


CAPTURE_LINES = [
    "Sep 04 15:54:00 kali sshd[155771]: Server listening on 0.0.0.0 port 22.",
    "Sep 04 16:02:20 kali sshd-session[162084]: pam_unix(sshd:auth): authentication failure; "
    "logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1  user=root",
    "Sep 04 16:02:23 kali sshd-session[162084]: Failed password for root from 127.0.0.1 port 59010 ssh2",
    "Sep 04 16:02:25 kali sshd-session[162084]: Connection closed by authenticating user root "
    "127.0.0.1 port 59010 [preauth]",
]

GROUND_TRUTH = [
    {"line_number": "2", "timestamp": "2026-09-04T16:02:20", "user": "",
     "scenario": "A", "instance": "1", "description": ""},
    {"line_number": "3", "timestamp": "2026-09-04T16:02:23", "user": "root",
     "scenario": "A", "instance": "1", "description": ""},
    {"line_number": "4", "timestamp": "2026-09-04T16:02:25", "user": "",
     "scenario": "A", "instance": "1", "description": ""},
]


def write_capture(tmp_path, name="A_1", lines=None, rows=None):
    log_path = tmp_path / f"{name}.log"
    gt_path = tmp_path / f"{name}_gt.csv"
    log_path.write_text("\n".join(lines or CAPTURE_LINES) + "\n")
    with open(gt_path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(GROUND_TRUTH[0]))
        writer.writeheader()
        writer.writerows(rows or GROUND_TRUTH)
    return str(log_path), str(gt_path)


def test_only_labelled_lines_are_carried_over(tmp_path):
    """The rest of a capture is Kali's own background -- sshd banners, and
    earlier instances' lines, because each --auth-file run read the whole
    growing file. The real background replaces all of it."""
    captured, = load_capture(*write_capture(tmp_path))

    assert len(captured.lines) == 3
    messages = [line[3] for line in captured.lines]
    assert not any("Server listening" in message for message in messages)


def test_attack_lines_are_carried_verbatim(tmp_path):
    """The whole point of the authentic path is that the attack lines are what
    a real sshd wrote. A transform applied here would make them authored."""
    captured, = load_capture(*write_capture(tmp_path))

    _offset, process, pid, message, user = captured.lines[1]
    assert process == "sshd-session"
    assert pid == "162084"
    assert message == "Failed password for root from 127.0.0.1 port 59010 ssh2"
    assert user == "root"


def test_spacing_within_an_instance_is_preserved(tmp_path):
    """Re-stamping moves *when* an attack happened, never how fast it
    happened -- the real tool's pacing is part of what is being measured."""
    captured, = load_capture(*write_capture(tmp_path))

    assert [line[0] for line in captured.lines] == [
        timedelta(0), timedelta(seconds=3), timedelta(seconds=5)]

    placed = place(captured, datetime(2015, 12, 11), __import__("random").Random(1))
    gaps = [placed[i + 1]["ts"] - placed[i]["ts"] for i in range(len(placed) - 1)]
    assert gaps == [timedelta(seconds=3), timedelta(seconds=2)]


def test_the_year_comes_from_ground_truth_not_from_the_log(tmp_path):
    """Syslog omits the year, so parsing the capture with a default year would
    silently place every line in the wrong one."""
    captured, = load_capture(*write_capture(tmp_path))
    assert captured.lines  # the offsets are year-independent; the parse is not
    # A capture whose ground truth names a line the log does not have is a
    # mismatched pair, and scoring it would attribute the wrong lines.
    rows = [dict(GROUND_TRUTH[0], line_number="99")]
    with pytest.raises(ValueError):
        load_capture(*write_capture(tmp_path, name="bad", rows=rows))


def test_instances_from_separate_files_are_renumbered(tmp_path):
    """Each capture came from its own attack_runner invocation and numbers its
    instance independently, so two files both call themselves instance 1.
    Scoring groups by (scenario, instance), so leaving them would pool two
    instances into one and halve the denominator."""
    first = write_capture(tmp_path, name="A_1")
    second = write_capture(tmp_path, name="A_2")

    loaded = load_captures([first, second])

    assert [(c.scenario, c.instance) for c in loaded] == [("A", 1), ("A", 2)]


def test_placement_stays_inside_the_scenario_time_window(tmp_path):
    """Injection times are drawn from the same distribution the synthetic
    generators use, so neither arm gets easier placement."""
    import random

    captured, = load_capture(*write_capture(tmp_path))
    day = datetime(2015, 12, 11)
    for seed in range(50):
        placed = place(captured, day, random.Random(seed))
        assert 1 <= placed[0]["ts"].hour <= 5     # gen_scenario_a's window


def test_every_placed_line_carries_its_instance_label(tmp_path):
    captured, = load_capture(*write_capture(tmp_path))
    placed = place(captured, datetime(2015, 12, 11), __import__("random").Random(0))

    assert all(event["scenario"] == "A" and event["instance"] == 1 for event in placed)


def test_parse_pairs_rejects_a_path_without_its_ground_truth():
    assert parse_pairs(["a.log:a_gt.csv"]) == [("a.log", "a_gt.csv")]
    with pytest.raises(ValueError):
        parse_pairs(["a.log"])


def test_empty_captures_are_refused():
    from logdet_eval.corpus_captured import build_captured_corpus

    with pytest.raises(ValueError):
        build_captured_corpus([])


def test_span_of_an_instance_with_no_lines_is_zero():
    assert CapturedInstance("A", 1).span == timedelta()
