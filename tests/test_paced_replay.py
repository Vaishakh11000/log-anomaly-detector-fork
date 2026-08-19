"""
Tests for the paced-replay instrument.

This module decides whether three of the eight camouflage strategies can be
measured against Wazuh at all, and its correctness rests on two claims that are
easy to break silently in a refactor: that per-source-IP spacing is honoured up
to the clamp, and that relaxing global order is only sound when no unkeyed
frequency rule can fire. Both are asserted here.
"""

import pytest

from logdet_eval.paced_replay import (
    MIN_SPACING,
    RATE_CONSTRAINTS,
    Scheduled,
    flagged_lines,
    replay_duration,
    schedule,
    verify_order_relaxation_safe,
)


def line(ip: str, user: str = "root") -> str:
    return f"Jan  1 00:00:00 LabSZ sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


class TestSpacing:
    def test_min_spacing_clears_every_shipped_rate_limit(self):
        """The clamp must sit above timeframe/frequency for every sshd rule, or
        a clamped gap could still let a rule accumulate."""
        binding = max(timeframe / frequency
                      for frequency, timeframe in RATE_CONSTRAINTS.values())
        assert MIN_SPACING > binding

    def test_same_ip_gap_is_preserved_below_the_clamp(self):
        lines = [line("10.0.0.1") for _ in range(3)]
        stamps = [0.0, 20.0, 40.0]
        offsets = [s.offset for s in schedule(lines, stamps)]
        assert offsets == [0.0, 20.0, 40.0]

    def test_same_ip_gap_is_clamped_above_the_bound(self):
        """A three-hour real gap costs the clamp, not three hours -- the whole
        reason a 28-day corpus is replayable at all."""
        lines = [line("10.0.0.1") for _ in range(3)]
        stamps = [0.0, 10_800.0, 21_600.0]
        offsets = [s.offset for s in schedule(lines, stamps)]
        assert offsets == [0.0, MIN_SPACING, 2 * MIN_SPACING]

    def test_different_ips_do_not_delay_each_other(self):
        """Rules key on same_source_ip, so unrelated sources cost nothing."""
        lines = [line(f"10.0.0.{i}") for i in range(5)]
        stamps = [0.0, 3600.0, 7200.0, 10_800.0, 14_400.0]
        assert replay_duration(schedule(lines, stamps)) == 0.0

    def test_lines_without_an_ip_are_never_delayed(self):
        lines = ["Jan  1 00:00:00 LabSZ CRON[1]: (root) CMD (run-parts)"] * 4
        stamps = [0.0, 9999.0, 19_999.0, 29_999.0]
        assert replay_duration(schedule(lines, stamps)) == 0.0


class TestOrdering:
    def test_relaxed_order_is_never_slower_than_strict(self):
        lines = [line(f"10.0.0.{i % 4}") for i in range(24)]
        stamps = [float(i * 600) for i in range(24)]
        relaxed = replay_duration(schedule(lines, stamps))
        strict = replay_duration(schedule(lines, stamps, preserve_global_order=True))
        assert relaxed <= strict

    def test_strict_order_never_emits_a_line_before_its_predecessor(self):
        lines = [line(f"10.0.0.{i % 3}") for i in range(9)]
        stamps = [float(i * 500) for i in range(9)]
        items = schedule(lines, stamps, preserve_global_order=True)
        by_number = sorted(items, key=lambda s: s.line_number)
        offsets = [s.offset for s in by_number]
        assert offsets == sorted(offsets)

    def test_output_is_ordered_by_emission_time(self):
        lines = [line(f"10.0.0.{i % 3}") for i in range(9)]
        stamps = [float(i * 500) for i in range(9)]
        offsets = [s.offset for s in schedule(lines, stamps)]
        assert offsets == sorted(offsets)

    def test_line_numbers_survive_reordering(self):
        """Attribution is by line number, so relaxing order must not lose it."""
        lines = [line(f"10.0.0.{i % 3}") for i in range(9)]
        stamps = [float(i * 500) for i in range(9)]
        items = schedule(lines, stamps)
        assert sorted(s.line_number for s in items) == list(range(1, 10))


class TestOrderRelaxationSafety:
    def test_clean_corpus_reports_all_zero(self):
        lines = [line("10.0.0.1"), line("10.0.0.2")]
        assert verify_order_relaxation_safe(lines) == {"5705": 0, "5714": 0, "5719": 0}

    @pytest.mark.parametrize("text,rule", [
        ("Jan  1 00:00:00 LabSZ sshd[1]: Timeout before authentication for 10.0.0.1", "5705"),
        ("Jan  1 00:00:00 LabSZ sshd[1]: CRC-32 compensation attack detected", "5714"),
        ("Jan  1 00:00:00 LabSZ sshd[1]: User root not allowed because listed in DenyUsers", "5719"),
    ])
    def test_unkeyed_rule_triggers_are_detected(self, text, rule):
        """A corpus that can drive an unkeyed frequency rule must be flagged --
        otherwise the relaxed schedule would inflate that rule's rate and hand
        Wazuh detections it did not earn."""
        assert verify_order_relaxation_safe([text])[rule] > 0


class TestAttribution:
    def _alert(self, text: str, level: int = 10, rule_id: str = "5712") -> dict:
        return {"rule": {"level": level, "id": rule_id}, "full_log": text}

    def test_alerts_map_back_to_line_numbers(self):
        items = [Scheduled(1, line("10.0.0.1", "alice"), 0.0),
                 Scheduled(2, line("10.0.0.2", "bob"), 0.0)]
        alerts = [self._alert(items[1].text)]
        assert flagged_lines(alerts, items, min_level=3) == {2}

    def test_alerts_below_the_level_are_ignored(self):
        items = [Scheduled(1, line("10.0.0.1"), 0.0)]
        alerts = [self._alert(items[0].text, level=3)]
        assert flagged_lines(alerts, items, min_level=7) == set()

    def test_repeated_identical_lines_are_consumed_in_order(self):
        """The corpus contains duplicate lines; two alerts on the same text must
        attribute to two different lines, not the same one twice."""
        text = line("10.0.0.1")
        items = [Scheduled(1, text, 0.0), Scheduled(2, text, 75.0)]
        alerts = [self._alert(text), self._alert(text)]
        assert flagged_lines(alerts, items, min_level=3) == {1, 2}

    def test_unknown_text_is_dropped_rather_than_misattributed(self):
        items = [Scheduled(1, line("10.0.0.1"), 0.0)]
        alerts = [self._alert("Jan  1 00:00:00 LabSZ sshd[1]: something else")]
        assert flagged_lines(alerts, items, min_level=3) == set()
