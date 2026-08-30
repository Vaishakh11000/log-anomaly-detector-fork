"""
Demo replay: the schedule it computes, and the file it writes.

Timing is asserted against injected clock/sleep rather than by waiting, so the
whole suite runs instantly and still pins the property that matters -- the
replay targets absolute times, so a slow write does not push every later line
further behind.
"""

from datetime import datetime

import pytest

from logdet.replay import (
    DEFAULT_MAX_GAP,
    Paced,
    pace_schedule,
    replay,
    restamp_line,
)


def line(ts: str, message: str = "sshd[1]: Failed password for root from 1.2.3.4") -> str:
    return f"{ts} host {message}"


# --- schedule ---------------------------------------------------------------


def test_gaps_come_from_the_logs_own_timestamps():
    schedule = pace_schedule([line("Aug  3 10:00:00"),
                              line("Aug  3 10:00:10"),
                              line("Aug  3 10:00:40")], speed=1.0, max_gap=100)
    assert [p.delay for p in schedule] == [0.0, 10.0, 30.0]


def test_speed_divides_every_gap():
    schedule = pace_schedule([line("Aug  3 10:00:00"), line("Aug  3 10:01:00")],
                             speed=60.0, max_gap=100)
    assert schedule[1].delay == pytest.approx(1.0)


def test_long_silences_are_clamped_and_reported():
    """A real log contains hours of nothing. Clamping is what makes a replay
    watchable, and marking it is what keeps the report honest about the
    replay no longer being a faithful time-scaling."""
    schedule = pace_schedule([line("Aug  3 10:00:00"), line("Aug  3 12:00:00")],
                             speed=60.0, max_gap=DEFAULT_MAX_GAP)
    assert schedule[1].delay == DEFAULT_MAX_GAP
    assert schedule[1].clamped is True
    assert schedule[0].clamped is False


def test_a_timestamp_going_backwards_does_not_wind_the_clock_back():
    schedule = pace_schedule([line("Aug  3 10:00:10"), line("Aug  3 10:00:00")],
                             speed=1.0, max_gap=100)
    assert schedule[1].delay == 0.0


def test_unparseable_lines_ride_along_with_zero_delay():
    """A line the parser does not recognise still has to be replayed -- it is
    part of the traffic the detector sees -- but it has no clock of its own to
    be scheduled by."""
    schedule = pace_schedule([line("Aug  3 10:00:00"),
                              "not a syslog line at all",
                              line("Aug  3 10:00:05")], speed=1.0, max_gap=100)
    assert [p.delay for p in schedule] == [0.0, 0.0, 5.0]
    assert schedule[1].line == "not a syslog line at all"


def test_blank_lines_are_dropped():
    schedule = pace_schedule([line("Aug  3 10:00:00"), "\n", "   \n"])
    assert len(schedule) == 1


def test_year_rollover_does_not_produce_a_year_long_gap():
    """The OpenSSH corpus runs Dec -> Jan. Without the parser's rollover state
    the January line reads as eleven months *earlier*, which clamps to zero and
    silently drops every remaining gap in the corpus."""
    schedule = pace_schedule([line("Dec 31 23:59:50"), line("Jan  1 00:00:00")],
                             speed=1.0, max_gap=100)
    assert schedule[1].delay == pytest.approx(10.0)


def test_speed_must_be_positive():
    with pytest.raises(ValueError):
        pace_schedule([line("Aug  3 10:00:00")], speed=0)


# --- restamping -------------------------------------------------------------


def test_restamp_rewrites_only_the_leading_timestamp():
    original = line("Aug  3 10:00:00")
    out = restamp_line(original, datetime(2026, 12, 25, 7, 8, 9))
    assert out.startswith("Dec 25 07:08:09 host ")
    assert out.endswith("Failed password for root from 1.2.3.4")


def test_restamp_pads_a_single_digit_day_like_syslog():
    out = restamp_line(line("Aug  3 10:00:00"), datetime(2026, 12, 5, 1, 2, 3))
    assert out.startswith("Dec  5 01:02:03")


def test_restamp_leaves_a_line_with_no_timestamp_alone():
    """Prefixing a timestamp onto a line that had none would manufacture a log
    line that never existed."""
    assert restamp_line("garbage", datetime(2026, 1, 1)) == "garbage"


# --- writing ----------------------------------------------------------------


class FakeClock:
    """A clock that only moves when something sleeps."""

    def __init__(self):
        self.t = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds

    def work(self, seconds: float) -> None:
        self.t += seconds


def test_replay_writes_every_line_in_order(tmp_path):
    out = tmp_path / "live.log"
    clock = FakeClock()
    schedule = pace_schedule([line("Aug  3 10:00:00"), line("Aug  3 10:00:01")],
                             speed=1.0)
    summary = replay(schedule, out, sleep=clock.sleep, clock=clock)

    assert out.read_text().splitlines() == [p.line for p in schedule]
    assert summary["lines"] == 2
    assert summary["scheduled_seconds"] == pytest.approx(1.0)


def test_replay_appends_by_default_and_truncates_on_request(tmp_path):
    """Appending is the default because the tailer resumes from a byte offset:
    truncating under a running stream leaves the offset past the end of file."""
    out = tmp_path / "live.log"
    out.write_text("existing\n")
    clock = FakeClock()
    schedule = [Paced(delay=0.0, line="new")]

    replay(schedule, out, sleep=clock.sleep, clock=clock)
    assert out.read_text() == "existing\nnew\n"

    replay(schedule, out, truncate=True, sleep=clock.sleep, clock=clock)
    assert out.read_text() == "new\n"


def test_replay_creates_the_output_directory(tmp_path):
    out = tmp_path / "nested" / "dir" / "live.log"
    clock = FakeClock()
    replay([Paced(delay=0.0, line="x")], out, sleep=clock.sleep, clock=clock)
    assert out.exists()


def test_timing_targets_absolute_times_so_slow_writes_do_not_accumulate(tmp_path):
    """Sleeping `delay` between writes adds the cost of every write to the
    schedule, so a long replay drifts minutes behind itself. Targeting absolute
    times absorbs the cost instead."""
    out = tmp_path / "live.log"
    clock = FakeClock()

    def slow_write(count, line):
        clock.work(0.4)          # each write takes 0.4s of wall clock

    schedule = [Paced(delay=0.0, line="a"), Paced(delay=1.0, line="b"),
                Paced(delay=1.0, line="c")]
    replay(schedule, out, sleep=clock.sleep, clock=clock, on_line=slow_write)

    # Naive per-line sleeping would wait the full 1.0s twice and finish 0.8s
    # late. Absolute targets subtract the write cost instead.
    assert clock.slept == [pytest.approx(0.6), pytest.approx(0.6)]
    # Last line written at its scheduled 2.0s, plus its own 0.4s of writing.
    assert clock.t == pytest.approx(2.4)


def test_a_line_already_overdue_is_not_slept_on(tmp_path):
    out = tmp_path / "live.log"
    clock = FakeClock()

    def very_slow(count, line):
        clock.work(10.0)

    replay([Paced(delay=0.0, line="a"), Paced(delay=1.0, line="b")], out,
           sleep=clock.sleep, clock=clock, on_line=very_slow)
    assert clock.slept == []


def test_restamp_is_applied_to_the_written_file(tmp_path):
    out = tmp_path / "live.log"
    clock = FakeClock()
    replay([Paced(delay=0.0, line=line("Aug  3 10:00:00"))], out,
           sleep=clock.sleep, clock=clock, restamp=True,
           now=lambda: datetime(2026, 12, 25, 7, 8, 9))
    assert out.read_text().startswith("Dec 25 07:08:09 host ")
