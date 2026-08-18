"""
Syslog omits the year, so a log spanning New Year needs the rollover inferred.

Getting this wrong is silent and total: January sorts before December, so every
window-based computation downstream -- incident grouping, impossible travel, and
any SIEM frequency rule we compare against -- operates on scrambled time. The
real OpenSSH corpus spans Dec 10 to Jan 07, so this is load-bearing for the
kill-point measurement rather than a nicety.
"""

import pandas as pd

from logdet.preprocessing import preprocess_file


def write_log(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_december_to_january_increments_the_year(tmp_path):
    log = write_log(tmp_path / "roll.log", [
        "Dec 31 23:59:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
        "Jan 01 00:00:05 host sshd[2]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
    ])
    df = preprocess_file(log, str(tmp_path / "out.csv"), year=2015)

    assert df["timestamp"].iloc[0].year == 2015
    assert df["timestamp"].iloc[1].year == 2016
    assert df["timestamp"].is_monotonic_increasing


def test_ordinary_month_jitter_does_not_invent_a_year(tmp_path):
    """A small backwards step is out-of-order logging, not a new year. Treating
    it as a rollover would push a year of drift into the timeline."""
    log = write_log(tmp_path / "jitter.log", [
        "Mar 02 10:00:00 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
        "Feb 28 09:00:00 host sshd[2]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
    ])
    df = preprocess_file(log, str(tmp_path / "out.csv"), year=2015)
    assert set(df["timestamp"].dt.year) == {2015}


def test_rollover_can_be_switched_off(tmp_path):
    log = write_log(tmp_path / "roll.log", [
        "Dec 31 23:59:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
        "Jan 01 00:00:05 host sshd[2]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
    ])
    df = preprocess_file(log, str(tmp_path / "out.csv"), year=2015,
                         handle_year_rollover=False)
    assert set(df["timestamp"].dt.year) == {2015}


def test_single_month_corpora_are_unaffected(tmp_path):
    """The v1 synthetic corpus is one month; the feature must be a no-op there,
    which is what makes it safe to enable by default."""
    log = write_log(tmp_path / "july.log", [
        f"Jul {day:02d} 10:00:00 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2"
        for day in range(14, 20)
    ])
    df = preprocess_file(log, str(tmp_path / "out.csv"), year=2026)
    assert set(df["timestamp"].dt.year) == {2026}
    assert df["timestamp"].is_monotonic_increasing
