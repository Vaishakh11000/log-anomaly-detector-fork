"""
The rule baseline -- what the detector is measured against.

These tests exist to keep the comparison honest in both directions: the rules
must actually fire on the attacks they target (no strawman), and they must not
quietly acquire the pipeline's impossible-travel rule (no double-counting).
"""

import pandas as pd

from logdet_eval.config import (
    BASELINE_BRUTE_FORCE_MIN_FAILURES,
    BASELINE_ENUMERATION_MIN_USERS,
)
from logdet_eval.baseline_rules import (
    detect,
    per_rule_counts,
    rule_brute_force,
    rule_enumeration,
    rule_privileged_command,
)

BASE = pd.Timestamp("2026-07-18 02:00:00")


def frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def failures(user: str, ip: str, n: int, start=BASE, step_seconds=3) -> list[dict]:
    return [
        {"timestamp": start + pd.Timedelta(seconds=i * step_seconds), "user": user,
         "source_ip": ip, "message": f"Failed password for {user} from {ip} port 5100 ssh2"}
        for i in range(n)
    ]


def test_brute_force_fires_at_the_threshold():
    df = frame(failures("alice", "203.0.113.9", BASELINE_BRUTE_FORCE_MIN_FAILURES))
    assert len(rule_brute_force(df)) == BASELINE_BRUTE_FORCE_MIN_FAILURES


def test_brute_force_stays_quiet_below_the_threshold():
    df = frame(failures("alice", "203.0.113.9", BASELINE_BRUTE_FORCE_MIN_FAILURES - 1))
    assert rule_brute_force(df) == set()


def test_brute_force_claims_the_success_that_follows_the_burst():
    """The classic 'brute force succeeded' alert -- the compromise line is the
    one an analyst actually needs."""
    rows = failures("alice", "203.0.113.9", BASELINE_BRUTE_FORCE_MIN_FAILURES)
    rows.append({"timestamp": BASE + pd.Timedelta(seconds=20), "user": "alice",
                 "source_ip": "203.0.113.9",
                 "message": "Accepted password for alice from 203.0.113.9 port 5100 ssh2"})
    df = frame(rows)
    assert len(df) - 1 in rule_brute_force(df)


def test_slow_failures_defeat_the_frequency_window():
    """Not a bug -- this is the mechanism the adversarial 'slow' strategy
    exploits, and the reason a frequency-threshold baseline collapses under it.
    Pinned so a later widening of the window is a visible decision."""
    df = frame(failures("alice", "203.0.113.9", 5, step_seconds=60 * 60))
    assert rule_brute_force(df) == set()


def test_enumeration_fires_on_distinct_usernames_from_one_ip():
    rows = []
    for i in range(BASELINE_ENUMERATION_MIN_USERS):
        rows += failures(f"user{i}", "203.0.113.7", 1, start=BASE + pd.Timedelta(seconds=i * 10))
    assert len(rule_enumeration(frame(rows))) == BASELINE_ENUMERATION_MIN_USERS


def test_repeated_failures_for_one_user_are_not_enumeration():
    df = frame(failures("alice", "203.0.113.7", BASELINE_ENUMERATION_MIN_USERS + 2))
    assert rule_enumeration(df) == set()


def test_privileged_command_keywords():
    df = frame([
        {"timestamp": BASE, "user": "alice", "source_ip": None,
         "message": "sudo: alice : TTY=pts/0 ; COMMAND=/bin/su root"},
        {"timestamp": BASE, "user": "root", "source_ip": None,
         "message": "useradd[9001]: new user: name=backdoor"},
        {"timestamp": BASE, "user": "root", "source_ip": None,
         "message": "CRON[8124]: (root) CMD (run-parts /etc/cron.hourly)"},
    ])
    assert rule_privileged_command(df) == {0, 1}


def test_benign_traffic_stays_clean():
    """A baseline that alerts on ordinary traffic would flatter the detector
    for the wrong reason."""
    df = frame([
        {"timestamp": BASE + pd.Timedelta(minutes=i * 30), "user": "alice",
         "source_ip": "10.0.0.5",
         "message": "Accepted password for alice from 10.0.0.5 port 5100 ssh2"}
        for i in range(6)
    ])
    assert not detect(df)["is_anomaly"].any()


def test_the_baseline_does_not_include_impossible_travel():
    """Deliberately excluded: that rule is shared with the production detector,
    so including it here would double-count it instead of comparing rules
    against embeddings."""
    df = frame([
        {"timestamp": BASE, "user": "alice", "source_ip": "10.0.0.5",
         "message": "Accepted password for alice from 10.0.0.5 port 5100 ssh2"},
        {"timestamp": BASE + pd.Timedelta(minutes=20), "user": "alice", "source_ip": "203.0.113.9",
         "message": "Accepted password for alice from 203.0.113.9 port 5100 ssh2"},
    ])
    assert not detect(df)["is_anomaly"].any()


def test_detect_records_which_rule_fired():
    rows = failures("alice", "203.0.113.9", BASELINE_BRUTE_FORCE_MIN_FAILURES)
    rows.append({"timestamp": BASE + pd.Timedelta(seconds=30), "user": "alice",
                 "source_ip": None, "message": "sudo: alice : COMMAND=/bin/su root"})
    result = detect(frame(rows))

    assert result["rules_fired"].iloc[0] == "brute_force"
    assert result["rules_fired"].iloc[-1] == "privileged_command"
    counts = per_rule_counts(result)
    assert counts["brute_force"] == BASELINE_BRUTE_FORCE_MIN_FAILURES
    assert counts["privileged_command"] == 1
    assert counts["enumeration"] == 0
