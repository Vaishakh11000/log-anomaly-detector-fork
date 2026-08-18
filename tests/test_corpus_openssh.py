"""
The kill-point corpus builder.

The measurement in CLAUDE.md §1b rests on this file being honest about what is
real and what is injected, so the classification and background-construction
rules are pinned here. Fixtures are tiny and in-memory: the real 655k-line
corpus is a 73MB download and these are unit tests.
"""

from datetime import datetime, timedelta

import pytest

from logdet_eval.corpus_openssh import (
    build_background,
    classify,
    home_subnets,
    real_users,
)


BASE = datetime(2015, 12, 10, 9, 0, 0)


def at(seconds: int) -> str:
    """Timestamp `seconds` after the fixture epoch, as an ISO string."""
    return (BASE + timedelta(seconds=seconds)).isoformat()


def event(ts: str, message: str) -> dict:
    return {"ts": datetime.fromisoformat(ts), "process": "sshd", "pid": "1",
            "message": message, "user": None, "scenario": None,
            "instance": None, "description": None}


BENIGN = [
    event("2015-12-10T09:00:00", "Accepted password for curi from 137.189.241.9 port 22 ssh2"),
    event("2015-12-10T09:00:01", "pam_unix(sshd:session): session opened for user curi by (uid=0)"),
    event("2015-12-10T17:00:00", "pam_unix(sshd:session): session closed for user curi"),
]


def test_failed_auth_lines_are_classified_as_attack_traffic():
    events = BENIGN + [
        event("2015-12-10T10:00:00", "Failed password for root from 59.63.188.30 port 5 ssh2"),
        event("2015-12-10T10:00:01", "Invalid user webmaster from 173.234.31.186"),
    ]
    benign, attacker = classify(events)
    assert len(benign) == 3
    assert len(attacker) == 2


def test_brute_force_byproducts_without_an_ip_are_not_treated_as_benign():
    """These two templates are 57,815 lines of the real corpus and carry no
    source IP, so IP-based filtering alone leaves them in and quietly fills the
    'benign' background with attack texture."""
    events = BENIGN + [
        event("2015-12-10T10:00:00", "PAM service(sshd) ignoring max retries; 6 > 5"),
        event("2015-12-10T10:00:01", "pam_unix(sshd:auth): check pass; user unknown"),
    ]
    benign, attacker = classify(events)
    assert len(attacker) == 2
    assert all("curi" in e["message"] for e in benign)


def test_an_ip_that_attacks_elsewhere_taints_its_other_lines():
    """A prolific attacker's non-failure lines are still attacker traffic."""
    attacks = [
        event(at(3600 + i),
              f"Failed password for root from 59.63.188.30 port {i} ssh2")
        for i in range(12)
    ]
    quiet = event("2015-12-10T11:00:00", "Connection closed by 59.63.188.30 [preauth]")
    benign, attacker = classify(BENIGN + attacks + [quiet])
    assert quiet in attacker
    assert len(benign) == 3


def test_real_users_come_from_successful_logins_only():
    events = BENIGN + [
        event("2015-12-10T10:00:00", "Failed password for root from 59.63.188.30 port 5 ssh2"),
    ]
    assert real_users(events) == ["curi"]


def test_home_subnets_are_derived_from_where_users_actually_log_in():
    """Scenario B's baseline leg must come from the account's genuine usual
    range, or the injected impossible travel is not travel from anywhere real."""
    events = BENIGN + [
        event("2015-12-11T09:00:00", "Accepted password for curi from 137.189.241.40 port 22 ssh2"),
        event("2015-12-12T09:00:00", "Accepted password for hxu from 111.222.107.90 port 22 ssh2"),
    ]
    subnets = home_subnets(events)
    assert subnets["curi"] == "137.189.241."
    assert subnets["hxu"] == "111.222.107."


def test_background_mixes_in_ambient_attacks_at_the_requested_ratio():
    benign = [event(at(i), "session closed for user curi")
              for i in range(100)]
    attacker = [event(at(3600 + i), "Failed password for root")
                for i in range(50)]
    background = build_background(benign, attacker, ambient_ratio=0.1, seed=1)

    assert len(background) == 110
    assert sum(1 for e in background if "Failed" in e["message"]) == 10


def test_background_is_chronological():
    """Everything downstream -- grouping windows, the travel check, SIEM
    frequency rules -- assumes the log reads forward in time."""
    benign = [event(at(i), "session closed for user curi")
              for i in range(20)]
    attacker = [event(at(-3600 + i), "Failed password for root")
                for i in range(20)]
    background = build_background(benign, attacker, ambient_ratio=0.5, seed=1)
    assert [e["ts"] for e in background] == sorted(e["ts"] for e in background)


def test_background_sampling_is_seed_reproducible():
    benign = [event(at(i), "session closed for user curi")
              for i in range(50)]
    attacker = [event(at(3600 + i), f"Failed password for root {i}")
                for i in range(50)]
    a = build_background(benign, attacker, 0.2, seed=7)
    b = build_background(benign, attacker, 0.2, seed=7)
    c = build_background(benign, attacker, 0.2, seed=8)
    assert [e["message"] for e in a] == [e["message"] for e in b]
    assert [e["message"] for e in a] != [e["message"] for e in c]
