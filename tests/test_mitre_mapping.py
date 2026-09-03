"""
MITRE mapping -- the anti-hallucination contract.

The LLM never chooses technique IDs; it only writes prose about matches this
module hands it. That design is only worth anything if this module is itself
incapable of emitting an ID that isn't in its table.
"""

import pandas as pd
import pytest

from logdet.config import ENUMERATION_MIN_DISTINCT_USERS
from logdet.mitre_mapping import (
    MITRE_LOOKUP,
    kill_chain_of,
    SIGNAL_LOOKUP,
    detect_incident_signals,
    map_incident_to_mitre,
    map_to_mitre,
)

KNOWN_IDS = {e["technique_id"] for e in MITRE_LOOKUP} | {e["technique_id"] for e in SIGNAL_LOOKUP.values()}


def ids(entries: list[dict]) -> set[str]:
    return {e["technique_id"] for e in entries}


def test_failed_password_maps_to_brute_force():
    assert "T1110" in ids(map_to_mitre("Failed password for admin from 10.0.0.5 port 51422 ssh2"))


def test_sudo_maps_to_privilege_escalation():
    assert "T1548" in ids(map_to_mitre("sudo: alice : COMMAND=/bin/su root"))


def test_routine_cron_lines_stay_unmapped():
    """Regression: matching the bare word 'cron' tagged half the corpus as
    Persistence, because routine CRON lines are the most common benign message
    in these logs."""
    assert map_to_mitre("CRON[8124]: (root) CMD (run-parts /etc/cron.hourly)") == []


def test_an_ordinary_benign_line_maps_to_nothing():
    assert map_to_mitre("Server listening on 0.0.0.0 port 22.") == []


def test_every_emitted_id_comes_from_the_table():
    """The grounding invariant. If this fails, the narrative layer can be fed
    an ID that exists nowhere in the data."""
    messages = [
        "Failed password for admin from 10.0.0.5 port 51422 ssh2",
        "sudo: alice : COMMAND=/bin/su root",
        "useradd[9001]: new user: name=backdoor",
        "nmap scan detected from 10.0.0.9",
        "some entirely unremarkable line",
    ]
    for message in messages:
        assert ids(map_to_mitre(message)) <= KNOWN_IDS


def test_enumeration_signal_needs_enough_distinct_usernames():
    base = pd.Timestamp("2026-07-18 14:00:00")
    users = [f"user{i}" for i in range(ENUMERATION_MIN_DISTINCT_USERS)]
    df = pd.DataFrame([
        {"timestamp": base, "user": u, "source_ip": "203.0.113.7",
         "message": f"Failed password for {u} from 203.0.113.7"}
        for u in users
    ])
    assert "account_enumeration" in detect_incident_signals(df)
    assert "T1087" in ids(map_incident_to_mitre(df))

    too_few = df.iloc[: ENUMERATION_MIN_DISTINCT_USERS - 1]
    assert "account_enumeration" not in detect_incident_signals(too_few)


def test_impossible_travel_signal_is_incident_level_only():
    """No single log line reveals it -- it only exists across an incident."""
    df = pd.DataFrame([
        {"user": "alice", "source_ip": "10.0.0.5", "impossible_travel": False,
         "message": "Accepted password for alice from 10.0.0.5"},
        {"user": "alice", "source_ip": "203.0.113.9", "impossible_travel": True,
         "message": "Accepted password for alice from 203.0.113.9"},
    ])
    assert "T1021.004" in ids(map_incident_to_mitre(df))
    assert "T1021.004" not in ids(map_to_mitre(df["message"].iloc[1]))


def test_incident_techniques_are_deduplicated():
    df = pd.DataFrame([
        {"user": "alice", "source_ip": "10.0.0.5",
         "message": "Failed password for alice from 10.0.0.5"}
        for _ in range(5)
    ])
    techniques = map_incident_to_mitre(df)
    assert len(techniques) == len({t["technique_id"] for t in techniques})


def test_every_table_entry_is_well_formed():
    """The table is now keywords plus a join key -- names and tactics come from
    ATT&CK (see test_attack.py), so what is checked here is the authored half."""
    for entry in MITRE_LOOKUP:
        assert entry["technique_id"].startswith("T")
        assert entry["keywords"]
        assert all(kw == kw.lower() for kw in entry["keywords"]), "matching is case-folded"
        assert "technique_name" not in entry and "tactic" not in entry, (
            "hand-typed names and tactics are what the ATT&CK index replaced; "
            "re-adding one puts the author back in charge of what a technique is")


def test_described_techniques_carry_every_field_the_prompt_reads():
    """The narrative prompt reads these fields directly; a missing one becomes
    a 'nan' in an examiner-facing narrative."""
    for entry in map_to_mitre("Failed password for admin from 10.0.0.5 port 51422 ssh2"):
        assert entry["technique_name"] and entry["tactic"]
        assert entry["tactics"] and entry["tactic_ids"] and entry["kill_chain"]


def test_incident_techniques_are_ordered_by_kill_chain():
    """The technique list reads as a progression rather than by match order."""
    df = pd.DataFrame([
        {"user": "alice", "source_ip": "10.0.0.5", "impossible_travel": False,
         "message": "Failed password for alice from 10.0.0.5"},
        {"user": "alice", "source_ip": "10.0.0.5", "impossible_travel": False,
         "message": "Accepted password for alice from 10.0.0.5"},
    ])
    positions = [min(t["kill_chain"]) for t in map_incident_to_mitre(df)]
    assert positions == sorted(positions)
    # T1078 Valid Accounts (Initial Access) precedes T1110 Brute Force
    # (Credential Access) in the matrix, whatever order the lines arrived in.
    assert [t["technique_id"] for t in map_incident_to_mitre(df)] == ["T1078", "T1110"]


def test_kill_chain_of_orders_tactics_and_names_their_techniques():
    df = pd.DataFrame([
        {"user": "alice", "source_ip": "10.0.0.5", "impossible_travel": True,
         "message": "Accepted password for alice from 10.0.0.5"},
    ])
    chain = kill_chain_of(map_incident_to_mitre(df))
    assert [t["position"] for t in chain] == sorted(t["position"] for t in chain)
    assert all(t["tactic_id"].startswith("TA") for t in chain)
    lateral = [t for t in chain if t["tactic"] == "Lateral Movement"]
    assert lateral and lateral[0]["technique_ids"] == ["T1021.004"]


def test_a_signal_technique_keeps_its_authored_evidence_sentence():
    """ATT&CK describes the technique; the evidence line describes *our*
    detector, so it stays authored and must survive the STIX lookup."""
    df = pd.DataFrame([
        {"user": "alice", "source_ip": "10.0.0.5", "impossible_travel": True,
         "message": "Accepted password for alice from 10.0.0.5"},
    ])
    travel = [t for t in map_incident_to_mitre(df) if t["technique_id"] == "T1021.004"]
    assert travel and "geographically implausible" in travel[0]["evidence"]
