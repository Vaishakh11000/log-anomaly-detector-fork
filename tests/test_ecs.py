"""
ECS mapping is a faithful, lossless-at-the-boundary projection.

The point of these tests is that ECS is an *edge* format: the internal columns
are unchanged, and mapping out and back does not lose an identity the pipeline
keys on. Nothing here touches detection -- ecs.py adds a module and reads no
detection code -- so there is no benchmark number for it to move.
"""

from datetime import datetime

import pandas as pd

from logdet import ecs
from logdet.preprocessing import LineParser


# --- event record -> ECS ----------------------------------------------------

def _record():
    return {
        "timestamp": datetime(2026, 7, 18, 10, 22, 31),
        "host": "server1",
        "process": "sshd",
        "pid": "1382",
        "message": "Failed password for admin from 192.168.1.5 port 51422 ssh2",
        "raw": "Jul 18 10:22:31 server1 sshd[1382]: Failed password ...",
        "user": "admin",
        "source_ip": "192.168.1.5",
        "template": "Failed password for <IP> port <PORT> ssh<NUM>",
    }


def test_event_maps_core_fields_to_ecs():
    doc = ecs.event_to_ecs(_record())
    assert doc["@timestamp"] == "2026-07-18T10:22:31"
    assert doc["host"]["name"] == "server1"
    assert doc["process"]["name"] == "sshd"
    assert doc["process"]["pid"] == 1382                      # coerced to int
    assert doc["user"]["name"] == "admin"
    assert doc["source"]["ip"] == "192.168.1.5"
    assert doc["event"]["original"].startswith("Jul 18")
    assert doc["ecs"]["version"] == ecs.ECS_VERSION
    assert doc["logdet"]["template"].startswith("Failed password")


def test_failed_password_is_categorized_as_auth_failure():
    doc = ecs.event_to_ecs(_record())
    assert doc["event"]["category"] == ["authentication"]
    assert doc["event"]["outcome"] == "failure"
    assert doc["event"]["action"] == "logon-failed"


def test_accepted_password_is_success():
    rec = _record()
    rec["message"] = "Accepted password for root from 10.0.0.1 port 5 ssh2"
    assert ecs.categorize(rec["message"])["outcome"] == "success"


def test_invalid_user_is_failure_before_failed_password_rule():
    assert ecs.categorize("Invalid user oracle from 1.2.3.4")["action"] == "invalid-user"


def test_unrecognised_line_is_unknown_not_a_guess():
    cat = ecs.categorize("Server listening on 0.0.0.0 port 22")
    assert cat["category"] == []
    assert cat["outcome"] == "unknown"


def test_no_categorize_flag_leaves_event_uninterpreted():
    doc = ecs.event_to_ecs(_record(), categorize_event=False)
    assert "outcome" not in doc["event"]


def test_module_label_overrides_process():
    doc = ecs.event_to_ecs(_record(), module="auth")
    assert doc["event"]["module"] == "auth"
    assert doc["process"]["name"] == "sshd"            # process itself unchanged


# --- pruning ----------------------------------------------------------------

def test_nan_from_a_csv_cell_is_pruned_not_emitted():
    rec = _record()
    rec["source_ip"] = float("nan")                    # pandas' missing-cell value
    doc = ecs.event_to_ecs(rec)
    assert "source" not in doc
    # and the serialized form is valid JSON, not the token NaN
    import json
    json.loads(ecs.to_ndjson([doc]))


def test_space_timestamp_is_normalised_to_iso_t():
    rec = _record()
    rec["timestamp"] = "2026-07-14 00:39:00"           # parsed-CSV / incident form
    assert ecs.event_to_ecs(rec)["@timestamp"] == "2026-07-14T00:39:00"


def test_missing_user_is_pruned_not_emitted_empty():
    rec = _record()
    rec["user"] = "unknown"                            # a parser placeholder
    rec["source_ip"] = None
    doc = ecs.event_to_ecs(rec)
    assert "user" not in doc                            # no {"name": None}
    assert "source" not in doc                          # no {"ip": None}


# --- round trip -------------------------------------------------------------

def test_ecs_round_trip_preserves_the_keyed_identities():
    rec = _record()
    back = ecs.ecs_to_record(ecs.event_to_ecs(rec))
    for field in ("host", "process", "message", "user", "source_ip"):
        assert back[field] == rec[field]
    assert back["timestamp"] == "2026-07-18T10:22:31"


def test_ecs_to_record_reads_flattened_form_too():
    flat = {"@timestamp": "2026-07-18T10:22:31", "source.ip": "9.9.9.9",
            "user.name": "carol", "host.name": "h1", "message": "hi"}
    rec = ecs.ecs_to_record(flat)
    assert rec["source_ip"] == "9.9.9.9"
    assert rec["user"] == "carol"
    assert rec["host"] == "h1"


def test_missing_user_round_trips_to_the_parser_placeholder():
    rec = _record()
    rec["user"] = "unknown"
    back = ecs.ecs_to_record(ecs.event_to_ecs(rec))
    assert back["user"] == "unknown"                   # not None -- graph reads this


def test_real_parsed_line_survives_the_round_trip():
    line = ("Jul 18 10:22:31 server1 sshd[1382]: "
            "Failed password for admin from 192.168.1.5 port 51422 ssh2")
    rec = LineParser(year=2026).parse(line)
    back = ecs.ecs_to_record(ecs.event_to_ecs(rec))
    assert back["user"] == "admin"
    assert back["source_ip"] == "192.168.1.5"
    assert back["process"] == "sshd"


# --- incident -> ECS --------------------------------------------------------

def _incident_entry():
    return {
        "incident_id": 7,
        "users": ["root", "admin"],
        "source_ips": ["203.0.113.7", "203.0.113.8"],
        "start": "2026-07-18 14:00:00",
        "end": "2026-07-18 14:05:00",
        "event_count": 12,
        "severity": "high",
        "mitre_techniques": [
            {"technique_id": "T1110", "technique_name": "Brute Force",
             "tactic": "Credential Access"},
        ],
        "kill_chain": [{"tactic": "Credential Access", "techniques": ["T1110"]}],
    }


def test_incident_maps_to_ecs_alert_with_related_and_threat():
    doc = ecs.incident_to_ecs(_incident_entry())
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["id"] == 7
    assert doc["event"]["severity"] == "high"
    assert doc["user"]["name"] == "root"                # first of the set
    assert doc["source"]["ip"] == "203.0.113.7"
    assert doc["related"]["user"] == ["root", "admin"]  # full set
    assert doc["related"]["ip"] == ["203.0.113.7", "203.0.113.8"]
    assert doc["threat"]["technique"][0]["id"] == "T1110"


def test_incident_with_no_techniques_prunes_the_threat_block():
    entry = _incident_entry()
    entry["mitre_techniques"] = []
    entry["kill_chain"] = []
    doc = ecs.incident_to_ecs(entry)
    assert "threat" not in doc


# --- serialization ----------------------------------------------------------

def test_flatten_produces_dotted_keys():
    flat = ecs.flatten(ecs.event_to_ecs(_record()))
    assert flat["source.ip"] == "192.168.1.5"
    assert flat["process.pid"] == 1382


def test_to_ndjson_is_one_document_per_line():
    docs = [ecs.event_to_ecs(_record()), ecs.event_to_ecs(_record())]
    text = ecs.to_ndjson(docs)
    lines = text.splitlines()
    assert len(lines) == 2
    import json
    assert json.loads(lines[0])["user"]["name"] == "admin"
