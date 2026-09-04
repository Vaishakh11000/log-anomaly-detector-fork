"""CLI wiring: launch + capture + attribute + ground-truth CSV, no network.

The launch driver is stubbed to return a fixed record whose window brackets the
auth file, so the test exercises the CLI's capture -> attribute -> CSV path
deterministically rather than depending on the wall clock.
"""

import csv
from datetime import datetime

from attack_runner import attacks, cli
from attack_runner.groundtruth import AttackRecord


def test_enumeration_from_file_writes_ground_truth(tmp_path, monkeypatch):
    auth = tmp_path / "auth.log"
    auth.write_text(
        "Sep 04 10:00:00 h sshd[1]: Invalid user oracle from 10.10.10.1 port 1\n"
        "Sep 04 10:00:01 h sshd[2]: Invalid user postgres from 10.10.10.1 port 2\n"
        "Sep 04 10:00:02 h sshd[3]: Accepted password for alice from 10.0.0.9 port 3 ssh2\n"
    )
    gt = tmp_path / "gt.csv"
    recs = tmp_path / "recs.json"

    fixed = AttackRecord(
        scenario="C", instance=1, source_ips=["10.10.10.1"], tool="ssh",
        t_start=datetime(2026, 9, 4, 9, 59, 0),
        t_end=datetime(2026, 9, 4, 10, 1, 0))
    monkeypatch.setattr(attacks, "enumeration", lambda *a, **k: fixed)

    rc = cli.main([
        "enumeration", "--source-ip", "10.10.10.1", "--instance", "1",
        "--users", "oracle", "postgres",
        "--auth-file", str(auth), "--year", "2026",
        "--ground-truth-out", str(gt), "--records-out", str(recs),
    ])
    assert rc == 0

    rows = list(csv.DictReader(gt.open()))
    labelled = {r["line_number"] for r in rows}
    assert labelled == {"1", "2"}          # attacker lines, not the benign login
    assert all(r["scenario"] == "C" for r in rows)
    assert recs.exists()


def test_no_capture_source_records_launch_only(tmp_path, monkeypatch):
    fixed = AttackRecord(scenario="A", instance=1, source_ips=["10.10.10.1"], tool="ssh")
    monkeypatch.setattr(attacks, "brute_force", lambda *a, **k: fixed)
    recs = tmp_path / "recs.json"
    rc = cli.main(["brute_force", "--records-out", str(recs)])
    assert rc == 0 and recs.exists()
