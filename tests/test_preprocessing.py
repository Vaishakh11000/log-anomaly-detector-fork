"""
Parsing and templating. Everything downstream sees templates rather than raw
lines, so a templating regression silently changes what the detector learns.
"""

from pathlib import Path

import pandas as pd
import pytest

from logdet.preprocessing import (
    extract_ip,
    extract_user,
    parse_line,
    preprocess_file,
    template_message,
)

SSHD = "Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin from 192.168.1.5 port 51422 ssh2"


def test_parse_line_extracts_syslog_fields():
    parsed = parse_line(SSHD, year=2026)
    assert parsed["host"] == "server1"
    assert parsed["process"] == "sshd"
    assert parsed["pid"] == "1382"
    assert parsed["message"].startswith("Failed password for admin")
    assert parsed["timestamp"] == pd.Timestamp("2026-07-18 10:22:31")


def test_parse_line_handles_a_process_with_no_pid():
    parsed = parse_line("Jul 18 10:22:31 server1 CRON: pam_unix(cron:session): session opened", year=2026)
    assert parsed is not None
    assert parsed["process"] == "CRON"
    assert parsed["pid"] is None


def test_parse_line_returns_none_for_non_syslog_input():
    assert parse_line("this is not a log line") is None
    assert parse_line("") is None


def test_extract_user_prefers_the_explicit_user_field():
    assert extract_user("pam_unix(sshd:auth): authentication failure user=root") == "root"


def test_extract_user_falls_back_to_the_for_x_from_y_form():
    assert extract_user("Failed password for admin from 192.168.1.5 port 51422 ssh2") == "admin"


def test_extract_user_reports_unknown_rather_than_guessing():
    """'unknown' is a real signal downstream -- sequence_grouping refuses to
    join two rows on it, so it must not be a plausible-looking username."""
    assert extract_user("Server listening on 0.0.0.0 port 22.") == "unknown"


def test_extract_ip():
    assert extract_ip("Failed password for admin from 192.168.1.5 port 51422 ssh2") == "192.168.1.5"
    assert extract_ip("session opened for user root") is None


def test_templating_collapses_lines_that_differ_only_in_ip_pid_and_port():
    """The property the whole embedding stack rests on: same behaviour from a
    different address must produce the same vector."""
    a = template_message("Failed password for admin from 192.168.1.5 port 51422 ssh2")
    b = template_message("Failed password for admin from 203.0.113.9 port 40001 ssh2")
    assert a == b
    assert "<IP>" in a and "port <PORT>" in a


def test_templating_keeps_semantically_different_lines_apart():
    failed = template_message("Failed password for admin from 192.168.1.5 port 51422 ssh2")
    accepted = template_message("Accepted password for admin from 192.168.1.5 port 51422 ssh2")
    assert failed != accepted


def test_templating_masks_pids():
    assert template_message("sshd[1382]: connection closed") == "sshd[<PID>]: connection closed"


def test_preprocess_file_on_the_committed_sample(tmp_path):
    sample = Path(__file__).resolve().parents[1] / "data" / "raw" / "sample.log"
    out = tmp_path / "parsed.csv"
    df = preprocess_file(str(sample), str(out), year=2026)

    assert out.exists()
    assert len(df) > 0
    assert {"timestamp", "host", "process", "message", "user", "source_ip", "template"} <= set(df.columns)
    assert df["timestamp"].notna().all()
    # a parsed corpus that produced one template per line would mean templating
    # did nothing at all
    assert df["template"].nunique() < len(df)


# --- process names carrying parentheses -----------------------------------
# journald names user-session pam `(systemd)` and `(sd-pam)`, and LogHub's
# Linux.log carries `su(pam_unix)`. Both are auth lines, and both were silently
# dropped while the process field rejected parentheses.

def test_a_parenthesised_process_name_parses():
    line = ("Aug 30 19:10:10 archlinux (systemd)[1865]: "
            "pam_unix(systemd-user:session): session opened for user sddm(uid=968)")
    parsed = parse_line(line)
    assert parsed is not None
    assert parsed["process"] == "(systemd)"
    assert parsed["pid"] == "1865"


def test_a_process_name_with_an_embedded_module_parses():
    line = "Jun 15 04:06:18 combo su(pam_unix)[2077]: session opened for user news by (uid=0)"
    parsed = parse_line(line)
    assert parsed is not None
    assert parsed["process"] == "su(pam_unix)"


def test_ordinary_process_names_are_unaffected():
    line = "Aug 30 14:08:45 archlinux sshd[11866]: Failed password for root from 10.0.0.5 port 22 ssh2"
    parsed = parse_line(line)
    assert parsed["process"] == "sshd"
    assert parsed["pid"] == "11866"
