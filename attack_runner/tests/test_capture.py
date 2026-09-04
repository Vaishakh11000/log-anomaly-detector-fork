"""Parsing the auth stream into attribution fields."""

from datetime import datetime

from attack_runner.capture import capture_file, capture_journald, parse_line


def test_parse_failed_password():
    c = parse_line("Sep 04 10:01:02 host sshd[123]: Failed password for admin "
                   "from 10.10.10.1 port 5555 ssh2", 7, year=2026)
    assert c.line_number == 7
    assert c.ts == datetime(2026, 9, 4, 10, 1, 2)
    assert c.source_ip == "10.10.10.1"
    assert c.user == "admin"


def test_parse_invalid_user():
    c = parse_line("Sep 04 10:01:02 host sshd[9]: Failed password for invalid "
                   "user oracle from 203.0.113.5 port 22 ssh2", 1, year=2026)
    assert c.user == "oracle"
    assert c.source_ip == "203.0.113.5"


def test_parse_garbage_line_yields_nulls():
    c = parse_line("not a syslog line at all", 3, year=2026)
    assert c.ts is None and c.source_ip is None and c.user is None
    assert c.raw == "not a syslog line at all"


def test_capture_file(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Sep 04 10:00:00 host sshd[1]: Failed password for root from 10.10.10.1 port 1 ssh2\n"
        "Sep 04 10:00:01 host sshd[2]: Accepted password for alice from 10.0.0.5 port 2 ssh2\n"
    )
    lines = capture_file(str(p), year=2026)
    assert len(lines) == 2
    assert lines[0].user == "root" and lines[1].user == "alice"


def test_capture_journald_with_injected_runner():
    class Proc:
        stdout = ("Sep 04 10:00:00 host sshd[1]: Failed password for root "
                  "from 10.10.10.1 port 1 ssh2\n")
    lines = capture_journald("sshd", year=2026, runner=lambda *a, **k: Proc())
    assert len(lines) == 1 and lines[0].source_ip == "10.10.10.1"


def test_capture_journald_identifiers_build_t_flags():
    captured = {}

    class Proc:
        stdout = ("Sep 04 10:00:00 host sshd-session[9]: Invalid user oracle "
                  "from 127.0.0.11 port 2 ssh2\n")

    def fake_runner(cmd, **k):
        captured["cmd"] = cmd
        return Proc()

    lines = capture_journald(None, year=2026, runner=fake_runner,
                             identifiers=["sshd", "sshd-session"])
    assert "-t" in captured["cmd"]
    assert captured["cmd"].count("-t") == 2
    assert "sshd-session" in captured["cmd"]
    # unit is absent, so no -u flag was added
    assert "-u" not in captured["cmd"]
    assert len(lines) == 1 and lines[0].user == "oracle"
