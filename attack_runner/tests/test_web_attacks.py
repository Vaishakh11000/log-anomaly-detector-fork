"""The web second source: driver, access-log capture, and CLI wiring.

Mirrors the ssh drivers' tests -- the tool call goes through an injected runner
so no web server is needed, capture parses a fixture access log, and the CLI
path is exercised with a stubbed launch whose window brackets the fixture.
"""

import csv
from datetime import datetime, timedelta, timezone

from attack_runner import attacks, cli
from attack_runner.capture import capture_access_file, parse_access_line
from attack_runner.groundtruth import AttackRecord, attribute


class _Recorder:
    """Captures the commands a driver shells out to, without running them."""

    def __init__(self):
        self.calls = []

    def __call__(self, cmd, *a, **k):
        self.calls.append(cmd)
        class _P:  # minimal completed-process stand-in
            returncode = 0
            stdout = ""
            stderr = ""
        return _P()


# --- driver -----------------------------------------------------------------

def test_web_bruteforce_falls_back_to_curl(monkeypatch):
    # force the "no hydra" path so the test is deterministic on any box
    monkeypatch.setattr(attacks, "_which", lambda *names: None)
    runner = _Recorder()
    rec = attacks.web_bruteforce("http://127.0.0.1/wp-login.php", "127.0.0.1",
                                 instance=2, attempts=5, runner=runner,
                                 now=lambda: datetime(2026, 9, 5, 12, 0, 0))
    assert rec.scenario == "W" and rec.instance == 2
    assert rec.tool == "curl" and rec.source_ips == ["127.0.0.1"]
    assert len(runner.calls) == 5                      # one request per attempt
    assert runner.calls[0][0] == "curl"
    assert "http://127.0.0.1/wp-login.php" in runner.calls[0]
    assert any("password=wrongpass0" in part for part in runner.calls[0])


def test_web_bruteforce_prefers_hydra(monkeypatch):
    monkeypatch.setattr(attacks, "_which", lambda *names: "hydra")
    runner = _Recorder()
    rec = attacks.web_bruteforce("http://127.0.0.1:8080/login", "10.10.10.1",
                                 instance=1, attempts=8, runner=runner,
                                 now=lambda: datetime(2026, 9, 5, 12, 0, 0))
    assert rec.tool == "hydra"
    assert len(runner.calls) == 1                      # hydra runs the whole list
    cmd = runner.calls[0]
    assert cmd[0] == "hydra" and "http-post-form" in cmd
    assert "-s" in cmd and "8080" in cmd               # non-default port carried


# --- capture ----------------------------------------------------------------

_ACCESS_LINE = ('203.0.113.66 - - [05/Sep/2026:12:00:01 +0000] '
                '"POST /wp-login.php HTTP/1.1" 401 20 "-" "curl/7.1"')


def test_parse_access_line():
    c = parse_access_line(_ACCESS_LINE, 7)
    assert c.line_number == 7
    assert c.source_ip == "203.0.113.66"
    assert c.user is None                               # access logs carry no user
    assert c.ts is not None
    # 12:00:01 UTC converted to this machine's local naive time
    expected = (datetime(2026, 9, 5, 12, 0, 1, tzinfo=timezone.utc)
                .astimezone().replace(tzinfo=None))
    assert c.ts == expected


def test_parse_access_garbage_yields_nulls():
    c = parse_access_line("not an access line", 3)
    assert c.ts is None and c.source_ip is None
    assert c.raw == "not an access line"


def test_capture_access_file(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        '203.0.113.66 - - [05/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "b"\n'
        '203.0.113.66 - - [05/Sep/2026:12:00:01 +0000] "POST /login HTTP/1.1" 401 2 "-" "c"\n'
    )
    lines = capture_access_file(str(p))
    assert len(lines) == 2
    assert all(ln.source_ip == "203.0.113.66" for ln in lines)


# --- attribution (the whole point: an access line joins by ip+time) ---------

def test_access_lines_attribute_to_web_record():
    lines = [parse_access_line(_ACCESS_LINE, 1)]
    base = lines[0].ts
    rec = AttackRecord(scenario="W", instance=1, source_ips=["203.0.113.66"],
                       tool="curl", t_start=base - timedelta(seconds=2),
                       t_end=base + timedelta(seconds=2))
    result = attribute(lines, [rec])
    assert result["labels"][1] == {"scenario": "W", "instance": 1}


# --- CLI end to end ---------------------------------------------------------

def test_cli_web_bruteforce_from_access_file(tmp_path, monkeypatch):
    access = tmp_path / "access.log"
    access.write_text(
        '203.0.113.66 - - [05/Sep/2026:12:00:00 +0000] "POST /login HTTP/1.1" 401 2 "-" "c"\n'
        '203.0.113.66 - - [05/Sep/2026:12:00:01 +0000] "POST /login HTTP/1.1" 401 2 "-" "c"\n'
        '10.0.0.9 - - [05/Sep/2026:12:00:02 +0000] "GET /index.html HTTP/1.1" 200 9 "-" "b"\n'
    )
    # local-naive window bracketing the two attacker lines
    lo = (datetime(2026, 9, 5, 11, 59, 58, tzinfo=timezone.utc)
          .astimezone().replace(tzinfo=None))
    hi = (datetime(2026, 9, 5, 12, 0, 1, 500000, tzinfo=timezone.utc)
          .astimezone().replace(tzinfo=None))
    fixed = AttackRecord(scenario="W", instance=1, source_ips=["203.0.113.66"],
                         tool="curl", t_start=lo, t_end=hi)
    monkeypatch.setattr(attacks, "web_bruteforce", lambda *a, **k: fixed)

    gt = tmp_path / "gt.csv"
    corpus = tmp_path / "corpus.log"
    rc = cli.main([
        "web_bruteforce", "--source-ip", "203.0.113.66", "--instance", "1",
        "--access-file", str(access),
        "--ground-truth-out", str(gt), "--records-out", str(tmp_path / "r.json"),
        "--corpus-out", str(corpus),
    ])
    assert rc == 0
    labelled = {int(r["line_number"]) for r in csv.DictReader(gt.open())}
    assert labelled == {1, 2}                           # the 401 burst, not the benign GET
    assert corpus.read_text().splitlines()[2].startswith("10.0.0.9")
