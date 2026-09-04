"""
capture.py
Read the sshd auth stream the attacks produce, and pull out the fields ground
truth is attributed on (timestamp, source IP, user).

Two sources, same interface as the analyzer's own ingestion (CLAUDE.md
section 2): a plain file (auth.log) and journald. On Kali the monitored sshd
writes to one of these; the runner brackets each attack with a start/end time
and everything captured in that window from the attack's IPs is attributed to
it (see groundtruth.py).

Parsing is intentionally minimal and syslog-shaped -- enough to attribute, not
a full log parser. The analyzer re-parses the raw line with logdet's own
LineParser; this layer only needs to know *when* and *from where*.
"""

from __future__ import annotations

import re
import subprocess
from datetime import datetime

from .groundtruth import CapturedLine

# "Mon DD HH:MM:SS host proc[pid]: message"  -- the syslog auth format.
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+\S+?(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
# "for <u> from", "for invalid user <u> from", and the bare "Invalid user
# <u> from" that sshd emits without a "for" -- all three carry the username.
_USER_RE = re.compile(
    r"(?:for\s+(?:invalid\s+user\s+)?|invalid\s+user\s+)(?P<user>\S+)\s+from",
    re.IGNORECASE)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_line(raw: str, line_number: int, year: int) -> CapturedLine:
    """Parse one syslog auth line into the fields attribution needs.

    `year` is supplied because syslog carries no year (the same gap
    preprocessing.py handles); the caller passes the year the attack ran in.
    """
    raw = raw.rstrip("\n")
    m = _SYSLOG_RE.match(raw)
    ts = source_ip = user = None
    if m:
        try:
            ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]),
                          *(int(x) for x in m["time"].split(":")))
        except (ValueError, KeyError):
            ts = None
        msg = m["msg"]
        ip_m = _IP_RE.search(msg)
        source_ip = ip_m["ip"] if ip_m else None
        user_m = _USER_RE.search(msg)
        user = user_m["user"] if user_m else None
    return CapturedLine(line_number=line_number, raw=raw, ts=ts,
                        source_ip=source_ip, user=user)


def capture_file(path: str, year: int, start_line: int = 1) -> list[CapturedLine]:
    """Read a whole auth.log-style file. `start_line` lets a caller resume."""
    out = []
    with open(path, "r", errors="replace") as f:
        for i, raw in enumerate(f, start=1):
            if i < start_line:
                continue
            out.append(parse_line(raw, i, year))
    return out


def capture_journald(unit: str | None, year: int, since: str | None = None,
                     runner=subprocess.run,
                     identifiers: list[str] | None = None) -> list[CapturedLine]:
    """Read the journal in syslog form. `runner` is injectable for tests.

    Uses `-o short-iso` and rebuilds the syslog-shaped line, mirroring the
    analyzer's journald source (CLAUDE.md section 2, Decision Log 2026-08-30:
    the short form is fine for capture; the analyzer needs JSON for its cursor,
    which this layer does not).

    On modern systemd sshd auth events are logged under the syslog identifiers
    `sshd` and `sshd-session` (OpenSSH 9.8+ splits the listener from the
    per-connection session process), and the `ssh.service` unit journal
    (`-u ssh`) does not carry the sshd-session children. So `identifiers` (one
    or more `-t` filters) is the reliable selector on a journald box; `unit`
    remains for the older single-process case. When both are given, `-u` and
    `-t` combine, which journalctl treats as an OR.
    """
    cmd = ["journalctl", "-o", "short", "--no-pager"]
    if unit:
        cmd += ["-u", unit]
    for ident in identifiers or []:
        cmd += ["-t", ident]
    if since:
        cmd += ["--since", since]
    proc = runner(cmd, capture_output=True, text=True, check=True)
    return [parse_line(raw, i, year)
            for i, raw in enumerate(proc.stdout.splitlines(), start=1)]
