"""
preprocessing.py
Parses raw log lines into structured events and templates them
(masks variable fields like IPs, timestamps, ports, user IDs) so
downstream embedding models see the *pattern*, not the noise.

Expected raw log format (adjust regex for your actual dataset,
e.g. auth.log, HDFS, or BGL):
    <timestamp> <host> <process>[<pid>]: <message>

Example:
    Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin from 192.168.1.5 port 51422 ssh2
"""

import re
import argparse
import pandas as pd
from datetime import datetime

# --- Regex patterns for masking variable fields ---
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_PATTERN = re.compile(r"\bport \d+\b")
PID_PATTERN = re.compile(r"\[\d+\]")
USER_PATTERN = re.compile(r"\buser[= ]([\w\-]+)\b", re.IGNORECASE)

# Basic syslog-style line parser: "Mon DD HH:MM:SS host process[pid]: message"
LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


def parse_line(line: str, year: int = None):
    """Parse a single raw log line into a structured dict. Returns None if no match."""
    match = LOG_LINE_RE.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()
    year = year or datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {parts['timestamp']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = None

    return {
        "timestamp": ts,
        "host": parts["host"],
        "process": parts["process"],
        "pid": parts["pid"],
        "message": parts["message"],
        "raw": line.strip(),
    }


def extract_user(message: str) -> str:
    """Best-effort extraction of a username from the log message, for per-user baselines."""
    m = USER_PATTERN.search(message)
    if m:
        return m.group(1)
    # fallback patterns e.g. "for admin from"
    m2 = re.search(r"for ([\w\-]+) from", message)
    return m2.group(1) if m2 else "unknown"


def extract_ip(message: str) -> str:
    m = IP_PATTERN.search(message)
    return m.group(0) if m else None


def template_message(message: str) -> str:
    """Mask variable fields so semantically-identical log lines map to the
    same template regardless of IP/port/pid. This is what gets embedded."""
    templated = IP_PATTERN.sub("<IP>", message)
    templated = PORT_PATTERN.sub("port <PORT>", templated)
    templated = PID_PATTERN.sub("[<PID>]", templated)
    templated = re.sub(r"\b\d+\b", "<NUM>", templated)
    return templated


# A backwards jump of more than this many months between consecutive lines is
# read as a new year rather than as out-of-order logging. Syslog omits the year,
# so Dec -> Jan (a drop of 11) is indistinguishable from Jan -> Dec without it.
# The threshold keeps ordinary jitter (Mar -> Feb) from inventing a year.
YEAR_ROLLOVER_MIN_DROP = 6


def preprocess_file(input_path: str, output_path: str, year: int = None,
                    handle_year_rollover: bool = True) -> pd.DataFrame:
    """Parse a raw log file into the structured frame the pipeline scores.

    `handle_year_rollover` matters for any log spanning New Year: syslog carries
    no year, so a fixed one places January *before* December and silently
    corrupts every window-based computation downstream -- incident grouping, the
    impossible-travel check, and any SIEM frequency rule compared against them.
    It is a no-op on single-month corpora such as the v1 synthetic set.
    """
    records = []
    current_year = year
    previous_month = None

    with open(input_path, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_line(line, year=current_year)
            if parsed is None:
                continue

            if handle_year_rollover and parsed["timestamp"] is not None:
                month = parsed["timestamp"].month
                if (previous_month is not None
                        and previous_month - month >= YEAR_ROLLOVER_MIN_DROP):
                    current_year = (current_year or parsed["timestamp"].year) + 1
                    parsed = parse_line(line, year=current_year)
                previous_month = month
            parsed["user"] = extract_user(parsed["message"])
            parsed["source_ip"] = extract_ip(parsed["message"])
            parsed["template"] = template_message(parsed["message"])
            records.append(parsed)

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"Parsed {len(df)} log lines -> {output_path}")
    return df


def cli() -> None:
    parser = argparse.ArgumentParser(description="Parse and template raw log files.")
    parser.add_argument("--input", required=True, help="Path to raw log file")
    parser.add_argument("--output", required=True, help="Path to write parsed CSV")
    parser.add_argument("--year", type=int, default=None, help="Year to assume (syslogs omit year)")
    args = parser.parse_args()

    preprocess_file(args.input, args.output, year=args.year)


if __name__ == "__main__":
    cli()
