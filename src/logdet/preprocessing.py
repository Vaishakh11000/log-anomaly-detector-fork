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

from .templating import TemplateMiner

# --- Regex patterns for masking variable fields ---
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_PATTERN = re.compile(r"\bport \d+\b")
PID_PATTERN = re.compile(r"\[\d+\]")
USER_PATTERN = re.compile(r"\buser[= ]([\w\-]+)\b", re.IGNORECASE)

# Basic syslog-style line parser: "Mon DD HH:MM:SS host process[pid]: message"
LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.()]+)(?:\[(?P<pid>\d+)\])?:\s+"
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


class LineParser:
    """Parses raw log lines one at a time, carrying the year-rollover state.

    Batch and stream need the same parse, but a stream has no file to iterate
    twice: the rollover rule below depends on the *previous* line, so the state
    has to live somewhere that survives between lines. Keeping it in an object
    means `preprocess_file` and the streaming ingester share one parser rather
    than two implementations that can drift apart.
    """

    def __init__(self, year: int | None = None, handle_year_rollover: bool = True,
                 miner: TemplateMiner | None = None):
        self.year = year
        self.handle_year_rollover = handle_year_rollover
        self.previous_month: int | None = None
        # Optional Drain3 miner (Stage 3). Off unless a caller passes one, so a
        # default parse produces exactly the columns every number in `results/`
        # was computed from. `template_id` is additive -- nothing in detection
        # reads it -- but a column that appears by default still changes every
        # parsed CSV in the project, and the point of adding it separately from
        # consuming it is that the two steps can be checked apart.
        self.miner = miner

    def parse(self, line: str) -> dict | None:
        """One raw line -> the enriched record the pipeline scores, or None."""
        parsed = parse_line(line, year=self.year)
        if parsed is None:
            return None

        if self.handle_year_rollover and parsed["timestamp"] is not None:
            month = parsed["timestamp"].month
            if (self.previous_month is not None
                    and self.previous_month - month >= YEAR_ROLLOVER_MIN_DROP):
                self.year = (self.year or parsed["timestamp"].year) + 1
                parsed = parse_line(line, year=self.year)
            self.previous_month = month

        parsed["user"] = extract_user(parsed["message"])
        parsed["source_ip"] = extract_ip(parsed["message"])
        parsed["template"] = template_message(parsed["message"])
        if self.miner is not None:
            # The mined cluster id, not the mined template text: the text a
            # cluster reports widens as more lines arrive, so a text recorded
            # per line leaves early rows disagreeing with late rows about what
            # one cluster is. See templating.py.
            parsed["template_id"] = self.miner.add(parsed["message"])
        return parsed

    def parse_many(self, lines) -> list[dict]:
        """Parse an iterable of lines, dropping the ones that don't match."""
        records = [self.parse(line) for line in lines]
        return [r for r in records if r is not None]


def preprocess_file(input_path: str, output_path: str, year: int = None,
                    handle_year_rollover: bool = True,
                    mine_templates: bool = False,
                    template_state_path: str | None = None,
                    miner: "TemplateMiner | None" = None) -> pd.DataFrame:
    """Parse a raw log file into the structured frame the pipeline scores.

    `handle_year_rollover` matters for any log spanning New Year: syslog carries
    no year, so a fixed one places January *before* December and silently
    corrupts every window-based computation downstream -- incident grouping, the
    impossible-travel check, and any SIEM frequency rule compared against them.
    It is a no-op on single-month corpora such as the v1 synthetic set.

    `mine_templates` adds the Drain3 `template_id` column (Stage 3). It is off
    by default: nothing in detection reads that column, but turning it on by
    default would change every parsed CSV in the project at once, and the
    reason mining and consuming are separate steps is so each can be checked on
    its own. `template_state_path`, if given, is where the mined cluster table
    is written -- ids mean nothing without it.

    `miner` passes in an *existing* miner instead of starting a fresh one, which
    is what any caller scoring against a fitted sequence model has to do: cluster
    ids are assigned by the miner that saw the traffic, so a corpus mined by a
    second, independent miner gets a numbering the model was never fit on. The
    miner keeps mining (rather than only matching) so a genuinely new template
    still gets an id -- one the model does not know, which reads as silence and
    never as evidence. See templating.TemplateMiner.match for why freezing is
    the more dangerous option.
    """
    if miner is None and mine_templates:
        miner = TemplateMiner()
    parser = LineParser(year=year, handle_year_rollover=handle_year_rollover,
                        miner=miner)

    with open(input_path, "r", errors="ignore") as f:
        records = parser.parse_many(f)

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"Parsed {len(df)} log lines -> {output_path}")
    if miner is not None:
        print(f"Mined {miner.cluster_count} templates")
        if template_state_path:
            miner.save(template_state_path)
            print(f"Template state -> {template_state_path}")
    return df


def cli() -> None:
    parser = argparse.ArgumentParser(description="Parse and template raw log files.")
    parser.add_argument("--input", required=True, help="Path to raw log file")
    parser.add_argument("--output", required=True, help="Path to write parsed CSV")
    parser.add_argument("--year", type=int, default=None, help="Year to assume (syslogs omit year)")
    parser.add_argument("--format", choices=["syslog", "nginx"], default="syslog",
                        help="Source format (default: syslog). 'nginx' reads an "
                             "nginx/Apache access log via the ECS boundary.")
    parser.add_argument("--host", default=None,
                        help="Hostname to record (nginx only; access logs carry none)")
    parser.add_argument("--drain3", action="store_true",
                        help="Also mine Drain3 templates into a template_id column")
    parser.add_argument("--template-state", default=None,
                        help="Where to write the mined template table (implies --drain3)")
    args = parser.parse_args()

    mine = args.drain3 or bool(args.template_state)
    if args.format == "nginx":
        # Imported here, not at module scope: weblog imports this module for
        # `template_message`, so a top-level import would be circular. The
        # syslog branch below is the untouched original path -- a default run
        # produces exactly the columns every number in `results/` came from.
        from .weblog import preprocess_web_file
        preprocess_web_file(args.input, args.output, host=args.host,
                            mine_templates=mine,
                            template_state_path=args.template_state)
        return

    preprocess_file(args.input, args.output, year=args.year,
                    mine_templates=mine,
                    template_state_path=args.template_state)


if __name__ == "__main__":
    cli()
