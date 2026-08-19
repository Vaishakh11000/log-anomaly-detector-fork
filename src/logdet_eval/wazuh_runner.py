"""
wazuh_runner.py
Drives the real Wazuh manager over a corpus and returns per-line verdicts.

Third-party rules executed by a third-party engine. Nothing here interprets
Wazuh's rule language -- `wazuh-logtest` inside the official container does the
matching, and this module only feeds it lines and reads back which rule fired.
That boundary is the point: the kill point is measuring whether a mature ruleset
degrades under camouflage, and any rule semantics we implemented ourselves would
put our own judgement back inside the thing being measured.

Two properties of the tool make per-line attribution trustworthy:

* it emits exactly one `**Phase 1` block per input line, in order, so block N
  corresponds to log line N -- asserted, not assumed
* it keeps correlation state across a single stdin session, so composite and
  frequency rules (5712 and friends) fire as they would in the manager. Verified
  against the real analysisd: both produce 14x 5710 + 1x 5712 on the same input

Known limitation, and it shapes how results may be read: **Wazuh's frequency
windows are keyed on arrival time, not on the timestamp in the log line.** A
corpus replayed at machine speed therefore looks simultaneous to it, so batch
mode cannot measure timing-based camouflage (`slow`, `temporal`) against Wazuh
at all. Those strategies need the paced replay instead. See the 2026-08-18
Decision Log entry.
"""

import re
import subprocess
from dataclasses import dataclass, field

CONTAINER = "wazuh"
LOGTEST = "/var/ossec/bin/wazuh-logtest"

# Wazuh's own severity scale. Level 3 is where the manager starts writing
# alerts; 7+ is "worth waking someone"; 10+ is its own brute-force/attack tier.
# Results are reported across thresholds rather than at one we picked, because
# choosing a single cutoff would be us deciding what counts as a detection for
# the system we are being compared against.
LEVEL_THRESHOLDS = (3, 7, 10)

_BLOCK = re.compile(r"^\*\*Phase 1", re.M)
_RULE_ID = re.compile(r"^\tid: '(\d+)'", re.M)
_LEVEL = re.compile(r"^\tlevel: '(\d+)'", re.M)
_MITRE = re.compile(r"^\tmitre\.id: '\[(.*?)\]'", re.M)
_ALERT = re.compile(r"^\*\*Alert to be generated", re.M)


@dataclass
class LineVerdict:
    """What Wazuh made of one log line."""

    line_number: int          # 1-based, matching ground truth
    rule_id: str | None
    level: int
    alerted: bool
    mitre: list[str] = field(default_factory=list)


def _parse_block(block: str, line_number: int) -> LineVerdict:
    rule = _RULE_ID.search(block)
    level = _LEVEL.search(block)
    mitre = _MITRE.search(block)
    techniques = (
        [t.strip().strip("'") for t in mitre.group(1).split(",") if t.strip()]
        if mitre else []
    )
    return LineVerdict(
        line_number=line_number,
        rule_id=rule.group(1) if rule else None,
        level=int(level.group(1)) if level else 0,
        alerted=bool(_ALERT.search(block)),
        mitre=techniques,
    )


def analyze(log_path: str, container: str = CONTAINER) -> list[LineVerdict]:
    """Run the corpus through Wazuh and return one verdict per log line."""
    # logtest writes its analysis to stderr and only blank lines to stdout, so
    # the two are merged rather than captured separately.
    with open(log_path, "rb") as handle:
        completed = subprocess.run(
            ["docker", "exec", "-i", container, LOGTEST],
            stdin=handle, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

    output = completed.stdout.decode(errors="replace")
    blocks = _BLOCK.split(output)[1:]          # drop the tool's banner

    n_lines = sum(1 for _ in open(log_path, errors="ignore"))
    if len(blocks) != n_lines:
        raise AssertionError(
            f"Wazuh returned {len(blocks)} verdicts for {n_lines} log lines. "
            "Ground-truth line numbers would be misaligned, so the comparison "
            "would be scoring the wrong lines."
        )

    return [_parse_block(block, i) for i, block in enumerate(blocks, start=1)]


def flagged_lines(verdicts: list[LineVerdict], min_level: int) -> set[int]:
    """Lines Wazuh alerted on at or above `min_level`."""
    return {v.line_number for v in verdicts
            if v.alerted and v.level >= min_level}


def rule_counts(verdicts: list[LineVerdict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for verdict in verdicts:
        if verdict.rule_id:
            counts[verdict.rule_id] = counts.get(verdict.rule_id, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def mitre_techniques(verdicts: list[LineVerdict], min_level: int = 3) -> set[str]:
    """Techniques Wazuh attributed, for the coverage comparison. Wazuh ships
    MITRE IDs on its rules, so this is its own attribution, not ours."""
    return {t for v in verdicts if v.alerted and v.level >= min_level for t in v.mitre}


def container_available(container: str = CONTAINER) -> bool:
    """True if the manager container is up and logtest is runnable."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "test", "-x", LOGTEST],
            capture_output=True, timeout=30,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
