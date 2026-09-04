"""
groundtruth.py
Ground truth captured *at generation time*, travelling with the logs.

CLAUDE.md section 2d: the whole reason to run real tools on Kali is that the
attack lines become authentic tool output rather than fabricated strings. But
authentic output has no label attached, so scoring would break -- unless we
record, as each attack is launched, exactly which lines it is expected to
produce. That is what an `AttackRecord` is: the parameters of one attack
instance and the window it ran in, written down before the log is even parsed.

The same principle as the synthetic track's decision to camouflage the event
list rather than the finished file (CLAUDE.md, generate_logs.py): keep every
attack line bound to its scenario/instance label through every transformation.

Attribution is by identity + time, not by trusting the tool to tell us which
lines it wrote: a captured auth line is attributed to an attack instance when
its source IP is one the instance used and its timestamp falls in the
instance's window. This is deliberately conservative -- an ambient brute force
from the same IP in the same window would be (correctly) swept in, because from
the log's point of view it is indistinguishable, and pretending otherwise
would flatter the score.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class AttackRecord:
    """One attack instance's ground truth, known at launch time.

    `synthetic` marks the parts that are *not* real tool output -- e.g.
    impossible travel needs a second, geographically distant source IP that no
    local tool can genuinely produce (CLAUDE.md section 2d). The write-up has
    to state which lines are authentic and which are authored; this field is
    where that distinction is recorded rather than assumed.
    """

    scenario: str                       # "A" brute force, "B" impossible travel, "C" enumeration
    instance: int
    camouflage: list[str] = field(default_factory=list)
    target_user: str | None = None
    source_ips: list[str] = field(default_factory=list)
    t_start: datetime | None = None
    t_end: datetime | None = None
    tool: str = ""                      # e.g. "hydra", "ssh", "nmap"
    synthetic: bool = False             # True when the base traffic is authored, not captured
    description: str = ""

    def covers(self, ts: datetime, source_ip: str | None) -> bool:
        """Does a captured line at `ts` from `source_ip` belong to this instance?

        The window bounds carry microsecond precision (they come from
        `datetime.now()` at launch), but syslog and journald stamp lines to the
        **whole second** only, so a captured line reads as `S.000000`. Comparing
        those directly drops every line of a sub-second attack: an enumeration
        that fires all its ssh attempts in ~30ms has a window like
        38.870-38.902, and each real line at 38.000000 fails `ts < t_start` and
        is judged "before the attack". So the start bound is floored to the whole
        second before comparing -- consistent with the conservative philosophy in
        this module's docstring: where the log cannot express sub-second
        ordering, include rather than assert precision we do not have. Found on
        the Kali box when every enumeration instance attributed 0 lines.

        Consequence for the runner: space attack instances into distinct,
        non-adjacent whole seconds (this project uses ~2.5s), or two same-second
        instances will attribute each other's lines once the bound floors.
        """
        if self.t_start is not None and ts < self.t_start.replace(microsecond=0):
            return False
        if self.t_end is not None and ts > self.t_end:
            return False
        if self.source_ips and source_ip not in self.source_ips:
            return False
        return True


@dataclass
class CapturedLine:
    """One raw log line the capture layer saw, with the fields we attribute on."""

    line_number: int                    # 1-based into the shipped stream
    raw: str
    ts: datetime | None = None
    source_ip: str | None = None
    user: str | None = None


def attribute(lines: list[CapturedLine], records: list[AttackRecord]) -> dict:
    """Label captured lines against the attack records.

    Returns a ground-truth mapping line_number -> {scenario, instance} for
    every attributed line, plus a per-instance count so a caller can tell an
    instance produced *no* attributable lines (a real failure mode: the tool
    ran but the sshd config swallowed the lines) apart from one that was simply
    never launched.
    """
    labels: dict[int, dict] = {}
    per_instance: dict[tuple, int] = {(r.scenario, r.instance): 0 for r in records}

    for line in lines:
        if line.ts is None:
            continue
        for record in records:
            if record.covers(line.ts, line.source_ip):
                labels[line.line_number] = {
                    "scenario": record.scenario,
                    "instance": record.instance,
                }
                per_instance[(record.scenario, record.instance)] += 1
                break   # first matching instance wins; windows should not overlap

    return {"labels": labels, "per_instance": {f"{s}:{i}": n
                                               for (s, i), n in per_instance.items()}}


def write_ground_truth_csv(labels: dict[int, dict], path: str,
                           lines: list[CapturedLine]) -> None:
    """Same shape as generate_logs.write_outputs' CSV, so the existing scorer
    (`logdet_eval.scoring`) reads a captured corpus with no changes."""
    by_number = {ln.line_number: ln for ln in lines}
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["line_number", "timestamp", "user", "scenario",
                         "instance", "description"])
        for n in sorted(labels):
            ln = by_number.get(n)
            writer.writerow([
                n,
                ln.ts.isoformat() if ln and ln.ts else "",
                ln.user if ln else "",
                labels[n]["scenario"],
                labels[n]["instance"],
                "",
            ])


def dump_records(records: list[AttackRecord], path: str) -> None:
    """Persist the launch-time record so ground truth survives the trip to the
    analyzer even if attribution is re-run there."""
    def enc(o):
        return o.isoformat() if isinstance(o, datetime) else o

    with open(path, "w") as f:
        json.dump([{k: enc(v) for k, v in asdict(r).items()} for r in records],
                  f, indent=2)
