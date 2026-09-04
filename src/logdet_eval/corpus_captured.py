"""
corpus_captured.py
Injects *authentic* Kali-captured attack lines into the real OpenSSH benign
background, so an authentic attack can be scored on the same footing as the
synthetic scenarios `corpus_openssh.build_killpoint_corpus` injects.

Why this module exists
----------------------
The first authentic attacks (CLAUDE.md Stage 6, `results/kali/`) were scored
*standalone*: a ~100-line capture holding almost nothing but the attack itself.
That reads 0% instance detection on brute force and 33% on enumeration against
the synthetic corpus's 100%, and the dominant cause is the corpus rather than
the detector -- an attacked account whose only lines are the attack has no
benign per-user baseline, so the burst *is* that account's norm and a per-user
outlier detector ranks it an inlier. `results/kali/notes.md` records that
reading and names this module as the comparable measurement.

So the capture is reduced to its labelled attack lines, those lines are
re-stamped onto a day of the real corpus and interleaved into the same
background `build_killpoint_corpus` uses, and the ground truth is renumbered
against the combined file. Everything else about the measurement -- background,
ambient ratio, scorer, seeds -- is held identical to the synthetic arm, so the
only thing that differs between the two arms is where the attack lines came
from.

What is real here and what is not
---------------------------------
Real: every background line, and every attack line *verbatim* as a modern sshd
wrote it in response to real hydra/ssh traffic (message, process, pid, and the
sub-second spacing between the lines of one instance).
Authored: which day and time of day the instance is injected at -- drawn from
the same distribution the synthetic generators use, so the two arms are matched
rather than one being handed easier placement.

Deliberately *not* rewritten, though both would have been defensible:

  - The source IP stays `127.0.0.1`. The captures were run against Kali's own
    sshd, so that is genuinely where the traffic came from. It costs nothing to
    keep: `template_message` masks every IP before embedding, so the detector
    never sees the address, and scenarios A and C do not use the
    impossible-travel rule, which is the only place a subnet is read.
  - The target account stays `root`, the account hydra was actually pointed at.
    It does not need retargeting to a corpus user to fix the baseline problem:
    `root` has 68 lines of genuine history in this background, well above
    `MIN_SAMPLES_PER_USER`, so it gets a real per-user model out of real
    corpus traffic. That is precisely the baseline the standalone capture
    lacked.
"""

import csv
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from logdet.preprocessing import parse_line
from logdet_eval.corpus_openssh import (
    CORPUS_HOST,
    build_background,
    load_classified,
)


# Time of day an instance is injected at, per scenario, matched to the synthetic
# generators in generate_logs.py so neither arm gets easier placement:
# gen_scenario_a draws hours 1-5, gen_scenario_c draws hours 0-23.
SCENARIO_HOURS = {"A": (1, 5), "B": (0, 23), "C": (0, 23)}


@dataclass
class CapturedInstance:
    """One authentic attack instance, reduced to its labelled lines.

    Timestamps are held as offsets from the instance's first labelled line, so
    the instance can be re-stamped anywhere in the background while keeping the
    exact spacing the real tooling produced.
    """

    scenario: str
    instance: int
    description: str = ""
    source: str = ""
    # (offset from instance start, process, pid, message, labelled user)
    lines: list[tuple[timedelta, str, str | None, str, str | None]] = field(default_factory=list)

    @property
    def span(self) -> timedelta:
        return self.lines[-1][0] if self.lines else timedelta()


def load_capture(log_path: Path | str, gt_path: Path | str) -> list[CapturedInstance]:
    """Read one (corpus.log, ground_truth.csv) pair into its attack instances.

    Only the lines ground truth labels are kept. The rest of the capture is
    Kali's own background -- sshd startup banners, and, because each
    `--auth-file` run read the whole growing file, earlier instances' lines --
    and the real corpus background replaces all of it. Dropping it is also what
    removes the third confound `results/kali/notes.md` records: with one
    instance per corpus there is no overlap left to muddy attribution.
    """
    raw = Path(log_path).read_text(errors="ignore").splitlines()

    rows: list[dict] = []
    with open(gt_path, newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)
    if not rows:
        return []

    # The gt timestamp carries the year the capture was taken in; the log line
    # does not (syslog omits it), so the year has to come from here or every
    # parsed timestamp is silently placed in the wrong year.
    year = datetime.fromisoformat(rows[0]["timestamp"]).year

    grouped: dict[tuple[str, int], list[dict]] = {}
    for row in rows:
        grouped.setdefault((row["scenario"], int(row["instance"])), []).append(row)

    instances: list[CapturedInstance] = []
    for (scenario, number), group in sorted(grouped.items()):
        parsed: list[tuple[datetime, str, str | None, str, str | None]] = []
        for row in group:
            index = int(row["line_number"]) - 1     # ground truth is 1-based
            if not 0 <= index < len(raw):
                raise ValueError(
                    f"{log_path}: ground truth names line {index + 1}, "
                    f"but the log has {len(raw)} lines")
            event = parse_line(raw[index], year=year)
            if event is None or event["timestamp"] is None:
                raise ValueError(f"{log_path}:{index + 1} did not parse: {raw[index]!r}")
            parsed.append((event["timestamp"], event["process"], event["pid"],
                           event["message"], row.get("user") or None))

        parsed.sort(key=lambda item: item[0])
        base = parsed[0][0]
        instances.append(CapturedInstance(
            scenario=scenario,
            instance=number,
            source=str(log_path),
            lines=[(ts - base, process, pid, message, user)
                   for ts, process, pid, message, user in parsed],
        ))

    return instances


def load_captures(pairs: list[tuple[str, str]]) -> list[CapturedInstance]:
    """Load several capture pairs, renumbering instances per scenario.

    Each capture file was written by its own `attack_runner` invocation and
    numbers its instance independently, so two files can both call themselves
    instance 1. Scoring groups by (scenario, instance), and two instances
    sharing a key would be pooled into one -- silently halving the
    denominator -- so they are renumbered in the order given.
    """
    counters: dict[str, int] = {}
    loaded: list[CapturedInstance] = []
    for log_path, gt_path in pairs:
        for captured in load_capture(log_path, gt_path):
            counters[captured.scenario] = counters.get(captured.scenario, 0) + 1
            captured.instance = counters[captured.scenario]
            loaded.append(captured)

    # Descriptions come from the runner's own record where one was written
    # beside the capture, so the manifest says which tool produced each
    # instance rather than asserting it here.
    for captured in loaded:
        record = Path(captured.source).with_name(
            Path(captured.source).stem + "_rec.json")
        if record.exists():
            try:
                entries = json.loads(record.read_text())
                if entries:
                    captured.description = entries[0].get("description", "")
            except (ValueError, OSError):
                pass

    return loaded


def place(captured: CapturedInstance, day_start: datetime,
          rng: random.Random) -> list[dict]:
    """Re-stamp one instance onto a day of the background.

    The offsets between the instance's lines are preserved exactly, so what
    moves is only *when* the attack happened, never how fast it happened.
    """
    low, high = SCENARIO_HOURS.get(captured.scenario, (0, 23))
    start = day_start + timedelta(hours=rng.randint(low, high),
                                  minutes=rng.randint(0, 59),
                                  seconds=rng.randint(0, 59))
    return [
        {
            "ts": start + offset,
            "process": process,
            "pid": pid,
            "message": message,
            "user": user,
            "scenario": captured.scenario,
            "instance": captured.instance,
            "description": captured.description,
        }
        for offset, process, pid, message, user in captured.lines
    ]


def build_captured_corpus(captures: list[CapturedInstance],
                          ambient_ratio: float = 0.05,
                          seed: int = 42,
                          source: Path | str | None = None) -> tuple[list[dict], dict]:
    """Real OpenSSH background + authentic captured attack instances.

    The background half is built by exactly the calls
    `build_killpoint_corpus` makes, at the same ambient ratio and the same
    seed, so the two arms differ only in the attack lines.
    """
    if not captures:
        raise ValueError("no captured instances to inject")

    rng = random.Random(seed)
    benign, attacker, _users, _subnets = load_classified(source)
    background = build_background(benign, attacker, ambient_ratio, seed)
    if not background:
        raise RuntimeError("empty background -- the corpus did not load")

    days = sorted({event["ts"].date() for event in background})
    day_starts = [datetime(day.year, day.month, day.day) for day in days]

    attacks: list[dict] = []
    for captured in captures:
        attacks += place(captured, rng.choice(day_starts), rng)

    combined = sorted(background + attacks, key=lambda e: e["ts"])

    per_scenario: dict[str, dict] = {}
    for captured in captures:
        entry = per_scenario.setdefault(captured.scenario, {"instances": 0, "lines": 0})
        entry["instances"] += 1
        entry["lines"] += len(captured.lines)

    manifest = {
        "corpus": "loghub-openssh + authentic-kali-capture",
        "benign_lines": len(benign),
        "attacker_lines": len(attacker),
        "ambient_ratio": ambient_ratio,
        "background_lines": len(background),
        "attack_lines": len(attacks),
        "attack_instances": len(captures),
        "per_scenario": per_scenario,
        "total_lines": len(combined),
        "days_covered": len(days),
        "seed": seed,
        "host": CORPUS_HOST,
        "captures": [
            {
                "scenario": c.scenario,
                "instance": c.instance,
                "lines": len(c.lines),
                "span_seconds": round(c.span.total_seconds(), 3),
                "description": c.description,
                "source": c.source,
            }
            for c in captures
        ],
    }
    return combined, manifest


def parse_pairs(values: list[str]) -> list[tuple[str, str]]:
    """`corpus.log:ground_truth.csv`, the same argument shape score_captured.py
    takes, so one set of paths drives both."""
    pairs = []
    for value in values:
        corpus, _, gt = value.partition(":")
        if not gt:
            raise ValueError(f"expected corpus.log:ground_truth.csv, got {value!r}")
        pairs.append((corpus, gt))
    return pairs


def cli() -> None:
    import argparse

    from logdet.config import PROCESSED_DATA_DIR
    from logdet_eval.generate_logs import write_outputs

    parser = argparse.ArgumentParser(
        description="Inject authentic captured attack lines into the real "
                    "OpenSSH benign background.")
    parser.add_argument("pairs", nargs="+", metavar="corpus.log:ground_truth.csv")
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default=f"{PROCESSED_DATA_DIR}/kali_injected")
    args = parser.parse_args()

    captures = load_captures(parse_pairs(args.pairs))
    events, manifest = build_captured_corpus(
        captures, ambient_ratio=args.ambient_ratio, seed=args.seed)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_outputs(events, str(out / "corpus.log"), str(out / "ground_truth.csv"),
                  host=CORPUS_HOST)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    cli()
