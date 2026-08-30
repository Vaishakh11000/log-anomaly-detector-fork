"""
bakeoff.py
Stage 2b -- the live bake-off. Fires attacks into a single running log stream
that this detector and Wazuh are both reading, and scores them against ground
truth the injector already knows.

Why this is one stream and not two runs. The kill point (CLAUDE.md 1b) compared
the two systems by running each over a file; that is a measurement, but it is
not watchable and it cannot be steered by somebody in the room. Here one writer
appends each line to both sinks at the same instant -- the file the detector
service tails, and the file Wazuh's logcollector watches -- so neither system
can be handed a different corpus, and the audience picks what is fired from a
grid of (attack type x camouflage level).

Ground truth is automatic because the injector generated the attack: every line
written is recorded with its 1-based line number and its scenario/instance
label, so both systems reduce to a set of flagged line numbers and go through
the same `scoring.measure_lines` the kill point used.

What is measured and what is only shown
---------------------------------------
Wazuh keys its correlation windows on *arrival* time, not on the timestamp in
the line (Decision Log 2026-08-18). So any run that compresses time is not a
measurement of Wazuh at all -- its drop under `slow` would be zero by
construction. Conditions fired with `compress != 1` are therefore marked
`time_scaled` and reported as illustration, with the real figure living in
`results/killpoint/killpoint_paced_ambient0.05.md`. `compress=1` (the default)
runs in real time and is scored honestly.

Usage:
    logdet-bakeoff --attack brute_force --level rephrase
    logdet-bakeoff --grid --repeat 3
    logdet-bakeoff --benign-only --duration 60
"""

import argparse
import copy
import json
import random
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

import pandas as pd

from logdet.config import DATA_DIR, RESULTS_DIR
from logdet_eval.config import (
    KILLPOINT_BRUTE_FORCE_FAILURES,
    KILLPOINT_ENUMERATION_PROBES,
    KILLPOINT_PROBE_USERNAMES,
    SYNTHETIC_HOST,
    SYNTHETIC_USERS,
)
from logdet_eval import generate_logs, paced_replay, scoring, wazuh_runner
from logdet_eval.adversarial import REALISTIC_COMBO, camouflage_events

DEFAULT_LIVE_LOG = str(DATA_DIR / "live" / "bakeoff.log")

# The grid the examiner picks from. Attack names are plain English on purpose --
# "brute_force" is what goes on a button, "A" is what goes in a results table.
ATTACKS = {
    "brute_force": "A",
    "impossible_travel": "B",
    "enumeration": "C",
}

# Camouflage levels. The first four are timing-independent and are the ones a
# real-time bake-off can score honestly; the last two move events in time and
# are included because a demo that never shows a loss reads as rigged
# (CLAUDE.md Stage 2b), not because this instrument can measure them.
LEVELS = {
    "none": [],
    "mimicry": ["mimicry"],
    "rephrase": ["rephrase"],
    "ip_rotate": ["ip_rotate"],
    "slow": ["slow"],
    "realistic-combo": REALISTIC_COMBO,
}

TIMING_DEPENDENT = {"slow", "temporal", "realistic-combo"}

# Wazuh alert level counted as a detection. Same primary as the kill point, so
# the live numbers sit on the same scale as the recorded ones.
PRIMARY_LEVEL = 3

# After the last line is written: our micro-batch closes on 5s of quiet, and
# analysisd runs ~2s behind the writer with alerts.json flushed after that.
SETTLE_SECONDS = 20.0


# --- Ground truth ----------------------------------------------------------

@dataclass
class WrittenLine:
    """One line as it went onto the wire, with everything needed to score it."""

    line_number: int          # 1-based into this session's stream
    text: str                 # exact bytes both systems saw
    timestamp: datetime
    message: str              # the part after "host process[pid]: "
    scenario: str | None = None
    instance: int | None = None
    user: str | None = None
    description: str | None = None


class Manifest:
    """Every line this session wrote, indexed the two ways it gets looked up.

    Wazuh echoes the whole matched line in `full_log`, so its alerts attribute
    by exact text. Our incidents carry only the parsed `timestamp` and
    `message`, so ours attribute by that pair. Both indexes map to the same
    1-based line numbers, which is what makes one scorer serve both systems.
    """

    def __init__(self) -> None:
        self.lines: list[WrittenLine] = []

    def record(self, text: str, timestamp: datetime, message: str,
               scenario: str | None = None, instance: int | None = None,
               user: str | None = None, description: str | None = None) -> WrittenLine:
        line = WrittenLine(
            line_number=len(self.lines) + 1, text=text, timestamp=timestamp,
            message=message, scenario=scenario, instance=instance,
            user=user, description=description,
        )
        self.lines.append(line)
        return line

    def __len__(self) -> int:
        return len(self.lines)

    def pending_by_text(self) -> dict[str, list[int]]:
        return _pending([(line.text, line.line_number) for line in self.lines])

    def pending_by_key(self) -> dict[tuple[str, str], list[int]]:
        return _pending([(event_key(line.timestamp, line.message), line.line_number)
                         for line in self.lines])

    def ground_truth(self) -> pd.DataFrame:
        """The labelled attack lines, in the schema `scoring.measure_lines` wants."""
        rows = [
            {"line_number": line.line_number, "timestamp": line.timestamp.isoformat(),
             "user": line.user, "scenario": line.scenario, "instance": line.instance,
             "description": line.description}
            for line in self.lines if line.scenario
        ]
        return pd.DataFrame(rows, columns=["line_number", "timestamp", "user",
                                           "scenario", "instance", "description"])


def _pending(pairs) -> dict:
    """Group line numbers by key, newest last, ready to be pop()ed in order.

    Repeated identical lines are real -- a brute force is the same line over and
    over -- so an index has to hand out one line number per alert rather than
    collapsing them, or a burst of 20 would score as a single detected line.
    """
    out: dict = {}
    for key, number in pairs:
        out.setdefault(key, []).append(number)
    for numbers in out.values():
        numbers.reverse()
    return out


def event_key(timestamp: datetime, message: str) -> tuple[str, str]:
    """The (second, message) pair our incidents can be attributed by.

    Syslog carries whole seconds, so this is the finest resolution both sides
    genuinely agree on; sub-second precision would look exact and silently miss.
    """
    return (pd.Timestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"), message.strip())


# --- Sinks -----------------------------------------------------------------

class ListSink:
    """Collects lines in memory. The sink the tests drive."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, text: str) -> None:
        self.lines.append(text)

    def close(self) -> None:
        pass


class FileSink:
    """Appends to the log the detector service tails.

    Flushed per line: the tailer reads by byte offset, and a buffered writer
    would hand it half a line, which parses as garbage and drops an event.
    """

    def __init__(self, path: str | Path, truncate: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "w" if truncate else "a")

    def write(self, text: str) -> None:
        self.handle.write(text + "\n")
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()


class WazuhSink:
    """Appends to the file Wazuh's logcollector watches, inside the container.

    One long-lived `docker exec -i` shell rather than one per line: a container
    exec costs tens of milliseconds, which would put Wazuh's copy of the stream
    measurably behind ours and make arrival-time correlation a property of the
    harness instead of the ruleset.
    """

    def __init__(self, container: str = paced_replay.CONTAINER,
                 log_path: str = paced_replay.REPLAY_LOG) -> None:
        self.container = container
        self.writer = subprocess.Popen(
            ["docker", "exec", "-i", container, "sh", "-c",
             f"while IFS= read -r l; do printf '%s\\n' \"$l\" >> {log_path}; done"],
            stdin=subprocess.PIPE, text=True,
        )

    def write(self, text: str) -> None:
        self.writer.stdin.write(text + "\n")
        self.writer.stdin.flush()

    def close(self) -> None:
        if self.writer.stdin and not self.writer.stdin.closed:
            self.writer.stdin.close()
        self.writer.wait()


class Fanout:
    """Writes one line to every sink before returning.

    Sequential and unbuffered on purpose. The whole claim of a bake-off is that
    both systems saw the same stream; queueing one sink to make the writer
    faster would introduce exactly the skew the claim rules out.
    """

    def __init__(self, sinks: list) -> None:
        self.sinks = sinks

    def write(self, text: str) -> None:
        for sink in self.sinks:
            sink.write(text)

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


# --- Traffic ---------------------------------------------------------------

def restamp(events: list[dict], start: datetime, compress: float = 1.0) -> list[dict]:
    """Move an event list to wall-clock `start`, keeping its internal spacing.

    Both systems have to see the attack *now* -- a line stamped last Tuesday is
    not a live attack to either of them. Relative offsets are preserved rather
    than flattened, so at `compress=1` the log's own time and wall-clock time
    advance together and every window (30-min grouping, 60-min travel, Wazuh's
    120s frequency rules) covers exactly what it covers in a recording.

    `compress > 1` divides the gaps. That is what makes `slow` watchable and it
    is also what stops the run being a measurement -- see the module docstring.
    """
    if not events:
        return []
    events = copy.deepcopy(events)
    origin = min(event["ts"] for event in events)
    for event in events:
        offset = (event["ts"] - origin).total_seconds() / max(compress, 1e-9)
        event["ts"] = start + timedelta(seconds=offset)
    events.sort(key=lambda event: event["ts"])
    return events


def build_attack(attack: str, level: str, seed: int, instance: int = 1,
                 user: str | None = None) -> list[dict]:
    """Generate one labelled attack instance at the requested camouflage level.

    Magnitudes come from the kill point's pre-registered ranges, not v1's, so
    the attack clears the thresholds Wazuh's rules were written for -- judging a
    third-party ruleset on a 4-attempt "brute force" would handicap it exactly
    as writing rules for your own attacks flatters you (CLAUDE.md 8).
    """
    if attack not in ATTACKS:
        raise ValueError(f"unknown attack {attack!r}; choose from {sorted(ATTACKS)}")
    if level not in LEVELS:
        raise ValueError(f"unknown level {level!r}; choose from {sorted(LEVELS)}")

    random.seed(seed)
    day_start = datetime(2026, 1, 1)
    user = user or random.choice(SYNTHETIC_USERS)

    if attack == "brute_force":
        events = generate_logs.gen_scenario_a(
            user, day_start, instance, failures=KILLPOINT_BRUTE_FORCE_FAILURES)
    elif attack == "impossible_travel":
        events = generate_logs.gen_scenario_b(user, day_start, instance)
    else:
        events = generate_logs.gen_scenario_c(
            day_start, instance, probes=KILLPOINT_ENUMERATION_PROBES,
            username_pool=KILLPOINT_PROBE_USERNAMES)

    return camouflage_events(events, LEVELS[level], seed)


class BenignFeed:
    """The quiet background both systems read between firings.

    Drawn from the same generators as the synthetic corpus, so the vocabulary is
    the one the detector was fitted on and "normal" means what it means in every
    number in `results/`. Each line is stamped at the moment it is written: the
    generators lay a whole simulated day out at once, and replaying that day's
    internal gaps would mean waiting hours for the next line.
    """

    def __init__(self, seed: int = 0) -> None:
        self.rng = random.Random(seed)
        self.queue: list[dict] = []

    def next_event(self, now: datetime) -> dict:
        while not self.queue:
            random.seed(self.rng.randrange(1 << 30))
            self.queue = generate_logs.gen_benign_unit(datetime(2026, 1, 1))
        event = self.queue.pop(0)
        event["ts"] = now
        return event


# --- The session -----------------------------------------------------------

@dataclass
class Session:
    """One bake-off: a fanout writer, a manifest, and the clock they share."""

    fanout: Fanout
    manifest: Manifest = field(default_factory=Manifest)
    benign: BenignFeed = field(default_factory=BenignFeed)
    host: str = SYNTHETIC_HOST
    sleeper = staticmethod(time.sleep)
    clock = staticmethod(datetime.now)

    def emit(self, event: dict) -> WrittenLine:
        text = generate_logs.format_line(event, self.host)
        line = self.manifest.record(
            text=text, timestamp=event["ts"], message=event["message"],
            scenario=event.get("scenario"), instance=event.get("instance"),
            user=event.get("user"), description=event.get("description"),
        )
        self.fanout.write(text)
        return line

    def emit_benign(self, count: int, rate: float) -> None:
        """Write `count` background lines at `rate` lines/second."""
        gap = 1.0 / rate if rate > 0 else 0.0
        for index in range(count):
            self.emit(self.benign.next_event(self.clock()))
            if gap and index < count - 1:
                self.sleeper(gap)

    def fire(self, events: list[dict], compress: float = 1.0,
             benign_rate: float = 0.0) -> list[WrittenLine]:
        """Write one attack in wall-clock time, keeping the background running.

        Blocking for the attack's own duration is not a limitation of the
        harness, it is the point: a system that correlates on arrival time can
        only be judged by letting the events actually arrive apart.

        Attack and background are merged into one offset-ordered schedule rather
        than run on two threads, because two writers would interleave lines
        differently for each sink and the two systems would stop seeing an
        identical stream.
        """
        started = self.clock()
        scheduled = restamp(events, started, compress)
        span = (scheduled[-1]["ts"] - started).total_seconds() if scheduled else 0.0

        plan: list[tuple[float, dict | None]] = [
            ((event["ts"] - started).total_seconds(), event) for event in scheduled
        ]
        if benign_rate > 0:
            gap = 1.0 / benign_rate
            offset = gap
            while offset < span:
                plan.append((offset, None))
                offset += gap
        plan.sort(key=lambda item: item[0])

        written: list[WrittenLine] = []
        for offset, event in plan:
            delay = offset - (self.clock() - started).total_seconds()
            if delay > 0:
                self.sleeper(delay)
            now = self.clock()
            if event is None:
                self.emit(self.benign.next_event(now))
            else:
                written.append(self.emit(event))
        return written


# --- Attribution -----------------------------------------------------------

def wazuh_flagged(alerts: list[dict], manifest: Manifest,
                  min_level: int = PRIMARY_LEVEL) -> set[int]:
    """Map Wazuh alerts back to line numbers by the text it echoes."""
    pending = manifest.pending_by_text()
    hits: set[int] = set()
    for alert in alerts:
        if alert.get("rule", {}).get("level", 0) < min_level:
            continue
        numbers = pending.get(alert.get("full_log", ""))
        if numbers:
            hits.add(numbers.pop())
    return hits


def ours_flagged(incidents: list[dict], manifest: Manifest) -> set[int]:
    """Map our incidents back to line numbers by (second, message).

    Incidents carry the parsed event, not the raw line, so the raw text Wazuh is
    attributed by is not available here. The pair is unique enough in practice
    and repeated pairs are consumed in order, the same discipline `_pending`
    applies to Wazuh's repeated lines.
    """
    pending = manifest.pending_by_key()
    hits: set[int] = set()
    for incident in incidents:
        for event in incident.get("events", []):
            timestamp = event.get("timestamp")
            message = event.get("message", "")
            if not timestamp:
                continue
            try:
                key = event_key(pd.Timestamp(timestamp), message)
            except (ValueError, TypeError):
                continue
            numbers = pending.get(key)
            if numbers:
                hits.add(numbers.pop())
    return hits


# --- Running a condition ---------------------------------------------------

@dataclass
class Readers:
    """Where each system's verdicts are read from.

    Injected rather than constructed inside `run_condition` so the scoring path
    can be tested without a service and without a container -- the same reason
    `api_client` exists as a module (Decision Log 2026-08-30).
    """

    incidents: Callable                     # () -> list[dict], our incidents so far
    wazuh_mark: Callable | None = None      # () -> opaque position in alerts.json
    wazuh_since: Callable | None = None     # (mark) -> alerts written after it


def run_condition(session: Session, attack: str, level: str, seed: int,
                  readers: Readers, repeat: int = 1, compress: float = 1.0,
                  benign_rate: float = 0.0, settle: float = SETTLE_SECONDS) -> dict:
    """Fire `repeat` instances of one grid cell and score both systems on them.

    Only the lines this call wrote are scored. The session's manifest keeps
    growing across conditions -- it has to, because line numbers are positions
    in one continuous stream -- so the ground truth is narrowed to this cell's
    instances rather than the whole session's.
    """
    mark = readers.wazuh_mark() if readers.wazuh_mark else None
    first_line = len(session.manifest) + 1

    for index in range(repeat):
        events = build_attack(attack, level, seed + index, instance=index + 1)
        session.fire(events, compress=compress, benign_rate=benign_rate)

    session.sleeper(settle)

    ours = ours_flagged(readers.incidents(), session.manifest)
    alerts = readers.wazuh_since(mark) if readers.wazuh_since else []
    theirs = wazuh_flagged(alerts, session.manifest)

    truth = session.manifest.ground_truth()
    truth = truth[truth["line_number"] >= first_line]
    total = len(session.manifest) - first_line + 1

    return {
        "attack": attack,
        "level": level,
        "seed": seed,
        "repeat": repeat,
        "compress": compress,
        # A compressed run tells Wazuh every event arrived at once, so its score
        # is an artefact of the harness rather than a property of its rules.
        "measured": compress == 1.0 and level not in TIMING_DEPENDENT,
        "lines_written": total,
        "ours": scoring.measure_lines(ours, truth, total),
        "wazuh": scoring.measure_lines(theirs, truth, total, alert_count=len(alerts)),
    }


def differential_vs_baseline(baseline: dict, condition: dict) -> float | None:
    """How much more Wazuh lost to this camouflage than we did.

    The same quantity section 1b is written in, computed live. Returns None when
    either side of the pair is unmeasured, because a differential built on a
    time-scaled run would be a number with no referent.
    """
    if not (baseline.get("measured") and condition.get("measured")):
        return None
    return scoring.differential(
        scoring.instance_drop(baseline["ours"], condition["ours"]),
        scoring.instance_drop(baseline["wazuh"], condition["wazuh"]),
    )


# --- Reporting -------------------------------------------------------------

def _rate(result: dict, system: str) -> str:
    return f"{result[system]['overall']['instance_detection_rate'] * 100:.0f}%"


def _line_rate(result: dict, system: str) -> str:
    return f"{result[system]['overall']['line_detection_rate'] * 100:.0f}%"


def render_report(results: list[dict]) -> str:
    """One table per attack, with the unmeasured rows marked as such."""
    lines = ["# Live bake-off", ""]
    lines.append(f"Fired {len(results)} conditions; "
                 f"{sum(1 for r in results if r['measured'])} measured in real time.")
    lines.append("")
    lines.append("Rows marked `illustration` were fired with time compressed or with a "
                 "timing-based camouflage. Wazuh correlates on arrival time, so its "
                 "score on those rows is fixed by the harness, not by its rules -- the "
                 "measured figures for `slow`, `temporal` and `realistic-combo` are in "
                 "`results/killpoint/killpoint_paced_ambient0.05.md`.")
    lines.append("")

    for attack in dict.fromkeys(result["attack"] for result in results):
        rows = [result for result in results if result["attack"] == attack]
        baseline = next((row for row in rows if row["level"] == "none"), None)
        lines.append(f"## {attack}")
        lines.append("")
        lines.append("| level | ours (inst / lines) | Wazuh (inst / lines) | "
                     "our alerts | Wazuh alerts | differential | |")
        lines.append("|---|---|---|---|---|---|---|")
        for row in rows:
            diff = differential_vs_baseline(baseline, row) if baseline else None
            note = "" if row["measured"] else "illustration"
            lines.append(
                f"| `{row['level']}` | "
                f"{_rate(row, 'ours')} / {_line_rate(row, 'ours')} | "
                f"{_rate(row, 'wazuh')} / {_line_rate(row, 'wazuh')} | "
                f"{row['ours']['overall']['alerts']} | {row['wazuh']['overall']['alerts']} | "
                f"{'--' if diff is None else f'{diff:+.1f}pt'} | {note} |"
            )
        lines.append("")

    lines.append("The differential is computed on **instance** detection, which is the "
                 "quantity section 1b is registered in. Over a handful of live instances "
                 "it saturates -- one instance reads 0% or 100% and nothing in between -- "
                 "so the line rate is shown beside it as the finer-grained evidence of "
                 "the same firing. Pooled figures come from the kill-point runs "
                 "(CLAUDE.md 4), never from a live demo.")
    lines.append("")
    return "\n".join(lines)


# --- CLI -------------------------------------------------------------------

# `GET /incidents` caps a page at 10000 (api.py). A long demo run can exceed
# that, and a silently truncated page would score the tail of the session as
# undetected -- so the reader pages instead of asking for everything at once.
INCIDENT_PAGE_SIZE = 10000


def all_incidents(client, page_size: int = INCIDENT_PAGE_SIZE) -> list[dict]:
    """Every incident the service holds, walked one page at a time."""
    found: list[dict] = []
    while True:
        page = client.incidents(limit=page_size, offset=len(found))
        found.extend(page)
        if len(page) < page_size:
            return found


def build_readers(client, container: str | None) -> Readers:
    """Wire the live readers: our service over HTTP, Wazuh over the container."""
    if container is None:
        return Readers(incidents=lambda: all_incidents(client))
    return Readers(
        incidents=lambda: all_incidents(client),
        wazuh_mark=lambda: paced_replay.alerts_line_count(container),
        wazuh_since=lambda mark: paced_replay.read_alerts(mark, container),
    )


def open_session(live_log: str, container: str | None, host: str = SYNTHETIC_HOST,
                 seed: int = 0) -> Session:
    sinks = [FileSink(live_log, truncate=True)]
    if container is not None:
        sinks.append(WazuhSink(container))
    return Session(fanout=Fanout(sinks), benign=BenignFeed(seed), host=host)


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Stage 2b: fire attacks at this detector and Wazuh on one live stream.")
    parser.add_argument("--attack", choices=sorted(ATTACKS), help="Single condition to fire")
    parser.add_argument("--level", choices=sorted(LEVELS), default="none")
    parser.add_argument("--grid", action="store_true",
                        help="Fire every attack x level in turn")
    parser.add_argument("--levels", nargs="+", choices=sorted(LEVELS),
                        default=["none", "mimicry", "rephrase", "ip_rotate"],
                        help="Levels the grid walks (default: the measurable four)")
    parser.add_argument("--benign-only", action="store_true",
                        help="Quiet baseline: background traffic and nothing else")
    parser.add_argument("--duration", type=float, default=60.0,
                        help="Seconds of background for --benign-only")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Attack instances per condition")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--compress", type=float, default=1.0,
                        help="Divide event gaps by this. Anything but 1 makes the run "
                             "an illustration, not a measurement")
    parser.add_argument("--benign-rate", type=float, default=0.5,
                        help="Background lines per second during a firing")
    parser.add_argument("--settle", type=float, default=SETTLE_SECONDS)
    parser.add_argument("--live-log", default=DEFAULT_LIVE_LOG)
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--no-wazuh", action="store_true",
                        help="Score this detector only. The run is not a bake-off")
    parser.add_argument("--container", default=paced_replay.CONTAINER)
    parser.add_argument("--no-start-stream", action="store_true",
                        help="Assume the service is already tailing --live-log")
    parser.add_argument("--output", default=str(Path(RESULTS_DIR) / "bakeoff"))
    args = parser.parse_args()

    from logdet.api_client import ApiClient, DEFAULT_BASE_URL

    container = None if args.no_wazuh else args.container
    if container is not None and not wazuh_runner.container_available(container):
        # Refusing beats degrading. The kill point's habit of probing once and
        # carrying on detector-only cost whole runs before anyone noticed
        # (CLAUDE.md Known Issues); a bake-off with one contestant is worse,
        # because the table it prints still looks like a comparison.
        raise SystemExit(
            f"Wazuh container {container!r} is not answering. Start it "
            f"(`docker start {container}`), wait ~30s for wazuh-analysisd, or pass --no-wazuh.")

    client = ApiClient(args.api_url or DEFAULT_BASE_URL)
    session = open_session(args.live_log, container, seed=args.seed)

    try:
        if not args.no_start_stream:
            try:
                client.stop_stream()      # a leftover stream would hold the log open
            except Exception:
                pass
            client.start_stream(source="file", path=args.live_log,
                                from_start=True, use_offset_store=False)
            print(f"streaming {args.live_log}")

        if container is not None:
            print("resetting Wazuh correlation state ...")
            paced_replay.reset_correlation_state(container)

        readers = build_readers(client, container)

        if args.benign_only:
            print(f"quiet baseline: {args.duration:.0f}s at {args.benign_rate}/s")
            session.emit_benign(int(args.duration * args.benign_rate), args.benign_rate)
            session.sleeper(args.settle)
            incidents = readers.incidents()
            print(f"{len(session.manifest)} benign lines -> {len(incidents)} incidents")
            return

        if args.grid:
            # --attack narrows the grid to one row, which is what a demo does
            # when the examiner has already picked the attack.
            attacks = [args.attack] if args.attack else sorted(ATTACKS)
            plan = [(attack, level) for attack in attacks for level in args.levels]
        elif args.attack:
            plan = [(args.attack, args.level)]
        else:
            parser.error("choose --attack, --grid or --benign-only")

        results = []
        for attack, level in plan:
            print(f"firing {attack} / {level} x{args.repeat} ...", flush=True)
            result = run_condition(
                session, attack, level, args.seed, readers, repeat=args.repeat,
                compress=args.compress, benign_rate=args.benign_rate, settle=args.settle)
            results.append(result)
            print(f"  ours {_rate(result, 'ours')}  wazuh {_rate(result, 'wazuh')}"
                  f"{'' if result['measured'] else '  (illustration)'}")
    finally:
        session.fanout.close()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "bakeoff.json").write_text(json.dumps(results, indent=2))
    (output / "bakeoff.md").write_text(render_report(results))
    print(f"wrote {output / 'bakeoff.md'}")
