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
    logdet-bakeoff --grid --repeat 5
    logdet-bakeoff --benign-only --duration 60

The same grid, driven by whoever is in the room, is
`streamlit run src/logdet_eval/bakeoff_dashboard.py`.
"""

import argparse
import copy
import json
import random
import subprocess
import threading
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

    The lock is what lets a second thread write background traffic while a
    firing is in progress (the grid page keeps the quiet stream running between
    cells). Without it two threads could interleave *between* sinks -- our file
    getting line A then B while the container got B then A -- which is the one
    thing this class exists to prevent.
    """

    def __init__(self, sinks: list) -> None:
        self.sinks = sinks
        self.lock = threading.Lock()

    def write(self, text: str) -> None:
        with self.lock:
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
    # Held across "take the next line number" and "write the line". The grid
    # page keeps background traffic flowing on a second thread, and a line
    # numbered on one thread but written after a line numbered later on another
    # would put the manifest -- which *is* the ground truth -- out of step with
    # what both systems actually read.
    lock: threading.Lock = field(default_factory=threading.Lock)
    sleeper = staticmethod(time.sleep)
    clock = staticmethod(datetime.now)

    def emit(self, event: dict) -> WrittenLine:
        with self.lock:
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


def run_instance(session: Session, attack: str, level: str, seed: int,
                 readers: Readers, instance: int = 1, compress: float = 1.0,
                 benign_rate: float = 0.0, settle: float = SETTLE_SECONDS) -> dict:
    """Fire one attack instance and score both systems on the lines it wrote.

    Only the lines this call wrote are scored. The session's manifest keeps
    growing -- it has to, because line numbers are positions in one continuous
    stream -- so the ground truth is narrowed to this instance rather than the
    whole session's.
    """
    mark = readers.wazuh_mark() if readers.wazuh_mark else None
    first_line = len(session.manifest) + 1

    events = build_attack(attack, level, seed, instance=instance)
    session.fire(events, compress=compress, benign_rate=benign_rate)
    session.sleeper(settle)

    ours = ours_flagged(readers.incidents(), session.manifest)
    alerts = readers.wazuh_since(mark) if readers.wazuh_since else []
    theirs = wazuh_flagged(alerts, session.manifest)

    truth = session.manifest.ground_truth()
    truth = truth[truth["line_number"] >= first_line]
    total = len(session.manifest) - first_line + 1

    return {
        "seed": seed,
        "instance": instance,
        "lines_written": total,
        "ours": scoring.measure_lines(ours, truth, total),
        "wazuh": scoring.measure_lines(theirs, truth, total, alert_count=len(alerts)),
    }


def run_condition(session: Session, attack: str, level: str, seed: int,
                  readers: Readers, repeat: int = 1, compress: float = 1.0,
                  benign_rate: float = 0.0, settle: float = SETTLE_SECONDS,
                  on_instance: Callable | None = None) -> dict:
    """Fire `repeat` instances of one grid cell and pool their scores.

    Each instance is fired at its own seed and scored on its own, then the runs
    are pooled with `scoring.pool_runs` -- the same pooler the kill point uses,
    which recomputes rates from summed counts rather than averaging them, so an
    instance that happens to produce fewer attack lines does not get equal
    weight.

    Pooling is the point of `repeat`. Instance detection over a single instance
    reads 0% or 100% and nothing in between, so the registered differential
    (CLAUDE.md 1b) computes to +0.0pt live no matter what either system did.
    `repeat=n` makes the finest visible step 100/n points; the report prints
    that step so nobody reads a live figure as if it were a pooled kill-point
    one. It is still not admissible under CLAUDE.md 4 -- that wants >=5 seeds
    on the recorded corpus, not a handful of firings in a demo room.
    """
    runs = []
    for index in range(repeat):
        run = run_instance(session, attack, level, seed + index, readers,
                           instance=index + 1, compress=compress,
                           benign_rate=benign_rate, settle=settle)
        runs.append(run)
        if on_instance:
            on_instance(index + 1, repeat, run)

    pooled_ours = scoring.pool_runs([run["ours"] for run in runs])
    pooled_wazuh = scoring.pool_runs([run["wazuh"] for run in runs])
    total = sum(run["lines_written"] for run in runs)
    for pooled in (pooled_ours, pooled_wazuh):
        pooled["overall"]["total_lines"] = total

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
        "ours": pooled_ours,
        "wazuh": pooled_wazuh,
        "runs": runs,
    }


def run_benign_baseline(session: Session, readers: Readers, count: int, rate: float,
                        settle: float = SETTLE_SECONDS) -> dict:
    """Act 1: background traffic and nothing else, scored on both systems.

    No attack is fired, so the ground truth is that *every* line is benign and
    every alert either system raises is a false positive. That makes this the
    one act where the number is directly comparable without a camouflage level
    attached, and it is the act the demo opens with -- so it needs an artifact
    like the attack acts have, rather than a line printed to a terminal that
    scrolls away.
    """
    mark = readers.wazuh_mark() if readers.wazuh_mark else None
    first_line = len(session.manifest) + 1
    started = session.clock()

    session.emit_benign(count, rate)
    session.sleeper(settle)

    incidents = readers.incidents()
    ours = {line for line in ours_flagged(incidents, session.manifest)
            if line >= first_line}
    alerts = readers.wazuh_since(mark) if readers.wazuh_since else []
    theirs = {line for line in wazuh_flagged(alerts, session.manifest)
              if line >= first_line}

    total = len(session.manifest) - first_line + 1
    ours_incidents = [incident for incident in incidents
                      if any(line >= first_line for line in
                             ours_flagged([incident], session.manifest))]

    def share(flagged: set[int]) -> float:
        return round(len(flagged) / total, 4) if total else 0.0

    return {
        "act": "benign_baseline",
        "lines_written": total,
        "benign_rate": rate,
        "elapsed_seconds": round((session.clock() - started).total_seconds(), 1),
        "measured": True,
        "ours": {"flagged_lines": len(ours), "false_positive_rate": share(ours),
                 "incidents": len(ours_incidents)},
        "wazuh": {"flagged_lines": len(theirs), "false_positive_rate": share(theirs),
                  "alerts": len(alerts)},
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


# --- Driving the grid from a UI --------------------------------------------

class BackgroundTraffic:
    """Keeps the quiet stream running between firings, on its own thread.

    Act 1 of the demo is a stream with nothing happening in it, and a stream
    that stops between clicks is not that -- both systems would be idle, the
    detector's "seconds since last batch" would climb, and the audience would
    be looking at a dead log rather than a quiet one.
    """

    def __init__(self, session: Session, rate: float = 0.5) -> None:
        self.session = session
        self.rate = rate
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running or self.rate <= 0:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        gap = 1.0 / self.rate
        while not self._stop.wait(gap):
            self.session.emit(self.session.benign.next_event(self.session.clock()))

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        self._thread = None


class GridRunner:
    """Owns one bake-off session and fires grid cells on a worker thread.

    The page the examiner clicks cannot fire a condition inline: a real-time
    firing takes as long as the attack takes, plus the settle window, and a
    Streamlit script that blocks for two minutes stops repainting -- so the
    live incident counts, the stream health and the progress of the firing all
    freeze at exactly the moment somebody is watching them.

    One firing at a time. Two overlapping attacks would share a stream and a
    manifest, and each condition scores the lines *it* wrote by line number, so
    a second firing's lines landing inside the first one's range would be
    counted as undetected attack lines for the wrong cell.
    """

    def __init__(self, session: Session, readers: Readers, repeat: int = 1,
                 compress: float = 1.0, benign_rate: float = 0.5,
                 settle: float = SETTLE_SECONDS) -> None:
        self.session = session
        self.readers = readers
        self.repeat = repeat
        self.compress = compress
        self.settle = settle
        self.background = BackgroundTraffic(session, benign_rate)
        self.results: list[dict] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._state: dict = {"busy": False, "attack": None, "level": None,
                             "instance": 0, "repeat": repeat, "error": None}

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def fire(self, attack: str, level: str, seed: int = 1,
             repeat: int | None = None) -> bool:
        """Start one grid cell. False means a firing is already in flight."""
        if self.busy:
            return False
        if attack not in ATTACKS or level not in LEVELS:
            raise ValueError(f"not a grid cell: {attack!r} x {level!r}")
        repeat = repeat or self.repeat
        self._set(busy=True, attack=attack, level=level, instance=0,
                  repeat=repeat, error=None)
        self._thread = threading.Thread(
            target=self._run, args=(attack, level, seed, repeat), daemon=True)
        self._thread.start()
        return True

    def _run(self, attack: str, level: str, seed: int, repeat: int) -> None:
        try:
            result = run_condition(
                self.session, attack, level, seed, self.readers, repeat=repeat,
                compress=self.compress,
                # The background thread is already writing the quiet stream, so
                # the firing must not write its own or the demo would run at
                # twice the background rate whenever an attack is in flight.
                benign_rate=0.0 if self.background.running else self.background.rate,
                settle=self.settle,
                on_instance=lambda index, total, run: self._set(instance=index),
            )
            with self._lock:
                self.results.append(result)
        except Exception as exc:                      # noqa: BLE001 -- surfaced, not swallowed
            self._set(error=f"{type(exc).__name__}: {exc}")
        finally:
            self._set(busy=False)

    def _set(self, **fields) -> None:
        with self._lock:
            self._state.update(fields)

    def state(self) -> dict:
        """A snapshot the page can render without holding the lock."""
        with self._lock:
            return dict(self._state, results=len(self.results))

    def close(self) -> None:
        self.background.stop()
        if self._thread:
            self._thread.join(timeout=1.0)
        self.session.fanout.close()


# --- Reporting -------------------------------------------------------------

def instance_cell(result: dict, system: str) -> str:
    """Instance detection with its denominator attached.

    The denominator is not decoration: "100%" over one instance and "100%" over
    five are the same string and wildly different evidence, and this number is
    the one the registered differential is computed from.
    """
    overall = result[system]["overall"]
    text = f"{overall['instance_detection_rate'] * 100:.0f}%"
    if overall.get("instances"):
        text += f" ({overall['instances_detected']}/{overall['instances']})"
    return text


def line_cell(result: dict, system: str) -> str:
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
                f"{instance_cell(row, 'ours')} / {line_cell(row, 'ours')} | "
                f"{instance_cell(row, 'wazuh')} / {line_cell(row, 'wazuh')} | "
                f"{row['ours']['overall']['alerts']} | {row['wazuh']['overall']['alerts']} | "
                f"{'--' if diff is None else f'{diff:+.1f}pt'} | {note} |"
            )
        lines.append("")

    lines.append(f"The differential is computed on **instance** detection, which is the "
                 f"quantity section 1b is registered in. Instances per condition here: "
                 f"{instances_note(results)}, so the finest step the live differential "
                 f"can take is {resolution(results)}. The line rate is shown beside it "
                 f"as the finer-grained evidence of the same firing. Admissible pooled "
                 f"figures come from the kill-point runs over >=5 seeds (CLAUDE.md 4), "
                 f"never from a live demo.")
    note = ceiling_note(results)
    if note:
        lines.append("")
        lines.append(note)
    lines.append("")
    return "\n".join(lines)


def ceiling_note(results: list[dict]) -> str:
    """Say so when every measured row detected every instance.

    A +0.0pt differential has two completely different causes and the table
    cannot tell them apart. One is granularity -- too few instances for the
    metric to move -- which more repeats fix. The other is the ceiling: both
    systems found every instance in every condition, so neither dropped, and no
    number of repeats changes that. Leaving the reader to guess which one they
    are looking at is how a live table gets over-read.
    """
    measured = [result for result in results if result.get("measured")]
    if len(measured) < 2:
        return ""
    at_ceiling = all(
        result[system]["overall"]["instance_detection_rate"] == 1.0
        for result in measured for system in ("ours", "wazuh")
    )
    if not at_ceiling:
        return ""
    return ("Both systems detected **every instance in every measured condition**, so "
            "both drops are zero and the differential is +0.0pt by arithmetic rather "
            "than by a tie in robustness. More repeats cannot move it: one surviving "
            "line is enough to call an instance detected, and at these magnitudes "
            "(15-25 failures, 10-12 probes) rewording never removes them all. What "
            "separates the two systems here is the *share of the attack's lines* each "
            "one flagged, which is the column beside it.")


def instances_pooled(result: dict) -> int:
    """How many attack instances this condition's numbers were pooled over."""
    return int(result["ours"]["overall"].get("instances") or result.get("repeat", 1))


def instances_note(results: list[dict]) -> str:
    counts = sorted({instances_pooled(result) for result in results})
    return ", ".join(str(count) for count in counts) or "0"


def resolution(results: list[dict]) -> str:
    """The smallest non-zero differential this run could have produced.

    Instance detection moves in 100/n point steps, so a run of one instance can
    only ever report +0.0pt or +/-100pt -- which is why the first live firing
    (2026-08-30) reported +0.0pt on every row and said nothing. Printing the
    step keeps a reader from mistaking a coarse live number for a pooled one.
    """
    counts = [instances_pooled(result) for result in results] or [1]
    return f"{100 / max(counts):.0f}pt"


def render_baseline_report(result: dict) -> str:
    """Act 1 as a page: what each system says when nothing is happening."""
    total = result["lines_written"] or 1
    ours, wazuh = result["ours"], result["wazuh"]
    return "\n".join([
        "# Live bake-off -- Act 1, the quiet baseline",
        "",
        f"{result['lines_written']} benign lines at {result['benign_rate']}/s over "
        f"{result['elapsed_seconds']:.0f}s. **No attack was fired**, so every line is "
        f"benign by construction and every alert below is a false positive.",
        "",
        "| system | lines flagged | share of the stream | alerts |",
        "|---|---|---|---|",
        f"| this detector | {ours['flagged_lines']} | "
        f"{ours['flagged_lines'] / total * 100:.0f}% | "
        f"{ours['flagged_lines']} in {ours['incidents']} incidents |",
        f"| Wazuh (level >={PRIMARY_LEVEL}) | {wazuh['flagged_lines']} | "
        f"{wazuh['flagged_lines'] / total * 100:.0f}% | {wazuh['alerts']} |",
        "",
        f"Wazuh is counted at level >={PRIMARY_LEVEL}, the kill point's primary level, "
        f"where a single successful login is already an alert (rule 5715) -- so its "
        f"count here is what saturation looks like on quiet traffic, not a failure of "
        f"its rules. Ours is the precision weakness this project has carried since v1 "
        f"(CLAUDE.md Known Issues), seen with no attack present at all.",
        "",
        "This is one short run at one background rate, not a false-positive rate for "
        "either system. The recorded alert volumes are in "
        "`results/killpoint/killpoint_ambient0.05.md`.",
        "",
    ])


def merge_runs(sources: list[Path]) -> list[dict]:
    """Load several invocations' results into one ordered table.

    The 18-cell grid was fired in five invocations, because firing the whole of
    it in real time takes hours and a run that dies takes everything with it.
    The merged report was then assembled by a throwaway script, which left the
    committed table with no generator -- the one artifact in `results/` nobody
    could reproduce. This is that generator.

    Each row keeps the directory it came from, and a cell fired twice is
    refused rather than silently resolved: the table holds one row per
    (attack, level), and choosing which of two firings that row is belongs to
    whoever fired them, not to a sort order.
    """
    merged: dict[tuple[str, str], dict] = {}
    for source in sources:
        path = source / "bakeoff.json" if source.is_dir() else source
        for result in json.loads(path.read_text()):
            cell = (result["attack"], result["level"])
            if cell in merged:
                raise ValueError(
                    f"{cell[0]} / {cell[1]} was fired in both "
                    f"{merged[cell]['source']} and {source}. The table holds one row "
                    f"per cell -- pass whichever firing you mean to report.")
            merged[cell] = dict(result, source=str(source))

    order = {(attack, level): (a, l)
             for a, attack in enumerate(ATTACKS)
             for l, level in enumerate(LEVELS)}
    unknown = (len(ATTACKS), len(LEVELS))
    return [merged[cell] for cell in sorted(merged, key=lambda c: order.get(c, unknown))]


def invocation(results: list[dict], source: str) -> str:
    """The `logdet-bakeoff` command that produced one source directory.

    Derived from the rows themselves rather than recorded, so it cannot drift
    away from what the JSON beside it actually contains.
    """
    rows = [result for result in results if result["source"] == source]
    attacks = list(dict.fromkeys(row["attack"] for row in rows))
    levels = list(dict.fromkeys(row["level"] for row in rows))
    parts = ["logdet-bakeoff", "--grid"]
    if len(attacks) == 1:
        parts += ["--attack", attacks[0]]
    parts += ["--levels", *levels]
    parts += ["--repeat", str(rows[0].get("repeat", 1))]
    if rows[0].get("seed", 1) != 1:
        parts += ["--seed", str(rows[0]["seed"])]
    if rows[0].get("compress", 1.0) != 1.0:
        parts += ["--compress", f"{rows[0]['compress']:g}"]
    parts += ["--output", source]
    return " ".join(parts)


def provenance_section(results: list[dict]) -> str:
    """How the merged table was fired, and how to rebuild it from the JSON."""
    sources = list(dict.fromkeys(result["source"] for result in results))
    commands = [invocation(results, source) for source in sources]
    merge = "logdet-bakeoff --merge " + " ".join(sources)
    return "\n".join([
        "## How this table was produced",
        "",
        f"The {len(results)} cells came from {len(sources)} `logdet-bakeoff` "
        f"invocation{'s' if len(sources) != 1 else ''}, not one, so line numbers restart "
        f"per invocation and each cell is scored only on the lines it wrote:",
        "",
        "```",
        *commands,
        "```",
        "",
        "The per-invocation JSON is kept beside this file, and this report is "
        "regenerated from it -- no hand assembly:",
        "",
        "```",
        merge,
        "```",
        "",
    ])


def render_merged_report(results: list[dict], notes: str = "") -> str:
    """The merged table, its provenance, and any hand-written reading appended.

    The tables and the provenance are computed; the interpretation is not, and
    pretending otherwise would either lose the reading or invite a generator
    that writes conclusions. So the prose lives in a file passed with --notes
    and is appended verbatim.
    """
    parts = [render_report(results), provenance_section(results)]
    if notes.strip():
        parts.append(notes.strip() + "\n")
    return "\n".join(parts)


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
    parser.add_argument("--repeat", type=int, default=3,
                        help="Attack instances per condition, pooled. One instance "
                             "makes instance detection read 0%% or 100%%, so the "
                             "differential is +0.0pt whatever happened; n instances "
                             "make the finest step 100/n points (default: 3)")
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
    parser.add_argument("--merge", nargs="+", metavar="DIR",
                        help="Fire nothing: rebuild one report from the bakeoff.json "
                             "of each directory given. The whole grid takes hours in "
                             "real time, so it is fired in several invocations and "
                             "merged afterwards")
    parser.add_argument("--notes", metavar="FILE",
                        help="Markdown appended verbatim to a --merge report. The "
                             "tables are computed; the reading of them is not")
    args = parser.parse_args()

    if args.merge:
        results = merge_runs([Path(source) for source in args.merge])
        notes = Path(args.notes).read_text() if args.notes else ""
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "bakeoff.json").write_text(json.dumps(results, indent=2))
        (output / "bakeoff.md").write_text(render_merged_report(results, notes))
        print(f"merged {len(results)} cells from {len(args.merge)} runs "
              f"-> {output / 'bakeoff.md'}")
        return

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
            baseline = run_benign_baseline(
                session, readers, int(args.duration * args.benign_rate),
                args.benign_rate, settle=args.settle)
            output = Path(args.output)
            output.mkdir(parents=True, exist_ok=True)
            (output / "benign_baseline.json").write_text(json.dumps(baseline, indent=2))
            (output / "benign_baseline.md").write_text(render_baseline_report(baseline))
            print(f"{baseline['lines_written']} benign lines -> "
                  f"ours {baseline['ours']['flagged_lines']} lines in "
                  f"{baseline['ours']['incidents']} incidents, "
                  f"wazuh {baseline['wazuh']['flagged_lines']} lines")
            print(f"wrote {output / 'benign_baseline.md'}")
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
            print(f"  ours {instance_cell(result, 'ours')}  wazuh {instance_cell(result, 'wazuh')}"
                  f"{'' if result['measured'] else '  (illustration)'}")
    finally:
        session.fanout.close()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "bakeoff.json").write_text(json.dumps(results, indent=2))
    (output / "bakeoff.md").write_text(render_report(results))
    print(f"wrote {output / 'bakeoff.md'}")
