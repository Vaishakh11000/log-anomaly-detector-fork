"""
stream.py
Live ingestion: tail a log file, score new lines in micro-batches against a
detector that was fitted earlier, and grow incidents as events arrive.

This is the streaming half of the fit/score split. Three things make it
different from re-running the batch pipeline on a growing file, and all three
are about *state*:

  - The detector is loaded, never fitted here. Fitting on live traffic would
    let a long-running attack teach the model that it is normal.
  - Impossible travel and incident grouping both compare an event with earlier
    events. A micro-batch of five lines has no such history inside it, so the
    processor keeps a rolling window of recently scored events and judges each
    batch against that window. Evicting a window is what bounds memory; it is
    also the only reason a streamed verdict could ever differ from a batch one.
  - Incidents are grown event by event rather than recomputed, using the same
    link rule the batch grouper uses (`sequence_grouping.linked`), so an
    incident means the same thing on both paths.

The reader's byte offset is written to disk after every batch, so a restart
resumes where it stopped instead of re-alerting on the whole file or silently
skipping whatever arrived while it was down.

Usage:
    logdet-fit --input data/processed/parsed.csv
    logdet-stream --input /var/log/auth.log --follow
    logdet-stream --input data/raw/synthetic.log --from-start --once
"""

import argparse
import json
import time
from pathlib import Path

import pandas as pd

from logdet.anomaly_detection import (
    PerUserAnomalyDetector,
    assign_severity,
    detect_impossible_travel,
)
from logdet.config import (
    DEFAULT_DETECTOR_PATH,
    DEFAULT_OFFSET_STORE,
    GROUP_BY_SOURCE_IP,
    INCIDENT_WINDOW_MINUTES,
    STREAM_BATCH_MAX_LINES,
    STREAM_BATCH_MAX_SECONDS,
    STREAM_POLL_SECONDS,
    STREAM_RETENTION_MINUTES,
)
from logdet.embedding import add_embeddings_to_df
from logdet.preprocessing import LineParser
from logdet.sequence_grouping import linked

# Columns kept in the rolling window. Embeddings are deliberately dropped: they
# are 384 floats per row, they are only needed to score a row once, and holding
# them would make memory grow with the window rather than with the alert rate.
CONTEXT_COLUMNS = [
    "timestamp", "host", "process", "user", "source_ip", "message", "raw",
    "anomaly_score", "is_anomaly", "ml_anomaly", "impossible_travel", "severity",
]


class OffsetStore:
    """Remembers how far into a file the tailer has read.

    Keyed on the file's inode as well as its path: a rotated log keeps the path
    and gets a new inode, and resuming at the old offset would then skip the
    start of the new file.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}   # a corrupt offset file must not stop ingestion

    def save(self, source_path: str | Path, inode: int, offset: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "path": str(source_path),
            "inode": inode,
            "offset": offset,
        }, indent=2))

    def offset_for(self, source_path: str | Path, inode: int) -> int | None:
        """The stored offset, or None if it belongs to a different file."""
        stored = self.load()
        if stored.get("path") != str(source_path) or stored.get("inode") != inode:
            return None
        return stored.get("offset")


class FileTailSource:
    """Yields complete lines appended to a file, without blocking.

    Only whole lines are returned: a partial final line means the writer is
    mid-write, so the offset is left before it and the remainder is read again
    next poll. Advancing past it would split one log line into two.
    """

    def __init__(self, path: str | Path, offset_store: OffsetStore | None = None,
                 from_start: bool = False):
        self.path = Path(path)
        self.offset_store = offset_store
        self.from_start = from_start
        self._offset = 0
        self._inode: int | None = None
        self._opened = False

    def _open(self) -> None:
        stat = self.path.stat()
        self._inode = stat.st_ino
        resumed = (self.offset_store.offset_for(self.path, self._inode)
                   if self.offset_store else None)

        if resumed is not None and resumed <= stat.st_size:
            self._offset = resumed
        elif self.from_start:
            self._offset = 0
        else:
            self._offset = stat.st_size   # follow: only what arrives from now on
        self._opened = True

    def read_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        if not self._opened:
            self._open()

        stat = self.path.stat()
        if stat.st_ino != self._inode or stat.st_size < self._offset:
            # rotated, or truncated in place -- start the new file from the top
            self._inode = stat.st_ino
            self._offset = 0

        if stat.st_size == self._offset:
            return []

        with open(self.path, "r", errors="ignore") as f:
            f.seek(self._offset)
            data = f.read()

        lines = data.splitlines(keepends=True)
        complete = [line for line in lines if line.endswith("\n")]
        consumed = sum(len(line) for line in complete)
        self._offset += consumed
        return [line.rstrip("\n") for line in complete]

    def commit(self) -> None:
        """Persist the read position. Called after a batch is fully scored, so
        a crash mid-batch replays that batch rather than losing it."""
        if self.offset_store and self._inode is not None:
            self.offset_store.save(self.path, self._inode, self._offset)


class IterableSource:
    """Wraps a list or generator of lines. Used by tests and by replay."""

    def __init__(self, lines, chunk_size: int = 1_000_000):
        self._lines = list(lines)
        self._chunk_size = chunk_size

    def read_lines(self) -> list[str]:
        chunk, self._lines = self._lines[:self._chunk_size], self._lines[self._chunk_size:]
        return chunk

    def commit(self) -> None:
        pass


class MicroBatcher:
    """Accumulates lines and closes a batch on whichever limit trips first.

    Count alone would stall a half-full batch forever on a quiet log -- the
    alert would arrive whenever the next burst happened to come. Time alone
    would score one line at a time during a burst, which wastes the embedding
    model's batching entirely. The clock is injectable so tests do not sleep.
    """

    def __init__(self, max_lines: int = STREAM_BATCH_MAX_LINES,
                 max_seconds: float = STREAM_BATCH_MAX_SECONDS,
                 time_fn=time.monotonic):
        self.max_lines = max_lines
        self.max_seconds = max_seconds
        self._time = time_fn
        self._buffer: list[str] = []
        self._opened_at = self._time()

    def add(self, lines) -> None:
        if not self._buffer and lines:
            self._opened_at = self._time()
        self._buffer.extend(lines)

    def should_flush(self) -> bool:
        if not self._buffer:
            return False
        if len(self._buffer) >= self.max_lines:
            return True
        return (self._time() - self._opened_at) >= self.max_seconds

    def flush(self) -> list[str]:
        batch, self._buffer = self._buffer[:self.max_lines], self._buffer[self.max_lines:]
        self._opened_at = self._time()
        return batch

    def pending(self) -> int:
        return len(self._buffer)


class IncidentTracker:
    """Grows incidents event by event, with batch-identical link semantics.

    Batch grouping is transitive -- A links to B, B links to C, so all three are
    one incident even where A and C share nothing. That is preserved here by
    merging incidents whenever a new event links to more than one of them.

    An incident closes once the log clock has moved past its last event by more
    than the window: nothing arriving after that can link to it, so it will
    never change again and can be reported as final.
    """

    def __init__(self, window_minutes: int = INCIDENT_WINDOW_MINUTES,
                 group_by_source_ip: bool = GROUP_BY_SOURCE_IP):
        self.window = pd.Timedelta(minutes=window_minutes)
        self.group_by_source_ip = group_by_source_ip
        self._next_id = 0
        self.incidents: dict[int, dict] = {}      # id -> {"events": [...], "last_ts": ts}
        self._recent: list[tuple[dict, int]] = []  # (event, incident id) inside the window

    def add(self, event: dict) -> int:
        """File one anomalous event; returns the incident id it landed in."""
        ts = event["timestamp"]
        matches = {
            incident_id for prior, incident_id in self._recent
            if abs(ts - prior["timestamp"]) <= self.window
            and linked(event, prior, self.group_by_source_ip)
        }

        if not matches:
            incident_id = self._next_id
            self._next_id += 1
            self.incidents[incident_id] = {"events": [], "last_ts": ts}
        else:
            incident_id = min(matches)
            for other in matches - {incident_id}:
                merged = self.incidents.pop(other)
                self.incidents[incident_id]["events"].extend(merged["events"])
                self.incidents[incident_id]["last_ts"] = max(
                    self.incidents[incident_id]["last_ts"], merged["last_ts"])
                self._recent = [(e, incident_id if i == other else i)
                                for e, i in self._recent]

        incident = self.incidents[incident_id]
        incident["events"].append(event)
        incident["events"].sort(key=lambda e: e["timestamp"])
        incident["last_ts"] = max(incident["last_ts"], ts)
        self._recent.append((event, incident_id))
        return incident_id

    def prune_recent(self, now: pd.Timestamp) -> None:
        """Drop events too old to link to anything arriving next."""
        self._recent = [(e, i) for e, i in self._recent
                        if now - e["timestamp"] <= self.window]

    def closed_before(self, now: pd.Timestamp) -> list[int]:
        """Incident ids that can no longer change, removed from the tracker."""
        closed = [i for i, inc in self.incidents.items()
                  if now - inc["last_ts"] > self.window]
        for incident_id in closed:
            self.incidents.pop(incident_id)
        self._recent = [(e, i) for e, i in self._recent if i not in closed]
        return closed

    def drain(self) -> list[int]:
        """Close everything -- called at shutdown so no incident is lost."""
        remaining = sorted(self.incidents)
        self.incidents.clear()
        self._recent.clear()
        return remaining


class StreamProcessor:
    """Scores micro-batches against a pre-fitted detector and emits incidents."""

    def __init__(self, detector: PerUserAnomalyDetector,
                 retention_minutes: int = STREAM_RETENTION_MINUTES,
                 window_minutes: int = INCIDENT_WINDOW_MINUTES,
                 year: int | None = None):
        self.detector = detector
        self.retention = pd.Timedelta(minutes=retention_minutes)
        self.parser = LineParser(year=year)
        self.tracker = IncidentTracker(window_minutes=window_minutes)
        self.history: pd.DataFrame | None = None
        self.lines_seen = 0
        self.lines_parsed = 0
        # Snapshots of every incident emitted, so a closed one can be reported
        # in full even after its events have left the rolling window.
        self._emitted: dict[int, dict] = {}

    # -- scoring -------------------------------------------------------------

    def _score(self, df: pd.DataFrame) -> pd.DataFrame:
        """ML score + impossible travel + severity, judged against history."""
        scored = self.detector.score(df)

        # Impossible travel compares a login with that user's previous one, so
        # the batch alone is not enough context -- prepend the rolling window
        # and keep only the new rows' verdicts.
        if self.history is not None and len(self.history):
            combined = pd.concat([self.history, scored], ignore_index=True)
            combined = detect_impossible_travel(combined)
            scored = combined.tail(len(scored)).copy()
        else:
            scored = detect_impossible_travel(scored)

        scored["ml_anomaly"] = scored["is_anomaly"]
        scored["is_anomaly"] = scored["ml_anomaly"] | scored["impossible_travel"]
        return assign_severity(scored)

    def _remember(self, scored: pd.DataFrame) -> None:
        keep = scored[[c for c in CONTEXT_COLUMNS if c in scored.columns]]
        self.history = keep if self.history is None else pd.concat(
            [self.history, keep], ignore_index=True)
        newest = self.history["timestamp"].max()
        if pd.notna(newest):
            self.history = self.history[
                self.history["timestamp"] >= newest - self.retention].reset_index(drop=True)

    # -- incidents -----------------------------------------------------------

    def _snapshot(self, incident_id: int, status: str) -> dict:
        from logdet.pipeline import build_incident_entry   # local: avoids a cycle

        events = self.tracker.incidents[incident_id]["events"]
        entry = build_incident_entry(incident_id, pd.DataFrame(events))
        entry["status"] = status
        self._emitted[incident_id] = entry
        return entry

    def process(self, lines: list[str]) -> list[dict]:
        """Score one micro-batch; return the incidents it created or changed."""
        self.lines_seen += len(lines)
        records = self.parser.parse_many(lines)
        self.lines_parsed += len(records)
        if not records:
            return []

        df = pd.DataFrame(records).dropna(subset=["timestamp"])
        if df.empty:
            return []

        df = add_embeddings_to_df(df, template_col="template")
        scored = self._score(df)
        self._remember(scored)

        anomalies = scored[scored["is_anomaly"]].sort_values("timestamp")
        touched: list[int] = []
        for _, row in anomalies.iterrows():
            incident_id = self.tracker.add(row.to_dict())
            if incident_id not in touched:
                touched.append(incident_id)

        # Snapshot before closing: closing removes an incident from the tracker,
        # and the snapshot is built from the tracker's event list.
        for incident_id in touched:
            self._snapshot(incident_id, "open")

        now = scored["timestamp"].max()
        self.tracker.prune_recent(now)
        closed = self.tracker.closed_before(now)
        for incident_id in closed:
            if incident_id in self._emitted:
                self._emitted[incident_id]["status"] = "closed"

        # One emission per incident per batch. An incident that is created and
        # closed inside the same batch is reported once, as closed -- emitting
        # it as open first would be an alert that was already stale when it
        # printed.
        order = touched + [i for i in closed if i not in touched]
        return [self._emitted[i] for i in order if i in self._emitted]

    def drain(self) -> list[dict]:
        """Mark every still-open incident closed. Call once at shutdown."""
        final = []
        for incident_id in self.tracker.drain():
            entry = self._emitted.get(incident_id)
            if entry is not None:
                entry["status"] = "closed"
                final.append(entry)
        return final


def run_stream(source, processor: StreamProcessor, once: bool = False,
               batcher: MicroBatcher | None = None,
               poll_seconds: float = STREAM_POLL_SECONDS,
               on_incident=None, sleep_fn=time.sleep) -> list[dict]:
    """Poll a source, score whole micro-batches, hand incidents to a callback.

    `once` drains what is already there and stops -- that is replay-a-file mode
    and what the tests use. Without it this follows the file indefinitely.
    """
    batcher = batcher or MicroBatcher()
    emitted: list[dict] = []

    def emit(incidents):
        for incident in incidents:
            emitted.append(incident)
            if on_incident:
                on_incident(incident)

    while True:
        arrived = source.read_lines()
        batcher.add(arrived)

        # `once` also flushes a part-full batch: there is no later traffic to
        # complete it, and leaving the tail unscored would silently drop lines.
        while batcher.should_flush() or (once and batcher.pending()):
            emit(processor.process(batcher.flush()))
            source.commit()

        if once:
            if not arrived and not batcher.pending():
                break
            continue

        sleep_fn(poll_seconds)

    emit(processor.drain())
    return emitted


def _format_alert(incident: dict) -> str:
    techniques = ", ".join(t["technique_id"] for t in incident["mitre_techniques"]) or "-"
    return (f"[{incident['status']:>6}] incident {incident['incident_id']:>4} "
            f"{incident['severity']:>6} | {incident['summary']} | MITRE: {techniques}")


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Score a live log file in micro-batches against a fitted detector.")
    parser.add_argument("--input", required=True, help="Log file to tail")
    parser.add_argument("--detector", default=DEFAULT_DETECTOR_PATH,
                        help="Detector saved by logdet-fit")
    parser.add_argument("--output", help="Append emitted incidents here as JSON lines")
    parser.add_argument("--offset-store", default=DEFAULT_OFFSET_STORE,
                        help="Where the read position is recorded between runs")
    parser.add_argument("--from-start", action="store_true",
                        help="Read the whole file, not only lines appended from now on")
    parser.add_argument("--once", action="store_true",
                        help="Score what is already in the file, then exit (replay mode)")
    parser.add_argument("--follow", action="store_true",
                        help="Keep tailing (the default unless --once is given)")
    parser.add_argument("--no-offset-store", action="store_true",
                        help="Do not record or resume a read position")
    parser.add_argument("--batch-lines", type=int, default=STREAM_BATCH_MAX_LINES)
    parser.add_argument("--batch-seconds", type=float, default=STREAM_BATCH_MAX_SECONDS)
    parser.add_argument("--narrate", action="store_true",
                        help="Generate an LLM narrative for closed high-severity incidents")
    args = parser.parse_args()

    detector = PerUserAnomalyDetector.load(args.detector)
    print(f"Loaded detector: {len(detector.models)} per-user models, "
          f"{detector.embedding_dim}-d embeddings from '{detector.embedding_model}'")

    store = None if args.no_offset_store else OffsetStore(args.offset_store)
    source = FileTailSource(args.input, offset_store=store,
                            from_start=args.from_start or args.once)
    processor = StreamProcessor(detector)
    batcher = MicroBatcher(max_lines=args.batch_lines, max_seconds=args.batch_seconds)

    out = open(args.output, "a") if args.output else None

    def on_incident(incident: dict) -> None:
        if args.narrate and incident["status"] == "closed":
            from logdet.llm_narrative import generate_narrative
            from logdet.pipeline import should_narrate
            if should_narrate(incident["severity"], incident["event_count"]):
                try:
                    incident["narrative"] = generate_narrative(pd.DataFrame(incident["events"]))
                except Exception as exc:
                    incident["narrative"] = f"[LLM narrative generation failed: {exc}]"
        print(_format_alert(incident), flush=True)
        if out:
            out.write(json.dumps(incident, default=str) + "\n")
            out.flush()

    print(f"Streaming {args.input} "
          f"({'replay, then exit' if args.once else 'following'}); Ctrl-C to stop")
    try:
        run_stream(source, processor, once=args.once, batcher=batcher,
                   on_incident=on_incident)
    except KeyboardInterrupt:
        for incident in processor.drain():
            on_incident(incident)
    finally:
        if out:
            out.close()
        print(f"Read {processor.lines_seen} lines, parsed {processor.lines_parsed}")


if __name__ == "__main__":
    cli()
