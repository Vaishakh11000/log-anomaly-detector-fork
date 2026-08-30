"""
Streaming ingestion: batching, offsets, rolling context, incremental incidents.

The suite is embedding-free -- a fake detector supplies the ML verdict, so
these tests assert the *streaming* logic (what state is carried between
batches) rather than re-testing Isolation Forest. The one property worth more
than all the others: a stream must reach the same verdict as a batch run over
the same lines, and it can only do that if it keeps enough history.
"""

import json

import pandas as pd
import pytest

from logdet.anomaly_detection import run_anomaly_detection
from logdet.sequence_grouping import group_anomalies
from logdet.stream import (
    FileTailSource,
    IncidentTracker,
    IterableSource,
    MicroBatcher,
    OffsetStore,
    StreamProcessor,
    run_stream,
)


# --- fakes --------------------------------------------------------------


class FakeClock:
    """Hand-advanced monotonic clock, so no test ever sleeps."""

    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeDetector:
    """Scores a line anomalous when its message contains a marker.

    Stands in for the fitted detector so the streaming tests need neither the
    embedding model nor a trained forest. It mimics the real contract: adds
    'anomaly_score' and 'is_anomaly', and refuses to score unfitted.
    """

    def __init__(self, marker: str = "Failed password"):
        self.marker = marker
        self.models = {}
        self.embedding_dim = 384
        self.embedding_model = "fake"

    def score(self, df: pd.DataFrame, **kwargs) -> pd.DataFrame:
        df = df.copy()
        flags = df["message"].str.contains(self.marker, case=False, na=False)
        df["is_anomaly"] = flags
        df["anomaly_score"] = [-0.2 if f else 0.2 for f in flags]
        return df


@pytest.fixture(autouse=True)
def no_embeddings(monkeypatch):
    """The stream calls the embedder before scoring; the fake detector ignores
    embeddings, so skip the model download entirely."""
    monkeypatch.setattr("logdet.stream.add_embeddings_to_df", lambda df, **kw: df)


def line(ts: str, message: str) -> str:
    return f"{ts} LabSZ sshd[1234]: {message}"


BRUTE_FORCE = [
    line(f"Jul 18 10:0{i}:00", f"Failed password for admin from 203.0.113.9 port 5100{i} ssh2")
    for i in range(5)
]
BENIGN = [
    line("Jul 18 10:00:30", "Accepted password for alice from 10.0.0.5 port 52000 ssh2"),
    line("Jul 18 10:01:30", "Connection closed by 10.0.0.5 port 52000"),
]


def processor() -> StreamProcessor:
    return StreamProcessor(FakeDetector(), year=2026)


# --- micro-batching -----------------------------------------------------


def test_batch_closes_on_the_line_limit():
    clock = FakeClock()
    batcher = MicroBatcher(max_lines=3, max_seconds=60, time_fn=clock)
    batcher.add(["a", "b"])
    assert not batcher.should_flush()
    batcher.add(["c"])
    assert batcher.should_flush()
    assert batcher.flush() == ["a", "b", "c"]


def test_batch_closes_on_the_time_limit_even_when_part_full():
    """A quiet log must still alert. Without the timer a half-full batch waits
    for traffic that may not come for hours."""
    clock = FakeClock()
    batcher = MicroBatcher(max_lines=50, max_seconds=5, time_fn=clock)
    batcher.add(["a"])
    assert not batcher.should_flush()
    clock.advance(5)
    assert batcher.should_flush()


def test_empty_buffer_never_flushes():
    clock = FakeClock()
    batcher = MicroBatcher(max_lines=1, max_seconds=0, time_fn=clock)
    clock.advance(100)
    assert not batcher.should_flush()


def test_flush_leaves_the_overflow_for_the_next_batch():
    batcher = MicroBatcher(max_lines=2, max_seconds=60, time_fn=FakeClock())
    batcher.add(["a", "b", "c"])
    assert batcher.flush() == ["a", "b"]
    assert batcher.pending() == 1


# --- file tailing and offsets -------------------------------------------


def test_tail_reads_only_what_is_appended(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    source = FileTailSource(log)
    assert source.read_lines() == []          # follow mode: history is not replayed

    with open(log, "a") as f:
        f.write("new line\n")
    assert source.read_lines() == ["new line"]


def test_from_start_replays_the_existing_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("one\ntwo\n")
    assert FileTailSource(log, from_start=True).read_lines() == ["one", "two"]


def test_a_partial_line_is_not_consumed_until_it_is_complete(tmp_path):
    """The writer can be mid-line. Splitting one log line into two would parse
    as garbage and silently drop an event."""
    log = tmp_path / "auth.log"
    log.write_text("complete\npart")
    source = FileTailSource(log, from_start=True)
    assert source.read_lines() == ["complete"]

    with open(log, "a") as f:
        f.write("ial\n")
    assert source.read_lines() == ["partial"]


def test_offset_survives_a_restart(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("one\n")
    store = OffsetStore(tmp_path / "offset.json")

    first = FileTailSource(log, offset_store=store, from_start=True)
    assert first.read_lines() == ["one"]
    first.commit()

    with open(log, "a") as f:
        f.write("two\n")

    resumed = FileTailSource(log, offset_store=store, from_start=True)
    assert resumed.read_lines() == ["two"], "restart re-read a line it had already scored"


def test_rotation_restarts_at_the_top_of_the_new_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("first file\n")
    store = OffsetStore(tmp_path / "offset.json")
    source = FileTailSource(log, offset_store=store, from_start=True)
    source.read_lines()
    source.commit()

    log.unlink()
    log.write_text("second file\n")   # same path, new inode
    assert source.read_lines() == ["second file"]


def test_truncation_in_place_restarts_at_the_top(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("a long first line\n")
    source = FileTailSource(log, from_start=True)
    source.read_lines()

    log.write_text("short\n")   # smaller than the stored offset
    assert source.read_lines() == ["short"]


def test_a_corrupt_offset_file_does_not_stop_ingestion(tmp_path):
    store_path = tmp_path / "offset.json"
    store_path.write_text("{not json")
    assert OffsetStore(store_path).load() == {}


def test_offset_is_ignored_when_it_belongs_to_another_file(tmp_path):
    store = OffsetStore(tmp_path / "offset.json")
    store.save(tmp_path / "other.log", inode=1, offset=99)
    assert store.offset_for(tmp_path / "auth.log", inode=1) is None


# --- incremental incident grouping --------------------------------------


def _event(ts: str, user: str, ip: str) -> dict:
    return {"timestamp": pd.Timestamp(ts), "user": user, "source_ip": ip,
            "message": "Failed password"}


def test_events_sharing_a_user_inside_the_window_join_one_incident():
    tracker = IncidentTracker(window_minutes=30)
    a = tracker.add(_event("2026-07-18 10:00:00", "admin", "203.0.113.9"))
    b = tracker.add(_event("2026-07-18 10:05:00", "admin", "198.51.100.4"))
    assert a == b
    assert len(tracker.incidents[a]["events"]) == 2


def test_the_same_user_outside_the_window_starts_a_new_incident():
    tracker = IncidentTracker(window_minutes=30)
    a = tracker.add(_event("2026-07-18 10:00:00", "admin", "203.0.113.9"))
    tracker.prune_recent(pd.Timestamp("2026-07-18 12:00:00"))
    b = tracker.add(_event("2026-07-18 12:00:00", "admin", "203.0.113.9"))
    assert a != b


def test_a_bridging_event_merges_two_incidents():
    """Transitivity, which is what union-find buys the batch grouper. An event
    linking to two open incidents has to fuse them, or one attack reads as two."""
    tracker = IncidentTracker(window_minutes=30)
    first = tracker.add(_event("2026-07-18 10:00:00", "alice", "10.0.0.1"))
    second = tracker.add(_event("2026-07-18 10:01:00", "bob", "10.0.0.2"))
    assert first != second

    bridge = tracker.add({"timestamp": pd.Timestamp("2026-07-18 10:02:00"),
                          "user": "alice", "source_ip": "10.0.0.2",
                          "message": "Failed password"})
    assert bridge == first
    assert second not in tracker.incidents
    assert len(tracker.incidents[first]["events"]) == 3


def test_an_incident_closes_once_the_window_has_passed():
    tracker = IncidentTracker(window_minutes=30)
    incident_id = tracker.add(_event("2026-07-18 10:00:00", "admin", "203.0.113.9"))
    assert tracker.closed_before(pd.Timestamp("2026-07-18 10:20:00")) == []
    assert tracker.closed_before(pd.Timestamp("2026-07-18 11:00:00")) == [incident_id]
    assert tracker.incidents == {}


# --- the processor ------------------------------------------------------


def test_a_brute_force_split_across_batches_stays_one_incident():
    """The property the rolling window exists for: batch boundaries are an
    artefact of arrival timing and must not split an attack into two alerts."""
    proc = processor()
    proc.process(BRUTE_FORCE[:2])
    proc.process(BRUTE_FORCE[2:])
    assert len(proc.tracker.incidents) == 1
    assert len(next(iter(proc.tracker.incidents.values()))["events"]) == 5


def test_benign_lines_raise_no_incident():
    proc = processor()
    assert proc.process(BENIGN) == []
    assert proc.tracker.incidents == {}


def test_unparsable_lines_are_counted_and_dropped():
    proc = processor()
    proc.process(["this is not a syslog line", BRUTE_FORCE[0]])
    assert proc.lines_seen == 2
    assert proc.lines_parsed == 1


def test_history_is_evicted_beyond_the_retention_window():
    proc = StreamProcessor(FakeDetector(), retention_minutes=10, year=2026)
    proc.process([line("Jul 18 10:00:00", "Accepted password for alice from 10.0.0.5 port 1 ssh2")])
    proc.process([line("Jul 18 12:00:00", "Accepted password for alice from 10.0.0.5 port 2 ssh2")])
    assert len(proc.history) == 1, "an event two hours stale is still being carried"


def test_impossible_travel_is_caught_across_two_batches():
    """The rule compares a login with the *previous* one. If the earlier login
    arrived in an earlier batch, only the rolling context can see it."""
    proc = processor()
    proc.process([line("Jul 18 10:00:00",
                       "Accepted password for alice from 10.0.0.5 port 52000 ssh2")])
    incidents = proc.process([line("Jul 18 10:15:00",
                                   "Accepted password for alice from 203.0.113.44 port 52010 ssh2")])
    assert incidents, "impossible travel went undetected across a batch boundary"
    assert incidents[0]["severity"] == "high"


def test_streamed_incidents_match_a_batch_run_over_the_same_lines():
    """The claim that makes streaming trustworthy. Same lines, same detector,
    same verdict -- whether they arrive all at once or five at a time."""
    lines = BRUTE_FORCE + BENIGN
    detector = FakeDetector()

    proc = StreamProcessor(detector, year=2026)
    run_stream(IterableSource(lines), proc, once=True,
               batcher=MicroBatcher(max_lines=2, max_seconds=60, time_fn=FakeClock()))
    streamed = len(proc._emitted)

    from logdet.preprocessing import LineParser
    frame = pd.DataFrame(LineParser(year=2026).parse_many(lines))
    scored = detector.score(frame)
    scored["impossible_travel"] = False
    scored["ml_anomaly"] = scored["is_anomaly"]
    batched = len(group_anomalies(scored))

    assert streamed == batched == 1


# --- the loop -----------------------------------------------------------


def test_run_once_drains_a_part_full_final_batch():
    proc = processor()
    emitted = run_stream(IterableSource(BRUTE_FORCE), proc, once=True,
                         batcher=MicroBatcher(max_lines=4, max_seconds=60, time_fn=FakeClock()))
    assert proc.lines_parsed == 5, "the 5th line was left unscored in the open batch"
    assert emitted


def test_every_incident_is_closed_when_the_stream_ends():
    proc = processor()
    emitted = run_stream(IterableSource(BRUTE_FORCE), proc, once=True)
    assert emitted[-1]["status"] == "closed"
    assert proc.tracker.incidents == {}


def test_the_offset_is_committed_only_after_a_batch_is_scored(tmp_path):
    """A crash mid-batch must replay that batch, not skip it."""
    log = tmp_path / "auth.log"
    log.write_text("\n".join(BRUTE_FORCE) + "\n")
    store = OffsetStore(tmp_path / "offset.json")

    run_stream(FileTailSource(log, offset_store=store, from_start=True),
               processor(), once=True)

    saved = json.loads((tmp_path / "offset.json").read_text())
    assert saved["offset"] == log.stat().st_size
