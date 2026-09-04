"""
The HTTP service: lifecycle, the incident store, filtering, and the live feed.

Embedding-free, like the streaming suite: a fake detector supplies the ML
verdict and the embedder is stubbed out, so these tests assert what the *API
layer* does -- what it stores, what it hands back, what it refuses -- rather
than re-testing detection, which `test_stream.py` and the regression locks
already cover.

The property worth the most here is that the API is a pass-through: an
incident that reaches HTTP must be the incident the processor emitted, whole
and unmodified. Everything else in this file is a filter or a status field.
"""

import asyncio
import json
import queue
import time

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from logdet.api import (
    StreamService,
    StreamStartRequest,
    TimestampedProcessor,
    build_source,
    create_app,
    event_stream,
)


# --- fakes ------------------------------------------------------------------


class FakeDetector:
    """Same stand-in the streaming suite uses: anomalous when the message
    carries a marker, no embedding model, no trained forest."""

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
    monkeypatch.setattr("logdet.stream.add_embeddings_to_df", lambda df, **kw: df)


@pytest.fixture
def loadable_detector(monkeypatch):
    """Make `/stream/start` load the fake detector instead of a real file."""
    monkeypatch.setattr("logdet.api.PerUserAnomalyDetector.load",
                        staticmethod(lambda path: FakeDetector()))


@pytest.fixture
def service() -> StreamService:
    return StreamService()


@pytest.fixture
def client(service: StreamService) -> TestClient:
    return TestClient(create_app(service))


def incident(incident_id: int, *, severity: str = "low", event_count: int = 1,
             users: list[str] | None = None, status: str = "open",
             mitre: bool = False) -> dict:
    """An incident in the shape `pipeline.build_incident_entry` produces."""
    return {
        "incident_id": incident_id,
        "summary": f"incident {incident_id}",
        "users": users if users is not None else ["alice"],
        "source_ips": ["203.0.113.9"],
        "start": "2026-07-18 10:00:00",
        "end": "2026-07-18 10:05:00",
        "event_count": event_count,
        "severity": severity,
        "status": status,
        "mitre_techniques": ([{"technique_id": "T1110", "technique_name": "Brute Force",
                               "tactic": "Credential Access"}] if mitre else []),
        "events": [{"timestamp": "2026-07-18 10:00:00", "user": "alice",
                    "source_ip": "203.0.113.9", "message": "Failed password"}],
    }


def line(ts: str, message: str) -> str:
    return f"{ts} LabSZ sshd[1234]: {message}"


BRUTE_FORCE = [
    line(f"Jul 18 10:0{i}:00", f"Failed password for admin from 203.0.113.9 port 5100{i} ssh2")
    for i in range(5)
]


def wait_until(predicate, timeout: float = 15.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# --- health and status ------------------------------------------------------


def test_health_answers_before_any_stream_has_started(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["stream"]["running"] is False
    assert body["stream"]["incidents_total"] == 0


def test_status_counts_open_and_closed_separately(client, service):
    service._record(incident(1, status="open"))
    service._record(incident(2, status="closed"))
    body = client.get("/stream/status").json()
    assert body["incidents_total"] == 2
    assert body["incidents_open"] == 1
    assert body["incidents_closed"] == 1


def test_seconds_since_last_batch_is_none_until_a_batch_is_scored(service):
    assert service.status()["seconds_since_last_batch"] is None


def test_the_processor_stamps_when_it_last_scored(service):
    """Lines seen alone cannot tell a quiet log from a dead reader; the
    timestamp is what separates them."""
    processor = TimestampedProcessor(FakeDetector(), year=2026)
    assert processor.last_batch_at is None
    processor.process(BRUTE_FORCE)
    assert processor.last_batch_at is not None


# --- the incident store -----------------------------------------------------


def test_a_stored_incident_is_a_snapshot_not_a_reference(client, service):
    """The processor rewrites its own incident dicts in place as they close.
    Holding a reference would mean serialising one mid-rewrite."""
    live = incident(1, severity="low")
    service._record(live)
    live["severity"] = "high"
    live["events"].append({"message": "mutated"})

    stored = client.get("/incidents/1").json()
    assert stored["severity"] == "low"
    assert len(stored["events"]) == 1


def test_re_recording_an_incident_replaces_it(client, service):
    """An incident is emitted again when it closes; the later emission wins."""
    service._record(incident(1, status="open"))
    service._record(incident(1, status="closed"))
    body = client.get("/incidents").json()
    assert body["total"] == 1
    assert body["incidents"][0]["status"] == "closed"


def test_unknown_incident_is_404(client):
    assert client.get("/incidents/999").status_code == 404


def test_the_served_incident_is_the_emitted_one_unmodified(client, service):
    emitted = incident(7, severity="high", event_count=4, mitre=True)
    service._record(emitted)
    assert client.get("/incidents/7").json() == emitted


# --- listing, ranking, filtering -------------------------------------------


def test_incidents_are_ranked_by_corroboration_not_arrival(client, service):
    """Same ranking the dashboard uses. Timestamp order puts a singleton false
    positive on top, which is the view the triage policy exists to avoid."""
    service._record(incident(1, severity="high", event_count=1))
    service._record(incident(2, severity="low", event_count=6))
    service._record(incident(3, severity="medium", event_count=1))

    ids = [i["incident_id"] for i in client.get("/incidents").json()["incidents"]]
    assert ids == [2, 1, 3]


def test_listing_returns_everything_by_default(client, service):
    """Unlike the dashboard, which hides the non-notable set by default. An
    API that silently dropped rows would be a trap."""
    service._record(incident(1, severity="low", event_count=1))
    service._record(incident(2, severity="high", event_count=1))
    assert client.get("/incidents").json()["total"] == 2


def test_notable_applies_the_dashboards_default_filter(client, service):
    service._record(incident(1, severity="low", event_count=1))     # not notable
    service._record(incident(2, severity="high", event_count=1))    # high
    service._record(incident(3, severity="low", event_count=2))     # multi-event

    ids = {i["incident_id"]
           for i in client.get("/incidents", params={"notable": True}).json()["incidents"]}
    assert ids == {2, 3}


def test_severity_filter_accepts_several_values(client, service):
    service._record(incident(1, severity="high"))
    service._record(incident(2, severity="medium"))
    service._record(incident(3, severity="low"))
    body = client.get("/incidents", params=[("severity", "high"), ("severity", "low")]).json()
    assert {i["incident_id"] for i in body["incidents"]} == {1, 3}


def test_status_user_events_and_mitre_filters(client, service):
    service._record(incident(1, status="closed", users=["alice"], event_count=3, mitre=True))
    service._record(incident(2, status="open", users=["bob"], event_count=1))

    assert client.get("/incidents", params={"status": "closed"}).json()["total"] == 1
    assert client.get("/incidents", params={"user": "bob"}).json()["total"] == 1
    assert client.get("/incidents", params={"min_events": 2}).json()["total"] == 1
    assert client.get("/incidents", params={"with_mitre": True}).json()["total"] == 1


def test_limit_and_offset_page_the_ranked_list(client, service):
    for i in range(1, 6):
        service._record(incident(i, event_count=i))
    body = client.get("/incidents", params={"limit": 2, "offset": 1}).json()
    assert body["total"] == 5                    # total is before paging
    assert [i["incident_id"] for i in body["incidents"]] == [4, 3]


# --- source construction ----------------------------------------------------


def test_a_file_source_without_a_path_is_rejected():
    with pytest.raises(ValueError):
        build_source(StreamStartRequest(source="file", path=None))


def test_journald_defaults_to_authpriv_and_narrows_to_a_unit():
    _, label = build_source(StreamStartRequest(source="journald", use_offset_store=False))
    assert "facility=10" in label
    _, unit_label = build_source(StreamStartRequest(
        source="journald", journald_unit="sshd", use_offset_store=False))
    assert "sshd" in unit_label


# --- starting and stopping --------------------------------------------------


def test_start_refuses_a_detector_that_is_not_there(client, tmp_path):
    response = client.post("/stream/start",
                           json={"source": "file", "path": str(tmp_path / "x.log"),
                                 "detector": str(tmp_path / "missing.joblib")})
    assert response.status_code == 400
    assert "logdet-fit" in response.json()["detail"]


def test_start_refuses_a_file_source_with_no_path(client, loadable_detector):
    response = client.post("/stream/start", json={"source": "file"})
    assert response.status_code == 400


def test_a_replay_run_reaches_http(client, service, loadable_detector, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(BRUTE_FORCE) + "\n")

    started = client.post("/stream/start", json={
        "source": "file", "path": str(log), "once": True,
        "use_offset_store": False, "batch_lines": 2, "batch_seconds": 1e9})
    assert started.status_code == 200

    assert wait_until(lambda: not service.running)
    status = client.get("/stream/status").json()
    assert status["lines_seen"] == len(BRUTE_FORCE)
    assert status["lines_parsed"] == len(BRUTE_FORCE)
    assert status["error"] is None

    body = client.get("/incidents").json()
    assert body["total"] == 1
    assert body["incidents"][0]["event_count"] == len(BRUTE_FORCE)
    assert body["incidents"][0]["status"] == "closed"


def test_a_second_stream_is_refused_while_one_runs(client, service, loadable_detector,
                                                   tmp_path):
    """Incident ids come from one processor's counter, so two streams would
    hand out colliding ids for different incidents."""
    log = tmp_path / "auth.log"
    log.write_text("\n".join(BRUTE_FORCE) + "\n")
    payload = {"source": "file", "path": str(log), "from_start": True,
               "use_offset_store": False}

    assert client.post("/stream/start", json=payload).status_code == 200
    try:
        assert wait_until(lambda: service.running)
        assert client.post("/stream/start", json=payload).status_code == 409
    finally:
        service.stop()


def test_a_following_stream_stops_on_request(client, service, loadable_detector, tmp_path):
    """Follow mode has no natural end, so without a stop the thread outlives
    every caller that is not the interpreter itself."""
    log = tmp_path / "auth.log"
    log.write_text("\n".join(BRUTE_FORCE) + "\n")

    client.post("/stream/start", json={"source": "file", "path": str(log),
                                       "from_start": True, "use_offset_store": False,
                                       "batch_lines": 2, "batch_seconds": 1e9})
    assert wait_until(lambda: client.get("/incidents").json()["total"] >= 1)

    stopped = client.post("/stream/stop")
    assert stopped.status_code == 200
    assert stopped.json()["running"] is False
    assert not service.running


def test_a_dead_worker_reports_its_error_rather_than_claiming_to_run(service):
    """A thread that dies quietly leaves the service claiming to stream over a
    source that stopped producing."""

    class ExplodingSource:
        def read_lines(self):
            raise OSError("source went away")

        def commit(self):
            pass

    service.start(ExplodingSource(), TimestampedProcessor(FakeDetector(), year=2026),
                  "exploding", "fake.joblib", None)
    assert wait_until(lambda: not service.running)
    assert "source went away" in service.status()["error"]


# --- live feed --------------------------------------------------------------


def drain_stream(service: StreamService, frames_wanted: int, on_open=None,
                 **kwargs) -> list[str]:
    """Collect `frames_wanted` frames from the SSE generator, then close it.

    The generator is driven directly rather than over the TestClient: Starlette
    runs an app to completion before returning a response, so a request to an
    endpoint that streams until the client goes away never returns at all --
    the test hangs instead of failing.

    `on_open` fires after the first frame, which is the earliest point at which
    the subscriber exists. Publishing before that is publishing to nobody --
    the feed carries new events only, by design.
    """
    disconnected = kwargs.pop("disconnected", _never_disconnected)

    async def collect() -> list[str]:
        agen = event_stream(service, disconnected, **kwargs)
        frames = []
        try:
            async for frame in agen:
                frames.append(frame)
                if len(frames) == 1 and on_open is not None:
                    on_open()
                if len(frames) >= frames_wanted:
                    break
        finally:
            await agen.aclose()
        return frames

    return asyncio.run(collect())


async def _never_disconnected() -> bool:
    return False


def test_the_feed_opens_with_a_comment_frame(service):
    """A first byte before anything has happened: without it a client cannot
    tell "connected and quiet" from "still connecting"."""
    assert drain_stream(service, 1) == [": connected\n\n"]


def test_events_pushes_each_incident_as_it_is_emitted(service):
    def publish():
        service._record(incident(1, severity="high"))
        service._record(incident(2, severity="low"))

    frames = drain_stream(service, 3, on_open=publish, poll_seconds=0.001)
    payloads = [json.loads(f[len("data: "):]) for f in frames if f.startswith("data: ")]
    assert [p["type"] for p in payloads] == ["incident", "incident"]
    assert [p["incident"]["incident_id"] for p in payloads] == [1, 2]


def test_a_quiet_feed_sends_keepalives(service):
    """A connection that says nothing for minutes gets closed by whatever sits
    in front of it. The comment frames are what stop that."""
    frames = drain_stream(service, 3, poll_seconds=0.001, keepalive_seconds=0.002)
    assert frames[1:] == [": keepalive\n\n", ": keepalive\n\n"]


def test_a_subscriber_is_removed_when_the_client_goes_away(service):
    async def gone() -> bool:
        return True

    drain_stream(service, 1, disconnected=gone)
    assert service.status()["subscribers"] == 0


def test_the_feed_is_registered_as_an_event_stream(client):
    """The media type is what makes a browser's EventSource work at all."""
    route = next(r for r in client.app.routes if getattr(r, "path", None) == "/events")
    assert route.name == "events"


def test_a_slow_subscriber_drops_events_instead_of_stalling_the_detector(service):
    """The scoring thread must never block on an HTTP client. A dropped push
    costs a refresh; a blocked detector costs detection."""
    full: queue.Queue = queue.Queue(maxsize=1)
    full.put({"type": "filler"})
    service._subscribers.append(full)

    service._record(incident(1))                 # must not raise or block
    assert service.status()["dropped_events"] == 1
    assert service.incident(1) is not None       # still retrievable over HTTP


# --- narration tiers --------------------------------------------------------


def test_a_triage_request_stores_the_line_in_its_own_field(client, service,
                                                           monkeypatch):
    """A one-sentence triage line must never be mistaken for a narrative that
    was actually written, so the two live in different fields."""
    service._record(incident(1))
    monkeypatch.setattr("logdet.llm_narrative.narrate",
                        lambda df, tier="full", **kw: f"text from {tier}")
    body = client.post("/incidents/1/narrate", params={"tier": "triage"}).json()
    assert body["triage_line"] == "text from triage"
    assert not body.get("narrative")


def test_the_default_tier_is_the_full_narrative(client, service, monkeypatch):
    service._record(incident(1))
    monkeypatch.setattr("logdet.llm_narrative.narrate",
                        lambda df, tier="full", **kw: f"text from {tier}")
    body = client.post("/incidents/1/narrate").json()
    assert body["narrative"] == "text from full"
    assert not body.get("triage_line")


def test_an_unknown_tier_is_refused_rather_than_narrated(client, service):
    service._record(incident(1))
    assert client.post("/incidents/1/narrate", params={"tier": "cheap"}).status_code == 422


def test_a_triage_line_does_not_satisfy_a_later_full_request(client, service,
                                                             monkeypatch):
    service._record(incident(1))
    monkeypatch.setattr("logdet.llm_narrative.narrate",
                        lambda df, tier="full", **kw: f"text from {tier}")
    client.post("/incidents/1/narrate", params={"tier": "triage"})
    body = client.post("/incidents/1/narrate").json()
    assert body["narrative"] == "text from full"
    assert body["triage_line"] == "text from triage"
