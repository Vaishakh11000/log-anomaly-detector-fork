"""
api.py
FastAPI service: the second interface onto the live detector, alongside the
Streamlit dashboard.

The service *owns* the stream rather than reading a file somebody else wrote.
`logdet-stream` scores a source in micro-batches and hands each incident to a
callback; this wraps that loop in a background thread, keeps every emitted
incident in memory, and exposes it over HTTP -- a snapshot list, one incident
at a time, a status/lag view, a live push feed, and on-demand narration.

Why it owns the stream instead of serving `incidents.json`. Stage 2b's bake-off
puts this detector and Wazuh side by side on the same live traffic, with the
audience choosing what to fire at them; that needs a feed something else can
subscribe to while it is happening, which a file written at the end of a batch
run cannot provide. It is also the collector/analyzer split (Stage 7) starting
to take shape: once alerts leave the process over HTTP, the thing reading them
no longer has to be on the same machine.

Three things worth knowing before changing this file:

  - **Nothing here scores anything.** Detection, grouping and severity all
    happen in `stream.StreamProcessor`, unchanged. This module starts it, stops
    it, and serves what it emits. That is deliberate: the streamed numbers are
    pinned equal to the batch numbers by `tests/test_stream_regression.py`, and
    an API that re-derived any of them would put that equivalence at risk for
    no gain.
  - **Incidents are stored as deep copies taken at emit time.** The processor
    mutates its own incident dicts in place (an "open" incident becomes
    "closed"), so holding a reference would mean serialising a dict on the HTTP
    thread while the scoring thread rewrites it. Copying at the boundary makes
    every response internally consistent, and a status change arrives as its
    own later emission anyway.
  - **One stream at a time.** Incident ids come from a single processor's
    counter, so two concurrent streams would hand out colliding ids and the
    same `/incidents/7` would mean two different things. Starting a second one
    is a 409, not a queue.

There is no authentication. The service binds 127.0.0.1 by default for that
reason -- see `API_HOST` in config.py before exposing it on the demo link.

Usage:
    logdet-fit --input data/processed/parsed.csv
    logdet-api                                   # http://127.0.0.1:8000/docs
    curl -X POST localhost:8000/stream/start \\
         -H 'content-type: application/json' \\
         -d '{"source": "file", "path": "/var/log/auth.log"}'
    curl -N localhost:8000/events                # live feed
    curl -X POST localhost:8000/collector/ingest \\
         -H 'content-type: application/x-ndjson' \\
         --data-binary @lines.ndjson            # remote collector -> tailed file
"""

import argparse
import asyncio
import copy
import json
import queue
import threading
import time
from typing import Literal
from pathlib import Path

import pandas as pd
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from logdet.anomaly_detection import PerUserAnomalyDetector
from logdet.collector import CollectorSink, parse_ndjson_lines
from logdet.config import (
    API_EVENT_QUEUE_SIZE,
    API_HOST,
    API_PORT,
    API_SSE_POLL_SECONDS,
    DEFAULT_CURSOR_STORE,
    DEFAULT_DETECTOR_PATH,
    DEFAULT_OFFSET_STORE,
    STREAM_BATCH_MAX_LINES,
    STREAM_BATCH_MAX_SECONDS,
)
from logdet.journald import AUTHPRIV_FACILITY, CursorStore, JournaldSource
from logdet.stream import (
    FileTailSource,
    MicroBatcher,
    OffsetStore,
    StreamProcessor,
    run_stream,
)
from logdet.triage import is_notable, triage_key


class TimestampedProcessor(StreamProcessor):
    """A StreamProcessor that records when it last scored a batch.

    `lines_seen` alone cannot answer "is this thing still alive?" -- it stops
    moving both when the log is quiet and when the reader has silently died,
    and those need different responses from whoever is watching. A timestamp
    separates them: quiet is a recent batch with no new lines, dead is no batch
    at all. CLAUDE.md 2c asks for link health to be visible rather than
    inferred from an absence of alerts; this is the number that makes that
    possible.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_batch_at: float | None = None

    def process(self, lines: list[str]) -> list[dict]:
        result = super().process(lines)
        self.last_batch_at = time.time()
        return result


class StreamService:
    """Owns the background scoring thread and everything it has emitted.

    Deliberately not a global singleton behind a lock-free dict: the scoring
    thread writes while HTTP handlers read, so every shared structure is
    guarded. The lock is held only for dict operations, never across the
    scoring call itself -- holding it there would make a slow batch block
    /health, which is the one endpoint that has to answer during a slow batch.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._incidents: dict[int, dict] = {}
        self._subscribers: list[queue.Queue] = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._processor: TimestampedProcessor | None = None
        self._source = None
        self._source_label: str | None = None
        self._started_at: float | None = None
        self._finished_at: float | None = None
        self._error: str | None = None
        self._detector_path: str | None = None
        self._dropped_events = 0

    # -- lifecycle -----------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, source, processor: TimestampedProcessor, source_label: str,
              detector_path: str, batcher: MicroBatcher, once: bool = False) -> None:
        """Begin scoring `source` on a background thread.

        The caller builds the source and loads the detector, so a bad path or a
        provenance-mismatched model fails inside the request and returns a 4xx,
        instead of failing in a thread nobody is watching and leaving the
        service reporting "running" over a stream that is already dead.
        """
        if self.running:
            raise RuntimeError("a stream is already running")

        self._stop.clear()
        self._incidents.clear()
        self._error = None
        self._finished_at = None
        self._processor = processor
        self._source = source
        self._source_label = source_label
        self._detector_path = detector_path
        self._started_at = time.time()

        def worker() -> None:
            try:
                run_stream(source, processor, once=once, batcher=batcher,
                           on_incident=self._record, stop_fn=self._stop.is_set)
            except Exception as exc:                      # noqa: BLE001
                # A thread that dies quietly leaves the service claiming to be
                # streaming over a source that stopped producing. Record it so
                # /stream/status can say so.
                self._error = f"{type(exc).__name__}: {exc}"
            finally:
                self._finished_at = time.time()
                close = getattr(source, "close", None)
                if close:
                    close()
                self._publish({"type": "stream_finished", "error": self._error})

        self._thread = threading.Thread(target=worker, name="logdet-stream",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> bool:
        """Ask the loop to finish its current batch and return. True if it did."""
        if not self.running:
            return True
        self._stop.set()
        self._thread.join(timeout=timeout)
        return not self.running

    # -- incident store ------------------------------------------------------

    def _record(self, incident: dict) -> None:
        snapshot = copy.deepcopy(incident)
        with self._lock:
            self._incidents[snapshot["incident_id"]] = snapshot
        self._publish({"type": "incident", "incident": snapshot})

    def incidents(self) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(i) for i in self._incidents.values()]

    def incident(self, incident_id: int) -> dict | None:
        with self._lock:
            found = self._incidents.get(incident_id)
            return copy.deepcopy(found) if found is not None else None

    def annotate(self, incident_id: int, **fields) -> dict | None:
        """Attach fields (a narrative) to a stored incident."""
        with self._lock:
            found = self._incidents.get(incident_id)
            if found is None:
                return None
            found.update(fields)
            return copy.deepcopy(found)

    # -- live feed -----------------------------------------------------------

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=API_EVENT_QUEUE_SIZE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish(self, event: dict) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Never block the scoring thread on a slow HTTP client. The
                # incident is still in the store, so a dropped push costs the
                # subscriber a refresh, not the alert.
                self._dropped_events += 1

    # -- status --------------------------------------------------------------

    def status(self) -> dict:
        processor = self._processor
        incidents = self.incidents()
        last_batch = processor.last_batch_at if processor else None
        return {
            "running": self.running,
            "source": self._source_label,
            "detector": self._detector_path,
            "started_at": self._started_at,
            "finished_at": self._finished_at,
            "lines_seen": processor.lines_seen if processor else 0,
            "lines_parsed": processor.lines_parsed if processor else 0,
            "last_batch_at": last_batch,
            # How long since anything was scored. The number a watcher reads to
            # tell a quiet log from a dead reader.
            "seconds_since_last_batch": (time.time() - last_batch) if last_batch else None,
            "incidents_total": len(incidents),
            "incidents_open": sum(1 for i in incidents if i.get("status") == "open"),
            "incidents_closed": sum(1 for i in incidents if i.get("status") == "closed"),
            "subscribers": len(self._subscribers),
            "dropped_events": self._dropped_events,
            "error": self._error,
        }


# --- request models ---------------------------------------------------------


class StreamStartRequest(BaseModel):
    """What to stream. Mirrors `logdet-stream`'s flags, one for one."""

    source: Literal["file", "journald"] = "file"
    path: str | None = Field(None, description="Log file to tail (source=file)")
    detector: str = Field(DEFAULT_DETECTOR_PATH, description="Detector from logdet-fit")
    from_start: bool = Field(False, description="Read the whole file, not only new lines")
    once: bool = Field(False, description="Replay what is there, then stop")
    use_offset_store: bool = Field(True, description="Record and resume a read position")
    offset_store: str = DEFAULT_OFFSET_STORE
    cursor_store: str = DEFAULT_CURSOR_STORE
    journald_unit: str | None = Field(None, description="Restrict to one unit, e.g. sshd")
    journald_since: str | None = Field(None, description="journalctl --since syntax")
    batch_lines: int = STREAM_BATCH_MAX_LINES
    batch_seconds: float = STREAM_BATCH_MAX_SECONDS


def build_source(request: StreamStartRequest):
    """Construct the source and a human-readable label for it.

    Same construction as `stream.cli`, kept here rather than shared because the
    CLI's version is argparse-shaped and this one is request-shaped; the only
    thing that must agree between them is the defaults, which both take from
    config.
    """
    if request.source == "journald":
        cursors = CursorStore(request.cursor_store) if request.use_offset_store else None
        source = JournaldSource(
            unit=request.journald_unit,
            facility=None if request.journald_unit else AUTHPRIV_FACILITY,
            follow=not request.once,
            since=request.journald_since or ("-1h" if request.once else None),
            cursor_store=cursors)
        return source, f"journald ({source.key})"

    if not request.path:
        raise ValueError("source=file needs a path")
    store = OffsetStore(request.offset_store) if request.use_offset_store else None
    source = FileTailSource(request.path, offset_store=store,
                            from_start=request.from_start or request.once)
    return source, request.path


# --- live feed --------------------------------------------------------------


async def event_stream(service: StreamService, disconnected,
                       poll_seconds: float = API_SSE_POLL_SECONDS,
                       keepalive_seconds: float = 15.0):
    """Yield server-sent-event frames for one subscriber until it disconnects.

    Module-level rather than a closure inside the endpoint so it can be driven
    directly by a test. Starlette's TestClient runs an app to completion before
    returning a response, so an endpoint that streams forever cannot be
    exercised over its HTTP client at all -- the test would hang rather than
    fail. Pulling the generator out is what makes the frames assertable.

    The queue is drained with `get_nowait` and an `await asyncio.sleep` between
    polls rather than a blocking `get`: a blocking get would hold an event-loop
    worker for the entire quiet period, and quiet is the normal state of a log.
    """
    q = service.subscribe()
    try:
        yield ": connected\n\n"
        idle = 0.0
        while True:
            if await disconnected():
                break
            try:
                event = q.get_nowait()
            except queue.Empty:
                await asyncio.sleep(poll_seconds)
                idle += poll_seconds
                # Comment frames keep proxies and idle-timeout logic from
                # closing a connection that is merely quiet.
                if idle >= keepalive_seconds:
                    idle = 0.0
                    yield ": keepalive\n\n"
                continue
            idle = 0.0
            yield f"data: {json.dumps(event, default=str)}\n\n"
    finally:
        service.unsubscribe(q)


# --- app --------------------------------------------------------------------


def create_app(service: StreamService | None = None,
               sink: "CollectorSink | None" = None) -> FastAPI:
    """Build the app around a service instance.

    Taking the service as an argument is what makes the endpoints testable: a
    test hands in a service driven by a canned source and never starts a
    thread over a real file. `sink` is the collector's on-disk buffer, taken
    the same way so a test can point it at a tmp path.
    """
    service = service or StreamService()
    sink = sink or CollectorSink()
    app = FastAPI(
        title="LLM Log Anomaly Detector",
        description="Live incidents from an embedding detector scoring a tailed "
                    "log or the systemd journal.",
        version="0.1.0",
    )
    app.state.service = service
    app.state.sink = sink

    @app.get("/health")
    def health() -> dict:
        """Cheap liveness plus the stream's vital signs."""
        return {"status": "ok", "stream": service.status()}

    @app.get("/stream/status")
    def stream_status() -> dict:
        return service.status()

    @app.post("/stream/start")
    def stream_start(request: StreamStartRequest = Body(...)) -> dict:
        if service.running:
            raise HTTPException(status_code=409, detail="a stream is already running")

        try:
            detector = PerUserAnomalyDetector.load(request.detector)
        except FileNotFoundError:
            raise HTTPException(
                status_code=400,
                detail=f"no detector at {request.detector} -- run logdet-fit first")
        except ValueError as exc:
            # A provenance mismatch. Loading a detector fit on different
            # embeddings would score happily and mean nothing, so this is a
            # refusal, not a warning.
            raise HTTPException(status_code=400, detail=str(exc))

        try:
            source, label = build_source(request)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        processor = TimestampedProcessor(detector)
        batcher = MicroBatcher(max_lines=request.batch_lines,
                               max_seconds=request.batch_seconds)
        service.start(source, processor, label, request.detector, batcher,
                      once=request.once)
        return service.status()

    @app.post("/stream/stop")
    def stream_stop() -> dict:
        stopped = service.stop()
        if not stopped:
            raise HTTPException(status_code=504,
                                detail="stream did not stop within the timeout")
        return service.status()

    @app.post("/collector/ingest")
    async def collector_ingest(request: Request) -> dict:
        """Receive log lines from a remote collector and append them to disk.

        This is the analyzer side of attack_runner/ship.py (CLAUDE.md 2c/2d):
        the Kali box POSTs newline-delimited JSON here, and each line lands in
        the collector file the analyzer's stream tails. Ingestion does not
        score anything and does not require a stream to be running -- it just
        grows the file, so a collector can buffer into it before the stream
        starts and across a stream restart.

        The body is NDJSON of ``{"line": "..."}`` objects (what the shipper
        sends); plain text lines are also accepted for manual testing. The
        response echoes how many lines were written and the file's size, which
        is the ack the shipper needs to advance its committed offset.
        """
        body = await request.body()
        lines = parse_ndjson_lines(body)
        written = sink.append(lines)
        return {"received": len(lines), "written": written, **sink.status()}

    @app.get("/collector/status")
    def collector_status() -> dict:
        return sink.status()

    @app.get("/incidents")
    def list_incidents(
        severity: list[str] | None = Query(None, description="Repeatable: high/medium/low"),
        status: str | None = Query(None, description="open or closed"),
        user: str | None = None,
        min_events: int = 0,
        notable: bool = Query(False, description="Only high-severity or multi-event"),
        with_mitre: bool = Query(False, description="Only incidents with a technique"),
        limit: int = Query(100, ge=1, le=10000),
        offset: int = Query(0, ge=0),
    ) -> dict:
        """Incidents ranked highest-corroboration first.

        The ranking is `triage.triage_key`, the same one the dashboard uses.
        Timestamp order would be wrong here for the reason it is wrong there:
        the detector favours recall, so the newest incident is usually a
        singleton false positive and the real attack is further down.

        Unlike the dashboard this returns everything by default -- an API that
        silently hid rows would be a trap. `notable=true` applies the
        dashboard's default filter.
        """
        found = service.incidents()
        if severity:
            wanted = set(severity)
            found = [i for i in found if i.get("severity") in wanted]
        if status:
            found = [i for i in found if i.get("status") == status]
        if user:
            found = [i for i in found if user in i.get("users", [])]
        if min_events:
            found = [i for i in found if i.get("event_count", 0) >= min_events]
        if notable:
            found = [i for i in found if is_notable(i)]
        if with_mitre:
            found = [i for i in found if i.get("mitre_techniques")]

        found.sort(key=triage_key, reverse=True)
        return {
            "total": len(found),
            "limit": limit,
            "offset": offset,
            "incidents": found[offset:offset + limit],
        }

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: int) -> dict:
        found = service.incident(incident_id)
        if found is None:
            raise HTTPException(status_code=404, detail=f"no incident {incident_id}")
        return found

    @app.post("/incidents/{incident_id}/narrate")
    def narrate_incident(incident_id: int, tier: str = "full") -> dict:
        """Generate the LLM text for one incident, on demand, at one tier.

        On demand rather than automatic, and one at a time: a full narrative
        costs ~3.9s per incident on the demo-box GPU and ~18.2s on its CPU
        (CLAUDE.md 2c), so narrating every incident as it closed would put the
        scoring thread minutes behind the log it is meant to be following.

        `tier=triage` is the cheap one-sentence route on the small model, for
        the incidents the narrative budget would otherwise leave with no prose.
        The two are stored in different fields, so a triage line can never be
        mistaken for a narrative that was actually written.
        """
        if tier not in {"full", "triage"}:
            raise HTTPException(status_code=422, detail=f"unknown tier: {tier}")
        found = service.incident(incident_id)
        if found is None:
            raise HTTPException(status_code=404, detail=f"no incident {incident_id}")
        field = "narrative" if tier == "full" else "triage_line"
        if found.get(field):
            return found

        from logdet.llm_narrative import narrate_detail
        try:
            text, dropped = narrate_detail(
                pd.DataFrame(found["events"]), tier=tier,
                context_events=found.get("context_events"))
        except Exception as exc:                          # noqa: BLE001
            raise HTTPException(status_code=503,
                                detail=f"narrative generation failed: {exc}")
        # The IDs the enforcement removed travel with the text. A client that
        # only renders the prose cannot otherwise tell this incident from one
        # where the model claimed nothing -- the drop is silent by design, and
        # silent is exactly what makes it unauditable in the field.
        return service.annotate(incident_id, **{field: text,
                                                "narrative_dropped": dropped}) or found

    @app.get("/events")
    async def events(request: Request) -> StreamingResponse:
        """Server-sent events: one message per incident as it is emitted.

        Subscribers get new events only; the backlog is `GET /incidents`.
        Sending the backlog down this channel too would double-deliver every
        incident to a client that did both, which is the normal way to use it.
        """
        return StreamingResponse(event_stream(service, request.is_disconnected),
                                 media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    return app


app = create_app()


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Serve live detector incidents over HTTP.")
    parser.add_argument("--host", default=API_HOST,
                        help="Bind address. The default is loopback: this service "
                             "has no authentication.")
    parser.add_argument("--port", type=int, default=API_PORT)
    parser.add_argument("--reload", action="store_true", help="Auto-reload on edit (dev)")
    args = parser.parse_args()

    import uvicorn

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"Warning: binding {args.host} exposes unauthenticated security "
              f"findings on the network. Intended only for the direct link.")
    uvicorn.run("logdet.api:app" if args.reload else app,
                host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    cli()
