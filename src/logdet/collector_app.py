"""
collector_app.py
The light half of the collector/analyzer split (CLAUDE.md 2c/2d).

A standalone FastAPI app that does one thing: receive the NDJSON a remote
shipper (attack_runner/ship.py) sends and append each line to one on-disk file
the analyzer tails. It imports nothing from the detection stack -- only
`logdet.collector` and `logdet.config` -- so the container built from it needs
no torch, no sentence-transformers, no model, and starts in a fraction of a
second. That is the reason to split it out rather than run the whole
`logdet-api` on the collector box: the receiver stays up (and keeps buffering)
independently of the heavy analyzer, which is exactly the durability the split
is supposed to buy.

It exposes the same three routes `logdet-api` does for collection, byte for
byte, so a shipper cannot tell whether it is talking to the standalone
collector or the single-box API:

    GET  /health
    POST /collector/ingest
    GET  /collector/status
"""

import argparse

from fastapi import FastAPI, Request

from logdet.collector import CollectorSink, parse_ndjson_lines
from logdet.config import COLLECTOR_HOST, COLLECTOR_PORT


def create_app(sink: CollectorSink | None = None) -> FastAPI:
    """Build the collector app around a sink.

    Taking the sink as an argument is what makes it testable: a test points it
    at a tmp path and drives the routes with no server and no shared volume.
    """
    sink = sink or CollectorSink()
    app = FastAPI(
        title="LLM Log Anomaly Detector -- Collector",
        description="Receives shipped log lines and appends them to the file "
                    "the analyzer tails. Runs no detection.",
        version="0.1.0",
    )
    app.state.sink = sink

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "collector": sink.status()}

    @app.post("/collector/ingest")
    async def collector_ingest(request: Request) -> dict:
        """Receive log lines from a remote collector and append them to disk.

        Identical contract to `logdet-api`'s route: NDJSON of ``{"line": "..."}``
        objects (what the shipper sends), plain text also accepted for a manual
        curl, and the response echoes lines written plus file size -- the ack
        the shipper reads to advance its committed offset.
        """
        body = await request.body()
        lines = parse_ndjson_lines(body)
        written = sink.append(lines)
        return {"received": len(lines), "written": written, **sink.status()}

    @app.get("/collector/status")
    def collector_status() -> dict:
        return sink.status()

    return app


app = create_app()


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Receive shipped log lines and append them to the "
                    "collector file the analyzer tails. Runs no detection.")
    parser.add_argument("--host", default=COLLECTOR_HOST,
                        help="Bind address. The default is loopback: this "
                             "service has no authentication.")
    parser.add_argument("--port", type=int, default=COLLECTOR_PORT)
    args = parser.parse_args()

    import uvicorn

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"Warning: binding {args.host} exposes an unauthenticated ingest "
              f"endpoint on the network. Intended only for the direct link.")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    cli()
