"""
collector.py
The ingestion end of the collector/analyzer split (CLAUDE.md 2c/2d).

This module holds only what is needed to receive shipped log lines and write
them to one on-disk file: a small append-only sink and the NDJSON body parser
the shipper's format needs. It imports nothing from the detection stack
(no torch, no sentence-transformers), so a collector process built around it
starts fast and stays small -- which is the whole point of splitting it off
from the analyzer. `logdet.api` and `logdet.collector_app` both import these
two names from here rather than defining them, so the collector container and
the single-box API share one implementation.
"""

import json
import threading
from pathlib import Path

from logdet.config import COLLECTOR_LOG_PATH


class CollectorSink:
    """Append lines a remote collector ships to one on-disk file.

    Deliberately independent of the stream (CLAUDE.md 2c/2d). Ingestion just
    grows a file; a normal file-tail stream reads it. That decoupling is the
    whole point: the collector on the Kali box can keep shipping into it while
    the analyzer's stream is restarting, and the stream resumes from its own
    byte offset with nothing lost -- the same durability the shipper has on its
    own side, mirrored here. In the container split the two are separate
    processes with separate lifecycles, so that durability stops being a claim
    about threads and becomes a claim about restarts.

    The path is fixed at construction, never taken from the request. The
    endpoint has no authentication, so a client-chosen path would be an
    arbitrary-file-write primitive; one fixed sink is the safe shape.

    A lock guards the append because HTTP handlers run concurrently and two
    interleaved writes could split a line -- and half a log line parses as
    garbage and drops an event.
    """

    def __init__(self, path: str = COLLECTOR_LOG_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.lines_written = 0

    def append(self, lines: list[str]) -> int:
        """Append raw log lines, each terminated with a newline. Returns the
        count written. A blank line is dropped rather than written, because a
        blank line tails as an empty record."""
        clean = [ln.rstrip("\n") for ln in lines if ln.strip()]
        if not clean:
            return 0
        with self._lock:
            with self.path.open("a") as f:
                f.write("\n".join(clean) + "\n")
            self.lines_written += len(clean)
        return len(clean)

    def status(self) -> dict:
        size = self.path.stat().st_size if self.path.exists() else 0
        return {"path": str(self.path), "lines_written": self.lines_written,
                "bytes": size}


def parse_ndjson_lines(body: bytes) -> list[str]:
    """Pull raw log lines out of a shipped NDJSON body.

    attack_runner/ship.py sends one JSON object per line, ``{"line": "..."}``.
    This is lenient on purpose: a body line that is a JSON object yields its
    ``line`` field, a body line that is not JSON is taken as a raw log line as
    it stands. That way a curl of plain text works for a quick manual test and
    the shipper's structured form works in production, with no separate route.
    """
    out: list[str] = []
    for raw in body.decode("utf-8", "replace").splitlines():
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            out.append(raw)
            continue
        if isinstance(obj, dict) and "line" in obj:
            out.append(str(obj["line"]))
        elif isinstance(obj, str):
            out.append(obj)
        else:
            out.append(raw)
    return out
