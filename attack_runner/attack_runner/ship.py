"""
ship.py
Ship captured log lines to the analyzer over HTTP, reliably.

CLAUDE.md section 2c ("Reliability is in the shipping code, not the cable")
names four requirements, and each maps to something here:

  * disk-backed buffer on the collector -- a 3-second analyzer restart must not
    silently eat data. `Shipper` appends every line to a local spool file
    before trying to send it, and only advances the committed offset once the
    analyzer has acknowledged. A crash resumes from the spool.
  * track a byte offset into the source so reconnects neither duplicate nor
    skip. The offset here is a *line* offset into the spool, committed to its
    own file after a successful POST; on restart, shipping resumes from it.
  * HTTP POST with retry, never a raw socket -- resume is trivial over one and
    painful over the other. urllib, exponential backoff, bounded attempts.
  * link health visible -- `Shipper.status()` returns lines spooled vs
    committed and the last error, which is what a dashboard shows instead of
    inferring health from an absence of alerts.

stdlib only (urllib): this runs on a bare Kali box with no pip packages
(pyproject.toml). The payload is newline-delimited JSON, one object per line,
which the analyzer's collector endpoint appends to the file it tails.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ShipResult:
    sent: int
    committed_offset: int
    ok: bool
    error: str | None = None


class Shipper:
    """Disk-backed, resumable HTTP shipper.

    The spool and offset files make shipping crash-safe: a line is durable on
    disk before any send is attempted, and the offset only moves past lines the
    analyzer has acknowledged. Point two `Shipper`s at the same spool dir and
    the second resumes exactly where the first died.
    """

    def __init__(self, url: str, spool_dir: str,
                 max_retries: int = 5, backoff: float = 0.5,
                 timeout: float = 5.0, opener=None):
        self.url = url
        self.spool = Path(spool_dir)
        self.spool.mkdir(parents=True, exist_ok=True)
        self.spool_file = self.spool / "outbox.ndjson"
        self.offset_file = self.spool / "offset"
        self.max_retries = max_retries
        self.backoff = backoff
        self.timeout = timeout
        # injectable so tests need no network; defaults to urllib.
        self._opener = opener or self._urllib_post
        self.last_error: str | None = None

    # --- durability ---------------------------------------------------------

    def enqueue(self, lines: list[str]) -> None:
        """Append lines to the durable spool. Cheap and never blocks on the
        network -- capture can keep running while the link is down."""
        with self.spool_file.open("a") as f:
            for raw in lines:
                f.write(json.dumps({"line": raw.rstrip("\n")}) + "\n")

    def _committed(self) -> int:
        try:
            return int(self.offset_file.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _commit(self, offset: int) -> None:
        # write-then-rename so a crash mid-write cannot leave a torn offset.
        tmp = self.offset_file.with_suffix(".tmp")
        tmp.write_text(str(offset))
        tmp.replace(self.offset_file)

    def _pending(self, committed: int) -> list[str]:
        if not self.spool_file.exists():
            return []
        with self.spool_file.open() as f:
            return f.readlines()[committed:]

    # --- transport ----------------------------------------------------------

    def _urllib_post(self, url: str, body: bytes) -> int:
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-ndjson"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.status

    def _post_with_retry(self, body: bytes) -> None:
        last: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                status = self._opener(self.url, body)
                if 200 <= status < 300:
                    self.last_error = None
                    return
                last = RuntimeError(f"HTTP {status}")
            except (urllib.error.URLError, OSError, RuntimeError) as exc:
                last = exc
            time.sleep(self.backoff * (2 ** attempt))
        self.last_error = str(last)
        raise ConnectionError(f"shipping failed after {self.max_retries} attempts: {last}")

    def flush(self) -> ShipResult:
        """Send everything spooled but not yet committed. Idempotent on success:
        a repeat call sends nothing because the offset has advanced."""
        committed = self._committed()
        pending = self._pending(committed)
        if not pending:
            return ShipResult(sent=0, committed_offset=committed, ok=True)
        body = "".join(pending).encode()
        try:
            self._post_with_retry(body)
        except ConnectionError as exc:
            return ShipResult(sent=0, committed_offset=committed, ok=False,
                              error=str(exc))
        new_offset = committed + len(pending)
        self._commit(new_offset)
        return ShipResult(sent=len(pending), committed_offset=new_offset, ok=True)

    def ship(self, lines: list[str]) -> ShipResult:
        """Enqueue then flush -- the normal path."""
        self.enqueue(lines)
        return self.flush()

    def status(self) -> dict:
        committed = self._committed()
        total = len(self.spool_file.read_text().splitlines()) if self.spool_file.exists() else 0
        return {
            "url": self.url,
            "spooled": total,
            "committed": committed,
            "pending": total - committed,
            "last_error": self.last_error,
        }
