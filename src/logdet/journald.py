"""
journald.py
Live ingestion from the systemd journal, as a source the streaming pipeline can
tail exactly like a file.

Why a second source at all: a tailed file is a *replay* of traffic somebody else
already wrote down. `journalctl -f` is the machine's own live auth stream, so it
is the first thing in this project that is genuinely live rather than a file
being read quickly. Everything downstream -- micro-batching, scoring, incident
growth -- is unchanged; only where the lines come from is different.

Three details carry the design:

  - **`-o json`, not `-o short`.** The short format looks like syslog and would
    parse, but it carries no cursor. The JSON form gives `__CURSOR` per entry,
    which is journald's own resume token and the only honest equivalent of the
    file tailer's byte offset. The syslog-shaped line is rebuilt from the JSON
    fields instead, so `LineParser` sees exactly the format it was written for.

  - **The cursor is committed after a batch is scored**, never before, for the
    same reason the byte offset is: a crash mid-batch must replay that batch
    rather than skip it.

  - **Follow mode reads a non-blocking pipe; one-shot mode reads a blocking
    one.** `run_stream(once=True)` stops as soon as a read comes back empty, and
    on a pipe "empty" means "nothing yet", not "nothing left" -- a non-blocking
    read would end the run before journalctl had written its first chunk.

Usage:
    logdet-stream --journald                     # authpriv facility, follow
    logdet-stream --journald --journald-unit sshd
    logdet-stream --journald --journald-since "-1h" --once
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

# authpriv. sshd, sudo, su and pam log here, which is the auth.log content the
# detector is fitted on -- the rest of the journal is a different vocabulary and
# would be scored against a model that never saw anything like it.
AUTHPRIV_FACILITY = 10

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


class CursorStore:
    """Remembers the last journal entry that was fully scored.

    Kept separate from `OffsetStore` rather than folded into it: a byte offset
    is only meaningful with the inode it was taken from, a cursor is only
    meaningful with the journal filter it came from, and one file holding both
    would let a file run and a journald run overwrite each other's resume point.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}   # a corrupt cursor file must not stop ingestion

    def save(self, key: str, cursor: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"key": key, "cursor": cursor}, indent=2))

    def cursor_for(self, key: str) -> str | None:
        """The stored cursor, or None if it was taken under a different filter."""
        stored = self.load()
        if stored.get("key") != key:
            return None
        return stored.get("cursor")


def _decode_message(value) -> str:
    """journald returns MESSAGE as a byte array when it is not valid UTF-8."""
    if isinstance(value, list):
        return bytes(value).decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def format_entry(entry: dict) -> str | None:
    """Rebuild a syslog-shaped line from one journal JSON entry.

    Returns None for an entry with no message or no usable timestamp, rather
    than emitting a line that `LineParser` would reject anyway.
    """
    message = _decode_message(entry.get("MESSAGE"))
    if not message:
        return None

    raw_ts = entry.get("__REALTIME_TIMESTAMP")
    try:
        when = datetime.fromtimestamp(int(raw_ts) / 1_000_000)
    except (TypeError, ValueError):
        return None

    stamp = (f"{MONTHS[when.month - 1]} {when.day:>2d} "
             f"{when.hour:02d}:{when.minute:02d}:{when.second:02d}")
    host = entry.get("_HOSTNAME") or "localhost"
    process = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "unknown"
    pid = entry.get("SYSLOG_PID") or entry.get("_PID")

    process_field = f"{process}[{pid}]" if pid else str(process)
    return f"{stamp} {host} {process_field}: {message}"


def build_argv(unit: str | None = None, facility: int | None = AUTHPRIV_FACILITY,
               follow: bool = True, since: str | None = None,
               after_cursor: str | None = None) -> list[str]:
    """The journalctl invocation for one filter.

    A stored cursor wins over `--since`: resuming from where scoring stopped is
    the whole point of keeping it, and passing both would let the time window
    silently drop entries the cursor says are still unread.
    """
    argv = ["journalctl", "-o", "json", "--no-pager"]
    if unit:
        argv += ["-u", unit]
    elif facility is not None:
        argv += [f"SYSLOG_FACILITY={facility}"]

    if after_cursor:
        argv += ["--after-cursor", after_cursor]
    elif since:
        argv += ["--since", since]
    elif follow:
        # `-n 0` is journalctl's own "no history, then follow". `--since now`
        # looks like it should mean the same thing and does not -- it returns
        # the whole journal, so a first follow run would replay every entry as
        # if it had just arrived.
        argv += ["-n", "0"]

    if follow:
        argv += ["-f"]
    return argv


def filter_key(unit: str | None, facility: int | None) -> str:
    """Identifies which slice of the journal a cursor was taken from."""
    return f"unit={unit}" if unit else f"facility={facility}"


class JournaldSource:
    """Yields syslog-shaped lines from the journal, without blocking in follow mode.

    Implements the same `read_lines()` / `commit()` contract as `FileTailSource`,
    so `run_stream` and `StreamProcessor` need no knowledge of where lines came
    from.
    """

    def __init__(self, unit: str | None = None,
                 facility: int | None = AUTHPRIV_FACILITY,
                 follow: bool = True, since: str | None = None,
                 cursor_store: CursorStore | None = None,
                 chunk_reader=None, chunk_size: int = 65536):
        self.unit = unit
        self.facility = facility
        self.follow = follow
        self.since = since
        self.cursor_store = cursor_store
        self.chunk_size = chunk_size
        self.key = filter_key(unit, facility)

        self._chunk_reader = chunk_reader   # tests inject one; None spawns journalctl
        self._process = None
        self._buffer = ""
        self._started = False
        self._eof = False
        self._pending_cursor: str | None = None
        self._committed_cursor: str | None = None

    # -- process plumbing ---------------------------------------------------

    def _start(self) -> None:
        resumed = self.cursor_store.cursor_for(self.key) if self.cursor_store else None
        self._committed_cursor = resumed
        if self._chunk_reader is None:
            argv = build_argv(unit=self.unit, facility=self.facility,
                              follow=self.follow, since=self.since,
                              after_cursor=resumed)
            self._process = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
            fd = self._process.stdout.fileno()
            # Follow mode must never block the poll loop; one-shot mode must
            # block, or `run_stream(once=True)` mistakes "not written yet" for
            # "end of journal" and exits after reading nothing.
            if self.follow:
                os.set_blocking(fd, False)
            self._chunk_reader = lambda: self._read_fd(fd)
        self._started = True

    def _read_fd(self, fd: int) -> bytes:
        try:
            return os.read(fd, self.chunk_size)
        except (BlockingIOError, InterruptedError):
            return b""
        except OSError:
            self._eof = True
            return b""

    # -- source contract ----------------------------------------------------

    def read_lines(self) -> list[str]:
        if not self._started:
            self._start()
        if self._eof:
            return []

        chunk = self._chunk_reader()
        if chunk is None:
            chunk = b""
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        if chunk == "" and not self.follow:
            self._eof = True

        self._buffer += chunk
        # A partial trailing line is left in the buffer until its newline
        # arrives: half a JSON entry is not a log line, it is a parse error.
        parts = self._buffer.split("\n")
        self._buffer = parts.pop()

        lines = []
        for part in parts:
            if not part.strip():
                continue
            try:
                entry = json.loads(part)
            except json.JSONDecodeError:
                continue
            cursor = entry.get("__CURSOR")
            if cursor:
                self._pending_cursor = cursor
            formatted = format_entry(entry)
            if formatted:
                lines.append(formatted)
        return lines

    def commit(self) -> None:
        """Persist the cursor of the last entry read, after its batch is scored."""
        if self.cursor_store and self._pending_cursor:
            self.cursor_store.save(self.key, self._pending_cursor)
            self._committed_cursor = self._pending_cursor

    def close(self) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None


def journald_available() -> bool:
    """True if journalctl exists and this user may read the journal."""
    try:
        result = subprocess.run(["journalctl", "-n", "0", "--no-pager"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
