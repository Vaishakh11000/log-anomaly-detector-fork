"""
replay.py
Writes a recorded log back out in wall-clock time, so the live path has
something to be live *about*.

Why this exists. `logdet-stream --once` replays a file as fast as it can read
it, which is the right thing for a regression lock and the wrong thing for a
demo: 751 lines arrive in one breath, every incident closes before anyone has
looked at the screen, and nothing about it distinguishes a streaming detector
from a batch one. This module puts the original spacing back -- optionally
compressed by a speed factor -- and appends to a file that `logdet-stream` or
the API tails. The detector is then genuinely following traffic that is still
being written.

What it does *not* do. It does not touch detection, grouping or scoring, and
it does not decide anything about ground truth. It is a tap: lines in, the same
lines out, later. That is why it lives in `logdet/` rather than the evaluation
package -- nothing here measures anything, and `logdet_eval/paced_replay.py`
(the instrument that feeds Wazuh for the kill point) has a different job: it
schedules per *source IP* to exercise Wazuh's `same_source_ip` frequency rules,
and it talks to a container. This one preserves global order and writes a file.

Two knobs are worth understanding before using them in front of anyone:

  - `--speed` compresses the *gaps between lines*, not the timestamps in them.
    At the default 60x, a corpus spanning an hour of log time replays in a
    minute, and the detector still reads the original timestamps -- so incident
    windows, impossible travel, and every number they produce mean exactly what
    they mean in batch mode.
  - `--restamp` rewrites each line's syslog timestamp to the moment it is
    written. The display then reads as "now", which is what a demo wants, but
    it also compresses the log's own time by the speed factor: a brute force
    spread over 40 minutes becomes 40 seconds of log time at 60x, so the
    30-minute grouping window and the 60-minute travel window no longer cover
    what they covered in the recording. It is off by default for that reason,
    and results produced under it are not comparable to anything in `results/`.

`--max-gap` is the other thing that keeps a demo watchable: real logs contain
hours of silence, and at 60x an hour is still a minute of nothing happening.
Clamping the wait means the replay is no longer a faithful time-scaling, which
is fine for a demo and is why the clamp is reported at the end of the run.

Usage:
    logdet-replay --input data/raw/synthetic.log --output data/live/demo.log
    logdet-stream --input data/live/demo.log            # in another terminal
"""

import argparse
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from logdet.preprocessing import LineParser

# The leading "Mon DD HH:MM:SS" of a syslog line. Anchored, so a timestamp-like
# string inside a message is never mistaken for the line's own clock.
SYSLOG_TIMESTAMP_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")

DEFAULT_SPEED = 60.0
DEFAULT_MAX_GAP = 2.0


@dataclass
class Paced:
    """One line and how long to wait before writing it."""

    delay: float
    line: str
    clamped: bool = False


def pace_schedule(lines, speed: float = DEFAULT_SPEED,
                  max_gap: float = DEFAULT_MAX_GAP, min_gap: float = 0.0,
                  year: int | None = None) -> list[Paced]:
    """Turn raw lines into (wait, line) pairs from their own timestamps.

    Three cases the corpora actually contain, each handled rather than assumed
    away:

      - **A line with no parseable timestamp** (a continuation line, a format
        the parser does not know) inherits a zero gap, so it is written with
        the line it belongs to instead of being scheduled on its own.
      - **A timestamp that goes backwards.** Real logs interleave sources, and
        the OpenSSH corpus crosses New Year. Negative gaps clamp to zero rather
        than winding the clock back.
      - **A gap longer than `max_gap`.** Clamped, and the line is marked so the
        caller can report how much of the replay was not faithful.

    `year` is passed through to the parser, which carries the year-rollover
    state; without it a Dec -> Jan corpus produces one enormous negative gap.
    """
    if speed <= 0:
        raise ValueError("speed must be positive")

    parser = LineParser(year=year)
    schedule: list[Paced] = []
    previous: datetime | None = None

    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        parsed = parser.parse(line)
        timestamp = parsed["timestamp"] if parsed else None

        if timestamp is None or previous is None:
            gap, clamped = 0.0, False
        else:
            real = (timestamp - previous).total_seconds()
            gap = max(real, 0.0) / speed
            clamped = gap > max_gap
            gap = min(gap, max_gap)
            gap = max(gap, min_gap)

        if timestamp is not None:
            previous = timestamp
        schedule.append(Paced(delay=gap, line=line, clamped=clamped))

    return schedule


def restamp_line(line: str, when: datetime) -> str:
    """Rewrite a syslog line's leading timestamp to `when`.

    Lines whose head does not match are returned untouched -- silently
    prefixing a timestamp onto something that had none would create a log line
    that never existed.
    """
    # syslog right-pads a single-digit day with a space ("Aug  3"), which is
    # what the parser's regex expects; built by hand rather than with %e
    # because %e is not portable and %d would write "03".
    stamp = f"{when.strftime('%b')} {when.day:2d} {when.strftime('%H:%M:%S')}"
    if not SYSLOG_TIMESTAMP_RE.match(line):
        return line
    return SYSLOG_TIMESTAMP_RE.sub(stamp, line, count=1)


def replay(schedule: list[Paced], output_path: str | Path, truncate: bool = False,
           restamp: bool = False, sleep=time.sleep, clock=time.monotonic,
           now=datetime.now, on_line=None) -> dict:
    """Write a paced schedule to `output_path`, appending as it goes.

    Timing is against an absolute target rather than a chain of sleeps: sleeping
    `delay` between writes accumulates the cost of every write, which over
    thousands of lines drifts the replay minutes behind its own schedule.

    Every line is flushed. A buffered writer would hand the tailer nothing until
    4KB had accumulated, which on a quiet stream is the whole demo.

    `sleep`, `clock` and `now` are injected so the tests can replay a corpus in
    no time at all and still assert the schedule.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if truncate else "a"

    written = 0
    clamped = 0
    start = clock()
    target = start

    with open(path, mode, buffering=1) as out:
        for item in schedule:
            target += item.delay
            wait = target - clock()
            if wait > 0:
                sleep(wait)
            line = restamp_line(item.line, now()) if restamp else item.line
            out.write(line + "\n")
            out.flush()
            written += 1
            clamped += bool(item.clamped)
            if on_line:
                on_line(written, line)

    return {
        "lines": written,
        "clamped_gaps": clamped,
        "scheduled_seconds": sum(i.delay for i in schedule),
        "elapsed_seconds": clock() - start,
        "output": str(path),
    }


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Replay a recorded log into a file in wall-clock time, so "
                    "the streaming detector has live traffic to follow.")
    parser.add_argument("--input", required=True, help="Recorded log to replay")
    parser.add_argument("--output", required=True,
                        help="File to append to. Point logdet-stream at this.")
    parser.add_argument("--speed", type=float, default=DEFAULT_SPEED,
                        help="Time compression. 60 = one hour of log per minute. "
                             "1 = true speed (default: %(default)s)")
    parser.add_argument("--rate", type=float, default=None,
                        help="Ignore timestamps and emit this many lines per "
                             "second. Simplest demo mode; destroys the log's own "
                             "burstiness, which is part of what is being detected.")
    parser.add_argument("--max-gap", type=float, default=DEFAULT_MAX_GAP,
                        help="Longest wait between lines, seconds. Keeps hours of "
                             "silence out of a demo (default: %(default)s)")
    parser.add_argument("--truncate", action="store_true",
                        help="Start the output file empty instead of appending")
    parser.add_argument("--restamp", action="store_true",
                        help="Rewrite each line's timestamp to now. Makes the "
                             "display read as live, but compresses the log's own "
                             "time by --speed, so incident and travel windows no "
                             "longer cover what they covered in the recording.")
    parser.add_argument("--year", type=int, default=None,
                        help="Year to assume for syslog timestamps")
    parser.add_argument("--quiet", action="store_true", help="No per-line output")
    args = parser.parse_args()

    with open(args.input, errors="ignore") as f:
        lines = f.readlines()

    if args.rate:
        if args.rate <= 0:
            parser.error("--rate must be positive")
        gap = 1.0 / args.rate
        schedule = [Paced(delay=0.0 if i == 0 else gap, line=line.rstrip("\n"))
                    for i, line in enumerate(lines) if line.strip()]
    else:
        schedule = pace_schedule(lines, speed=args.speed, max_gap=args.max_gap,
                                 year=args.year)

    total = sum(i.delay for i in schedule)
    print(f"Replaying {len(schedule)} lines -> {args.output} "
          f"(~{total:.0f}s at {'rate ' + str(args.rate) + '/s' if args.rate else str(args.speed) + 'x'})")
    if args.restamp:
        print("--restamp is on: log time now equals arrival time, so these "
              "numbers are not comparable to results/ (see the module docstring).")

    def progress(count: int, line: str) -> None:
        if not args.quiet and count % 25 == 0:
            print(f"  {count}/{len(schedule)} lines", flush=True)

    try:
        summary = replay(schedule, args.output, truncate=args.truncate,
                         restamp=args.restamp, on_line=progress)
    except KeyboardInterrupt:
        print("\nStopped.")
        return

    print(f"Wrote {summary['lines']} lines in {summary['elapsed_seconds']:.1f}s.")
    if summary["clamped_gaps"]:
        print(f"{summary['clamped_gaps']} gap(s) clamped to --max-gap "
              f"{args.max_gap}s -- the replay is compressed further than "
              f"{args.speed}x wherever the source was idle.")


if __name__ == "__main__":
    cli()
