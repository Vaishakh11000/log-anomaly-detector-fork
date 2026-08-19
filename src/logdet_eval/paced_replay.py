"""
paced_replay.py
Feeds a corpus to the real Wazuh manager in wall-clock time, so that timing-based
camouflage can be measured against it at all.

Why this module exists
----------------------
Wazuh's correlation windows are keyed on **arrival time, not on the timestamp in
the log line** (Decision Log, 2026-08-18). Batch replay pushes a month of logs at
it in seconds, so every event is simultaneous to it and an attack spread over
hours still looks like a burst. Three of the eight camouflage strategies --
`slow`, `temporal` and `realistic-combo` -- are therefore unmeasurable in batch
mode and are excluded from the kill-point verdict.

Measured 2026-08-19, the same 15 `Invalid user` lines from one IP:

    burst, 0.2s apart   ->  rule 5710 x14  +  5712 x1   (brute force alert)
    paced, 20s apart    ->  rule 5710 x15  +  5712 x0   (no brute force alert)

Same lines, same rules, opposite verdict. That is the measurement batch replay
cannot make, and it is what this module automates.

What has to be preserved, and what does not
-------------------------------------------
Replaying at true speed is unaffordable -- the kill-point corpus spans 28.5 days.
Two properties of Wazuh's own rules make a much cheaper schedule *equivalent*
rather than merely approximate:

1. **The sshd frequency rules are rate limits.** A rule with `frequency=N` and
   `timeframe=T` fires only if N events land inside T seconds. Spacing events by
   more than `T/N` puts the rate below the threshold, and any *larger* spacing
   keeps it there. So a real gap only has to be honoured up to `MIN_SPACING`;
   past that, clamping it changes nothing the rules can observe. Derived from the
   shipped ruleset (see `RATE_CONSTRAINTS`), the binding case is 360/6 = 60s.

2. **They key on `same_source_ip`.** Two events from different IPs never share a
   counter, so spacing only has to be enforced *per source IP*. Events from other
   addresses can be emitted during a wait rather than after it.

Both are properties of the rules as shipped, read off the ruleset -- not
assumptions about Wazuh's behaviour, and not tuning. Nothing here modifies the
ruleset, the engine, or the container clock; the alternatives that would have
made runs faster (time dilation with rescaled `timeframe`s, or `libfaketime` on
analysisd) were rejected precisely because they alter the third party we are
being compared against.
"""

import json
import subprocess
import time
from dataclasses import dataclass

from logdet.preprocessing import extract_ip

CONTAINER = "wazuh"
REPLAY_LOG = "/var/ossec/logs/test-replay.log"
ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"

# Every `frequency`/`timeframe` pair in 0095-sshd_rules.xml, as shipped by Wazuh
# 4.9.0. The slowest rate a rule can be driven at and still fire is
# `timeframe / frequency`; spacing events wider than the largest such value puts
# them below *every* one of these thresholds.
#   5703 6/360  5705 6/360  5712 8/120  5714 3/120  5719 8/120  5763 8/120
#   5720 frequency=8 with no timeframe -> treated as Wazuh's 360s default
RATE_CONSTRAINTS = {
    "5703": (6, 360), "5705": (6, 360), "5712": (8, 120), "5714": (3, 120),
    "5719": (8, 120), "5720": (8, 360), "5763": (8, 120),
}

# 60s is the binding constraint (360/6); the margin absorbs the ~2s ingestion
# latency and scheduler jitter without pretending to a precision we do not have.
MIN_SPACING = 75.0

# After a run, per-IP counters must be empty before the next one starts or the
# previous condition contaminates it. Restarting analysisd clears them instantly,
# which is exactly the state a full timeframe of silence would produce.
ANALYSISD_WARMUP = 30.0

@dataclass
class Scheduled:
    """One line and the offset, in seconds from the start of the replay, at
    which it must be written."""

    line_number: int          # 1-based, matching ground truth
    text: str
    offset: float


def schedule(lines: list[str], timestamps: list[float],
             min_spacing: float = MIN_SPACING,
             preserve_global_order: bool = False) -> list[Scheduled]:
    """Turn a corpus into a replay timetable.

    `timestamps` are the events' own clock values in epoch seconds. Each line is
    emitted as early as possible subject to one rule: it must sit at least
    `min(real_gap, min_spacing)` after the previous line from the *same source
    IP*. Lines with no IP, and lines whose real gap is already under the
    spacing, cost nothing extra. Output is ordered by emission time.

    `preserve_global_order` additionally forbids a line from being emitted
    before the one that preceded it in the log. It is off by default, and that
    is the single biggest cost lever in this module -- holding global order
    serialises every per-IP chain behind every other one and costs roughly 3x.

    Turning it off is safe **for this corpus**, not in general. Relaxing order
    lets the aggregate event rate run higher than reality, which only matters to
    rules that count events without keying on a source. Every sshd frequency
    rule that can fire here (5703, 5712, 5720, 5763) carries `same_source_ip`;
    the three that do not (5705, 5714, 5719) need `Timeout before
    authentication`, a CRC-32 attack, or a denied user, and the corpus contains
    none of those. Re-check that with `verify_order_relaxation_safe` before
    running this against a different corpus.
    """
    if len(lines) != len(timestamps):
        raise ValueError("lines and timestamps must be the same length")

    out: list[Scheduled] = []
    cursor = 0.0
    last_by_ip: dict[str, tuple[float, float]] = {}   # ip -> (offset, log time)

    for index, (text, event_time) in enumerate(zip(lines, timestamps), start=1):
        ip = extract_ip(text)
        earliest = cursor if preserve_global_order else 0.0
        if ip is not None and ip in last_by_ip:
            prev_offset, prev_time = last_by_ip[ip]
            needed = min(event_time - prev_time, min_spacing)
            earliest = max(earliest, prev_offset + needed)
        if ip is not None:
            last_by_ip[ip] = (earliest, event_time)
        if preserve_global_order:
            cursor = earliest
        out.append(Scheduled(line_number=index, text=text, offset=earliest))

    out.sort(key=lambda item: (item.offset, item.line_number))
    return out


# Trigger patterns for the sshd frequency rules that do NOT carry
# `same_source_ip`. If a corpus contains none of these, relaxing global order
# cannot change any frequency rule's verdict.
UNKEYED_RULE_TRIGGERS = {
    "5705": r"Timeout before authentication",
    "5714": r"CRC-32|crc32",
    "5719": r"not allowed because|DenyUsers|AllowUsers",
}


def verify_order_relaxation_safe(lines: list[str]) -> dict[str, int]:
    """Count lines that could drive a frequency rule with no source key.

    All zeros means `preserve_global_order=False` is sound for this corpus.
    Any non-zero count means the relaxed schedule could inflate that rule's
    firing rate, and the run should hold global order instead.
    """
    import re as _re
    return {rule: sum(1 for line in lines if _re.search(pattern, line, _re.I))
            for rule, pattern in UNKEYED_RULE_TRIGGERS.items()}


def replay_duration(scheduled: list[Scheduled]) -> float:
    return scheduled[-1].offset if scheduled else 0.0


def _exec(command: str, container: str = CONTAINER) -> str:
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", command],
        capture_output=True, text=True, check=True,
    ).stdout


def alerts_line_count(container: str = CONTAINER) -> int:
    return int(_exec(f"wc -l < {ALERTS_JSON}", container).strip() or 0)


def read_alerts(since_line: int, container: str = CONTAINER) -> list[dict]:
    alerts = []
    for raw in _exec(f"tail -n +{since_line + 1} {ALERTS_JSON}", container).splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            alerts.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return alerts


def reset_correlation_state(container: str = CONTAINER,
                            warmup: float = ANALYSISD_WARMUP) -> None:
    """Empty Wazuh's per-IP frequency counters between runs.

    Without this the tail of one condition still sits in the counters when the
    next begins, and the same attacker IPs recur across every seed -- so a run
    could inherit a detection it did not earn.
    """
    subprocess.run(["docker", "exec", container,
                    "/var/ossec/bin/wazuh-control", "restart"],
                   capture_output=True, check=False)
    time.sleep(warmup)


def run(scheduled: list[Scheduled], container: str = CONTAINER,
        progress_every: float = 300.0) -> list[dict]:
    """Write the corpus to the watched file on schedule; return the new alerts.

    Blocks for `replay_duration(scheduled)` seconds by construction -- the wait
    *is* the measurement.
    """
    before = alerts_line_count(container)
    writer = subprocess.Popen(
        ["docker", "exec", "-i", container, "sh", "-c",
         f"while IFS= read -r l; do printf '%s\\n' \"$l\" >> {REPLAY_LOG}; done"],
        stdin=subprocess.PIPE, text=True,
    )
    started = time.monotonic()
    next_report = progress_every
    try:
        for item in scheduled:
            due = started + item.offset
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            writer.stdin.write(item.text + "\n")
            writer.stdin.flush()
            elapsed = time.monotonic() - started
            if elapsed >= next_report:
                print(f"    replay {elapsed / 60:.0f}m / "
                      f"{replay_duration(scheduled) / 60:.0f}m", flush=True)
                next_report += progress_every
    finally:
        writer.stdin.close()
        writer.wait()

    # analysisd is ~2s behind the writer; give the last events time to land.
    time.sleep(15)
    return read_alerts(before, container)


def flagged_lines(alerts: list[dict], scheduled: list[Scheduled],
                  min_level: int) -> set[int]:
    """Map alerts back to 1-based corpus line numbers.

    Wazuh echoes the matched line in `full_log`, so attribution is by exact text.
    Repeated identical lines are consumed in order, which is the same order
    analysisd emitted them in.
    """
    pending: dict[str, list[int]] = {}
    for item in scheduled:
        pending.setdefault(item.text, []).append(item.line_number)
    for numbers in pending.values():
        numbers.reverse()          # pop() then yields ascending line numbers

    hits: set[int] = set()
    for alert in alerts:
        if alert.get("rule", {}).get("level", 0) < min_level:
            continue
        text = alert.get("full_log", "")
        numbers = pending.get(text)
        if numbers:
            hits.add(numbers.pop())
        elif text in pending:
            pass                   # more alerts than copies: fires once per line
    return hits
