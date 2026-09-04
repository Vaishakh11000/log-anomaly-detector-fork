"""live_bakeoff.py -- the two-box bake-off, scored side by side.

The single-box bake-off (`bakeoff.py`) has one writer append every line to
both sinks at once, so ground truth is built as the lines are written. The
two-box bake-off inverts that: the attack lines are *born on the Kali box* as
authentic tool output (CLAUDE.md 2d), shipped over the Cat6 link
(`attack_runner/ship.py`) into the analyzer's ``POST /collector/ingest``, and
they land in the collector file the detector's stream tails. Nothing on the
analyzer authored them, which is the whole point.

This module is the analyzer side of that. Three jobs:

  1. **Feed Wazuh the same lines.** The ingest endpoint only grows the
     collector file (it must not import the evaluation track, CLAUDE.md 5), so
     a `WazuhMirror` tails that file and appends each new line, in order, to
     the file Wazuh's logcollector watches. Order is preserved, so Wazuh's
     line numbers match the collector's -- the property one scorer needs to
     serve both systems.

  2. **Align ground truth.** Kali captures ground truth at launch time
     (`attack_runner/groundtruth.py`): a CSV of ``line_number`` (1-based into
     that run's shipped stream) with a scenario/instance label. Because the
     collector file receives the shipped stream in order, collector line N is
     Kali's shipped line N. Firing several instances into one collector file
     shifts each run's numbers by the file length before that run -- exactly
     the continuous-stream numbering `bakeoff.Manifest` already uses.

  3. **Score both systems** with the kill point's own `scoring.measure_lines`,
     reusing `bakeoff.ours_flagged` / `bakeoff.wazuh_flagged` by rebuilding a
     `Manifest` from the collector file: parse each line with the pipeline's
     own `LineParser` (so the (second, message) keys match our incidents), and
     label it from the merged Kali ground truth.

Attacks-only: no benign background is generated here, so this is not a
false-positive / alert-volume measurement (`bakeoff.run_benign_baseline` is,
single box). Only the camouflage layer is authored; base attacks are real tool
output. What this instrument shows is the *live demonstration* -- attacks
launched on one physical machine, alerts appearing on another -- more than a
new gap number: authentic attacks already read ~100% on both systems in the
injected §4 runs (`results/kali/injected_notes.md`), an attack-shape finding,
not a robustness win.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import pandas as pd

from logdet.preprocessing import LineParser
from logdet_eval import bakeoff, paced_replay, scoring

# Same primary alert level as the kill point and the single-box bake-off, so a
# Wazuh detection means the same thing across all three instruments.
PRIMARY_LEVEL = bakeoff.PRIMARY_LEVEL

# A line that does not parse still occupies a position in the shipped stream,
# so it must keep its line number or every later attack line misaligns. It is
# never an attack line (auth lines parse), so this sentinel timestamp only ever
# lands on benign filler and its key is never looked up by a real incident.
_UNPARSED_TS = datetime(1970, 1, 1)


# --- Ground truth alignment ------------------------------------------------

@dataclass
class GroundTruth:
    """The merged, collector-aligned labels for one live session.

    Kali writes one CSV per fire, numbered 1..N into *that* run's shipped
    stream. `add_fire` shifts a run's numbers by the collector file length
    captured just before it shipped, so all fires share one numbering.
    """

    by_line: dict[int, dict] = field(default_factory=dict)

    def add_fire(self, gt_rows: list[dict], offset: int) -> int:
        """Merge one fire's ground-truth rows, shifted by `offset` collector
        lines already present. Returns how many labelled rows were added."""
        added = 0
        for row in gt_rows:
            line_number = int(row["line_number"]) + offset
            self.by_line[line_number] = {
                "scenario": row.get("scenario"),
                "instance": row.get("instance"),
                "user": row.get("user"),
            }
            added += 1
        return added


def read_ground_truth_csv(text: str) -> list[dict]:
    """Parse the CSV `attack_runner` writes into row dicts. Accepts the raw CSV
    text so the caller can fetch it however it likes (ssh cat, a local file)."""
    from io import StringIO

    frame = pd.read_csv(StringIO(text))
    return frame.to_dict("records")


# --- Rebuilding the manifest from the collector file -----------------------

def build_manifest(collector_path: str | Path, ground_truth: GroundTruth,
                   year: int | None = None) -> bakeoff.Manifest:
    """Replay the collector file into a `Manifest`, labelling attack lines.

    Every non-blank line is recorded so its position matches Kali's shipped
    line number. The parse must be the pipeline's, because our incidents carry
    the `LineParser`'s `message`, and `ours_flagged` keys on (second, message).
    """
    parser = LineParser(year=year)
    manifest = bakeoff.Manifest()
    with open(collector_path) as handle:
        for raw in handle:
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            line_number = len(manifest) + 1
            label = ground_truth.by_line.get(line_number)
            parsed = parser.parse(raw)
            if parsed is None or parsed.get("timestamp") is None:
                manifest.record(text=raw, timestamp=_UNPARSED_TS, message=raw,
                                scenario=label["scenario"] if label else None,
                                instance=label["instance"] if label else None,
                                user=label["user"] if label else None)
                continue
            manifest.record(
                text=raw, timestamp=parsed["timestamp"], message=parsed["message"],
                scenario=label["scenario"] if label else None,
                instance=label["instance"] if label else None,
                user=label["user"] if label else parsed.get("user"),
            )
    return manifest


def score_live(collector_path: str | Path, ground_truth: GroundTruth,
               incidents: list[dict], alerts: list[dict],
               year: int | None = None,
               min_level: int = PRIMARY_LEVEL) -> dict:
    """Score both systems on the whole collector file at once.

    `measure_lines` groups by scenario/instance, so firing several instances
    into one file and scoring once gives the per-scenario and overall pooled
    figures directly -- no separate pooling step.
    """
    manifest = build_manifest(collector_path, ground_truth, year=year)
    ours = bakeoff.ours_flagged(incidents, manifest)
    theirs = bakeoff.wazuh_flagged(alerts, manifest, min_level=min_level)
    truth = manifest.ground_truth()
    total = len(manifest)
    return {
        "lines": total,
        "ours": _augment_overall(scoring.measure_lines(ours, truth, total)),
        "wazuh": _augment_overall(scoring.measure_lines(
            theirs, truth, total, alert_count=len(alerts))),
        "our_incidents": len(incidents),
        "wazuh_alerts": len(alerts),
    }


def _augment_overall(system: dict) -> dict:
    """`measure_lines` carries only rates at the overall level; sum the counts
    from per-scenario so the report and callers can show `2/3` not just a rate.
    """
    per = system["per_scenario"].values()
    system["overall"].update({
        "instances": sum(s["instances"] for s in per),
        "instances_detected": sum(s["instances_detected"] for s in per),
        "attack_lines": sum(s["attack_lines"] for s in per),
        "lines_detected": sum(s["lines_detected"] for s in per),
        "line_detection_rate": system["overall"]["line_detection_rate"],
    })
    return system


# --- Feeding Wazuh the shipped stream --------------------------------------

class WazuhMirror:
    """Tail the collector file and append each complete new line to the file
    Wazuh's logcollector watches, in order and 1:1.

    A partial trailing line (a POST caught mid-flight) is left until its newline
    arrives, the same discipline the file tailer uses: half a log line parses as
    garbage. Runs on its own thread so lines reach Wazuh as they land rather
    than only at scoring time, which is what keeps arrival-time correlation a
    property of Wazuh's rules and not of a late bulk replay.
    """

    def __init__(self, collector_path: str | Path, sink,
                 poll: float = 0.3) -> None:
        self.path = Path(collector_path)
        self.sink = sink
        self.poll = poll
        self._offset = 0
        self.mirrored = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def catch_up(self) -> int:
        """Mirror every complete line since the last call. Returns how many."""
        if not self.path.exists():
            return 0
        with self.path.open() as handle:
            handle.seek(self._offset)
            data = handle.read()
        if "\n" not in data:
            return 0
        complete, _, _rest = data.rpartition("\n")
        written = 0
        for line in complete.split("\n"):
            if line.strip():
                self.sink.write(line)
                written += 1
        self._offset += len(complete) + 1
        self.mirrored += written
        return written

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.catch_up()
            time.sleep(self.poll)
        self.catch_up()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.catch_up()


# --- Orchestration ---------------------------------------------------------

# Camouflage levels the grid can fire, mapped to the strategy sets the shared
# `camouflage` library (vendored on Kali) applies. `none` fires the authentic
# attack unchanged. Timing levels (`slow`) are the paced instrument's domain,
# not this one's -- kept here only so a cell can be requested and marked.
LEVELS: dict[str, list[str]] = {
    "none": [],
    "mimicry": ["mimicry"],
    "rephrase": ["rephrase"],
    "ip_rotate": ["ip_rotate"],
    "slow": ["slow"],
    "realistic-combo": ["mimicry", "rephrase", "ip_rotate", "noise"],
}


def collector_line_count(path: str | Path) -> int:
    """Non-blank lines in the collector file -- the shipped-stream position."""
    path = Path(path)
    if not path.exists():
        return 0
    with path.open() as handle:
        return sum(1 for line in handle if line.strip())


def wait_stable(path: str | Path, settle: float, poll: float = 0.5,
                timeout: float = 180.0) -> int:
    """Block until the collector file has stopped growing for `settle` seconds.

    A fire's lines arrive over HTTP a batch at a time, so the file grows for a
    moment after `attack-run` returns; the next fire's offset is only correct
    once this one has fully landed.
    """
    last = -1
    stable_since = time.time()
    start = time.time()
    while time.time() - start < timeout:
        count = collector_line_count(path)
        if count != last:
            last = count
            stable_since = time.time()
        elif time.time() - stable_since >= settle:
            return count
        time.sleep(poll)
    return last


def run_live(cells: list[dict], fire: Callable[[dict], list[dict]],
             incidents_reader: Callable[[], list[dict]],
             wazuh_mark: Callable[[], int],
             wazuh_since: Callable[[int], list[dict]],
             collector_path: str | Path, sink,
             *, reset: Callable[[], None] | None = None,
             settle: float = 6.0, year: int | None = None,
             min_level: int = PRIMARY_LEVEL,
             on_cell: Callable[[dict, int, int], None] | None = None) -> dict:
    """Drive a whole live session and score both systems once at the end.

    `fire(cell)` launches one attack on Kali (shipping over the link) and
    returns its ground-truth rows. Everything external is injected -- `fire`,
    the two readers, the Wazuh sink, `reset` -- so the orchestration is
    testable with stubs and no ssh, container or service, the same reason
    `bakeoff.Readers` exists.
    """
    if reset is not None:
        reset()
    ground_truth = GroundTruth()
    mirror = WazuhMirror(collector_path, sink)
    mirror.start()
    mark = wazuh_mark()
    try:
        for cell in cells:
            pre_sleep = cell.get("pre_sleep", 0)
            if pre_sleep:
                # brute_force fires all from 127.0.0.1 (hydra cannot bind a
                # source), and sshd's srclimit_penalise is keyed per source /32,
                # so back-to-back instances get throttled to a single line. Let
                # the penalty decay before the next instance (v2 capture fix).
                time.sleep(pre_sleep)
            offset = collector_line_count(collector_path)
            gt_rows = fire(cell)
            wait_stable(collector_path, settle)
            added = ground_truth.add_fire(gt_rows, offset)
            if on_cell is not None:
                on_cell(cell, offset, added)
        # Let the last fire's lines finish landing, then let the detector's
        # micro-batcher and the Wazuh mirror drain what arrived.
        wait_stable(collector_path, settle)
        time.sleep(settle)
        mirror.catch_up()
    finally:
        mirror.stop()

    incidents = incidents_reader()
    alerts = wazuh_since(mark)
    result = score_live(collector_path, ground_truth, incidents, alerts,
                        year=year, min_level=min_level)
    result["cells"] = cells
    result["mirrored"] = mirror.mirrored
    return result


class KaliFirer:
    """Fire one attack on the Kali box over ssh, shipping over the link.

    The attack still runs against Kali's own sshd on loopback (every authentic
    capture in this project does); the link only carries the captured lines to
    the analyzer. So the attribution `--source-ip` stays the loopback address
    the auth log actually shows, not the link address.
    """

    def __init__(self, ssh_host: str, peer: str, *, runner_dir: str = "~/attack_runner",
                 year: int | None = None, attempts: int = 15,
                 users: tuple[str, ...] = ("root", "admin", "test", "oracle", "postgres"),
                 identifiers: tuple[str, ...] = ("sshd", "sshd-session"),
                 source_base: str = "127.0.0.1",
                 gt_remote: str = "/tmp/live_gt.csv",
                 spool_remote: str = "/tmp/live_spool") -> None:
        self.ssh_host = ssh_host
        self.peer = peer.rstrip("/")
        self.runner_dir = runner_dir
        self.year = year
        self.attempts = attempts
        self.users = users
        self.identifiers = identifiers
        self.source_base = source_base
        self.gt_remote = gt_remote
        self.spool_remote = spool_remote

    def _remote_command(self, cell: dict) -> str:
        import shlex
        attack = cell["attack"]
        instance = cell["instance"]
        level = cell.get("level", "none")
        camouflage = LEVELS.get(level, [])
        # Enumeration binds a distinct loopback source per instance so sshd's
        # per-source penalty does not empty later instances (v2 capture fix).
        source_ip = (self.source_base if attack != "enumeration"
                     else f"127.0.0.{10 + instance}")
        year = self.year or datetime.now().year
        parts = [
            "python3", "-m", "attack_runner.cli", attack,
            "--target-host", "127.0.0.1", "--target-port", "22",
            "--source-ip", source_ip, "--instance", str(instance),
            "--year", str(year),
            "--journald-identifier", *self.identifiers,
            "--peer", self.peer, "--spool", self.spool_remote,
            "--ground-truth-out", self.gt_remote,
            "--records-out", "/tmp/live_records.json",
        ]
        if attack == "brute_force":
            parts += ["--attempts", str(self.attempts), "--user", "root"]
        elif attack == "enumeration":
            parts += ["--users", *self.users]
        if camouflage:
            parts += ["--camouflage", *camouflage]
        return f"cd {self.runner_dir} && " + " ".join(shlex.quote(p) for p in parts)

    def __call__(self, cell: dict) -> list[dict]:
        import subprocess
        launch = subprocess.run(["ssh", self.ssh_host, self._remote_command(cell)],
                                capture_output=True, text=True, timeout=180)
        if launch.returncode != 0:
            raise RuntimeError(f"kali fire failed: {launch.stderr.strip()}")
        fetched = subprocess.run(["ssh", self.ssh_host, f"cat {self.gt_remote}"],
                                 capture_output=True, text=True, timeout=30, check=True)
        return read_ground_truth_csv(fetched.stdout)


# --- Report ----------------------------------------------------------------

def _row(system: dict) -> str:
    overall = system["overall"]
    return (f"{overall['instance_detection_rate'] * 100:.0f}% "
            f"({overall['instances_detected']}/{overall['instances']}) / "
            f"{overall['line_detection_rate'] * 100:.0f}%")


def render_report(result: dict, meta: dict) -> str:
    lines = [
        "# Live two-box bake-off",
        "",
        "Authentic attacks launched on the Kali box, shipped over the Cat6 link "
        "into `POST /collector/ingest`, scored side by side. Attacks-only "
        "(no benign background), so this is not an alert-volume measurement.",
        "",
        f"- peer: `{meta.get('peer')}`  seeds: live firings, not recorded seeds",
        f"- collector lines: {result['lines']}  mirrored to Wazuh: {result.get('mirrored')}",
        f"- our incidents: {result['our_incidents']}  Wazuh alerts (level "
        f">= {meta.get('min_level', PRIMARY_LEVEL)}): {result['wazuh_alerts']}",
        "",
        "| system | instance / line detection |",
        "|---|---|",
        f"| this detector | {_row(result['ours'])} |",
        f"| Wazuh | {_row(result['wazuh'])} |",
        "",
        "## Per scenario",
        "",
        "| scenario | ours (inst / lines) | Wazuh (inst / lines) |",
        "|---|---|---|",
    ]
    scenarios = sorted(set(result["ours"]["per_scenario"])
                       | set(result["wazuh"]["per_scenario"]))
    for scenario in scenarios:
        ours = result["ours"]["per_scenario"].get(scenario)
        wazuh = result["wazuh"]["per_scenario"].get(scenario)
        lines.append(
            f"| {scenario} | "
            f"{_row({'overall': ours}) if ours else '-'} | "
            f"{_row({'overall': wazuh}) if wazuh else '-'} |")
    lines.append("")
    lines.append("Interpretation lives in `results/bakeoff_live/notes.md`, not here "
                 "(bake-off precedent: a generator that writes conclusions is "
                 "scripting the narrative).")
    lines.append("")
    return "\n".join(lines)


def cli(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import subprocess

    from logdet.api_client import ApiClient
    from logdet.config import COLLECTOR_LOG_PATH
    from logdet_eval import wazuh_runner

    parser = argparse.ArgumentParser(
        description="Live two-box bake-off: Kali ships authentic attacks over "
                    "the link; detector and Wazuh scored side by side.")
    parser.add_argument("--ssh-host", default="kali")
    parser.add_argument("--peer", default="http://10.10.10.2:8000")
    parser.add_argument("--api", default="http://10.10.10.2:8000",
                        help="analyzer API base for reading incidents")
    parser.add_argument("--collector", default=COLLECTOR_LOG_PATH)
    parser.add_argument("--attacks", nargs="+", default=["brute_force", "enumeration"],
                        choices=["brute_force", "enumeration"])
    parser.add_argument("--repeat", type=int, default=3,
                        help="instances per attack")
    parser.add_argument("--level", default="none", choices=sorted(LEVELS))
    parser.add_argument("--attempts", type=int, default=15)
    parser.add_argument("--settle", type=float, default=6.0)
    parser.add_argument("--brute-space", type=float, default=90.0,
                        help="seconds to wait before each brute_force instance "
                             "after the first, so sshd's per-source penalty decays")
    parser.add_argument("--min-level", type=int, default=PRIMARY_LEVEL)
    parser.add_argument("--output", default="results/bakeoff_live")
    args = parser.parse_args(argv)

    if not wazuh_runner.container_available():
        parser.error("Wazuh container is not answering -- start it "
                     "(docker start wazuh) and wait ~20-30s for analysisd.")

    cells = []
    for attack in args.attacks:
        for index in range(args.repeat):
            cell = {"attack": attack, "level": args.level, "instance": index + 1}
            if attack == "brute_force" and index > 0:
                cell["pre_sleep"] = args.brute_space
            cells.append(cell)

    client = ApiClient(args.api)

    def reset() -> None:
        Path(args.collector).parent.mkdir(parents=True, exist_ok=True)
        with open(args.collector, "w"):
            pass
        try:
            client.stop_stream()
        except Exception:
            pass
        paced_replay.reset_correlation_state()
        client.start_stream(source="file", path="data/live/collector.log",
                            from_start=True)

    firer = KaliFirer(args.ssh_host, args.peer, year=None, attempts=args.attempts)

    # Reset (which restarts Wazuh) BEFORE opening the sink's long-lived
    # `docker exec` shell, so that shell is not opened across the restart.
    print("resetting: truncating collector, restarting Wazuh, restarting stream...")
    reset()
    sink = bakeoff.WazuhSink()

    def on_cell(cell: dict, offset: int, added: int) -> None:
        print(f"fired {cell['attack']} #{cell['instance']} @ {args.level}: "
              f"+{added} attack line(s) at collector offset {offset}")

    try:
        result = run_live(
            cells, firer, client.incidents,
            paced_replay.alerts_line_count,
            paced_replay.read_alerts,
            args.collector, sink, reset=None, settle=args.settle,
            min_level=args.min_level, on_cell=on_cell)
    finally:
        sink.close()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    report = render_report(result, {"peer": args.peer, "min_level": args.min_level})
    (out / "bakeoff_live.md").write_text(report)
    # The raw result, minus the (large) cell echo already in the report.
    serialisable = {k: v for k, v in result.items() if k != "cells"}
    (out / "bakeoff_live.json").write_text(json.dumps(serialisable, indent=1, default=str))
    print(report)
    return 0

