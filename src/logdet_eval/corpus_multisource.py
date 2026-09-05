"""
corpus_multisource.py
Build a two-source corpus -- real ssh auth + real web access -- in which an
authentic ssh attack and an authentic web attack from the *same* source IP land
close enough in time to be one incident, so multi-source correlation can be
measured with real detection rather than demonstrated on a toy.

Why this exists
---------------
Stage 4 declined multi-source correlation for want of a corpus: `Linux.log`,
the only real multi-service log here, carries exactly **one** genuine
cross-service link in 9,666 events (`results/correlation/notes.md`). The graph
would find nothing to correlate. Stage 7's ECS boundary and the nginx access-log
parser (`logdet/weblog.py`) closed the *format* gap -- a web line and an ssh
line already reduce to the same eight columns and group on `source_ip` with no
detection change (proven: a flagged 401 burst and a flagged Failed-password
burst from one IP form a single `nginx`+`sshd` incident). What was still missing
is an *attack* that spans the two sources, and §1b/§8 forbid the author planting
a synthetic one and then finding it.

So both halves are authentic tool output captured on the Kali box
(`attack_runner`): scenario A/C from ssh (`brute_force`/`enumeration`) and
scenario W from the web (`web_bruteforce`, a real 401 burst in an access log).
This module injects them into the real OpenSSH benign background -- the same
background `corpus_captured` uses, so the ssh half gets `root`'s genuine per-user
baseline -- with an optional real web benign background, and harmonises the two
attack halves onto one source IP so the graph joins them.

What is authored, and what is not
---------------------------------
Real: every background line, and every attack line verbatim as the tool produced
it (message, spacing).
Authored, and stated rather than hidden:
  - **The shared source IP.** Two captures run on one box do not naturally share
    an internet-routable address, so the attack lines of both halves are
    overwritten onto one `shared_ip`. This is safe for detection -- `template`
    masks every IP before the embedder sees it, so the detector never reads the
    address -- and it is the *whole point* for correlation, which is the graph's
    `source_ip` join. Overwriting only the attack rows keeps the benign traffic's
    own IPs, so the join is not made trivial by giving everything one address.
  - **When each pair is injected**, drawn like `corpus_captured`'s placement so
    neither the correlation nor the detection is handed an easier position.
  - The ssh and web halves of one cross-source incident are paired by index and
    placed a few minutes apart, inside `INCIDENT_WINDOW_MINUTES`, because a
    real "web login probe then ssh brute force from the same host" is minutes
    apart, not simultaneous.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from logdet.config import INCIDENT_WINDOW_MINUTES
from logdet.preprocessing import preprocess_file
from logdet.weblog import WebLogParser
from logdet_eval.corpus_captured import (
    CapturedInstance,
    SCENARIO_HOURS,
    load_captures,
)
from logdet_eval.corpus_openssh import (
    CORPUS_HOST,
    build_background,
    load_classified,
)
from logdet_eval.generate_logs import write_outputs

# How far after the ssh half the web half is placed. Well inside the incident
# window so the two halves group, but not simultaneous -- a real cross-source
# attack is a sequence, not one instant.
CROSS_SOURCE_GAP = timedelta(minutes=3)

# The columns preprocess_file writes; the web records are conformed to these so
# the two halves concatenate without going ragged.
PARSED_COLUMNS = ["timestamp", "host", "process", "pid", "message", "raw",
                  "user", "source_ip", "template"]


@dataclass
class WebCapturedInstance:
    """One authentic web attack instance, reduced to its labelled access lines.

    The web counterpart of `corpus_captured.CapturedInstance`. Each line is
    already a fully parsed internal record (via WebLogParser), held as an offset
    from the instance's first line so it can be re-stamped anywhere while
    keeping the exact spacing the tool produced.
    """

    scenario: str
    instance: int
    source: str = ""
    # (offset from instance start, parsed record dict)
    lines: list[tuple[timedelta, dict]] = field(default_factory=list)


def load_web_capture(log_path: Path | str, gt_path: Path | str,
                     host: str = "web1") -> list[WebCapturedInstance]:
    """Read one (access.log, ground_truth.csv) pair into its web attack instances.

    Only the ground-truth-labelled lines are kept -- the rest of the capture is
    benign browsing the runner swept in, replaced here by the corpus background.
    Each kept line is parsed by the same WebLogParser the pipeline uses, so the
    record carries `source_ip`, `template` and the masked `message` exactly as
    detection will see them.
    """
    raw = Path(log_path).read_text(errors="ignore").splitlines()
    parser = WebLogParser(host=host)

    rows: list[dict] = []
    with open(gt_path, newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return []

    grouped: dict[tuple[str, int], list[dict]] = {}
    for row in rows:
        grouped.setdefault((row["scenario"], int(row["instance"])), []).append(row)

    instances: list[WebCapturedInstance] = []
    for (scenario, number), group in sorted(grouped.items()):
        parsed: list[tuple[datetime, dict]] = []
        for row in group:
            index = int(row["line_number"]) - 1     # ground truth is 1-based
            if not 0 <= index < len(raw):
                raise ValueError(
                    f"{log_path}: ground truth names line {index + 1}, "
                    f"but the log has {len(raw)} lines")
            record = parser.parse(raw[index])
            if record is None or record["timestamp"] is None:
                raise ValueError(f"{log_path}:{index + 1} did not parse: {raw[index]!r}")
            ts = pd.to_datetime(record["timestamp"]).to_pydatetime()
            parsed.append((ts, record))

        parsed.sort(key=lambda item: item[0])
        base = parsed[0][0]
        instances.append(WebCapturedInstance(
            scenario=scenario, instance=number, source=str(log_path),
            lines=[(ts - base, record) for ts, record in parsed]))

    return instances


def load_web_captures(pairs: list[tuple[str, str]],
                      host: str = "web1") -> list[WebCapturedInstance]:
    """Load several web capture pairs, renumbering instances per scenario.

    Same renumbering as `corpus_captured.load_captures`: two files each numbering
    themselves instance 1 would be pooled into one and silently halve the
    denominator, so instances are renumbered in the order given.
    """
    counters: dict[str, int] = {}
    loaded: list[WebCapturedInstance] = []
    for log_path, gt_path in pairs:
        for captured in load_web_capture(log_path, gt_path, host=host):
            counters[captured.scenario] = counters.get(captured.scenario, 0) + 1
            captured.instance = counters[captured.scenario]
            loaded.append(captured)
    return loaded


def _place_ssh(captured: CapturedInstance, start: datetime) -> list[dict]:
    """Re-stamp one ssh instance's syslog events onto `start`, spacing kept."""
    return [
        {
            "ts": start + offset, "process": process, "pid": pid,
            "message": message, "user": user,
            "scenario": captured.scenario, "instance": captured.instance,
            "description": "",
        }
        for offset, process, pid, message, user in captured.lines
    ]


def _place_web(captured: WebCapturedInstance, start: datetime,
               shared_ip: str) -> list[dict]:
    """Re-stamp one web instance's parsed records onto `start`.

    The source IP is overwritten to `shared_ip` here, on the attack rows only,
    which is what makes the web half join the ssh half in the graph. The record
    is otherwise verbatim; `template` already masks the IP, so detection is
    untouched by the rewrite. `_instance`/`_scenario` are carried for ground
    truth and dropped when the frame is built (reindexed to PARSED_COLUMNS).
    """
    placed = []
    for offset, record in captured.lines:
        row = dict(record)
        row["timestamp"] = start + offset
        row["source_ip"] = shared_ip
        row["_scenario"] = captured.scenario
        row["_instance"] = captured.instance
        placed.append(row)
    return placed


def build_multisource_corpus(ssh_pairs: list[tuple[str, str]],
                             web_pairs: list[tuple[str, str]],
                             shared_ip: str = "203.0.113.66",
                             ambient_ratio: float = 0.05,
                             seed: int = 42,
                             ssh_source: Path | str | None = None,
                             web_background: Path | str | None = None,
                             web_host: str = "web1",
                             ) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Real ssh + web background with authentic cross-source attacks injected.

    Returns `(parsed_frame, ground_truth, manifest)`. The frame is already
    parsed -- the two sources are each parsed by their own parser and
    concatenated -- so a caller embeds and detects on it directly (there is no
    single raw log the mixed corpus can be re-parsed from without one source
    losing its `source_ip`).

    ssh and web captures are paired by index into cross-source instances; a pair
    with no partner is injected on its own (still a real single-source attack).
    """
    if not ssh_pairs and not web_pairs:
        raise ValueError("no captures to inject")

    rng = random.Random(seed)
    ssh_caps = load_captures(ssh_pairs) if ssh_pairs else []
    web_caps = load_web_captures(web_pairs, host=web_host) if web_pairs else []

    benign, attacker, real_users, _subnets = load_classified(ssh_source)
    background = build_background(benign, attacker, ambient_ratio, seed)
    if not background:
        raise RuntimeError("empty background -- the corpus did not load")
    days = sorted({event["ts"].date() for event in background})
    day_starts = [datetime(d.year, d.month, d.day) for d in days]

    # Pair ssh and web instances so a cross-source incident has both halves.
    pairs = _pair_instances(ssh_caps, web_caps)
    ssh_events: list[dict] = []
    web_rows: list[dict] = []
    for ssh_cap, web_cap in pairs:
        day = rng.choice(day_starts)
        hours = SCENARIO_HOURS.get(ssh_cap.scenario if ssh_cap else "C", (0, 23))
        start = day + timedelta(hours=rng.randint(*hours),
                                minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        if ssh_cap is not None:
            ssh_events += _place_ssh(ssh_cap, start)
        if web_cap is not None:
            web_rows += _place_web(web_cap, start + CROSS_SOURCE_GAP, shared_ip)

    ssh_df, ssh_markers = _parse_ssh_half(background, ssh_events, seed, shared_ip)
    web_df = _web_half_frame(web_rows, web_background, web_host)

    merged = pd.concat([ssh_df, web_df], ignore_index=True)
    merged["timestamp"] = pd.to_datetime(merged["timestamp"])
    merged = merged.sort_values("timestamp").reset_index(drop=True)

    web_markers = [(pd.to_datetime(r["timestamp"]), r["message"],
                    r["_scenario"], r["_instance"]) for r in web_rows]
    ground_truth = _ground_truth(merged, ssh_markers + web_markers)
    manifest = _manifest(ssh_caps, web_caps, merged, ground_truth,
                         shared_ip, ambient_ratio, seed, real_users)
    return merged, ground_truth, manifest


def _pair_instances(ssh_caps, web_caps):
    """Zip ssh and web instances into cross-source pairs, padding the shorter."""
    n = max(len(ssh_caps), len(web_caps))
    return [(ssh_caps[i] if i < len(ssh_caps) else None,
             web_caps[i] if i < len(web_caps) else None) for i in range(n)]


def _parse_ssh_half(background, ssh_events, seed, shared_ip):
    """Background + ssh attacks -> a parsed frame, with attack IPs harmonised.

    Written to a syslog file and parsed by the real `preprocess_file`, so the
    ssh half is parsed exactly as every other ssh corpus in the project is. The
    attack rows' `source_ip` is then overwritten to `shared_ip` -- the captures
    were run against loopback, so their real address (127.0.0.1) is not the
    shared internet IP the web half carries.
    """
    import tempfile

    combined = sorted(background + ssh_events, key=lambda e: e["ts"])
    tmp = Path(tempfile.mkdtemp(prefix="multisource_ssh_"))
    log_path, gt_path = tmp / "ssh.log", tmp / "ssh_gt.csv"
    write_outputs(combined, str(log_path), str(gt_path), host=CORPUS_HOST)
    df = preprocess_file(str(log_path), str(tmp / "parsed.csv"),
                         year=combined[0]["ts"].year)

    gt = pd.read_csv(gt_path)
    markers = []
    for _, r in gt.iterrows():
        pos = int(r["line_number"]) - 1              # 1-based into the ssh file
        if 0 <= pos < len(df):
            df.loc[pos, "source_ip"] = shared_ip
            markers.append((pd.to_datetime(df.iloc[pos]["timestamp"]),
                            df.iloc[pos]["message"], r["scenario"], int(r["instance"])))
    return df, markers


def _web_half_frame(web_rows, web_background, web_host):
    """The web attack rows (+ optional real benign web background) as a frame."""
    rows = list(web_rows)
    if web_background is not None:
        parser = WebLogParser(host=web_host)
        for line in Path(web_background).read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            record = parser.parse(line)
            if record is not None and record["timestamp"] is not None:
                record = dict(record)
                record["timestamp"] = pd.to_datetime(record["timestamp"]).to_pydatetime()
                rows.append(record)
    if not rows:
        return pd.DataFrame(columns=PARSED_COLUMNS)
    return pd.DataFrame(rows).reindex(columns=PARSED_COLUMNS)


def _ground_truth(merged, markers):
    """Number the attack lines against the merged frame.

    Each marker is (timestamp, message, scenario, instance) recorded when the
    attack row was placed -- from the ssh ground truth for the ssh half and from
    the placed records for the web half. A marker is matched to the merged row
    with the same (timestamp, message), each merged row consumed at most once so
    repeated identical attack lines each take a distinct line number. Line
    numbers are 1-based into the merged corpus, the shape `scoring.measure_lines`
    reads.
    """
    remaining: dict[tuple, list[tuple[str, int]]] = {}
    for ts, message, scenario, instance in markers:
        remaining.setdefault((ts, message), []).append((scenario, instance))

    rows = []
    for pos, row in merged.iterrows():
        key = (row["timestamp"], row["message"])
        bucket = remaining.get(key)
        if bucket:
            scenario, instance = bucket.pop(0)
            rows.append([pos + 1, row["timestamp"].isoformat(), row.get("user"),
                         scenario, instance, ""])

    return pd.DataFrame(rows, columns=["line_number", "timestamp", "user",
                                       "scenario", "instance", "description"])


def _manifest(ssh_caps, web_caps, merged, ground_truth, shared_ip,
              ambient_ratio, seed, real_users):
    return {
        "corpus": "loghub-openssh + authentic-kali ssh + web capture",
        "shared_ip": shared_ip,
        "ambient_ratio": ambient_ratio,
        "seed": seed,
        "total_lines": int(len(merged)),
        "attack_lines": int(len(ground_truth)),
        "ssh_instances": len(ssh_caps),
        "web_instances": len(web_caps),
        "real_users": real_users,
        "host": CORPUS_HOST,
        "web_host": "web1",
        "scenarios": sorted(ground_truth["scenario"].unique().tolist())
        if len(ground_truth) else [],
    }
