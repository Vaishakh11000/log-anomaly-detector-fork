"""
coverage_report.py
The detection coverage matrix: which ATT&CK techniques can this system even
see, and which does it only claim?

Three questions, kept apart because they have different strengths of evidence:

  1. What does ATT&CK say is detectable from the telemetry we ingest?
     Computed from the pinned STIX bundle, not chosen here: a technique enters
     the universe when one of ATT&CK's own detection strategies has an analytic
     whose log source is one we read. That is a third-party denominator, which
     is the whole point -- a coverage figure over a denominator the author
     picked measures nothing.

  2. Which of those does the authored keyword table map?
     Read from `logdet.mitre_mapping`.

  3. Which has this system ever actually emitted, on a real corpus?
     Measured by running the mapper over parsed corpora. A technique mapped but
     never observed is a claim, not a capability, and the matrix says so.

The denominator is reported twice and never merged. ATT&CK's Linux analytics
for authentication techniques are written against `auditd`, not syslog -- its
guidance for T1110 Brute Force is `auditd:USER_LOGIN` -- so a strict log-source
match understates what an auth.log stream can see, while counting auditd as
ours overstates what we read. Both are printed: the strict figure is ATT&CK's,
the wider one is an authored claim about events rather than files.

Nothing here is a detection change; it reads the mapper and reports.
"""

import argparse
import collections
import json
import tempfile
from pathlib import Path

import pandas as pd

from logdet.attack import (
    ATTACK_VERSION,
    DECLARED_LOG_SOURCES,
    EQUIVALENT_LOG_SOURCES,
    fetch_bundle,
    parse_bundle,
)
from logdet.config import RAW_DATA_DIR, RESULTS_DIR
from logdet.mitre_mapping import MITRE_LOOKUP, SIGNAL_LOOKUP, map_to_mitre
from logdet.preprocessing import preprocess_file

DEFAULT_OUTPUT = Path(RESULTS_DIR) / "coverage"


def authored_sources() -> dict[str, str]:
    """technique_id -> how it is mapped: a keyword match or a structural signal."""
    mapped = {entry["technique_id"]: "keyword" for entry in MITRE_LOOKUP}
    for entry in SIGNAL_LOOKUP.values():
        mapped[entry["technique_id"]] = "signal"
    return mapped


def visible_universe(parsed: dict, log_sources: frozenset[str]) -> dict[str, dict]:
    """Techniques ATT&CK says are detectable from `log_sources`."""
    return {
        technique_id: entry
        for technique_id, entry in parsed["techniques"].items()
        if set(entry["log_sources"]) & log_sources
        and not entry["deprecated"] and not entry["revoked"]
    }


def observe_corpus(log_path: Path, year: int, limit: int | None = None) -> dict[str, int]:
    """Lines per technique the keyword table matches on a real corpus.

    Parses first rather than grepping the raw file, so what is counted is the
    `message` field the pipeline actually maps -- a raw line also carries the
    host and process, and matching there would count a technique the detector
    would never attach.
    """
    with tempfile.TemporaryDirectory() as tmp:
        frame = preprocess_file(str(log_path), str(Path(tmp) / "parsed.csv"), year=year)
    if limit:
        frame = frame.head(limit)

    counts: collections.Counter = collections.Counter()
    for message in frame.get("message", []):
        for entry in map_to_mitre(message):
            counts[entry["technique_id"]] += 1
    counts["_lines"] = len(frame)
    return dict(counts)


def observe_incidents(incidents_path: Path) -> dict[str, int]:
    """Incidents per technique from a finished pipeline run.

    The two signal-derived techniques (impossible travel, account enumeration)
    exist only across an incident, so no line-level count can evidence them.
    This is the only place they can be observed.
    """
    incidents = json.loads(Path(incidents_path).read_text())
    counts: collections.Counter = collections.Counter()
    for incident in incidents:
        for technique in incident.get("mitre_techniques", []):
            counts[technique["technique_id"]] += 1
    counts["_incidents"] = len(incidents)
    return dict(counts)


def build_matrix(parsed: dict, observations: dict[str, dict[str, int]]) -> list[dict]:
    """One row per technique: what ATT&CK calls it, whether we map it, and
    whether it has ever been seen."""
    mapped = authored_sources()
    strict = visible_universe(parsed, DECLARED_LOG_SOURCES)
    wider = visible_universe(parsed, DECLARED_LOG_SOURCES | EQUIVALENT_LOG_SOURCES)

    rows = []
    for technique_id in sorted(set(mapped) | set(wider)):
        entry = parsed["techniques"].get(technique_id)
        if entry is None:
            continue
        seen = {name: counts.get(technique_id, 0) for name, counts in observations.items()}
        rows.append({
            "technique_id": technique_id,
            "name": entry["name"],
            "tactics": entry["tactics"],
            "kill_chain": min(entry["kill_chain"], default=99),
            "mapped_by": mapped.get(technique_id),
            "in_strict_universe": technique_id in strict,
            "in_wider_universe": technique_id in wider,
            "attack_log_sources": sorted(
                set(entry["log_sources"]) & (DECLARED_LOG_SOURCES | EQUIVALENT_LOG_SOURCES)),
            "observed": seen,
        })
    return sorted(rows, key=lambda r: (r["kill_chain"], r["technique_id"]))


def summarise(rows: list[dict]) -> dict:
    mapped = [r for r in rows if r["mapped_by"]]
    strict = [r for r in rows if r["in_strict_universe"]]
    wider = [r for r in rows if r["in_wider_universe"]]
    observed = [r for r in mapped if any(count for count in r["observed"].values())]
    signal_only = [r for r in mapped if r["mapped_by"] == "signal"]
    return {
        "attack_version": ATTACK_VERSION,
        "mapped": len(mapped),
        "strict_universe": len(strict),
        "wider_universe": len(wider),
        "mapped_in_strict": len([r for r in mapped if r["in_strict_universe"]]),
        "mapped_in_wider": len([r for r in mapped if r["in_wider_universe"]]),
        "mapped_outside_universe": len([r for r in mapped if not r["in_wider_universe"]]),
        "mapped_and_observed": len(observed),
        "mapped_never_observed": len(mapped) - len(observed),
        "signal_mapped": len(signal_only),
    }


def render(rows: list[dict], summary: dict, corpora: dict[str, dict[str, int]]) -> str:
    out: list[str] = []
    out.append("# Detection coverage matrix\n")
    out.append(f"ATT&CK Enterprise **{summary['attack_version']}**, pinned and verified by "
               "SHA-256 (`logdet.attack`). Every technique name, tactic and declared log "
               "source below is ATT&CK's; only the keyword table that attaches a technique "
               "to a log message is authored.\n")

    out.append("## What the denominator is\n")
    out.append("A technique is *visible* when one of ATT&CK's own detection strategies "
               "has an analytic whose log source is one this system reads. Two readings, "
               "reported separately because they are not equally defensible:\n")
    out.append(f"- **strict** -- ATT&CK's syslog log sources "
               f"(`{'`, `'.join(sorted(DECLARED_LOG_SOURCES))}`): "
               f"**{summary['strict_universe']}** techniques.")
    out.append(f"- **wider** -- plus auditd's authentication events "
               f"(`{'`, `'.join(sorted(EQUIVALENT_LOG_SOURCES))}`), which record the same "
               f"events from a different subsystem: **{summary['wider_universe']}** "
               "techniques. This half is an authored claim, not ATT&CK's.\n")

    out.append("## Headline\n")
    out.append("| | count |")
    out.append("|---|---|")
    out.append(f"| Techniques the table maps | {summary['mapped']} |")
    out.append(f"| ...inside the strict universe | {summary['mapped_in_strict']} "
               f"of {summary['strict_universe']} |")
    out.append(f"| ...inside the wider universe | {summary['mapped_in_wider']} "
               f"of {summary['wider_universe']} |")
    out.append(f"| ...outside both (mapped from telemetry ATT&CK does not credit) "
               f"| {summary['mapped_outside_universe']} |")
    out.append(f"| Mapped **and** observed on a corpus | {summary['mapped_and_observed']} |")
    out.append(f"| Mapped but **never** observed | {summary['mapped_never_observed']} |\n")

    corpus_names = list(corpora)
    out.append("## The matrix\n")
    header = "| tactic | technique | mapped | ATT&CK log sources we read | " + \
             " | ".join(corpus_names) + " |"
    out.append(header)
    out.append("|---" * (4 + len(corpus_names)) + "|")
    line_level = {name for name, counts in corpora.items() if "_lines" in counts}
    for row in rows:
        cells = []
        for name in corpus_names:
            if not row["mapped_by"]:
                cells.append("-")
            elif row["mapped_by"] == "signal" and name in line_level:
                # Structural signals exist only across an incident; a zero here
                # would read as "never seen" when it means "not askable".
                cells.append("n/a")
            else:
                cells.append(str(row["observed"].get(name, 0)))
        counts = " | ".join(cells)
        out.append(
            f"| {' / '.join(row['tactics'])} | `{row['technique_id']}` {row['name']} | "
            f"{row['mapped_by'] or '**no**'} | "
            f"{', '.join(f'`{s}`' for s in row['attack_log_sources']) or '-'} | {counts} |")

    out.append("\n### How to read a row\n")
    out.append("A `0` in a corpus column is a technique the table can emit and this corpus "
               "never triggered -- a claim with no evidence behind it, not a miss. The two "
               "signal-derived techniques (impossible travel, account enumeration) cannot "
               "appear in a line-level column at all: they exist only across an incident, "
               "so they are counted from a finished pipeline run when one is supplied and "
               "read `n/a` in a line-level column.\n")
    out.append("A sub-technique marked **no** under a parent this table does map is not a "
               "gap in detection so much as a gap in *resolution*: the table says T1110 "
               "Brute Force where ATT&CK distinguishes password guessing from spraying "
               "from stuffing, and nothing in an auth line separates them.\n")

    out.append("### Corpora\n")
    for name, counts in corpora.items():
        size = counts.get("_lines") or counts.get("_incidents") or 0
        unit = "lines" if "_lines" in counts else "incidents"
        out.append(f"- **{name}** -- {size} {unit}")
    return "\n".join(out) + "\n"


def run(output_dir: Path, incidents: Path | None, openssh_limit: int | None) -> dict:
    fetch_bundle()
    parsed = parse_bundle()

    corpora: dict[str, dict[str, int]] = {}
    synthetic = Path(RAW_DATA_DIR) / "synthetic.log"
    if synthetic.exists():
        corpora["synthetic"] = observe_corpus(synthetic, year=2026)

    openssh = Path("data/external/SSH.log")
    if openssh.exists():
        corpora["openssh"] = observe_corpus(openssh, year=2026, limit=openssh_limit)

    if incidents and Path(incidents).exists():
        corpora["incidents"] = observe_incidents(Path(incidents))

    rows = build_matrix(parsed, corpora)
    summary = summarise(rows)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "coverage.md").write_text(render(rows, summary, corpora))
    (output_dir / "coverage.json").write_text(json.dumps(
        {"summary": summary, "corpora": corpora, "rows": rows}, indent=2) + "\n")
    return summary


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Detection coverage matrix against the pinned ATT&CK bundle.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--incidents", default=None,
                        help="a finished incidents.json, for the incident-level signals")
    parser.add_argument("--openssh-limit", type=int, default=None,
                        help="score only the first N parsed OpenSSH lines")
    args = parser.parse_args()

    summary = run(Path(args.output), args.incidents, args.openssh_limit)
    print(f"ATT&CK {summary['attack_version']}: table maps {summary['mapped']} techniques; "
          f"{summary['mapped_in_strict']}/{summary['strict_universe']} of the strict "
          f"universe, {summary['mapped_in_wider']}/{summary['wider_universe']} of the wider.")
    print(f"Observed on a corpus: {summary['mapped_and_observed']}; "
          f"never observed: {summary['mapped_never_observed']}")
    print(f"Report: {Path(args.output) / 'coverage.md'}")


if __name__ == "__main__":
    cli()
