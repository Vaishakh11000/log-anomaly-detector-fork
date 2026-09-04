"""
ecs.py
Maps this project's internal event and incident records onto the Elastic Common
Schema (ECS), and back again, at the *boundaries* of the pipeline.

Why this module exists (Stage 7)
--------------------------------
Detection, grouping and scoring all key on a small set of internal column names
-- ``user``, ``source_ip``, ``host``, ``process``, ``timestamp``, ``message``,
``template`` -- which are already a de-facto common schema. ECS is the *standard
naming* of that same schema. Adopting it buys interoperability: an incident this
system emits can be read by any tool that speaks ECS, and a source that already
emits ECS (a shipper, a web-log parser, journald exported as JSON) can be mapped
straight onto the internal columns without a bespoke parser per format.

The design decision that keeps this safe
----------------------------------------
ECS is treated as an *export/import format*, never as the internal
representation. Nothing in the pipeline reads ECS: ``preprocessing`` still emits
the internal columns, detection still keys on them, and this module is imported
only at the edges (an ECS export of finished incidents; an ECS-native source
mapped in). Because this file adds a new module and changes no detection code, a
default parse produces exactly the columns every number in ``results/`` was
computed from -- there is nothing here for section 4 to measure. That is the same
discipline the Drain3 ``template_id`` column followed: add the capability first,
in a form that cannot move a detection number, and let anything that *consumes*
it be the change that owes the benchmark.

What maps to what
-----------------
Internal event record            ECS field
    timestamp                ->  @timestamp   (ISO 8601)
    host                     ->  host.name, host.hostname
    process                  ->  process.name
    pid                      ->  process.pid  (int)
    message                  ->  message
    user                     ->  user.name    (dropped when not a real identity)
    source_ip                ->  source.ip
    raw                      ->  event.original
    template / template_id   ->  logdet.template / logdet.template_id  (namespaced)

``event.category`` / ``event.action`` / ``event.outcome`` are filled from the
message text by a small keyword classifier (``categorize``). It is best-effort
labelling in the same spirit as ``extract_user`` -- a projection of what the line
already says, not a detection signal -- and nothing in this project reads it
back. It is here because ECS consumers expect an event to be categorized, and a
``Failed password`` line carrying ``event.outcome: failure`` is what makes the
export useful to another SIEM.

The custom fields live under a ``logdet`` namespace so they cannot collide with
ECS-reserved subfields (ECS defines its own ``log.*``). ECS documents are nested
dicts (the canonical form); ``flatten`` produces the dotted-key form some tabular
consumers want, and ``to_ndjson`` writes one document per line.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

from logdet.entity_graph import normalise_identity

ECS_VERSION = "8.11"


# --- event categorization (best-effort, from the message text) --------------
#
# One small table rather than scattered conditionals. Each entry is
# (compiled pattern, category list, action, outcome). First match wins, so more
# specific patterns come first. Everything unmatched is a bare ``event`` with an
# unknown outcome, which is the honest label for a line we did not recognise.
_CATEGORY_RULES: list[tuple[re.Pattern, list[str], str, str]] = [
    (re.compile(r"invalid user", re.I),
     ["authentication"], "invalid-user", "failure"),
    (re.compile(r"failed (password|none|publickey)", re.I),
     ["authentication"], "logon-failed", "failure"),
    (re.compile(r"authentication failure|auth(entication)? fail", re.I),
     ["authentication"], "logon-failed", "failure"),
    (re.compile(r"accepted (password|publickey|keyboard)", re.I),
     ["authentication"], "logged-in", "success"),
    (re.compile(r"session opened", re.I),
     ["authentication", "session"], "session-opened", "success"),
    (re.compile(r"session closed", re.I),
     ["session"], "session-closed", "unknown"),
    (re.compile(r"disconnect|connection closed|bye bye", re.I),
     ["network"], "disconnected", "unknown"),
]


def categorize(message: str) -> dict[str, Any]:
    """ECS ``event.*`` categorization for one message, best-effort.

    Returns the ``category`` list, ``action`` and ``outcome``. Unrecognised
    lines get ``category: []`` and ``outcome: unknown`` rather than a guess --
    labelling a line we do not understand as a success or failure would be an
    invention, which is the exact failure mode the narrative work spent two
    sessions closing.
    """
    text = message or ""
    for pattern, category, action, outcome in _CATEGORY_RULES:
        if pattern.search(text):
            return {"category": category, "action": action, "outcome": outcome}
    return {"category": [], "action": None, "outcome": "unknown"}


def _iso(timestamp) -> str | None:
    """A timestamp as ISO 8601, or None. Accepts a datetime, a pandas
    Timestamp, or an already-stringified one (the incident JSON stores strings)."""
    if timestamp is None:
        return None
    if isinstance(timestamp, str):
        if not timestamp:
            return None
        # A parsed CSV / the incident JSON stores "YYYY-MM-DD HH:MM:SS" -- ISO
        # 8601 with a space where the standard wants a 'T'. A consumer expecting
        # @timestamp to be ISO would reject the space, so normalise just that
        # shape and leave anything else untouched.
        if re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", timestamp):
            return timestamp.replace(" ", "T", 1)
        return timestamp
    isoformat = getattr(timestamp, "isoformat", None)
    if isoformat is not None:
        try:
            return isoformat()
        except Exception:
            return None
    return str(timestamp)


def _int_or_none(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (ValueError, TypeError):
        return None


def _prune(doc: dict) -> dict:
    """Drop keys whose value is None or an empty dict, recursively, so an ECS
    document carries only the fields a line actually had. An empty ``user`` or
    ``source`` object is noise to a consumer and, worse, reads as a claim that
    the field was looked for and found empty."""
    cleaned: dict[str, Any] = {}
    for key, value in doc.items():
        if isinstance(value, dict):
            nested = _prune(value)
            if nested:
                cleaned[key] = nested
        elif value is None:
            continue
        elif isinstance(value, float) and math.isnan(value):
            # pandas turns a missing CSV cell into a float NaN, which survives a
            # None check and serialises to the token ``NaN`` -- invalid JSON that
            # a strict consumer rejects. A missing field is dropped, not emitted.
            continue
        else:
            cleaned[key] = value
    return cleaned


# --- event record -> ECS ----------------------------------------------------

def event_to_ecs(record: dict, *,
                 module: str | None = None,
                 categorize_event: bool = True) -> dict:
    """One parsed event record -> a nested ECS document.

    ``record`` is what ``preprocessing.LineParser.parse`` produces. ``module``
    labels the source (``event.module``, e.g. ``"auth"``/``"web"``); when None it
    falls back to the process name, which for this project's corpora is ``sshd``.
    ``categorize_event`` fills ``event.category``/``action``/``outcome`` from the
    message -- off if a caller wants the raw projection with no interpretation.
    """
    message = record.get("message")
    user = normalise_identity(record.get("user"))

    event_block: dict[str, Any] = {
        "kind": "event",
        "module": module or record.get("process"),
        "dataset": record.get("process"),
        "original": record.get("raw"),
    }
    if categorize_event and message is not None:
        event_block.update(categorize(message))

    doc = {
        "@timestamp": _iso(record.get("timestamp")),
        "message": message,
        "ecs": {"version": ECS_VERSION},
        "event": event_block,
        "host": {
            "name": record.get("host"),
            "hostname": record.get("host"),
        },
        "process": {
            "name": record.get("process"),
            "pid": _int_or_none(record.get("pid")),
        },
        "user": {"name": user},
        "source": {"ip": record.get("source_ip")},
        "logdet": {
            "template": record.get("template"),
            "template_id": record.get("template_id"),
        },
    }
    return _prune(doc)


# --- ECS -> internal event record (for ECS-native sources) ------------------

def _get(doc: dict, dotted: str):
    """Read a possibly-nested ECS field by dotted path, tolerating either the
    nested form (``{"source": {"ip": ...}}``) or the flattened form
    (``{"source.ip": ...}``). Sources in the wild ship both."""
    if dotted in doc:
        return doc[dotted]
    node: Any = doc
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def ecs_to_record(doc: dict) -> dict:
    """A nested-or-flat ECS document -> the internal columns the pipeline scores.

    This is the ingestion direction: a source that already speaks ECS is mapped
    onto ``user``/``source_ip``/``host``/``process``/``message``/``timestamp`` so
    it joins the same detection path as a syslog line, with no format-specific
    parser. ``template`` is deliberately not reconstructed here -- it is the
    masked form the embedder sees, and ``preprocessing.template_message`` owns
    that; a caller feeding these records in should template them the same way a
    syslog line is templated.
    """
    user = _get(doc, "user.name")
    return {
        "timestamp": _get(doc, "@timestamp"),
        "host": _get(doc, "host.name") or _get(doc, "host.hostname"),
        "process": _get(doc, "process.name"),
        "pid": _get(doc, "process.pid"),
        "message": _get(doc, "message"),
        "raw": _get(doc, "event.original"),
        "user": user if user is not None else "unknown",
        "source_ip": _get(doc, "source.ip"),
    }


# --- incident entry -> ECS --------------------------------------------------

def incident_to_ecs(entry: dict) -> dict:
    """One incident entry (the JSON ``build_incident_entry`` produces) -> an ECS
    document describing the incident as a whole.

    An incident spans many events, so the single-valued ECS identity fields
    (``source.ip``, ``user.name``) carry the first of each and the full sets go in
    ``related.ip`` / ``related.user`` -- which is exactly what ECS ``related.*`` is
    for. ``threat.technique.*`` carries the grounded MITRE techniques; these are
    ``mitre_techniques`` (the retrieval output), never a narrative's prose IDs.
    """
    users = entry.get("users") or []
    ips = entry.get("source_ips") or []
    techniques = entry.get("mitre_techniques") or []

    doc = {
        "@timestamp": _iso(entry.get("start")),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert",
            "id": entry.get("incident_id"),
            "start": _iso(entry.get("start")),
            "end": _iso(entry.get("end")),
            "severity": entry.get("severity"),
            "count": entry.get("event_count"),
        },
        "user": {"name": users[0] if users else None},
        "source": {"ip": ips[0] if ips else None},
        "related": {
            "user": users or None,
            "ip": ips or None,
        },
        "threat": {
            "technique": [
                {"id": t.get("technique_id"), "name": t.get("technique_name")}
                for t in techniques
            ] or None,
            "tactic": {
                "name": [k.get("tactic") for k in (entry.get("kill_chain") or [])]
                        or None,
            },
        },
        "logdet": {
            "kill_chain": entry.get("kill_chain") or None,
        },
    }
    return _prune(doc)


# --- serialization helpers --------------------------------------------------

def flatten(doc: dict, prefix: str = "") -> dict:
    """Nested ECS -> dotted-key form (``{"source.ip": ...}``). Lists and leaf
    values are kept as-is; only dicts are descended. Some tabular consumers want
    this, and it is the form Elasticsearch accepts interchangeably with nested."""
    flat: dict[str, Any] = {}
    for key, value in doc.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, prefix=f"{dotted}."))
        else:
            flat[dotted] = value
    return flat


def to_ndjson(docs: Iterable[dict]) -> str:
    """One ECS document per line. The interchange format for the collector and
    for any downstream shipper -- the same shape ``/collector/ingest`` speaks."""
    return "\n".join(json.dumps(doc, ensure_ascii=False, sort_keys=True)
                     for doc in docs)


# --- CLI --------------------------------------------------------------------

def cli() -> None:
    """Export parsed events or finished incidents as ECS NDJSON.

    This is the boundary in action: a finished run's incidents, or a parsed
    corpus, re-emitted in a format another SIEM reads -- with no detection code
    involved on either side.
    """
    import argparse
    import pandas as pd

    parser = argparse.ArgumentParser(
        description="Export events or incidents as Elastic Common Schema NDJSON.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="Parsed events CSV -> ECS event documents")
    group.add_argument("--incidents", help="Incidents JSON -> ECS alert documents")
    parser.add_argument("--output", required=True, help="Path to write NDJSON")
    parser.add_argument("--module", default=None,
                        help="event.module label for exported events (default: process name)")
    parser.add_argument("--no-categorize", action="store_true",
                        help="Skip event.category/action/outcome classification")
    args = parser.parse_args()

    if args.input:
        frame = pd.read_csv(args.input)
        docs = [event_to_ecs(row.to_dict(), module=args.module,
                             categorize_event=not args.no_categorize)
                for _, row in frame.iterrows()]
    else:
        entries = json.loads(Path(args.incidents).read_text())
        docs = [incident_to_ecs(entry) for entry in entries]

    Path(args.output).write_text(to_ndjson(docs) + "\n")
    print(f"Wrote {len(docs)} ECS documents -> {args.output}")


if __name__ == "__main__":
    cli()
