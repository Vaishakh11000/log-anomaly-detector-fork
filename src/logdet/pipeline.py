"""
pipeline.py
End-to-end pipeline: parsed logs -> embeddings -> per-user anomaly detection
-> incident grouping -> MITRE-mapped LLM narrative.

Orchestration only -- no detection or mapping logic lives here.

Usage:
    python src/pipeline.py --input data/processed/parsed.csv --no-llm
    python src/pipeline.py --input data/processed/parsed.csv --output data/processed/incidents.json
"""

import argparse
import json
import pandas as pd

from logdet.embedding import add_embeddings_to_df
from logdet.anomaly_detection import (run_anomaly_detection, highest_severity,
                                      travel_evidence)
from logdet.sequence_grouping import group_anomalies, describe_incident
from logdet.mitre_mapping import kill_chain_of, map_incident_to_mitre
from logdet.llm_narrative import generate_narrative, generate_triage, narrate_detail
from logdet.sequence_model import TransitionModel
from logdet.config import (
    NARRATE_SEVERITIES,
    NARRATE_MIN_EVENTS,
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_SEQUENCE_MODEL_PATH,
    SEQUENCE_SUPPRESSION,
    LLM_TRIAGE_MODEL,
    LLM_TRIAGE_NUM_PREDICT,
)


def should_narrate(severity: str, event_count: int) -> bool:
    """Narrative budget policy -- see NARRATE_* in config.py for the rationale."""
    return severity in NARRATE_SEVERITIES or event_count >= NARRATE_MIN_EVENTS


def _max_surprisal(incident: pd.DataFrame) -> float | None:
    """Most surprising transition in an incident, or None if none was scored."""
    if "transition_surprisal" not in incident.columns:
        return None
    values = incident["transition_surprisal"].dropna()
    return float(values.max()) if len(values) else None


EVENT_FIELDS = ["timestamp", "user", "source_ip", "message"]


def _event_records(frame: pd.DataFrame) -> list[dict]:
    """Serialisable event rows.

    fillna before astype(str), or missing cells serialise as the string "nan".
    """
    fields = [c for c in EVENT_FIELDS if c in frame.columns]
    return (frame[fields].astype(object)
            .where(frame[fields].notna(), "")
            .astype(str).to_dict(orient="records"))


def build_incident_entry(incident_id: int, incident: pd.DataFrame,
                         context: pd.DataFrame | None = None) -> dict:
    """Everything about an incident that doesn't need the LLM.

    `context` is the wider frame the incident was cut out of -- the full scored
    log in batch mode, the rolling window in the stream. It is used only to
    retrieve *evidence*: the benign earlier login an impossible-travel hit was
    compared against, which is flagged nowhere and so has never been shown
    (Known Issues). Those rows land in `context_events`, deliberately not in
    `events`: they are not detections, they must not count towards
    `event_count`, severity or triage, and the bake-off attributes our flagged
    lines by walking `events` -- putting a benign line there would turn a
    display fix into a false positive.
    """
    techniques = map_incident_to_mitre(incident)
    evidence = travel_evidence(incident, context) if context is not None else None
    return {
        "incident_id": incident_id,
        "summary": describe_incident(incident),
        "users": sorted({str(u) for u in incident["user"].dropna()}),
        "source_ips": sorted({str(p) for p in incident["source_ip"].dropna()}),
        "start": str(incident["timestamp"].min()),
        "end": str(incident["timestamp"].max()),
        "event_count": len(incident),
        "severity": highest_severity(incident["severity"]),
        # The sequence model's contribution to triage: the most surprising
        # template transition anywhere in this incident, or None when the
        # model was not used. It orders the list (triage.triage_key) and
        # nothing else -- it is not part of any detection decision.
        "max_transition_surprisal": _max_surprisal(incident),
        "mitre_techniques": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "tactic": t["tactic"], "tactics": t["tactics"],
             "tactic_ids": t["tactic_ids"], "url": t["url"],
             "description": t["description"]}
            for t in techniques
        ],
        # The tactics this incident touches, in ATT&CK matrix order -- the
        # kill-chain view of the same techniques. Derived from the bundle, so
        # it says where the activity sits in an attack rather than only what it
        # was. Enrichment, like the techniques it comes from: it feeds no
        # detection, grouping or severity decision.
        "kill_chain": kill_chain_of(techniques),
        "events": _event_records(incident),
        # Evidence, not detections -- see the docstring.
        "context_events": [
            dict(record, role="prior login compared against")
            for record in _event_records(evidence)
        ] if evidence is not None and len(evidence) else [],
    }


def run_pipeline(input_csv: str, output_json: str, use_llm: bool = True,
                 narrate_all: bool = False, sequence_model_path: str | None = None,
                 suppress: bool = SEQUENCE_SUPPRESSION,
                 triage_lines: bool = False):
    df = pd.read_csv(input_csv, parse_dates=["timestamp"])
    print(f"Loaded {len(df)} parsed log rows")

    df = add_embeddings_to_df(df, template_col="template")
    print("Embeddings generated")

    # Opt-in. Without `--suppress` it re-ranks rather than re-flags: the same
    # lines are flagged and the same incidents are grouped with it on or off,
    # so every number in `results/` stays comparable across the switch, and
    # what changes is which incidents rank first and which get narrated. With
    # `--suppress` that stops being true by design -- see suppression.py.
    sequence_model = None
    if sequence_model_path:
        sequence_model = TransitionModel.load(sequence_model_path)
        print(f"Loaded transition model: {len(sequence_model.vocabulary)} templates, "
              f"routine <= {sequence_model.routine_threshold:.3f} nats, "
              f"rare >= {sequence_model.rare_threshold:.3f}")

    scored = run_anomaly_detection(df, sequence_model=sequence_model,
                                   suppress=suppress)
    if suppress and "suppressed" in scored.columns:
        print(f"Suppressed {int(scored['suppressed'].sum())} lone flagged rows "
              "with an unremarkable template transition")
    print(f"Flagged {scored['is_anomaly'].sum()} anomalous rows out of {len(scored)} "
          f"({scored['impossible_travel'].sum()} via impossible-travel)")

    incidents = group_anomalies(scored)
    print(f"Grouped into {len(incidents)} incidents "
          f"({sum(1 for i in incidents if len(i) > 1)} multi-event)")

    results = [build_incident_entry(i, inc, context=scored)
               for i, inc in enumerate(incidents)]
    carried = sum(1 for entry in results if entry["context_events"])
    if carried:
        print(f"Carried the compared-against login into {carried} "
              "impossible-travel incidents as evidence")

    if use_llm:
        targets = [e for e in results
                   if narrate_all or should_narrate(e["severity"], e["event_count"])]
        print(f"Narrating {len(targets)} of {len(results)} incidents "
              f"({'all' if narrate_all else 'severity in ' + str(sorted(NARRATE_SEVERITIES)) + f' or >={NARRATE_MIN_EVENTS} events'})")

        for n, entry in enumerate(targets, start=1):
            print(f"  [{n}/{len(targets)}] incident {entry['incident_id']} "
                  f"({entry['severity']}, {entry['event_count']} events)...", flush=True)
            try:
                entry["narrative"], dropped = narrate_detail(
                    incidents[entry["incident_id"]], tier="full",
                    context_events=entry["context_events"])
                entry["narrative_dropped"] = dropped
                if dropped:
                    print(f"      dropped {', '.join(dropped)} "
                          f"(not in this incident's grounded list)")
            except Exception as e:
                entry["narrative"] = f"[LLM narrative generation failed: {e}]"

        for entry in results:
            entry.setdefault("narrative", None)

        # The cheap tier for everything the budget policy left with no prose at
        # all. One sentence each, so 75 incidents cost what a handful of full
        # narratives do.
        if triage_lines:
            rest = [e for e in results if not e.get("narrative")]
            print(f"Triage line for the remaining {len(rest)} incidents "
                  f"({LLM_TRIAGE_MODEL}, {LLM_TRIAGE_NUM_PREDICT} tokens each)")
            for n, entry in enumerate(rest, start=1):
                try:
                    result = generate_triage(
                        incidents[entry["incident_id"]],
                        context_events=entry["context_events"])
                    entry["triage_line"] = result.line
                    entry["narrative_dropped"] = result.dropped
                    if result.dropped:
                        print(f"  [{n}/{len(rest)}] incident {entry['incident_id']}: "
                              f"dropped {', '.join(result.dropped)}")
                except Exception as e:
                    entry["triage_line"] = f"[triage line generation failed: {e}]"

        for entry in results:
            entry.setdefault("triage_line", None)

    # Every technique ID the model claimed and the enforcement removed, so a
    # reader can tell an incident where that happened from one where it did
    # not. Never merged into mitre_techniques: these are the IDs the grounded
    # lookup did *not* hand over, and the whole point is that the system does
    # not assert them.
    for entry in results:
        entry.setdefault("narrative_dropped", [])

    with open(output_json, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Wrote {len(results)} incidents -> {output_json}")

    return results


def cli() -> None:
    parser = argparse.ArgumentParser(description="Run the full log anomaly detection pipeline.")
    parser.add_argument("--input", required=True, help="Parsed log CSV (from preprocessing.py)")
    parser.add_argument("--output", default=DEFAULT_INCIDENTS_PATH)
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM narrative generation")
    parser.add_argument("--narrate-all", action="store_true",
                        help="Narrate every incident, ignoring the NARRATE_* budget policy (slow)")
    parser.add_argument("--triage-lines", action="store_true",
                        help="Also give every un-narrated incident a one-sentence triage "
                             "line on the small model (LLM_TRIAGE_MODEL). Cheap per "
                             "incident, but there are many of them -- see config.py.")
    parser.add_argument("--sequence-model", nargs="?", const=DEFAULT_SEQUENCE_MODEL_PATH,
                        default=None,
                        help="Adjust severity tiers with a fitted transition model over "
                             "template_id (input must be parsed with --drain3). Does not "
                             "change which lines are flagged or how they group.")
    parser.add_argument("--suppress", action="store_true", default=SEQUENCE_SUPPRESSION,
                        help="Clear is_anomaly on lone flagged lines whose template "
                             "transition is not rare (needs --sequence-model). Unlike "
                             "every other Stage 3 switch this one changes what is "
                             "detected -- see logdet/suppression.py.")
    args = parser.parse_args()

    run_pipeline(args.input, args.output, use_llm=not args.no_llm,
                 narrate_all=args.narrate_all,
                 sequence_model_path=args.sequence_model,
                 suppress=args.suppress,
                 triage_lines=args.triage_lines)


if __name__ == "__main__":
    cli()
