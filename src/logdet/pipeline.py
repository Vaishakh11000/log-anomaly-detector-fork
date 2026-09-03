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
from logdet.anomaly_detection import run_anomaly_detection, highest_severity
from logdet.sequence_grouping import group_anomalies, describe_incident
from logdet.mitre_mapping import map_incident_to_mitre
from logdet.llm_narrative import generate_narrative
from logdet.sequence_model import TransitionModel
from logdet.config import (
    NARRATE_SEVERITIES,
    NARRATE_MIN_EVENTS,
    DEFAULT_INCIDENTS_PATH,
    DEFAULT_SEQUENCE_MODEL_PATH,
    SEQUENCE_SUPPRESSION,
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


def build_incident_entry(incident_id: int, incident: pd.DataFrame) -> dict:
    """Everything about an incident that doesn't need the LLM."""
    techniques = map_incident_to_mitre(incident)
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
             "tactic": t["tactic"]}
            for t in techniques
        ],
        # fillna before astype(str), or missing cells serialise as the string "nan"
        "events": incident[["timestamp", "user", "source_ip", "message"]]
                  .astype(object).where(incident[["timestamp", "user", "source_ip", "message"]].notna(), "")
                  .astype(str).to_dict(orient="records"),
    }


def run_pipeline(input_csv: str, output_json: str, use_llm: bool = True,
                 narrate_all: bool = False, sequence_model_path: str | None = None,
                 suppress: bool = SEQUENCE_SUPPRESSION):
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

    results = [build_incident_entry(i, inc) for i, inc in enumerate(incidents)]

    if use_llm:
        targets = [e for e in results
                   if narrate_all or should_narrate(e["severity"], e["event_count"])]
        print(f"Narrating {len(targets)} of {len(results)} incidents "
              f"({'all' if narrate_all else 'severity in ' + str(sorted(NARRATE_SEVERITIES)) + f' or >={NARRATE_MIN_EVENTS} events'})")

        for n, entry in enumerate(targets, start=1):
            print(f"  [{n}/{len(targets)}] incident {entry['incident_id']} "
                  f"({entry['severity']}, {entry['event_count']} events)...", flush=True)
            try:
                entry["narrative"] = generate_narrative(incidents[entry["incident_id"]])
            except Exception as e:
                entry["narrative"] = f"[LLM narrative generation failed: {e}]"

        for entry in results:
            entry.setdefault("narrative", None)

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
                 suppress=args.suppress)


if __name__ == "__main__":
    cli()
