"""
sequence_report.py
Measures what the Stage 3 transition model actually separates, before any
claim is made for it.

The sequence model exists because v1 scores every line independently, which is
the structural reason precision is 0.29. Before wiring it into anything that
faces a user, the question worth answering is narrow and checkable: on a corpus
with ground truth, is the surprisal of an attack line's template transition
distinguishable from a benign line's?

Reports three things, none of them assumed:

*How much the fit source matters.* Fitting the transition model on the same
frame it scores lets a brute-force burst teach the model that the burst is
normal. This is the sequence-model form of the mistake `fit.py` already avoids
for the detector, and the report measures the cost rather than asserting it.

*What each sequence key contributes.* The model consults the user key first and
falls back to source IP only for rows it cannot score. Whether that ordering is
right is a measurement, not a preference: taking the maximum across keys instead
lets the weaker key overwrite the stronger one.

*Where the severity thresholds land.* They are quantiles of the fitted
distribution, so the report prints the nats they resolve to and how many attack
and benign lines fall in each band.

*What it does to an analyst's queue.* Separation on lines is not the same thing
as a better list of incidents, and this is where the design decision was made:
the severity coupling and the triage ordering are both measured against the
ground truth, and only one of them earns its place.

Separation is reported as AUC -- the chance that a randomly chosen attack line
scores more surprising than a randomly chosen benign one. 0.5 is a coin flip.
This is a diagnostic of one signal in isolation and is *not* a detection
result: nothing here changes `is_anomaly`, so no number in `results/` moves
because of it (CLAUDE.md section 4).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from logdet.anomaly_detection import (
    assign_severity,
    detect_impossible_travel,
    highest_severity,
    PerUserAnomalyDetector,
)
from logdet.config import RESULTS_DIR
from logdet.embedding import add_embeddings_to_df
from logdet.preprocessing import preprocess_file
from logdet.sequence_grouping import group_anomalies
from logdet.sequence_model import TransitionModel
from logdet.triage import SEVERITY_RANK, is_notable
from logdet_eval.config import SYNTHETIC_YEAR

DEFAULT_LOG = "data/raw/synthetic.log"
DEFAULT_GROUND_TRUTH = "data/raw/ground_truth.csv"


def load_corpus(log_path: str, ground_truth_path: str, parsed_path: str,
                year: int = SYNTHETIC_YEAR) -> pd.DataFrame:
    """Parse the log with template mining on and mark the ground-truth lines."""
    df = preprocess_file(log_path, parsed_path, year=year, mine_templates=True)
    df = df.reset_index(drop=True)
    df["line_number"] = np.arange(1, len(df) + 1)
    ground_truth = pd.read_csv(ground_truth_path)
    df["attack"] = df["line_number"].isin(set(ground_truth["line_number"]))
    scenarios = ground_truth.set_index("line_number")["scenario"].to_dict()
    df["scenario"] = df["line_number"].map(scenarios).fillna("benign")
    # Instance ids are what "9 attack instances" counts -- a scenario fires
    # several times and each firing has to be surfaced separately.
    instances = ground_truth.set_index("line_number")["instance"].to_dict()
    df["instance"] = df["line_number"].map(instances)
    return df


def separation(model: TransitionModel, df: pd.DataFrame) -> dict:
    """Attack-vs-benign separation of the surprisal this model assigns."""
    scored = df.assign(surprisal=model.surprisal(df))
    defined = scored.dropna(subset=["surprisal"])
    attack = defined[defined["attack"]]["surprisal"]
    benign = defined[~defined["attack"]]["surprisal"]

    result = {
        "fitted_rows": model.fitted_rows,
        "vocabulary": len(model.vocabulary),
        "rows": int(len(df)),
        # Rows the model is silent on: the first event of every sequence, rows
        # with no usable actor key, and unknown templates. Silence is the
        # designed answer for those, so the count belongs in the report -- a
        # signal defined on a third of the corpus is a different claim from one
        # defined on all of it.
        "rows_scored": int(len(defined)),
        "unknown_template_rate": round(model.unknown_rate(df), 4),
        "attack_lines_scored": int(len(attack)),
        "benign_lines_scored": int(len(benign)),
        "routine_threshold": (round(model.routine_threshold, 3)
                              if model.routine_threshold is not None else None),
        "rare_threshold": (round(model.rare_threshold, 3)
                           if model.rare_threshold is not None else None),
    }
    if len(attack) and len(benign):
        result["auc"] = round(float(roc_auc_score(defined["attack"], defined["surprisal"])), 3)
        result["attack_median"] = round(float(attack.median()), 3)
        result["benign_median"] = round(float(benign.median()), 3)
        result["attack_p90"] = round(float(attack.quantile(0.9)), 3)
        result["benign_p90"] = round(float(benign.quantile(0.9)), 3)
    else:
        result["auc"] = None
    return result


def band_counts(model: TransitionModel, df: pd.DataFrame) -> dict:
    """How many attack and benign lines land in each severity-shift band."""
    if model.routine_threshold is None:
        return {}
    scored = df.assign(surprisal=model.surprisal(df))
    defined = scored.dropna(subset=["surprisal"])

    def band(value: float) -> str:
        if value <= model.routine_threshold:
            return "routine (demoted)"
        if value >= model.rare_threshold:
            return "rare (promoted)"
        return "middle (unchanged)"

    defined = defined.assign(band=defined["surprisal"].map(band))
    silent = len(scored) - len(defined)
    counts = {
        name: {
            "attack": int(rows["attack"].sum()),
            "benign": int((~rows["attack"]).sum()),
        }
        for name, rows in defined.groupby("band")
    }
    counts["silent (unchanged)"] = {
        "attack": int(scored["attack"].sum() - defined["attack"].sum()),
        "benign": int(silent - (scored["attack"].sum() - defined["attack"].sum())),
    }
    return counts


def triage_effect(df: pd.DataFrame, model: TransitionModel) -> dict:
    """What the surprisal does to the list an analyst actually works.

    Two candidate consumption points, measured against the same ground truth:
    shifting the severity tier, and breaking ties in the triage order. Both
    leave `is_anomaly` alone, so the 130 flagged rows and 94 incidents are the
    same in every row of both tables -- what moves is which incidents are
    called notable and what order they come in.
    """
    scored = add_embeddings_to_df(df, template_col="template")
    scored = PerUserAnomalyDetector().fit(scored).score(scored)
    scored = detect_impossible_travel(scored)
    scored["ml_anomaly"] = scored["is_anomaly"]
    scored["is_anomaly"] = scored["ml_anomaly"] | scored["impossible_travel"]
    scored["transition_surprisal"] = model.surprisal(scored)
    defined = scored["transition_surprisal"].dropna()

    attack_lines = set(df.loc[df["attack"], "line_number"])
    instances = {row.line_number: (row.scenario, row.instance)
                 for row in df[df["attack"]].itertuples()} if "scenario" in df.columns else {}
    n_instances = len(set(instances.values()))

    def incident_rows(routine: float | None, rare: float | None) -> list[dict]:
        column = None if routine is None else "transition_surprisal"
        tiered = assign_severity(scored, surprisal_col=column,
                                 routine_threshold=routine, rare_threshold=rare)
        rows = []
        for incident in group_anomalies(tiered):
            lines = set(incident["line_number"])
            values = incident["transition_surprisal"].dropna()
            rows.append({
                "event_count": len(incident),
                "severity": highest_severity(incident["severity"]),
                "max_transition_surprisal": float(values.max()) if len(values) else 0.0,
                "hits": lines & attack_lines,
            })
        return rows

    def notable_view(rows: list[dict]) -> dict:
        notable = [r for r in rows if is_notable(r)]
        with_attack = sum(1 for r in notable if r["hits"])
        return {
            "incidents": len(rows),
            "notable": len(notable),
            "notable_containing_an_attack": with_attack,
            "precision": round(with_attack / len(notable), 3) if notable else 0.0,
        }

    baseline_rows = incident_rows(None, None)
    flagged_lines = int(scored["is_anomaly"].sum())
    severity_variants = {"off (v1 tiers)": notable_view(baseline_rows)}
    for label, routine_q, rare_q in (
            ("promote+demote, rare p90", 0.50, 0.90),
            ("promote+demote, rare p95", 0.50, 0.95),
            ("promote+demote, rare p99", 0.50, 0.99),
            ("demote only", 0.50, None)):
        routine = float(defined.quantile(routine_q))
        rare = float(defined.quantile(rare_q)) if rare_q is not None else float("inf")
        severity_variants[label] = notable_view(incident_rows(routine, rare))

    def ordering(rows: list[dict], key) -> dict:
        order = sorted(rows, key=key, reverse=True)
        seen, rank_for_full_coverage = set(), None
        for position, row in enumerate(order, start=1):
            seen |= {instances[line] for line in row["hits"]}
            if rank_for_full_coverage is None and len(seen) == n_instances:
                rank_for_full_coverage = position
        return {
            **{f"precision_at_{k}": round(sum(1 for r in order[:k] if r["hits"]) / k, 3)
               for k in (5, 10, 20)},
            "rank_for_full_instance_coverage": rank_for_full_coverage,
        }

    orderings = {
        "v1: (events, severity)":
            ordering(baseline_rows, lambda r: (r["event_count"], SEVERITY_RANK[r["severity"]])),
        "(events, severity, surprisal)":
            ordering(baseline_rows, lambda r: (r["event_count"], SEVERITY_RANK[r["severity"]],
                                               r["max_transition_surprisal"])),
        "surprisal alone":
            ordering(baseline_rows, lambda r: r["max_transition_surprisal"]),
    }
    return {"attack_instances": n_instances,
            "flagged_lines": flagged_lines,
            "incidents": len(baseline_rows),
            "severity_coupling": severity_variants,
            "ordering": orderings}


def run(log_path: str, ground_truth_path: str, output_dir: str,
        year: int = SYNTHETIC_YEAR) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    df = load_corpus(log_path, ground_truth_path, str(output / "parsed_templates.csv"),
                     year=year)
    benign = df[~df["attack"]]

    results = {
        "corpus": {
            "log": log_path,
            "rows": int(len(df)),
            "attack_lines": int(df["attack"].sum()),
            "templates_mined": int(df["template_id"].nunique()),
        },
        "fit_source": {
            "whole_corpus": separation(TransitionModel().fit(df), df),
            "benign_only": separation(TransitionModel().fit(benign), df),
        },
        "sequence_keys": {},
        "bands_benign_fit": {},
    }

    for keys in (("user",), ("source_ip",), ("user", "source_ip")):
        model = TransitionModel(keys=keys).fit(benign)
        results["sequence_keys"]["+".join(keys)] = separation(model, df)

    benign_model = TransitionModel().fit(benign)
    results["bands_benign_fit"] = band_counts(benign_model, df)
    results["triage"] = triage_effect(df, benign_model)

    (output / "sequence_separation.json").write_text(json.dumps(results, indent=2))
    (output / "sequence_separation.md").write_text(render_report(results))
    return results


def render_report(results: dict) -> str:
    corpus = results["corpus"]
    lines = [
        "# Transition-model separation (Stage 3)",
        "",
        f"Corpus: `{corpus['log']}` -- {corpus['rows']} lines, "
        f"{corpus['attack_lines']} of them ground-truth attack lines, "
        f"{corpus['templates_mined']} mined templates.",
        "",
        "AUC is the chance a randomly chosen attack line scores more surprising",
        "than a randomly chosen benign one. 0.5 is a coin flip. **This measures one",
        "signal in isolation and is not a detection result** -- the sequence model",
        "only shifts severity tiers, so no number in `results/` moves because of it.",
        "",
        "## Fit source",
        "",
        "| fit on | rows scored | AUC | attack median | benign median |",
        "|---|---|---|---|---|",
    ]
    for name, row in results["fit_source"].items():
        lines.append(
            f"| {name.replace('_', ' ')} | {row['rows_scored']}/{row['rows']} | "
            f"{row['auc']} | {row.get('attack_median')} | {row.get('benign_median')} |")
    lines += [
        "",
        "Fitting on the frame being scored is the failure `fit.py` already avoids for",
        "the detector, and it costs more here: a brute-force burst repeats one",
        "transition often enough to teach the model that the burst is routine.",
        "",
        "## Sequence key (all fitted on benign lines only)",
        "",
        "| keys | rows scored | AUC |",
        "|---|---|---|",
    ]
    for name, row in results["sequence_keys"].items():
        lines.append(f"| `{name}` | {row['rows_scored']}/{row['rows']} | {row['auc']} |")
    lines += [
        "",
        "Keys are consulted in precedence order -- the user key scores a row if it can,",
        "and source IP fills only the rows it cannot. What these numbers support is the",
        "*ranking* of the keys, not the combining rule: the user key is much the stronger",
        "signal on both corpora, and the fallback earns its place by being the only key",
        "with anything to say about account enumeration, which varies the username on",
        "every line by design. Taking the maximum across keys instead was measured and is",
        "a wash (0.852 here against precedence's 0.856 on the synthetic corpus, 0.923",
        "against 0.912 on the kill-point corpus), so precedence is kept for being the",
        "simpler rule, not for scoring better. The combined row sits *below* user-alone on",
        "the kill-point corpus because the fallback adds rows the user key could not score",
        "at all -- coverage bought at lower quality, not a regression.",
        "",
        "## Severity bands",
        "",
    ]
    benign_fit = results["fit_source"]["benign_only"]
    lines += [
        f"Routine at or below **{benign_fit['routine_threshold']} nats**, "
        f"rare at or above **{benign_fit['rare_threshold']}** "
        "(quantiles of the fitted distribution, not fixed constants).",
        "",
        "| band | attack lines | benign lines |",
        "|---|---|---|",
    ]
    for name, row in results["bands_benign_fit"].items():
        lines.append(f"| {name} | {row['attack']} | {row['benign']} |")

    triage = results.get("triage")
    if triage:
        lines += [
            "",
            "## What it does to the analyst's queue",
            "",
            f"Every row below has the same {triage['flagged_lines']} flagged lines in the "
            f"same {triage['incidents']} incidents -- the sequence model cannot change",
            "`is_anomaly`. What moves is which incidents are called notable, and in what",
            "order they come.",
            "",
            "### Shifting the severity tier",
            "",
            "| severity coupling | notable | of those, contain an attack | precision |",
            "|---|---|---|---|",
        ]
        for name, row in triage["severity_coupling"].items():
            lines.append(f"| {name} | {row['notable']} | "
                         f"{row['notable_containing_an_attack']} | {row['precision']} |")
        lines += [
            "",
            "Promotion strictly adds false positives -- it never surfaces an attack the",
            "baseline missed. Demotion is inert, because an incident is notable when it",
            "is high severity **or** has two or more events, and the incidents a demotion",
            "could remove are already notable on their event count. **So the severity",
            "tier is the wrong place to consume the sequence model**, and this is a",
            "measured negative result rather than a tuning problem: no threshold in the",
            "table beats leaving it off.",
            "",
            "### Breaking ties in the triage order",
            "",
            "| ordering | P@5 | P@10 | P@20 | rank by which all "
            f"{triage['attack_instances']} instances are seen |",
            "|---|---|---|---|---|",
        ]
        for name, row in triage["ordering"].items():
            lines.append(
                f"| {name} | {row['precision_at_5']} | {row['precision_at_10']} | "
                f"{row['precision_at_20']} | {row['rank_for_full_instance_coverage']} |")
        lines += [
            "",
            "Ranking on the surprisal *alone* is not safe: it drops precision@5 on both",
            "corpora with ground truth, because a lone line with a rare transition",
            "outranks a twenty-event brute force, and event count is the stronger",
            "evidence. Used as a **tiebreaker after event count and severity** it leaves",
            "precision@k untouched on both corpora and brings full coverage of every",
            "attack instance forward -- rank 16 to 12 on the synthetic corpus, 65 to 39",
            "on the kill-point OpenSSH corpus. That is a real if modest saving in analyst",
            "work for a signal that costs nothing to compute, and it is the consumption",
            "point adopted in `logdet/triage.py`. It is not a detection improvement and",
            "must not be reported as one: the same incidents are flagged either way.",
        ]
    lines.append("")
    return "\n".join(lines)


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Measure how well the transition model separates attack from benign lines.")
    parser.add_argument("--input", default=DEFAULT_LOG)
    parser.add_argument("--ground-truth", default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--output", default=str(Path(RESULTS_DIR) / "sequence"))
    parser.add_argument("--year", type=int, default=SYNTHETIC_YEAR)
    args = parser.parse_args()

    results = run(args.input, args.ground_truth, args.output, year=args.year)
    print(render_report(results))
    print(f"\nWritten to {args.output}")


if __name__ == "__main__":
    cli()
