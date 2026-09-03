"""
suppression_report.py
What Stage 3 alert suppression costs and buys, on every corpus with ground truth.

Suppression (see `logdet/suppression.py`) is the first Stage 3 change that
clears `is_anomaly`, so unlike the severity shift and the triage tiebreaker it
moves every number CLAUDE.md section 4 asks for. This module measures three of
the four on the clean corpora:

  1. line-level precision / recall / F1
  2. instance detection on the clean corpus
  4. alert volume (flagged lines and incident count)

Item 3 -- instance detection under camouflage, pooled over at least five seeds
-- is not measurable here and is deliberately not attempted: it needs the
camouflage transforms and the multi-seed pooling that `adversarial.py` owns.
Run `logdet-adversarial --seeds 5 --suppress` for it. **A suppression rule
judged on this report alone would be judged on exactly the half of the evidence
that saturates**, which is the mistake the 2026-08-16 contamination retune made
and the reason section 4 lists item 3 separately.

The threshold is swept rather than asserted, because the intuitive value turns
out to be the wrong one. "Suppress a routine transition" reads as "at or below
the fitted median", and at that threshold the rule is nearly inert: the flagged
rows are already the anomalous tail, and a line the embedding detector found
unusual almost never has a below-median template transition. The sweep is what
shows that, and it is printed for both corpora so the adopted value is visible
as a choice rather than a constant.

Two things this report is careful about, both of which would otherwise make it
flatter the rule:

*The history is a separate corpus.* The transition model is fitted on
benign-only traffic that is not the traffic being scored -- generated at a
disjoint seed for the synthetic corpus, and built from a differently-seeded
background sample for the kill-point corpus. Fitting on the scored frame is
measured elsewhere at AUC 0.912 -> 0.558, and using ground-truth labels to pick
the benign rows (which the earlier `sequence_report` does, legitimately, as a
diagnostic) is not available to a rule that has to run at inference time.

*The miner is shared.* Cluster ids mean nothing across two independent miners,
so the scored corpus is mined by a miner restored from the history's own state.
It keeps mining rather than freezing, so a genuinely new template gets a new
id the model does not know -- which scores as silence, and silence never
suppresses.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from logdet.anomaly_detection import run_anomaly_detection
from logdet.config import (
    RESULTS_DIR,
    SEQUENCE_RARE_QUANTILE,
    SEQUENCE_ROUTINE_QUANTILE,
)
from logdet.embedding import add_embeddings_to_df
from logdet.preprocessing import preprocess_file
from logdet.sequence_grouping import group_anomalies
from logdet.sequence_model import TransitionModel
from logdet.suppression import lone_flagged_mask, suppress_routine_singletons
from logdet.templating import TemplateMiner
from logdet_eval.config import SYNTHETIC_TOTAL_LINES, SYNTHETIC_YEAR, SYNTHETIC_SEED
from logdet_eval.generate_logs import build_dataset, format_line

# Quantiles of the fitted history swept for the threshold. 0.50 and 0.90 are
# the two the model already carries (`routine_threshold`, `rare_threshold`);
# the others are there so the adopted value can be read as a point on a curve.
SWEEP_QUANTILES = (0.50, 0.75, SEQUENCE_RARE_QUANTILE, 0.95, 0.99)


def _prf(scored: pd.DataFrame) -> dict:
    """Line-level precision / recall / F1 against the `attack` column."""
    flagged = scored["is_anomaly"].astype(bool)
    attack = scored["attack"].astype(bool)
    tp = int((flagged & attack).sum())
    fp = int((flagged & ~attack).sum())
    fn = int((~flagged & attack).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3)}


def _instances(scored: pd.DataFrame) -> dict:
    """Instance detection: an instance counts as detected if any of its lines is."""
    attacks = scored[scored["attack"]]
    if attacks.empty or "instance" not in attacks.columns:
        return {"instances": 0, "instances_detected": 0, "instance_detection_rate": 0.0}
    per_instance = attacks.groupby(["scenario", "instance"])["is_anomaly"].any()
    return {"instances": int(len(per_instance)),
            "instances_detected": int(per_instance.sum()),
            "instance_detection_rate": round(float(per_instance.mean()), 3)}


def evaluate(scored: pd.DataFrame) -> dict:
    """Every section-4 number this report can compute, for one arm."""
    incidents = group_anomalies(scored)
    return {
        **_prf(scored),
        **_instances(scored),
        "flagged_lines": int(scored["is_anomaly"].sum()),
        "incidents": len(incidents),
        "singleton_incidents": sum(1 for i in incidents if len(i) == 1),
        "suppressed_lines": int(scored["suppressed"].sum())
        if "suppressed" in scored.columns else 0,
        "suppressed_attack_lines": int((scored["suppressed"] & scored["attack"]).sum())
        if "suppressed" in scored.columns else 0,
    }


def conditional_separation(scored: pd.DataFrame) -> dict:
    """How well the surprisal separates attack from benign in each population.

    The published AUCs (0.856 synthetic, 0.912 kill-point) are over *all* lines,
    where most benign lines are unflagged and routine -- the easy half of the
    comparison, and exactly the half suppression never sees. Restricting to the
    rows suppression can actually act on is a different question and gets a
    different answer, so it is computed here rather than argued.
    """
    from sklearn.metrics import roc_auc_score

    flagged = scored["is_anomaly"].astype(bool)
    lone = lone_flagged_mask(scored)

    def auc(mask) -> dict:
        sub = scored[mask].dropna(subset=["transition_surprisal"])
        row = {"rows": int(len(sub)), "attack": int(sub["attack"].sum())}
        if sub["attack"].nunique() < 2:
            row["auc"] = None
            return row
        row["auc"] = round(float(roc_auc_score(sub["attack"],
                                               sub["transition_surprisal"])), 3)
        row["attack_median"] = round(float(
            sub[sub["attack"]]["transition_surprisal"].median()), 2)
        row["benign_median"] = round(float(
            sub[~sub["attack"]]["transition_surprisal"].median()), 2)
        return row

    return {"all_lines": auc(pd.Series(True, index=scored.index)),
            "flagged_only": auc(flagged),
            "flagged_and_lone": auc(flagged & lone)}


def eligibility(scored: pd.DataFrame, history_surprisal: pd.Series) -> dict:
    """Why the pool of suppressible rows is the size it is.

    Reported because the headline result is a *count*, and a count is only
    interpretable next to the population it was drawn from. Each guard is shown
    stripping the pool down in turn, so a reader can see which one is load
    bearing rather than taking the docstring's word for it.
    """
    flagged = scored["is_anomaly"].astype(bool)
    lone = lone_flagged_mask(scored)
    defined = scored["transition_surprisal"].notna()
    travel = scored["impossible_travel"].astype(bool)

    def count(mask) -> dict:
        sub = scored[mask]
        return {"rows": int(mask.sum()), "attack": int(sub["attack"].sum())}

    pool_mask = flagged & lone & defined & ~travel
    return {
        "flagged": count(flagged),
        "flagged_and_lone": count(flagged & lone),
        "flagged_and_lone_not_travel": count(flagged & lone & ~travel),
        "eligible_pool": count(pool_mask),
        "sweep": [
            {
                "quantile": q,
                "threshold_nats": round(float(history_surprisal.quantile(q)), 3),
                **{f"suppressed_{k}": v for k, v in count(
                    pool_mask & (scored["transition_surprisal"]
                                 <= history_surprisal.quantile(q))).items()},
            }
            for q in SWEEP_QUANTILES
        ],
    }


def score_corpus(history: pd.DataFrame, corpus: pd.DataFrame) -> tuple:
    """Fit on history, score the corpus once, and return (model, scored frame).

    The detector is fitted on the corpus as the batch path has always done, so
    the only thing that differs between the arms below is suppression. Scoring
    happens once and the arms are derived from that one frame: re-running the
    detector per arm would let Isolation Forest sampling noise show up as a
    suppression effect.
    """
    model = TransitionModel().fit(history)
    scored = run_anomaly_detection(add_embeddings_to_df(corpus, template_col="template"))
    scored["transition_surprisal"] = model.surprisal(scored)
    return model, scored


def run_corpus(name: str, history: pd.DataFrame, corpus: pd.DataFrame) -> dict:
    model, scored = score_corpus(history, corpus)
    history_surprisal = model.surprisal(history).dropna()

    baseline = evaluate(scored.assign(suppressed=False))
    arms = {"off": baseline}
    for q in SWEEP_QUANTILES:
        threshold = float(history_surprisal.quantile(q))
        arms[f"q{q:.2f}"] = {
            "threshold_nats": round(threshold, 3),
            **evaluate(suppress_routine_singletons(scored, threshold)),
        }

    return {
        "corpus": name,
        "rows": int(len(corpus)),
        "attack_lines": int(corpus["attack"].sum()),
        "history_rows": int(len(history)),
        "history_templates": len(model.vocabulary),
        "unknown_template_rate": round(model.unknown_rate(scored), 4),
        "routine_threshold": round(model.routine_threshold, 3),
        "rare_threshold": round(model.rare_threshold, 3),
        "conditional_separation": conditional_separation(scored),
        "eligibility": eligibility(scored, history_surprisal),
        "arms": arms,
    }


# --- corpus construction ---------------------------------------------------

def _parse(path: str, miner: TemplateMiner, out_csv: str, year: int) -> pd.DataFrame:
    df = preprocess_file(path, out_csv, year=year, miner=miner, mine_templates=True)
    return df.reset_index(drop=True)


def _label(df: pd.DataFrame, ground_truth_path: str) -> pd.DataFrame:
    df = df.copy()
    df["line_number"] = np.arange(1, len(df) + 1)
    truth = pd.read_csv(ground_truth_path)
    df["attack"] = df["line_number"].isin(set(truth["line_number"]))
    df["scenario"] = df["line_number"].map(
        truth.set_index("line_number")["scenario"].to_dict()).fillna("benign")
    df["instance"] = df["line_number"].map(
        truth.set_index("line_number")["instance"].to_dict())
    return df


def synthetic_corpus(work: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """The v1 corpus, with a benign-only history corpus at a disjoint seed."""
    events = build_dataset(total_lines=SYNTHETIC_TOTAL_LINES, instances_per_scenario=0,
                           seed=SYNTHETIC_SEED + 1000)
    history_log = work / "synthetic_history.log"
    history_log.write_text("\n".join(format_line(e) for e in events) + "\n")

    miner = TemplateMiner()
    history = _parse(str(history_log), miner, str(work / "sh.csv"), SYNTHETIC_YEAR)
    corpus = _parse("data/raw/synthetic.log", miner, str(work / "sc.csv"), SYNTHETIC_YEAR)
    return history, _label(corpus, "data/raw/ground_truth.csv")


def killpoint_corpus(work: Path, ambient_ratio: float = 0.05) -> tuple[pd.DataFrame, pd.DataFrame]:
    """The kill-point OpenSSH corpus, with a differently-seeded background as history.

    The history here overlaps the scored corpus in its benign pool -- the host
    only has ~2.4k genuinely benign lines and both draws come from them. That
    is realistic (history is the same host's earlier traffic) but it is not a
    held-out split, and the report says so rather than implying one.
    """
    from logdet_eval.corpus_openssh import CORPUS_HOST, build_background, load_classified

    benign, attacker, _users, _subnets = load_classified()
    background = build_background(benign, attacker, ambient_ratio, seed=1042)
    history_log = work / "killpoint_history.log"
    history_log.write_text(
        "\n".join(format_line(e, CORPUS_HOST) for e in background) + "\n")

    miner = TemplateMiner()
    history = _parse(str(history_log), miner, str(work / "kh.csv"), 2026)
    corpus = _parse("data/processed/killpoint/corpus.log", miner, str(work / "kc.csv"), 2026)
    return history, _label(corpus, "data/processed/killpoint/ground_truth.csv")


def run(output_dir: str, corpora: tuple[str, ...] = ("synthetic", "killpoint")) -> dict:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="suppression-"))

    results = []
    if "synthetic" in corpora:
        history, corpus = synthetic_corpus(work)
        results.append(run_corpus("synthetic (751 lines)", history, corpus))
    if "killpoint" in corpora:
        history, corpus = killpoint_corpus(work)
        results.append(run_corpus("kill-point OpenSSH (2,583 lines)", history, corpus))

    payload = {"adopted_quantile": SEQUENCE_RARE_QUANTILE, "corpora": results}
    (out / "suppression.json").write_text(json.dumps(payload, indent=2))
    (out / "suppression.md").write_text(render_report(payload))
    return payload


def render_report(payload: dict) -> str:
    adopted = f"q{payload['adopted_quantile']:.2f}"
    lines = [
        "# Alert suppression on the clean corpora (Stage 3)",
        "",
        "Suppression clears `is_anomaly` on a flagged line that is **alone in its",
        "incident** and whose **template transition is not rare**, and never on an",
        "impossible-travel hit or on a line the model is silent about. See",
        "`logdet/suppression.py` for the four guards.",
        "",
        "**This is three quarters of CLAUDE.md section 4.** Line-level P/R/F1,",
        "instance detection on the clean corpus and alert volume are below; instance",
        "detection *under camouflage*, pooled over five seeds, is not here and is not",
        "optional -- `logdet-adversarial --seeds 5 --suppress`. Clean instance",
        "detection saturates at 100%, so this report cannot see the safety margin",
        "camouflage eats first.",
        "",
    ]
    for row in payload["corpora"]:
        lines += [
            f"## {row['corpus']}",
            "",
            f"History: {row['history_rows']} benign lines, {row['history_templates']} "
            f"mined templates, {row['unknown_template_rate']:.2%} of scored lines carry a "
            "template the model never saw (those are never suppressed).",
            f"Routine (median) = {row['routine_threshold']} nats, "
            f"rare (p90) = {row['rare_threshold']} nats.",
            "",
            "### Which guard removes what",
            "",
            "| population | rows | of which attack lines |",
            "|---|---|---|",
        ]
        labels = {
            "flagged": "flagged by the detector",
            "flagged_and_lone": "+ alone in its incident",
            "flagged_and_lone_not_travel": "+ not an impossible-travel hit",
            "eligible_pool": "+ the model has a transition to score",
        }
        for key, label in labels.items():
            cell = row["eligibility"][key]
            lines.append(f"| {label} | {cell['rows']} | {cell['attack']} |")
        lines += [
            "",
            "### Why loneness is the guard that matters",
            "",
            "AUC is the chance a randomly chosen attack line scores *more* surprising",
            "than a randomly chosen benign one, within that population. 0.5 is a coin",
            "flip; below 0.5 means the signal points the wrong way.",
            "",
            "| population | rows | attack | AUC | attack median | benign median |",
            "|---|---|---|---|---|---|",
        ]
        sep_labels = {"all_lines": "all lines (the published figure)",
                      "flagged_only": "flagged rows only",
                      "flagged_and_lone": "flagged **and** lone"}
        for key, label in sep_labels.items():
            cell = row["conditional_separation"][key]
            lines.append(
                f"| {label} | {cell['rows']} | {cell['attack']} | {cell['auc']} | "
                f"{cell.get('attack_median', '--')} | {cell.get('benign_median', '--')} |")
        lines += [
            "",
            "**Loneness is the safety property; the surprisal is only the selectivity.**",
            "Among flagged rows the surprisal separates attack from benign badly or",
            "backwards, so suppressing on the surprisal alone would preferentially delete",
            "attacks. Restricted to lone rows it inverts, because the lone attack lines",
            "that exist are impossible-travel hits -- which the third guard removes from",
            "the pool anyway. Any change that weakens the first two guards has to be",
            "re-measured under camouflage from scratch; weakening the threshold alone is",
            "comparatively safe.",
            "",
            "### Threshold sweep",
            "",
            "| quantile of history | nats | lines suppressed | of which attack |",
            "|---|---|---|---|",
        ]
        for entry in row["eligibility"]["sweep"]:
            mark = "  ← adopted" if entry["quantile"] == payload["adopted_quantile"] else ""
            lines.append(
                f"| q{entry['quantile']:.2f} | {entry['threshold_nats']} | "
                f"{entry['suppressed_rows']}{mark} | {entry['suppressed_attack']} |")
        lines += [
            "",
            "q0.50 is the literal reading of \"suppress a *routine* transition\" and is",
            "nearly inert. That is structural: the flagged rows are already the anomalous",
            "tail, so a line the embedding detector found unusual almost never has a",
            "below-median transition. The two signals are positively correlated.",
            "",
            "### Section 4 numbers",
            "",
            "| suppression | P | R | F1 | instance detection | flagged lines | incidents |",
            "|---|---|---|---|---|---|---|",
        ]
        for name, arm in row["arms"].items():
            label = "off" if name == "off" else (
                f"{name}" + (" (adopted)" if name == adopted else ""))
            lines.append(
                f"| {label} | {arm['precision']} | {arm['recall']} | {arm['f1']} | "
                f"{arm['instance_detection_rate']:.0%} "
                f"({arm['instances_detected']}/{arm['instances']}) | "
                f"{arm['flagged_lines']} | {arm['incidents']} |")
        lines.append("")
    return "\n".join(lines)


ADVERSARIAL_ARMS_HELP = (
    "label=directory pairs, each directory holding an adversarial_results.json. "
    "The control arm must be labelled 'off'.")



# --- section 4 item 3: instance detection under camouflage ------------------

def merge_adversarial(arms: dict[str, str]) -> dict:
    """Put the camouflage arms of the suppression decision in one table.

    `arms` maps a label to a directory holding an `adversarial_results.json`
    written by `logdet-adversarial`. The control arm must be keyed "off".

    This is the half of CLAUDE.md section 4 the clean-corpus report cannot
    reach, and it is the half that decides. Clean instance detection saturates
    at 100% on both corpora with or without suppression, so the only place the
    safety margin is visible is here -- which is the lesson the 2026-08-16
    contamination retune paid for.
    """
    loaded = {
        label: {row["condition"]: row
                for row in json.loads((Path(d) / "adversarial_results.json").read_text())}
        for label, d in arms.items()
    }
    control = loaded["off"]
    conditions = list(control)

    rows = []
    for condition in conditions:
        entry = {"condition": condition, "arms": {}}
        for label, by_condition in loaded.items():
            overall = by_condition[condition]["overall"]
            entry["arms"][label] = {
                "instance_detection_rate": overall["instance_detection_rate"],
                "instances_detected": overall["instances_detected"],
                "instances": overall["instances"],
                "line_detection_rate": overall["line_detection_rate"],
                "flagged_lines": overall["total_flagged_lines"],
                "incidents": overall["incidents"],
                "suppressed_lines": overall.get("suppressed_lines"),
                "suppressed_attack_lines": overall.get("suppressed_attack_lines"),
            }
        base = entry["arms"]["off"]["instance_detection_rate"]
        for label, cell in entry["arms"].items():
            cell["instance_delta_points"] = round(
                (cell["instance_detection_rate"] - base) * 100, 1)
        rows.append(entry)

    return {"seeds": json.loads(
                (Path(arms["off"]) / "adversarial_results.json").read_text())[0]["seeds"],
            "conditions": rows}


def render_adversarial(merged: dict) -> str:
    labels = list(merged["conditions"][0]["arms"])
    lines = [
        "# Alert suppression under camouflage (Stage 3)",
        "",
        f"CLAUDE.md section 4, item 3: instance detection under camouflage, pooled "
        f"over **{merged['seeds']} seeds**. Same corpus, same camouflage code, same",
        "scorer; the only thing that differs between arms is whether suppression ran",
        "and at what threshold.",
        "",
        "The transition model is fitted on a **separate benign-only corpus** generated",
        "at a disjoint seed, once, not per seed -- it is history, and varying it with",
        "the evaluation seed would confound \"the attacker changed tactics\" with \"the",
        "defender was shown a different past\".",
        "",
        "## Instance detection (the registered metric)",
        "",
        "| condition | " + " | ".join(labels) + " | worst cost |",
        "|---" * (len(labels) + 2) + "|",
    ]
    for row in merged["conditions"]:
        cells = []
        for label in labels:
            cell = row["arms"][label]
            delta = cell["instance_delta_points"]
            suffix = "" if label == "off" else f" ({delta:+.1f}pt)"
            cells.append(f"{cell['instance_detection_rate']:.1%}"
                         f" ({cell['instances_detected']}/{cell['instances']}){suffix}")
        worst = min(row["arms"][l]["instance_delta_points"] for l in labels)
        lines.append(f"| `{row['condition']}` | " + " | ".join(cells)
                     + f" | {worst:+.1f}pt |")

    lines += [
        "",
        "## What it cost: evidence retained, and alert volume",
        "",
        "Instance detection can hold at +0.0pt while the *evidence* behind a detection",
        "thins out, because one surviving line is enough to call an instance detected.",
        "The line-detection rate is where that shows, and it is the column to read on",
        "the timing-spread conditions.",
        "",
        "| condition | " + " | ".join(f"{l}: line rate" for l in labels)
        + " | " + " | ".join(f"{l}: incidents" for l in labels)
        + " | attack lines suppressed |",
        "|---" * (2 * len(labels) + 2) + "|",
    ]
    for row in merged["conditions"]:
        rates = [f"{row['arms'][label]['line_detection_rate']:.3f}" for label in labels]
        counts = [str(row["arms"][label]["incidents"]) for label in labels]
        cost = " / ".join(
            str(row["arms"][label]["suppressed_attack_lines"])
            for label in labels if label != "off")
        lines.append(f"| `{row['condition']}` | " + " | ".join(rates) + " | "
                     + " | ".join(counts) + f" | {cost} |")
    lines += [
        "",
        "The suppression rate itself carries the mechanism: it sits near 3% of flagged",
        "lines on every condition and rises on the **timing-spread** ones, which are",
        "exactly the conditions that cost attack lines. Spreading an attack in time is",
        "what makes its lines lone, and lone is what puts a line in the eligible pool.",
        "That is the predicted failure mode, found where it was predicted.",
        "",
    ]
    return "\n".join(lines)


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Measure Stage 3 alert suppression on every corpus with ground truth.")
    parser.add_argument("--output", default=str(Path(RESULTS_DIR) / "suppression"))
    parser.add_argument("--corpora", nargs="+", default=["synthetic", "killpoint"],
                        choices=["synthetic", "killpoint"])
    parser.add_argument("--merge-adversarial", nargs="+", metavar="LABEL=DIR",
                        default=None, help=ADVERSARIAL_ARMS_HELP)
    args = parser.parse_args()

    if args.merge_adversarial:
        arms = dict(pair.split("=", 1) for pair in args.merge_adversarial)
        merged = merge_adversarial(arms)
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        (out / "suppression_adversarial.json").write_text(json.dumps(merged, indent=2))
        (out / "suppression_adversarial.md").write_text(render_adversarial(merged))
        print(render_adversarial(merged))
        print(f"\nWritten to {args.output}")
        return

    payload = run(args.output, tuple(args.corpora))
    print(render_report(payload))
    print(f"\nWritten to {args.output}")


if __name__ == "__main__":
    cli()
