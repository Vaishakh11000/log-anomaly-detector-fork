"""
history.py
The history slice every suppression-enabled evaluation run fits its sequence
model on.

Stage 3 suppression needs a transition model, and *where that model is fitted*
is the single decision most able to invalidate the result. Fitting it on the
corpus being scored collapses the signal from AUC 0.912 to 0.558 on the
kill-point corpus (`results/sequence/killpoint/`), because ambient brute force
teaches the model that brute force is routine. Fitting it on the ground-truth
benign rows is worse in a different way: legitimate for a diagnostic, but not
available to a rule that has to run at inference time, so a result obtained
that way would not be reproducible by the shipped system.

So an evaluation run builds its own history: the same generator, the same
background construction, **no injected attacks**, at a seed disjoint from every
evaluation seed. That is the evaluation-track form of what `logdet-fit` does in
production, and it is the only form that keeps a suppression number honest.

Two things travel with the model and cannot be separated from it:

*The miner state.* The model is keyed on Drain3 cluster ids, which mean nothing
outside the miner that assigned them. Every scored corpus is mined by a miner
restored from this state, so all conditions in a run share one vocabulary and
none mutates the state the next condition will load.

*The threshold in nats.* Read off the history's own transition distribution,
never off the corpus being scored -- a quantile of the scored corpus would move
with the attack, which is precisely the property a suppression threshold must
not have.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from logdet.config import SEQUENCE_SUPPRESSION_QUANTILE
from logdet.preprocessing import preprocess_file
from logdet.sequence_model import TransitionModel
from logdet.templating import TemplateMiner
from logdet_eval.config import (
    SYNTHETIC_HOST,
    SYNTHETIC_TOTAL_LINES,
    SYNTHETIC_YEAR,
)
from logdet_eval.generate_logs import build_dataset, format_line

# Offset applied to an evaluation seed to pick the history corpus's seed. Any
# fixed, large offset works; the only requirement is that the history corpus is
# never one of the corpora being scored.
HISTORY_SEED_OFFSET = 1000


class FittedHistory:
    """A transition model, the miner state it is numbered against, and a threshold.

    Bundled rather than returned as a tuple because handing any one of the
    three to a scorer without the other two produces numbers that look fine and
    mean nothing -- the same failure mode `PerUserAnomalyDetector.load` refuses
    outright for embeddings.
    """

    def __init__(self, model: TransitionModel, miner_state: str, threshold: float,
                 rows: int):
        self.model = model
        self.miner_state = miner_state
        self.threshold = threshold
        self.rows = rows

    def describe(self) -> str:
        return (f"{self.rows} benign history lines, {len(self.model.vocabulary)} "
                f"templates, suppression threshold {self.threshold:.3f} nats")


def _fit(log_path: Path, parsed_csv: Path, state_path: Path, year: int,
         quantile: float) -> FittedHistory:
    miner = TemplateMiner()
    history = preprocess_file(str(log_path), str(parsed_csv), year=year,
                              miner=miner, mine_templates=True)
    miner.save(state_path)

    model = TransitionModel().fit(history)
    threshold = float(model.surprisal(history).dropna().quantile(quantile))
    return FittedHistory(model, str(state_path), threshold, len(history))


def synthetic_history(work_dir: Path, seed: int,
                      total_lines: int = SYNTHETIC_TOTAL_LINES,
                      year: int = SYNTHETIC_YEAR,
                      host: str = SYNTHETIC_HOST,
                      quantile: float = SEQUENCE_SUPPRESSION_QUANTILE) -> FittedHistory:
    """Benign-only synthetic traffic: the same generator with no attack instances."""
    events = build_dataset(total_lines=total_lines, instances_per_scenario=0,
                           year=year, seed=seed)
    log_path = work_dir / "history.log"
    log_path.write_text("\n".join(format_line(e, host) for e in events) + "\n")
    return _fit(log_path, work_dir / "history_parsed.csv",
                work_dir / "history_templates.json", year, quantile)


def openssh_history(work_dir: Path, seed: int, ambient_ratio: float = 0.05,
                    year: int = 2026,
                    quantile: float = SEQUENCE_SUPPRESSION_QUANTILE) -> FittedHistory:
    """The kill-point background with no injected attacks, at a disjoint seed.

    This history overlaps the scored corpus in its benign pool: the host has
    only ~2.4k genuinely benign lines and both draws come from them. That is
    realistic -- history is the same host's earlier traffic -- but it is not a
    held-out split, and any report using it has to say so rather than implying
    one. The ambient attacker traffic is deliberately kept, because a
    background with none would make an injected attack trivially separable and
    would flatter every number downstream.
    """
    from logdet_eval.corpus_openssh import CORPUS_HOST, build_background, load_classified

    benign, attacker, _users, _subnets = load_classified()
    background = build_background(benign, attacker, ambient_ratio, seed)
    log_path = work_dir / "history.log"
    log_path.write_text(
        "\n".join(format_line(e, CORPUS_HOST) for e in background) + "\n")
    return _fit(log_path, work_dir / "history_parsed.csv",
                work_dir / "history_templates.json", year, quantile)
