"""
fit.py
Fits a per-user detector on a slice of history and writes it to disk.

This is the "fit" half of the fit/score split that streaming needs. The stream
must never fit on the traffic it is judging: an Isolation Forest learns what is
normal from whatever it is shown, so fitting on live traffic would let a
long-running attack define itself as normal. Fitting here, on a corpus chosen
deliberately, keeps the baseline a decision rather than an accident.

The same argument applies with more force to the Stage 3 sequence model: a
brute-force burst repeats one template transition often enough to teach a model
fitted on it that the burst is routine. Measured on the synthetic corpus, that
self-poisoning costs 0.855 -> 0.715 AUC in separating attack lines from benign
ones -- so the transition model is fitted here, on history, and never inside
the scoring path.

Usage:
    logdet-fit --input data/processed/parsed.csv --output models/detector.joblib
    logdet-fit --input data/processed/parsed.csv --sequence-model
"""

import argparse

import pandas as pd

from logdet.anomaly_detection import PerUserAnomalyDetector
from logdet.config import (
    CONTAMINATION,
    DEFAULT_DETECTOR_PATH,
    DEFAULT_SEQUENCE_MODEL_PATH,
)
from logdet.embedding import add_embeddings_to_df
from logdet.sequence_model import TransitionModel


def fit_detector(input_csv: str, output_path: str = DEFAULT_DETECTOR_PATH,
                 contamination: float = CONTAMINATION,
                 sequence_output: str | None = None) -> PerUserAnomalyDetector:
    """Embed a parsed-log CSV, fit a detector on it, and persist it.

    `sequence_output`, if given, also fits the Stage 3 transition model over
    the `template_id` column and writes it alongside. It is a separate file
    rather than a field on the detector because the two are fit on different
    things -- the detector on embeddings, the sequence model on mined cluster
    ids -- and only the second is invalidated by re-mining the templates.
    """
    df = pd.read_csv(input_csv, parse_dates=["timestamp"])
    print(f"Loaded {len(df)} parsed rows of history from {input_csv}")

    df = add_embeddings_to_df(df, template_col="template")
    detector = PerUserAnomalyDetector(contamination=contamination).fit(df)
    detector.save(output_path)

    print(f"Fitted per-user models for {len(detector.models)} users "
          f"(plus the global fallback) -> {output_path}")

    if sequence_output:
        sequence = TransitionModel().fit(df)
        sequence.save(sequence_output)
        print(f"Fitted transition model over {len(sequence.vocabulary)} templates "
              f"(routine <= {sequence.routine_threshold:.3f} nats, "
              f"rare >= {sequence.rare_threshold:.3f}) -> {sequence_output}")
    return detector


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Fit a detector on historical logs and save it for the stream to score with.")
    parser.add_argument("--input", required=True,
                        help="Parsed log CSV of history (from logdet-preprocess)")
    parser.add_argument("--output", default=DEFAULT_DETECTOR_PATH)
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help="Expected anomaly fraction; leave at the config value in production")
    parser.add_argument("--sequence-model", nargs="?", const=DEFAULT_SEQUENCE_MODEL_PATH,
                        default=None,
                        help="Also fit the Stage 3 transition model over template_id "
                             "(the input must have been parsed with --drain3)")
    args = parser.parse_args()

    fit_detector(args.input, args.output, contamination=args.contamination,
                 sequence_output=args.sequence_model)


if __name__ == "__main__":
    cli()
