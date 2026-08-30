"""
fit.py
Fits a per-user detector on a slice of history and writes it to disk.

This is the "fit" half of the fit/score split that streaming needs. The stream
must never fit on the traffic it is judging: an Isolation Forest learns what is
normal from whatever it is shown, so fitting on live traffic would let a
long-running attack define itself as normal. Fitting here, on a corpus chosen
deliberately, keeps the baseline a decision rather than an accident.

Usage:
    logdet-fit --input data/processed/parsed.csv --output models/detector.joblib
"""

import argparse

import pandas as pd

from logdet.anomaly_detection import PerUserAnomalyDetector
from logdet.config import CONTAMINATION, DEFAULT_DETECTOR_PATH
from logdet.embedding import add_embeddings_to_df


def fit_detector(input_csv: str, output_path: str = DEFAULT_DETECTOR_PATH,
                 contamination: float = CONTAMINATION) -> PerUserAnomalyDetector:
    """Embed a parsed-log CSV, fit a detector on it, and persist it."""
    df = pd.read_csv(input_csv, parse_dates=["timestamp"])
    print(f"Loaded {len(df)} parsed rows of history from {input_csv}")

    df = add_embeddings_to_df(df, template_col="template")
    detector = PerUserAnomalyDetector(contamination=contamination).fit(df)
    detector.save(output_path)

    print(f"Fitted per-user models for {len(detector.models)} users "
          f"(plus the global fallback) -> {output_path}")
    return detector


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Fit a detector on historical logs and save it for the stream to score with.")
    parser.add_argument("--input", required=True,
                        help="Parsed log CSV of history (from logdet-preprocess)")
    parser.add_argument("--output", default=DEFAULT_DETECTOR_PATH)
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help="Expected anomaly fraction; leave at the config value in production")
    args = parser.parse_args()

    fit_detector(args.input, args.output, contamination=args.contamination)


if __name__ == "__main__":
    cli()
