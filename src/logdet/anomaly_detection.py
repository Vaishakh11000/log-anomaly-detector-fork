"""
anomaly_detection.py
Learns a per-user "normal" baseline over log-line embeddings using
Isolation Forest, and scores new log lines for anomalousness. Per-user
baselines avoid the naive "any login from Russia is bad" failure mode --
anomaly is judged relative to *that user's* historical pattern.

Also owns two signals the embedding model can't provide on its own:
  - impossible-travel: a physics check (same user, different IP subnet,
    within a short window) that semantic similarity is blind to, since
    template_message() masks the IP before embedding
  - severity tiers: a simple bucketing of anomaly strength, plus a hard
    override to "high" for impossible-travel hits, which are trusted
    more than the ML score
"""

import numpy as np
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
from sklearn.ensemble import IsolationForest

from logdet.config import (
    EMBEDDING_MODEL,
    CONTAMINATION,
    MIN_SAMPLES_PER_USER,
    RANDOM_STATE,
    SEVERITY_THRESHOLDS,
    IMPOSSIBLE_TRAVEL_WINDOW_MINUTES,
    TRAVEL_SUBNET_PREFIX_LENGTH,
)

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


class PerUserAnomalyDetector:
    """Per-user Isolation Forests over sentence embeddings, with a global
    fallback for users too sparse to model on their own.

    Fitting and scoring are separate calls so a detector can be fit on history
    and then score a live stream (Stage 2). `save`/`load` persist a fitted
    detector between the two.
    """

    # Bumped whenever the persisted layout changes, so an old file fails loudly
    # rather than loading into a structure that no longer means the same thing.
    FORMAT_VERSION = 1

    def __init__(self, contamination: float = CONTAMINATION, random_state: int = RANDOM_STATE):
        self.contamination = contamination
        self.random_state = random_state
        self.models = {}          # user -> fitted IsolationForest
        self.global_model = None  # fallback for users with sparse history
        self.embedding_model = EMBEDDING_MODEL
        self.embedding_dim: int | None = None

    def fit(self, df: pd.DataFrame, user_col: str = "user", embedding_col: str = "embedding"):
        all_embeddings = np.stack(df[embedding_col].values)
        self.embedding_dim = all_embeddings.shape[1]
        self.global_model = IsolationForest(
            contamination=self.contamination, random_state=self.random_state
        ).fit(all_embeddings)

        for user, group in df.groupby(user_col):
            if len(group) < MIN_SAMPLES_PER_USER:
                continue  # too little data -> will use global model at inference
            embeddings = np.stack(group[embedding_col].values)
            model = IsolationForest(
                contamination=self.contamination, random_state=self.random_state
            ).fit(embeddings)
            self.models[user] = model

        return self

    def score(self, df: pd.DataFrame, user_col: str = "user", embedding_col: str = "embedding") -> pd.DataFrame:
        """Adds 'anomaly_score' (lower = more anomalous) and 'is_anomaly' (bool) columns."""
        if self.global_model is None:
            raise RuntimeError(
                "detector has not been fitted -- call fit() or load() first")
        df = df.copy()
        if len(df) and self.embedding_dim is not None:
            width = np.asarray(df[embedding_col].iloc[0]).reshape(1, -1).shape[1]
            if width != self.embedding_dim:
                raise ValueError(
                    f"embeddings are {width}-dimensional but this detector was fit on "
                    f"{self.embedding_dim}. Scoring anyway would produce numbers that "
                    "look valid and mean nothing.")
        scores = []
        flags = []

        for _, row in df.iterrows():
            user = row[user_col]
            embedding = row[embedding_col].reshape(1, -1)
            model = self.models.get(user, self.global_model)
            score = model.decision_function(embedding)[0]
            pred = model.predict(embedding)[0]  # -1 = anomaly, 1 = normal
            scores.append(score)
            flags.append(pred == -1)

        df["anomaly_score"] = scores
        df["is_anomaly"] = flags
        return df


    def save(self, path) -> "PerUserAnomalyDetector":
        """Persist the fitted detector.

        The provenance stamped alongside it is the point: an Isolation Forest
        will happily score embeddings from a *different* embedding model and
        return plausible-looking numbers that mean nothing. `load` refuses that
        rather than letting it through.
        """
        if self.global_model is None:
            raise RuntimeError("refusing to save an unfitted detector")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "format_version": self.FORMAT_VERSION,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "embedding_model": self.embedding_model,
            "embedding_dim": self.embedding_dim,
            "min_samples_per_user": MIN_SAMPLES_PER_USER,
            "sklearn_version": sklearn.__version__,
            "fitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "users": sorted(self.models),
            "global_model": self.global_model,
            "models": self.models,
        }, path)
        return self

    @classmethod
    def load(cls, path, expect_embedding_model: str | None = EMBEDDING_MODEL
             ) -> "PerUserAnomalyDetector":
        """Restore a fitted detector, refusing anything that would score garbage.

        Pass `expect_embedding_model=None` only to inspect a stored detector,
        never to score with one.
        """
        payload = joblib.load(Path(path))

        stored_version = payload.get("format_version")
        if stored_version != cls.FORMAT_VERSION:
            raise ValueError(
                f"detector was written in format {stored_version}, this code reads "
                f"{cls.FORMAT_VERSION}. Refit rather than guessing at the difference.")

        stored_embedding = payload.get("embedding_model")
        if expect_embedding_model is not None and stored_embedding != expect_embedding_model:
            raise ValueError(
                f"detector was fit on embeddings from '{stored_embedding}' but the "
                f"pipeline is configured for '{expect_embedding_model}'. The vectors "
                "are not comparable, so every score would be meaningless.")

        detector = cls(contamination=payload["contamination"],
                       random_state=payload["random_state"])
        detector.embedding_model = stored_embedding
        detector.embedding_dim = payload.get("embedding_dim")
        detector.global_model = payload["global_model"]
        detector.models = payload["models"]
        return detector

    @staticmethod
    def describe(path) -> dict:
        """Provenance of a stored detector without loading its models."""
        payload = joblib.load(Path(path))
        return {key: payload[key] for key in (
            "format_version", "contamination", "random_state", "embedding_model",
            "embedding_dim", "min_samples_per_user", "sklearn_version",
            "fitted_at", "users") if key in payload}


def _subnet_prefix(ip: str, prefix_len: int = TRAVEL_SUBNET_PREFIX_LENGTH) -> str:
    return ".".join(ip.split(".")[:prefix_len])


def detect_impossible_travel(
    df: pd.DataFrame,
    user_col: str = "user",
    time_col: str = "timestamp",
    ip_col: str = "source_ip",
    message_col: str = "message",
    window_minutes: int = IMPOSSIBLE_TRAVEL_WINDOW_MINUTES,
    subnet_prefix_len: int = TRAVEL_SUBNET_PREFIX_LENGTH,
) -> pd.DataFrame:
    """Adds an 'impossible_travel' bool column: True when a successful login
    for a user comes from a different IP subnet than that user's immediately
    preceding successful login, within `window_minutes`. Only considers
    "accepted"/successful-login-style lines -- this is a physics check on
    real logins, not a generic IP-change detector."""
    df = df.copy()
    df["impossible_travel"] = False
    window = pd.Timedelta(minutes=window_minutes)

    login_mask = df[message_col].str.contains("accepted password", case=False, na=False)
    logins = df[login_mask & df[ip_col].notna()].sort_values([user_col, time_col])

    prev_user = None
    prev_ip = None
    prev_time = None
    for idx, row in logins.iterrows():
        user, ip, ts = row[user_col], row[ip_col], row[time_col]
        if user == prev_user and ts - prev_time <= window:
            if _subnet_prefix(ip, subnet_prefix_len) != _subnet_prefix(prev_ip, subnet_prefix_len):
                df.loc[idx, "impossible_travel"] = True
        prev_user, prev_ip, prev_time = user, ip, ts

    return df


def assign_severity(df: pd.DataFrame, score_col: str = "anomaly_score") -> pd.DataFrame:
    """Adds a 'severity' column (high/medium/low/none) from the negated
    anomaly score (higher = more anomalous), per SEVERITY_THRESHOLDS.
    Rows with impossible_travel=True are forced to "high" regardless of
    the ML score -- a confirmed physics-based signal outranks a soft
    semantic one."""
    df = df.copy()

    def _bucket(row) -> str:
        if not row["is_anomaly"]:
            return "none"
        negated = -row[score_col]
        if negated >= SEVERITY_THRESHOLDS["high"]:
            return "high"
        if negated >= SEVERITY_THRESHOLDS["medium"]:
            return "medium"
        return "low"

    df["severity"] = df.apply(_bucket, axis=1)
    if "impossible_travel" in df.columns:
        df.loc[df["impossible_travel"], "severity"] = "high"
    return df


def highest_severity(severities: pd.Series) -> str:
    """Reduce a Series of severity labels to the single highest one."""
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


def run_anomaly_detection(df: pd.DataFrame,
                          contamination: float = CONTAMINATION,
                          detector: "PerUserAnomalyDetector | None" = None) -> pd.DataFrame:
    """Full Phase 3 detection stack: per-user ML scoring + impossible-travel
    rule + severity tiers. This is the entry point pipeline.py should call --
    it owns how the signals combine so orchestration code stays thin.

    `contamination` is a parameter so Phase 7 can sweep it without reaching
    into the internals; production callers should leave it at the config value.

    Keeps 'ml_anomaly' (the embedding verdict before the rule is OR-ed in)
    alongside 'is_anomaly', so evaluation can attribute a detection to the
    model or to the rule.
    """
    # Passing a detector means "score with this, do not refit" -- the streaming
    # path (fit on history, score on the stream). Omitting it keeps the batch
    # behaviour v1 had, fit and score on the same frame, so the pinned
    # 751 -> 130 -> 94 numbers are unaffected.
    if detector is None:
        detector = PerUserAnomalyDetector(contamination=contamination).fit(df)
    scored = detector.score(df)
    scored = detect_impossible_travel(scored)
    scored["ml_anomaly"] = scored["is_anomaly"]
    scored["is_anomaly"] = scored["ml_anomaly"] | scored["impossible_travel"]
    scored = assign_severity(scored)
    return scored


if __name__ == "__main__":
    # smoke test with random embeddings
    rng = np.random.default_rng(0)
    df = pd.DataFrame({
        "user": ["alice"] * 20 + ["bob"] * 20,
        "embedding": [rng.normal(0, 1, 384) for _ in range(38)] + [rng.normal(5, 1, 384) for _ in range(2)],
    })
    detector = PerUserAnomalyDetector().fit(df)
    scored = detector.score(df)
    print(scored["is_anomaly"].value_counts())

    # impossible-travel + severity smoke test
    travel_df = pd.DataFrame({
        "user": ["alice", "alice", "bob"],
        "timestamp": pd.to_datetime([
            "2026-07-18 10:00:00", "2026-07-18 10:15:00", "2026-07-18 10:00:00",
        ]),
        "source_ip": ["10.0.0.12", "203.0.113.44", "10.0.1.9"],
        "message": [
            "Accepted password for alice from 10.0.0.12 port 51000 ssh2",
            "Accepted password for alice from 203.0.113.44 port 51010 ssh2",
            "Accepted password for bob from 10.0.1.9 port 51020 ssh2",
        ],
        "anomaly_score": [0.1, 0.1, 0.1],
        "is_anomaly": [False, False, False],
    })
    travel_scored = detect_impossible_travel(travel_df)
    travel_scored["is_anomaly"] = travel_scored["is_anomaly"] | travel_scored["impossible_travel"]
    travel_scored = assign_severity(travel_scored)
    print(travel_scored[["user", "impossible_travel", "severity"]])
