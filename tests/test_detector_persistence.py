"""Persisting a fitted detector (Stage 2: fit on history, score on stream).

The failure this file mostly guards against is silent rather than loud. An
Isolation Forest will score embeddings produced by a *different* embedding
model and return plausible numbers that mean nothing, so the provenance checks
matter more than the round-trip does.
"""

import numpy as np
import pandas as pd
import pytest

from logdet.anomaly_detection import PerUserAnomalyDetector, run_anomaly_detection
from logdet.config import EMBEDDING_MODEL


def frame(n_per_user: int = 12, dim: int = 384, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    users = ["alice", "bob"]
    return pd.DataFrame({
        "user": [u for u in users for _ in range(n_per_user)],
        "embedding": [rng.normal(0, 1, dim) for _ in range(len(users) * n_per_user)],
    })


def with_log_columns(df: pd.DataFrame) -> pd.DataFrame:
    """The columns the impossible-travel rule and severity tiers read."""
    df = df.copy()
    df["timestamp"] = pd.date_range("2026-01-01", periods=len(df), freq="min")
    df["source_ip"] = "10.0.0.1"
    df["message"] = "Accepted password for " + df["user"] + " from 10.0.0.1 port 22 ssh2"
    return df


@pytest.fixture
def fitted() -> PerUserAnomalyDetector:
    return PerUserAnomalyDetector().fit(frame())


class TestRoundTrip:
    def test_scores_are_identical_after_a_save_and_load(self, fitted, tmp_path):
        """The whole point: a detector fit yesterday must score today's stream
        exactly as it would have scored it yesterday."""
        data = frame(seed=1)
        before = fitted.score(data)
        path = tmp_path / "detector.joblib"
        fitted.save(path)
        after = PerUserAnomalyDetector.load(path).score(data)

        np.testing.assert_allclose(before["anomaly_score"], after["anomaly_score"])
        assert before["is_anomaly"].tolist() == after["is_anomaly"].tolist()

    def test_per_user_models_survive(self, fitted, tmp_path):
        path = tmp_path / "d.joblib"
        fitted.save(path)
        assert set(PerUserAnomalyDetector.load(path).models) == set(fitted.models)

    def test_hyperparameters_survive(self, tmp_path):
        detector = PerUserAnomalyDetector(contamination=0.07, random_state=7).fit(frame())
        path = tmp_path / "d.joblib"
        detector.save(path)
        loaded = PerUserAnomalyDetector.load(path)
        assert (loaded.contamination, loaded.random_state) == (0.07, 7)

    def test_describe_reports_provenance_without_scoring(self, fitted, tmp_path):
        path = tmp_path / "d.joblib"
        fitted.save(path)
        info = PerUserAnomalyDetector.describe(path)
        assert info["embedding_model"] == EMBEDDING_MODEL
        assert info["embedding_dim"] == 384
        assert info["users"] == sorted(fitted.models)


class TestRefusals:
    def test_saving_an_unfitted_detector_is_refused(self, tmp_path):
        with pytest.raises(RuntimeError, match="unfitted"):
            PerUserAnomalyDetector().save(tmp_path / "d.joblib")

    def test_scoring_an_unfitted_detector_is_refused(self):
        with pytest.raises(RuntimeError, match="not been fitted"):
            PerUserAnomalyDetector().score(frame())

    def test_a_different_embedding_model_is_refused(self, fitted, tmp_path):
        """The silent-garbage case: same vector width, different meaning."""
        path = tmp_path / "d.joblib"
        fitted.save(path)
        with pytest.raises(ValueError, match="not comparable"):
            PerUserAnomalyDetector.load(path, expect_embedding_model="some-other-model")

    def test_a_stale_format_version_is_refused(self, fitted, tmp_path, monkeypatch):
        path = tmp_path / "d.joblib"
        fitted.save(path)
        monkeypatch.setattr(PerUserAnomalyDetector, "FORMAT_VERSION", 99)
        with pytest.raises(ValueError, match="format"):
            PerUserAnomalyDetector.load(path)

    def test_mismatched_embedding_width_is_refused(self, fitted):
        with pytest.raises(ValueError, match="dimensional"):
            fitted.score(frame(dim=128))

    def test_inspection_may_bypass_the_embedding_check(self, fitted, tmp_path):
        path = tmp_path / "d.joblib"
        fitted.save(path)
        assert PerUserAnomalyDetector.load(path, expect_embedding_model=None) is not None


class TestBatchPathUnchanged:
    def test_omitting_a_detector_still_fits_on_the_frame(self):
        """v1's behaviour, and what the pinned 751 -> 130 -> 94 lock depends on."""
        data = frame()
        data = with_log_columns(data)
        assert "is_anomaly" in run_anomaly_detection(data).columns

    def test_supplying_a_detector_scores_without_refitting(self, fitted):
        data = frame(seed=2)
        data = with_log_columns(data)
        models_before = dict(fitted.models)
        run_anomaly_detection(data, detector=fitted)
        assert fitted.models == models_before

    def test_a_supplied_detector_gives_the_same_verdicts_as_scoring_directly(self, fitted):
        data = frame(seed=3)
        data = with_log_columns(data)
        direct = fitted.score(data)
        viarun = run_anomaly_detection(data, detector=fitted)
        assert direct["is_anomaly"].tolist() == viarun["ml_anomaly"].tolist()
