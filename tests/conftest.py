"""
Shared fixtures.

Everything here is deliberately embedding-free: the unit suite must run in
seconds on CI without downloading a sentence-transformer. Tests that do need
the real model are marked `slow`.
"""

import numpy as np
import pandas as pd
import pytest


def event(ts: str, user: str, ip: str | None, message: str) -> dict:
    """One parsed log row, in the shape preprocessing.py produces."""
    return {
        "timestamp": pd.Timestamp(ts),
        "user": user,
        "source_ip": ip,
        "message": message,
        "is_anomaly": True,
    }


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(0)


@pytest.fixture
def embedded_frame(rng: np.random.Generator) -> pd.DataFrame:
    """A frame with fake 384-d embeddings: alice has ample history, bob does
    not (below MIN_SAMPLES_PER_USER), and two rows sit far off the manifold."""
    rows = (
        [{"user": "alice", "embedding": rng.normal(0, 1, 384)} for _ in range(20)]
        + [{"user": "bob", "embedding": rng.normal(0, 1, 384)} for _ in range(3)]
        + [{"user": "alice", "embedding": rng.normal(8, 1, 384)} for _ in range(2)]
    )
    return pd.DataFrame(rows)
