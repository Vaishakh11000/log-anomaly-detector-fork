"""
End-to-end behaviour lock on the v1 synthetic corpus.

This is the test that says "the refactor changed nothing." It runs the real
embedding model, so it is marked `slow` and skipped in CI; run it locally
before any commit that touches detection.

If a number here changes, that is a *detection change*, and CLAUDE.md section 4
applies: re-run the adversarial suite over >=5 seeds and record the delta
against docs/results.v1/ before updating these constants. Never just edit the
expected value to make the test green -- that is the failure mode this file
exists to prevent.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "data" / "raw" / "synthetic.log"

# v1 baseline, reproduced after the Stage 0 restructure (2026-08-18).
EXPECTED_LINES = 751
EXPECTED_ANOMALIES = 130
EXPECTED_TRAVEL_HITS = 3
EXPECTED_INCIDENTS = 94

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def scored():
    from logdet.anomaly_detection import run_anomaly_detection
    from logdet.embedding import add_embeddings_to_df
    from logdet.preprocessing import preprocess_file

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        df = preprocess_file(str(CORPUS), str(Path(tmp) / "parsed.csv"), year=2026)
    return run_anomaly_detection(add_embeddings_to_df(df))


def test_the_corpus_parses_to_the_expected_line_count(scored):
    assert len(scored) == EXPECTED_LINES


def test_anomaly_counts_match_the_v1_baseline(scored):
    assert int(scored["is_anomaly"].sum()) == EXPECTED_ANOMALIES
    assert int(scored["impossible_travel"].sum()) == EXPECTED_TRAVEL_HITS


def test_incident_count_matches_the_v1_baseline(scored):
    """94 incidents for 9 real attacks is v1's headline weakness (CLAUDE.md
    section 3). Pinned so that Stage 3's sequence modelling has to *show* the
    improvement rather than assert it."""
    from logdet.sequence_grouping import group_anomalies

    assert len(group_anomalies(scored)) == EXPECTED_INCIDENTS


def test_every_flagged_line_carries_a_severity(scored):
    flagged = scored[scored["is_anomaly"]]
    assert flagged["severity"].isin({"low", "medium", "high"}).all()
    assert (scored[~scored["is_anomaly"]]["severity"] == "none").all()


def test_impossible_travel_hits_are_always_high_severity(scored):
    """The physics check outranks the ML score -- a confirmed signal must never
    be filed as low."""
    assert (scored[scored["impossible_travel"]]["severity"] == "high").all()
