"""
The streaming path reaches the same verdict as the batch path.

Streaming only earns trust if arrival timing does not change the answer. This
runs the real embedding model over the v1 synthetic corpus twice -- once as a
batch, once as micro-batches through the tailer -- against one detector fitted
on that corpus, and asserts the same 130 flagged events in the same 94
incidents. Marked `slow` (it downloads the sentence-transformer) and skipped
in CI, like the batch lock it mirrors.

If these diverge, the streaming state is losing something: the rolling context
window is too short, or an incident is being split at a batch boundary.
CLAUDE.md section 4 applies to any change that moves them.
"""

import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "data" / "raw" / "synthetic.log"

EXPECTED_ANOMALIES = 130
EXPECTED_INCIDENTS = 94

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def streamed():
    from logdet.anomaly_detection import PerUserAnomalyDetector
    from logdet.embedding import add_embeddings_to_df
    from logdet.preprocessing import preprocess_file
    from logdet.stream import FileTailSource, MicroBatcher, StreamProcessor, run_stream

    with tempfile.TemporaryDirectory() as tmp:
        df = preprocess_file(str(CORPUS), str(Path(tmp) / "parsed.csv"), year=2026)
        detector = PerUserAnomalyDetector().fit(add_embeddings_to_df(df))

        processor = StreamProcessor(detector, year=2026)
        run_stream(FileTailSource(CORPUS, from_start=True), processor, once=True,
                   batcher=MicroBatcher(max_lines=25, max_seconds=1e9))
    return processor


def test_the_stream_flags_the_same_events_as_the_batch_run(streamed):
    events = sum(entry["event_count"] for entry in streamed._emitted.values())
    assert events == EXPECTED_ANOMALIES


def test_the_stream_groups_them_into_the_same_incidents(streamed):
    assert len(streamed._emitted) == EXPECTED_INCIDENTS


def test_every_incident_is_closed_by_the_end_of_the_stream(streamed):
    assert streamed.tracker.incidents == {}
    assert all(e["status"] == "closed" for e in streamed._emitted.values())
