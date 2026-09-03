"""
Stage 3 alert suppression -- the first change that clears `is_anomaly`.

Four guards decide whether a flagged row is withdrawn, and each one has a test
here that fails if it is removed. They are not equally important: the loneness
guard and the impossible-travel guard are the *safety* properties (they are
what keep attack lines out of the suppression pool), while the surprisal
threshold is only selectivity. A refactor that weakens either of the first two
has to be re-measured under camouflage from scratch, and these tests are the
cheap early warning for that.
"""

import numpy as np
import pandas as pd
import pytest

from logdet.anomaly_detection import run_anomaly_detection
from logdet.sequence_grouping import group_anomalies
from logdet.sequence_model import TransitionModel
from logdet.suppression import (
    lone_flagged_mask,
    lone_mask,
    neighbourhood_counts,
    suppress_routine_singletons,
    suppression_mask,
    threshold_for,
)


def frame(rows: list[dict]) -> pd.DataFrame:
    """A scored frame with the columns suppression reads, and sane defaults."""
    defaults = {"user": "alice", "source_ip": "10.0.0.5", "is_anomaly": True,
                "impossible_travel": False, "transition_surprisal": 0.1,
                "message": "x"}
    built = []
    for n, row in enumerate(rows):
        merged = {**defaults, "timestamp": pd.Timestamp("2026-07-14 10:00:00")
                  + pd.Timedelta(minutes=n * 90), **row}
        built.append(merged)
    return pd.DataFrame(built)


# --- guard 2: loneness -----------------------------------------------------

def test_a_flagged_row_alone_in_its_incident_is_lone():
    # 90 minutes apart, so the 30-minute grouping window never links them.
    scored = frame([{}, {}])
    assert list(lone_flagged_mask(scored)) == [True, True]


def test_rows_that_group_together_are_not_lone():
    scored = frame([{}, {}])
    scored["timestamp"] = pd.to_datetime(
        ["2026-07-14 10:00:00", "2026-07-14 10:05:00"])
    assert list(lone_flagged_mask(scored)) == [False, False]


def test_a_corroborated_row_is_never_suppressed():
    """The guard that matters most: a row sharing an actor with another flagged
    row inside the window is evidence, however ordinary its transition."""
    scored = frame([{}, {}])
    scored["timestamp"] = pd.to_datetime(
        ["2026-07-14 10:00:00", "2026-07-14 10:05:00"])
    assert not suppression_mask(scored, threshold=5.0).any()


def test_an_unflagged_row_is_never_suppressed():
    scored = frame([{"is_anomaly": False}])
    assert not suppression_mask(scored, threshold=5.0).any()


# --- guard 1: impossible travel -------------------------------------------

def test_an_impossible_travel_hit_is_never_suppressed():
    """The physics rule is the *only* thing that detects Scenario B -- both
    login legs are identical vectors once the IP is masked -- so suppressing
    one would remove the only evidence there is."""
    scored = frame([{"impossible_travel": True}])
    assert list(lone_flagged_mask(scored)) == [True]
    assert not suppression_mask(scored, threshold=5.0).any()


# --- guard 3: silence is not evidence -------------------------------------

def test_a_row_the_model_cannot_score_is_never_suppressed():
    """NaN means an unknown template, the first event of a sequence, or no
    usable actor key. Reading silence as 'unremarkable' is what would break
    account enumeration under ip_rotate, where both keys change every line."""
    scored = frame([{"transition_surprisal": np.nan}])
    assert not suppression_mask(scored, threshold=5.0).any()


# --- guard 4: the threshold ------------------------------------------------

def test_a_rare_transition_survives_and_an_ordinary_one_does_not():
    scored = frame([{"transition_surprisal": 0.5}, {"transition_surprisal": 9.0}])
    assert list(suppression_mask(scored, threshold=1.0)) == [True, False]


def test_no_threshold_means_no_suppression():
    assert not suppression_mask(frame([{}]), threshold=None).any()


# --- the applied form ------------------------------------------------------

def test_suppression_clears_is_anomaly_but_keeps_the_ml_verdict():
    """`ml_anomaly` records what the embedding detector said. Overwriting it
    would erase the evidence that a row was flagged and then withdrawn, which
    is what evaluation attributes detections through."""
    scored = frame([{}])
    scored["ml_anomaly"] = True
    after = suppress_routine_singletons(scored, threshold=1.0)
    assert not after["is_anomaly"].iloc[0]
    assert after["ml_anomaly"].iloc[0]
    assert after["suppressed"].iloc[0]


def test_a_second_pass_suppresses_nothing_further():
    """Removing a singleton cannot change any other incident's membership -- no
    other row was linked to it, or it would not have been a singleton. So
    iterating is provably a no-op, which is why the rule runs exactly once."""
    scored = frame([{}, {}, {"transition_surprisal": 9.0}])
    once = suppress_routine_singletons(scored, threshold=1.0)
    twice = suppress_routine_singletons(once.drop(columns="suppressed"), threshold=1.0)
    assert list(once["is_anomaly"]) == list(twice["is_anomaly"])


def test_suppression_never_flags_a_row_that_was_not_flagged():
    scored = frame([{"is_anomaly": False}, {}])
    after = suppress_routine_singletons(scored, threshold=1.0)
    assert not after["is_anomaly"].iloc[0]


def test_suppressing_a_singleton_removes_exactly_one_incident():
    scored = frame([{}, {"transition_surprisal": 9.0}])
    before = len(group_anomalies(scored))
    after = len(group_anomalies(suppress_routine_singletons(scored, threshold=1.0)))
    assert (before, after) == (2, 1)


# --- wiring into the detection stack --------------------------------------

@pytest.fixture
def stack_frame(rng=np.random.default_rng(0)) -> pd.DataFrame:
    """Enough rows for the detector to fit, with template ids attached."""
    n = 40
    return pd.DataFrame({
        "timestamp": pd.date_range("2026-07-14 10:00:00", periods=n, freq="90min"),
        "user": ["alice"] * n,
        "source_ip": ["10.0.0.5"] * n,
        "message": ["Accepted password for alice from 10.0.0.5 port 22 ssh2"] * n,
        "template_id": [1, 2] * (n // 2),
        "embedding": [rng.normal(0, 1, 8) for _ in range(n - 2)]
                     + [rng.normal(6, 1, 8) for _ in range(2)],
    })


def test_the_adopted_default_is_pinned():
    """Adopted on the section 4 suite (results/suppression/), not on clean data.

    Pinned so a flip back is a deliberate edit with a failing test attached
    rather than a silent change to what the detector reports. The quantile is
    pinned for the same reason: 0.99 measures *better* on clean corpora and
    costs 13.3pt of `slow` instance detection under camouflage."""
    from logdet import config

    assert config.SEQUENCE_SUPPRESSION is True
    assert config.SEQUENCE_SUPPRESSION_QUANTILE == config.SEQUENCE_RARE_QUANTILE


def test_suppression_needs_a_sequence_model_so_the_batch_locks_are_untouched(stack_frame):
    """This is what keeps the pinned 751 -> 130 -> 94 batch and stream locks
    green with suppression on by default: neither path passes a sequence model,
    so neither can suppress anything."""
    scored = run_anomaly_detection(stack_frame)
    assert "suppressed" not in scored.columns
    assert scored["is_anomaly"].equals(
        run_anomaly_detection(stack_frame, suppress=False)["is_anomaly"])


def test_suppression_can_only_remove_flags_never_add_them(stack_frame):
    model = TransitionModel().fit(stack_frame)
    without = run_anomaly_detection(stack_frame, sequence_model=model)
    with_suppression = run_anomaly_detection(
        stack_frame, sequence_model=model, suppress=True, suppression_threshold=99.0)
    assert (with_suppression["is_anomaly"] <= without["is_anomaly"]).all()


def test_a_suppressed_row_tiers_as_none(stack_frame):
    """Severity is assigned after suppression on purpose: a row that is no
    longer flagged must not keep the tier it had while it was."""
    model = TransitionModel().fit(stack_frame)
    scored = run_anomaly_detection(
        stack_frame, sequence_model=model, suppress=True, suppression_threshold=99.0)
    assert (scored.loc[scored["suppressed"], "severity"] == "none").all()


def test_the_default_threshold_is_the_models_own_rare_boundary(stack_frame):
    """Reused rather than introduced, so it cannot drift from the value the
    severity shift documented."""
    model = TransitionModel().fit(stack_frame)
    assert threshold_for(model) == model.rare_threshold


def test_no_sequence_model_means_no_suppression_however_the_flag_is_set(stack_frame):
    scored = run_anomaly_detection(stack_frame, suppress=True)
    assert "suppressed" not in scored.columns


# --- the evaluation harness must not splice two experiments ----------------

def test_a_checkpoint_written_with_suppression_is_refused_by_a_run_without_it(tmp_path):
    """Suppression changes what the detector flags, so half a run with it and
    half without would produce one reported differential that describes neither
    system. The resume guard already refuses a mismatched ambient ratio; this
    pins that suppression is guarded the same way."""
    import json

    from logdet_eval.killpoint import load_resumable

    partial = tmp_path / "killpoint.partial.json"
    partial.write_text(json.dumps({
        "seeds": 5, "start_seed": 42, "ambient_ratio": 0.05,
        "contamination": 0.2, "suppression": True, "wazuh_available": True,
        "conditions": [{"condition": "baseline"}],
    }))
    settings = {"seeds": 5, "start_seed": 42, "ambient_ratio": 0.05,
                "contamination": 0.2}
    assert load_resumable(partial, {**settings, "suppression": True}) is not None
    assert load_resumable(partial, {**settings, "suppression": False}) is None


# --- guard 2, the graph version: which loneness test ------------------------
#
# Loneness is the safety guard (see the module docstring), so the entity-graph
# versions of it get the same treatment the original got: one test per property
# that would silently change what gets deleted.

def _graph_frame() -> pd.DataFrame:
    """One busy benign entity with a single flagged line, and one flagged line
    whose entity nothing else touches. `incident` calls both lone; the graph
    tests are what separate them."""
    rows = []
    base = pd.Timestamp("2026-07-14 10:00:00")
    for n in range(5):                       # busy host: 4 benign + 1 flagged
        rows.append({"user": "busy", "source_ip": "10.0.0.9",
                     "timestamp": base + pd.Timedelta(minutes=n),
                     "is_anomaly": n == 0})
    rows.append({"user": "onceonly", "source_ip": "203.0.113.7",
                 "timestamp": base + pd.Timedelta(minutes=2), "is_anomaly": True})
    defaults = {"impossible_travel": False, "transition_surprisal": 0.1, "message": "x"}
    return pd.DataFrame([{**defaults, **row} for row in rows])


def test_share_at_zero_is_the_shipped_incident_test():
    """The two are computed by different code -- the grouper's components on the
    flagged rows, and a graph query over the whole frame -- so their agreement
    is asserted rather than assumed. A drift between them would silently change
    which alerts are withdrawn."""
    for scored in (_graph_frame(), frame([{}, {}]), frame([{}, {}, {}])):
        assert list(lone_mask(scored, mode="share", flagged_share=0.0)) == \
               list(lone_flagged_mask(scored))


def test_quiet_excludes_a_line_on_a_busy_but_benign_entity():
    scored = _graph_frame()
    incident = lone_mask(scored, mode="incident")
    quiet = lone_mask(scored, mode="quiet")

    # both flagged lines are alone among the flagged rows
    assert [bool(v) for v in incident] == [True, False, False, False, False, True]
    # only the one nothing else touches is quiet
    assert [bool(v) for v in quiet] == [False, False, False, False, False, True]


def test_a_raised_share_calls_a_corroborated_line_lone():
    """`share` above 0 is the direction that suppresses *more*: a line grouping
    corroborates is still called lone when its entity's traffic is
    overwhelmingly benign. This is what makes it the risky end of the sweep."""
    scored = _graph_frame()
    scored.loc[1, "is_anomaly"] = True      # busy host now has 2 of 5 flagged

    assert not lone_mask(scored, mode="incident").iloc[0]
    assert not lone_mask(scored, mode="share", flagged_share=0.0).iloc[0]
    # one of its four in-window neighbours is flagged: share 0.25
    assert lone_mask(scored, mode="share", flagged_share=0.25).iloc[0]


def test_quiet_is_a_subset_of_incident_which_is_a_subset_of_a_raised_share():
    """The sweep is ordered, and the ordering is what lets a single dial be read
    as safety on one end and selectivity on the other."""
    scored = _graph_frame()
    quiet = lone_mask(scored, mode="quiet")
    incident = lone_mask(scored, mode="incident")
    loose = lone_mask(scored, mode="share", flagged_share=0.75)
    assert (quiet <= incident).all()
    assert (incident <= loose).all()


def test_neighbourhood_counts_see_benign_traffic_union_find_could_not():
    counts = neighbourhood_counts(_graph_frame())
    # the flagged line on the busy host: 4 benign neighbours, none flagged
    assert counts.loc[0, "neighbours"] == 4
    assert counts.loc[0, "flagged_neighbours"] == 0
    # the isolated line shares neither user nor IP with anything
    assert counts.loc[5, "neighbours"] == 0


def test_a_row_without_a_timestamp_is_never_called_lone_by_any_test():
    """The graph cannot see such a row, so it would otherwise score zero
    neighbours -- maximally lone, the opposite of the safe answer."""
    scored = frame([{}, {}])
    scored.loc[0, "timestamp"] = pd.NaT
    for mode in ("incident", "share", "quiet"):
        assert not lone_mask(scored, mode=mode, flagged_share=0.5).iloc[0]


def test_an_unknown_loneness_mode_is_refused():
    with pytest.raises(ValueError, match="unknown loneness mode"):
        lone_mask(frame([{}]), mode="whatever")


def test_the_default_loneness_test_is_pinned():
    """Changing it is a detection change and owes the full section 4 suite, so
    it should be a deliberate edit with a failing test attached."""
    from logdet.config import SUPPRESSION_FLAGGED_SHARE, SUPPRESSION_LONENESS
    assert SUPPRESSION_LONENESS == "incident"
    assert SUPPRESSION_FLAGGED_SHARE == 0.0
