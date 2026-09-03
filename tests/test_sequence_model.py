"""
The Stage 3 transition model over mined template ids.

The load-bearing test here is the last one: enabling the sequence model must
not move `is_anomaly`. Every number CLAUDE.md section 4 asks for is derived
from that column, so if it holds, turning the model on cannot change line-level
P/R/F1, instance detection clean or camouflaged, or the incident count.
"""

import json

import numpy as np
import pandas as pd
import pytest

from logdet.anomaly_detection import assign_severity, run_anomaly_detection
from logdet.sequence_model import TransitionModel, vocabulary_fingerprint


def sequence(user: str, ip: str | None, template_ids: list[int],
             start: str = "2026-07-14 10:00:00") -> pd.DataFrame:
    """One actor emitting templates in order, one minute apart."""
    stamps = pd.date_range(start, periods=len(template_ids), freq="1min")
    return pd.DataFrame({
        "timestamp": stamps,
        "user": [user] * len(template_ids),
        "source_ip": [ip] * len(template_ids),
        "template_id": template_ids,
    })


@pytest.fixture
def routine_history() -> pd.DataFrame:
    """alice does 1 -> 2 -> 1 -> 2 ... forever, and never anything else."""
    return sequence("alice", "10.0.0.5", [1, 2] * 20)


# --- what the model learns ---

def test_a_routine_transition_is_less_surprising_than_an_unseen_one(routine_history):
    model = TransitionModel().fit(routine_history)
    routine = model.transition_surprisal(1, 2, "user", "alice")
    unseen = model.transition_surprisal(1, 1, "user", "alice")
    assert routine < unseen


def test_first_event_of_a_sequence_has_no_surprisal(routine_history):
    model = TransitionModel().fit(routine_history)
    scored = model.surprisal(sequence("alice", "10.0.0.5", [1, 2]))
    assert pd.isna(scored.iloc[0])
    assert not pd.isna(scored.iloc[1])


def test_an_unknown_template_is_neutral_not_suspicious(routine_history):
    """Novel wording mines a new cluster. Reporting that as maximal surprisal
    would rebuild the signature brittleness `rephrase` camouflage exploits --
    the one robustness win this project has."""
    model = TransitionModel().fit(routine_history)
    scored = model.surprisal(sequence("alice", "10.0.0.5", [1, 99]))
    assert pd.isna(scored.iloc[1])
    assert model.unknown_rate(sequence("alice", "10.0.0.5", [1, 99])) == 0.5


def test_an_unseen_actor_backs_off_to_the_global_table(routine_history):
    """A brand-new user is a cold start, not an attacker. Without the backoff
    every first-seen actor would score as maximally surprising."""
    model = TransitionModel().fit(routine_history)
    known = model.surprisal(sequence("alice", "10.0.0.5", [1, 2])).iloc[1]
    stranger = model.surprisal(sequence("carol", "10.0.9.9", [1, 2])).iloc[1]
    assert stranger == pytest.approx(known, abs=0.5)


def test_rows_with_no_usable_key_are_skipped():
    """"unknown" is the parser reporting no user, not a user -- threading every
    unattributed line into one pseudo-actor invents transitions nobody made."""
    history = sequence("unknown", None, [1, 2] * 10)
    model = TransitionModel().fit(history)
    assert model.surprisal(history).isna().all()


def test_the_first_key_that_can_score_a_row_keeps_it():
    """The user key is the stronger one (AUC 0.958 against source IP's 0.758 on
    the kill-point corpus), so precedence is what the module promises: a later
    key fills silence and never overrules. Pinned because "take the more
    surprising of the two" is the tempting alternative and it quietly changes
    which key decides a row."""
    history = pd.concat([
        sequence("alice", "10.0.0.5", [1, 2] * 20),
        sequence("bob", "10.0.0.9", [3, 4] * 20, start="2026-07-15 10:00:00"),
    ], ignore_index=True)
    model = TransitionModel().fit(history)

    probe = sequence("alice", "10.0.0.9", [1, 2], start="2026-07-16 10:00:00")
    user_only = TransitionModel(keys=("user",)).fit(history).surprisal(probe).iloc[1]
    assert model.surprisal(probe).iloc[1] == pytest.approx(user_only)


def test_the_second_key_fills_rows_the_first_cannot():
    """Account enumeration varies the username on every line, so there is no
    per-user sequence at all -- without the fallback the model is silent on
    exactly the attack shape it should have most to say about."""
    history = sequence("alice", "10.0.0.5", [1, 2] * 20)
    model = TransitionModel().fit(history)

    # A different username on every line, one source IP throughout.
    probe = sequence("alice", "10.0.0.5", [1, 2])
    probe["user"] = ["root", "admin"]
    scored = model.surprisal(probe)
    assert not pd.isna(scored.iloc[1])
    assert pd.isna(TransitionModel(keys=("user",)).fit(history).surprisal(probe).iloc[1])


# --- calibration ---

def test_thresholds_are_read_off_the_fit_corpus(routine_history):
    model = TransitionModel().fit(routine_history)
    assert model.routine_threshold is not None
    assert model.rare_threshold >= model.routine_threshold


def test_fitting_without_a_template_id_column_is_refused():
    with pytest.raises(ValueError, match="drain3"):
        TransitionModel().fit(pd.DataFrame({"user": ["alice"], "timestamp": [pd.Timestamp("2026-07-14")]}))


# --- persistence ---

def test_round_trip_preserves_scores(tmp_path, routine_history):
    model = TransitionModel().fit(routine_history)
    path = tmp_path / "sequence.json"
    model.save(path)
    restored = TransitionModel.load(path, expect_fingerprint=model.fingerprint)

    probe = sequence("alice", "10.0.0.5", [1, 2, 1])
    pd.testing.assert_series_equal(model.surprisal(probe), restored.surprisal(probe))
    assert restored.routine_threshold == model.routine_threshold


def test_a_foreign_vocabulary_is_refused(tmp_path, routine_history):
    """Cluster ids are only meaningful relative to the miner that assigned
    them. Loading against a differently-numbered miner would look up every
    transition under the wrong template and return plausible nonsense."""
    model = TransitionModel().fit(routine_history)
    path = tmp_path / "sequence.json"
    model.save(path)
    with pytest.raises(ValueError, match="vocabulary"):
        TransitionModel.load(path, expect_fingerprint="0000000000000000")


def test_a_stale_format_is_refused(tmp_path, routine_history):
    path = tmp_path / "sequence.json"
    TransitionModel().fit(routine_history).save(path)
    payload = json.loads(path.read_text())
    payload["format_version"] = 999
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="format"):
        TransitionModel.load(path)


def test_an_unfitted_model_will_not_save(tmp_path):
    with pytest.raises(RuntimeError, match="unfitted"):
        TransitionModel().save(tmp_path / "sequence.json")


def test_fingerprint_ignores_order():
    assert vocabulary_fingerprint([3, 1, 2]) == vocabulary_fingerprint([1, 2, 3])


# --- severity coupling ---

def severity_frame(surprisals: list[float]) -> pd.DataFrame:
    return pd.DataFrame({
        "is_anomaly": [True] * len(surprisals),
        # -0.10 negated puts every row in the "medium" band on its own
        "anomaly_score": [-0.10] * len(surprisals),
        "transition_surprisal": surprisals,
    })


def test_a_routine_transition_demotes_and_a_rare_one_promotes():
    frame = severity_frame([0.1, 1.0, 9.0])
    tiered = assign_severity(frame, surprisal_col="transition_surprisal",
                             routine_threshold=0.5, rare_threshold=5.0)
    assert list(tiered["severity"]) == ["low", "medium", "high"]


def test_silence_leaves_the_tier_alone():
    frame = severity_frame([np.nan])
    tiered = assign_severity(frame, surprisal_col="transition_surprisal",
                             routine_threshold=0.5, rare_threshold=5.0)
    assert tiered["severity"].iloc[0] == "medium"


def test_severity_never_leaves_the_flagged_range():
    """"none" means not flagged. A tier shift is not allowed to change what was
    flagged, in either direction."""
    frame = severity_frame([0.0, 0.0])
    frame["anomaly_score"] = [-0.01, -0.01]     # already the lowest tier
    tiered = assign_severity(frame, surprisal_col="transition_surprisal",
                             routine_threshold=0.5, rare_threshold=5.0)
    assert list(tiered["severity"]) == ["low", "low"]

    unflagged = pd.DataFrame({"is_anomaly": [False], "anomaly_score": [0.4],
                              "transition_surprisal": [99.0]})
    assert assign_severity(unflagged, surprisal_col="transition_surprisal",
                           routine_threshold=0.5, rare_threshold=5.0
                           )["severity"].iloc[0] == "none"


def test_impossible_travel_still_overrides_a_demotion():
    frame = severity_frame([0.0])
    frame["impossible_travel"] = [True]
    tiered = assign_severity(frame, surprisal_col="transition_surprisal",
                             routine_threshold=0.5, rare_threshold=5.0)
    assert tiered["severity"].iloc[0] == "high"


def test_thresholds_absent_means_no_shift():
    frame = severity_frame([0.0, 99.0])
    tiered = assign_severity(frame, surprisal_col="transition_surprisal")
    assert list(tiered["severity"]) == ["medium", "medium"]


# --- the section 4 no-op ---

def test_enabling_the_sequence_model_does_not_move_is_anomaly(rng):
    """Every number section 4 asks for is derived from `is_anomaly`. If this
    holds, the sequence model cannot change line-level P/R/F1, instance
    detection clean or camouflaged, or the incident count -- so it lands
    without owing a camouflage re-run."""
    frame = pd.DataFrame({
        "user": ["alice"] * 20 + ["bob"] * 20,
        "source_ip": ["10.0.0.5"] * 20 + ["10.0.0.9"] * 20,
        "timestamp": pd.date_range("2026-07-14 10:00:00", periods=40, freq="1min"),
        "template_id": ([1, 2] * 10) + ([3, 4] * 10),
        "embedding": [rng.normal(0, 1, 384) for _ in range(38)]
                     + [rng.normal(8, 1, 384) for _ in range(2)],
        "message": ["Accepted password for alice from 10.0.0.5 port 22 ssh2"] * 40,
    })
    model = TransitionModel().fit(frame)

    without = run_anomaly_detection(frame)
    with_model = run_anomaly_detection(frame, sequence_model=model)

    pd.testing.assert_series_equal(without["is_anomaly"], with_model["is_anomaly"])
    pd.testing.assert_series_equal(without["ml_anomaly"], with_model["ml_anomaly"])
    pd.testing.assert_series_equal(without["impossible_travel"], with_model["impossible_travel"])
    assert "transition_surprisal" in with_model.columns
    assert "transition_surprisal" not in without.columns


# --- how detection actually consumes it ---

def test_severity_coupling_is_off_by_default(rng):
    """Measured against ground truth, shifting the tier makes the queue worse
    at every threshold tried (results/sequence/sequence_separation.md), so a
    caller that passes a model gets the surprisal column and the triage
    tiebreaker -- not a re-tiering."""
    frame = pd.DataFrame({
        "user": ["alice"] * 20 + ["bob"] * 20,
        "source_ip": ["10.0.0.5"] * 20 + ["10.0.0.9"] * 20,
        "timestamp": pd.date_range("2026-07-14 10:00:00", periods=40, freq="1min"),
        "template_id": ([1, 2] * 10) + ([3, 4] * 10),
        "embedding": [rng.normal(0, 1, 384) for _ in range(38)]
                     + [rng.normal(8, 1, 384) for _ in range(2)],
        "message": ["Accepted password for alice from 10.0.0.5 port 22 ssh2"] * 40,
    })
    model = TransitionModel().fit(frame)

    without = run_anomaly_detection(frame)
    default = run_anomaly_detection(frame, sequence_model=model)
    shifted = run_anomaly_detection(frame, sequence_model=model, adjust_severity=True)

    pd.testing.assert_series_equal(without["severity"], default["severity"])
    assert "transition_surprisal" in default.columns
    assert not shifted["severity"].equals(without["severity"])


def test_surprisal_breaks_a_triage_tie():
    """Two incidents alike on event count and severity: the more surprising
    template transition is worked first."""
    from logdet.triage import triage_key
    dull = {"event_count": 2, "severity": "medium", "max_transition_surprisal": 0.2}
    sharp = {"event_count": 2, "severity": "medium", "max_transition_surprisal": 3.9}
    assert triage_key(sharp) > triage_key(dull)


def test_an_incident_with_no_surprisal_ranks_as_it_did_before():
    """The streaming path emits no surprisal, and a missing field must not
    reorder anything -- event count and severity still decide."""
    from logdet.triage import triage_key
    big = {"event_count": 5, "severity": "low"}
    small = {"event_count": 2, "severity": "high", "max_transition_surprisal": 9.9}
    assert triage_key(big) > triage_key(small)
    assert triage_key({"event_count": 1, "severity": "low"}) == (1, 1, 0.0)
