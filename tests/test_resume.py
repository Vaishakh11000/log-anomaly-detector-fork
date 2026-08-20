"""Tests for resuming a kill-point run from its checkpoint.

Checkpoints were written for three runs before anything could read them, so a
crash at condition 8 of 9 still cost the whole run. What matters here is not
that resume works but that it *refuses* to work when the checkpoint belongs to
a different experiment -- splicing two runs together and reporting them as one
would be a worse outcome than losing the compute.
"""

import json

import pytest

from logdet_eval.killpoint import RESUME_KEYS, load_resumable


SETTINGS = {"seeds": 5, "start_seed": 42, "ambient_ratio": 0.05,
            "contamination": 0.15}


def write(tmp_path, payload: dict):
    path = tmp_path / "run.partial.json"
    path.write_text(json.dumps(payload))
    return path


def partial(**overrides) -> dict:
    base = {**SETTINGS, "wazuh_available": True,
            "conditions": [{"condition": "baseline"}, {"condition": "rephrase"}]}
    base.update(overrides)
    return base


class TestAccepts:
    def test_returns_completed_conditions(self, tmp_path):
        got = load_resumable(write(tmp_path, partial()), SETTINGS)
        assert [c["condition"] for c in got] == ["baseline", "rephrase"]

    def test_missing_checkpoint_is_not_an_error(self, tmp_path):
        assert load_resumable(tmp_path / "absent.json", SETTINGS) is None

    def test_empty_condition_list_starts_fresh(self, tmp_path):
        assert load_resumable(write(tmp_path, partial(conditions=[])), SETTINGS) is None

    def test_keys_absent_from_the_checkpoint_are_not_treated_as_mismatches(self, tmp_path):
        """The paced runner records extra knobs the batch one does not; a batch
        checkpoint must not be rejected merely for lacking them."""
        stored = partial()
        settings = {**SETTINGS, "max_events_per_ip": 12}
        assert load_resumable(write(tmp_path, stored), settings) is not None


class TestRefuses:
    @pytest.mark.parametrize("key,value", [
        ("seeds", 3),
        ("start_seed", 99),
        ("ambient_ratio", 0.2),
        ("contamination", 0.10),
    ])
    def test_any_parameter_mismatch_starts_fresh(self, tmp_path, key, value):
        path = write(tmp_path, partial(**{key: value}))
        assert load_resumable(path, SETTINGS) is None

    def test_checkpoint_written_without_wazuh_is_refused(self, tmp_path):
        """A detector-only checkpoint has no SIEM column, so resuming onto it
        would silently produce a run with no differential."""
        path = write(tmp_path, partial(wazuh_available=False))
        assert load_resumable(path, SETTINGS) is None

    def test_corrupt_checkpoint_starts_fresh_rather_than_raising(self, tmp_path):
        path = tmp_path / "run.partial.json"
        path.write_text("{not json")
        assert load_resumable(path, SETTINGS) is None

    def test_every_guarded_key_is_actually_checked(self, tmp_path):
        """Guard against a key being added to RESUME_KEYS but never compared."""
        for key in RESUME_KEYS:
            if key not in SETTINGS:
                continue
            sentinel = "different"
            path = write(tmp_path, partial(**{key: sentinel}))
            assert load_resumable(path, SETTINGS) is None, key
