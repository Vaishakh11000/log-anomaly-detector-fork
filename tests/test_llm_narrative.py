"""
Tests for the narrative prompt (Stage 5).

Two things are pinned here, both because breaking them is silent. The grounded
arm's wording is byte-identical to the text every number in
`results/faithfulness/` was measured on, so a change to it invalidates the
comparison between arms rather than failing. And the empty-match arm must
actually say that no technique applies -- the whole point of the 2026-09-05
rewording, which was measured against 24/24 and 107/107 invention in the arm
before it.
"""

import pandas as pd
import pytest

from logdet import llm_narrative
from logdet.config import (LLM_NARRATIVE_MODEL, LLM_TRIAGE_MODEL,
                           LLM_TRIAGE_NUM_PREDICT)

from logdet.llm_narrative import (
    EMPTY_MATCHES,
    build_prompt,
    build_triage_prompt,
    format_incident_for_prompt,
    strip_technique_ids,
)


def _incident(message: str) -> pd.DataFrame:
    return pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00"]),
        "user": ["alice"],
        "source_ip": ["203.0.113.5"],
        "impossible_travel": [False],
        "message": [message],
    })


MATCHED = _incident("Failed password for alice from 203.0.113.5 port 51422 ssh2")
UNMATCHED = _incident("kernel: usb 1-2: device descriptor read error")


def test_a_matched_incident_still_gets_the_original_wording():
    """Byte-for-byte, because the grounded arm is the comparison baseline."""
    prompt = build_prompt(MATCHED)
    assert "2. Which MITRE ATT&CK stage(s) this incident progresses through" in prompt
    assert "Only reference technique IDs listed above. Do not invent new ones." in prompt
    assert EMPTY_MATCHES not in prompt


def test_an_unmatched_incident_is_told_that_none_applies_is_the_answer():
    prompt = build_prompt(UNMATCHED)
    assert EMPTY_MATCHES in prompt
    assert "saying exactly that is the correct answer" in prompt
    assert "Cite no technique ID at all." in prompt


def test_the_unmatched_arm_never_asks_which_stage_it_progresses_through():
    """The defect the rewording fixed: instruction 2 demanded a stage while the
    lookup handed over nothing to name one from, and phi3 filled the hole every
    time it mentioned a technique at all."""
    prompt = build_prompt(UNMATCHED)
    assert "Which MITRE ATT&CK stage(s)" not in prompt
    assert "Do not invent new ones." not in prompt


@pytest.mark.parametrize("incident", [MATCHED, UNMATCHED])
def test_both_arms_still_carry_the_four_numbered_tasks(incident):
    prompt = build_prompt(incident)
    for number in ("1.", "2.", "3.", "4."):
        assert f"\n{number}" in prompt


def test_the_fallback_block_is_the_one_the_prompt_switches_on():
    """`build_prompt` picks the arm by comparing against EMPTY_MATCHES, so the
    two must not drift apart."""
    _, mitre = format_incident_for_prompt(UNMATCHED)
    assert mitre == EMPTY_MATCHES
    _, matched = format_incident_for_prompt(MATCHED)
    assert matched != EMPTY_MATCHES


# --- structured output (Stage 5) -------------------------------------------

from logdet.llm_narrative import (  # noqa: E402
    build_structured_prompt,
    parse_structured,
    validate_structured,
)

GROUNDED = [{"technique_id": "T1110", "technique_name": "Brute Force"}]


def test_an_id_the_incident_was_not_handed_is_dropped_not_printed():
    """The enforcement the prose prompt only ever asked for."""
    result = validate_structured(
        {"techniques": ["T1110", "T1567"], "what_happened": "x"}, {"T1110"})
    assert result.techniques == ["T1110"]
    assert result.dropped == ["T1567"]
    assert "T1567" not in result.render(GROUNDED)


def test_an_id_returned_with_its_name_attached_still_matches():
    """A model told to copy "T1110" returns "T1110 (Brute Force)" often enough
    to matter, and a literal comparison would drop a grounded technique."""
    result = validate_structured({"techniques": ["T1110 (Brute Force)"]}, {"T1110"})
    assert result.techniques == ["T1110"]
    assert result.dropped == []


def test_every_claimed_id_can_be_dropped_leaving_an_honest_empty_line():
    result = validate_structured({"techniques": ["T1059", "T1078"]}, set())
    assert result.techniques == []
    assert result.dropped == ["T1059", "T1078"]
    assert "none matched by the grounded lookup" in result.render([])


def test_the_rendered_technique_line_uses_attack_names_not_the_models():
    result = validate_structured({"techniques": ["T1110"], "what_happened": "x"},
                                 {"T1110"})
    assert "T1110 (Brute Force)" in result.render(GROUNDED)


def test_a_reply_wrapped_in_prose_still_parses():
    text = 'Here is the JSON:\n{"what_happened": "x", "techniques": ["T1110"]}\nDone.'
    result = parse_structured(text, {"T1110"})
    assert not result.parse_failed
    assert result.techniques == ["T1110"]


def test_an_unparseable_reply_is_recorded_not_silently_emptied():
    result = parse_structured("the model just wrote prose", {"T1110"})
    assert result.parse_failed
    assert "the model just wrote prose" in result.render(GROUNDED)


def test_a_list_valued_prose_field_is_flattened():
    result = validate_structured(
        {"what_happened": ["First this.", "Then that."], "techniques": []}, set())
    assert result.what_happened == "First this. Then that."


def test_duplicate_claims_are_counted_once():
    result = validate_structured({"techniques": ["T1110", "T1110", "T9999", "T9999"]},
                                 {"T1110"})
    assert result.techniques == ["T1110"]
    assert result.dropped == ["T9999"]


def test_the_structured_prompt_keeps_both_technique_arms():
    grounded = build_structured_prompt(MATCHED)
    assert "copied verbatim from the list above" in grounded
    assert '"techniques"' in grounded

    empty = build_structured_prompt(UNMATCHED)
    assert "leave this empty" in empty
    assert "the correct answer" in empty


def test_structured_output_is_the_default_and_the_flip_is_deliberate():
    """Pinned, like SUPPRESSION_LONENESS and the suppression default: turning
    this off restores prose narratives that invent technique IDs, so it must be
    an edit with a failing test attached rather than a quiet change."""
    from logdet.config import LLM_STRUCTURED_OUTPUT
    assert LLM_STRUCTURED_OUTPUT is True


# --- triage tier (Stage 5 model routing) ------------------------------------
#
# The tier's whole enforcement is that a technique ID cannot reach a triage
# line, so these tests plant one and assert it does not survive.

def test_a_triage_line_carries_no_technique_id_even_a_grounded_one():
    """The one-liner has no field for a technique claim, so it makes none --
    the incident's techniques are the retrieval's to state beside it."""
    clean, dropped = strip_technique_ids(
        "Repeated failed logins for alice from 203.0.113.5, consistent with "
        "T1110 (Brute Force).")
    assert "T1110" not in clean
    assert dropped == ["T1110"]


def test_an_invented_id_in_a_triage_line_is_recorded_not_silently_lost():
    clean, dropped = strip_technique_ids("Looks like T1047 and T1207 activity.")
    assert dropped == ["T1047", "T1207"]
    assert "T" not in clean.replace("Looks", "")


def test_stripping_an_id_leaves_no_empty_brackets_behind():
    clean, _ = strip_technique_ids("Brute force (T1110). Scanning [T1046] seen.")
    assert "()" not in clean and "[]" not in clean
    assert clean == "Brute force. Scanning seen."


def test_a_line_with_no_technique_id_is_returned_untouched():
    text = "One failed sudo attempt for bob from 10.0.0.4; looks routine."
    assert strip_technique_ids(text) == (text, [])


def test_the_triage_prompt_forbids_ids_and_asks_for_one_sentence():
    prompt = build_triage_prompt(MATCHED)
    assert "Name no technique IDs" in prompt
    assert "removed before it is displayed" in prompt
    # the same blocks as the other two tiers, so the arms stay comparable
    assert "Incident events (chronological):" in prompt
    assert "Matched MITRE ATT&CK techniques" in prompt


def test_the_triage_prompt_is_shorter_than_the_full_one():
    """The prompt is nearly the same size; the saving is the generation cap.
    Pinned so a future edit cannot quietly make the cheap tier the expensive
    one."""
    assert len(build_triage_prompt(MATCHED)) < len(build_prompt(MATCHED)) * 1.2


def test_narrate_routes_to_the_tier_it_is_given(monkeypatch):
    seen = {}

    def fake_complete(prompt, model="m", json_mode=False, num_predict=0):
        seen.update(model=model, num_predict=num_predict, json_mode=json_mode)
        return "Failed logins for alice from 203.0.113.5."

    monkeypatch.setattr(llm_narrative, "_complete", fake_complete)
    text = llm_narrative.narrate(MATCHED, tier="triage")
    assert text == "Failed logins for alice from 203.0.113.5."
    assert seen["num_predict"] == LLM_TRIAGE_NUM_PREDICT
    assert seen["model"] == LLM_TRIAGE_MODEL
    assert seen["json_mode"] is False


def test_narrate_refuses_an_unknown_tier():
    with pytest.raises(ValueError):
        llm_narrative.narrate(MATCHED, tier="medium")


def test_both_tiers_default_to_one_model_until_a_second_is_measured():
    """Routing is a token-budget split first. Pointing the full tier at a
    larger model is a config edit made on measured evidence, not a default."""
    from logdet.config import LLM_MODEL
    assert LLM_TRIAGE_MODEL == LLM_MODEL
    assert LLM_NARRATIVE_MODEL == LLM_MODEL


# --- what the enforcement removed, surfaced to the reader --------------------
#
# A dropped ID was recorded in the dataclasses and nowhere else, so an incident
# where the model tried to cite a technique read exactly like one where it did
# not. These pin the meaning the dashboard and the API now display: the field
# holds the IDs the *grounded lookup did not hand over*, in either tier.

def test_narrate_detail_reports_an_id_the_full_tier_validated_away(monkeypatch):
    monkeypatch.setattr(
        llm_narrative, "_complete",
        lambda *a, **k: '{"what_happened": "Repeated failures.", '
                        '"techniques": ["T1110", "T1047"]}')
    text, dropped = llm_narrative.narrate_detail(MATCHED, tier="full")
    assert dropped == ["T1047"]          # T1110 is grounded for this incident
    assert "T1047" not in text


def test_a_grounded_id_stripped_from_a_triage_line_is_not_reported(monkeypatch):
    """The triage tier strips every ID, so most removals are of correct ones.
    Reporting those as rejected claims would cry wolf on every incident the
    model got right."""
    monkeypatch.setattr(
        llm_narrative, "_complete",
        lambda *a, **k: "Repeated failed logins for alice, consistent with T1110.")
    text, dropped = llm_narrative.narrate_detail(MATCHED, tier="triage")
    assert "T1110" not in text
    assert dropped == []


def test_an_invented_id_in_a_triage_line_is_reported(monkeypatch):
    monkeypatch.setattr(
        llm_narrative, "_complete",
        lambda *a, **k: "Looks like T1047 activity for alice.")
    _, dropped = llm_narrative.narrate_detail(MATCHED, tier="triage")
    assert dropped == ["T1047"]


def test_narrate_still_returns_only_text():
    """Existing callers render a string; the detail form is additive."""
    assert llm_narrative.narrate.__doc__


def test_the_triage_cap_is_the_swept_value_not_the_first_one_tried():
    """80 cut 19% of lines mid-sentence, 120 cuts 1% for 5% more wall clock
    (results/routing/cap_sweep/). Lowering it back is a deliberate edit."""
    assert LLM_TRIAGE_NUM_PREDICT == 120


def test_the_word_limit_is_off_because_it_measured_worse():
    """Measured alternative to raising the cap: it truncates about as little
    but shortens the line and scored below the token-capped arms."""
    from logdet.config import TRIAGE_MAX_WORDS
    assert TRIAGE_MAX_WORDS is None


def test_a_word_limit_reaches_the_prompt_only_when_asked_for():
    assert "words" not in build_triage_prompt(MATCHED)
    assert "under 25 words" in build_triage_prompt(MATCHED, max_words=25)
