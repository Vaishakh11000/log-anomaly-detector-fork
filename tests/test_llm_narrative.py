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

from logdet.llm_narrative import (
    EMPTY_MATCHES,
    build_prompt,
    format_incident_for_prompt,
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
