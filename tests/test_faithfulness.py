"""
Tests for the narrative faithfulness checker (Stage 5).

The checker exists to test a claim -- "the LLM never invents MITRE technique
IDs" -- so these tests test the checker with narratives whose faithfulness is
known by construction. A checker that passes everything would report a perfect
score and mean nothing, so most of these assert that a *planted* hallucination
is caught.
"""

import pytest

from logdet_eval.faithfulness import (
    Check,
    check_narrative,
    derivable_counts,
    extract_claims,
    render,
    tally,
)

PROMPT = """You are a SOC analyst assistant.

Incident summary:
- 4 anomalous events from 2026-07-18 10:00:00 to 2026-07-18 10:12:00
- Distinct usernames involved (1): alice
- Distinct source IPs (1): 203.0.113.5

Incident events (chronological):
- [2026-07-18 10:00:00] user=alice src=203.0.113.5 : Failed password for alice
- [2026-07-18 10:12:00] user=alice src=203.0.113.5 : sudo: alice : COMMAND=/bin/su root

Matched MITRE ATT&CK techniques (grounded lookup, do not invent new ones):
- T1110 (Brute Force) - Credential Access
"""

ENTRY = {
    "incident_id": 7,
    "event_count": 4,
    "users": ["alice"],
    "source_ips": ["203.0.113.5"],
    "mitre_techniques": [{"technique_id": "T1110"}],
    "context_events": [],
}

CONTROL_ENTRY = dict(ENTRY, incident_id=8, mitre_techniques=[])


# --- extraction ------------------------------------------------------------

def test_extracts_technique_ids_including_sub_techniques():
    claims = extract_claims("This maps to T1110 and T1021.004 specifically.")
    values = {c.value for c in claims if c.kind == "technique"}
    assert values == {"T1110", "T1021.004"}


def test_extracts_ip_user_time_and_quantity():
    text = ("At 10:00:00 the user alice failed 12 login attempts "
            "from 203.0.113.5.")
    kinds = {}
    for claim in extract_claims(text, user_vocabulary={"alice"}):
        kinds.setdefault(claim.kind, set()).add(claim.value)
    assert kinds["ip"] == {"203.0.113.5"}
    assert kinds["user"] == {"alice"}
    assert kinds["time"] == {"10:00:00"}
    assert kinds["quantity"] == {"12"}


def test_clock_inside_a_full_timestamp_is_not_counted_twice():
    claims = [c for c in extract_claims("seen at 2026-07-18 10:00:00 only")
              if c.kind == "time"]
    assert len(claims) == 1
    assert claims[0].value == "2026-07-18 10:00:00"


def test_common_words_after_user_are_not_username_claims():
    """The rule that replaced the stopword list, measured failing on the first
    three real narratives: prose puts English words in username position
    constantly ("the user attempted", "account discovery"). Unquoted words
    that are not usernames in the corpus are not claims about a user."""
    text = ("An unauthorized user attempted access and account discovery "
            "followed, with one username per failed attempt.")
    assert [c for c in extract_claims(text, user_vocabulary={"alice"})
            if c.kind == "user"] == []


def test_quoted_name_is_a_username_claim_even_outside_the_vocabulary():
    claims = [c for c in extract_claims("the account 'mallory' was used",
                                        user_vocabulary={"alice"})
              if c.kind == "user"]
    assert [c.value for c in claims] == ["mallory"]


def test_real_corpus_username_is_a_claim_without_quotes():
    """The dangerous case: the narrative attributes the incident to a real
    account that was not in it."""
    claims = [c for c in extract_claims("the user bob escalated",
                                        user_vocabulary={"alice", "bob"})
              if c.kind == "user"]
    assert [c.value for c in claims] == ["bob"]


def test_spelled_out_quantities_are_normalised_to_digits():
    claims = [c for c in extract_claims("three failed logins") if c.kind == "quantity"]
    assert [c.value for c in claims] == ["3"]


# --- grounding: the constraint under test ----------------------------------

def test_grounded_technique_passes():
    check = check_narrative("Consistent with T1110 brute forcing.", PROMPT, ENTRY)
    assert check.faithful


def test_invented_technique_is_caught_even_when_another_was_handed():
    check = check_narrative(
        "This shows T1110 followed by T1078 valid-account abuse.", PROMPT, ENTRY)
    assert not check.faithful
    assert [c.value for c in check.ungrounded] == ["T1078"]


def test_any_technique_in_the_control_arm_is_ungrounded():
    """An incident matched no technique, so its prompt lists none. Naming one
    is invention by definition -- this is the control arm the report splits on."""
    check = check_narrative("Likely T1046 network service discovery.",
                            PROMPT, CONTROL_ENTRY)
    assert not check.grounded_arm
    assert [c.value for c in check.ungrounded] == ["T1046"]


def test_technique_present_in_prompt_text_but_not_handed_is_still_ungrounded():
    """The technique check is against the incident's matched list, not against
    the prompt string, so a stray ID elsewhere in the prompt cannot launder
    an invention."""
    prompt = PROMPT + "\n(earlier unrelated note mentioning T1078)\n"
    check = check_narrative("Attributed to T1078.", prompt, ENTRY)
    assert [c.value for c in check.ungrounded] == ["T1078"]


# --- grounding: the other claim kinds --------------------------------------

def test_invented_ip_is_caught():
    check = check_narrative("Traffic came from 198.51.100.9.", PROMPT, ENTRY)
    assert [c.value for c in check.ungrounded] == ["198.51.100.9"]


def test_user_from_another_incident_is_caught_and_this_incidents_user_passes():
    vocabulary = {"alice", "bob"}
    assert check_narrative("The user alice was targeted.", PROMPT, ENTRY,
                           vocabulary).faithful
    bad = check_narrative("The user bob was targeted.", PROMPT, ENTRY, vocabulary)
    assert [c.value for c in bad.ungrounded] == ["bob"]


def test_quoted_invented_user_is_caught_with_no_vocabulary_at_all():
    bad = check_narrative("The account 'mallory' was used.", PROMPT, ENTRY)
    assert [c.value for c in bad.ungrounded] == ["mallory"]


def test_invented_time_is_caught():
    check = check_narrative("It began at 03:17:00.", PROMPT, ENTRY)
    assert [c.value for c in check.ungrounded] == ["03:17:00"]


def test_quantity_derivable_from_the_incident_passes():
    # 4 is the event count and 1 the number of distinct users; neither digit
    # is printed as a bare number the model could have copied blindly.
    assert "4" in derivable_counts(ENTRY) and "1" in derivable_counts(ENTRY)
    assert check_narrative("There were 4 events from 1 user.", PROMPT, ENTRY).faithful


def test_inflated_quantity_is_caught():
    check = check_narrative("There were 400 failed attempts.", PROMPT, ENTRY)
    assert [c.value for c in check.ungrounded] == ["400"]


def test_nan_is_always_ungrounded():
    """The v1 hallucination: "escalated to root using 'nan'". A literal `nan`
    is never a legitimate thing for a narrative to say, so it fails even if
    the string somehow reached the prompt."""
    check = check_narrative("Escalated using 'nan'.", PROMPT + "\nnan\n", ENTRY)
    assert [c.kind for c in check.ungrounded] == ["placeholder"]


def test_a_fully_grounded_narrative_is_faithful():
    narrative = ("Between 2026-07-18 10:00:00 and 2026-07-18 10:12:00 the user "
                 "alice was targeted from 203.0.113.5 across 4 events, "
                 "consistent with T1110. Confidence: Medium.")
    check = check_narrative(narrative, PROMPT, ENTRY)
    assert check.faithful, [c.value for c in check.ungrounded]


# --- reporting -------------------------------------------------------------

def _check(incident_id: int, grounded: bool, narrative: str) -> Check:
    entry = dict(ENTRY if grounded else CONTROL_ENTRY, incident_id=incident_id)
    return check_narrative(narrative, PROMPT, entry)


def test_tally_splits_by_arm_and_counts_inventions():
    checks = [
        _check(1, True, "Consistent with T1110."),
        _check(2, True, "T1110 and also T1078."),
        _check(3, False, "Likely T1046."),
    ]
    counts = tally(checks)
    assert counts["narratives"] == 3 and counts["faithful"] == 1
    assert counts["by_kind"]["technique"]["claims"] == 4
    assert counts["by_kind"]["technique"]["ungrounded"] == 2
    assert counts["arms"]["grounded"]["narratives"] == 2
    assert counts["arms"]["no_technique"]["by_kind"]["technique"]["ungrounded"] == 1


def test_report_renders_headline_and_failures():
    text = render([_check(1, True, "T1110 and T1078 from 198.51.100.9.")],
                  model="phi3", corpus="corpus.csv")
    assert "Invented technique IDs" in text
    assert "T1078" in text and "198.51.100.9" in text
    assert "What this does not measure" in text


def test_report_renders_with_no_narratives():
    assert "Invented technique IDs" in render([], model="phi3", corpus="c.csv")


@pytest.mark.parametrize("value", ["T1110", "T1021.004"])
def test_technique_regex_requires_the_full_shape(value):
    assert [c.value for c in extract_claims(f"see {value} here")
            if c.kind == "technique"] == [value]
    assert [c for c in extract_claims("T11 and T123456 and XT1110")
            if c.kind == "technique"] == []


# --- clock formats: the false-positive class the first full run exposed ------

def test_meridiem_times_map_to_the_24_hour_form():
    from logdet_eval.faithfulness import time_variants
    assert "13:38" in time_variants("1:38 PM")
    assert "07:53" in time_variants("7:53 AM")
    assert "00:15" in time_variants("12:15 AM")
    assert "12:15" in time_variants("12:15 PM")


def test_am_pm_restatement_of_a_log_time_is_grounded():
    """phi3 routinely rewrites 13:38 as "1:38 PM". That is a correct
    restatement of the prompt, and calling it a hallucination was measured
    inflating this claim kind to a 57% ungrounded rate."""
    prompt = PROMPT.replace("10:12:00", "13:38:00")
    check = check_narrative("Escalation occurred at 1:38 PM.", prompt, ENTRY)
    assert check.faithful, [c.value for c in check.ungrounded]


def test_a_genuinely_invented_meridiem_time_is_still_caught():
    check = check_narrative("It began at 4:20 PM.", PROMPT, ENTRY)
    assert [c.value for c in check.ungrounded] == ["4:20 PM"]


def test_bare_hour_with_a_meridiem_is_not_a_quantity():
    claims = extract_claims("at precisely 2 PM involving user activity")
    assert [c for c in claims if c.kind == "quantity"] == []
