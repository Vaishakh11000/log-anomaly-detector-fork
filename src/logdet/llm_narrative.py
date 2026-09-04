"""
llm_narrative.py
Feeds a grouped anomaly incident (+ its retrieved MITRE technique matches)
to a local LLM (via Ollama) and asks it to produce a plain-English attack
narrative. The prompt is retrieval-grounded: the LLM is given the actual
MITRE matches found via mitre_mapping.py, not asked to invent technique IDs
from scratch.

Grounding the prompt is necessary and was measured insufficient. phi3 invented
a technique ID in 33% of technique mentions on the synthetic corpus and 60% on
OpenSSH while being told in the prompt not to (results/faithfulness/), so two
things changed on 2026-09-04, both measured on both corpora:

  * the **empty-match arm** says that no technique applying is the correct
    answer, instead of leaving instruction 2 asking which stage the incident
    reaches with nothing to answer from. Invention in that arm: 24/24 and
    107/107 before, 0 and 0 after.
  * **structured output** (the default) moves the technique claim into a JSON
    field that `validate_structured` checks against the grounded list, dropping
    any ID the incident was not handed. That is an enforcement rather than an
    instruction, and it reads 0 invented IDs on both corpora.

Requires Ollama running locally: https://ollama.com
    ollama serve
    ollama pull phi3
"""

import json
import re
from dataclasses import dataclass, field as dataclass_field

import pandas as pd
import requests

from logdet.mitre_mapping import map_incident_to_mitre
from logdet.config import (OLLAMA_URL, LLM_MODEL, LLM_TIMEOUT_SECONDS, LLM_NUM_PREDICT,
                    LLM_TEMPERATURE, NARRATIVE_SENTENCE_RANGE, NARRATIVE_MAX_EVENTS,
                    LLM_STRUCTURED_OUTPUT, LLM_TRIAGE_MODEL, LLM_NARRATIVE_MODEL,
                    LLM_TRIAGE_NUM_PREDICT, TRIAGE_SENTENCE_RANGE,
                    TRIAGE_MAX_WORDS)

TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

PROMPT_TEMPLATE = """You are a SOC analyst assistant. Below is a sequence of anomalous log events
from a single incident, along with MITRE ATT&CK techniques that were matched
by a grounded lookup table.

Incident summary:
{summary}

Incident events (chronological):
{events}

Matched MITRE ATT&CK techniques (grounded lookup, do not invent new ones):
{mitre_matches}

Write a concise ({sentences} sentence) narrative explaining:
1. What likely happened, in plain English, in chronological order
{technique_task}
3. A confidence level (Low/Medium/High) and brief justification
4. One recommended next action for the analyst

{technique_rule}
"""

# Two fillings of the same template. The grounded one is byte-identical to the
# text that produced every number in results/faithfulness/, which is what keeps
# the two arms comparable -- and what keeps the ~600-token narration-latency
# baseline in CLAUDE.md section 2c comparable too. A test asserts it.
GROUNDED_TASK = "2. Which MITRE ATT&CK stage(s) this incident progresses through"
GROUNDED_RULE = "Only reference technique IDs listed above. Do not invent new ones."

# The empty-match arm, reworded 2026-09-05. The old fallback line ("No known
# technique matched; treat as a novel/unclassified anomaly") left instruction 2
# standing, so the prompt still *asked* for a stage while handing over nothing
# to name one from -- and phi3 filled the hole every single time it mentioned a
# technique at all: 24/24 invented on the synthetic corpus, 107/107 on OpenSSH
# (results/faithfulness/notes.md). This states that "none applies" is the
# correct answer rather than an absence to be filled.
EMPTY_MATCHES = ("- None. The grounded lookup matched no ATT&CK technique for "
                 "this incident.")
EMPTY_TASK = ("2. That no MITRE ATT&CK technique applies to this incident -- the "
              "grounded\n   lookup matched none, and saying exactly that is the "
              "correct answer")
EMPTY_RULE = ("Cite no technique ID at all. The lookup matched none, so naming any ID "
              "would be an invention rather than an analysis.")

# --- structured output (Stage 5) -------------------------------------------
#
# The prose prompt asks the model not to invent technique IDs and it does it
# anyway -- 33% of technique mentions on the synthetic corpus, 60% on OpenSSH
# (results/faithfulness/). An instruction is not an enforcement mechanism, so
# this arm moves the technique claim out of the prose and into a named field
# that code can check: any ID the incident was not handed is *dropped* before a
# reader ever sees it. The prose fields are still prose and are still capable of
# naming a technique; what changes is that the system's own technique statement
# is no longer the model's to choose.
#
# Ollama's `format: "json"` constrains the decoder to valid JSON, so this does
# not rely on the model remembering to close a brace.
STRUCTURED_TEMPLATE = """You are a SOC analyst assistant. Below is a sequence of anomalous log events
from a single incident, along with MITRE ATT&CK techniques that were matched
by a grounded lookup table.

Incident summary:
{summary}

Incident events (chronological):
{events}

Matched MITRE ATT&CK techniques (grounded lookup):
{mitre_matches}

Reply with JSON only, with exactly these keys:
{{
  "what_happened": "{sentences} sentences, plain English, in chronological order",
  "techniques": [{technique_field}],
  "confidence": "Low" or "Medium" or "High",
  "justification": "why that confidence level, in one sentence",
  "recommended_action": "one next step for the analyst"
}}

{technique_rule}
"""

STRUCTURED_GROUNDED_FIELD = ('"technique IDs copied verbatim from the list above; '
                             '[] if none of them apply"')
STRUCTURED_EMPTY_FIELD = '"leave this empty: [] -- the lookup matched no technique"'

STRUCTURED_GROUNDED_RULE = (
    "Put technique IDs only in the \"techniques\" field, and only ones listed "
    "above.\nAny other ID is discarded before the analyst sees it. Do not name "
    "technique IDs\nin the prose fields.")
STRUCTURED_EMPTY_RULE = (
    "The lookup matched no technique, so \"techniques\" must be [] and saying "
    "that no\nknown technique applies is the correct answer. Do not name a "
    "technique ID in any\nfield -- any ID is discarded before the analyst sees "
    "it.")

STRUCTURED_KEYS = ("what_happened", "techniques", "confidence", "justification",
                   "recommended_action")


@dataclass
class StructuredNarrative:
    """One narrative as the model returned it, after validation.

    `techniques` holds only IDs the incident was actually handed; `dropped`
    holds what the model claimed and did not get. Both are recorded, because a
    silent drop would hide exactly the behaviour this arm exists to measure.
    """

    what_happened: str = ""
    techniques: list[str] = dataclass_field(default_factory=list)
    dropped: list[str] = dataclass_field(default_factory=list)
    confidence: str = ""
    justification: str = ""
    recommended_action: str = ""
    parse_failed: bool = False
    raw: str = ""

    def render(self, grounded: list[dict] | None = None) -> str:
        """The plain-text narrative every existing consumer already reads.

        The technique line is built from the *validated* list joined to the
        incident's own ATT&CK descriptions, so it says what the retrieval says
        rather than what the model said.
        """
        by_id = {t["technique_id"]: t for t in (grounded or [])}
        if self.techniques:
            named = ", ".join(
                f"{tid} ({by_id[tid]['technique_name']})" if tid in by_id else tid
                for tid in self.techniques)
        else:
            named = "none matched by the grounded lookup"

        parts = [self.what_happened.strip()]
        parts.append(f"MITRE ATT&CK: {named}.")
        if self.confidence:
            justification = self.justification.strip()
            parts.append(f"Confidence: {self.confidence}"
                         + (f" -- {justification}" if justification else "."))
        if self.recommended_action.strip():
            parts.append(f"Recommended action: {self.recommended_action.strip()}")
        return "\n\n".join(part for part in parts if part.strip())


def _as_text(value) -> str:
    """Models return a list of sentences about as often as a string."""
    if isinstance(value, list):
        return " ".join(str(item).strip() for item in value if str(item).strip())
    return "" if value is None else str(value).strip()


def validate_structured(payload: dict, grounded_ids) -> StructuredNarrative:
    """Keep the technique IDs the incident was handed; drop the rest.

    This is the enforcement the prose prompt only ever asked for. IDs are
    matched by their bare identifier, because a model that was told to copy
    "T1110" returns "T1110 (Brute Force)" often enough to matter.
    """
    allowed = set(grounded_ids)
    kept, dropped = [], []
    claimed = payload.get("techniques")
    if isinstance(claimed, (str, dict)):
        claimed = [claimed]
    for item in claimed or []:
        for found in TECHNIQUE_ID_RE.findall(str(item)):
            (kept if found in allowed else dropped).append(found)
    # de-duplicate, keeping the order the model gave
    seen: set[str] = set()
    kept = [t for t in kept if not (t in seen or seen.add(t))]
    seen = set()
    dropped = [t for t in dropped if not (t in seen or seen.add(t))]

    return StructuredNarrative(
        what_happened=_as_text(payload.get("what_happened")),
        techniques=kept,
        dropped=dropped,
        confidence=_as_text(payload.get("confidence")),
        justification=_as_text(payload.get("justification")),
        recommended_action=_as_text(payload.get("recommended_action")),
        raw=json.dumps(payload),
    )


def parse_structured(text: str, grounded_ids) -> StructuredNarrative:
    """Parse the model's reply, tolerating the prose it sometimes wraps around
    the JSON. A reply that will not parse at all is recorded as a parse failure
    with its text kept, never quietly turned into an empty narrative."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        try:
            payload = json.loads(text[start:end + 1]) if 0 <= start < end else None
        except json.JSONDecodeError:
            payload = None
    if not isinstance(payload, dict):
        return StructuredNarrative(what_happened=text.strip(), parse_failed=True,
                                   raw=text)
    result = validate_structured(payload, grounded_ids)
    result.raw = text
    return result


def build_structured_prompt(incident_df: pd.DataFrame,
                            context_events: list[dict] | None = None) -> str:
    """The JSON-mode prompt, built from the same blocks as the prose one."""
    events_str, mitre_str = format_incident_for_prompt(incident_df)
    empty = mitre_str == EMPTY_MATCHES
    prompt = STRUCTURED_TEMPLATE.format(
        summary=summarise_incident(incident_df),
        events=events_str,
        mitre_matches=mitre_str,
        sentences=NARRATIVE_SENTENCE_RANGE,
        technique_field=STRUCTURED_EMPTY_FIELD if empty else STRUCTURED_GROUNDED_FIELD,
        technique_rule=STRUCTURED_EMPTY_RULE if empty else STRUCTURED_GROUNDED_RULE,
    )
    context_str = _context_lines(context_events)
    if context_str:
        prompt = prompt.replace(
            "Matched MITRE ATT&CK techniques",
            CONTEXT_BLOCK.format(context=context_str) + "Matched MITRE ATT&CK techniques",
            1)
    return prompt


def generate_structured(incident_df: pd.DataFrame, model: str = LLM_MODEL,
                        context_events: list[dict] | None = None
                        ) -> StructuredNarrative:
    """Narrate one incident as JSON, then drop every technique ID the grounded
    lookup did not hand over."""
    grounded = map_incident_to_mitre(incident_df)
    text = _complete(build_structured_prompt(incident_df, context_events),
                     model=model, json_mode=True)
    return parse_structured(text, {t["technique_id"] for t in grounded})


# Spliced in ahead of the MITRE block, and only when there is evidence to show.
# The prompt is byte-identical to the pre-Stage-4 one when the list is empty,
# which keeps the narration-latency figures in CLAUDE.md section 2c (592 prompt
# tokens on the module's own smoke incident) comparable across this change.
CONTEXT_BLOCK = """Benign events the detector compared those against (evidence, NOT anomalies):
{context}

"""


def _context_lines(context_events: list[dict] | None) -> str:
    """Format retrieved evidence rows for the prompt.

    These are the events an incident was *judged against* -- for impossible
    travel, the user's earlier login from the other subnet. Without them the
    narrative asserts a conclusion whose second half is nowhere in the prompt,
    and phi3 fills the hole by inventing one.
    """
    lines = []
    for event in context_events or []:
        parts = [f"- [{event.get('timestamp', '')}]"]
        user, src = _field(event.get("user")), _field(event.get("source_ip"))
        if user:
            parts.append(f"user={user}")
        if src:
            parts.append(f"src={src}")
        role = _field(event.get("role"))
        parts.append(f": {event.get('message', '')}")
        if role:
            parts.append(f"({role})")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def _field(value) -> str | None:
    """Readable field value, or None when the parser found nothing.

    Missing cells must never reach the prompt as the literal string "nan":
    phi3 treats it as a real value and invents detail around it (an early run
    produced "escalated to root using 'nan'").
    """
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return None if text.lower() in {"", "nan", "none", "unknown"} else text


def summarise_incident(incident_df: pd.DataFrame) -> str:
    """Compact factual header: who, where, when, how many events.

    Enumeration incidents hit a different username on every line, so the
    per-line events alone read as noise -- the LLM needs the aggregate view to
    tell "one attacker probing many accounts" from "many unrelated failures".
    """
    users = sorted({u for u in map(_field, incident_df.get("user", [])) if u})
    ips = sorted({p for p in map(_field, incident_df.get("source_ip", [])) if p})
    times = pd.to_datetime(incident_df["timestamp"])

    lines = [
        f"- {len(incident_df)} anomalous events from {times.min()} to {times.max()}",
        f"- Distinct usernames involved ({len(users)}): {', '.join(users) or 'n/a'}",
        f"- Distinct source IPs ({len(ips)}): {', '.join(ips) or 'n/a'}",
    ]
    if "impossible_travel" in incident_df.columns and incident_df["impossible_travel"].any():
        lines.append("- Flagged by the impossible-travel physics check")
    return "\n".join(lines)


def format_incident_for_prompt(incident_df: pd.DataFrame) -> tuple[str, str]:
    """Return (events_block, mitre_block) for the prompt."""
    shown = incident_df.head(NARRATIVE_MAX_EVENTS)
    event_lines = []
    for _, row in shown.iterrows():
        # omit fields entirely when absent rather than showing a placeholder
        parts = [f"- [{row['timestamp']}]"]
        user, src = _field(row.get("user")), _field(row.get("source_ip"))
        if user:
            parts.append(f"user={user}")
        if src:
            parts.append(f"src={src}")
        parts.append(f": {row['message']}")
        event_lines.append(" ".join(parts))
    events_str = "\n".join(event_lines)
    if len(incident_df) > len(shown):
        events_str += f"\n- ... and {len(incident_df) - len(shown)} further similar events"

    matches = map_incident_to_mitre(incident_df)
    mitre_str = "\n".join(
        f"- {m['technique_id']} ({m['technique_name']}) - {m['tactic']}"
        + (f" [{m['evidence']}]" if "evidence" in m else "")
        for m in matches
    ) or EMPTY_MATCHES

    return events_str, mitre_str


def build_prompt(incident_df: pd.DataFrame,
                 context_events: list[dict] | None = None) -> str:
    """The exact text sent to the model, so a test can assert on it."""
    events_str, mitre_str = format_incident_for_prompt(incident_df)
    empty = mitre_str == EMPTY_MATCHES
    prompt = PROMPT_TEMPLATE.format(
        summary=summarise_incident(incident_df),
        events=events_str,
        mitre_matches=mitre_str,
        sentences=NARRATIVE_SENTENCE_RANGE,
        technique_task=EMPTY_TASK if empty else GROUNDED_TASK,
        technique_rule=EMPTY_RULE if empty else GROUNDED_RULE,
    )
    context_str = _context_lines(context_events)
    if context_str:
        prompt = prompt.replace(
            "Matched MITRE ATT&CK techniques",
            CONTEXT_BLOCK.format(context=context_str) + "Matched MITRE ATT&CK techniques",
            1)
    return prompt


def _complete(prompt: str, model: str = LLM_MODEL, json_mode: bool = False,
              num_predict: int = LLM_NUM_PREDICT) -> str:
    """One Ollama completion. `json_mode` constrains the decoder to valid JSON.

    `num_predict` is the tier knob: the prompt is the same size either way, so
    the generated length is what separates a triage line from a narrative in
    both latency and cost.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": num_predict,
            "temperature": LLM_TEMPERATURE,
        },
    }
    if json_mode:
        payload["format"] = "json"

    response = requests.post(OLLAMA_URL, json=payload, timeout=LLM_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json().get("response", "").strip()


def generate_narrative(incident_df: pd.DataFrame, model: str = LLM_MODEL,
                       context_events: list[dict] | None = None,
                       structured: bool | None = None) -> str:
    """The plain-text narrative every consumer reads.

    With `structured` on it is rendered from a validated JSON reply, so the
    technique line is the grounded list rather than whatever the model named.
    Off, it is the model's prose verbatim -- the arm every number in
    results/faithfulness/ was measured on.
    """
    if LLM_STRUCTURED_OUTPUT if structured is None else structured:
        result = generate_structured(incident_df, model=model,
                                     context_events=context_events)
        return result.render(map_incident_to_mitre(incident_df))
    return _complete(build_prompt(incident_df, context_events), model=model)


# --- triage tier (Stage 5 model routing) ------------------------------------
#
# The full narrative is not the only thing an analyst needs, and it is not
# affordable for every incident: 75 of the synthetic corpus's 94 incidents are
# below the NARRATE_* threshold and carry no prose at all, because narrating
# them costs ~3.9s each on the 4060 and ~18.2s on its CPU. A triage line is the
# cheap tier -- one sentence, capped at LLM_TRIAGE_NUM_PREDICT tokens, so the
# cost is the prompt plus a fraction of the generation.
#
# Technique IDs are removed from the sentence rather than validated in place.
# The full tier can keep them because structured output gives the claim its own
# field; a one-liner has no field, and editing an ID out of the middle of a
# sentence would leave prose the model did not write. So the rule is simpler
# and enforceable: the triage line carries no ID at all, and the incident's
# techniques are the retrieval's to state, exactly as they already are in the
# dashboard and the API.
TRIAGE_TEMPLATE = """You are a SOC analyst assistant. Below is one anomaly incident from a log
detector. An analyst is scanning a list of these and needs a single line.

Incident summary:
{summary}

Incident events (chronological):
{events}

Matched MITRE ATT&CK techniques (grounded lookup):
{mitre_matches}

Write {sentences} sentence of plain English: who did what, from where, and
whether it looks like an attack or like routine activity.{length}

Name no technique IDs. The techniques are shown to the analyst from the
grounded lookup, and any ID written here is removed before it is displayed.
No heading, no bullet points, no preamble -- the sentence only.
"""


@dataclass
class TriageLine:
    """One triage sentence after the technique IDs have been taken out.

    `dropped` records what the model wrote and lost, for the same reason
    `StructuredNarrative.dropped` does: a silent removal would hide the
    behaviour this tier is enforcing against.
    """

    line: str = ""
    dropped: list[str] = dataclass_field(default_factory=list)
    raw: str = ""

    def render(self) -> str:
        return self.line


# An ID with whatever bracket, colon or dash the model wrapped around it, so
# removing "(T1110)" does not leave an empty pair of brackets behind.
_TECHNIQUE_MENTION_RE = re.compile(
    r"\s*[\(\[]?\bT\d{4}(?:\.\d{3})?\b[\)\]]?\s*[:,;-]?")


def strip_technique_ids(text: str) -> tuple[str, list[str]]:
    """Return the text with every technique ID removed, and the IDs removed."""
    found: list[str] = []
    seen: set[str] = set()
    for match in TECHNIQUE_ID_RE.findall(text):
        if match not in seen:
            seen.add(match)
            found.append(match)
    clean = _TECHNIQUE_MENTION_RE.sub(" ", text)
    clean = re.sub(r"\(\s*\)|\[\s*\]", "", clean)
    clean = re.sub(r"\s+([.,;:])", r"\1", clean)
    clean = re.sub(r"[ \t]+", " ", clean).strip()
    return clean, found


def build_triage_prompt(incident_df: pd.DataFrame,
                        context_events: list[dict] | None = None,
                        max_words: int | None = None) -> str:
    """The triage-tier prompt, built from the same blocks as the other two.

    `max_words` adds a length instruction. It exists because the token cap ends
    generation rather than the model ending it, so a sentence the model has not
    finished is cut mid-clause; asking for a shorter one is the alternative to
    paying for a larger cap.
    """
    events_str, mitre_str = format_incident_for_prompt(incident_df)
    words = TRIAGE_MAX_WORDS if max_words is None else max_words
    prompt = TRIAGE_TEMPLATE.format(
        summary=summarise_incident(incident_df),
        events=events_str,
        mitre_matches=mitre_str,
        sentences=TRIAGE_SENTENCE_RANGE,
        length=f" Keep it under {words} words." if words else "",
    )
    context_str = _context_lines(context_events)
    if context_str:
        prompt = prompt.replace(
            "Matched MITRE ATT&CK techniques",
            CONTEXT_BLOCK.format(context=context_str) + "Matched MITRE ATT&CK techniques",
            1)
    return prompt


def generate_triage(incident_df: pd.DataFrame, model: str = LLM_TRIAGE_MODEL,
                    context_events: list[dict] | None = None,
                    num_predict: int = LLM_TRIAGE_NUM_PREDICT,
                    max_words: int | None = None) -> TriageLine:
    """One sentence for the incident list, on the small model."""
    text = _complete(build_triage_prompt(incident_df, context_events,
                                         max_words=max_words),
                     model=model, num_predict=num_predict)
    line, found = strip_technique_ids(text)
    return TriageLine(line=line, dropped=found, raw=text)


def narrate_detail(incident_df: pd.DataFrame, tier: str = "full",
                   context_events: list[dict] | None = None,
                   model: str | None = None) -> tuple[str, list[str]]:
    """Route one incident to a tier: the text a reader sees, and what was cut.

    The second element is every technique ID the model claimed and the
    enforcement removed -- validated away in the full tier, stripped out of the
    sentence in the triage one. It is returned rather than discarded because a
    silent removal is invisible to the person reading the incident, who cannot
    otherwise tell the model tried to cite a technique and was overruled.
    """
    if tier == "triage":
        result = generate_triage(incident_df, model=model or LLM_TRIAGE_MODEL,
                                 context_events=context_events)
        # The triage tier strips *every* ID, grounded ones included, because a
        # one-liner has no field to validate a claim in. So most of what it
        # removes is correct and unremarkable, and reporting that as a rejected
        # claim would cry wolf on every incident the model got right. Only the
        # IDs the lookup did not hand over are worth a reader's attention --
        # which is what `dropped` already means in the full tier.
        grounded = {t["technique_id"] for t in map_incident_to_mitre(incident_df)}
        return result.render(), [t for t in result.dropped if t not in grounded]
    if tier != "full":
        raise ValueError(f"unknown narration tier: {tier!r}")
    model = model or LLM_NARRATIVE_MODEL
    if LLM_STRUCTURED_OUTPUT:
        result = generate_structured(incident_df, model=model,
                                     context_events=context_events)
        return result.render(map_incident_to_mitre(incident_df)), result.dropped
    # Free prose has no enforcement to report: the technique claim is loose in
    # the sentence, which is the arm structured output exists to replace.
    return generate_narrative(incident_df, model=model,
                              context_events=context_events), []


def narrate(incident_df: pd.DataFrame, tier: str = "full",
            context_events: list[dict] | None = None,
            model: str | None = None) -> str:
    """`narrate_detail` without the dropped list, for callers that only render."""
    return narrate_detail(incident_df, tier=tier, context_events=context_events,
                          model=model)[0]


if __name__ == "__main__":
    # smoke test (requires Ollama running locally)
    sample = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 10:02:00",
                                     "2026-07-18 10:10:00", "2026-07-18 10:12:00"]),
        "user": ["alice", "alice", "alice", "alice"],
        "source_ip": ["203.0.113.5"] * 4,
        "impossible_travel": [False] * 4,
        "message": [
            "Failed password for alice from 203.0.113.5 port 51422 ssh2",
            "Failed password for alice from 203.0.113.5 port 51423 ssh2",
            "Accepted password for alice from 203.0.113.5 port 51430 ssh2",
            "sudo: alice : COMMAND=/bin/su root",
        ],
    })
    events, mitre = format_incident_for_prompt(sample)
    print("Grounded techniques passed to the LLM:")
    print(mitre, "\n")
    try:
        print(generate_narrative(sample))
    except requests.exceptions.ConnectionError:
        print("Ollama not running locally -- start it with `ollama serve` and `ollama pull phi3`.")
