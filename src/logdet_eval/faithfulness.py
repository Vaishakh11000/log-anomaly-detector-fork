"""
faithfulness.py
Does the narrative only say things the prompt actually contained?

Stage 5 opens with the one claim this project makes that has never been
measured. CLAUDE.md section 2 states it as a hard constraint -- *"the LLM never
invents MITRE technique IDs"* -- and section 8 lists letting it do so as an
anti-goal. The architecture that is supposed to enforce it is real (the
techniques come from `mitre_mapping`, the prompt says "Only reference technique
IDs listed above"), but until now the evidence for it holding was that nobody
had seen it break since the v1 `"nan"` incident. That is not a measurement.

What this measures
------------------

Every narrative is checked against **the exact prompt that produced it**. A
claim is *grounded* when the thing it names appears in that prompt, and
*ungrounded* otherwise. Five classes of claim are extractable deterministically,
so no LLM judge is involved and the checker cannot drift:

  ``technique``   a MITRE ID (T1110, T1021.004). Grounded only if it is in the
                  incident's own matched-technique list -- the strictest check
                  here, because it is the constraint being tested.
  ``ip``          an IPv4 address.
  ``user``        a name in a username-claim position ("user alice",
                  "account 'root'") that is either quoted or is a username the
                  corpus actually contains -- see the note above
                  ``USER_CLAIM_RE`` for why ordinary prose forces that.
  ``time``        a date or clock time.
  ``quantity``    a count attached to a counted noun ("12 failed attempts"),
                  grounded if the number is in the prompt or is a count the
                  incident actually has (events, distinct users, distinct IPs).

Plus one hard-coded regression: the literal token ``nan`` must never appear.
That is the v1 hallucination (an early run produced *"escalated to root using
'nan'"*), and `llm_narrative._field` exists to prevent it reaching the prompt.

The control arm is free, and it is the real system
--------------------------------------------------

41 of the synthetic corpus's 94 incidents match no technique at all, so their
prompt carries the fallback line *"No known technique matched"* while still
saying "do not invent new ones". Those are not a synthetic ablation -- they are
what the deployed system sends for 44% of its incidents, and **any technique ID
in one of their narratives is invented by definition**. The report splits every
figure by that arm, because a 0% hallucination rate over incidents that were all
handed techniques would not distinguish "the grounding works" from "the model
copies whatever it is given".

What this does NOT measure
--------------------------

It checks the *entities* a narrative names, not the story it tells about them.
A narrative that grounds every ID, IP, user and count can still assert a wrong
causal sequence, an unjustified confidence level, or a recommendation the
evidence does not support. Judging that needs either a human or an LLM judge,
and an LLM judge would put an unmeasured model inside the measurement. This is
the floor -- necessary, not sufficient -- and it is reported as such.

Usage:
    uv run logdet-faithfulness                      # synthetic corpus, all incidents
    uv run logdet-faithfulness --limit 20           # quick pass while iterating
    uv run logdet-faithfulness --input data/processed/killpoint/parsed.csv \
        --output results/faithfulness/killpoint
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from logdet.anomaly_detection import run_anomaly_detection
from logdet.config import LLM_MODEL, PROCESSED_DATA_DIR, RESULTS_DIR
from logdet.embedding import add_embeddings_to_df
from logdet.entity_graph import normalise_identity
from logdet.llm_narrative import build_prompt, generate_narrative
from logdet.pipeline import build_incident_entry, should_narrate
from logdet.sequence_grouping import group_anomalies

# --- claim extraction ------------------------------------------------------

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DATETIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?\b")
# The meridiem is captured, not ignored: phi3 routinely rewrites a 24-hour log
# timestamp as "1:38 PM", which is a correct restatement of 13:38 and not an
# invention. Measured on the first full run, that one habit accounted for most
# of a 57% ungrounded rate on this claim kind.
CLOCK_RE = re.compile(
    r"(?<![\w.:])(?P<h>\d{1,2}):(?P<m>\d{2})(?::(?P<s>\d{2}))?"
    r"(?:\s*(?P<mer>[AaPp]\.[Mm]\.|[AaPp][Mm]))?(?![\d:])")
NAN_RE = re.compile(r"(?<![\w.])nan(?![\w.])", re.IGNORECASE)

# A name only counts as a username *claim* when it sits in a position that
# asserts one. "the user attempted" is not a claim about a user called
# "attempted", which is what the stopword list is for.
# The leading `(?<![\w-])` is load-bearing: without it "valid-account abuse"
# reads as a claim about a user called "abuse".
USER_CLAIM_RE = re.compile(
    r"(?<![\w-])(?:user(?:name)?|account|logged in as|login as)\s+"
    r"(?P<open>['\"`]?)(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{1,31})(?P=open)",
    re.IGNORECASE)

# A username claim is only counted when the name is *plausibly a username*,
# because ordinary SOC prose puts English words in username position all the
# time -- "the user attempted", "account discovery", "one username per failed
# attempt". A stopword list does not scale against that and was measured
# failing on the first three real narratives. Two signals are used instead,
# and both are properties of the text rather than of a word list:
#
#   - the narrative **quoted** the name (`user 'bob'`), which is an explicit
#     assertion that this token is an identifier, or
#   - the token is a username **the corpus actually contains** somewhere else.
#     That is the dangerous hallucination -- attributing an incident to a real
#     account that was not in it -- and an English word can only trip it by
#     also being a username in the log.
#
# What this misses is a wholly invented, unquoted name that appears nowhere in
# the corpus. That is a deliberate precision-over-recall trade: a user check
# with false positives pollutes every other figure in the report.

COUNTED_NOUNS = (
    "attempts?|logins?|log-ins?|failures?|failed|events?|lines?|times|"
    "users?|usernames?|accounts?|addresses|ips?|hosts?|sources?|"
    "minutes?|hours?|seconds?|days?|techniques?|incidents?"
)
WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}
# `(?<![\w:.\-])` keeps the trailing "00" of a timestamp out: without it
# "10:00:00 the user" parses as a claim of "00 users".
# The negative lookahead for a meridiem keeps clock times out: "at precisely
# 2 PM involving user carol" is a time, not a claim of two users.
QUANTITY_RE = re.compile(
    r"(?<![\w:.\-])(?P<n>\d{1,6}|" + "|".join(WORD_NUMBERS) + r")"
    r"(?!\s*[AaPp]\.?[Mm]\.?\b)\s+"
    r"(?:[A-Za-z-]+\s+){0,2}?"
    r"(?P<noun>" + COUNTED_NOUNS + r")\b",
    re.IGNORECASE)


@dataclass(frozen=True)
class Claim:
    """One extractable assertion in a narrative."""
    kind: str
    value: str
    quote: str


@dataclass
class Check:
    """The result of checking one narrative against its own prompt."""
    incident_id: int
    grounded_arm: bool          # was this incident handed any technique at all?
    claims: list[Claim] = field(default_factory=list)
    ungrounded: list[Claim] = field(default_factory=list)
    narrative: str = ""
    seconds: float = 0.0

    @property
    def faithful(self) -> bool:
        return not self.ungrounded


def extract_claims(narrative: str,
                   user_vocabulary: set[str] | None = None) -> list[Claim]:
    """Every deterministically checkable assertion in a narrative.

    `user_vocabulary` is every username the corpus contains. See the note
    above USER_CLAIM_RE for why a username claim needs it or a quote.
    """
    claims: list[Claim] = []

    def add(kind: str, value: str, match: re.Match) -> None:
        start, end = max(0, match.start() - 30), match.end() + 30
        claims.append(Claim(kind, value, narrative[start:end].strip().replace("\n", " ")))

    for match in TECHNIQUE_RE.finditer(narrative):
        add("technique", match.group(0), match)
    for match in IPV4_RE.finditer(narrative):
        add("ip", match.group(0), match)

    # Dates first, so the clock inside "2026-07-18 10:00" is not re-extracted
    # on its own and counted twice.
    consumed: list[tuple[int, int]] = []
    for match in DATETIME_RE.finditer(narrative):
        add("time", match.group(0), match)
        consumed.append((match.start(), match.end()))
    for match in CLOCK_RE.finditer(narrative):
        if any(start <= match.start() < end for start, end in consumed):
            continue
        add("time", match.group(0).strip(), match)

    vocabulary = {u.lower() for u in (user_vocabulary or ())}
    for match in USER_CLAIM_RE.finditer(narrative):
        name = match.group("name")
        quoted = bool(match.group("open"))
        if not quoted and name.lower() not in vocabulary:
            continue
        add("user", name, match)

    for match in QUANTITY_RE.finditer(narrative):
        raw = match.group("n").lower()
        add("quantity", str(WORD_NUMBERS.get(raw, raw)), match)

    for match in NAN_RE.finditer(narrative):
        add("placeholder", match.group(0), match)

    return claims


# --- grounding -------------------------------------------------------------

def time_variants(value: str) -> list[str]:
    """Every spelling of a clock time that means the same instant.

    A narrative saying "1:38 PM" about a 13:38 log line is restating the
    prompt, not inventing a time, and a checker that calls that a
    hallucination reports a number nobody can act on.
    """
    forms = [value]
    match = CLOCK_RE.fullmatch(value.strip())
    if match is None:
        return forms
    hour, minute = int(match.group("h")), match.group("m")
    seconds = match.group("s")
    meridiem = (match.group("mer") or "").lower().replace(".", "")
    if meridiem:
        hour = hour % 12 + (12 if meridiem.startswith("p") else 0)
    stem = f"{hour:02d}:{minute}"
    forms.append(stem)
    forms.append(f"{stem}:{seconds}" if seconds else f"{stem}:00")
    return forms


def _prompt_contains(prompt: str, value: str) -> bool:
    """Literal, case-insensitive, whole-token containment."""
    return re.search(r"(?<![\w.])" + re.escape(value) + r"(?![\w.])",
                     prompt, re.IGNORECASE) is not None


def derivable_counts(entry: dict) -> set[str]:
    """Numbers the incident genuinely has, beyond those printed in the prompt.

    The prompt says "4 anomalous events" in words the model can copy, but it
    can also legitimately say "two source IPs" by counting the list it was
    shown, so those counts are grounded even though the digit is absent.
    """
    return {
        str(entry["event_count"]),
        str(len(entry["users"])),
        str(len(entry["source_ips"])),
        str(len(entry["mitre_techniques"])),
        str(len(entry.get("context_events") or [])),
    }


def check_narrative(narrative: str, prompt: str, entry: dict,
                    user_vocabulary: set[str] | None = None) -> Check:
    """Which claims in this narrative are not in the prompt that produced it."""
    grounded_ids = {t["technique_id"] for t in entry.get("mitre_techniques", [])}
    counts = derivable_counts(entry)
    check = Check(incident_id=entry["incident_id"],
                  grounded_arm=bool(grounded_ids),
                  narrative=narrative)

    for claim in extract_claims(narrative, user_vocabulary):
        if claim.kind == "technique":
            # The strict one: not "was it anywhere in the prompt" but "was it
            # in the list this incident was actually handed".
            ok = claim.value in grounded_ids
        elif claim.kind == "placeholder":
            ok = False          # `nan` is never a legitimate thing to say
        elif claim.kind == "quantity":
            ok = claim.value in counts or _prompt_contains(prompt, claim.value)
        elif claim.kind == "time":
            ok = any(_prompt_contains(prompt, form)
                     for form in time_variants(claim.value))
        else:
            ok = _prompt_contains(prompt, claim.value)

        check.claims.append(claim)
        if not ok:
            check.ungrounded.append(claim)

    return check


# --- running ---------------------------------------------------------------

def score_and_group(input_csv: str
                    ) -> tuple[list[pd.DataFrame], list[dict], set[str]]:
    """The pipeline's own detection and grouping, so prompts are byte-exact.

    Reconstructing an incident from `incidents.json` would be cheaper and
    slightly wrong -- the JSON drops `impossible_travel`, which changes one
    line of the prompt summary -- and a faithfulness checker run against a
    prompt the system never sent measures nothing.
    """
    frame = pd.read_csv(input_csv, parse_dates=["timestamp"])
    frame = add_embeddings_to_df(frame, template_col="template")
    scored = run_anomaly_detection(frame)
    incidents = group_anomalies(scored)
    entries = [build_incident_entry(i, inc, context=scored)
               for i, inc in enumerate(incidents)]
    # Every username the corpus contains, flagged or not -- the plausibility
    # vocabulary the user check needs.
    vocabulary = {str(u) for u in scored["user"].dropna().unique()
                  if normalise_identity(u)}
    return incidents, entries, vocabulary


def run(input_csv: str, model: str = LLM_MODEL, limit: int | None = None,
        narrate_all: bool = True) -> list[Check]:
    """Narrate, then check each narrative against the prompt that produced it."""
    incidents, entries, vocabulary = score_and_group(input_csv)
    targets = [e for e in entries
               if narrate_all or should_narrate(e["severity"], e["event_count"])]
    if limit is not None:
        targets = targets[:limit]

    print(f"{len(entries)} incidents, narrating {len(targets)} with {model}")
    checks: list[Check] = []
    for n, entry in enumerate(targets, start=1):
        incident = incidents[entry["incident_id"]]
        prompt = build_prompt(incident, context_events=entry["context_events"])
        started = time.time()
        try:
            narrative = generate_narrative(incident, model=model,
                                           context_events=entry["context_events"])
        except Exception as error:                      # noqa: BLE001
            print(f"  [{n}/{len(targets)}] incident {entry['incident_id']}: "
                  f"generation failed: {error}")
            continue
        check = check_narrative(narrative, prompt, entry, vocabulary)
        check.seconds = time.time() - started
        checks.append(check)
        flag = "" if check.faithful else f"  <- {len(check.ungrounded)} ungrounded"
        print(f"  [{n}/{len(targets)}] incident {entry['incident_id']} "
              f"({'grounded' if check.grounded_arm else 'no-technique'}, "
              f"{len(check.claims)} claims, {check.seconds:.1f}s){flag}", flush=True)
    return checks


def rescore(input_csv: str, saved_json: str) -> list[Check]:
    """Re-check narratives already on disk, without calling the model again.

    The narratives are the expensive part and the checker is the part that
    changes, so a fix to an extraction rule should not cost another 94
    generations -- and re-generating would also change the narratives under
    the fix, making the before/after uncomparable.
    """
    payload = json.loads(Path(saved_json).read_text())
    narratives = {c["incident_id"]: c["narrative"] for c in payload["checks"]}
    incidents, entries, vocabulary = score_and_group(input_csv)

    checks = []
    for entry in entries:
        narrative = narratives.get(entry["incident_id"])
        if narrative is None:
            continue
        prompt = build_prompt(incidents[entry["incident_id"]],
                              context_events=entry["context_events"])
        check = check_narrative(narrative, prompt, entry, vocabulary)
        check.seconds = next((c["seconds"] for c in payload["checks"]
                              if c["incident_id"] == entry["incident_id"]), 0.0)
        checks.append(check)
    print(f"Re-scored {len(checks)} saved narratives from {saved_json}")
    return checks


# --- reporting -------------------------------------------------------------

CLAIM_KINDS = ("technique", "ip", "user", "time", "quantity", "placeholder")


def tally(checks: list[Check]) -> dict:
    """Counts per claim kind and per arm. Rates are recomputed from counts."""
    def kind_counts(subset: list[Check]) -> dict[str, dict[str, int]]:
        out = {}
        for kind in CLAIM_KINDS:
            total = sum(1 for c in subset for cl in c.claims if cl.kind == kind)
            bad = sum(1 for c in subset for cl in c.ungrounded if cl.kind == kind)
            out[kind] = {"claims": total, "ungrounded": bad}
        return out

    grounded = [c for c in checks if c.grounded_arm]
    ungrounded_arm = [c for c in checks if not c.grounded_arm]
    return {
        "narratives": len(checks),
        "faithful": sum(1 for c in checks if c.faithful),
        "by_kind": kind_counts(checks),
        "arms": {
            "grounded": {"narratives": len(grounded),
                         "faithful": sum(1 for c in grounded if c.faithful),
                         "by_kind": kind_counts(grounded)},
            "no_technique": {"narratives": len(ungrounded_arm),
                             "faithful": sum(1 for c in ungrounded_arm if c.faithful),
                             "by_kind": kind_counts(ungrounded_arm)},
        },
        "median_seconds": (sorted(c.seconds for c in checks)[len(checks) // 2]
                           if checks else 0.0),
    }


def _rate(bad: int, total: int) -> str:
    return "n/a" if total == 0 else f"{bad / total:.1%} ({bad}/{total})"


def render(checks: list[Check], model: str, corpus: str) -> str:
    counts = tally(checks)
    lines = [
        "# Narrative faithfulness",
        "",
        f"Corpus: `{corpus}` | model: `{model}` | "
        f"{counts['narratives']} narratives | "
        f"median {counts['median_seconds']:.1f}s each",
        "",
        "A claim is **grounded** when the thing it names is in the exact prompt",
        "that produced the narrative. Technique IDs are checked against the",
        "incident's own matched list, not against the prompt text, because that",
        "is the constraint under test.",
        "",
        "## Headline",
        "",
        f"- Narratives with no ungrounded claim: "
        f"**{counts['faithful']}/{counts['narratives']}**",
        f"- **Invented technique IDs: "
        f"{counts['by_kind']['technique']['ungrounded']}** of "
        f"{counts['by_kind']['technique']['claims']} technique mentions",
        "",
        "## By claim kind",
        "",
        "| kind | claims made | ungrounded | rate |",
        "|---|---|---|---|",
    ]
    for kind in CLAIM_KINDS:
        row = counts["by_kind"][kind]
        lines.append(f"| `{kind}` | {row['claims']} | {row['ungrounded']} | "
                     f"{_rate(row['ungrounded'], row['claims'])} |")

    lines += [
        "",
        "## By arm",
        "",
        "The `no-technique` arm is the control and it is not synthetic: those",
        "incidents matched nothing, so their prompt carries the *\"No known",
        "technique matched\"* fallback and **any** technique ID in their",
        "narrative is invented by definition.",
        "",
        "| arm | narratives | fully faithful | technique mentions | invented |",
        "|---|---|---|---|---|",
    ]
    for name, label in (("grounded", "handed >=1 technique"),
                        ("no_technique", "handed none (control)")):
        arm = counts["arms"][name]
        tech = arm["by_kind"]["technique"]
        lines.append(f"| {label} | {arm['narratives']} | "
                     f"{arm['faithful']}/{arm['narratives']} | {tech['claims']} | "
                     f"**{tech['ungrounded']}** |")

    failures = [c for c in checks if not c.faithful]
    lines += ["", "## Ungrounded claims", ""]
    if not failures:
        lines.append("None.")
    else:
        lines.append("| incident | arm | kind | claimed | in the narrative |")
        lines.append("|---|---|---|---|---|")
        for check in failures:
            for claim in check.ungrounded:
                quote = claim.quote.replace("|", "\\|")
                lines.append(
                    f"| {check.incident_id} | "
                    f"{'grounded' if check.grounded_arm else 'control'} | "
                    f"`{claim.kind}` | `{claim.value}` | ...{quote}... |")

    lines += [
        "",
        "## What this does not measure",
        "",
        "Entity groundedness is a floor, not a proof of correctness. A",
        "narrative can name only real IDs, IPs, users and counts and still tell",
        "the wrong story about them -- a causal order the log does not support,",
        "a confidence level nothing justifies, a recommended action the",
        "evidence does not warrant. Judging that needs a human or an LLM judge,",
        "and an LLM judge would put an unmeasured model inside the",
        "measurement.",
        "",
        f"Generated by `logdet-faithfulness`. Model `{model}` at the pipeline's",
        "own temperature, so numbers move a little run to run; the technique",
        "column is the one that is supposed to be exactly zero.",
        "",
    ]
    return "\n".join(lines)


def write_report(checks: list[Check], output_dir: str, model: str,
                 corpus: str) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "faithfulness.md").write_text(render(checks, model, corpus))
    payload = {
        "corpus": corpus,
        "model": model,
        "summary": tally(checks),
        "checks": [
            {"incident_id": c.incident_id, "grounded_arm": c.grounded_arm,
             "seconds": round(c.seconds, 2), "faithful": c.faithful,
             "claims": [claim.__dict__ for claim in c.claims],
             "ungrounded": [claim.__dict__ for claim in c.ungrounded],
             "narrative": c.narrative}
            for c in checks
        ],
    }
    (directory / "faithfulness.json").write_text(json.dumps(payload, indent=2))
    print(f"Wrote {directory / 'faithfulness.md'}")


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Check narratives against the prompts that produced them.")
    parser.add_argument("--input", default=f"{PROCESSED_DATA_DIR}/parsed.csv")
    parser.add_argument("--output", default=f"{RESULTS_DIR}/faithfulness")
    parser.add_argument("--model", default=LLM_MODEL)
    parser.add_argument("--limit", type=int, default=None,
                        help="narrate only the first N incidents")
    parser.add_argument("--rescore", metavar="FAITHFULNESS_JSON",
                        help="re-check narratives already saved by an earlier "
                             "run instead of generating new ones")
    parser.add_argument("--narrate-policy", action="store_true",
                        help="narrate only what the pipeline would narrate "
                             "(default: every incident, for a wider sample)")
    args = parser.parse_args()

    if args.rescore:
        checks = rescore(args.input, args.rescore)
    else:
        checks = run(args.input, model=args.model, limit=args.limit,
                     narrate_all=not args.narrate_policy)
    write_report(checks, args.output, args.model, args.input)


if __name__ == "__main__":
    cli()
