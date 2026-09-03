# Three fixes for narrative hallucination, measured

The 2026-09-04 baseline measured a hard constraint failing: phi3 invented MITRE
technique IDs in **33% of technique mentions on the synthetic corpus and 60% on
OpenSSH** (`results/faithfulness/notes.md`). Three changes were built and
measured on both corpora, cheapest first. Two worked; one found nothing to fix,
and *that* is the finding worth reading in it.

Every number below is one run of phi3 at the pipeline's own temperature, all 94
synthetic and all 193 kill-point OpenSSH incidents narrated.

## Headline

| arm | invented IDs, synthetic | OpenSSH | fully faithful, synthetic | OpenSSH |
|---|---|---|---|---|
| prose, original prompt (baseline) | **47 of 142** | **119 of 197** | 57/94 | 94/193 |
| prose, reworded empty-match prompt | 12 of 101 | 6 of 79 | 78/94 | 174/193 |
| **structured JSON, validated** | **0 of 65** | **0 of 58** | **88/94** | **187/193** |

## 1. The empty-match prompt (a wording change, no code path)

The baseline's control arm — incidents the grounded lookup matched nothing for,
which is **41 of 94 synthetic and 150 of 193 OpenSSH incidents**, i.e. the
deployed system's commonest case — invented a technique ID *every single time it
mentioned one*: 24/24 and 107/107.

The prompt was the cause and it is legible in hindsight. The fallback line said
"No known technique matched; treat as a novel/unclassified anomaly", and then
instruction 2 still asked **"Which MITRE ATT&CK stage(s) this incident
progresses through"**. The prompt demanded a stage while handing over nothing to
name one from. The rewording states that no technique applies and that saying so
is the correct answer, and drops the demand:

| arm, control incidents only | invented / mentions, synthetic | OpenSSH |
|---|---|---|
| before | 24 / 24 | 107 / 107 |
| after | **0 / 0** | **0 / 0** |

Zero mentions, not zero inventions: told that "none applies" is the answer, the
model stops naming techniques rather than naming correct ones. Narrative length
is unchanged (median 1261 characters against the baseline's 1287), so this is
not the model refusing to answer — it answers, without inventing.

**The grounded arm's prompt is byte-identical across these two runs**, which
makes it an accidental but useful variance control: it moved 23/118 → 12/101
(synthetic) and 12/90 → 6/79 (OpenSSH) on *identical* input. So a swing of
roughly ten mentions is run-to-run noise at temperature 0.2, and only the
control-arm change is attributable to the rewording. It is a large enough effect
not to need the benefit of the doubt.

## 2. Checking the technique *name*, not just the ID

The baseline notes flagged that "a right ID with a wrong name is a hallucination
that currently passes" — the checker saw `T1567` in the grounded list, or not,
and never read the words beside it. A `technique_name` claim kind now checks a
delimited name cited beside an ID (`T1110 - Brute Force`, `T1021.004 (SSH)`)
against what ATT&CK calls that technique, its sub-technique halves, and its
tactics — the last because the prompt hands the model
`- T1110 (Brute Force) - Credential Access`, so writing "T1110: Credential
Access" restates the prompt rather than inventing.

**It finds nothing, on either corpus:**

| | names checked | wrong |
|---|---|---|
| synthetic | 43 | **0** |
| kill-point OpenSSH | 33 | **0** |

That is not a checker that fails to fire — it is a real property of the failure.
The shipped check only validates names attached to an ID the incident was
**handed**, because the committed ATT&CK index carries just the 11 techniques
this system can emit and there is nothing offline to check a foreign ID's name
against. Measured against the full 54MB bundle instead
(`invented_name_check.py`), names beside an **invented** ID are wrong almost
every time:

| | names checked | wrong |
|---|---|---|
| synthetic | 40 | **39** |
| kill-point OpenSSH | 64 | **61** |

*"T1046: Pass the Hash"* (Network Service Discovery), *"T1078: Port Scan"*
(Valid Accounts), *"T1059: Session Hijacking"* (Command and Scripting
Interpreter). So the invention is **whole-cloth**: phi3 makes up an ID *and* a
name to go with it, rather than mislabelling a technique it was correctly given.
Given a real technique, it names it correctly every time in this sample. The
check stays as a regression guard on a failure mode that does not currently
occur, and it costs nothing to keep.

## 3. Structured JSON output (the fix the baseline pointed at)

The technique claim moves out of the prose and into a named JSON field that
`validate_structured` checks against the incident's grounded list; an ID the
lookup did not hand over is **dropped before rendering**, so a reader never sees
it. Ollama's `format: "json"` constrains the decoder, so this does not depend on
the model remembering to close a brace.

| | synthetic | OpenSSH |
|---|---|---|
| Invented technique IDs | **0 of 65** | **0 of 58** |
| Technique IDs dropped by validation | 1 (`T1148`) | 0 |
| Replies that would not parse as JSON | **0** | **0** |
| Invented IPs | 0 of 50 | 0 of 128 |
| Invented usernames | 0 of 81 | 0 of 27 |
| Fabricated incident-summary blocks | **0** | 0 |
| Fully faithful narratives | 88/94 | 187/193 |

Three things about that table are worth stating plainly rather than banking.

**The denominator changed, so read the numerator.** The rendered narrative
carries a `MITRE ATT&CK: T1110 (Brute Force)` line built from the *grounded*
list, so those mentions are grounded by construction and the 65 and 58 are not
the same population as the baseline's 142 and 197. The number that matters is
that **no invented ID survives anywhere in the text** — including the prose
fields, which are still prose and still free to name a technique. Counted
directly, technique IDs appearing outside the rendered line are 4 on synthetic
(all grounded) and 0 on OpenSSH.

**Validation almost never had to fire.** One drop in 287 narratives. Told to put
IDs in a field and that other IDs are discarded, the model mostly complies —
which means most of the gain here is the same effect as fix 1 (a clearer task),
not the enforcement catching a determined hallucinator. The enforcement's value
is that it is an *enforcement*: it does not depend on that compliance holding for
a different model, a different corpus, or a longer prompt.

**The fabricated incident-summary block is gone.** The baseline's worst failure
was seven narratives emitting a fake summary in the system's own voice
("Incident summary: - 10 anomalous events from ... Distinct source IPs (2):").
The rewording cut it to two; a fixed output schema leaves nowhere to put it.

### What it costs

**Brevity.** A rendered narrative is ~546 characters against prose's ~1287:
answering in JSON, phi3 writes one or two sentences where it wrote four, despite
the schema asking for 4-6. The rendered form covers all four requested items
(what happened, techniques, confidence with justification, recommended action),
but it reads as a structured briefing rather than a story. Whether that is a
cost or an improvement is a judgement about the audience, not a measurement, and
it is the one thing here that was not measured.

**It is faster**, incidentally: median 2.0s against 3.4s per incident on the
4060, because the output is shorter.

**A dropped ID is invisible to the reader.** It is recorded in the harness and
in `StructuredNarrative.dropped`, but nothing surfaces it in the dashboard or
the API. Nobody looking at an incident can tell the model tried to cite a
technique and was overruled.

## What this still does not measure

Everything the baseline could not, unchanged: this checks the *entities* a
narrative names, not the story it tells about them. A structured narrative that
grounds every ID, IP, user and count can still assert a wrong causal order or an
unjustified confidence level. Judging that needs a human or an LLM judge, and an
LLM judge would put an unmeasured model inside the measurement.

One model, one temperature, one run per arm. The grounded-arm variance measured
above (~10 mentions) is the scale at which small differences here mean nothing.

## Reproducing

```bash
uv run logdet-faithfulness --output results/faithfulness/arms/empty_prompt
uv run logdet-faithfulness --structured --output results/faithfulness/arms/structured
uv run logdet-faithfulness --structured --input data/processed/killpoint/parsed.csv \
     --output results/faithfulness/arms/structured/killpoint
uv run python results/faithfulness/invented_name_check.py   # needs the 54MB bundle
```

The baseline arm is `results/faithfulness/` and was generated before the prompt
rewording; it cannot be reproduced at HEAD, which is why its narratives are
committed. `--rescore` re-checks any saved run without calling the model.
