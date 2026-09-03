# Reading the faithfulness measurement

Two corpora, phi3, every incident narrated, each narrative checked against the
exact prompt that produced it.

| | synthetic (94 incidents) | kill-point OpenSSH (193) |
|---|---|---|
| Narratives with no ungrounded claim | 57/94 | 94/193 |
| **Technique mentions** | 142 | 197 |
| **...invented** | **47 (33.1%)** | **119 (60.4%)** |
| IP claims / invented | 61 / 1 | 193 / 5 |
| user claims / invented | 51 / 0 | 22 / 1 |
| time claims / invented | 74 / 8 | 142 / 34 |
| quantity claims / invented | 36 / 4 | 62 / 7 |
| `nan` leaks | **0** | **0** |

## The headline: a hard constraint is false as written

CLAUDE.md §2 states *"The LLM never invents MITRE technique IDs"*. Measured, it
does — **47 times on the synthetic corpus and 119 times on OpenSSH**, in 33 of
94 and 87 of 193 narratives respectively.

The precise version of what is true and what is not matters here, because the
design decision behind the constraint is sound and the sentence describing it
is not:

- **True: the retrieval is grounded.** Every technique the system *reports* —
  `mitre_techniques`, the kill chain, the dashboard, the coverage matrix —
  comes from `mitre_mapping` and the pinned ATT&CK index. No LLM chooses those,
  and `attack.py` refuses IDs ATT&CK has revoked or deprecated.
- **False: that the prose obeys it.** The prompt says *"Only reference technique
  IDs listed above. Do not invent new ones."* An instruction is not an
  enforcement mechanism, and a 3.8B model does not treat it as one.

So the anti-hallucination architecture protects the **structured** output and
leaves the **narrative text** unprotected. Until now that gap was invisible
because nothing read the narrative back.

## Where the invention concentrates, and why that is the useful part

Split by arm, the two corpora say the same thing:

| arm | synthetic invented / mentions | OpenSSH invented / mentions |
|---|---|---|
| handed ≥1 technique | 23 / 118 (19%) | 12 / 90 (13%) |
| handed none (control) | **24 / 24 (100%)** | **107 / 107 (100%)** |

The control arm is not a synthetic ablation — it is the deployed system. 41 of
94 synthetic incidents and **150 of 193** OpenSSH incidents match no technique,
so their prompt carries the *"No known technique matched; treat as a
novel/unclassified anomaly"* fallback, and every technique ID in their narrative
is invented by definition.

**Grounding helps and does not suffice.** Handed a technique list, phi3 mostly
stays inside it (13-19% extra). Handed nothing, it fills the hole every time it
mentions a technique at all. The failure is worst exactly where the detector has
least to say, which is the opposite of what a reader would want.

## What it invents

All 24 distinct invented IDs on the synthetic corpus are **real ATT&CK
identifiers**, checked against the pinned 19.2 bundle — none are fabricated
strings. That makes them harder to spot, not easier:

- **6 of 24 are revoked or deprecated** in ATT&CK 19.2 — T1206 (Sudo Caching),
  T1058, T1503, T1109, T1209 revoked, T1108 deprecated. `attack.py`'s index
  builder refuses exactly these; the model emits them freely.
- Several are **impossible on an sshd auth log** — T1047 (Windows Management
  Instrumentation), T1207 (Rogue Domain Controller), T1538 (Cloud Service
  Dashboard).
- The **names are frequently wrong too**: narratives contain *"T1567 - Failed
  Authentication"* (T1567 is Exfiltration Over Web Service) and *"T1055:
  Initial Access"* (T1055 is Process Injection). A reader who checks the ID
  against ATT&CK finds a real page saying something else.

## Three narratives fabricate an entire incident summary

The most striking failures are not technique IDs. On synthetic incidents 7, 22
and 42, and OpenSSH incidents 16, 32, 77 and 142, phi3 emits a block that
**imitates the prompt's own summary format with invented values**. Incident 7
was one event at 08:21:00 with no user and no source IP; its narrative opens:

> Incident summary: - 10 anomalous events from 2026-07-14 08:59:30 to
> 2026-07-14 08:59:30 - ... Distinct source IPs (2): [192.168.1.10, ...]

Every number there is fabricated, and it is fabricated *in the voice of the
system*. This is the failure mode that would survive a demo unchallenged,
because it reads like the tool's own output rather than like prose.

## What held

- **`nan` never appeared**, on either corpus. `llm_narrative._field` has been
  doing its job since v1, and this is the first evidence rather than assertion.
- **Usernames are almost never invented** (0 and 1). See the limits below.
- **IPs are rarely invented** (1 and 5), and every case is inside a fabricated
  summary block rather than a standalone misattribution.

## Limits of this measurement

- It checks **entities, not stories**. A narrative can name only real IDs, IPs,
  users and counts and still assert a causal order the log does not support, or
  a confidence level nothing justifies. That needs a human or an LLM judge, and
  an LLM judge puts an unmeasured model inside the measurement.
- The **user check trades recall for precision**. A name counts as a claim only
  when quoted or when it is a username the corpus contains — because ordinary
  SOC prose puts English words in username position constantly ("the user
  attempted", "account discovery"). A stopword list was tried first and
  measured failing on the first three real narratives. So a wholly invented,
  unquoted name appearing nowhere in the corpus would be missed. The 0/51 and
  1/22 figures should be read as *"no misattribution to a real account"*, not
  as *"no invented user"*.
- **Clock formats were a false-positive class and are fixed.** phi3 rewrites
  13:38 as "1:38 PM", which is a correct restatement. Before the fix the `time`
  column read 57.3% ungrounded on the synthetic corpus; after it, 10.8%. The
  first number is in the git history as a reminder that a checker's own
  precision has to be measured before its output is quoted.
- **One model, one temperature.** phi3 at the pipeline's own settings. A larger
  model would very likely invent less; that is a Stage 5 experiment, not a
  claim this run supports.
- The report counts **mentions**, not incidents, for the technique figure.
  Per-incident: 33/94 and 87/193 narratives contain at least one invented ID.

## What this points at

The fix is already in the Stage 5 plan and now has a measurement behind it:
**structured JSON output**, with the technique field validated against the
grounded list and a rejected value dropped rather than printed. That converts
the prompt's instruction into an enforcement, which is the only thing the data
supports. Two smaller follow-ons:

1. **The empty-match prompt is the weak point.** The fallback line invites the
   model to classify the incident itself. Telling it plainly that no technique
   applies, and that saying so is the correct answer, is a one-line change worth
   measuring with this harness.
2. **Check the technique *name* as well as the ID**, against the ATT&CK bundle.
   A right ID with a wrong name is a hallucination that currently passes.

## Reproducing

```bash
uv run logdet-faithfulness                                  # synthetic, ~6 min GPU
uv run logdet-faithfulness --input data/processed/killpoint/parsed.csv \
     --output results/faithfulness/killpoint                # ~11 min GPU
uv run logdet-faithfulness --rescore results/faithfulness/faithfulness.json
```

`--rescore` re-checks saved narratives without calling the model, so a fix to an
extraction rule costs nothing and cannot change the narratives under itself.
Generation is at the pipeline's own temperature, so the counts move a little run
to run; the technique column is the one that is supposed to be zero.
