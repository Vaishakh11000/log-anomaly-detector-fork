# Introduction and Background

*Draft chapter. It states the problem, the gap in what is currently reported, the claim
this project defends, and what each later chapter delivers. Nothing here was computed or
re-run while writing: every figure is cited to the artifact that records it in `results/`
or `docs/results.v1/`, and figures that exist only in the project's Decision Log are cited
to `CLAUDE.md` explicitly. Source of record for results: `docs/FINDINGS.md`. Method detail
is not repeated here — it is in `docs/writeup/methodology.md`.*

---

## 1. The claim, stated first

A reader should meet this project's conclusion before its motivation, because the
conclusion is narrower than the motivation would lead them to expect, and a narrow claim
stated first reads as rigour where the same claim discovered later reads as concealment.

> Against **reworded** attacks, signature rules break and embeddings do not — a real,
> explainable, reproducible mechanism. Against **timing** and **IP rotation** the
> embedding detector is the *weaker* system. Under an attacker that **optimises** rather
> than picking from a fixed menu, the advantage disappears entirely. And **precision**
> resists five separate fixes, each measured and rejected because it cost adversarial
> margin.

Three numbers qualify it, and they belong in the introduction rather than deep in the
results:

| | Number | Artifact |
|---|---|---|
| The full tally across eight camouflage strategies | **1 win, 4 ties, 3 losses** | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| `realistic-combo` — the strategy closest to a real attacker — is a **loss** | **−13.3pt** | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Conservative differential under an optimising attacker | **−2.2pt** (negative) | `results/adaptive_wazuh/notes.md` |

The phrase this project may **not** use is *"more robust under camouflage"*. The
measurements do not support it. What they support is one mechanism, named and explained,
sitting alongside three losses that are reported with the same weight.

Not everything is qualified this way. Four results are measured on this system alone, or
on the comparator's own output, so no comparison arm can take them back; they are stated
as wins in the results chapter §6 and summarised in §9 below.

---

## 2. The setting

The object of study is the humblest kind of security telemetry: the authentication log of
a Linux host. Every SSH login attempt, successful or failed, every invalid username, every
PAM failure, lands in one text file in a format that has barely changed in thirty years.
It is the log that exists on every machine, that a small organisation actually has, and
that an attacker touches on the way in.

Three things about it shape everything that follows.

**It is mostly attack traffic already.** The public LogHub OpenSSH corpus — a real host's
auth log, 655,147 lines — is between 66% and 83% ambient internet brute force on *every*
day it covers (`CLAUDE.md` Decision Log, 2026-08-18). "Normal" on an internet-facing host
is not quiet; it is a constant low hum of people trying passwords. Any detector, and any
evaluation, that assumes a benign baseline has to build one deliberately.

**Alerts are cheap and attention is not.** A rule that fires on every failed password
finds every brute force and is useless. The v1 system reads line-level precision **0.29**,
recall **0.86**, F1 **0.43** on its 751-line synthetic corpus
(`docs/results.v1/evaluation.md` §1), raising **94 incidents for 9 real attacks**
(`docs/FINDINGS.md` §5). That is the number this project is worst at, and §9 says plainly
what happened when it was attacked.

**The analyst is the consumer, not an automated response.** This system may recommend an
action; it never takes one. That is a product position rather than a scope cut, and it is
fixed in the constraints (`docs/writeup/methodology.md` §3).

---

## 3. The gap: what nobody reports

There is no shortage of log anomaly detection. There is a shortage of one specific number.

**Open-source SIEMs publish detection, not degradation.** A ruleset ships with rules and,
if you are lucky, with test cases showing that they fire. It does not ship with a
statement of how much less it detects when an attacker slows an attack down, spreads it
across source addresses, or writes the same attack in different words. That number is not
in the documentation because nobody measures it and publishes it.

**The published literature evaluates on data where the attacker is not hiding from the
detector under test.** Eight peer-reviewed journal papers were assembled for the
2026-08-31 review — deliberately journal-only, each with a resolved DOI and an author
version on file (`~/presentation-2026-08-31/references/REFERENCES.md`; the review folder
was moved out of the repository on 2026-09-01, `CLAUDE.md` Decision Log). They cover the
field the honest way:

| # | Work | Why it is here |
|---|---|---|
| R1 | Almodovar et al., *LogFiT: Log Anomaly Detection Using Fine-Tuned Language Models*, IEEE TNSM 21(2), 2024 | The closest published work to a language-model approach on logs. Reports on clean data only. |
| R2 | Landauer et al., *Deep Learning for Anomaly Detection in Log Data: A Survey*, MLWA 12, 2023 | The field-wide survey: it shows what the field measures, and that evasion is not part of it. |
| R3 | Ali et al., *A Comprehensive Study of Machine Learning Techniques for Log-Based Anomaly Detection*, EMSE 30(5), 2025 | Finds simpler models competitive with deep ones on log data. |
| R4 | Wu, Li & Khomh, *On the Effectiveness of Log Representation for Log-Based Anomaly Detection*, EMSE 28(6), 2023 | Measures how much the representation choice — including sentence embeddings — matters. |
| R5 | Khan et al., *Impact of Log Parsing on Deep Learning-Based Anomaly Detection*, EMSE 29(6), 2024 | Shows how much parsing quality moves anomaly detection results. |
| R6 | Pang et al., *Deep Learning for Anomaly Detection: A Review*, ACM CSUR 54(2), 2021 | The standard review; supplies the framing and definitions. |
| R7 | Kheddar, *Transformers and Large Language Models for Efficient Intrusion Detection Systems*, Information Fusion 124, 2025 | 2025 survey: the field is moving toward LLMs, and evaluation is still on static datasets. |
| R8 | Debicha et al., *TAD: Transfer Learning-Based Multi-Adversarial Detection of Evasion Attacks Against NIDS*, FGCS 138, 2023 | The closest published work with an active adversary — and it is network traffic, not logs. |

The shared limitation is the gap this project addresses, and it is citable rather than
asserted: **all eight evaluate on data where the attacker is not trying to hide from the
specific detector being tested.** R8 is the only one with an active adversary and it
targets network intrusion detection rather than log analysis. **None of them compares a
detector against a production SIEM ruleset under camouflage.**

So the question this project asks is not "can a detector find brute force in an auth log"
— it can, and so can a twenty-year-old rule. The question is:

> **How much worse does each system get when the attacker actively tries to hide, and
> which of the two degrades less?**

That question has an uncomfortable property that makes it worth asking: it can come back
against you. This one did, on five of the eight strategies (§1).

---

## 4. Why the detection method is explicitly not the novelty

This must be said early and plainly, because the alternative is a write-up that overclaims
in its first paragraph.

**Isolation Forest over sentence embeddings is a standard design.** Log representation
choice is a studied question (R4) and simpler models are competitive with deep ones on log
data (R3, R6). Presenting the detector as a contribution would be dishonest. So would
presenting "we attached a local LLM to it", which is what a large part of the field is
currently doing (R7).

Two consequences follow, and both are load-bearing rather than modest.

**First, the contribution is the measurement regime.** What is uncommon is not the
detector but the rule that every change to detection, grouping or scoring must re-run the
adversarial suite over at least five seeds before it lands (`CLAUDE.md` §4), together with
a criterion registered in version control before any evaluation code existed (§7). Four of
the five rejected precision fixes were bought by that rule alone: each looked *better* on
clean data than the option that shipped, and each was caught by the camouflage arm
(`results/suppression/`, `docs/results.v1/contamination_retune.md`).

**Second, "we are not the novelty" is what makes the losses reportable.** A project whose
claim rests on the cleverness of its detector cannot afford to publish `ip_rotate −11.1pt`.
A project whose claim rests on measuring honestly can, and must.

The design decision that *is* worth stating is a negative one: the detector never sees a
source IP, because the message template is masked before embedding
(`docs/writeup/methodology.md` §2.1). That is why impossible travel has to be a separate
hand-written physics check, and why this write-up must never claim that embedding-based
detection catches it (results chapter §8).

---

## 5. North star and research questions

The project's stated aim is one sentence:

> A **local-first detection and explanation system that is continuously measured under
> adversarial conditions.**

It doubles as a decision rule, and it was used as one: a proposed feature had to either
improve detection or explanation, or make the adversarial measurement more credible. Work
that did neither was declined, and the declining is recorded rather than silently omitted
— multi-source breadth, peer-group baselines, score calibration, drift handling, and a
sixth precision attempt were each turned down with a stated reason (`CLAUDE.md`, Stage 3
and "Where the work goes now").

Four questions organise the work, and each is answered in the results chapter rather than
left open:

**RQ1 — Under camouflage, does an embedding detector degrade less than a production SIEM
ruleset?** *Answer: on one strategy of eight, by a large and explainable margin; on three
it degrades more.* Results §3.

**RQ2 — Does any such gap survive an attacker who optimises against the detector rather
than picking from a fixed menu of transforms?** *Answer: the one win survives and grows
(+35.6pt on held-out seeds), but the conservative differential across both systems is
−2.2pt.* Results §4.

**RQ3 — Can the precision weakness be fixed without spending adversarial margin?**
*Answer: five levers, five measured rejections, one modest survivor.* Results §5.

**RQ4 — Can a local LLM explain an incident without inventing the evidence?** *Answer: not
by instructing it — the constraint was measured false — but yes by structuring and
validating its output, on two corpora and two models.* Results §6.3.

---

## 6. What was inherited, and the three holes the fork was built to close

This is the development fork of a submitted final-year artifact. The v1 system already
worked: it detected **100%** of attack instances on its clean synthetic corpus
(`docs/results.v1/evaluation.md` §1). Its numbers are the baseline every later change is
measured against, and they are kept unmodified in `docs/results.v1/`.

Its problem was not capability. It was **credibility**, in three specific places, and each
is closed by a named piece of this project:

| v1 hole | Why it invalidated the comparison | Closed by |
|---|---|---|
| The rule baseline was **self-written** | The corpus was built from the same three attack templates the rules encode — near-oracle by construction, which is why it reads F1 0.96 (`docs/results.v1/evaluation.md` §1) | A third-party ruleset executed by its own engine: the real Wazuh manager (methodology §6) |
| The attacks were **self-written** | Injected synthetic lines, authored by the person grading them | Real `hydra`/`ssh` runs against a real sshd on a separate machine, ground truth captured at generation time (methodology §10.3) |
| The corpus was **synthetic** | 751 authored lines with full ground truth flatter every number | The real LogHub OpenSSH corpus, with a background built explicitly because the raw corpus is 66–83% ambient attack (methodology §4.3) |

One credibility hole is *not* closed and cannot be, from inside the project: **there has
been no independent red-teaming.** Every attack and every camouflage transform was
authored or driven by the author. The kill point removes self-written rules and the attack
runner removes self-written base attacks, but nobody outside the project has tried to
evade this detector. It is stated as a limitation, not scheduled as a task (methodology
§14).

The camouflage layer stays authored deliberately, and that is the right layer to author:
it is the object of study. What the fork removes is authorship of everything *around* it.

---

## 7. The kill point: a criterion written before the code

The whole roadmap rested on one unverified assumption — that v1's robustness gap would
survive contact with rules its author did not write. v1's headline collapse — the rule
baseline's recall falling **0.94 → 0.07** under `realistic-combo` while the full system
held at 0.78 (`docs/results.v1/evaluation.md` §3) — was measured against self-written
frequency-threshold rules that a slowed-down attack defeats almost by definition. A mature
third-party ruleset degrades by a different mechanism, and those numbers do not transfer.

So the assumption was tested first, cheaply, before anything was built on it. A criterion
was registered in version control before any evaluation code existed (`CLAUDE.md` §1b):
≥25pt differential on at least one camouflage strategy → continue; 10–25pt → cheap stages
only; below 10pt, or the SIEM degrades *less* → stop and publish the negative result.

Two properties make it binding rather than decorative, and both are structural:

- The verdict function is a hard-coded literal ladder, written before any result existed
  and pinned at its exact boundaries by tests — including tests asserting that a SIEM
  degrading less than this system returns **STOP** (`CLAUDE.md` §1b, methodology §8).
- The registered wording is "≥25pt on at least one strategy", so taking the maximum is the
  reading as registered, not a choice made afterwards.

The result was **CONTINUE at +31.1pt on `rephrase`** — and one win, four ties and three
losses everywhere else. The criterion was not moved, and the temptation to move it was
concrete rather than hypothetical: the paced run offered a ready-made argument for
changing the alert level after seeing an unfavourable result, and it was refused, partly
because changing a deciding threshold after seeing results is exactly what the kill point
exists to prevent, and partly because the higher levels do not favour this system anyway
(`CLAUDE.md` Decision Log, 2026-08-20; results §3.3).

This is why the introduction can state a narrow claim without apology. The measurement
could have gone the other way, the decision rule for what to do in that case was fixed in
advance, and the shape that came back is the shape being reported.

---

## 8. Scope and non-goals

Set here so that later chapters are read against the right expectations. The full list and
its reasoning are in methodology §3.

**In scope.** Linux auth/syslog and nginx access logs; batch and streaming ingestion;
comparison against one production SIEM ruleset; camouflage as the adversary model;
incident correlation; grounded ATT&CK enrichment; local LLM explanation; a two-machine
deployment split.

**Out of scope, deliberately.** No automated response, blocking or SOAR — the system
recommends, never acts. No fine-tuning of the narrative LLM, and no models above 8B
parameters. No required cloud API. No GPU requirement: CPU single-box is the supported
floor and the GPU is an accelerator, which is what makes "a team with no SOC budget could
run this" a measured statement rather than a slogan.

**Corpora not used, and why.** HDFS and BGL are the standard labelled log benchmarks and
were rejected as primary corpora on a specific ground: their anomalies are *system faults,
not adversarial behaviour*. With no attacker there is no technique to map, no attack
narrative to tell, and camouflage is semantically undefined — so running on them would
benchmark the one layer this project does not claim as its contribution while switching
off both of the things that make it distinctive (`CLAUDE.md` §3b, viva prep C7).

---

## 9. Contributions

Stated with their artifacts, and with the qualifications attached rather than deferred.

1. **A camouflage differential against a production SIEM ruleset, reported in full.** One
   win (`rephrase`, +31.1pt), four ties and three losses across eight strategies, pooled
   over five seeds on real OpenSSH traffic
   (`results/killpoint/killpoint_eight_strategies_ambient0.05.md`). The win is a mechanism
   — signature rules match literal strings, so a reworded line leaves the decoder, while
   its embedding does not move far — and it is stable across a 20× range of background
   density (+31.2 / +31.1 / +31.1,
   `results/killpoint/killpoint_ambient_sensitivity.md`).

2. **A measurement of what an *optimising* attacker changes.** A search over the shipped
   transforms, reported on held-out seeds. Pointed at the SIEM, the one win grows to
   +35.6pt and the optimiser finds nothing better to do than reword. Pointed at this
   detector, the conservative differential is **−2.2pt** — and that is the arm quoted
   (`results/adaptive_wazuh/notes.md`). On the synthetic corpus, where timing strategies
   *can* be searched, it beat this project's own published worst case by 11.1pt by
   locating the system's own 60-minute window from the scores alone
   (`results/adaptive/notes.md`).

3. **Precision as a closed negative result rather than an open task.** Five levers
   measured, five rejected, four of them because the mandatory camouflage arm exposed a
   cost that clean data hid; one modest survivor (194 → 147 incidents, precision 0.206 →
   0.248, recall and instance detection untouched)
   (`results/suppression/`, `docs/results.v1/contamination_retune.md`).

4. **Findings about the comparator that no differential expresses.** Its headline 100% is
   level-3 saturation — a single successful login is already an alert — and at level 7 or
   10 it detects **11.1%, one instance in nine, on the *clean* corpus**
   (`results/killpoint/killpoint_paced_ambient0.05.md`). On alert volume the direction is
   the opposite of what v1 assumed: this detector is the quieter system by roughly 3.2×
   (`results/killpoint/killpoint_ambient0.05.md`). Those are *our incidents* against *its
   alerts*, which are not the same unit, and alert-volume figures in this project
   reproduce to about ±0.5% across machines — the kill-point artifacts do not record which
   machine produced them, so the ratio is quotable and the digits are approximate
   (`results/adversarial_notes.md`).

5. **A measured — and then fixed — hallucination failure in the explanation layer.** The
   stated constraint "the LLM never invents MITRE technique IDs" was false when first
   measured: **47 of 142** technique mentions on the synthetic corpus and **119 of 197** on
   OpenSSH were fabricated. Rewording the empty-match prompt plus structured output with
   the technique field validated against the grounded list takes it to **0 of 65 and 0 of
   58**, confirmed on a second model (`results/faithfulness/arms/notes.md`). Quote
   `mitre_techniques` — the retrieval output — never a stored narrative's technique IDs.

6. **An end-to-end authentic-attack track.** Real `hydra`/`ssh` runs against a real sshd on
   a separate machine, captured with ground truth at generation time and injected into the
   real background: **100% instance detection on all nine camouflage conditions**, 50/50
   pooled. The qualification travels with the number — this is an **attack-shape** finding,
   because the camouflage library was authored around the synthetic attack shape and grips
   authentic heterogeneous instances less well, not a robustness win
   (`results/kali/injected_notes.md`).

7. **The method itself.** A pre-registered kill point honoured when it returned an
   uncomfortable shape; a comparator run as its own engine rather than reimplemented; a
   third-party attack toolchain; one detector-agnostic scorer for both systems; and a
   one-way import rule between pipeline and evaluation enforced statically in CI rather
   than by convention. Almost nobody publishes the rejections, because doing so requires
   having run all five.

---

## 10. What each later chapter delivers

**Methodology** (`docs/writeup/methodology.md`) — how the measurement was built and where
it could have broken. The system under measurement, kept brief because it is not the
contribution (§2); the constraints fixed in advance, including the one that was measured
false and rewritten rather than kept (§3); the three corpora and why the kill-point
background had to be constructed explicitly (§4); the adversary model, all seven
transforms, and what is authored versus third-party (§5); the comparator, with Sigma
dropped on measurement and nothing about Wazuh ever modified (§6); the metrics and the
three scoring rules enforced in code (§7); the pre-registered kill point and what makes it
binding (§8); the two instruments and why there must be two (§9); the four other
instruments — live bake-off, adaptive adversary, authentic attack runner, faithfulness
harness (§10); benchmark discipline (§11); structural safeguards (§12); environment and
reproducibility (§13); and threats to validity of the *method* (§14).

**Results** (`docs/writeup/results-chapter.md`) — the claim and its three qualifying
numbers before any table (§1); definitions and instruments (§2); the eight-strategy tally
with the win explained as a mechanism and the three losses named (§3); the optimising
attacker (§4); precision as a closed negative result with the five-lever table (§5); the
four results that are wins (§6); the live two-box run, labelled a demonstration rather
than a measurement (§7); limits (§8); what makes the numbers believable (§9); and an
artifact index (§10).

**Conclusion** — *not yet drafted.* It has to do three things and no more: restate the
narrow claim without widening it, say what an independent red team would be asked to
attack first, and name what the field would gain if degradation-under-evasion were a
reported number rather than an unasked question.

**Supporting material.** `docs/FINDINGS.md` is the source of record for every number and
is the document to hand an examiner first. `docs/writeup/abstract.md` carries the abstract
and a short variant. `docs/writeup/viva-qa.md` is sixteen hostile questions in
question → honest answer → artifact form, concession-first.

---

## 11. A note on how this document treats its own bad results

The three losses in §1, the −2.2pt in §9, the five precision rejections, the constraint
that was measured false, the committed artifact that stopped reproducing and had to be
diagnosed and re-cut — none of these were discovered by a reader. Each was measured,
recorded on the day, and placed where it is met early.

That is not modesty. It is the only thing that makes the one win worth believing. A
project that reports a clean sweep against a production SIEM has, in a field where nobody
publishes this number at all, most likely measured something other than what it claims.
