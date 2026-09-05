# Results

*Draft chapter. Every number is taken from an artifact in `results/` or
`docs/results.v1/` and cited to the file it came from. Nothing here was computed,
re-run or estimated while writing. Source of record: `docs/FINDINGS.md`.*

---

## 1. What this chapter claims, before the tables

The claim the measurements support is narrow, and it is stated first so that it reads as
a finding rather than as something a reader had to dig out:

> Against **reworded** attacks, signature rules break and embeddings do not — a real,
> explainable, reproducible mechanism. Against **timing** and **IP rotation** the
> embedding detector is the *weaker* system. Under an attacker that **optimises** rather
> than picking from a fixed menu, the advantage disappears entirely. And **precision**
> resists five separate fixes, each measured and rejected because it cost adversarial
> margin.

Three numbers qualify it, and they belong here rather than in a footnote:

| | Number | Artifact |
|---|---|---|
| Full tally across eight camouflage strategies | **1 win, 4 ties, 3 losses** | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| `realistic-combo` — the strategy closest to a real attacker — is a **loss** | **−13.3pt** | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Conservative differential under an optimising attacker | **−2.2pt** (negative) | `results/adaptive_wazuh/notes.md` |

Four further results are **not** differentials — they are measured on this system alone
or on the comparator's own output — so no comparison arm can take them back. They are
stated as wins in §6.

---

## 2. Definitions and instruments

**Instance detection** is the share of attack instances where *at least one* line was
flagged: would an analyst see the attack at all. It is the registered metric
(`CLAUDE.md` §1b) and moves in coarse steps — with 45 instances pooled over five seeds
the step is 2.2pt.

**Line detection** is the share of an attack's ground-truth lines that were flagged. It
is reported alongside instance detection because instance detection saturates, and the
line rate is where a mechanism remains visible after the headline metric has hit its
ceiling.

**Differential** is how much more the comparator's instance detection dropped than this
system's, under the identical camouflage on the identical corpus files. Positive means
this system held up better; negative means the comparator did.

**The comparator** is the real Wazuh manager (v4.9.0) running its own rules and its own
engine in Docker, not a reimplementation of its rule semantics
(`results/killpoint/killpoint_ambient0.05.md`). Sigma was measured first and dropped:
not one of ~3,300 rules matches an sshd auth line, so it would have scored ~0 recall
before any camouflage and could not have exhibited a measurable degradation
(`CLAUDE.md` Decision Log, 2026-08-18). That coverage gap is itself reported.

**Two instruments, and why.** Wazuh keys its correlation windows on *arrival* time, not
on the timestamp in the log line — verified on both `wazuh-logtest` and the live
`analysisd`, where 15 `Invalid user` lines from one IP fire rule 5712 identically at
3-second and 1-hour spacing. A corpus replayed at machine speed is therefore simultaneous
to it, and its drop under any timing strategy would be 0pt *by construction*. The five
timing-independent strategies are measured in batch; `slow`, `temporal` and
`realistic-combo` are measured by wall-clock-paced replay
(`results/killpoint/killpoint_ambient0.05.md` §"Why three strategies are excluded",
`results/killpoint/killpoint_paced_ambient0.05.md`). Wazuh's ruleset, engine and clock
are unmodified in both.

**The corpus.** Real LogHub OpenSSH: 2,483 real background lines (2,365 benign plus real
attacker traffic at `ambient_ratio=0.05`), 115 injected attack lines in 9 instances,
25 days, 9 real users, host `LabSZ`. Real: every background line, the usernames, the
host, the vocabulary. Authored: the injected instances and the camouflage layer
(`results/killpoint/killpoint_ambient0.05.md` §Corpus). Attack magnitudes — brute force
[15, 25] failures, enumeration [10, 12] usernames — were sized above both systems'
thresholds and pre-registered before any differential was computed.

**Pooling.** All rates are recomputed from summed confusion counts across five seeds
rather than averaged across them, because with 9 instances per corpus a per-seed rate
moves in 11pt steps and averaging misreports (`docs/results.v1/evaluation.md` §preamble).
Single-seed results are not admissible for instance detection (`CLAUDE.md` §4).

---

## 3. The headline: eight camouflage strategies

Against Wazuh on the real OpenSSH corpus, pooled over five seeds at
`ambient_ratio=0.05`:

| Strategy | Ours Δpt | Wazuh Δpt | Differential | Instrument | |
|---|---|---|---|---|---|
| `rephrase` | +2.2 | +33.3 | **+31.1** | batch | the entire result |
| `mimicry` | +0.0 | +0.0 | +0.0 | batch | tie |
| `noise` | +0.0 | +0.0 | +0.0 | batch | tie |
| `volume` | +0.0 | +0.0 | +0.0 | batch | tie |
| `temporal` | +0.0 | +0.0 | +0.0 | paced | tie |
| `slow` | +8.9 | +0.0 | **−8.9** | paced | **loss** |
| `ip_rotate` | +11.1 | +0.0 | **−11.1** | batch | **loss** |
| `realistic-combo` | +13.3 | +0.0 | **−13.3** | paced | **loss** |

Source: `results/killpoint/killpoint_eight_strategies_ambient0.05.md`, merged from
`killpoint_ambient0.05.md` (batch) and `killpoint_paced_ambient0.05.md` (paced). Each row
is taken whole from one instrument rather than mixed, because the paced corpus is thinned
to `max_events_per_ip=12` so that it can be replayed in real time.

**One win, four ties, three losses.** The pre-registered criterion was ≥25pt on at least
one strategy, which `rephrase` clears, so the registered verdict is **CONTINUE** — but
the sentence that belongs in the abstract is the tally, not the verdict.

### 3.1 Why the win is a mechanism and not luck

Wazuh's sshd rules match literal strings — `Failed password`, `Invalid user`. Rewording
the message drops the line out of the decoder entirely, so no rule can fire on it. A
sentence embedding of a reworded line stays near the original in vector space, so the
detector still ranks it an outlier. That is exactly what a signature engine should be
expected to do, which is what makes the result explainable rather than surprising
(`results/killpoint/killpoint_eight_strategies_ambient0.05.md`).

Two independent checks support reading it as a mechanism:

- **It does not depend on the corpus.** Measured across a 20× range of background
  density, `rephrase` reads **+31.2 / +31.1 / +31.1** at `ambient_ratio` 0.01 / 0.05 /
  0.20 — a 0.1pt spread, CONTINUE at all three
  (`results/killpoint/killpoint_ambient_sensitivity.md`).
- **It does not depend on the attacker being fixed.** Re-tested against an attacker
  allowed to search the camouflage space, `rephrase` reads **+35.6pt** on five held-out
  seeds — Wazuh 100% → 64.4% instance detection while this detector stays at 100%, with
  Wazuh keeping 29.5% of the attack's lines against 89.0% clean
  (`results/adaptive_wazuh/notes.md` §1).

The same mechanism is visible on the synthetic corpus from the other direction: under
`rephrase`, this system's own line detection goes *up*, from 86% to 100%, because rare
templates are precisely what an outlier detector responds to
(`results/adversarial_results.md`).

### 3.2 Where this system is the weaker one

These rows are not softened, and none of them is a floor or ceiling artefact:

- **`ip_rotate`, −11.1pt.** Spreading an attack across many source IPs defeats per-user
  embedding context; Wazuh's per-IP frequency rules simply fire on whichever IP still
  crosses the threshold. The size of the loss depends on how much ambient traffic there
  is to hide in — the sensitivity sweep gives a range of **−13.3 to −8.9** across
  background densities, a loss at every one
  (`results/killpoint/killpoint_ambient_sensitivity.md`).
- **`slow`, −8.9pt**, measured by paced replay
  (`results/killpoint/killpoint_paced_ambient0.05.md`).
- **`realistic-combo`, −13.3pt**, likewise, and this is the strategy closest to how a
  real attacker would behave. It is the largest single loss in the table.

On the synthetic corpus the same three strategies are also this system's worst
conditions in absolute terms: instance detection falls to 80% under `slow`, 84% under
`ip_rotate` and 91% under `realistic-combo`, and **every instance-level loss is confined
to scenario B, impossible travel** — which is detected by the hand-written physics rule
and not by the embeddings at all (`results/adversarial_results.md`). Both evasions work
by stepping outside that rule: `slow` pushes the two legs past its 60-minute window,
`ip_rotate` frequently lands both legs in the same /16 so its two-octet subnet comparison
sees no change.

### 3.3 No alert level rescues the picture, and shopping for one would be dishonest

Wazuh's alert level is its own severity scale, and the comparison changes shape
completely across it. All three thresholds are reported rather than the one that reads
best (`results/killpoint/killpoint_paced_ambient0.05.md`):

| Condition | Ours | Wazuh L3 | Wazuh L7 | Wazuh L10 |
|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 11.1% | 11.1% |
| `slow` | 91.1% | 100.0% | 0.0% | 0.0% |
| `temporal` | 100.0% | 100.0% | 0.0% | 0.0% |
| `realistic-combo` | 86.7% | 100.0% | 0.0% | 0.0% |

At level 3 Wazuh **cannot** degrade, because it starts saturated: a single failed login
is already a level-5 rule, so every injected instance is flagged without any correlation
happening at all. At levels 7 and 10 it detects 11.1% — one instance in nine — on the
*clean* corpus, so its small drops there are a floor effect. The registered primary level
was fixed before results existed and was not moved after seeing them; the decision and
its reasoning are in `CLAUDE.md`'s Decision Log entry for 2026-08-20.

---

## 4. Against an attacker that optimises rather than picks

Every camouflage figure above comes from eight hand-authored recipes at magnitudes chosen
once. That measures robustness against *the transforms their author thought of*. An
optimiser removes that limitation: the question becomes how much survives an attacker
allowed N attempts against the scores.

### 4.1 Pointed at this detector, on the synthetic corpus

The search is over the seven shipped transforms and their magnitudes, held to a validity
floor (an instance must keep ≥3 lines and ≥40% of its lines, or the plan is refused
before it can cost a query — otherwise the optimiser "evades" by deleting the attack).
Reported on five seeds the search never saw:

| | Instance detection | Line detection |
|---|---|---|
| no camouflage | 100% | 82.0% |
| `realistic-combo` (this project's published worst case) | 84.4% | 79.0% |
| **what the search found** | **73.3%** | **68.6%** |

Source: `results/adaptive/notes.md`. So the honest robustness figure under an optimising
attacker is **11.1pt worse than the number this project had been reporting**, and 27pt
below clean.

**The mechanism it found is legible**, which is what makes it worth reporting rather than
merely alarming: `slow` + `mimicry`, with the slow gap widened from 35 minutes to **61**.
61 minutes is just past the system's own 60-minute impossible-travel window and well past
its 30-minute grouping window — the optimiser located those constants from the scores
alone, without being told them.

Two findings land against this project's own evaluation suite:

- **`realistic-combo` ranks 49th of 106 valid subsets** on the search seed. The
  hand-picked "strongest realistic attacker" is a plausible attack, not a strong one.
- **Every subset containing `rephrase` scores 100% / 100%.** Combining novel wording with
  anything is self-defeating against an outlier detector — a single-strategy result that
  now holds across all 32 subsets containing it.

### 4.2 Pointed at both systems

The same search was then run against Wazuh and against this detector in turn, on the same
real OpenSSH corpus, five held-out seeds
(`results/adaptive_wazuh/notes.md`):

| Condition (held out, 5 seeds) | Ours Δpt | Wazuh Δpt | Differential |
|---|---|---|---|
| `rephrase` (fixed recipe) | +0.0 | +35.6 | **+35.6** |
| adaptive vs Wazuh (`rephrase+ip_rotate`) | +0.0 | +33.3 | +33.3 |
| **adaptive vs ours** (`noise+volume+ip_rotate`) | **+2.2** | +0.0 | **−2.2** |

**The number this project may quote is the conservative one: −2.2pt.** An attacker
optimising against Wazuh flatters us, so the identical search was pointed at this
detector too; it costs one instance in 45 and costs Wazuh nothing.

Three qualifications travel with that table and none of them is optional:

1. **`slow` and `temporal` are excluded from the search space on both sides**, because a
   batch-replayed corpus is simultaneous to an arrival-time-keyed SIEM and an optimiser
   handed that space converges on the harness artefact within a few queries. That removes
   the half of the space where this detector is *weakest*, so −2.2pt is itself an
   optimistic reading; the timing half is measured separately and is a loss
   (`slow` −8.9, `realistic-combo` −13.3).
2. **The search could not beat plain `rephrase` against Wazuh.** All 16 subsets containing
   it tie on the search seed and the tiebreak did not transfer — the searched plan reads
   +33.3pt against plain `rephrase`'s +35.6pt. Rewording is the whole mechanism.
3. **The winning anti-detector plan carries `volume_keep=1.0`, at which `volume` deletes
   nothing.** The plan is materially `noise+ip_rotate` with a shifted RNG stream, and the
   hill climb selected a no-op knob because it perturbs the random draw — 22.2pt on the
   search seeds became 2.2pt on fresh ones. The held-out split is what exposed it.

Both oracles hand the attacker true detection rates over *labelled* attack lines after
every attempt, which no real attacker receives. These are **upper bounds on evasion**,
not field estimates. And the space is the shipped transforms: a plateau means *these
transforms are exhausted*, never *this detector is robust*.

---

## 5. Precision is a measured negative result, not an open task

On the v1 synthetic corpus the full system reads precision **0.29**, recall **0.86**,
F1 **0.43**, at 100% instance detection, against a self-written rule baseline at
0.99 / 0.94 / 0.96 (`docs/results.v1/evaluation.md` §1). On the real kill-point OpenSSH
corpus it raises **194 incidents** for 9 attack instances before suppression
(`results/suppression/suppression.md`). This is the weakest number in the project and it
has not moved much.

What *is* new is that it has been attacked five times and the outcome of each attempt is
a measurement:

| Lever | Outcome | Why | Artifact |
|---|---|---|---|
| `CONTAMINATION=0.10` | **rejected** | same 100% clean instance detection at 2.4× less noise, but degrades `mimicry` 100% → **93%** and `realistic-combo` 91% → **87%** | `docs/results.v1/contamination_retune.md` |
| Sequence model keying `is_anomaly` | **refused by design** | template ids shift under `rephrase`; keying detection on them would destroy the one kill-point win | `CLAUDE.md` Stage 3 |
| Sequence severity shift | **inert** | identical notable set under demotion; promotion grew it 19 → 48 while surfacing no attack the baseline missed | `results/sequence/` |
| Suppression at q0.99 | **rejected** | best clean numbers of any arm (synthetic F1 0.446 → 0.624), and costs `slow` **13.3pt** of instance detection (80.0% → 66.7%), line rate 0.824 → **0.266** | `results/suppression/suppression_adversarial.md` |
| Graph loneness (`quiet`, `share@0.50`) | **rejected** | `quiet` is *strictly dominated* — same attack lines lost, fewer benign ones cleaned; `share@0.50` repeats the q0.99 mistake on the guard instead of the threshold | `results/suppression/loneness/notes.md` |

**What survived** is alert suppression at q0.90: on the real kill-point corpus
**194 → 147 incidents** and precision **0.206 → 0.248**, with recall (0.570) and instance
detection (100%, 9/9) untouched (`results/suppression/suppression.md`). Under camouflage
it is unchanged on every condition and seed by seed — across all 45 instance-firings it
never removed the last surviving line of an instance — at a real, sub-instance cost of 8
attack lines on `slow` and 6 on `realistic-combo`
(`results/suppression/suppression_adversarial.md`).

Four of the five rejections were bought by the rule that a change to detection, grouping
or scoring must re-run the camouflage arm over ≥5 seeds (`CLAUDE.md` §4). Each of those
four looks *better* on clean data than the option that shipped. That is the point of the
rule, and it is why the defensible claim here is stronger than "precision is bad and we
did not fix it":

> Precision on this architecture resists every available lever that does not cost
> adversarial margin, and each rejection is a measurement rather than an opinion.

---

## 6. Four results that are wins, and are stated as wins

The three qualifying numbers in §1 are all differentials. The four below are not: each is
measured on this system alone, or on the comparator's own output, so there is no arm in
which they come back negative.

### 6.1 On real traffic this detector is the quieter system

On the clean kill-point corpus it raises **1,415 incidents** against Wazuh's **4,546
alerts** at Wazuh's own default level — roughly **3.2×** more from the SIEM — and the
gap holds across all nine conditions (`results/killpoint/killpoint_ambient0.05.md`
§"Alert volume"). The paced corpus reproduces the direction at a smaller scale, 716
against 1,472 (`results/killpoint/killpoint_paced_ambient0.05.md`), and the adaptive run
reads 1,440 of our flagged lines against 4,563 Wazuh alerts
(`results/adaptive_wazuh/notes.md` §5).

Two honest qualifications. These are *our incidents* against *its alerts*, which are not
the same unit. And **alert-volume figures in this project reproduce to about ±0.5% across
machines** (§8), so they are approximate; the kill-point artifacts do not record which
machine produced them, so quote the ratio rather than the digits. The direction — the
opposite of what v1 assumed on synthetic data — is the finding.

### 6.2 The comparator's headline score is level-3 saturation, not correlation

Checked rather than assumed. In the live grid firing, **135 of 135** successful-login
alerts in the container's `alerts.json` are rule **5715 "sshd: authentication success",
level 3** (`results/bakeoff/bakeoff.md`). Wazuh flags the attack's lines by flagging every
successful login, without ever establishing that the travel was impossible. Raise the
threshold and it detects 11.1% on the clean corpus
(`results/killpoint/killpoint_paced_ambient0.05.md`). This is a finding about the
comparator that no differential expresses.

The same firing produced the one live cell where instance detection moved:
`impossible_travel` under `rephrase`, **100% (3/3) for this system against Wazuh's 0%
(0/3)** — because impossible travel is a two-line attack, so rewording removes *every*
line from Wazuh's decoder, where a 15–25 line brute force always leaves one behind
(`results/bakeoff/bakeoff.md`). The eleven other measured cells sit at a ceiling, which
the report computes and states rather than leaving a reader to assume a tie on
robustness.

### 6.3 The LLM stopped inventing MITRE technique IDs

The design constraint stated since v1 — *the LLM never invents technique IDs* — was
**false when first measured**: **47 of 142** technique mentions on the synthetic corpus
and **119 of 197** on OpenSSH were fabricated, several of them real but revoked ATT&CK
identifiers (`results/faithfulness/notes.md`). Two changes fixed it
(`results/faithfulness/arms/notes.md`):

| Arm | Invented IDs, synthetic | OpenSSH | Fully faithful, syn / OpenSSH |
|---|---|---|---|
| prose, original prompt | **47 of 142** | **119 of 197** | 57/94 / 94/193 |
| prose, reworded empty-match prompt | 12 of 101 | 6 of 79 | 78/94 / 174/193 |
| **structured JSON, validated** | **0 of 65** | **0 of 58** | **88/94** / **187/193** |

Most of the failure was a *wording bug*: the empty-match fallback said "no known
technique matched" while the instruction still demanded which ATT&CK stage the incident
progressed through. Stating that "none applies" is the correct answer took the control
arm — 41 of 94 synthetic and 150 of 193 OpenSSH incidents, i.e. the commonest case — from
**24/24 and 107/107 invented to 0 and 0**, with narrative length unchanged. Structured
JSON with the technique field validated against the grounded list is the enforcement, and
it removed the worst failure mode outright: seven narratives had fabricated an entire
incident-summary block in the system's own voice, and that goes 7 → 2 → **0**.

Confirmed on a second model: llama3 reads **0 invented of 63** under structured output
with **0 validation drops**, against phi3's 0 of 65 with 1 drop. The name check finds
**0 wrong of 43 and 0 of 33** — not a checker that fails to fire, but a property of the
failure: measured against the full ATT&CK bundle, names beside an *invented* ID are wrong
**39 of 40** and **61 of 64**, so the invention is whole-cloth and phi3 names a technique
correctly every time it is actually handed one.

The enforcement itself **fired once in 287 narratives**, so most of the gain is the
clearer task rather than the guard catching a determined hallucinator. Its worth is that
it does not depend on that compliance holding for the next model.

**Reporting rule that follows from this:** quote `mitre_techniques` — the grounded
retrieval — and never a stored narrative's technique IDs. Narratives produced before this
change still carry invented IDs.

> `results/faithfulness/notes.md` (the baseline failure);
> `results/faithfulness/arms/notes.md` (the three arms, the name check, the one drop in
> 287); `results/routing/notes.md` (the llama3 arm).

### 6.4 Authentic attacks from real tooling do not evade the detector

Real `hydra` and `ssh` runs against a real sshd on a separate machine, ground truth
captured at generation time, injected into the real OpenSSH background at the same
ambient ratio, seeds and scorer as a matched synthetic arm. Ten distinct captures — five
brute force, five enumeration — pooled over five seeds
(`results/kali/injected_notes.md` §v2):

| Condition | Authentic instance | Synthetic instance |
|---|---|---|
| baseline | 100% (50/50) | 100% (45/45) |
| `slow` | **100%** | 86.7% (−13.3) |
| `rephrase` | **100%** | 95.6% (−4.4) |
| `ip_rotate` | **100%** | 93.3% (−6.7) |
| `realistic-combo` | **100%** | 77.8% (−22.2) |
| `temporal` / `mimicry` / `noise` / `volume` | 100% | 100% |

**State the qualification with the number.** This is an *attack-shape* finding, not a
robustness win: the camouflage library was authored around the synthetic attack shape — a
homogeneous burst of near-identical `Failed password` lines — and has little grip on
authentic heterogeneous instances against a `root` account with 68 lines of genuine
history in the background. `rephrase` rewords `Failed password` and `Accepted password`,
of which an authentic brute-force instance has one and an authentic enumeration instance
has none, so it cannot remove the last flagged line. The synthetic arm reproduces the
known losses in the same run, which is what shows the transforms are genuinely being
applied rather than silently doing nothing to both arms.

An earlier three-capture run of the same measurement read the line rate **higher** for
authentic attacks (60.0% over 75 lines against synthetic's 26.5% over 343). The richer v2
captures **reversed** that — authentic 45.0% over 1,080 pooled attack lines against
synthetic 52.0% over 544 — because the thin early captures were almost entirely the one
highly anomalous `Failed password` line, while richer captures add `pam_unix`,
`Connection closed` and penalty lines that also occur in the background and are therefore
less individually anomalous. Absolute evidence per instance rose ~14×; instance detection
stayed 100%.

One authentic-tooling finding stands on its own: a real 20-attempt hydra run against a
rate-limiting modern sshd (`srclimit_penalise`) leaves **5 log lines, exactly one a
`Failed password`**, where the synthetic generator writes 15–25. Authentic brute force
hands the detector roughly a fifth of the evidence. Still detected — but the honest
summary is *same instance detection, much less evidence behind it*.

### 6.5 The method is a result too

Five precision levers measured and rejected; a kill point registered before the code
existed and honoured when it returned an uncomfortable shape; a comparator run as its own
engine rather than reimplemented; a camouflage arm made mandatory on every detection
change. Almost nobody publishes the rejections, because doing so requires having run all
five.

---

## 7. The live two-box demonstration

Authentic attacks launched on a separate Kali machine, shipped over a direct Cat6 link
into the analyzer's collector endpoint, with both systems scored on the identical stream —
318 collector lines, 318 mirrored to Wazuh's watched file, so neither system was handed a
different corpus (`results/bakeoff_live/notes.md`):

| System | Instance (6/6) | Line rate | Flagged |
|---|---|---|---|
| this detector | **100%** | **80%** (93/117) | 105 |
| Wazuh (level ≥3) | **100%** | 72% (84/117) | 96 |

The only separation is enumeration: 78% (21/27) against Wazuh's 56% (15/27).

**This is a demonstration, not a new measurement, and the artifact says so.** Both
systems tie on instance detection exactly as the injected authentic runs found
(§6.4) — an attack-shape result, not a robustness one. The camouflage level was `none`,
so nothing about camouflage is being re-tested. And six live firings are **not** the ≥5
recorded seeds the benchmark rule requires, so the line-rate edge must not be quoted as a
differential.

---

## 8. Limits

Stated here rather than left to be found.

- **Alert-volume figures reproduce to about ±0.5% across machines; detection rates are
  exact.** A committed 2026-08-18 artifact stopped reproducing on one condition
  (`realistic-combo`: 703 flagged lines / 670 incidents against a fresh 705 / 673) while
  line detection (0.776) and instance detection (0.911) stayed bit-identical. The cause is
  **CPU thread count** — 703/670 at `OMP_NUM_THREADS` ≤ 8, 705/673 at 16–20, this box's
  default being 20 on an **i7-13650HX (14c/20t)**. BLAS and torch reorder their reductions,
  embeddings differ in the last float bits, and near-tied rows cross the `contamination`
  cutoff. **Every flipped line is benign**, which is why detection rates did not move.
  Thread pinning was declined: it would make which lines get flagged depend on an
  environment variable. Quote an alert-volume figure as approximate and name the machine
  (`results/adversarial_notes.md`).
- **No independent red-teaming.** Every attack and every camouflage transform was authored
  or driven by the author. This cannot be fixed from inside the project and is a
  limitation to state, not a task to schedule.
- **The authentic-attack sample is small**: five distinct captures per scenario, placed
  across five seeds, so five placements of five underlying attacks. Scenario B has no
  authentic capture — its distant leg needs a second geographic IP and stays synthetic by
  necessity (`results/kali/injected_notes.md`).
- **Impossible travel is detected by a hand-written rule, not by embeddings.** Both login
  legs are textually identical once IPs are masked, so they embed to the same vector: the
  embedding layer alone detects **0%** of impossible-travel instances and the full system
  reaches 100% only via the rule (`docs/results.v1/evaluation.md` §2). Never claim that
  embedding-based detection catches impossible travel. Every instance-level camouflage
  loss on the synthetic corpus lands on this one rule
  (`results/adversarial_results.md`).
- **Narrative faithfulness is measured on entities, not stories.** A narrative can ground
  every ID, IP and count and still assert a causal order the log does not support. An LLM
  judge was rejected deliberately: it would put an unmeasured model inside the measurement
  (`results/faithfulness/notes.md`).
- **The `volume` camouflage row partly measures an attack that stopped rather than one
  that hid.** Held to the adaptive adversary's validity floor, 4–30 of the 128
  fixed-magnitude subsets per seed fall below it and **every one of them carries
  `volume`** — on some draws a 6-line enumeration is thinned to 2 lines. No verdict rests
  on that row, but it should not be quoted as pure evasion
  (`results/adaptive/notes.md`).
- **The eval set is small and rates are coarse**: 9 attack instances per corpus, so
  pooled instance detection moves in 2.2pt steps over five seeds. Small differences are
  not meaningful (`docs/results.v1/evaluation.md` §Threats to validity).
- **The MITRE enrichment counts matches, not true positives.** Of 11 mapped techniques,
  **1 of 86** falls inside ATT&CK's own syslog-visible universe and 9 fall outside both
  denominators; 5 have never fired on either corpus, and T1110 matches 457,880 of 655,147
  OpenSSH lines (`results/coverage/notes.md`). Whether the enrichment is *correct* on the
  lines it matches is unmeasured and would need technique-level ground truth no corpus
  here has.
- **The v1 rule baseline is near-oracle by construction** — the synthetic corpus is built
  from the same three attack templates the rules encode, which is why it reads F1 0.96
  there. The third-party comparator exists precisely to remove that
  (`docs/results.v1/evaluation.md` §1).

---

## 9. What makes these numbers worth believing

Each item removes one specific way the author could have graded their own homework:

- **The kill point was pre-registered** — thresholds, deciding quantity and deadline fixed
  in version control before any evaluation code existed, and never moved after results
  appeared, including when the result came back as one win and three losses
  (`CLAUDE.md` §1b).
- **The rules are third-party, executed by their own engine** — the real Wazuh manager,
  not a reimplementation. Sigma was measured and dropped, and the gap reported.
- **The attacks are third-party too** for the un-camouflaged case — real `hydra`/`ssh`
  against a real sshd on a separate machine, ground truth captured at generation time.
  Only the camouflage layer is authored, which is the layer this project is supposed to
  own.
- **Both systems are scored by one detector-agnostic scorer** on identical corpus files.
- **No change to detection, grouping or scoring lands without the camouflage suite over
  ≥5 seeds** (`CLAUDE.md` §4). Four of the five precision rejections were bought by that
  rule.
- **The evaluation track may never be imported by the pipeline**, enforced statically in
  `tests/test_layering.py` rather than by convention.

---

## 10. Artifact index

| Question | File |
|---|---|
| The eight-strategy tally | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| The registered verdict and its batch half | `results/killpoint/killpoint_ambient0.05.md` |
| The timing half (paced replay) | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Does the win depend on the corpus? | `results/killpoint/killpoint_ambient_sensitivity.md` |
| The optimising attacker | `results/adaptive/notes.md`, `results/adaptive_wazuh/notes.md` |
| Camouflage on the synthetic corpus | `results/adversarial_results.md` |
| Live side-by-side, two machines | `results/bakeoff_live/notes.md`, `results/bakeoff/bakeoff.md` |
| Authentic attacks from real tooling | `results/kali/injected_notes.md` |
| Precision: the five rejections | `results/suppression/`, `results/suppression/loneness/notes.md`, `docs/results.v1/contamination_retune.md` |
| LLM hallucination, measured and fixed | `results/faithfulness/notes.md`, `results/faithfulness/arms/notes.md` |
| ATT&CK coverage denominators | `results/coverage/notes.md` |
| Reproducibility caveat | `results/adversarial_notes.md` |
| v1 baseline comparison | `docs/results.v1/evaluation.md` |
| Full project state, roadmap, decision log | `CLAUDE.md` |
