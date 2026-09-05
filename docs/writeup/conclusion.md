# Conclusion

*Draft chapter. Nothing here was computed, re-run or estimated while writing: every figure
is restated from an artifact in `results/` or `docs/results.v1/` and cited to it, and
figures that exist only in the project's Decision Log are cited to `CLAUDE.md` explicitly.
Source of record: `docs/FINDINGS.md`. Results detail is not repeated here — it is in
`docs/writeup/results-chapter.md`; method detail is in `docs/writeup/methodology.md`.*

---

## 1. The claim, restated and not widened

> Against **reworded** attacks, signature rules break and embeddings do not — a real,
> explainable, reproducible mechanism. Against **timing** and **IP rotation** the
> embedding detector is the *weaker* system. Under an attacker that **optimises** rather
> than picking from a fixed menu, the advantage disappears entirely. And **precision**
> resists five separate fixes, each measured and rejected because it cost adversarial
> margin.

The three numbers that qualify it are the same three the introduction opened with, and
they do not improve on second telling:

| | Number | Artifact |
|---|---|---|
| Full tally across eight camouflage strategies | **1 win, 4 ties, 3 losses** | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| `realistic-combo` — the strategy closest to a real attacker — is a **loss** | **−13.3pt** | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Conservative differential under an optimising attacker | **−2.2pt** (negative) | `results/adaptive_wazuh/notes.md` |

Three sentences this project may not write, each of which a reader could reasonably have
expected from the motivation:

- **Not** "more robust under camouflage." One strategy of eight, and the detector is the
  weaker system on three.
- **Not** "robust against an adaptive adversary." The conservative differential there is
  negative, and it is negative on a search space that *excludes* the timing half where
  this detector is weakest — so −2.2pt is itself the optimistic reading
  (results §4.2).
- **Not** "the LLM never invents technique IDs" as an architectural guarantee. That
  sentence was measured false, then made true by structured validated output on two
  corpora and two models (results §6.3). The design decision stands; the sentence that
  described it did not.

What survives is one mechanism, named and explained, sitting beside three losses reported
with the same weight. That is a smaller result than the roadmap that produced it, and it
is the result the measurements support.

---

## 2. What the four non-differential wins settle

The three qualifying numbers are all comparisons, and a comparison can come back against
you. Four results are not comparisons — each is measured on this system alone or on the
comparator's own output — so no arm can take them back (results §6). What each one
*settles*, as distinct from what it reports:

**Alert volume settles a question v1 got backwards.** On real traffic this detector is the
quieter system by roughly **3.2×** against Wazuh at its own default level, and the gap
holds across all nine camouflage conditions (`results/killpoint/killpoint_ambient0.05.md`).
Two qualifications travel with it permanently: these are *our incidents* against *its
alerts*, which are not the same unit, and alert-volume figures in this project reproduce to
about ±0.5% across machines — the kill-point artifacts do not record which machine produced
them, so the ratio is quotable and the digits are approximate
(`results/adversarial_notes.md`). The absolute precision weakness is unchanged; what is
settled is the *direction*, and it is the opposite of what synthetic data suggested.

**Level-3 saturation settles what the comparator's 100% means.** Wazuh reads 100%
because a single successful login is already an alert — it flags the attack's lines without
correlating them — and at level 7 or 10 it detects **11.1%, one instance in nine, on the
clean corpus** (`results/killpoint/killpoint_paced_ambient0.05.md`). That is a finding
about the comparator no differential can express, and it is why "the SIEM ties with you"
and "the SIEM correlated the attack" are different statements.

**Grounding-plus-validation settles that a prompt instruction is not an enforcement
mechanism.** Invented technique IDs went from **47/142 and 119/197 to 0 and 0**
(`results/faithfulness/arms/notes.md`). The instructive part is the split: most of the
failure was a wording bug in the empty-match case, and the structured validation fired
**once in 287 narratives**. Its worth is therefore not that it caught a determined
hallucinator but that it does not depend on the next model's compliance. The reporting rule
that follows is permanent — quote `mitre_techniques`, the grounded retrieval output, never
a stored narrative's technique IDs.

**Authentic tooling settles that the un-camouflaged result is not an artefact of
self-written attacks.** Real `hydra`/`ssh` runs against a real sshd on a separate machine,
ground truth captured at generation time, hold **100% instance detection on all nine
camouflage conditions**, 50/50 pooled (`results/kali/injected_notes.md`). The
qualification is not detachable: this is an **attack-shape** finding, because the
camouflage library was authored around the synthetic attack shape and grips authentic
heterogeneous instances less well. It says third-party attack tooling does not evade this
detector; it does not say the detector is robust.

Together these settle the four objections a reader reaches for first — *you are noisier
than the SIEM*, *the SIEM matched you so you have nothing*, *your LLM makes things up*, and
*your attacks are your own* — without any of them resting on a differential.

---

## 3. Precision is closed, not open

Precision is the weakest number in the project: **0.29** line-level with 94 incidents for 9
attacks on the synthetic corpus (`docs/results.v1/evaluation.md` §1), 194 incidents on the
real kill-point corpus before suppression (`results/suppression/suppression.md`). It has
not moved much, and the honest position is not that it is unfinished.

**Five levers were tried and five were rejected** — contamination retune, keying detection
on template ids, the sequence severity shift, suppression at q0.99, and both graph loneness
tests — with one modest survivor: suppression at q0.90, **194 → 147 incidents** and
precision **0.206 → 0.248**, recall and instance detection untouched. The table and the
per-lever reasoning are in results §5; the artifacts are `results/suppression/` and
`docs/results.v1/contamination_retune.md`.

The reason this is a *closure* rather than a pause is structural, and it has two parts.

**Four of the five rejections were bought by a rule, not by taste.** Each of those four
looked better on clean data than the option that shipped, and each was caught only by the
mandatory camouflage arm over ≥5 seeds (`CLAUDE.md` §4). q0.99 is the clearest case: the
best clean numbers of any arm, and it costs `slow` 13.3pt of instance detection
(`results/suppression/suppression_adversarial.md`). A project without that rule would have
shipped it and reported an improvement.

**The fifth was refused by design, and refusing it is the same decision as the headline
result.** Keying `is_anomaly` on a discrete template id is the obvious precision fix and is
unavailable here, because rewording moves a line to a different cluster — which is
precisely how signature rules break under `rephrase`, and that mechanism is the entire
kill-point win (`CLAUDE.md` Stage 3). Buying precision with the detector's only surviving
robustness advantage is not a trade this project can make.

So the defensible statement is stronger than an apology:

> Precision on this architecture resists every available lever that does not cost
> adversarial margin, and each rejection is a measurement rather than an opinion.

A sixth attempt needs a reason the five do not already cover, and it owes the full
benchmark suite regardless of how small the code change is (§6 below).

---

## 4. What an independent red team should attack first

This is the project's largest limitation and it cannot be closed from inside: every attack
and every camouflage transform was authored or driven by the author (methodology §14). The
kill point removes self-written *rules* and the attack runner removes self-written *base
attacks*, but nobody outside the project has tried to evade this detector.

The useful form of that admission is a brief. Handed the shipped camouflage library, the
harness and the scorer, a red team should be pointed at these first, in this order — each
follows from a measured weakness rather than from imagination.

**1. Transforms outside the shipped seven.** The adaptive adversary searched all 128
subsets of the shipped strategies and their magnitudes and converged rather than running
out of budget (`results/adaptive/notes.md`). The correct reading of that plateau is *these
transforms are exhausted*, never *this detector is robust*. The single highest-value thing
an outsider can do is write a transform that was not in the library, and the harness is
built so that one drops in: camouflage magnitudes are data rather than constants
(methodology §5.3).

**2. Wording that moves *toward* the common templates rather than away from them.** Every
subset containing `rephrase` reads 100%/100% against this detector, because novel wording
is *more* anomalous to an outlier detector, not less (results §4.1). That is a mechanism,
and mechanisms have a direction: it implies an attacker should be paraphrasing an attack
into the most ordinary phrasing available rather than out of it. `mimicry` is the shipped
transform nearest to that idea and it ties at +0.0pt
(`results/killpoint/killpoint_eight_strategies_ambient0.05.md`). Whether a stronger
mimicry — one that lands attack lines on the corpus's highest-frequency templates — breaks
the detector is **untested**, and it is stated here as the hypothesis to hand over, not as
a finding.

**3. The two axes where this system is already the weaker one.** Timing and IP rotation
are known losses (`slow` −8.9pt, `ip_rotate` −11.1pt, `realistic-combo` −13.3pt) and the
optimiser found the system's own 60-minute impossible-travel window from the scores alone
(`results/adaptive/notes.md`). A red team with more compute than one paced replay should
push there, because the constants are evidently discoverable.

**4. The one detection that is not an embedding at all.** Every instance-level camouflage
loss on the synthetic corpus lands on scenario B, impossible travel, which is a
hand-written physics rule with a 60-minute window and a two-octet subnet comparison
(`results/adversarial_results.md`; results §8). It is the most brittle component and the
easiest to reason about from outside.

**5. Attack shapes with little to detect.** Authentic captures hold 100% on all nine
conditions, but they are five distinct captures per scenario of two attack shapes
(`results/kali/injected_notes.md`). The case that could genuinely fail is a *short*
attack with no user identity attached — the web-side burst is the example the project
already knows about, since web traffic is mostly user-less and the per-user model has
nothing to work with there (`CLAUDE.md` Stage 7). More captures of the same shape would
not be a finding; a different shape might be.

The result a red team is most likely to return is a negative one for this project. That is
the correct expectation to set, and it is the reason the brief is written down.

---

## 5. What the field would gain from one reported number

The gap this project addresses is narrow and specific: **open-source SIEMs publish
detection, not degradation**, and all eight peer-reviewed works assembled for review
evaluate on data where the attacker is not trying to hide from the detector under test —
the one with an active adversary targets network traffic rather than logs, and none
compares against a production SIEM ruleset under camouflage (introduction §3).

Suppose degradation-under-evasion were routinely reported: for each detector and each
evasion strategy, how much detection is lost, on a stated corpus, pooled over seeds. Four
things follow, and this project is a small worked example of each.

**Comparisons would stop being ties.** On the clean corpus this detector and Wazuh both
read 100% instance detection, which says nothing. The eight-strategy table is where they
separate, in both directions
(`results/killpoint/killpoint_eight_strategies_ambient0.05.md`). A field that reports only
the clean number is comparing systems at a ceiling.

**Saturation would be visible as saturation.** A 100% that comes from a level-3 rule
firing on every successful login looks identical to a 100% that comes from correlation,
until the threshold is varied — at which point one of them reads 11.1% on clean data
(`results/killpoint/killpoint_paced_ambient0.05.md`). Reporting degradation forces the
distinction.

**Tuning would be audited by default.** Four of the five precision levers here improved
clean data and cost adversarial margin (§3). That failure mode is invisible without the
evasion arm and is presumably common — clean-data tuning is what everyone does, because it
is what everyone measures.

**Claims would be shaped by mechanism rather than by aggregate.** The one win in this
project is legible — literal-string rules lose a reworded line while its embedding does
not move far — and so are the losses. A single aggregate robustness score would have
hidden both, and the eight-row table is what makes each explainable.

The cost of producing this number is not small and should be stated rather than glossed: a
paired kill-point run is roughly 40 minutes of saturating CPU, the paced instrument was
about 6.5 hours for a five-seed run over three strategies, and the two adaptive searches
were roughly 17 and 34 minutes each (`CLAUDE.md` §3, Known Issues and the Stage 6 entries).
That is a working day of compute for a claim that would otherwise be an assumption — which
is the argument for reporting it, not against.

---

## 6. Future work, with what each item actually costs

Every planned stage is closed, and the remaining candidates were measured and declined
rather than left open (`CLAUDE.md`, "Where the work goes now"). So the items below are new
work, and each is priced.

**The price is set by a rule, not by the size of the diff.** Any change to detection,
grouping or scoring must report line-level P/R/F1 against the v1 baseline, instance
detection on the clean corpus, **instance detection under camouflage pooled over ≥5
seeds**, and alert volume (`CLAUDE.md` §4). Item 3 is the expensive one and the one that
is normally skipped. In practice that is the adversarial suite per arm plus, for anything
timing-related, the paced instrument; the run times are in §5 above. A one-line config
change and a new detection module cost the same measurement.

| Item | What it would change | Honest cost |
|---|---|---|
| **Independent red-teaming** (§4) | The largest limitation, and the only one that cannot be closed from inside. Would test whether the optimiser's plateau is a property of the detector or of the transform library | Someone else's time, not compute. No §4 obligation — it measures the existing system |
| **Attack variety, not volume** | A different authentic attack *shape* — a short burst, a different endpoint, a user-less request pattern. Five more identical captures would re-test a saturated metric and would not be a finding | A capture session on the second machine plus one injected re-run. No detection change, so no §4 arm |
| **Faithfulness on stories, not entities** | Everything measured so far is whether an ID, IP or count in a narrative appears in its prompt. Whether the causal order asserted is supported by the log is unmeasured (`results/faithfulness/notes.md`) | Blocked on a judge. An LLM judge would put an unmeasured model inside the measurement and was rejected for that reason (methodology §10.4); human adjudication is the honest alternative and does not scale |
| **A second comparator or a second log domain** | Everything here is sshd-shaped auth traffic compared against one ruleset. A different domain could degrade by a different mechanism entirely — which is the argument that forced the kill point, now pointed at this project's own conclusions (methodology §14) | A new corpus with ground truth, a new comparator deployment, and the full eight-strategy suite re-run against it |
| **A sixth precision attempt** | Nothing, unless it comes with a reason the five rejections do not cover (§3) | Full §4 including the camouflage arm, to demonstrate an improvement four prior arms showed was illusory on clean data |

Two things are deliberately *not* on this list, and both were declined with reasons
recorded rather than forgotten: peer-group baselines (they fix cold start, which no number
in `results/` measures, so a change owing the full suite would demonstrate nothing) and
score calibration (it re-scales without moving a threshold, so it changes no alert by
construction, and every threshold move tried here has been rejected on adversarial
evidence) — `CLAUDE.md` Stage 3.

---

## 7. Closing

The system does what it was built to do: it detects attacks in real authentication logs on
a laptop with no GPU required, groups them into incidents, grounds every technique claim it
makes in a pinned ATT&CK index, and explains itself in prose that no longer invents its own
evidence. None of that is the contribution.

The contribution is a number nobody reports, produced under conditions that make it hard to
flatter: a criterion fixed in version control before the code existed and honoured when it
returned an uncomfortable shape; a comparator run as its own engine rather than
reimplemented; attacks from third-party tooling; one detector-agnostic scorer for both
systems; and a benchmark rule that made four failed precision fixes visible instead of
shippable.

What that produced is one win, four ties and three losses. Against reworded attacks
signature rules break and embeddings do not, and the mechanism is explainable. Against
timing and IP rotation this detector is the weaker system. Under an attacker that optimises
rather than picking from a menu the advantage is negative. Precision resisted five measured
fixes.

A clean sweep against a production SIEM, in a field where nobody publishes this number at
all, would most likely have meant something other than what it claimed. This shape is
smaller, and it is what the measurements say.
