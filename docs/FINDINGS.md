# Findings

**Read this before anything else in the repository.** It is the front page of the
write-up: the claim this project can defend, the three numbers that qualify it, and
pointers to the artifact behind each one. Everything else — the roadmap in
`CLAUDE.md`, the stage-by-stage engineering, the 800-odd tests — exists to make these
numbers trustworthy, not to enlarge them.

---

## 1. The claim

> Against **reworded** attacks, signature rules break and embeddings do not — a real,
> explainable, reproducible mechanism. Against **timing** and **IP rotation** the
> embedding detector is the *weaker* system. Under an attacker that **optimises**
> rather than picking from a fixed menu, the advantage disappears entirely. And
> **precision** resists five separate fixes, each measured and rejected because it cost
> adversarial margin.

This is deliberately narrower than "more robust to camouflage", which the measurements
do not support. It is stated first because a narrow claim stated first reads as rigour,
and the same claim discovered by a reader reads as concealment.

Not everything here is qualified, though. **Four results are unambiguous and are stated
as wins in §4** — they are measured on this system alone or on the comparator's own
output, so no differential can take them back.

## 2. The three numbers that qualify it

| | Number | Where |
|---|---|---|
| The full tally across eight camouflage strategies | **1 win, 4 ties, 3 losses** | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| `realistic-combo` — the strategy closest to a real attacker — is a **loss** | **−13.3pt** | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Under an attacker that optimises rather than choosing from a menu, the conservative differential is **negative** | **−2.2pt** | `results/adaptive_wazuh/notes.md` |

A **differential** is how much more the third-party SIEM's detection dropped than ours
under the same camouflage. Positive means we held up better; negative means it did.
Measured in **percentage points of instance detection** — the share of attack instances
found at all — pooled over 5 seeds.

## 3. The eight-strategy tally in full

Against **Wazuh** (the real manager running its own rules and engine, not a
reimplementation), on the real LogHub OpenSSH corpus with attacks injected, pooled
over 5 seeds at `ambient_ratio=0.05`.

| Strategy | Ours Δpt | Wazuh Δpt | Differential | |
|---|---|---|---|---|
| `rephrase` | +2.2 | +33.3 | **+31.1** | the entire result |
| `mimicry` | +0.0 | +0.0 | +0.0 | tie |
| `noise` | +0.0 | +0.0 | +0.0 | tie |
| `temporal` | +0.0 | +0.0 | +0.0 | tie |
| `volume` | +0.0 | +0.0 | +0.0 | tie |
| `slow` | +8.9 | +0.0 | **−8.9** | **loss** |
| `ip_rotate` | +11.1 | +0.0 | **−11.1** | **loss** |
| `realistic-combo` | +13.3 | +0.0 | **−13.3** | **loss** |

The pre-registered criterion (`CLAUDE.md` §1b, fixed before any code was written) was
≥25pt on at least one strategy. `rephrase` clears it, so the verdict is **CONTINUE** —
but one win, four ties and three losses is what the table says, and that is the sentence
that belongs in the abstract.

### Why the one win is a mechanism and not luck

Wazuh's sshd rules match literal strings — `Failed password`, `Invalid user`. Rewording
the message drops the line out of the decoder entirely, so no rule can fire on it. A
sentence embedding of a reworded line stays near the original in vector space, so the
detector still ranks it an outlier. That is exactly what a signature engine should be
expected to do, which makes it explainable rather than surprising.

It is also **stable**: measured across a 20× range of background density it reads
+31.2 / +31.1 / +31.1 (`results/killpoint/killpoint_ambient_sensitivity.md`), and
re-tested against an attacker allowed to search rather than pick, it reads **+35.6pt** —
and the optimiser could find nothing better to do to a signature engine than reword
(`results/adaptive_wazuh/notes.md`).

### Where this system is the weaker one

- **`ip_rotate` −11.1pt** (range −13.3 to −8.9 across background densities). Spreading
  an attack over many source IPs defeats per-user embedding context; Wazuh's per-IP
  frequency rules simply fire on whichever IP still crosses the threshold.
- **`slow` −8.9pt** and **`realistic-combo` −13.3pt**, both measured by wall-clock-paced
  replay because Wazuh correlates on *arrival* time — batch replay would pin its drop at
  0pt by construction and produce an artefact rather than a measurement.
- **Under an optimising attacker, −2.2pt.** The same search was pointed at *both*
  systems; the arm that flatters us (optimising against Wazuh) is not the one quoted.
  Pointed at this detector it finds a plan costing us one instance in 45 and costing
  Wazuh nothing. Note that `slow` and `temporal` are excluded from that search space on
  both sides (the instrument cannot ask the question of an arrival-time-keyed SIEM),
  which removes the half of the space where this detector is weakest — so −2.2pt is
  itself an optimistic reading.
- On the synthetic corpus, where timing strategies *can* be searched, the optimiser beat
  this project's own published worst case by **11.1pt** (`realistic-combo` 84.4% against
  the searched plan's 73.3% instance detection), finding `slow+mimicry` with the gap
  widened to 61 minutes — i.e. it located the system's own 60-minute impossible-travel
  window from the scores alone (`results/adaptive/notes.md`).

## 4. Four results that are wins, and are stated as wins

The three qualifying numbers above are all *differentials* — this system measured against
another. These four are not: each is measured on this system alone, or on the
comparator's own output, so there is no arm in which they come back negative. They were
under-stated in earlier drafts, which is its own kind of inaccuracy.

**1. Alert volume flipped v1's story — we are not the noisier system on real data.**
On the clean kill-point corpus this detector raises **1,415 incidents** against Wazuh's
**4,546 alerts** at its own default level — roughly **3.2×** more from the SIEM, and the
gap holds across all nine camouflage conditions. Precision is still this project's
weakest number in absolute terms (0.29 line-level), and it is worth being precise about
the comparison: these are *our incidents* against *its alerts*, not the same unit. But
the direction is the opposite of what v1 assumed, and it is measured on real traffic.
`results/killpoint/killpoint_ambient0.05.md`

**2. The comparator's headline score is level-3 saturation, not correlation.**
Wazuh reads 100% instance detection at level 3 because a single successful login is
already an alert (rule 5715) — it flags the attack's lines without ever correlating
them. Raise the threshold to level 7 or 10 and it detects **11.1% — one instance in nine
— on the *clean* corpus**, before any camouflage. So its robustness at L3 is a ceiling
effect and its stability at L7/L10 is a floor effect. This was checked rather than
assumed, and it is a finding about the comparator that no differential expresses.
`results/killpoint/killpoint_paced_ambient0.05.md`

**3. The LLM stopped inventing MITRE technique IDs, and it is measured on two corpora
and two models.** The system's stated design constraint — the LLM never invents
technique IDs — was *false* when first measured: **47 of 142** technique mentions on the
synthetic corpus and **119 of 197** on OpenSSH were fabricated, several of them real but
revoked ATT&CK identifiers. Rewording the empty-match prompt plus structured JSON output
with the technique field validated against the grounded list takes that to **0 of 65 and
0 of 58**, with the fabricated incident-summary blocks gone (7 → 0). Confirmed on a
second model (llama3 as well as phi3). A constraint that was an assertion is now an
enforced property with a regression harness behind it. `results/faithfulness/arms/notes.md`

**4. Authentic attacks from real tooling hold 100% instance detection under every
camouflage condition.** Real `hydra` and `ssh` runs against a real sshd on a separate
machine, ground truth captured at generation time, injected into the real OpenSSH
background: **50/50 pooled per condition, 25/25 per scenario, across all nine
conditions.** State the qualification with it — this is an *attack-shape* finding, since
the camouflage library was authored around the synthetic attack shape and grips
authentic heterogeneous instances less well — but the end-to-end result is that
third-party attack tooling does not evade this detector.
`results/kali/injected_notes.md`

**And the method itself is a result.** Five precision levers measured and rejected (§5),
a kill point registered before the code existed and honoured when it returned an
uncomfortable shape, a comparator run as its own engine rather than reimplemented, and
a camouflage arm made mandatory on every detection change. Almost nobody publishes the
rejections, because doing so requires having run all five.

## 5. Precision is a measured negative result, not an open task

Precision is 0.29 with 94 incidents for 9 attacks on the synthetic corpus, and 193
incidents on the real corpus. **Five levers were tried against it and five were
rejected**, four of them because clean data hid a cost that only the camouflage suite
could see:

| Lever | Outcome | Why |
|---|---|---|
| `CONTAMINATION=0.10` | rejected | degrades `mimicry` 100%→93%, `realistic-combo` 91%→87% |
| Sequence model keying `is_anomaly` | refused by design | template ids shift under `rephrase`, destroying the one win |
| Sequence severity shift | inert | identical notable set; promotion grew it 19→48 surfacing nothing new |
| Suppression at q0.99 | rejected | best clean numbers of any arm (F1 0.446→0.624), costs `slow` 13.3pt |
| Graph loneness (`quiet`, `share@0.50`) | rejected | `quiet` strictly dominated; `share@0.50` repeats the q0.99 mistake |

What survived is alert suppression at q0.90: on the real corpus **194 → 147 incidents**
and precision **0.206 → 0.248**, with recall and instance detection untouched. Real, and
modest.

So the defensible claim is stronger than "precision is bad and we did not fix it":
*precision on this architecture resists every available lever that does not cost
adversarial margin, and each rejection is a measurement rather than an opinion.*
Artifacts: `results/suppression/`, `docs/results.v1/contamination_retune.md`.

## 6. What makes these numbers worth believing

Each of these removes a specific way the author could have graded their own homework:

- **The kill point was pre-registered** — thresholds, deciding quantity and deadline
  fixed in git before any Stage 1 code existed, and never moved after seeing results
  (`CLAUDE.md` §1b).
- **The rules are third-party and executed by their own engine** — the real Wazuh
  manager in Docker, not a reimplementation of its rule semantics. Sigma was measured
  first and dropped because not one of ~3,300 rules matches an sshd auth line; that gap
  is itself reported.
- **The attacks are third-party too, for the un-camouflaged case** — real `hydra`/`ssh`
  runs against a real sshd on a separate machine, with ground truth captured at
  generation time. Only the camouflage layer is authored, which is the layer this
  project is supposed to own.
- **Both systems are scored by one detector-agnostic scorer** on the identical corpus
  files.
- **No change to detection, grouping or scoring lands without the camouflage suite over
  ≥5 seeds** (`CLAUDE.md` §4). Four of the five precision rejections above were bought
  by that rule.
- **The evaluation track may never be imported by the pipeline**, enforced statically in
  `tests/test_layering.py` rather than by convention.

## 7. Limits, stated here rather than found later

- **Alert-volume figures reproduce to about ±0.5% across machines; detection rates are
  exact.** Incident and flagged-line counts shift with CPU thread count — BLAS reorders
  its reductions, embeddings differ in the last float bits, and near-tied *benign* rows
  cross the contamination cutoff. Diagnosed and re-cut in `results/adversarial_notes.md`.
  Quote an alert-volume number as approximate and name the machine.
- **No independent red-teaming.** Every attack and every camouflage transform was
  authored or driven by the author. This cannot be fixed from inside the project.
- **The authentic-attack sample is small**: 5 distinct captures per scenario, placed
  across 5 seeds. Instance detection is 100% on all nine camouflage conditions there,
  but that is an *attack-shape* finding — the camouflage library was authored around the
  synthetic attack shape and has less grip on authentic heterogeneous instances — not a
  robustness win (`results/kali/injected_notes.md`).
- **Impossible travel is detected by a hand-written rule, not by embeddings.** Both
  login legs are identical vectors after IP masking. Never claim otherwise.
- **Narrative faithfulness is measured on entities, not stories.** Invented MITRE
  technique IDs went from 47/142 and 119/197 to **0 and 0** under structured, validated
  output — but a narrative can ground every ID, IP and count and still assert a causal
  order the log does not support (`results/faithfulness/`).
- **The `volume` camouflage row partly measures an attack that stopped rather than one
  that hid** — on some seeds it thins a 6-line enumeration to 2 lines. No verdict rests
  on it.

## 8. Where the artifacts are

| Question | File |
|---|---|
| The eight-strategy tally | `results/killpoint/killpoint_eight_strategies_ambient0.05.md` |
| The registered verdict and its batch half | `results/killpoint/killpoint_ambient0.05.md` |
| The timing half (paced replay) | `results/killpoint/killpoint_paced_ambient0.05.md` |
| Does the win depend on the corpus? | `results/killpoint/killpoint_ambient_sensitivity.md` |
| The optimising attacker | `results/adaptive/notes.md`, `results/adaptive_wazuh/notes.md` |
| Live side-by-side demo, two machines | `results/bakeoff_live/notes.md`, `results/bakeoff/bakeoff.md` |
| Authentic attacks from real tooling | `results/kali/injected_notes.md` |
| Precision: the five rejections | `results/suppression/`, `results/suppression/loneness/notes.md` |
| LLM hallucination, measured and fixed | `results/faithfulness/arms/notes.md` |
| Reproducibility caveat | `results/adversarial_notes.md` |
| Full project state, roadmap, decision log | `CLAUDE.md` |
