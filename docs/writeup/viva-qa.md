# Viva preparation — hostile questions, honest answers

*Draft. Format is **question → the honest answer → the artifact that backs it**. Tone
follows `docs/DEMO.v1.md`'s honest-answers section: concede the point first, then say what
the measurement actually shows. Every number is cited; nothing here was computed while
writing.*

**Three rules for answering anything in this room.**

1. **Lead with the concession.** Every hard question below has a real point inside it. An
   answer that starts by defending sounds evasive; an answer that starts by agreeing and
   then adds the measurement sounds like someone who has done the work.
2. **Never quote a number without its qualification.** Especially alert volume
   (approximate, ~±0.5% across machines) and the authentic-attack 100% (an attack-shape
   finding).
3. **If you do not know, say so and name what would settle it.** Three answers below end
   that way on purpose.

---

## A. The claim itself

### A1. "`realistic-combo` is a loss, and that is the realistic attacker. So your system is worse than a SIEM against a realistic attacker."

**Yes — on that strategy, against Wazuh at level 3, that is what the measurement says,
and I report it as a loss.** `realistic-combo` costs this system 13.3 percentage points
of instance detection more than it costs Wazuh: **−13.3pt**. It is the largest single
loss in the table and it is the strategy closest to how a real attacker would behave. I
do not have a reading that makes it go away.

Three things belong beside it, and none of them is a rescue.

First, **the tally is what I actually claim**: one win, four ties, three losses across
eight strategies. I do not claim "more robust under camouflage" anywhere, because the
table does not support it. The claim is the mechanism — signature rules break when you
reword an attack; embeddings do not.

Second, **Wazuh's 0.0pt drop on that row is partly a property of its threshold, not of
its robustness.** At level 3 it cannot degrade because it starts saturated: a single
failed login is already a level-5 rule, so it flags every instance without correlating
anything. Raise the threshold to 7 or 10 and it detects 11.1% — one instance in nine — on
the *clean* corpus. So on that row I lose to a system that is flagging the attack by
flagging everything. That is a worse comparison for me than it first looks *and* a worse
comparison for Wazuh; both readings are in the artifact and neither changes the −13.3.

Third, **`realistic-combo` is not actually a strong attack**, which is a finding against
my own suite rather than a defence. When I built an optimiser and let it search the
camouflage space, `realistic-combo` ranked **49th of 106** valid subsets. The optimiser
found something 11.1pt worse for me. So the honest position is not "the realistic
attacker is a loss but only just" — it is "the realistic attacker is a loss, and a
competent attacker does better than that."

> `results/killpoint/killpoint_paced_ambient0.05.md` (the −13.3pt row and the
> L3/L7/L10 table); `results/killpoint/killpoint_eight_strategies_ambient0.05.md` (the
> tally); `results/adaptive/notes.md` (rank 49 of 106).

---

### A2. "Your win is one strategy out of eight. Isn't that cherry-picking?"

**It would be, if I reported the win and not the table.** I report the table first: one
win, four ties, three losses, with the three losses named individually and the biggest of
them called out as the most realistic attacker model.

The reason the roadmap continued on one strategy is that the criterion said so, and it
said so **before any result existed**. The registered kill point was "≥25pt differential
on at least one strategy" — fixed in version control before the evaluation code was
written, with a hard-coded threshold ladder pinned by eleven tests. `rephrase` reads
+31.1pt, so the verdict is CONTINUE as registered. If I had rewritten the criterion after
seeing the shape of the result — in either direction — the whole measurement would be
worthless.

What makes the one win worth having is that it is **a mechanism, not a lucky row**:

- Wazuh's sshd rules match literal strings, so a reworded line leaves the decoder
  entirely and no rule can fire; the embedding of the same line stays near the original.
  That is what a signature engine is *supposed* to do, so the result is explainable.
- It does not depend on the corpus: across a 20× range of background density it reads
  **+31.2 / +31.1 / +31.1**.
- It does not depend on the attacker being fixed: re-tested against an optimiser it reads
  **+35.6pt**, and the optimiser could find nothing better to do to a signature engine
  than reword.

So: one strategy, yes. One *mechanism*, with three independent checks that it is real.

> `results/killpoint/killpoint_eight_strategies_ambient0.05.md`;
> `results/killpoint/killpoint_ambient_sensitivity.md`;
> `results/adaptive_wazuh/notes.md` §1; `CLAUDE.md` §1b for the registered criterion.

---

### A3. "You measured −2.2pt under an optimising attacker. That means you have no advantage at all."

**Under an optimising attacker, in the half of the space that can be measured against
Wazuh, that is correct — the differential is negative and I quote it as negative.**

The detail matters because it shows the measurement was not arranged to flatter me. I ran
the identical search twice: once pointed at Wazuh, once pointed at my own detector.
Pointed at Wazuh it finds `rephrase+ip_rotate` and reads +33.3pt in my favour. Pointed at
me it finds `noise+volume+ip_rotate`, costing me one instance in 45 and costing Wazuh
nothing: **−2.2pt**. I quote the second, because the first is the arm that flatters me.

Two qualifications, and one of them makes my position *worse*:

- **−2.2pt is the smallest non-zero value the metric can take.** With 45 instances the
  step is 2.2pt, so this is one instance. I would not describe it as a collapse.
- **`slow` and `temporal` are excluded from that search space on both sides**, because
  Wazuh correlates on arrival time and a batch replay pins its drop at 0pt by
  construction — the optimiser would converge on a harness artefact. That removes the
  half of the space where I am *weakest*, so **−2.2pt is an optimistic reading**. The
  timing half is measured separately by paced replay and it is a loss for me: `slow`
  −8.9, `realistic-combo` −13.3.

I would also point at what the same optimiser did to my own published worst case on the
synthetic corpus, where timing *can* be searched: it beat `realistic-combo` by 11.1pt,
finding `slow+mimicry` with the gap widened to **61 minutes** — just past my own
60-minute impossible-travel window, which it located from the scores alone. That is a
real weakness of my system, found by my own tooling, and it is in the write-up.

> `results/adaptive_wazuh/notes.md` §2 and §3; `results/adaptive/notes.md`;
> `results/killpoint/killpoint_paced_ambient0.05.md`.

---

## B. The obvious weaknesses

### B4. "Your precision is 0.29. That is unusable."

**On the synthetic corpus, precision is 0.29 with recall 0.86 and F1 0.43, against a rule
baseline at 0.99 / 0.94 / 0.96. On the real corpus it raises 194 incidents for 9 attack
instances. It is the weakest number in the project and I state it as such.**

What I would push back on is that it is an *open* problem. It is a closed negative
result, and that is a different and more useful thing. Five levers were tried against it
and five were rejected:

| Lever | Outcome | Why |
|---|---|---|
| `CONTAMINATION=0.10` | rejected | 2.4× less noise at the same clean instance detection, but degrades `mimicry` 100% → 93% and `realistic-combo` 91% → 87% |
| sequence model keying `is_anomaly` | refused by design | template ids shift under `rephrase` — it would buy precision by destroying the one kill-point win |
| sequence severity shift | inert | identical notable set; promotion grew it 19 → 48 and surfaced nothing new |
| suppression at q0.99 | rejected | best clean numbers of any arm (F1 0.446 → 0.624) and costs `slow` **13.3pt** of instance detection, line rate 0.824 → 0.266 |
| graph loneness (`quiet`, `share@0.50`) | rejected | `quiet` strictly dominated — same attack lines lost, fewer benign ones cleaned; `share@0.50` repeats the q0.99 mistake |

What survived is alert suppression at q0.90: **194 → 147 incidents, precision 0.206 →
0.248**, with recall and instance detection untouched. Real, and modest.

The pattern in that table is the argument. **Four of the five look better on clean data
than the option that shipped.** They were caught by the rule that any detection change
must re-run the camouflage suite over five seeds — a rule that exists precisely because
clean instance detection saturates at 100% and hides the margin camouflage eats first.
So the claim I can defend is: *precision on this architecture resists every available
lever that does not cost adversarial margin, and each rejection is a measurement rather
than an opinion.*

If pressed on why I would not simply raise the threshold anyway: because a missed attack
is unrecoverable and a false positive costs an analyst thirty seconds, and because the
one untried lever — peer-group baselines — fixes cold start, which no number in
`results/` measures, so it could not register as an improvement even if it worked
perfectly.

> `docs/results.v1/evaluation.md` §1 and §5; `docs/results.v1/contamination_retune.md`;
> `results/suppression/suppression.md`; `results/suppression/suppression_adversarial.md`;
> `results/suppression/loneness/notes.md`.

---

### B5. "You wrote the camouflage yourself. You are grading your own homework."

**That is the sharpest criticism of the project and I cannot fully answer it. There has
been no independent red-teaming. Every attack and every camouflage transform was authored
or driven by me, and that limitation cannot be fixed from inside the project — it is
stated as a limitation, not as something I plan to close.**

Four things narrow it, and I would be specific about what each one does and does not buy.

1. **The rules are not mine.** The comparator is the real Wazuh manager running its own
   rules and its own engine in Docker — not a reimplementation of its rule semantics,
   because reimplementing them would put me back in charge of the matching. That removes
   the v1 problem of having written both the attacks and the rules that catch them, where
   the baseline scored F1 0.96 essentially by construction.
2. **The base attacks are not mine either.** For the un-camouflaged case they are real
   `hydra` and `ssh` runs against a real sshd on a separate machine, with ground truth
   captured at generation time. Only the camouflage layer is authored — and that is
   deliberately the layer this project is supposed to own, because measuring camouflage
   is the contribution.
3. **The attacker is not restricted to what I thought of.** I built an optimiser that
   searches the transform space against the detector's own scores. It beat my hand-picked
   worst case by 11.1pt and located my 60-minute travel window without being told it. It
   also found that my "strongest realistic attacker" ranks 49th of 106 — my suite grading
   itself and failing.
4. **The camouflage transforms were fixed in version control before the measurement**,
   so they could not be tuned toward a result.

What none of that buys is a genuinely adversarial third party. If a reviewer wants to
write a transform I did not think of, the search space is shipped library code and the
harness is one command. **An attacker who invents an eighth transform is outside
everything I measured**, and the correct reading of my optimiser's plateau is *these
transforms are exhausted*, never *this detector is robust*.

> `results/adaptive/notes.md` ("What this is not"); `results/kali/injected_notes.md`;
> `docs/FINDINGS.md` §6 and §7; `docs/results.v1/evaluation.md` §Threats to validity.

---

### B6. "Isn't this just Isolation Forest over sentence embeddings? That is not novel."

**The detection method is not the contribution and I say so in the first paragraph of the
design.** Isolation Forest over sentence embeddings is standard, and claiming otherwise
would be dishonest. Attaching an LLM is not novel either — everyone is doing that.

What is uncommon is the measurement. **No open-source SIEM and very little of the
published log-anomaly literature reports how much worse it gets when the attacker
actively tries to hide.** This project reports that on every change, as a gate: a
pre-registered criterion, a third-party comparator running its own engine, third-party
attack tooling, eight camouflage strategies over five seeds, an adaptive attacker, and a
rule that no detection change lands without re-running the camouflage arm.

The concrete evidence that the measurement is the contribution is the *rejections*. Five
precision fixes were measured and rejected, four of them because the camouflage arm
exposed a cost that clean data hid. Nobody publishes those, because publishing them
requires having run all five.

If the question is "what does the system do that a pile of scikit-learn does not" — it
groups anomalies into incidents on an entity graph, enriches them from a pinned ATT&CK
index where the technique metadata comes from the STIX bundle rather than from me, and
narrates them with a structured output whose technique field is validated against the
grounded list. But I would not lead with that. I would lead with the measurement.

> `CLAUDE.md` §1 (North Star, which states this explicitly);
> `results/suppression/`; `results/faithfulness/arms/notes.md`.

---

## C. Methodology

### C7. "Why not HDFS or BGL? Those are the standard labelled benchmarks."

**Because their anomalies are system faults, not adversarial behaviour, and this project
is about adversaries.** HDFS and BGL are LogHub datasets, they are labelled, and that is
exactly why the literature uses them — I understand the appeal of comparability.

Three things go dark if I use them, and they are the three things this project claims:

- **MITRE mapping has nothing to map.** There is no technique ID for a failed block
  replication.
- **Attack narrative has no attacker.** The explanation layer would be describing a disk.
- **Camouflage is meaningless.** You cannot hide a disk failure, because nothing is
  choosing to be there. The entire adversarial track — which is the contribution —
  becomes undefined.

Running on HDFS would benchmark the anomaly-detection layer, which is the one layer I
explicitly do *not* claim as a contribution, while switching off both things that make
the project distinctive.

I chose OpenSSH instead because it contains **real brute force and enumeration from the
open internet** in the log format the pipeline already parses. It has no labels, which I
handle two ways: injecting attacks with exact ground truth into real benign background
(that is the kill-point corpus), and precision@k with manual verification.

If comparability were later required, I would use **BGL, not HDFS** — its per-line labels
drop straight into the existing line-level P/R/F1 harness, whereas HDFS's block-level
labels would force restructuring the whole evaluation for no gain to any claim I make.

One thing I would concede without being pushed: OpenSSH is 66–83% ambient brute force on
*every* day, which is why the corpus builder has to construct the benign background
explicitly rather than assume it. That is a real awkwardness of the corpus and it is
documented.

> `CLAUDE.md` §3b (dataset strategy and the corpus-construction decision);
> `results/killpoint/killpoint_ambient0.05.md` §Corpus.

---

### C8. "Sigma matched nothing, so you switched to Wazuh. Did you pick a weak baseline to beat?"

**No — I switched because Sigma was the *unmeasurable* baseline, not the strong one, and
the switch made the comparison harder for me rather than easier.**

The measurement first. Across all ~3,300 rules in the official SigmaHQ repository, **not
one matches `Failed password`, `Accepted password`, `Invalid user` or `pam_unix`**. Its
210 Linux rules are 122 process_creation, 53 auditd, 8 file_event and 5
network_connection — all needing auditd or Sysmon-for-Linux telemetry this project does
not have. **Zero Linux rules use a frequency or threshold condition**, which is precisely
the rule class the `slow` camouflage exists to defeat.

So Sigma would have scored ~0 recall *before any camouflage*, and a system that detects
nothing cannot exhibit a measurable degradation. Keeping it would have handed me a
meaningless win. The original choice of Sigma was made on packaging convenience — pure
Python, no daemon — which is not a reason that survives an inventory of the rules.

**Wazuh is the harder baseline, not the softer one.** Its `0095-sshd_rules.xml` contains
seven frequency rules written for exactly these lines — rule 5712 is
`frequency=8 timeframe=120 same_source_ip`, tagged T1110 — i.e. rules designed for the
attacks I am injecting, written by people who have never seen my corpus. And it beats me
on three of the eight strategies.

Two further points on the honesty of the swap. **The kill point already named Wazuh as an
option**, so only the ruleset identity changed and the deciding threshold was untouched.
And **the Sigma coverage gap is itself reported** as a finding rather than quietly
dropped: a widely deployed rule format has essentially no coverage of sshd authentication
logs.

> `CLAUDE.md` Decision Log, 2026-08-18 (the Sigma rule inventory and the swap);
> `results/killpoint/killpoint_eight_strategies_ambient0.05.md`.

---

### C9. "Wazuh detects 100% at level 3. How can you claim any advantage?"

**On the clean corpus at level 3, we both detect 100%, and I say that before showing the
camouflaged rows.** The demo is deliberately built that way: the second act is "we both
catch it, and the SIEM hands you one clean alert while we hand you a pile", not "we catch
it and they do not".

What the 100% actually is, checked rather than assumed: **135 of 135 successful-login
alerts in the container's own `alerts.json` are rule 5715 "sshd: authentication success",
level 3.** Wazuh flags the attack's lines by flagging every successful login. It never
establishes that the travel was impossible or that the failures correlate. That is
saturation, not correlation.

Two consequences follow, and I report both:

- **At level 3 it cannot degrade**, so its 0.0pt drops under camouflage are a property of
  the threshold. At levels 7 and 10 it detects 11.1% — one instance in nine — on the
  clean corpus, so its stability there is a floor effect.
- **The saturation is visible live.** In the grid firing, impossible travel is a two-line
  attack, so rewording removes *every* line from Wazuh's decoder and it goes from 100%
  (3/3) to **0% (0/3)** while this system stays at 100%. A 15–25 line brute force always
  leaves a line behind, which is why the other eleven measured cells sit at a ceiling.

I did **not** move to a higher alert level to make the numbers look better, even though
there was a ready-made argument for it once paced replay existed. Changing the deciding
threshold after seeing results is the thing the kill point exists to prevent, and the
higher levels do not favour me anyway — the best differential across every level is
+11.1pt, still under the registered bar.

> `results/bakeoff/bakeoff.md` (rule 5715, 135/135; the +100pt cell);
> `results/killpoint/killpoint_paced_ambient0.05.md` (the L3/L7/L10 table);
> `CLAUDE.md` Decision Log, 2026-08-20.

---

## D. Follow-ups they are likely to reach for

### D10. "Your alert volume claim — you say you are quieter than Wazuh. Is that a fair comparison?"

**Partly. The direction is real; the unit is not identical and I flag that.** On the clean
kill-point corpus this detector raises **1,415 incidents** against Wazuh's **4,546
alerts** at its own default level, roughly **3.2×**, and the gap holds across all nine
conditions. The adaptive run reproduces the ratio (1,440 flagged lines against 4,563
alerts).

Three qualifications, unprompted:

- **These are our incidents against its alerts**, which are not the same unit. The
  direction is the claim, not the digits.
- **Alert-volume figures in this project reproduce to about ±0.5% across machines;
  detection rates are exact.** A committed artifact stopped reproducing on one condition
  (703 flagged lines / 670 incidents against a fresh 705 / 673) and the cause was **CPU
  thread count** — BLAS reorders its reductions, embeddings differ in the last float
  bits, and near-tied *benign* rows cross the contamination cutoff. Every flipped line was
  benign, which is why line detection (0.776) and instance detection (0.911) were
  bit-identical. I declined to pin the thread count, because that would make which lines
  get flagged depend on an environment variable.
- **Precision is still my weakness in absolute terms.** Being quieter than a saturated
  SIEM is not the same as being precise.

> `results/killpoint/killpoint_ambient0.05.md` §Alert volume;
> `results/adaptive_wazuh/notes.md` §5; `results/adversarial_notes.md`.

---

### D11. "You claim embeddings are robust, but your impossible-travel detection is a hand-written rule."

**Correct, and I state it as a limitation in the results chapter rather than waiting to be
asked.** The embedding layer alone detects **0%** of impossible-travel instances; the full
system reaches 100% only because of the rule. The reason is structural: `template_message`
masks IPs before embedding, so the two legs of the login are textually identical and embed
to the same vector. No semantic model can separate them.

It gets worse before it gets better, and both halves are in the artifact. **Every
instance-level camouflage loss on the synthetic corpus is confined to that one rule** —
`slow` pushes the two legs past its 60-minute window, `ip_rotate` frequently lands both
legs in the same /16 so its two-octet subnet comparison sees no change. My measured
adversarial weakness is the single hand-written rule in the system, not the model.

The half that goes the other way: under `rephrase` the rule is defeated outright — novel
wording no longer matches its keyword — and the attack is still caught, because unusual
phrasing is exactly what an outlier detector responds to. **The two layers fail on
opposite inputs.** That is defence in depth by accident rather than by design, and I would
describe it that way.

Never claim that embedding-based detection catches impossible travel.

> `docs/results.v1/evaluation.md` §2; `results/adversarial_results.md`.

---

### D12. "Can the LLM hallucinate? What stops it inventing a technique ID?"

**It did, and I only know that because I measured it. The design constraint I had written
down — the LLM never invents technique IDs — was false.** First measurement: **47 of 142**
technique mentions on the synthetic corpus and **119 of 197** on OpenSSH were fabricated,
several of them real ATT&CK identifiers that had been revoked or deprecated, and seven
narratives fabricated an entire incident-summary block in the system's own voice.

The retrieval was always grounded; the *prose* was not, because until then nothing read it
back. An instruction in a prompt is not an enforcement mechanism.

Two changes fixed it, and the cheaper one did most of the work:

- **A wording bug.** The empty-match fallback said "no known technique matched" while the
  instruction still demanded which ATT&CK stage the incident progressed through — the
  prompt asked for a stage with nothing to answer from. Stating that "none applies" is the
  correct answer took the control arm from **24/24 and 107/107 invented to 0 and 0**, with
  narrative length unchanged.
- **Structured JSON with the technique field validated** against the grounded list, and a
  rejected ID dropped before rendering and shown to the analyst as a rejection.

Result: **0 of 65 and 0 of 58** invented, fully-faithful narratives 57/94 → 88/94 and
94/193 → 187/193, fabricated summary blocks 7 → 0. Confirmed on a second model — llama3
reads 0 invented of 63 with zero validation drops.

Two things I would volunteer. The validation **fired once in 287 narratives**, so most of
the gain is the clearer task rather than the guard catching a determined hallucinator —
the guard's worth is that it does not depend on that compliance holding for the next
model. And **faithfulness is measured on entities, not stories**: a narrative can ground
every ID, IP and count and still assert a causal order the log does not support. Fixing
that needs a judge, and an LLM judge would put an unmeasured model inside the measurement.

**Practical rule:** quote `mitre_techniques` — the grounded retrieval — never a stored
narrative's technique IDs. Narratives generated before this change still carry invented
ones.

> `results/faithfulness/notes.md`; `results/faithfulness/arms/notes.md`;
> `results/routing/notes.md` (the llama3 arm).

---

### D13. "Your authentic attacks score 100% under every camouflage condition. Isn't that too good to be true?"

**It is not a robustness win and I would correct the framing before answering.** It is an
*attack-shape* finding: real `hydra`/`ssh` attacks hold 100% instance detection on all
nine conditions (50/50 pooled, 25/25 per scenario), while the matched synthetic arm in the
same run loses instances on four — `slow` 86.7%, `rephrase` 95.6%, `ip_rotate` 93.3%,
`realistic-combo` 77.8%.

The reason is that **the camouflage library was authored around the synthetic attack
shape** — a homogeneous burst of near-identical `Failed password` lines on a freshly-drawn
user — and authentic instances are the opposite. `rephrase` rewords `Failed password` and
`Accepted password`; an authentic brute-force instance has one such line and an authentic
enumeration instance has none, so rewording cannot remove the last flagged line. That the
synthetic arm *does* lose instances in the same run is what proves the transforms are
genuinely being applied rather than silently doing nothing to both arms.

What I would concede in the same breath:

- **The sample is five distinct captures per scenario**, placed across five seeds. The
  ≥5-seed rule is satisfied, and the effective independent sample is five, not
  twenty-five.
- **Scenario B has no authentic capture** — its distant leg needs a second geographic IP
  and stays synthetic by necessity.
- **A real hydra run leaves far less evidence than the synthetic generator**: 20 attempts
  against a rate-limiting modern sshd produce 5 log lines, exactly one a `Failed
  password`, against 15–25 synthetic ones. Same instance detection, much thinner margin.
- An earlier three-capture run read the line rate *higher* for authentic attacks; the
  richer captures **reversed** that (45.0% over 1,080 lines against synthetic's 52.0%).
  I report the reversal rather than the friendlier earlier figure.

> `results/kali/injected_notes.md` (§v2 for the ten-capture run and the reversal).

---

### D14. "Where does the −11.1pt on `ip_rotate` come from? Is it a bug?"

**No, it is the mechanism working against me, and it is explainable in one sentence:
spreading an attack across many source IPs defeats per-user embedding context, while
Wazuh's per-IP frequency rules simply fire on whichever IP still crosses the threshold.**

On the synthetic corpus there is a second, sharper reason, and it lands on the same weak
spot as everything else: rotating *both* legs of an impossible-travel login into the
documentation IP ranges frequently puts them in the same /16, and the rule compares only
the first two octets — so it sees no change and stays silent. That is a probabilistic
defeat of the hand-written rule, not an attack on the embeddings.

The size of the loss depends on the background: the sensitivity sweep gives **−13.3 to
−8.9** across a 20× range of ambient density. It is a loss at every density, and the
write-up carries the range rather than the friendlier end.

> `results/killpoint/killpoint_ambient_sensitivity.md`; `results/adversarial_results.md`.

---

### D15. "How much of this is reproducible? Could I re-run it?"

**Detection rates reproduce exactly. Alert-volume figures reproduce to about ±0.5% across
machines, and I know why.**

A committed artifact from 2026-08-18 stopped reproducing on exactly one condition:
`realistic-combo` read 703 flagged lines / 670 incidents committed, against 705 / 673 on a
fresh run — while line detection (0.776) and instance detection (0.911) were bit-identical
in both. I chased it through three checks. All 45 camouflaged corpora rebuild
byte-identical at both commits; the parsed records are identical under both regex
versions; and the artifact's *own* commit, run today, gives the *new* numbers. Same code,
different answer — so the environment changed, not the repository.

The cause is **CPU thread count**: 703/670 at `OMP_NUM_THREADS` ≤ 8, 705/673 at 16–20
(this box, an i7-13650HX 14c/20t, defaults to 20). BLAS and torch reorder their reductions
with the thread count, embeddings differ in the last float bits, and near-tied rows cross
the contamination cutoff. **Every flipped line is benign** — filler in the `admin` bucket
that the `noise` strategy floods with near-duplicates — which is exactly why detection
rates never moved.

I **declined to pin the thread count**, even though it would make the old numbers come
back, because that would make which lines get flagged depend on an environment variable —
a detection-affecting knob smuggled in as configuration, and every other result in
`results/` was produced without it. The artifact was re-cut at the machine's natural
configuration instead, and the caveat is stated in the limits section.

> `results/adversarial_notes.md`.

---

### D16. "What would you do next?"

Three things, in order of how much they would change the claim, and I would be clear that
**none of them is unfinished work** — every planned stage is closed and the remaining
items were measured and declined rather than left open.

1. **Independent red-teaming.** The single largest limitation. Hand the shipped camouflage
   library and the harness to someone else and let them write a transform I did not think
   of. My optimiser's plateau means *these transforms are exhausted*, never *this detector
   is robust*.
2. **Attack variety rather than attack volume.** The authentic captures are five per
   scenario of two attack shapes. Where I would spend the next capture session is a
   *different shape* — a short burst, a different endpoint, a 403 instead of a 401 —
   because a short user-less burst is the case that could genuinely fail to detect. Five
   more identical bursts would not be a finding.
3. **Faithfulness on stories, not entities.** Everything measured so far is whether an ID,
   IP or count in the narrative appears in the prompt. Whether the causal order it asserts
   is supported by the log is unmeasured, and doing it properly needs a judge I am not
   willing to put inside my own measurement.

What I would **not** do is a sixth attempt at precision without a reason the five
rejections do not already cover.

> `results/adaptive/notes.md`; `results/kali/injected_notes.md`;
> `results/faithfulness/notes.md`; `CLAUDE.md` §3, "Where the work goes now".

---

## E. One-line fallbacks

If a question lands somewhere unrehearsed, these are true and safe:

- **On the claim:** "One win, four ties, three losses. The win is `rephrase` at +31.1pt
  and it is a mechanism; the biggest loss is `realistic-combo` at −13.3pt and it is the
  most realistic attacker."
- **On any advantage claim:** "Under an optimising attacker the conservative differential
  is −2.2pt — negative — and that is the number I quote."
- **On precision:** "0.29. Five levers measured, five rejected, four of them because
  clean data hid a cost the camouflage suite could see."
- **On rigging:** "The rules are third-party and run in their own engine, the attacks are
  third-party tooling, and the criterion was in git before the code. The camouflage is
  mine, there has been no independent red-teaming, and that is a stated limitation."
- **On an alert-volume number:** "Approximate — those reproduce to about ±0.5% across
  machines. Detection rates are exact."
- **On any number I cannot place:** "I would rather check the artifact than guess — it is
  in `results/`, and `docs/FINDINGS.md` points at the file."
