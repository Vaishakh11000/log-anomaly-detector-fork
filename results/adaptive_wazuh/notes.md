# Reading the adaptive-vs-Wazuh run

Interpretation, kept out of the generator on purpose (same rule as
`results/bakeoff/notes.md`): a generator that writes conclusions is scripting the
narrative, which CLAUDE.md §8 lists as an anti-goal. The tables in
`adaptive_wazuh.md` are computed; the reading below is authored.

Run: 2026-09-04, 34.0 minutes of CPU, 92 detector/SIEM queries, 5 held-out seeds
neither search saw, real LogHub OpenSSH corpus at `ambient_ratio=0.05`, Wazuh
manager up throughout.

## 1. The kill point's one win survives an optimising attacker, and grows

`rephrase` was registered at **+31.1pt** against a fixed attacker. On five fresh
seeds here it reads **+35.6pt**: Wazuh drops 100% → 64.4% instance detection
while this detector stays at 100%. The mechanism is unchanged and is visible in
the line rates in the same table — Wazuh keeps 29.5% of the attack's lines
against 89.0% clean, because its sshd decoder matches literal strings and a
reworded line falls out of it.

**The search could not beat plain `rephrase`.** Every one of the 16 subsets
containing `rephrase` ties at 66.7% instance detection on the search seed; the
optimiser could only break the tie on the line rate, and picked
`rephrase+ip_rotate` for 32.4% against `rephrase` alone at 37.0%. That tiebreak
**did not transfer**: held out, the searched plan reads +33.3pt and plain
`rephrase` reads +35.6pt. A 2.3pt overfit on a metric that moves in 2.2pt steps
is noise, but it is the right kind of noise to show — it is exactly what the
held-out split exists to catch, and it caught it.

So the honest statement is that the differential is a property of the
*mechanism*, not of the attacker's cleverness: rewording is the whole result,
and an attacker allowed to optimise finds nothing better to do to a signature
engine than reword.

## 2. The conservative differential is −2.2pt, and that is the number to quote

An attacker optimising against Wazuh flatters us. Pointed at this detector, the
identical search finds `noise+volume+ip_rotate [volume_keep=1.0]`, which costs us
**2.2pt** (one attack instance in 45) and costs Wazuh **nothing** — a −2.2pt
differential. That is the smaller of the two adaptive rows and is what the
project may claim under an optimising attacker.

Two things stop that being a dramatic finding in either direction. It is one
instance: at 45 instances the metric's step is 2.2pt, so this is the smallest
non-zero value it can take. And `slow` is outside this search space (§3), which
removes the transform that actually hurts this detector — the synthetic-corpus
search found `slow+mimicry` and cost 11.1pt there.

The same plan **improves** Wazuh's line detection, 89.0% → 96.7%. Why is not
established by this run; the direction is consistent with the kill point's
`ip_rotate` row, where Wazuh loses nothing and we lose ground.

## 3. What was taken out of the space, and why it is not a choice

`slow` and `temporal` are excluded from **both** sides. Wazuh correlates on
arrival time (Decision Log 2026-08-18), so a batch-replayed corpus is
simultaneous to it and its drop under a timing strategy is 0pt by construction.
An optimiser handed that space converges on the artefact within a handful of
queries and reports a spectacular differential that measures the harness.
`WazuhOracle` raises rather than scoring such a plan, and a test pins it.

The cost is stated plainly rather than buried: this is the half of the space
where we are strong, so the tables here are **not** a statement of how bad
camouflage gets for this detector. The timing half is measured, by
`logdet-paced-killpoint`, and it is a loss for us (`slow` −8.9,
`realistic-combo` −13.3).

## 4. A limit of the search itself, found by the held-out split

The detector-arm winner carries `volume_keep=1.0`, and at that setting `volume`
**deletes nothing** — `reduce_volume` keeps every middle event. So the winning
plan is materially `noise+ip_rotate`, except that `volume` still consumes draws
from the seeded RNG and therefore shifts every later random choice. Plain
`noise+ip_rotate` scored 100% on the same search seed; the "improvement" the
hill climb found is largely a different draw of the same corpus, not a stronger
attack.

That is a real weakness of hill climbing a discrete, 9-instance objective, and
it is worth recording rather than smoothing over: **the optimiser can select a
no-op knob because it perturbs the random stream.** The held-out evaluation is
what exposes it — 2.2pt on fresh seeds against 22.2pt on the search seeds.

## 5. Alert volume reproduces the kill point's flip

On the clean corpus Wazuh emits **4,563** alerts against our **1,440** flagged
lines, roughly 3.2× — the same ratio the kill point recorded. Our volume rises
to 2,095 under the anti-detector plan, which is the documented behaviour: novel
or unfamiliar traffic is more anomalous, so robustness is paid for in noise.
Precision remains this project's weakness.

## 6. What this run does not say

- Both oracles hand the attacker true detection rates over **labelled** attack
  lines. Upper bound on evasion for both systems, not a field estimate.
- Wazuh is read at level ≥3 only. The kill point reports L3/L7/L10; the higher
  levels are a floor effect on this corpus (11.1% on clean data), and shopping
  for a level after seeing a result is the thing §1b exists to prevent.
- The space is the shipped transforms and their magnitudes. A plateau means
  *these transforms are exhausted*, never *this system is robust*.
- The registered §1b criterion is untouched by any of this. It was decided on
  2026-08-19 at +31.1pt against a fixed attacker; this is a re-test that agrees,
  not a re-run of the decision.
