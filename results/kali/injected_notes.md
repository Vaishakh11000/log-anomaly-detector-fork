# Authentic Kali attacks in the real background — reading the result

Interpretation kept out of the generator (bake-off precedent). Numbers in
`injected/injected.md` and `injected/injected.json` are computed; the reading
below is authored.

Run: 2026-09-04, 248s, 5 seeds, ambient ratio 0.05.
Command: `uv run python results/kali/injected_run.py --seeds 5`

This is the measurement `results/kali/notes.md` named as its next step. The
first authentic captures were scored **standalone** — a ~100-line file that is
almost entirely the attack itself — and read 0% instance detection on brute
force and 33% on enumeration. That reading said the dominant cause was the
corpus rather than the detector: an attacked account whose only lines are the
attack has no benign per-user baseline, so the burst *is* that account's norm
and a per-user outlier detector ranks it an inlier.

Here the same captured lines are injected into the real OpenSSH benign
background, at the same ambient ratio, seeds and scorer as a matched synthetic
arm built by `corpus_openssh.build_killpoint_corpus`. Only the origin of the
attack lines differs between the arms.

## The headline

| scenario | authentic, standalone | **authentic, injected** | synthetic, injected |
|---|---|---|---|
| A brute force | 0% (0/3) | **100% (15/15)** | 100% (15/15) |
| C enumeration | 33% (1/3) | **100% (15/15)** | 100% (15/15) |

**The confound was the corpus, and removing it closes the whole gap.** On the
registered metric — instance detection — authentic attacks in a real background
score exactly what synthetic ones score, at every one of the five seeds. The
0%/33% standalone figures measured a corpus with no baseline in it, and
`results/kali/notes.md`'s refusal to quote them as this detector's score on real
attacks was correct.

## The line rate is higher for authentic — and that is not a win

| scenario | authentic line rate | synthetic line rate | authentic attack lines | synthetic attack lines |
|---|---|---|---|---|
| A | 60.0% (45/75) | 26.5% (91/343) | 75 | 343 |
| C | 93.7% (89/95) | 86.0% (141/164) | 95 | 164 |

**Do not read this as "the detector finds authentic attacks more easily".** The
two rates are computed over different populations, and the difference is the
populations rather than the detector:

- An authentic hydra instance is **5 heterogeneous lines** — a disconnect, a
  `pam_unix` auth failure, one `Failed password`, a connection close — several
  of which are individually rare in this background, so a high fraction flags.
- A synthetic instance is **15-25 near-identical `Failed password` lines**. They
  are self-similar, so an outlier detector ranks most of them as inliers. That
  is this project's known precision weakness seen from the ratio side, and it is
  why the synthetic A row reads 26.5%.

So the authentic arm's higher rate sits on a **4.6× smaller denominator**. The
absolute evidence available is the number that matters, and it goes the other
way.

## The genuine finding from the standalone run survives, now with a control

A real hydra run of **20 attempts** against a rate-limiting modern sshd
(OpenSSH 9.x, `srclimit_penalise`) leaves **5 log lines, exactly one of them a
`Failed password`**. The synthetic generator writes 15-25 `Failed password`
lines for the same nominal attack. Authentic brute force therefore hands the
detector roughly a fifth of the evidence, and this is a property of modern sshd
rather than of the capture procedure.

It is still detected 15/15 here — one surviving flagged line is enough to call
an instance detected — but the margin is thinner than the synthetic arm's, and
that is the honest way to state the result: **same instance detection, much less
evidence behind it.**

Enumeration shows the same rate limiter more sharply, and here part of it *is*
the capture procedure. The three C runs were fired back to back from one source
IP, so the penalty activated during C_1 and **C_2 and C_3 contain no
`Invalid user` lines at all** — 6 and 3 `drop connection … penalty` lines
respectively. Across all three instances, 12 of 19 authentic C lines are penalty
drops rather than probes. The next capture run should space instances past the
penalty window or use distinct source IPs; until then the C rows describe an
enumeration that sshd mostly refused to let happen.

## Alert volume

| arm | corpus lines | flagged lines (mean over seeds) |
|---|---|---|
| authentic | 2,517 | 249 |
| synthetic | 2,602 | 275 |

Both arms share the background, and the attacks are ~1% of the corpus, so this
is essentially the same false-positive load in both — the known ~10% flagged
rate on this corpus, not an effect of the attack origin.

## What is real here and what is authored

- **Real:** every background line; and every attack line verbatim as a modern
  sshd wrote it in response to real hydra/ssh traffic — message text, process,
  pid, and the sub-second spacing between the lines of one instance.
- **Authored:** which day and time of day each instance is injected at, drawn
  from the same distribution the synthetic generators use so neither arm gets
  easier placement.
- **Deliberately not rewritten:** the source IP stays `127.0.0.1` (the captures
  really were against Kali's own sshd, and `template_message` masks every IP
  before embedding, so the detector never sees it); the target account stays
  `root`, which needs no retargeting because `root` has **68 lines of genuine
  history** in this background — comfortably above `MIN_SAMPLES_PER_USER`, so it
  gets a real per-user model out of real corpus traffic. That is exactly the
  baseline the standalone capture lacked.

## Limits — read these before quoting the 100%

1. **The five seeds are five placements of the *same three* captured attacks,
   not fifteen independent attacks.** Seeds vary the background sample and the
   injection time; they cannot vary the attack, because there are only three
   captures per scenario. The synthetic arm *does* generate fresh attacks per
   seed, so its 15/15 is over 15 distinct instances and the authentic arm's is
   over 3 instances placed 5 ways. The pooling is still worth doing — it shows
   the result is not one lucky placement — but the effective independent sample
   is 3, and §4's ≥5-seed rule is satisfied in letter rather than in the spirit
   that matters here. More captures is the fix.
2. **No camouflage.** This is the clean-corpus comparison only. §4 item 3 —
   instance detection under camouflage, applied to authentic lines — is not done
   and is the obvious next arm; the transforms are already shared library code
   (`camouflage.py`), so it is a runner change rather than new machinery.
3. **Scenario B has no authentic capture** and appears in the synthetic arm
   only: its distant leg needs a second geographic IP and stays synthetic by
   necessity (CLAUDE.md §2d). The `all` rows therefore differ in composition as
   well as in origin; compare A against A and C against C.
4. **This is one background at one ambient ratio.** The ambient sensitivity
   sweep that was run for the kill point has not been repeated here.

---

# §4 item 3 — the same authentic attacks under camouflage

Run: 2026-09-04, 2164s (~36 min), 5 seeds, ambient ratio 0.05, all 9 conditions.
Command: `uv run python results/kali/injected_run.py --seeds 5`

This closes limit #2 above. The seven camouflage transforms plus
`realistic-combo` are applied to the attack lines of **both** arms by the same
shared `logdet_eval.camouflage` code the fixed recipes and the adaptive
adversary use — a runner change, no transform authored here. Benign background
is untouched; only the attack lines are disguised.

## The headline

| condition | authentic instance | synthetic instance |
|---|---|---|
| baseline | 100% (30/30) | 100% (45/45) |
| temporal | 100% | 100% |
| slow | **100%** | **84.4% (−15.6)** |
| rephrase | **100%** | 97.8% (−2.2) |
| mimicry | 100% | 100% |
| noise | 100% | 100% |
| volume | 100% | 100% |
| ip_rotate | **100%** | 91.1% (−8.9) |
| realistic-combo | **100%** | **82.2% (−17.8)** |

**Authentic attacks resist every camouflage condition; the synthetic arm loses
instances on four of them.** Read this as a statement about attack *shape*, not
about the detector being more robust on real traffic in general. Three things
must travel with it.

## 1. The transforms genuinely bite — on the synthetic arm

The synthetic-injected arm reproduces the *direction* of the known camouflage
losses (`slow`, `ip_rotate`, `realistic-combo` all drop; the tracker's pure-
synthetic suite reads 80.0 / 84.4 / 91.1, this OpenSSH-injected one 84.4 / 91.1
/ 82.2 — different corpus and instance count, same shape). So the camouflage is
being applied with real effect. Authentic's flat 100% is a genuine contrast, not
the transforms silently doing nothing to both arms.

## 2. Why the transforms have little purchase on authentic lines

The camouflage library was authored around the *synthetic* attack shape: a
homogeneous burst of near-identical `Failed password` lines on a freshly-drawn
corpus user. Authentic instances are the opposite shape, and each losing
transform fails on that difference:

- **rephrase** (synthetic −2.2): `REPHRASE_MAP` rewords `Failed password` and
  `Accepted password`. An authentic A instance has **one** such line; its other
  four (a disconnect, a `pam_unix` auth failure, a connection close) are not
  rephrase-able, and authentic C (`Invalid user …`) has **nothing** in the map.
  So rewording cannot remove an authentic instance's last flagged line. A
  synthetic instance is all `Failed password`, so rephrasing shifts every line's
  template together and can push one instance under. Same mechanism as the kill
  point — heterogeneity is simply what protects the authentic side.
- **slow** (synthetic −15.6): spreading events past the 30-min grouping / 60-min
  travel windows makes an isolated synthetic `Failed password` blend into ambient
  brute force. Authentic instances carry individually-rare lines that stay
  outliers even when isolated, and `root` has a real per-user baseline for a lone
  anomaly to stand against.
- **ip_rotate** (synthetic −8.9): `template_message` masks the IP before
  embedding, so this only attacks the source-IP grouping axis. A/C group on the
  user, not the IP, and never use impossible travel, so it is near-inert on the
  authentic shape.
- **volume**: thins repeated middle lines. Authentic instances are already
  3–5 lines (170 → 121 attack lines), so there is little repetition to thin;
  both arms stay 100% at instance level.

## 3. The line rate carries the real mechanism, and it agrees across arms

Instance detection saturates; the line rate is where the transforms show. Novel
wording makes lines *more* anomalous on both arms — `rephrase` line rate
authentic +9.4, synthetic +13.8 — and `volume` raises the rate on both by
deleting the self-similar inliers and leaving the rare lines. `noise` dilutes
the flagged proportion (synthetic line rate −10.3) and inflates alert volume
(synthetic 290 → 427, authentic 249 → 296). These are the documented behaviours,
reproduced on authentic lines.

## Limits specific to this arm

- **Still three captures per scenario, placed five ways.** Authentic 30/30 can
  move in 1/30 steps and does not, so the stability is real — but it rests on
  three underlying heterogeneous attacks, where the synthetic 45/45 rests on
  fresh draws per seed. The honest claim is "these three real attack shapes
  resist these transforms", not "authentic attacks are robust". More captures,
  and more attack *variety*, is the fix.
- **The contrast is attack-shape vs the detector, not us vs a SIEM.** Nothing
  here re-tests the kill point; it says the shipped camouflage recipes were
  tuned to a synthetic shape and have less grip on the authentic one.
