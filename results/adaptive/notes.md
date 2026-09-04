# Reading the adaptive adversary result

Written by hand. The tables in `adaptive.md` are generated; this file is the
interpretation, kept separate for the same reason the bake-off keeps them apart
(a generator that writes conclusions is scripting the narrative, CLAUDE.md §8).

## The headline, in plain words

We built an attacker that is allowed to try camouflage settings against the
detector over and over and keep whichever works best. It found a disguise that
is **meaningfully better than the strongest one this project had hand-picked**.

On five corpus draws the attacker never got to practise on:

| | attack instances the system still catches |
|---|---|
| no camouflage | 100% |
| `realistic-combo` — the published worst case | 84.4% |
| **what the search found** | **73.3%** |

So the honest robustness figure under an optimising attacker is **11 points
worse than the number this project has been reporting**, and 27 points below
clean. Line detection — how much of the attack's evidence survives — falls the
same way, 82.0% clean to 79.0% published to **68.6%** searched.

## What it found, and why that mechanism makes sense

`slow` + `mimicry`, with the slow gap widened from 35 minutes to **61**.

Both halves are explainable rather than lucky, which is what makes this worth
reporting:

- **61 minutes is just past 60.** The impossible-travel check compares a login
  with the previous one inside a 60-minute window, and incident grouping uses 30
  minutes. Pushing the gap past *both* windows is exactly what breaks the one
  detector component that catches scenario B at all. The optimiser found the
  system's own constant without being told it — it read it off the scores.
- **`mimicry` removes the evidence that survives.** Rewriting escalation lines
  as the dominant benign template moves them toward the middle of the learned
  distribution. It never hides a whole instance on its own; combined with
  timing it takes the line rate down with it.

## The finding about our own published suite

`realistic-combo` — the hand-picked "strongest realistic attacker" — ranks
**49th of 106** on the search seed. It is not a strong attack; it is a plausible
one. Three of its five transforms do nothing for the attacker here:

- `noise` is inert by construction (contamination fixes the *proportion*
  flagged, so padding the log raises alert count rather than hiding anything —
  already documented in `adversarial.py`);
- `ip_rotate` is neutral-to-harmful once `slow` is doing the work;
- `volume` deletes evidence but also deletes the attack (below).

And every subset containing **`rephrase` scores 100% / 100%** — fully detected.
Combining novel wording with anything is self-defeating, because rare templates
are what an outlier detector looks for. That was known as a single-strategy
result; it now holds across all 32 subsets that contain it.

## An uncomfortable one about `volume`

The adaptive adversary is held to a floor: an attack instance must keep at least
3 lines and at least 40% of its lines, or the plan is refused before it can cost
a query. Otherwise the optimiser "evades" by deleting the attack.

Applying that same floor to the **published** fixed recipes:

| seed | subsets below the floor (of 128) | all carry `volume`? |
|---|---|---|
| 42 | 22 | yes |
| 43 | 14 | yes |
| 44 | 4 | yes |
| 45 | 30 | yes |
| 46 | 10 | yes |

Reproduce in ~2 seconds with `uv run python results/adaptive/volume_floor_check.py`.

So on some draws the published `volume` condition thins a 6-line enumeration to
**2 lines**. Part of what the `volume` row in `results/adversarial_results.md`
measures is therefore an attack that partly stopped happening, not one that hid.
Nothing else in the suite is affected, the effect is small, and no verdict in
this project rests on `volume` — but the row should be read with that caveat and
we should not quote it as pure evasion.

## What this is not

- **Not a field estimate.** The attacker is handed the detector's true detection
  rates over labelled attack lines after every attempt. Nobody attacking a real
  system gets that. This is an upper bound on evasion.
- **Not budget-limited.** The search stopped on its own after 135 of 260
  allowed queries, because a whole round of neighbours produced no improvement.
  The flat tail of the budget curve is a real plateau, not a run that ran out.
- **Not a claim about detection generally.** The search space is the seven
  shipped transforms and their magnitudes. An attacker who invents an eighth is
  outside it. The correct reading of a plateau is *these transforms are
  exhausted*, not *this detector is robust*.
- **Not a change to the kill point.** §1b's verdict, thresholds and metric are
  untouched; this is a new measurement of our own system's degradation, not a
  re-run of the differential against Wazuh.

## The obvious next arm

Point the same search at **Wazuh** instead of at us. The oracle is already
behind a small interface and `logdet_eval.scoring` is detector-agnostic, so it
is a second `Oracle` subclass plus a container that must be up. That would say
whether a third-party ruleset also has magnitudes an optimiser can find — and
the kill point's one surviving win (`rephrase`, +31.1pt) is measured against a
*fixed* attacker, so an adaptive one is the fairest available re-test of it.
