# Alert suppression under camouflage (Stage 3)

CLAUDE.md section 4, item 3: instance detection under camouflage, pooled over **5 seeds**. Same corpus, same camouflage code, same
scorer; the only thing that differs between arms is whether suppression ran
and at what threshold.

The transition model is fitted on a **separate benign-only corpus** generated
at a disjoint seed, once, not per seed -- it is history, and varying it with
the evaluation seed would confound "the attacker changed tactics" with "the
defender was shown a different past".

## Instance detection (the registered metric)

| condition | off | q0.90 | q0.99 | worst cost |
|---|---|---|---|---|
| `baseline` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `temporal` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `slow` | 80.0% (36/45) | 80.0% (36/45) (+0.0pt) | 66.7% (30/45) (-13.3pt) | -13.3pt |
| `rephrase` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `mimicry` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `noise` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `volume` | 100.0% (45/45) | 100.0% (45/45) (+0.0pt) | 100.0% (45/45) (+0.0pt) | +0.0pt |
| `ip_rotate` | 84.4% (38/45) | 84.4% (38/45) (+0.0pt) | 80.0% (36/45) (-4.4pt) | -4.4pt |
| `realistic-combo` | 91.1% (41/45) | 91.1% (41/45) (+0.0pt) | 88.9% (40/45) (-2.2pt) | -2.2pt |

## What it cost: evidence retained, and alert volume

Instance detection can hold at +0.0pt while the *evidence* behind a detection
thins out, because one surviving line is enough to call an instance detected.
The line-detection rate is where that shows, and it is the column to read on
the timing-spread conditions.

| condition | off: line rate | q0.90: line rate | q0.99: line rate | off: incidents | q0.90: incidents | q0.99: incidents | attack lines suppressed |
|---|---|---|---|---|---|---|---|
| `baseline` | 0.858 | 0.858 | 0.858 | 519 | 497 | 303 | 0 / 0 |
| `temporal` | 0.858 | 0.858 | 0.858 | 520 | 498 | 305 | 0 / 0 |
| `slow` | 0.824 | 0.790 | 0.266 | 656 | 626 | 317 | 8 / 130 |
| `rephrase` | 0.996 | 0.996 | 0.996 | 510 | 489 | 298 | 0 / 0 |
| `mimicry` | 0.760 | 0.760 | 0.760 | 536 | 514 | 326 | 0 / 0 |
| `noise` | 0.824 | 0.824 | 0.824 | 548 | 521 | 346 | 0 / 0 |
| `volume` | 0.847 | 0.847 | 0.847 | 519 | 497 | 303 | 0 / 0 |
| `ip_rotate` | 0.837 | 0.837 | 0.601 | 602 | 580 | 331 | 0 / 55 |
| `realistic-combo` | 0.776 | 0.741 | 0.471 | 673 | 638 | 398 | 6 / 52 |

The suppression rate itself carries the mechanism: it sits near 3% of flagged
lines on every condition and rises on the **timing-spread** ones, which are
exactly the conditions that cost attack lines. Spreading an attack in time is
what makes its lines lone, and lone is what puts a line in the eligible pool.
That is the predicted failure mode, found where it was predicted.
