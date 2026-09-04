# Authentic Kali attacks under camouflage, in the real OpenSSH background

Seeds: [42, 43, 44, 45, 46]  |  ambient ratio: 0.05  |  2223.9s

Both arms use the identical background, ambient ratio, seeds and scorer,
and the identical camouflage transforms (`logdet_eval.camouflage`)
applied to the attack lines only. Only the origin of the attack lines
differs: authentic captured hydra/ssh output, or the synthetic scenario
generators.

## Instance detection, pooled over seeds (rates from summed counts)

| arm | condition | instance detection | line detection | attack lines |
|---|---|---|---|---|
| authentic | baseline | 100.0% (50/50) | 45.0% | 1080 |
| authentic | temporal | 100.0% (+0.0) (50/50) | 44.9% (-0.1) | 1080 |
| authentic | slow | 100.0% (+0.0) (50/50) | 45.0% (+0.0) | 1080 |
| authentic | rephrase | 100.0% (+0.0) (50/50) | 47.9% (+2.9) | 1080 |
| authentic | mimicry | 100.0% (+0.0) (50/50) | 45.0% (+0.0) | 1080 |
| authentic | noise | 100.0% (+0.0) (50/50) | 41.2% (-3.8) | 1080 |
| authentic | volume | 100.0% (+0.0) (50/50) | 48.6% (+3.6) | 593 |
| authentic | ip_rotate | 100.0% (+0.0) (50/50) | 45.0% (+0.0) | 1080 |
| authentic | realistic-combo | 100.0% (+0.0) (50/50) | 50.1% (+5.1) | 593 |
| synthetic | baseline | 100.0% (45/45) | 52.0% | 544 |
| synthetic | temporal | 100.0% (+0.0) (45/45) | 51.7% (-0.3) | 544 |
| synthetic | slow | 86.7% (-13.3) (39/45) | 50.9% (-1.1) | 544 |
| synthetic | rephrase | 95.6% (-4.4) (43/45) | 67.8% (+15.8) | 544 |
| synthetic | mimicry | 100.0% (+0.0) (45/45) | 56.1% (+4.1) | 544 |
| synthetic | noise | 100.0% (+0.0) (45/45) | 44.5% (-7.5) | 544 |
| synthetic | volume | 100.0% (+0.0) (45/45) | 73.4% (+21.4) | 323 |
| synthetic | ip_rotate | 93.3% (-6.7) (42/45) | 51.5% (-0.5) | 544 |
| synthetic | realistic-combo | 77.8% (-22.2) (35/45) | 67.7% (+15.7) | 319 |

## Per scenario (instance detection, pooled)

| arm | condition | A brute force | C enumeration |
|---|---|---|---|
| authentic | baseline | 100% (25/25) | 100% (25/25) |
| authentic | temporal | 100% (25/25) | 100% (25/25) |
| authentic | slow | 100% (25/25) | 100% (25/25) |
| authentic | rephrase | 100% (25/25) | 100% (25/25) |
| authentic | mimicry | 100% (25/25) | 100% (25/25) |
| authentic | noise | 100% (25/25) | 100% (25/25) |
| authentic | volume | 100% (25/25) | 100% (25/25) |
| authentic | ip_rotate | 100% (25/25) | 100% (25/25) |
| authentic | realistic-combo | 100% (25/25) | 100% (25/25) |
| synthetic | baseline | 100% (15/15) | 100% (15/15) |
| synthetic | temporal | 100% (15/15) | 100% (15/15) |
| synthetic | slow | 100% (15/15) | 100% (15/15) |
| synthetic | rephrase | 100% (15/15) | 100% (15/15) |
| synthetic | mimicry | 100% (15/15) | 100% (15/15) |
| synthetic | noise | 100% (15/15) | 100% (15/15) |
| synthetic | volume | 100% (15/15) | 100% (15/15) |
| synthetic | ip_rotate | 100% (15/15) | 100% (15/15) |
| synthetic | realistic-combo | 100% (15/15) | 100% (15/15) |

Scenario B (impossible travel) appears in the synthetic arm only: its
distant leg needs a second geographic IP and stays synthetic by
necessity (CLAUDE.md section 2d), so no authentic capture exists for it.

## Alert volume (mean flagged lines over seeds)

| arm | condition | flagged lines | corpus lines |
|---|---|---|---|
| authentic | baseline | 319 | 2699 |
| authentic | temporal | 319 | 2699 |
| authentic | slow | 319 | 2699 |
| authentic | rephrase | 323 | 2699 |
| authentic | mimicry | 319 | 2699 |
| authentic | noise | 538 | 3020 |
| authentic | volume | 280 | 2602 |
| authentic | ip_rotate | 319 | 2699 |
| authentic | realistic-combo | 447 | 2777 |
| synthetic | baseline | 282 | 2592 |
| synthetic | temporal | 280 | 2592 |
| synthetic | slow | 280 | 2592 |
| synthetic | rephrase | 292 | 2592 |
| synthetic | mimicry | 287 | 2592 |
| synthetic | noise | 426 | 2754 |
| synthetic | volume | 266 | 2548 |
| synthetic | ip_rotate | 281 | 2592 |
| synthetic | realistic-combo | 353 | 2641 |

The captured instances injected:

| scenario | instance | lines | span (s) | description |
|---|---|---|---|---|
| A | 1 | 30 | 11.0 | brute force, 15 attempts via hydra |
| A | 2 | 32 | 9.0 | brute force, 12 attempts via hydra |
| A | 3 | 38 | 14.0 | brute force, 18 attempts via hydra |
| A | 4 | 25 | 10.0 | brute force, 10 attempts via hydra |
| A | 5 | 45 | 16.0 | brute force, 20 attempts via hydra |
| C | 1 | 9 | 1.0 | enumeration of 5 candidate users |
| C | 2 | 9 | 0.0 | enumeration of 5 candidate users |
| C | 3 | 9 | 0.0 | enumeration of 5 candidate users |
| C | 4 | 9 | 1.0 | enumeration of 5 candidate users |
| C | 5 | 10 | 0.0 | enumeration of 5 candidate users |

Interpretation is authored and lives in `results/kali/injected_notes.md`, not in this generator.
