# Authentic Kali attacks under camouflage, in the real OpenSSH background

Seeds: [42, 43, 44, 45, 46]  |  ambient ratio: 0.05  |  2163.9s

Both arms use the identical background, ambient ratio, seeds and scorer,
and the identical camouflage transforms (`logdet_eval.camouflage`)
applied to the attack lines only. Only the origin of the attack lines
differs: authentic captured hydra/ssh output, or the synthetic scenario
generators.

## Instance detection, pooled over seeds (rates from summed counts)

| arm | condition | instance detection | line detection | attack lines |
|---|---|---|---|---|
| authentic | baseline | 100.0% (30/30) | 78.8% | 170 |
| authentic | temporal | 100.0% (+0.0) (30/30) | 79.4% (+0.6) | 170 |
| authentic | slow | 100.0% (+0.0) (30/30) | 79.4% (+0.6) | 170 |
| authentic | rephrase | 100.0% (+0.0) (30/30) | 88.2% (+9.4) | 170 |
| authentic | mimicry | 100.0% (+0.0) (30/30) | 78.8% (+0.0) | 170 |
| authentic | noise | 100.0% (+0.0) (30/30) | 78.8% (+0.0) | 170 |
| authentic | volume | 100.0% (+0.0) (30/30) | 84.3% (+5.5) | 121 |
| authentic | ip_rotate | 100.0% (+0.0) (30/30) | 78.8% (+0.0) | 170 |
| authentic | realistic-combo | 100.0% (+0.0) (30/30) | 84.5% (+5.7) | 110 |
| synthetic | baseline | 100.0% (45/45) | 59.3% | 543 |
| synthetic | temporal | 100.0% (+0.0) (45/45) | 59.5% (+0.2) | 543 |
| synthetic | slow | 84.4% (-15.6) (38/45) | 58.0% (-1.3) | 543 |
| synthetic | rephrase | 97.8% (-2.2) (44/45) | 73.1% (+13.8) | 543 |
| synthetic | mimicry | 100.0% (+0.0) (45/45) | 59.1% (-0.2) | 543 |
| synthetic | noise | 100.0% (+0.0) (45/45) | 49.0% (-10.3) | 543 |
| synthetic | volume | 100.0% (+0.0) (45/45) | 75.3% (+16.0) | 320 |
| synthetic | ip_rotate | 91.1% (-8.9) (41/45) | 58.4% (-0.9) | 543 |
| synthetic | realistic-combo | 82.2% (-17.8) (37/45) | 70.3% (+11.0) | 310 |

## Per scenario (instance detection, pooled)

| arm | condition | A brute force | C enumeration |
|---|---|---|---|
| authentic | baseline | 100% (15/15) | 100% (15/15) |
| authentic | temporal | 100% (15/15) | 100% (15/15) |
| authentic | slow | 100% (15/15) | 100% (15/15) |
| authentic | rephrase | 100% (15/15) | 100% (15/15) |
| authentic | mimicry | 100% (15/15) | 100% (15/15) |
| authentic | noise | 100% (15/15) | 100% (15/15) |
| authentic | volume | 100% (15/15) | 100% (15/15) |
| authentic | ip_rotate | 100% (15/15) | 100% (15/15) |
| authentic | realistic-combo | 100% (15/15) | 100% (15/15) |
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
| authentic | baseline | 249 | 2517 |
| authentic | temporal | 250 | 2517 |
| authentic | slow | 250 | 2517 |
| authentic | rephrase | 252 | 2517 |
| authentic | mimicry | 249 | 2517 |
| authentic | noise | 296 | 2566 |
| authentic | volume | 244 | 2507 |
| authentic | ip_rotate | 249 | 2517 |
| authentic | realistic-combo | 271 | 2537 |
| synthetic | baseline | 290 | 2592 |
| synthetic | temporal | 291 | 2592 |
| synthetic | slow | 289 | 2592 |
| synthetic | rephrase | 298 | 2592 |
| synthetic | mimicry | 293 | 2592 |
| synthetic | noise | 427 | 2753 |
| synthetic | volume | 266 | 2547 |
| synthetic | ip_rotate | 289 | 2592 |
| synthetic | realistic-combo | 348 | 2637 |

The captured instances injected:

| scenario | instance | lines | span (s) | description |
|---|---|---|---|---|
| A | 1 | 5 | 5.0 | brute force, 20 attempts via hydra |
| A | 2 | 5 | 5.0 | brute force, 20 attempts via hydra |
| A | 3 | 5 | 4.0 | brute force, 20 attempts via hydra |
| C | 1 | 10 | 0.0 | enumeration of 6 candidate users |
| C | 2 | 6 | 0.0 | enumeration of 6 candidate users |
| C | 3 | 3 | 0.0 | enumeration of 6 candidate users |

Interpretation is authored and lives in `results/kali/injected_notes.md`, not in this generator.
