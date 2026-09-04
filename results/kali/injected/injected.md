# Authentic Kali attacks injected into the real OpenSSH background

Seeds: [42, 43, 44, 45, 46]  |  ambient ratio: 0.05  |  248.2s

Both arms use the identical background, ambient ratio, seeds and scorer.
Only the origin of the attack lines differs.

## Pooled over seeds (rates recomputed from summed counts)

| arm | scenario | instance detection | line detection | attack lines |
|---|---|---|---|---|
| authentic | A | 100.0% (15/15) | 60.0% (45/75) | 75 |
| authentic | C | 100.0% (15/15) | 93.7% (89/95) | 95 |
| authentic | **all** | **100.0%** | **78.8%** | 170 |
| synthetic | A | 100.0% (15/15) | 26.5% (91/343) | 343 |
| synthetic | B | 100.0% (15/15) | 60.0% (18/30) | 30 |
| synthetic | C | 100.0% (15/15) | 86.0% (141/164) | 164 |
| synthetic | **all** | **100.0%** | **46.6%** | 537 |

Scenario B (impossible travel) appears in the synthetic arm only: its
distant leg needs a second geographic IP and stays synthetic by
necessity (CLAUDE.md section 2d), so no authentic capture exists for
it. Compare A against A and C against C; the `all` rows differ in
composition as well as in origin.

## Alert volume

| arm | corpus lines | flagged lines (mean over seeds) |
|---|---|---|
| authentic | 2517 | 249 |
| synthetic | 2602 | 275 |

## Per seed

| arm | seed | instance | line | flagged |
|---|---|---|---|---|
| authentic | 42 | 100.0% | 76.5% | 246 |
| authentic | 43 | 100.0% | 82.4% | 251 |
| authentic | 44 | 100.0% | 76.5% | 245 |
| authentic | 45 | 100.0% | 76.5% | 249 |
| authentic | 46 | 100.0% | 82.4% | 256 |
| synthetic | 42 | 100.0% | 31.9% | 258 |
| synthetic | 43 | 100.0% | 78.2% | 299 |
| synthetic | 44 | 100.0% | 29.3% | 254 |
| synthetic | 45 | 100.0% | 59.2% | 294 |
| synthetic | 46 | 100.0% | 39.8% | 270 |

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
