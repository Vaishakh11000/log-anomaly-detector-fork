# Alert suppression on the clean corpora (Stage 3)

Suppression clears `is_anomaly` on a flagged line that is **alone in its
incident** and whose **template transition is not rare**, and never on an
impossible-travel hit or on a line the model is silent about. See
`logdet/suppression.py` for the four guards.

**This is three quarters of CLAUDE.md section 4.** Line-level P/R/F1,
instance detection on the clean corpus and alert volume are below; instance
detection *under camouflage*, pooled over five seeds, is not here and is not
optional -- `logdet-adversarial --seeds 5 --suppress`. Clean instance
detection saturates at 100%, so this report cannot see the safety margin
camouflage eats first.

## synthetic (751 lines)

History: 750 benign lines, 10 mined templates, 0.80% of scored lines carry a template the model never saw (those are never suppressed).
Routine (median) = 0.901 nats, rare (p90) = 1.928 nats.

### Which guard removes what

| population | rows | of which attack lines |
|---|---|---|
| flagged by the detector | 130 | 39 |
| + alone in its incident | 84 | 2 |
| + not an impossible-travel hit | 82 | 0 |
| + the model has a transition to score | 59 | 0 |

### Why loneness is the guard that matters

AUC is the chance a randomly chosen attack line scores *more* surprising
than a randomly chosen benign one, within that population. 0.5 is a coin
flip; below 0.5 means the signal points the wrong way.

| population | rows | attack | AUC | attack median | benign median |
|---|---|---|---|---|---|
| all lines (the published figure) | 517 | 36 | 0.833 | 2.1 | 0.94 |
| flagged rows only | 98 | 30 | 0.278 | 2.1 | 2.32 |
| flagged **and** lone | 61 | 2 | 0.987 | 4.35 | 2.3 |

**Loneness is the safety property; the surprisal is only the selectivity.**
Among flagged rows the surprisal separates attack from benign badly or
backwards, so suppressing on the surprisal alone would preferentially delete
attacks. Restricted to lone rows it inverts, because the lone attack lines
that exist are impossible-travel hits -- which the third guard removes from
the pool anyway. Any change that weakens the first two guards has to be
re-measured under camouflage from scratch; weakening the threshold alone is
comparatively safe.

### Threshold sweep

| quantile of history | nats | lines suppressed | of which attack |
|---|---|---|---|
| q0.50 | 0.901 | 0 | 0 |
| q0.75 | 1.235 | 0 | 0 |
| q0.90 | 1.928 | 4  ← adopted | 0 |
| q0.95 | 2.257 | 26 | 0 |
| q0.99 | 2.64 | 50 | 0 |

q0.50 is the literal reading of "suppress a *routine* transition" and is
nearly inert. That is structural: the flagged rows are already the anomalous
tail, so a line the embedding detector found unusual almost never has a
below-median transition. The two signals are positively correlated.

### Section 4 numbers

| suppression | P | R | F1 | instance detection | flagged lines | incidents |
|---|---|---|---|---|---|---|
| off | 0.3 | 0.867 | 0.446 | 100% (9/9) | 130 | 94 |
| q0.50 | 0.3 | 0.867 | 0.446 | 100% (9/9) | 130 | 94 |
| q0.75 | 0.3 | 0.867 | 0.446 | 100% (9/9) | 130 | 94 |
| q0.90 (adopted) | 0.31 | 0.867 | 0.456 | 100% (9/9) | 126 | 90 |
| q0.95 | 0.375 | 0.867 | 0.523 | 100% (9/9) | 104 | 68 |
| q0.99 | 0.487 | 0.867 | 0.624 | 100% (9/9) | 80 | 44 |

### Which loneness test (Stage 4 entity graph)

Loneness is the guard doing the safety work, so it is the guard to move
if suppression is to be pushed harder -- the threshold has already been
swept above, and q0.99 was measured and rejected under camouflage. The
shipped test (`incident`) sees only the flagged rows. The graph sees the
whole frame, so it can tell an unknown IP appearing once from a busy
known host that also logged one odd line.

A flagged line on this corpus has a median of 1 events sharing its user or source IP inside the window, of which 0 are themselves flagged.

**The attack column is the one to read.** A test that calls attack lines
lone is a test that will delete evidence as soon as the threshold lets
one through.

| loneness test | rows called lone | of which attack |
|---|---|---|
| `quiet` | 58 | 0 |
| `incident`  ← shipped | 84 | 2 |
| `share@0.00` | 84 | 2 |
| `share@0.25` | 84 | 2 |
| `share@0.50` | 85 | 3 |
| `share@0.75` | 85 | 3 |

Section 4 numbers per loneness test, all at the adopted threshold
(q0.90):

| loneness test | P | R | F1 | instance detection | incidents | suppressed (attack) |
|---|---|---|---|---|---|---|
| `quiet` | 0.307 | 0.867 | 0.453 | 100% (9/9) | 91 | 3 (0) |
| `incident`  ← shipped | 0.31 | 0.867 | 0.456 | 100% (9/9) | 90 | 4 (0) |
| `share@0.00` | 0.31 | 0.867 | 0.456 | 100% (9/9) | 90 | 4 (0) |
| `share@0.25` | 0.31 | 0.867 | 0.456 | 100% (9/9) | 90 | 4 (0) |
| `share@0.50` | 0.31 | 0.867 | 0.456 | 100% (9/9) | 90 | 4 (0) |
| `share@0.75` | 0.31 | 0.867 | 0.456 | 100% (9/9) | 90 | 4 (0) |

Clean corpora cannot settle this on their own -- clean instance detection
saturates at 100%, which is exactly the margin camouflage eats first. Any
test adopted here owes the five-seed camouflage suite before its default
can change.

## kill-point OpenSSH (2,583 lines)

History: 2483 benign lines, 38 mined templates, 0.23% of scored lines carry a template the model never saw (those are never suppressed).
Routine (median) = 0.989 nats, rare (p90) = 2.59 nats.

### Which guard removes what

| population | rows | of which attack lines |
|---|---|---|
| flagged by the detector | 277 | 57 |
| + alone in its incident | 158 | 3 |
| + not an impossible-travel hit | 153 | 0 |
| + the model has a transition to score | 63 | 0 |

### Why loneness is the guard that matters

AUC is the chance a randomly chosen attack line scores *more* surprising
than a randomly chosen benign one, within that population. 0.5 is a coin
flip; below 0.5 means the signal points the wrong way.

| population | rows | attack | AUC | attack median | benign median |
|---|---|---|---|---|---|
| all lines (the published figure) | 1175 | 90 | 0.904 | 3.64 | 0.99 |
| flagged rows only | 162 | 48 | 0.645 | 1.94 | 2.13 |
| flagged **and** lone | 68 | 3 | 0.954 | 4.09 | 2.54 |

**Loneness is the safety property; the surprisal is only the selectivity.**
Among flagged rows the surprisal separates attack from benign badly or
backwards, so suppressing on the surprisal alone would preferentially delete
attacks. Restricted to lone rows it inverts, because the lone attack lines
that exist are impossible-travel hits -- which the third guard removes from
the pool anyway. Any change that weakens the first two guards has to be
re-measured under camouflage from scratch; weakening the threshold alone is
comparatively safe.

### Threshold sweep

| quantile of history | nats | lines suppressed | of which attack |
|---|---|---|---|
| q0.50 | 0.989 | 13 | 0 |
| q0.75 | 1.774 | 23 | 0 |
| q0.90 | 2.59 | 47  ← adopted | 0 |
| q0.95 | 2.59 | 47 | 0 |
| q0.99 | 2.773 | 53 | 0 |

q0.50 is the literal reading of "suppress a *routine* transition" and is
nearly inert. That is structural: the flagged rows are already the anomalous
tail, so a line the embedding detector found unusual almost never has a
below-median transition. The two signals are positively correlated.

### Section 4 numbers

| suppression | P | R | F1 | instance detection | flagged lines | incidents |
|---|---|---|---|---|---|---|
| off | 0.206 | 0.57 | 0.302 | 100% (9/9) | 277 | 194 |
| q0.50 | 0.216 | 0.57 | 0.313 | 100% (9/9) | 264 | 181 |
| q0.75 | 0.224 | 0.57 | 0.322 | 100% (9/9) | 254 | 171 |
| q0.90 (adopted) | 0.248 | 0.57 | 0.345 | 100% (9/9) | 230 | 147 |
| q0.95 | 0.248 | 0.57 | 0.345 | 100% (9/9) | 230 | 147 |
| q0.99 | 0.254 | 0.57 | 0.352 | 100% (9/9) | 224 | 141 |

### Which loneness test (Stage 4 entity graph)

Loneness is the guard doing the safety work, so it is the guard to move
if suppression is to be pushed harder -- the threshold has already been
swept above, and q0.99 was measured and rejected under camouflage. The
shipped test (`incident`) sees only the flagged rows. The graph sees the
whole frame, so it can tell an unknown IP appearing once from a busy
known host that also logged one odd line.

A flagged line on this corpus has a median of 1 events sharing its user or source IP inside the window, of which 0 are themselves flagged.

**The attack column is the one to read.** A test that calls attack lines
lone is a test that will delete evidence as soon as the threshold lets
one through.

| loneness test | rows called lone | of which attack |
|---|---|---|
| `quiet` | 104 | 0 |
| `incident`  ← shipped | 158 | 3 |
| `share@0.00` | 158 | 3 |
| `share@0.25` | 174 | 9 |
| `share@0.50` | 183 | 9 |
| `share@0.75` | 189 | 9 |

Section 4 numbers per loneness test, all at the adopted threshold
(q0.90):

| loneness test | P | R | F1 | instance detection | incidents | suppressed (attack) |
|---|---|---|---|---|---|---|
| `quiet` | 0.218 | 0.57 | 0.315 | 100% (9/9) | 179 | 15 (0) |
| `incident`  ← shipped | 0.248 | 0.57 | 0.345 | 100% (9/9) | 147 | 47 (0) |
| `share@0.00` | 0.248 | 0.57 | 0.345 | 100% (9/9) | 147 | 47 (0) |
| `share@0.25` | 0.254 | 0.57 | 0.352 | 100% (9/9) | 144 | 53 (0) |
| `share@0.50` | 0.26 | 0.57 | 0.357 | 100% (9/9) | 142 | 58 (0) |
| `share@0.75` | 0.265 | 0.57 | 0.362 | 100% (9/9) | 141 | 62 (0) |

Clean corpora cannot settle this on their own -- clean instance detection
saturates at 100%, which is exactly the margin camouflage eats first. Any
test adopted here owes the five-seed camouflage suite before its default
can change.
