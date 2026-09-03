# Which loneness test suppression should use — the reading

Generated tables are in `suppression_adversarial.md` (camouflage, 5 seeds, the
deciding half of CLAUDE.md section 4) and in `../suppression.md` (both clean
corpora). This file is the interpretation, kept separate so no generator writes
a conclusion.

## What was asked

Suppression withdraws a flagged line when it is *lone* and its template
transition is not rare. The 2026-09-03 measurement found that **loneness is the
guard doing the safety work and the surprisal is only selectivity** — among
flagged rows the surprisal separates attack from benign at AUC 0.278
(synthetic) and 0.645 (kill-point), i.e. at or below a coin flip. So the honest
lever for pushing suppression harder is a better loneness test, not a looser
threshold; q0.99 was already measured and rejected.

The shipped test (`incident`) is grouping's own answer and sees **only the
flagged rows**. The Stage 4 entity graph sees the whole frame, so it can tell an
unknown IP appearing exactly once from a busy known host that also logged one
odd line. Two graph tests were built and measured against it:

* `quiet` — lone only when *nothing at all* shares the line's user or source IP
  inside the window. Strictly the smallest pool, i.e. the safety end.
* `share@r` — lone when the *flagged* share of that neighbourhood is at or
  below `r`. At `r = 0.0` this is `incident` computed the other way; above it,
  lines that grouping corroborates are called lone when their entity's traffic
  is overwhelmingly benign. The selectivity end.

## Verdict: keep `incident`. Both graph tests are rejected on measurement.

**`quiet` is strictly dominated.** It costs the *same* attack lines as
`incident` — 8 on `slow`, 6 on `realistic-combo`, seed for seed — while
suppressing fewer benign ones, so it gives back part of the alert-volume win
(626 → 632 incidents on `slow`, 497 → 503 on `baseline`) and buys nothing for
it. That is the finding worth keeping: **the attack lines suppression costs are
genuinely isolated**, so a test that demands total isolation does not protect
them. Knowing about the benign traffic around an alert does not help here,
because on the conditions that cost evidence there is no benign traffic around
it either. The intuition that motivated the graph was wrong, and it took the
camouflage suite to say so.

**`share@0.50` buys nothing under camouflage and costs evidence.** Its incident
counts are identical to `incident` on all nine conditions, and it removes one
attack line on `temporal` and one on `volume` — two conditions that previously
cost zero — dropping their line rates 0.858 → 0.854 and 0.847 → 0.841.

The trap is that `share` looks good on clean data, exactly as q0.99 did: on the
kill-point corpus it takes 147 → 142 incidents and precision 0.248 → 0.260 with
recall untouched. It also triples the attack lines it admits into the pool
there, 3 → 9, leaving only the weak guard holding them back. This is the
2026-08-16 contamination lesson and the 2026-09-03 q0.99 lesson for the third
time, on the guard rather than on the threshold.

## What the graph did earn

`share@0.00` reproduces `incident` exactly on both real corpora — 84/84 lone
rows and 4 suppressed on synthetic, 158/158 and 47 on the kill-point corpus —
so the graph path and the grouper agree outside the unit test. The neighbourhood
counts stay in `logdet/suppression.py` as a measurement instrument; what they
cannot do is make this particular guard safer.

Instance detection, the registered metric, is **unchanged on every arm and every
condition**: 100% except `slow` 80.0%, `ip_rotate` 84.4%, `realistic-combo`
91.1%. Nothing here moved it in either direction.

## Not run

`share@0.75` was measured on the clean corpora only (141 incidents, precision
0.265 on the kill-point corpus) and not under camouflage. `share@0.50` already
loses attack lines with a smaller pool, so a larger pool is not a candidate; if
it is ever revisited it owes the full suite like everything else.
