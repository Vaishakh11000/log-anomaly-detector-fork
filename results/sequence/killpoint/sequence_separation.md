# Transition-model separation (Stage 3)

Corpus: `data/processed/killpoint/corpus.log` -- 2583 lines, 100 of them ground-truth attack lines, 42 mined templates.

AUC is the chance a randomly chosen attack line scores more surprising
than a randomly chosen benign one. 0.5 is a coin flip. **This measures one
signal in isolation and is not a detection result** -- the sequence model
only shifts severity tiers, so no number in `results/` moves because of it.

## Fit source

| fit on | rows scored | AUC | attack median | benign median |
|---|---|---|---|---|
| whole corpus | 1181/2583 | 0.558 | 0.947 | 1.016 |
| benign only | 1175/2583 | 0.912 | 3.584 | 0.981 |

Fitting on the frame being scored is the failure `fit.py` already avoids for
the detector, and it costs more here: a brute-force burst repeats one
transition often enough to teach the model that the burst is routine.

## Sequence key (all fitted on benign lines only)

| keys | rows scored | AUC |
|---|---|---|
| `user` | 660/2583 | 0.958 |
| `source_ip` | 750/2583 | 0.758 |
| `user+source_ip` | 1175/2583 | 0.912 |

Keys are consulted in precedence order -- the user key scores a row if it can,
and source IP fills only the rows it cannot. What these numbers support is the
*ranking* of the keys, not the combining rule: the user key is much the stronger
signal on both corpora, and the fallback earns its place by being the only key
with anything to say about account enumeration, which varies the username on
every line by design. Taking the maximum across keys instead was measured and is
a wash (0.852 here against precedence's 0.856 on the synthetic corpus, 0.923
against 0.912 on the kill-point corpus), so precedence is kept for being the
simpler rule, not for scoring better. The combined row sits *below* user-alone on
the kill-point corpus because the fallback adds rows the user key could not score
at all -- coverage bought at lower quality, not a regression.

## Severity bands

Routine at or below **0.981 nats**, rare at or above **2.539** (quantiles of the fitted distribution, not fixed constants).

| band | attack lines | benign lines |
|---|---|---|
| middle (unchanged) | 32 | 367 |
| rare (promoted) | 57 | 144 |
| routine (demoted) | 1 | 574 |
| silent (unchanged) | 10 | 1398 |

## What it does to the analyst's queue

Every row below has the same 277 flagged lines in the same 194 incidents -- the sequence model cannot change
`is_anomaly`. What moves is which incidents are called notable, and in what
order they come.

### Shifting the severity tier

| severity coupling | notable | of those, contain an attack | precision |
|---|---|---|---|
| off (v1 tiers) | 72 | 9 | 0.125 |
| promote+demote, rare p90 | 84 | 9 | 0.107 |
| promote+demote, rare p95 | 74 | 9 | 0.122 |
| promote+demote, rare p99 | 73 | 9 | 0.123 |
| demote only | 72 | 9 | 0.125 |

Promotion strictly adds false positives -- it never surfaces an attack the
baseline missed. Demotion is inert, because an incident is notable when it
is high severity **or** has two or more events, and the incidents a demotion
could remove are already notable on their event count. **So the severity
tier is the wrong place to consume the sequence model**, and this is a
measured negative result rather than a tuning problem: no threshold in the
table beats leaving it off.

### Breaking ties in the triage order

| ordering | P@5 | P@10 | P@20 | rank by which all 9 instances are seen |
|---|---|---|---|---|
| v1: (events, severity) | 1.0 | 0.6 | 0.3 | 65 |
| (events, severity, surprisal) | 1.0 | 0.6 | 0.3 | 39 |
| surprisal alone | 0.8 | 0.7 | 0.35 | 62 |

Ranking on the surprisal *alone* is not safe: it drops precision@5 on both
corpora with ground truth, because a lone line with a rare transition
outranks a twenty-event brute force, and event count is the stronger
evidence. Used as a **tiebreaker after event count and severity** it leaves
precision@k untouched on both corpora and brings full coverage of every
attack instance forward -- rank 16 to 12 on the synthetic corpus, 65 to 39
on the kill-point OpenSSH corpus. That is a real if modest saving in analyst
work for a signal that costs nothing to compute, and it is the consumption
point adopted in `logdet/triage.py`. It is not a detection improvement and
must not be reported as one: the same incidents are flagged either way.
