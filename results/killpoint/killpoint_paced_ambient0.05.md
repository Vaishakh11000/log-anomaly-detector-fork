# Paced-Replay Measurement (CLAUDE.md §1b, timing strategies)

The three strategies the batch runner cannot measure against Wazuh, measured.

Wazuh keys its correlation windows on **arrival time**, so a corpus replayed at
machine speed makes every event simultaneous to it and `slow`, `temporal` and
`realistic-combo` show a 0pt drop *by construction*. Here the corpus is replayed
in wall-clock time, so those windows mean what they mean in production.

`ambient_ratio=0.05`, `max_events_per_ip=12`, spacing bound 75s, pooled over 5 seeds.

**Best differential: 0.0pt → STOP**

## Instance-detection drop under camouflage

| Strategy | Ours (Δpt) | Wazuh L3 (Δpt) | Differential |
|---|---|---|---|
| slow | +8.9 | +0.0 | **-8.9** |
| temporal | +0.0 | +0.0 | **+0.0** |
| realistic-combo | +13.3 | +0.0 | **-13.3** |

## Every alert level, not just the primary one

Wazuh's level is *its* severity scale, and the comparison changes shape
completely across it, so all three thresholds are reported rather than the
one that reads best. Level 3 is where Wazuh starts writing alerts at all;
7 is "worth waking someone"; 10 is its own brute-force tier.

| Condition | Ours | Wazuh L3 | Wazuh L7 | Wazuh L10 |
|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 11.1% | 11.1% |
| slow | 91.1% | 100.0% | 0.0% | 0.0% |
| temporal | 100.0% | 100.0% | 0.0% | 0.0% |
| realistic-combo | 86.7% | 100.0% | 0.0% | 0.0% |

Two things this table makes visible, and both cut against a clean story:

- **At level 3 Wazuh cannot degrade, because it starts saturated.** A single
  failed login is already a level-5 rule, so every injected instance is flagged
  without any correlation happening at all. Its 100% is a property of the
  threshold, not evidence that pacing failed to hurt it.
- **At levels 7 and 10 Wazuh barely detects anything to begin with** — 11.1%,
  one instance in nine, on the *clean* corpus. A system that starts near zero
  cannot drop far, so the small differentials there are a floor effect rather
  than robustness.

## Alert volume

| Condition | Our incidents | Wazuh alerts (L3) |
|---|---|---|
| baseline | 716 | 1472 |
| slow | 734 | 1477 |
| temporal | 715 | 1478 |
| realistic-combo | 754 | 1277 |

## Corpus and instrument

- 600 real background lines, thinned to at most 12 events per source IP
- 109 injected attack lines, 9 instances
- replayed per source IP, real gaps honoured up to 75s (below every shipped rule's `timeframe/frequency`)
- Wazuh's ruleset, engine and clock are unmodified; correlation state is
  reset between runs so no condition inherits another's counters

Our detector is scored in batch on the identical corpus file — it reads the
timestamp out of each line, so arrival order does not reach it.
