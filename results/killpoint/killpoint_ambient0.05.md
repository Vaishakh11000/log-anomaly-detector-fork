# Kill-Point Measurement (CLAUDE.md §1b)

Detector vs **Wazuh** (real manager, v4.9.0, its own rules and engine) on the
real LogHub OpenSSH corpus. `ambient_ratio=0.05`, pooled over
5 seeds. Both systems scored on the *same corpus files* through the
same scorer; the only difference between the two columns is the detector.

## The registered criterion

| Differential | Decision |
|---|---|
| ≥25pt | continue the roadmap |
| 10–25pt | cheap stages only |
| <10pt, or SIEM degrades less | stop, publish the negative result |

**Best measurable differential: 31.1pt → CONTINUE**
(timing-independent strategies, batch replay)

## Instance-detection drop under camouflage

| Strategy | Ours (Δpt) | Wazuh L3 (Δpt) | Differential | Measurable in batch? |
|---|---|---|---|---|
| temporal | +0.0 | +0.0 | **+0.0** | no — arrival-time |
| slow | +11.1 | +0.0 | **-11.1** | no — arrival-time |
| rephrase | +2.2 | +33.3 | **+31.1** | yes |
| mimicry | +0.0 | +0.0 | **+0.0** | yes |
| noise | +0.0 | +0.0 | **+0.0** | yes |
| volume | +0.0 | +0.0 | **+0.0** | yes |
| ip_rotate | +11.1 | +0.0 | **-11.1** | yes |
| realistic-combo | +11.1 | +0.0 | **-11.1** | no — arrival-time |

## Why three strategies are excluded from the verdict

Wazuh's correlation windows and its `ignore` timers are keyed on **arrival
time, not on the timestamp in the log line** — verified on both `wazuh-logtest`
and the real `analysisd`: 15 `Invalid user` lines from one IP fire rule 5712
identically at 3-second and 1-hour spacing. A corpus replayed at machine speed
is therefore simultaneous to Wazuh, so `slow`, `temporal` and `realistic-combo`
cannot be measured against it in batch mode. That is a limit of the instrument,
not evidence that Wazuh resists them; the paced replay measures those.

This does not flatter this project either: Wazuh firing a brute-force rule on
events spread over hours is *indiscriminacy*, not robustness, which is why
alert volume is reported alongside detection.

## Alert volume

| Condition | Our incidents | Wazuh alerts (L3) |
|---|---|---|
| baseline | 1415 | 4546 |
| temporal | 1406 | 4560 |
| slow | 1417 | 4555 |
| rephrase | 1468 | 4241 |
| mimicry | 1466 | 4592 |
| noise | 2095 | 4557 |
| volume | 1327 | 4360 |
| ip_rotate | 1405 | 4596 |
| realistic-combo | 1775 | 4406 |

## Corpus

- 2483 real background lines (2365 benign + real attacker traffic at 5%)
- 115 injected attack lines, 9 instances
- brute force [15, 25] failures, enumeration [10, 12] usernames — sized above both
  systems' thresholds, pre-registered before any differential was computed
- 25 days, 9 real users, host `LabSZ`

Real: every background line, the usernames, the host, the vocabulary.
Authored: the injected instances and the camouflage layer.
