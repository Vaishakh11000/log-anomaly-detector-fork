# Kill-Point Measurement (CLAUDE.md §1b)

Detector vs **Wazuh** (real manager, v4.9.0, its own rules and engine) on the
real LogHub OpenSSH corpus. `ambient_ratio=0.05`, pooled over
1 seeds. Both systems scored on the *same corpus files* through the
same scorer; the only difference between the two columns is the detector.

## The registered criterion

| Differential | Decision |
|---|---|
| ≥25pt | continue the roadmap |
| 10–25pt | cheap stages only |
| <10pt, or SIEM degrades less | stop, publish the negative result |

**Best measurable differential: 22.2pt → PARTIAL**
(timing-independent strategies, batch replay)

## Instance-detection drop under camouflage

| Strategy | Ours (Δpt) | Wazuh L3 (Δpt) | Differential | Measurable in batch? |
|---|---|---|---|---|
| temporal | +0.0 | +0.0 | **+0.0** | no — arrival-time |
| slow | +22.2 | +0.0 | **-22.2** | no — arrival-time |
| rephrase | +11.1 | +33.3 | **+22.2** | yes |
| mimicry | +0.0 | +0.0 | **+0.0** | yes |
| noise | +0.0 | +0.0 | **+0.0** | yes |
| volume | +0.0 | +0.0 | **+0.0** | yes |
| ip_rotate | +11.1 | +0.0 | **-11.1** | yes |
| realistic-combo | +33.3 | +0.0 | **-33.3** | no — arrival-time |

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
| baseline | 260 | 926 |
| temporal | 278 | 909 |
| slow | 256 | 913 |
| rephrase | 286 | 858 |
| mimicry | 283 | 922 |
| noise | 398 | 905 |
| volume | 258 | 872 |
| ip_rotate | 257 | 925 |
| realistic-combo | 334 | 886 |

## Corpus

- 2483 real background lines (2365 benign + real attacker traffic at 5%)
- 111 injected attack lines, 9 instances
- brute force [15, 25] failures, enumeration [10, 12] usernames — sized above both
  systems' thresholds, pre-registered before any differential was computed
- 25 days, 9 real users, host `LabSZ`

Real: every background line, the usernames, the host, the vocabulary.
Authored: the injected instances and the camouflage layer.
