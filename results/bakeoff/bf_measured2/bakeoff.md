# Live bake-off

Fired 2 conditions; 2 measured in real time.

Rows marked `illustration` were fired with time compressed or with a timing-based camouflage. Wazuh correlates on arrival time, so its score on those rows is fixed by the harness, not by its rules -- the measured figures for `slow`, `temporal` and `realistic-combo` are in `results/killpoint/killpoint_paced_ambient0.05.md`.

## brute_force

| level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts | differential | |
|---|---|---|---|---|---|---|
| `none` | 100% (3/3) / 98% | 100% (3/3) / 91% | 179 | 188 | +0.0pt |  |
| `rephrase` | 100% (3/3) / 100% | 100% (3/3) / 29% | 467 | 145 | +0.0pt |  |

The differential is computed on **instance** detection, which is the quantity section 1b is registered in. Instances per condition here: 3, so the finest step the live differential can take is 33pt. The line rate is shown beside it as the finer-grained evidence of the same firing. Admissible pooled figures come from the kill-point runs over >=5 seeds (CLAUDE.md 4), never from a live demo.

Both systems detected **every instance in every measured condition**, so both drops are zero and the differential is +0.0pt by arithmetic rather than by a tie in robustness. More repeats cannot move it: one surviving line is enough to call an instance detected, and at these magnitudes (15-25 failures, 10-12 probes) rewording never removes them all. What separates the two systems here is the *share of the attack's lines* each one flagged, which is the column beside it.
