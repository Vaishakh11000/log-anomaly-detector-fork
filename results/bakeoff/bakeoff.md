# Live bake-off

Fired 2 conditions; 2 measured in real time.

Rows marked `illustration` were fired with time compressed or with a timing-based camouflage. Wazuh correlates on arrival time, so its score on those rows is fixed by the harness, not by its rules -- the measured figures for `slow`, `temporal` and `realistic-combo` are in `results/killpoint/killpoint_paced_ambient0.05.md`.

## brute_force

| level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts | differential | |
|---|---|---|---|---|---|---|
| `none` | 100% / 100% | 100% / 92% | 36 | 54 | +0.0pt |  |
| `rephrase` | 100% / 100% | 100% / 27% | 66 | 37 | +0.0pt |  |

The differential is computed on **instance** detection, which is the quantity section 1b is registered in. Over a handful of live instances it saturates -- one instance reads 0% or 100% and nothing in between -- so the line rate is shown beside it as the finer-grained evidence of the same firing. Pooled figures come from the kill-point runs (CLAUDE.md 4), never from a live demo.
