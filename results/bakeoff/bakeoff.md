# Live bake-off

Fired 18 conditions; 12 measured in real time.

Rows marked `illustration` were fired with time compressed or with a timing-based camouflage. Wazuh correlates on arrival time, so its score on those rows is fixed by the harness, not by its rules -- the measured figures for `slow`, `temporal` and `realistic-combo` are in `results/killpoint/killpoint_paced_ambient0.05.md`.

## brute_force

| level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts | differential | |
|---|---|---|---|---|---|---|
| `none` | 100% (3/3) / 98% | 100% (3/3) / 91% | 179 | 188 | +0.0pt |  |
| `mimicry` | 100% (3/3) / 97% | 100% (3/3) / 100% | 176 | 194 | +0.0pt |  |
| `rephrase` | 100% (3/3) / 100% | 100% (3/3) / 29% | 467 | 145 | +0.0pt |  |
| `ip_rotate` | 100% (3/3) / 100% | 100% (3/3) / 91% | 468 | 186 | +0.0pt |  |
| `slow` | 100% (3/3) / 100% | 100% (3/3) / 91% | 177 | 188 | -- | illustration |
| `realistic-combo` | 100% (3/3) / 97% | 100% (3/3) / 100% | 422 | 87 | -- | illustration |

## impossible_travel

| level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts | differential | |
|---|---|---|---|---|---|---|
| `none` | 100% (3/3) / 50% | 100% (3/3) / 100% | 404 | 861 | +0.0pt |  |
| `mimicry` | 100% (3/3) / 67% | 100% (3/3) / 100% | 1019 | 856 | +0.0pt |  |
| `rephrase` | 100% (3/3) / 100% | 0% (0/3) / 0% | 1626 | 900 | +100.0pt |  |
| `ip_rotate` | 100% (3/3) / 100% | 100% (3/3) / 100% | 2257 | 878 | +0.0pt |  |
| `slow` | 100% (3/3) / 67% | 100% (3/3) / 100% | 760 | 13 | -- | illustration |
| `realistic-combo` | 67% (2/3) / 33% | 100% (3/3) / 100% | 779 | 10 | -- | illustration |

## enumeration

| level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts | differential | |
|---|---|---|---|---|---|---|
| `none` | 100% (3/3) / 100% | 100% (3/3) / 100% | 77 | 69 | +0.0pt |  |
| `mimicry` | 100% (3/3) / 100% | 100% (3/3) / 100% | 199 | 71 | +0.0pt |  |
| `rephrase` | 100% (3/3) / 100% | 100% (3/3) / 34% | 318 | 45 | +0.0pt |  |
| `ip_rotate` | 100% (3/3) / 100% | 100% (3/3) / 100% | 436 | 60 | +0.0pt |  |
| `slow` | 100% (3/3) / 100% | 100% (3/3) / 100% | 585 | 87 | -- | illustration |
| `realistic-combo` | 100% (3/3) / 100% | 100% (3/3) / 100% | 710 | 57 | -- | illustration |

The differential is computed on **instance** detection, which is the quantity section 1b is registered in. Instances per condition here: 3, so the finest step the live differential can take is 33pt. The line rate is shown beside it as the finer-grained evidence of the same firing. Admissible pooled figures come from the kill-point runs over >=5 seeds (CLAUDE.md 4), never from a live demo.

## How this table was produced

Fired 2026-08-30 on the dev box (RTX 3050 6GB, i5-13450HX; CLAUDE.md 2c), with the
Wazuh manager running in Docker throughout and its correlation state reset before
each invocation. Seed 1, three instances per cell, background traffic 0.5 lines/s,
20s settle after each instance, Wazuh detection counted at level >=3 -- the same
primary level the kill point uses.

The 18 cells came from five `logdet-bakeoff` invocations, not one, so line numbers
restart per invocation and each cell is scored only on the lines it wrote:

```
logdet-bakeoff --grid --attack brute_force --levels none rephrase --repeat 3
logdet-bakeoff --grid --attack brute_force --levels mimicry ip_rotate --repeat 3
logdet-bakeoff --grid --attack enumeration --levels none mimicry rephrase ip_rotate --repeat 3
logdet-bakeoff --grid --attack impossible_travel --levels none mimicry rephrase ip_rotate --repeat 3
logdet-bakeoff --grid --levels slow realistic-combo --repeat 3 --compress 600
```

The per-invocation JSON is kept beside this file in `bf_measured2/`, `bf_measured/`,
`enum_measured/`, `it_measured/` and `illustration/`. The twelve measured rows ran at
`--compress 1`, in real time; the six illustration rows ran at `--compress 600`
because `slow` spans up to 22 hours per instance, and compressing time is exactly
what makes Wazuh's score on them an artefact of the harness.

## Reading it

**One cell moved, and it is the only cell that could.** `impossible_travel` /
`rephrase` is +100pt: Wazuh detected none of the three instances, we detected all
three. Impossible travel is a two-line attack, so rewording can take *every* line
out of Wazuh's sshd decoder. A 15-25 line brute force or a 10-12 line enumeration
always leaves a line behind, and one surviving line is enough to call an instance
detected -- which is why every other measured cell reads 100% on both sides and
+0.0pt. That +0.0pt is a ceiling, not a tie in robustness, and not a granularity
problem: three instances make the metric able to move in 33pt steps and it did not.

**The line rate is where the mechanism shows on the other two attacks.** Rewording
costs Wazuh 91% -> 29% of brute-force lines and 100% -> 34% of enumeration lines,
while ours stays at 97-100%. Same cause as the +100pt cell, short of the threshold
that flips an instance.

**Wazuh's 100% on impossible travel is not correlation.** Its alerts on those lines
are rule 5715 "sshd: authentication success", level 3 -- checked in the container's
`alerts.json`, 135 of 135 successful-login alerts carried that id. It flags every
successful login, so it flags this attack's two lines without ever knowing the
travel was impossible. That is the same level-3 saturation the kill point recorded
(`results/killpoint/killpoint_paced_ambient0.05.md`), and it is why rewording those
two lines takes it to 0%.

**Our 50% line rate on `impossible_travel` / `none` is the known display gap**, not
a detection miss: only the arriving login is flagged and grouped, and the earlier
login it was compared against is benign and never carried into the incident
(CLAUDE.md Known Issues, fix due with the entity graph in Stage 4). Under camouflage
it rises to 100%, because rewording makes both legs anomalous to the embeddings
rather than only one.

**Our alert volume rises with every camouflage level, on every attack** -- 77 -> 436
on enumeration, 404 -> 2257 on impossible travel. Novel wording is more anomalous,
not less, so the cost of staying robust is paid in noise. Precision remains this
system's weakness (CLAUDE.md Known Issues) and these rows are more evidence of it.

**Nothing here is an admissible pooled figure.** Three instances at one seed is a
demo, not a measurement; the registered numbers come from the kill-point runs over
>=5 seeds (CLAUDE.md 4).
