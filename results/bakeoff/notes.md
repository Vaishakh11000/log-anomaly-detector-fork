## Conditions of the run

Fired 2026-08-30 on the dev box (RTX 3050 6GB, i5-13450HX; CLAUDE.md 2c), with the
Wazuh manager running in Docker throughout and its correlation state reset before
each invocation. Seed 1, three instances per cell, background traffic 0.5 lines/s,
20s settle after each instance, Wazuh detection counted at level >=3 -- the same
primary level the kill point uses.

The twelve measured rows ran at `--compress 1`, in real time; the six illustration
rows ran at `--compress 600` because `slow` spans up to 22 hours per instance, and
compressing time is exactly what makes Wazuh's score on them an artefact of the
harness.

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
