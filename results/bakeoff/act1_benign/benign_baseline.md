# Live bake-off -- Act 1, the quiet baseline

30 benign lines at 0.5/s over 78s. **No attack was fired**, so every line is benign by construction and every alert below is a false positive.

| system | lines flagged | share of the stream | alerts |
|---|---|---|---|
| this detector | 5 | 17% | 5 in 3 incidents |
| Wazuh (level >=3) | 19 | 63% | 19 |

Wazuh is counted at level >=3, the kill point's primary level, where a single successful login is already an alert (rule 5715) -- so its count here is what saturation looks like on quiet traffic, not a failure of its rules. Ours is the precision weakness this project has carried since v1 (CLAUDE.md Known Issues), seen with no attack present at all.

This is one short run at one background rate, not a false-positive rate for either system. The recorded alert volumes are in `results/killpoint/killpoint_ambient0.05.md`.
