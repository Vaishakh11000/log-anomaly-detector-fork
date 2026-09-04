"""
How often the *published* camouflage recipes thin an attack below the floor
the adaptive adversary is held to.

`logdet-adaptive` refuses a plan that leaves an instance with fewer than 3
lines, or under 40% of its original lines, before that plan can cost a detector
query -- otherwise the optimiser "evades" by deleting the attack. Applying the
same rule to the 128 fixed-magnitude strategy subsets shows the rule is not
merely hypothetical: the published `volume` recipe (keep 50% of the repeated
middle events) sometimes leaves an instance with 2 lines of 6.

That matters for how the existing `volume` row in
`results/adversarial_results.md` should be read. Runs in ~2s, no models.

    uv run python results/adaptive/volume_floor_check.py
"""

from logdet_eval.adaptive import ValidityRule, subsets_of_strategies
from logdet_eval.camouflage import CamouflagePlan
from logdet_eval.generate_logs import build_dataset

rule = ValidityRule()
for seed in (42, 43, 44, 45, 46):
    events = build_dataset(seed=seed)
    rejected = []
    for combo in subsets_of_strategies():
        ok, why = rule.check(events, CamouflagePlan(strategies=combo), seed)
        if not ok:
            rejected.append(("+".join(combo) or "baseline", why))
    with_volume = sum(1 for label, _ in rejected if "volume" in label)
    print(f"seed {seed}: {len(rejected)} of 128 subsets below the floor, "
          f"{with_volume} of them carry `volume`")
    for label, why in rejected[:2]:
        print(f"    {label}: {why}")
