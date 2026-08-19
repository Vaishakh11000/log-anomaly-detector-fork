"""
scoring.py
Detector-agnostic scoring against injected ground truth.

The kill point compares two systems that share nothing internally: ours emits a
scored dataframe, Wazuh emits alerts. The only way that comparison means
anything is if both are reduced to the same question, asked the same way:

    for each injected attack instance, did the system flag any of its lines?

So both sides are reduced to a set of flagged 1-based line numbers, and the
metrics are computed here, once. `measure_lines` reproduces the schema of
adversarial.measure() exactly -- there is a test asserting the two agree on
identical input, because two scorers that drift apart would silently turn the
kill-point differential into an artefact of the scoring code.
"""

import pandas as pd


def measure_lines(flagged_lines: set[int], ground_truth: pd.DataFrame,
                  total_lines: int, alert_count: int | None = None) -> dict:
    """Score one system's flagged line numbers against injected ground truth.

    `flagged_lines` is 1-based into the log file, matching the `line_number`
    column ground truth uses. Lines outside the ground truth are not scored:
    the real corpus contains genuine attacks nobody labelled, so counting them
    as false positives would penalise a system for being right.
    """
    gt = ground_truth.copy()
    gt["is_anomaly"] = gt["line_number"].isin(flagged_lines)

    per_scenario = {}
    for scenario, rows in gt.groupby("scenario"):
        instances = rows.groupby("instance")["is_anomaly"].any()
        per_scenario[scenario] = {
            "attack_lines": int(len(rows)),
            "lines_detected": int(rows["is_anomaly"].sum()),
            "line_detection_rate": round(float(rows["is_anomaly"].mean()), 3),
            "instances": int(len(instances)),
            "instances_detected": int(instances.sum()),
            "instance_detection_rate": round(float(instances.mean()), 3),
        }

    all_instances = gt.groupby(["scenario", "instance"])["is_anomaly"].any()
    return {
        "overall": {
            "attack_lines": int(len(gt)),
            "line_detection_rate": round(float(gt["is_anomaly"].mean()), 3),
            "instance_detection_rate": round(float(all_instances.mean()), 3),
            "total_flagged_lines": len(flagged_lines),
            "total_lines": total_lines,
            "alerts": alert_count if alert_count is not None else len(flagged_lines),
        },
        "per_scenario": per_scenario,
    }


def instance_drop(baseline: dict, camouflaged: dict) -> float:
    """Drop in instance detection, in percentage points.

    This is the quantity CLAUDE.md section 1b is written in terms of, for both
    systems. Positive means camouflage worked.
    """
    return round(
        (baseline["overall"]["instance_detection_rate"]
         - camouflaged["overall"]["instance_detection_rate"]) * 100,
        1,
    )


def differential(ours_drop: float, siem_drop: float) -> float:
    """The deciding number: how much more the SIEM degrades than we do.

    Positive means the SIEM lost more ground to camouflage than this system
    did, which is the direction the roadmap's premise requires. Negative is the
    'stop and publish the negative result' case, and it is reported with the
    same sign convention either way -- there is no branch here that could
    quietly reinterpret an unfavourable result.
    """
    return round(siem_drop - ours_drop, 1)


MIN_ADMISSIBLE_SEEDS = 5
"""CLAUDE.md section 4: instance detection must be pooled over >=5 seeds. With 3
instances per scenario a single seed moves the number in 33% steps, and v1 saw
ip_rotate read 100% at one seed against 84% pooled over five."""


def verdict(best_differential: float) -> str:
    """Apply the pre-registered section 1b criterion. Thresholds are literals on
    purpose: they were registered before any Stage 1 code was written and are
    not configurable, because a threshold you can pass as an argument is a
    threshold you can move after seeing the result."""
    if best_differential >= 25:
        return "CONTINUE"
    if best_differential >= 10:
        return "PARTIAL"
    return "STOP"


_POOLED = ("attack_lines", "lines_detected", "instances", "instances_detected")


def pool_runs(runs: list[dict]) -> dict:
    """Pool per-seed results of one condition into a single result.

    Rates are recomputed from summed counts rather than averaged, so a seed that
    happens to produce fewer attack lines does not get equal weight -- the same
    rule adversarial.pool() follows. Pooling matters here more than usual: with
    3 instances per scenario a single seed moves instance detection in 33%
    steps, and v1 saw one strategy read 100% at a single seed against 84% pooled
    over five.
    """
    if not runs:
        raise ValueError("nothing to pool")

    scenarios = sorted({s for run in runs for s in run["per_scenario"]})
    per_scenario = {}
    for scenario in scenarios:
        rows = [run["per_scenario"][scenario] for run in runs
                if scenario in run["per_scenario"]]
        totals = {key: sum(row[key] for row in rows) for key in _POOLED}
        per_scenario[scenario] = {
            **totals,
            "line_detection_rate": _rate(totals["lines_detected"], totals["attack_lines"]),
            "instance_detection_rate": _rate(totals["instances_detected"], totals["instances"]),
        }

    attack_lines = sum(r["overall"]["attack_lines"] for r in runs)
    lines_detected = sum(s["lines_detected"] for s in per_scenario.values())
    instances = sum(s["instances"] for s in per_scenario.values())
    instances_detected = sum(s["instances_detected"] for s in per_scenario.values())

    return {
        "overall": {
            "attack_lines": attack_lines,
            "line_detection_rate": _rate(lines_detected, attack_lines),
            "instance_detection_rate": _rate(instances_detected, instances),
            "instances": instances,
            "instances_detected": instances_detected,
            "total_flagged_lines": sum(r["overall"]["total_flagged_lines"] for r in runs),
            "alerts": sum(r["overall"]["alerts"] for r in runs),
            "seeds": len(runs),
        },
        "per_scenario": per_scenario,
    }


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 3) if denominator else 0.0
