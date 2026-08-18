"""
killpoint.py
The pre-registered kill-point experiment (CLAUDE.md section 1b), our half.

Runs the detector across every camouflage strategy on the *real* OpenSSH
corpus and reports the drop in instance detection for each. The third-party
SIEM is measured on the identical corpora by the Wazuh runner; the deciding
number is the differential between the two systems' drops.

Registered criterion, which may not be moved after seeing results:

    >=25pt differential on at least one strategy  -> continue the roadmap
    10-25pt                                       -> cheap stages only
    <10pt, or the SIEM degrades less than we do   -> stop, publish the negative

This module deliberately writes only *our* numbers. It does not compute the
differential, because a file that reports the deciding number should not also
be the file that could quietly redefine it -- the comparison lives in its own
step, fed by both systems' outputs.
"""

import json
import tempfile
from pathlib import Path

from logdet.config import CONTAMINATION, RESULTS_DIR
from logdet_eval.adversarial import REALISTIC_COMBO, STRATEGIES, pool, run_condition
from logdet_eval.corpus_openssh import CORPUS_HOST, build_killpoint_corpus

# The corpus starts in December and runs into January; preprocessing detects
# the rollover from there.
CORPUS_START_YEAR = 2015

# baseline first -- every drop is measured against it
CONDITIONS: list[tuple[str, list[str]]] = (
    [("baseline", [])]
    + [(name, [name]) for name in STRATEGIES]
    + [("realistic-combo", REALISTIC_COMBO)]
)


def run(seeds: int = 5, start_seed: int = 42, ambient_ratio: float = 0.05,
        instances_per_scenario: int = 3,
        contamination: float = CONTAMINATION) -> dict:
    """Run every condition over `seeds` seeds and pool the results.

    Pooling over >=5 seeds is not optional (CLAUDE.md section 4): with 3
    instances per scenario a single seed moves instance detection in 33% steps,
    and v1 saw ip_rotate read 100% at one seed against 84% pooled over five.
    """
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        work_dir = Path(tmp)
        for name, strategies in CONDITIONS:
            runs = []
            for offset in range(seeds):
                seed = start_seed + offset
                base_events, manifest = build_killpoint_corpus(
                    instances_per_scenario=instances_per_scenario,
                    ambient_ratio=ambient_ratio,
                    seed=seed,
                )
                runs.append(run_condition(
                    name, strategies, base_events, work_dir, seed,
                    contamination=contamination,
                    host=CORPUS_HOST, year=CORPUS_START_YEAR,
                ))
            pooled = pool(runs)
            pooled["condition"] = name
            pooled["strategies"] = strategies
            results.append(pooled)
            rate = pooled["overall"]["instance_detection_rate"]
            print(f"  {name:<16} instance detection {rate:.0%}"
                  f"  | incidents {pooled['overall']['incidents']}")

    return {
        "corpus": "loghub-openssh",
        "ambient_ratio": ambient_ratio,
        "seeds": seeds,
        "start_seed": start_seed,
        "contamination": contamination,
        "corpus_manifest": manifest,
        "conditions": results,
    }


def drops(payload: dict) -> dict[str, float]:
    """Instance-detection drop per strategy, in percentage points."""
    by_name = {c["condition"]: c["overall"]["instance_detection_rate"]
               for c in payload["conditions"]}
    base = by_name["baseline"]
    return {name: round((base - rate) * 100, 1)
            for name, rate in by_name.items() if name != "baseline"}


def render_report(payload: dict) -> str:
    lines = [
        "# Kill-Point Measurement — Detector Half",
        "",
        "Instance detection under camouflage on the **real LogHub OpenSSH corpus**",
        f"(`ambient_ratio={payload['ambient_ratio']}`, pooled over "
        f"{payload['seeds']} seeds).",
        "",
        "These are only our numbers. The deciding figure in CLAUDE.md §1b is the",
        "*differential* against the third-party ruleset measured on the same corpora,",
        "which is computed in the comparison step.",
        "",
        "| Condition | Instance detection | Δ (pt) | Line detection | Incidents |",
        "|---|---|---|---|---|",
    ]
    base = next(c for c in payload["conditions"] if c["condition"] == "baseline")
    base_rate = base["overall"]["instance_detection_rate"]
    for cond in payload["conditions"]:
        o = cond["overall"]
        delta = "—" if cond["condition"] == "baseline" else \
            f"{(base_rate - o['instance_detection_rate']) * 100:+.1f}"
        lines.append(
            f"| {cond['condition']} | {o['instance_detection_rate']:.0%} | {delta} "
            f"| {o['line_detection_rate']:.0%} | {o['incidents']} |"
        )

    manifest = payload["corpus_manifest"]
    lines += [
        "",
        "## Corpus",
        "",
        f"- {manifest['background_lines']} real background lines "
        f"({manifest['benign_lines']} benign + real attacker traffic at "
        f"{payload['ambient_ratio']:.0%})",
        f"- {manifest['attack_lines']} injected attack lines across "
        f"{manifest['attack_instances']} instances",
        f"- {manifest['days_covered']} days, {len(manifest['real_users'])} real users "
        f"on host `{manifest['host']}`",
        "",
        "Real: every background line, the usernames, the host, the vocabulary.",
        "Authored: the injected attack instances and the camouflage layer.",
    ]
    return "\n".join(lines) + "\n"


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Kill-point measurement, detector half.")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--output-dir", default=f"{RESULTS_DIR}/killpoint")
    args = parser.parse_args()

    print(f"Kill-point sweep: {len(CONDITIONS)} conditions x {args.seeds} seeds "
          f"on the real OpenSSH corpus")
    payload = run(seeds=args.seeds, start_seed=args.seed,
                  ambient_ratio=args.ambient_ratio)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    tag = f"ambient{args.ambient_ratio:g}"
    (out / f"detector_{tag}.json").write_text(json.dumps(payload, indent=2))
    (out / f"detector_{tag}.md").write_text(render_report(payload))

    print("\nInstance-detection drops (pt):")
    for name, drop in sorted(drops(payload).items(), key=lambda kv: -kv[1]):
        print(f"  {name:<16} {drop:+.1f}")
    print(f"\nWrote -> {out}/detector_{tag}.json / .md")


if __name__ == "__main__":
    cli()
