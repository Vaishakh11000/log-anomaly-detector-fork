"""
Narration latency by tier and model, on whichever machine runs it.

Method is CLAUDE.md section 2c's, unchanged so the figures compare with the
ones already recorded there: the input is `llm_narrative.__main__`'s own smoke
incident, so the prompt is identical on every machine, and each figure is the
median of 3 timed runs after one warm-up, because generated length varies run
to run and a single run is not a machine property.

What is new is the tier axis. A triage line and a full narrative send prompts
of nearly the same size, so any difference between them is generation length,
which is the thing the tier split controls.

    uv run python results/routing/latency_bench.py
    uv run python results/routing/latency_bench.py --models phi3 llama3
"""

import argparse
import json
import statistics
import time

import pandas as pd

from logdet import llm_narrative
from logdet.llm_narrative import (build_prompt, build_structured_prompt,
                                  build_triage_prompt, generate_structured,
                                  generate_triage)

SMOKE = pd.DataFrame({
    "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 10:02:00",
                                 "2026-07-18 10:10:00", "2026-07-18 10:12:00"]),
    "user": ["alice"] * 4,
    "source_ip": ["203.0.113.5"] * 4,
    "impossible_travel": [False] * 4,
    "message": [
        "Failed password for alice from 203.0.113.5 port 51422 ssh2",
        "Failed password for alice from 203.0.113.5 port 51423 ssh2",
        "Accepted password for alice from 203.0.113.5 port 51430 ssh2",
        "sudo: alice : COMMAND=/bin/su root",
    ],
})


def time_tier(tier: str, model: str, repeats: int) -> dict:
    call = (lambda: generate_triage(SMOKE, model=model).line) if tier == "triage" \
        else (lambda: generate_structured(SMOKE, model=model).render())
    call()                                   # warm-up, discarded
    seconds, lengths = [], []
    for _ in range(repeats):
        started = time.time()
        text = call()
        seconds.append(time.time() - started)
        lengths.append(len(text))
    return {"tier": tier, "model": model,
            "median_seconds": round(statistics.median(seconds), 2),
            "seconds": [round(s, 2) for s in seconds],
            "median_chars": int(statistics.median(lengths))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", default=["phi3"])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", default="results/routing/latency.json")
    parser.add_argument("--ollama-url", default=None,
                        help="point at another Ollama server -- the CPU-floor "
                             "figure comes from a second server started with "
                             "CUDA_VISIBLE_DEVICES='' on port 11435 (CLAUDE.md 2c)")
    args = parser.parse_args()
    if args.ollama_url:
        llm_narrative.OLLAMA_URL = args.ollama_url

    prompts = {"triage": build_triage_prompt(SMOKE),
               "full": build_structured_prompt(SMOKE),
               "prose (reference)": build_prompt(SMOKE)}
    for name, text in prompts.items():
        print(f"{name:<18} prompt: {len(text)} chars")

    rows = []
    for model in args.models:
        for tier in ("triage", "full"):
            row = time_tier(tier, model, args.repeats)
            rows.append(row)
            print(f"{model:<8} {tier:<7} {row['median_seconds']:>6.2f}s median "
                  f"({row['median_chars']} chars)  runs={row['seconds']}", flush=True)

    payload = {"prompt_chars": {k: len(v) for k, v in prompts.items()},
               "repeats": args.repeats, "rows": rows}
    with open(args.output, "w") as handle:
        json.dump(payload, handle, indent=2)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
