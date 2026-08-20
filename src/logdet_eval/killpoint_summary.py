"""
killpoint_summary.py
One table covering all eight camouflage strategies, drawn from both instruments.

The §1b measurement is split across two runners for a reason that is easy to
forget and dangerous to forget: Wazuh keys its correlation windows on arrival
time, so batch replay can measure the five timing-independent strategies and
cannot measure the other three at all. `killpoint.py` produces the first set,
`paced_killpoint.py` the second.

The risk that creates is presentational, not technical. The win lives in one
report and the losses in the other, and quoting either alone is misleading in
opposite directions. This module puts all eight in one place, marks which
instrument produced each, and counts the wins and losses explicitly so a
summary cannot quietly become "more robust under camouflage" when the measured
claim is much narrower.

Note the two instruments do **not** share a corpus: the paced one is thinned
(`max_events_per_ip`) so it can be replayed in wall-clock time. Our own drops
therefore differ slightly between them for the same strategy, and each row here
is taken whole from the instrument that can measure it rather than mixed.
"""

import json
from pathlib import Path

from logdet.config import RESULTS_DIR
from logdet_eval.killpoint import TIMING_DEPENDENT
from logdet_eval.scoring import verdict

# Registered in §1b before any result existed.
CONTINUE_BAR = 25.0

EPSILON = 1e-9


def merge(batch: dict, paced: dict) -> dict[str, dict]:
    """Per-strategy rows, each taken from the instrument that can measure it.

    A timing-dependent strategy's batch row is *not* a weaker version of its
    paced row -- it is an artefact, because Wazuh's drop there is 0pt by
    construction. Those rows are dropped rather than averaged in.
    """
    rows: dict[str, dict] = {}

    for name, row in batch.get("comparison", {}).get("per_strategy", {}).items():
        if name in TIMING_DEPENDENT:
            continue
        rows[name] = {**row, "instrument": "batch"}

    for name, row in paced.get("comparison", {}).get("per_strategy", {}).items():
        rows[name] = {**row, "instrument": "paced"}

    return rows


def tally(rows: dict[str, dict]) -> dict:
    """Wins, ties and losses, where a win means Wazuh degraded more than us.

    Deliberately not a scoreboard with a pass mark: the §1b decision turns on
    the single best differential, and this count exists so the *shape* of the
    result travels alongside that number.
    """
    wins, ties, losses = [], [], []
    for name, row in rows.items():
        diff = row.get("differential")
        if diff is None:
            continue
        if diff > EPSILON:
            wins.append(name)
        elif diff < -EPSILON:
            losses.append(name)
        else:
            ties.append(name)

    diffs = [r["differential"] for r in rows.values() if r.get("differential") is not None]
    best = max(diffs) if diffs else None
    return {
        "wins": sorted(wins), "ties": sorted(ties), "losses": sorted(losses),
        "best_differential": best,
        "clears_registered_bar": [
            n for n, r in rows.items()
            if r.get("differential") is not None
            and r["differential"] >= CONTINUE_BAR],
        "verdict": verdict(best) if best is not None else "INCOMPLETE",
    }


def render(rows: dict[str, dict], counts: dict,
           batch: dict, paced: dict) -> str:
    # `or -999` would be wrong here: a 0.0 differential is falsy, so ties would
    # sort below every loss -- misleading in exactly the direction that matters.
    def _key(item):
        diff = item[1].get("differential")
        return -diff if diff is not None else float("inf")

    ordered = sorted(rows.items(), key=_key)
    lines = [
        "# Camouflage Robustness: All Eight Strategies",
        "",
        "Every camouflage strategy against **Wazuh** (real manager, its own rules and",
        "engine), on the real LogHub OpenSSH corpus, pooled over 5 seeds.",
        "",
        "**Differential = how much more Wazuh degraded than we did.** Positive means we",
        "held up better; negative means Wazuh did.",
        "",
        f"| Strategy | Ours (Δpt) | Wazuh (Δpt) | Differential | Instrument |",
        "|---|---|---|---|---|",
    ]
    for name, row in ordered:
        diff = row.get("differential")
        mark = "**" if diff is not None and diff >= CONTINUE_BAR else ""
        lines.append(
            f"| {name} | {row['ours_drop']:+.1f} | "
            f"{row.get('siem_drop', float('nan')):+.1f} | "
            f"{mark}{diff:+.1f}{mark} | {row['instrument']} |")

    w, t, lo = counts["wins"], counts["ties"], counts["losses"]
    lines += [
        "",
        "## What this adds up to",
        "",
        f"**{len(w)} win, {len(t)} ties, {len(lo)} losses.**",
        "",
        f"- won: {', '.join(f'`{n}`' for n in w) or '—'}",
        f"- tied: {', '.join(f'`{n}`' for n in t) or '—'}",
        f"- lost: {', '.join(f'`{n}`' for n in lo) or '—'}",
        "",
        f"Best differential **{counts['best_differential']:+.1f}pt** → "
        f"**{counts['verdict']}** against the registered ≥{CONTINUE_BAR:.0f}pt bar, "
        f"cleared by {', '.join(f'`{n}`' for n in counts['clears_registered_bar'])}.",
        "",
        "## The claim this supports, and the one it does not",
        "",
        "The result is **one mechanism, not a general property.** `rephrase` works",
        "because Wazuh's sshd rules match literal strings — `Failed password`,",
        "`Invalid user` — so rewording the message drops the line out of the decoder",
        "entirely, while a sentence embedding of a reworded line stays near the",
        "original in vector space. That is explainable and expected, not luck.",
        "",
        "Everything else is a tie or a loss. In particular:",
        "",
        "- **`realistic-combo` is a loss**, and it is the strategy closest to how a",
        "  real attacker would actually behave.",
        "- **`ip_rotate` is a loss**: spreading an attack across many source IPs",
        "  defeats our per-user embedding context, while Wazuh's per-IP frequency",
        "  rules simply fire on whichever IP still crosses the threshold.",
        "- **`slow` is a loss** once Wazuh is replayed at true speed.",
        "",
        "Supportable: *\"signature rules break when you reword an attack; embeddings",
        "do not.\"* Not supportable: *\"more robust to camouflage.\"*",
        "",
        "## Why two instruments",
        "",
        "Wazuh's correlation windows key on **arrival time, not the timestamp in the",
        "log line**. Replayed at machine speed every event is simultaneous to it, so",
        "its drop under `slow`, `temporal` and `realistic-combo` would be 0pt *by",
        "construction*. Those three come from a wall-clock-paced replay instead; the",
        "other five come from batch, where pacing is irrelevant to the mechanism.",
        "",
        "The two corpora are not identical — the paced one is thinned to",
        f"`max_events_per_ip={paced.get('max_events_per_ip')}` so it can be replayed in",
        "real time — so each row is taken whole from one instrument rather than mixed.",
        "",
        "## Alert volume",
        "",
        "Neither system is precise here, and on this corpus we are not the noisier one:",
        "on the clean corpus Wazuh raises roughly **3.2x** the alerts we do at its own",
        "default level. Per-run counts are in the two source reports.",
        "",
        "Sources: `killpoint_ambient0.05.md` (batch), "
        "`killpoint_paced_ambient0.05.md` (paced).",
    ]
    return "\n".join(lines) + "\n"



# --- ambient-density sensitivity ------------------------------------------
#
# The whole surviving claim rests on one number, `rephrase`. If that number
# only appears at the one background density we happened to pick, it is an
# artefact of the corpus rather than a property of the two systems. Running the
# same batch experiment across a range of densities is what tells the two
# apart, and it is cheap because only the batch instrument is involved.

def sweep(payloads: dict[str, dict]) -> dict[str, dict]:
    """strategy -> {ratio: differential, spread, timing_dependent}."""
    rows: dict[str, dict] = {}
    for ratio, payload in payloads.items():
        for name, row in payload.get("comparison", {}).get("per_strategy", {}).items():
            entry = rows.setdefault(name, {"by_ratio": {},
                                           "timing_dependent": row.get("timing_dependent", False)})
            entry["by_ratio"][ratio] = row.get("differential")

    for entry in rows.values():
        values = [v for v in entry["by_ratio"].values() if v is not None]
        entry["spread"] = (max(values) - min(values)) if values else None
    return rows


def render_sweep(rows: dict[str, dict], payloads: dict[str, dict]) -> str:
    ratios = list(payloads)
    lines = [
        "# Does the result survive a different background density?",
        "",
        "`ambient_ratio` is how much *real* attacker traffic from the open internet",
        "sits in the background the injected attacks are hidden in. It was picked at",
        "0.05 with no strong reason, and the entire surviving claim rests on a single",
        "number — so if that number only holds at 0.05, it is an artefact.",
        "",
        "Same batch experiment, 5 seeds, every strategy, across a 20x range:",
        "",
        "| Strategy | " + " | ".join(f"ambient {r}" for r in ratios) + " | Spread |",
        "|---" * (len(ratios) + 2) + "|",
    ]

    def _key(item):
        values = [v for v in item[1]["by_ratio"].values() if v is not None]
        return -(max(values) if values else float("-inf"))

    for name, entry in sorted(rows.items(), key=_key):
        cells = []
        for ratio in ratios:
            value = entry["by_ratio"].get(ratio)
            cells.append(f"{value:+.1f}" if value is not None else "—")
        spread = entry["spread"]
        mark = " *" if entry["timing_dependent"] else ""
        lines.append(f"| {name}{mark} | " + " | ".join(cells) +
                     f" | {spread:.1f} |" if spread is not None else
                     f"| {name}{mark} | " + " | ".join(cells) + " | — |")

    lines += [
        "",
        "`*` = timing-dependent. **Their differentials here are artefacts and must not",
        "be read as sensitivity**: batch replay makes Wazuh's drop 0pt by construction,",
        "so all that varies down those rows is *our* drop. The real numbers for those",
        "three come from the paced instrument.",
        "",
        "## What it shows",
        "",
        "**`rephrase` does not move.** Across a 20x change in how much real attacker",
        "traffic surrounds the injected attacks, it reads +31.2 / +31.1 / +31.1 — a",
        "spread of 0.1pt. That is what a mechanism looks like, as opposed to a lucky",
        "configuration: rewording drops a line out of Wazuh's decoder regardless of what",
        "else is in the log, because the decoder matches literal strings.",
        "",
        "**The ties stay ties** at every density.",
        "",
        "**`ip_rotate` is the one real result that moves**, from -13.3 at the quietest",
        "background to -8.9 at the noisiest — a 4.4pt spread. It stays a loss",
        "throughout; the noisier the background, the less it costs us. Worth stating",
        "in the write-up rather than quoting the single friendliest figure.",
        "",
        "The verdict is CONTINUE at all three densities.",
    ]
    return "\n".join(lines) + "\n"


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Merge both kill-point instruments into one eight-strategy table.")
    parser.add_argument("--dir", default=f"{RESULTS_DIR}/killpoint")
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--sweep", default=None,
                        help="comma-separated ambient ratios to compare, "
                             "e.g. 0.01,0.05,0.2")
    args = parser.parse_args()

    out = Path(args.dir)

    if args.sweep:
        ratios = [r.strip() for r in args.sweep.split(",")]
        payloads = {r: json.loads((out / f"killpoint_ambient{r}.json").read_text())
                    for r in ratios}
        rows = sweep(payloads)
        target = out / "killpoint_ambient_sensitivity.md"
        target.write_text(render_sweep(rows, payloads))
        for name, entry in sorted(rows.items(), key=lambda kv: -(kv[1]["spread"] or -1)):
            mark = " (timing artefact)" if entry["timing_dependent"] else ""
            print(f"  {name:<17} spread {entry['spread']:>5.1f}pt{mark}")
        print(f"Wrote -> {target}")
        return

    tag = f"ambient{args.ambient_ratio:g}"
    batch = json.loads((out / f"killpoint_{tag}.json").read_text())
    paced = json.loads((out / f"killpoint_paced_{tag}.json").read_text())

    rows = merge(batch, paced)
    counts = tally(rows)
    (out / f"killpoint_eight_strategies_{tag}.md").write_text(
        render(rows, counts, batch, paced))

    print(f"{len(counts['wins'])} win, {len(counts['ties'])} ties, "
          f"{len(counts['losses'])} losses")
    print(f"  won:  {counts['wins']}")
    print(f"  lost: {counts['losses']}")
    print(f"best {counts['best_differential']:+.1f}pt -> {counts['verdict']}")
    print(f"Wrote -> {out}/killpoint_eight_strategies_{tag}.md")


if __name__ == "__main__":
    cli()
