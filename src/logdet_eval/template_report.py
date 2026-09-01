"""
template_report.py
Inspects the templates Drain3 mines from a corpus, before any detection code
reads them.

Stage 3 replaces the hand-written regex templater with mined templates, and the
mining is a *learned* structure -- it is not obvious in advance whether it
recovers the log's real event vocabulary or shreds it. Two failure modes matter
and neither announces itself downstream:

- **Over-merging.** Two semantically different events land in one cluster, so a
  model keyed on the template id can no longer tell them apart. A failed
  password and an accepted password collapsing together would destroy exactly
  the signal this project detects on.
- **Over-splitting.** One event becomes many clusters because a variable field
  was not masked, so a sequence model sees a vocabulary that never repeats and
  every session looks novel.

Both are visible by comparing the mined clusters against the regex templates
already in the pipeline, which is what this report does. It is a read-only
inspection: it fits nothing, scores nothing, and changes no result.

Lives in `logdet_eval/` because it measures the pipeline rather than being part
of it (CLAUDE.md section 5 -- the dependency runs one way only).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from logdet import config as pipeline_config
from logdet.preprocessing import LineParser, template_message
from logdet.templating import TemplateMiner

from .datasets import CORPORA


# How many clusters the report lists in full. The tail is summarised by count:
# a mined set with thousands of singletons is a finding in itself, but printing
# them all makes the report unreadable.
TOP_N = 30

# Growth is sampled at these line counts, to show whether the cluster count
# saturates or keeps climbing. A vocabulary still growing at the end of 655k
# lines is not a vocabulary -- it means something variable is leaking into the
# templates. Absolute milestones rather than fractions of the corpus, because
# the total is not known until the file has been read once and reading it twice
# to find out would double the cost for a diagnostic.
GROWTH_CHECKPOINTS = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000,
                      250_000, 500_000, 1_000_000)


def mine_corpus(path: str, limit: int | None = None, year: int | None = None) -> dict:
    """Parse a raw log and mine its templates. Returns everything the report needs.

    Parsing runs through the pipeline's own `LineParser`, so the report inspects
    the same messages detection would see -- not a separately tokenised copy
    that could disagree with it.
    """
    miner = TemplateMiner()
    parser = LineParser(year=year, miner=miner)

    total_lines = 0
    parsed_count = 0
    # regex template -> Counter of mined cluster ids that regex template got
    # split across, and the reverse. These two maps are the whole diagnostic.
    regex_to_clusters: dict[str, Counter] = defaultdict(Counter)
    cluster_to_regex: dict[int, Counter] = defaultdict(Counter)
    growth: list[tuple[int, int]] = []

    checkpoints = set(GROWTH_CHECKPOINTS)

    with open(path, "r", errors="ignore") as handle:
        for line in handle:
            if limit is not None and total_lines >= limit:
                break
            total_lines += 1
            record = parser.parse(line)
            if record is None:
                continue
            parsed_count += 1
            cluster_id = record.get("template_id")
            if cluster_id is None:
                continue
            regex_template = record["template"]
            regex_to_clusters[regex_template][cluster_id] += 1
            cluster_to_regex[cluster_id][regex_template] += 1
            if total_lines in checkpoints:
                growth.append((total_lines, miner.cluster_count))

    if not growth or growth[-1][0] != total_lines:
        growth.append((total_lines, miner.cluster_count))

    return {
        "path": path,
        "total_lines": total_lines,
        "parsed_lines": parsed_count,
        "parse_rate": parsed_count / total_lines if total_lines else 0.0,
        "mined_clusters": miner.cluster_count,
        "regex_templates": len(regex_to_clusters),
        "templates": miner.templates(),
        "regex_to_clusters": {k: dict(v) for k, v in regex_to_clusters.items()},
        "cluster_to_regex": {k: dict(v) for k, v in cluster_to_regex.items()},
        "growth": growth,
        "miner": miner,
    }


def summarise_disagreements(result: dict) -> dict:
    """Where the mined clusters and the regex templates disagree, and how much.

    A one-to-one mapping means Drain3 recovered the regex's vocabulary without
    being told it, which is the result that would justify swapping them. Every
    departure from that is either a split or a merge, and merges are the
    dangerous direction -- a split costs a sequence model some sharpness, a
    merge destroys a distinction the detector currently makes.
    """
    splits = []      # one regex template mined into several clusters
    merges = []      # one cluster covering several regex templates

    for regex_template, clusters in result["regex_to_clusters"].items():
        if len(clusters) > 1:
            splits.append({
                "regex_template": regex_template,
                "cluster_count": len(clusters),
                "lines": sum(clusters.values()),
                "clusters": sorted(clusters.items(), key=lambda kv: -kv[1]),
            })

    for cluster_id, regexes in result["cluster_to_regex"].items():
        if len(regexes) > 1:
            merges.append({
                "template_id": cluster_id,
                "mined_template": result["miner"].template_for(cluster_id),
                "regex_count": len(regexes),
                "lines": sum(regexes.values()),
                "regex_templates": sorted(regexes.items(), key=lambda kv: -kv[1])[:6],
            })

    splits.sort(key=lambda d: -d["lines"])
    merges.sort(key=lambda d: -d["lines"])
    return {"splits": splits, "merges": merges}


# A merged cluster absorbed some variation. Whether that is harmless or costly
# depends on *what* varied: a position taking hundreds of values is an
# identifier (a username, a hostname) and collapsing it is the whole point of
# templating, while a position taking two or three values is usually a word that
# changes what the event means -- `Failed password` against `Failed none`. This
# is the cardinality below which a varying position is reported as a possible
# lost distinction rather than as an absorbed identifier.
SEMANTIC_MERGE_MAX_VALUES = 6


def varying_positions(regex_templates: list[str]) -> list[dict]:
    """Which token positions differ across the regex templates in one cluster.

    Compared token-wise, so it only speaks for templates of equal length;
    unequal ones are reported as a length difference instead, which is itself
    the coarsest possible sign that two different events were merged.
    """
    tokenised = [t.split() for t in regex_templates]
    lengths = {len(t) for t in tokenised}
    if len(lengths) > 1:
        return [{"position": None, "values": sorted(f"<{n} tokens>" for n in lengths),
                 "cardinality": len(lengths)}]

    out = []
    for index in range(next(iter(lengths))):
        values = {tokens[index] for tokens in tokenised}
        if len(values) > 1:
            out.append({
                "position": index,
                "values": sorted(values)[:8],
                "cardinality": len(values),
            })
    return out


def semantic_merges(result: dict, merges: list[dict]) -> list[dict]:
    """Merges that absorbed a *low-cardinality* word, i.e. a likely lost meaning.

    This is the finding that decides whether mined ids can replace the regex
    templates in detection, so it is computed rather than eyeballed off the
    tables above.
    """
    flagged = []
    for row in merges:
        regexes = list(result["cluster_to_regex"][row["template_id"]].keys())
        positions = [p for p in varying_positions(regexes)
                     if p["cardinality"] <= SEMANTIC_MERGE_MAX_VALUES]
        if positions:
            flagged.append({**row, "positions": positions})
    return flagged


def _pct(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.2f}%" if whole else "n/a"


def render(result: dict, disagreements: dict) -> str:
    """The Markdown report. Every claim in it is computed, none is asserted."""
    templates = result["templates"]
    total_matched = sum(t["size"] for t in templates) or 1
    singletons = [t for t in templates if t["size"] == 1]
    rare = [t for t in templates if t["size"] <= 5]

    lines: list[str] = []
    add = lines.append

    add("# Drain3 template inventory")
    add("")
    add(f"Corpus: `{result['path']}`")
    add("")
    add("Read-only inspection, run before any detection code reads a mined")
    add("template id. Nothing here was fitted, scored, or tuned.")
    add("")
    add("## Corpus")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Lines read | {result['total_lines']:,} |")
    add(f"| Lines parsed | {result['parsed_lines']:,} ({_pct(result['parsed_lines'], result['total_lines'])}) |")
    add(f"| Distinct regex templates (`template_message`) | {result['regex_templates']:,} |")
    add(f"| Distinct mined templates (Drain3) | {result['mined_clusters']:,} |")
    add("")
    add(f"Drain3 settings: `sim_th={pipeline_config.DRAIN_SIM_TH}`, "
        f"`depth={pipeline_config.DRAIN_DEPTH}`, "
        f"`max_children={pipeline_config.DRAIN_MAX_CHILDREN}`, "
        f"`max_clusters={pipeline_config.DRAIN_MAX_CLUSTERS}`, "
        f"`parametrize_numeric_tokens={pipeline_config.DRAIN_PARAMETRIZE_NUMERIC}`, "
        "plus IP/PORT/PID/HEX masking (see `logdet/templating.py`).")
    add("")

    add("## Does the vocabulary settle?")
    add("")
    add("Cluster count against lines read. A count still climbing at the end of")
    add("the corpus means something variable is leaking into the templates,")
    add("which would give a sequence model a vocabulary that never repeats.")
    add("")
    add("| Lines read | Clusters |")
    add("|---:|---:|")
    for seen, clusters in result["growth"]:
        add(f"| {seen:,} | {clusters:,} |")
    add("")

    add(f"## The {min(TOP_N, len(templates))} largest templates")
    add("")
    add("| id | lines | share | template |")
    add("|---:|---:|---:|---|")
    for row in templates[:TOP_N]:
        template = row["template"].replace("|", "\\|")
        add(f"| {row['template_id']} | {row['size']:,} | "
            f"{_pct(row['size'], total_matched)} | `{template}` |")
    add("")
    head_share = sum(t["size"] for t in templates[:TOP_N])
    add(f"Those {min(TOP_N, len(templates))} templates cover "
        f"{_pct(head_share, total_matched)} of all matched lines.")
    add("")

    add("## The tail")
    add("")
    add(f"- Templates matching exactly one line: **{len(singletons):,}** "
        f"({_pct(len(singletons), len(templates))} of templates, "
        f"{_pct(len(singletons), total_matched)} of lines)")
    add(f"- Templates matching 5 lines or fewer: **{len(rare):,}** "
        f"({_pct(len(rare), len(templates))} of templates)")
    add("")
    add("A rare template is not automatically an attack, but it is where the")
    add("rare events are, so a large singleton count is what a sequence model")
    add("would spend most of its vocabulary on.")
    add("")

    add("## Agreement with the existing regex templater")
    add("")
    add("The two templaters are compared per line: which regex template the")
    add("line got, and which mined cluster. Perfect agreement would be one")
    add("cluster per regex template and vice versa.")
    add("")
    splits, merges = disagreements["splits"], disagreements["merges"]
    add(f"- Regex templates split across more than one mined cluster: **{len(splits):,}**")
    add(f"- Mined clusters covering more than one regex template: **{len(merges):,}**")
    add("")
    add("**Merges are the direction that costs detection signal** -- two")
    add("distinguishable events becoming one id. Splits cost sharpness, not")
    add("distinctions.")
    add("")

    if merges:
        add("### Largest merges (one mined cluster, several regex templates)")
        add("")
        add("| id | lines | regex templates | mined template |")
        add("|---:|---:|---:|---|")
        for row in merges[:15]:
            mined = (row["mined_template"] or "").replace("|", "\\|")
            add(f"| {row['template_id']} | {row['lines']:,} | {row['regex_count']} | `{mined}` |")
        add("")
        add("What went into the biggest of them:")
        add("")
        for row in merges[:3]:
            add(f"- **cluster {row['template_id']}** "
                f"(`{(row['mined_template'] or '').replace('|', chr(92) + '|')}`)")
            for regex_template, count in row["regex_templates"]:
                add(f"  - {count:,} x `{regex_template.replace('|', chr(92) + '|')}`")
        add("")

    flagged = semantic_merges(result, merges)
    add("### Merges that may have absorbed a distinction, not an identifier")
    add("")
    add("A merged cluster collapsed some token position. Where that position")
    add(f"takes many values it is an identifier and collapsing it is the point;")
    add(f"where it takes {SEMANTIC_MERGE_MAX_VALUES} or fewer it is usually a word that changes what")
    add("the event *means*, and the mined id can no longer tell the two apart.")
    add("")
    if not flagged:
        add("None: every merge absorbed a high-cardinality position.")
        add("")
    else:
        add("| id | lines | position | values absorbed |")
        add("|---:|---:|---:|---|")
        for row in flagged[:15]:
            for position in row["positions"][:3]:
                where = "length" if position["position"] is None else f"token {position['position']}"
                values = ", ".join(f"`{v}`" for v in position["values"])
                add(f"| {row['template_id']} | {row['lines']:,} | {where} | {values} |")
        add("")

    if splits:
        add("### Largest splits (one regex template, several mined clusters)")
        add("")
        add("| lines | clusters | regex template |")
        add("|---:|---:|---|")
        for row in splits[:15]:
            template = row["regex_template"].replace("|", "\\|")
            add(f"| {row['lines']:,} | {row['cluster_count']} | `{template}` |")
        add("")

    add("## What this does not say")
    add("")
    add("- No detection code reads `template_id` yet, so no number in")
    add("  `results/` moved and CLAUDE.md section 4 was not triggered.")
    add("- Cluster ids are only meaningful relative to the miner state that")
    add("  produced them: Drain3 is online, so the ids depend on the order the")
    add("  lines arrived. A different corpus, or this one shuffled, numbers")
    add("  them differently.")
    add("- The mined template text a line was given at mining time is not the")
    add("  text its cluster carries at the end of the run -- templates widen as")
    add("  more lines arrive. Every template printed above is the final one.")
    return "\n".join(lines) + "\n"


def build_report(path: str, output_dir: str, limit: int | None = None,
                 year: int | None = None, state_path: str | None = None) -> Path:
    result = mine_corpus(path, limit=limit, year=year)
    disagreements = summarise_disagreements(result)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / "template_inventory.md"
    report_path.write_text(render(result, disagreements))

    (out / "templates.json").write_text(json.dumps({
        "path": result["path"],
        "total_lines": result["total_lines"],
        "parsed_lines": result["parsed_lines"],
        "mined_clusters": result["mined_clusters"],
        "regex_templates": result["regex_templates"],
        "growth": result["growth"],
        "templates": result["templates"],
        "splits": len(disagreements["splits"]),
        "merges": len(disagreements["merges"]),
        "semantic_merges": [
            {"template_id": r["template_id"], "lines": r["lines"],
             "mined_template": r["mined_template"], "positions": r["positions"]}
            for r in semantic_merges(result, disagreements["merges"])
        ],
    }, indent=2))

    if state_path:
        result["miner"].save(state_path)

    print(f"Parsed {result['parsed_lines']:,}/{result['total_lines']:,} lines; "
          f"mined {result['mined_clusters']:,} templates "
          f"against {result['regex_templates']:,} regex templates")
    print(f"Report -> {report_path}")
    return report_path


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect the templates Drain3 mines from a raw log corpus.")
    parser.add_argument("--input", default=str(CORPORA["openssh"].log_path),
                        help="Raw log file to mine (default: the LogHub OpenSSH corpus)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only read the first N lines")
    parser.add_argument("--year", type=int, default=None,
                        help="Year to assume (syslog omits it)")
    parser.add_argument("--output", default=str(Path(pipeline_config.RESULTS_DIR) / "templates"),
                        help="Directory to write the report into")
    parser.add_argument("--state", default=None,
                        help="Also persist the mined template table here")
    args = parser.parse_args()
    if not Path(args.input).exists():
        parser.error(f"{args.input} not found -- fetch it with `logdet-fetch-data openssh`")

    build_report(args.input, args.output, limit=args.limit, year=args.year,
                 state_path=args.state)


if __name__ == "__main__":
    cli()
