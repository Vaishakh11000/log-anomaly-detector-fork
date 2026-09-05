"""
multisource_run.py
Score an authentic two-source attack -- ssh + web from one IP -- and report
whether the two halves correlate into one incident, with real detection.

This is the measurement Stage 4 could not do for want of a corpus
(`results/correlation/notes.md`: one genuine cross-service link in 9,666 real
events) and Stage 7 unblocked: `logdet/weblog.py` gave the web source a parser,
`attack_runner web_bruteforce` gives an authentic web attack, and
`corpus_multisource.build_multisource_corpus` injects both halves into the real
OpenSSH benign background sharing one source IP.

It builds the corpus, runs the real detection chain on the merged parsed frame
(embed -> Isolation Forest -> grouping), scores each source with the kill
point's own `scoring.measure_lines`, and -- the point of the whole stage --
reports how many incidents carry *both* an ssh line and a web line, i.e. how
many cross-source attacks were correlated into a single alert.

Nothing here touches detection, grouping or scoring code, so §4's re-run
obligation does not apply; it is a runner over authentic captures.

    # after carrying capture/ back from Kali (see attack_runner/KALI_RUNBOOK.md):
    uv run python results/kali/multisource_run.py \
        --ssh capture/A_1.log:capture/A_1_gt.csv \
        --web capture/W_1.log:capture/W_1_gt.csv --seeds 5

    uv run python results/kali/multisource_run.py --smoke    # wiring check, no real data
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from logdet.anomaly_detection import run_anomaly_detection
from logdet.embedding import add_embeddings_to_df
from logdet.sequence_grouping import group_anomalies
from logdet_eval import scoring
from logdet_eval.corpus_captured import parse_pairs
from logdet_eval.corpus_multisource import build_multisource_corpus


def score_once(ssh_pairs, web_pairs, shared_ip, ambient_ratio, seed,
               ssh_source=None, web_background=None):
    """Build one corpus, detect, and return per-source rates + correlation count."""
    merged, gt, manifest = build_multisource_corpus(
        ssh_pairs, web_pairs, shared_ip=shared_ip, ambient_ratio=ambient_ratio,
        seed=seed, ssh_source=ssh_source, web_background=web_background)

    scored = run_anomaly_detection(add_embeddings_to_df(merged))
    flagged = {pos + 1 for pos in scored.index[scored["is_anomaly"]]}
    rates = scoring.measure_lines(flagged, gt, total_lines=len(scored))

    incidents = group_anomalies(scored)
    # A cross-source incident carries a web line (process "nginx") and an ssh
    # line in the same alert. Authentic captures from a modern OpenSSH log the
    # per-connection worker as "sshd-session", not "sshd" (see KALI captures),
    # so match any "sshd" variant rather than the bare name.
    def _cross(procs: set[str]) -> bool:
        return "nginx" in procs and any(p.startswith("sshd") for p in procs)
    cross = [g for g in incidents if _cross(set(g["process"].dropna()))]
    return {
        "seed": seed,
        "rates": rates,
        "incidents": len(incidents),
        "cross_source_incidents": len(cross),
        "attack_lines": int(len(gt)),
        "total_lines": int(len(merged)),
    }


def _smoke_fixtures():
    """Tiny authentic-shaped captures + a small ssh background, for a wiring
    check that needs no Kali data. Not a measurement -- one toy instance per
    source has no real baseline (see results/kali/notes.md)."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="multisource_smoke_"))
    (d / "A_1.log").write_text(
        "Jul 18 03:10:00 labsz sshd[9]: Failed password for root from 127.0.0.1 port 40000 ssh2\n"
        "Jul 18 03:10:02 labsz sshd[9]: Failed password for root from 127.0.0.1 port 40001 ssh2\n"
        "Jul 18 03:10:04 labsz sshd[9]: Failed password for root from 127.0.0.1 port 40002 ssh2\n")
    (d / "A_1_gt.csv").write_text(
        "line_number,timestamp,user,scenario,instance,description\n"
        "1,2026-07-18T03:10:00,root,A,1,bf\n2,2026-07-18T03:10:02,root,A,1,bf\n"
        "3,2026-07-18T03:10:04,root,A,1,bf\n")
    (d / "W_1.log").write_text(
        '203.0.113.66 - - [18/Jul/2026:03:13:00 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "c"\n'
        '203.0.113.66 - - [18/Jul/2026:03:13:01 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "c"\n'
        '203.0.113.66 - - [18/Jul/2026:03:13:02 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "c"\n')
    (d / "W_1_gt.csv").write_text(
        "line_number,timestamp,user,scenario,instance,description\n"
        "1,2026-07-18T03:13:00,,W,1,wb\n2,2026-07-18T03:13:01,,W,1,wb\n"
        "3,2026-07-18T03:13:02,,W,1,wb\n")
    bg = d / "bg.log"
    lines = [f"Jul 18 0{i%6}:0{i%6}:00 labsz sshd[{i}]: "
             f"Accepted password for root from 192.168.1.{i+2} port 22 ssh2"
             for i in range(12)]
    bg.write_text("\n".join(lines) + "\n")
    return ([(str(d / "A_1.log"), str(d / "A_1_gt.csv"))],
            [(str(d / "W_1.log"), str(d / "W_1_gt.csv"))], str(bg))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ssh", nargs="*", default=[], metavar="corpus.log:gt.csv")
    p.add_argument("--web", nargs="*", default=[], metavar="access.log:gt.csv")
    p.add_argument("--web-background", default=None,
                   help="optional real benign nginx access log")
    p.add_argument("--shared-ip", default="203.0.113.66")
    p.add_argument("--ambient-ratio", type=float, default=0.05)
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--seed-start", type=int, default=42)
    p.add_argument("--output", default="results/kali/multisource")
    p.add_argument("--smoke", action="store_true",
                   help="run on built-in tiny fixtures to check the wiring")
    args = p.parse_args(argv)

    ssh_source = None
    if args.smoke:
        ssh_pairs, web_pairs, ssh_source = _smoke_fixtures()
    else:
        if not args.ssh or not args.web:
            p.error("give --ssh and --web capture pairs (or --smoke)")
        ssh_pairs = parse_pairs(args.ssh)
        web_pairs = parse_pairs(args.web)

    runs = []
    for i in range(args.seeds):
        seed = args.seed_start + i
        result = score_once(ssh_pairs, web_pairs, args.shared_ip,
                            args.ambient_ratio, seed, ssh_source=ssh_source,
                            web_background=args.web_background)
        runs.append(result)
        print(f"seed {seed}: cross-source incidents "
              f"{result['cross_source_incidents']}, "
              f"overall line rate "
              f"{result['rates']['overall']['line_detection_rate']:.3f}")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "multisource.json").write_text(json.dumps(runs, indent=2, default=str))
    print(f"wrote {out / 'multisource.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
