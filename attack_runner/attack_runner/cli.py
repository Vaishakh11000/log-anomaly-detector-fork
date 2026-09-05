"""
cli.py
The attack_runner entry point: launch an attack, capture what it produced,
attribute ground truth, and ship it to the analyzer.

This is a scaffold, not the finished Stage 6 platform: the boxes are not cabled
together yet (CLAUDE.md section 2c says the SSD moves at Stage 2 and the two-box
split is Stage 6). What is here is the full pipeline in miniature, runnable on
one box against a local sshd, so that when the link exists only `--peer` and
`--source` change.

Flow (CLAUDE.md section 2d):
  1. drive a real tool against a real sshd            attacks.py
  2. capture the auth lines it produced               capture.py
  3. label them by identity + time                    groundtruth.py
  4. ship the raw lines to the analyzer, reliably     ship.py

Ground truth is captured at generation time (step 3 runs against the record
from step 1) and travels with the logs, so scoring on the analyzer needs no
knowledge of what was launched.
"""

from __future__ import annotations

import argparse
import sys

from . import attacks
from .camouflage import STRATEGIES
from .capture import capture_access_file, capture_file, capture_journald
from .groundtruth import attribute, dump_records, write_ground_truth_csv
from .ship import Shipper

ATTACKS = {"brute_force", "enumeration", "impossible_travel", "web_bruteforce"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Run an authentic attack, capture ground truth, ship to the analyzer.")
    p.add_argument("attack", choices=sorted(ATTACKS))
    p.add_argument("--target-host", default="127.0.0.1")
    p.add_argument("--target-port", type=int, default=22)
    p.add_argument("--user", default="root")
    p.add_argument("--users", nargs="+",
                   default=["admin", "test", "oracle", "postgres", "git"],
                   help="candidate users for enumeration")
    p.add_argument("--source-ip", default="10.10.10.1",
                   help="the address the analyzer will attribute lines to")
    p.add_argument("--distant-ip", default="203.0.113.7",
                   help="synthetic distant leg for impossible travel")
    p.add_argument("--target-url", default="http://127.0.0.1/wp-login.php",
                   help="web_bruteforce: the login endpoint to POST wrong "
                        "credentials at (should answer 401 on failure)")
    p.add_argument("--instance", type=int, default=1)
    p.add_argument("--camouflage", nargs="*", default=[], choices=STRATEGIES,
                   help="camouflage strategies to note on the record "
                        "(applied to captured lines by the shared camouflage.py)")
    p.add_argument("--year", type=int, default=None,
                   help="year for the syslog timestamps (defaults to this year)")
    p.add_argument("--attempts", type=int, default=20,
                   help="brute force: password-list length (a rate-limiting sshd "
                        "will still cap how many attempts actually land)")
    # capture source
    p.add_argument("--auth-file", help="capture from this auth.log-style file")
    p.add_argument("--access-file",
                   help="web_bruteforce: capture from this nginx/Apache access log")
    p.add_argument("--journald-unit", help="capture from journald for this unit")
    p.add_argument("--journald-identifier", nargs="+",
                   help="capture from journald by syslog identifier, e.g. "
                        "`sshd sshd-session`. On modern systemd this is the "
                        "reliable selector; `-u ssh` misses the sshd-session "
                        "children that carry the auth lines.")
    # shipping
    p.add_argument("--peer", help="analyzer base URL, e.g. http://10.10.10.2:8000")
    p.add_argument("--spool", default="./spool", help="disk-backed shipping buffer")
    p.add_argument("--ground-truth-out", default="ground_truth.csv")
    p.add_argument("--records-out", default="attack_records.json")
    p.add_argument("--corpus-out",
                   help="write the captured raw lines to this .log file. Its line "
                        "numbers match --ground-truth-out, so the pair scores on the "
                        "analyzer with no link -- this is the offline path while the "
                        "boxes are apart (CLAUDE.md section 2c)")
    args = p.parse_args(argv)

    from datetime import datetime
    year = args.year or datetime.now().year

    # 1. launch
    if args.attack == "brute_force":
        record = attacks.brute_force(args.target_host, args.target_port, args.user,
                                     args.source_ip, args.instance,
                                     attempts=args.attempts,
                                     camouflage=args.camouflage)
    elif args.attack == "enumeration":
        record = attacks.enumeration(args.target_host, args.target_port, args.users,
                                     args.source_ip, args.instance,
                                     camouflage=args.camouflage)
    elif args.attack == "web_bruteforce":
        record = attacks.web_bruteforce(args.target_url, args.source_ip,
                                        args.instance, user=args.user,
                                        attempts=args.attempts,
                                        camouflage=args.camouflage)
    else:
        record = attacks.impossible_travel(args.target_host, args.target_port, args.user,
                                           args.source_ip, args.distant_ip, args.instance,
                                           camouflage=args.camouflage)
    print(f"launched {args.attack} instance {args.instance} via {record.tool}"
          + (" (distant leg synthetic)" if record.synthetic else ""))

    # 2. capture
    if args.access_file:
        lines = capture_access_file(args.access_file)
    elif args.auth_file:
        lines = capture_file(args.auth_file, year)
    elif args.journald_unit or args.journald_identifier:
        import time as _time
        _time.sleep(1.0)   # let journald flush the attack's lines
        # Window the capture to a few seconds before the attack started, so the
        # corpus is this instance's traffic rather than the whole journal, and
        # so successive instances do not each re-read every earlier one.
        from datetime import timedelta
        since = (record.t_start - timedelta(seconds=3)).strftime("%Y-%m-%d %H:%M:%S")
        lines = capture_journald(args.journald_unit, year, since=since,
                                 identifiers=args.journald_identifier)
    else:
        print("no capture source (--access-file, --auth-file or --journald-unit); "
              "recorded the launch only", file=sys.stderr)
        dump_records([record], args.records_out)
        return 0

    # 3. attribute
    result = attribute(lines, [record])
    n = len(result["labels"])
    print(f"attributed {n} line(s) to instance {args.instance}")
    write_ground_truth_csv(result["labels"], args.ground_truth_out, lines)
    dump_records([record], args.records_out)

    if args.corpus_out:
        # The captured lines in line_number order, so line K here is the line
        # ground truth calls K. Carry this pair back to the analyzer and score
        # with logdet_eval.scoring; no link needed.
        with open(args.corpus_out, "w") as f:
            for ln in sorted(lines, key=lambda x: x.line_number):
                f.write(ln.raw.rstrip("\n") + "\n")
        print(f"wrote {len(lines)} captured line(s) -> {args.corpus_out}")

    # 4. ship
    if args.peer:
        shipper = Shipper(args.peer.rstrip("/") + "/collector/ingest", args.spool)
        ship_result = shipper.ship([ln.raw for ln in lines])
        print(f"shipped {ship_result.sent} line(s), "
              f"offset {ship_result.committed_offset}, ok={ship_result.ok}"
              + (f", error={ship_result.error}" if ship_result.error else ""))
        return 0 if ship_result.ok else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
