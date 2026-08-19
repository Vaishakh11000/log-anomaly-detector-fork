"""
corpus_openssh.py
Builds the kill-point corpus (CLAUDE.md section 1b) out of the real LogHub
OpenSSH log rather than synthetic traffic.

The problem this module exists to solve
---------------------------------------
Section 3b assumed OpenSSH could supply "real benign traffic" to inject attacks
into. Measured, it cannot: 66-83% of *every day* in the corpus is internet
brute force, and only ~2.4k of its 655k lines are genuinely benign. Dropping
attacks into that unfiltered would make brute force the statistical majority of
what the detector learns as normal, so an injected brute force would score as an
*inlier* -- and the resulting kill-point differential would be measuring base
rates rather than camouflage robustness.

So the background is built explicitly:

    benign lines (real, ~2.4k)  +  real attacker traffic downsampled to
                                   `ambient_ratio` of the background

Both halves are real log lines from the corpus. The ambient ratio is a declared
parameter, not a hidden default, because it is the one number an examiner should
push on -- results are reported across several values, not just one.

What is real here and what is not
---------------------------------
Real: every background line, the usernames, the host, the message vocabulary.
Authored: the injected attack instances (v1's three scenarios) and the
camouflage layer. That split is deliberate -- camouflage is the layer this
project claims as its contribution, so it is the layer that must be ours.
Stage 6 replaces the injected attacks with Kali-generated ones (section 2d).
"""

import random
from collections import Counter
from datetime import datetime
from pathlib import Path

from logdet.preprocessing import extract_ip, parse_line
from logdet_eval.datasets import fetch
from logdet_eval.config import (
    KILLPOINT_BRUTE_FORCE_FAILURES,
    KILLPOINT_ENUMERATION_PROBES,
    KILLPOINT_PROBE_USERNAMES,
)
from logdet_eval.generate_logs import (
    gen_scenario_a,
    gen_scenario_b,
    gen_scenario_c,
    next_pid,
)

# The host the corpus was captured from. Injected lines carry it too, so they
# are indistinguishable in form from real ones.
CORPUS_HOST = "LabSZ"

# Phrases that mark a line as part of failed-authentication activity. The last
# two matter more than they look: "ignoring max retries" (37,963 lines) and
# "check pass; user unknown" (19,852) are brute-force *byproducts* that carry no
# source IP, so IP-based filtering alone leaves them in and quietly fills the
# "benign" background with attack texture.
ATTACK_PHRASES = (
    "invalid user",
    "failed password",
    "break-in attempt",
    "authentication failure",
    "check pass; user unknown",
    "ignoring max retries",
    "not allowed because",
    "maximum authentication attempts exceeded",
    "failed none for",
)

# An IP is treated as an attacker once it has produced this many failed-auth
# lines. Deliberately blunt and deliberately low: the corpus's attackers produce
# thousands of lines each, so the threshold is nowhere near a decision boundary.
ATTACKER_MIN_FAILURES = 10


def load_events(path: Path | str | None = None, limit: int | None = None) -> list[dict]:
    """Parse the real corpus into the event dicts the rest of the eval uses.

    Handles the year rollover: the corpus runs Dec 10 -> Jan 07, and syslog
    omits the year, so a fixed year would order January *before* December and
    silently scramble every window-based rule in the comparison.
    """
    path = Path(path) if path else fetch("openssh")

    events: list[dict] = []
    year = 2015                     # arbitrary start; only ordering matters
    previous_month = None

    with open(path, errors="ignore") as handle:
        for line in handle:
            parsed = parse_line(line, year=year)
            if parsed is None or parsed["timestamp"] is None:
                continue

            month = parsed["timestamp"].month
            if previous_month is not None and month < previous_month:
                year += 1
                parsed = parse_line(line, year=year)
            previous_month = month

            events.append({
                "ts": parsed["timestamp"],
                "process": parsed["process"],
                "pid": parsed["pid"],
                "message": parsed["message"],
                "user": None,
                "scenario": None,
                "instance": None,
                "description": None,
            })
            if limit and len(events) >= limit:
                break

    return events


def _is_attack_line(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in ATTACK_PHRASES)


def classify(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split real events into (benign, attacker-associated).

    Two mechanical tests, both stated in the write-up: the line reads as a
    failed-authentication event, or its source IP is one that produced many
    such events elsewhere in the corpus.
    """
    failures_by_ip: Counter = Counter()
    for event in events:
        if _is_attack_line(event["message"]):
            ip = extract_ip(event["message"])
            if ip:
                failures_by_ip[ip] += 1

    attacker_ips = {ip for ip, n in failures_by_ip.items() if n >= ATTACKER_MIN_FAILURES}

    benign, attacker = [], []
    for event in events:
        ip = extract_ip(event["message"])
        if _is_attack_line(event["message"]) or (ip and ip in attacker_ips):
            attacker.append(event)
        else:
            benign.append(event)

    return benign, attacker


def home_subnets(events: list[dict], prefix_len: int = 3) -> dict[str, str]:
    """Each real user's usual login subnet, taken from where they actually log
    in from. Scenario B's "baseline leg" then comes from the account's genuine
    home range instead of a fabricated one, which is what makes the injected
    impossible-travel pair realistic against this corpus."""
    seen: dict[str, Counter] = {}
    for event in events:
        message = event["message"]
        if not message.lower().startswith("accepted password for"):
            continue
        parts = message.split()
        user, ip = parts[3], extract_ip(message)
        if not ip:
            continue
        subnet = ".".join(ip.split(".")[:prefix_len]) + "."
        seen.setdefault(user, Counter())[subnet] += 1
    return {user: counts.most_common(1)[0][0] for user, counts in seen.items()}


def real_users(events: list[dict], minimum_logins: int = 1) -> list[str]:
    """Usernames with at least one *successful* login -- the host's real user
    population. Injected attacks target these, so an injected brute force names
    an account that genuinely exists on the box."""
    counts: Counter = Counter()
    for event in events:
        message = event["message"]
        if message.lower().startswith("accepted password for"):
            counts[message.split()[3]] += 1
    return sorted(name for name, n in counts.items() if n >= minimum_logins)


def build_background(benign: list[dict], attacker: list[dict],
                     ambient_ratio: float, seed: int) -> list[dict]:
    """Benign traffic plus real attacker traffic thinned to `ambient_ratio`.

    Ambient attacks are kept because a host on the open internet always has
    some, and a background with none would make the injected attacks trivially
    separable. They stay unlabelled: they are texture, not ground truth, and
    scoring counts only the injected instances.
    """
    rng = random.Random(seed)
    target = int(len(benign) * ambient_ratio)
    sampled = rng.sample(attacker, min(target, len(attacker)))
    return sorted(benign + sampled, key=lambda e: e["ts"])


_CACHE: dict = {}


def load_classified(source: Path | str | None = None) -> tuple[list[dict], list[dict], list[str], dict]:
    """Parse + classify the corpus once and memoise it.

    Parsing 655k lines takes ~30s; a seed sweep would otherwise pay that on
    every one of its runs while producing byte-identical output each time. Only
    the background sample and the injected attacks vary with the seed.
    """
    key = str(source or "default")
    if key not in _CACHE:
        events = load_events(source)
        benign, attacker = classify(events)
        _CACHE[key] = (benign, attacker, real_users(events), home_subnets(events))
    return _CACHE[key]


def build_killpoint_corpus(instances_per_scenario: int = 3,
                           ambient_ratio: float = 0.05,
                           seed: int = 42,
                           source: Path | str | None = None) -> tuple[list[dict], dict]:
    """The full corpus: real background + labelled injected attack instances.

    Returns (events, manifest). The manifest records every knob that shaped the
    corpus so a result can be traced back to the exact inputs that produced it.
    """
    rng = random.Random(seed)

    benign, attacker, users, subnets = load_classified(source)
    background = build_background(benign, attacker, ambient_ratio, seed)

    if not background:
        raise RuntimeError("empty background -- the corpus did not load")

    days = sorted({event["ts"].date() for event in background})
    day_starts = [datetime(day.year, day.month, day.day) for day in days]

    attacks: list[dict] = []
    for instance in range(1, instances_per_scenario + 1):
        attacks += gen_scenario_a(rng.choice(users), rng.choice(day_starts), instance,
                                  failures=KILLPOINT_BRUTE_FORCE_FAILURES)
        travel_user = rng.choice(users)
        attacks += gen_scenario_b(travel_user, rng.choice(day_starts), instance,
                                  home_subnet=subnets.get(travel_user))
        attacks += gen_scenario_c(rng.choice(day_starts), instance,
                                  probes=KILLPOINT_ENUMERATION_PROBES,
                                  username_pool=KILLPOINT_PROBE_USERNAMES)

    combined = sorted(background + attacks, key=lambda e: e["ts"])

    manifest = {
        "benign_lines": len(benign),
        "attacker_lines": len(attacker),
        "ambient_ratio": ambient_ratio,
        "background_lines": len(background),
        "attack_lines": len(attacks),
        "attack_instances": instances_per_scenario * 3,
        "brute_force_failures": list(KILLPOINT_BRUTE_FORCE_FAILURES),
        "enumeration_probes": list(KILLPOINT_ENUMERATION_PROBES),
        "total_lines": len(combined),
        "real_users": users,
        "home_subnets": subnets,
        "days_covered": len(days),
        "seed": seed,
        "host": CORPUS_HOST,
    }
    return combined, manifest


def cli() -> None:
    import argparse
    import json

    from logdet.config import PROCESSED_DATA_DIR
    from logdet_eval.generate_logs import write_outputs

    parser = argparse.ArgumentParser(
        description="Build the kill-point corpus from the real OpenSSH log.")
    parser.add_argument("--ambient-ratio", type=float, default=0.05)
    parser.add_argument("--instances-per-scenario", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default=f"{PROCESSED_DATA_DIR}/killpoint")
    args = parser.parse_args()

    events, manifest = build_killpoint_corpus(
        instances_per_scenario=args.instances_per_scenario,
        ambient_ratio=args.ambient_ratio,
        seed=args.seed,
    )

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_outputs(events, str(out / "corpus.log"), str(out / "ground_truth.csv"),
                  host=CORPUS_HOST)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    cli()


# --- paced-replay corpus -------------------------------------------------
#
# The kill-point corpus above is built for batch scoring: it samples real
# OpenSSH days across the log's full 25-day range, which is right there and
# fatal here. Replayed in wall-clock time under the per-IP schedule it costs
# ~7h per condition (144h for a 5-seed run), because a handful of ambient
# attacker IPs carry dozens of events each and every one of those gaps has to
# be honoured up to the spacing bound.
#
# The paced corpus is therefore thinned rather than shortened: same real lines,
# same real users, same injected instances, but a cap on how many events any
# one ambient IP contributes. That cap is what bounds the replay, and it is a
# declared parameter rather than a hidden default because it is the one knob
# that changes what the paced instrument costs.

def thin_background(background: list[dict], max_events_per_ip: int,
                    target_lines: int | None, seed: int) -> list[dict]:
    """Cap each source IP's contribution, then subsample to `target_lines`.

    Keeps the earliest events of each IP rather than a random sample, so what
    survives is a real contiguous run of that host's traffic instead of a
    scatter that never happened in that order.
    """
    rng = random.Random(seed)
    kept: list[dict] = []
    seen: dict[str, int] = {}
    for event in sorted(background, key=lambda e: e["ts"]):
        key = extract_ip(event.get("message", ""))
        if key is not None:
            if seen.get(key, 0) >= max_events_per_ip:
                continue
            seen[key] = seen.get(key, 0) + 1
        kept.append(event)

    if target_lines is not None and len(kept) > target_lines:
        kept = sorted(rng.sample(kept, target_lines), key=lambda e: e["ts"])
    return kept


def build_paced_corpus(instances_per_scenario: int = 3,
                       ambient_ratio: float = 0.05,
                       max_events_per_ip: int = 12,
                       target_background_lines: int | None = 600,
                       seed: int = 42,
                       source: Path | str | None = None) -> tuple[list[dict], dict]:
    """Kill-point corpus thinned so it can be replayed in wall-clock time."""
    rng = random.Random(seed)

    benign, attacker, users, subnets = load_classified(source)
    background = thin_background(
        build_background(benign, attacker, ambient_ratio, seed),
        max_events_per_ip=max_events_per_ip,
        target_lines=target_background_lines,
        seed=seed,
    )
    if not background:
        raise RuntimeError("empty background -- the corpus did not load")

    days = sorted({event["ts"].date() for event in background})
    day_starts = [datetime(day.year, day.month, day.day) for day in days]

    attacks: list[dict] = []
    for instance in range(1, instances_per_scenario + 1):
        attacks += gen_scenario_a(rng.choice(users), rng.choice(day_starts), instance,
                                  failures=KILLPOINT_BRUTE_FORCE_FAILURES)
        travel_user = rng.choice(users)
        attacks += gen_scenario_b(travel_user, rng.choice(day_starts), instance,
                                  home_subnet=subnets.get(travel_user))
        attacks += gen_scenario_c(rng.choice(day_starts), instance,
                                  probes=KILLPOINT_ENUMERATION_PROBES,
                                  username_pool=KILLPOINT_PROBE_USERNAMES)

    combined = sorted(background + attacks, key=lambda e: e["ts"])
    manifest = {
        "corpus": "loghub-openssh-paced",
        "ambient_ratio": ambient_ratio,
        "max_events_per_ip": max_events_per_ip,
        "target_background_lines": target_background_lines,
        "background_lines": len(background),
        "attack_lines": len(attacks),
        "attack_instances": instances_per_scenario * 3,
        "total_lines": len(combined),
        "days_covered": len(days),
        "real_users": users,
        "seed": seed,
        "host": CORPUS_HOST,
    }
    return combined, manifest
