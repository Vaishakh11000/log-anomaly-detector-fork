"""
camouflage.py
The seven camouflage strategies, and nothing else.

This module is deliberately **stdlib-only and dependency-free**. It is the one
source of truth for how an attack is disguised, and CLAUDE.md section 2d
requires the Kali adversary box to apply the *identical* transforms to real
tool output -- but the SSD that holds this repo can only be in one machine at a
time, so `attack_runner/` vendors this single file rather than checking the
project out. Anything imported here (pandas, the detection stack, even
`logdet_eval.config`) would have to be installed on a box that has no reason to
carry it, so the constants below live here rather than in the config module and
`logdet_eval.config` re-exports them for backwards compatibility.

Method note carried from adversarial.py: camouflage is applied to the *event
list*, never to a finished log file, so each attack line keeps its
scenario/instance label through timestamp shuffling and noise injection.

`rephrase` and `mimicry` are opposites and both ship on purpose. Novel wording
makes an attack *more* anomalous, because rare templates are exactly what an
outlier detector looks for; real evasion means adopting the phrasing that
already dominates benign traffic.
"""

import copy
import random
import re
from dataclasses import dataclass, replace
from datetime import timedelta

# --- Knobs (definition site; logdet_eval.config re-exports these) ----------
CAMOUFLAGE_MIN_GAP_MINUTES = 8
CAMOUFLAGE_MAX_GAP_MINUTES = 20
CAMOUFLAGE_SLOW_MIN_GAP_MINUTES = 35
CAMOUFLAGE_SLOW_MAX_GAP_MINUTES = 90
CAMOUFLAGE_NOISE_RATIO = 1.5   # benign noise lines injected per attack line
CAMOUFLAGE_VOLUME_KEEP = 0.5   # share of repeated mid-sequence attack lines kept

# Alternate phrasings for the messages the scenarios actually emit. Kept
# semantically equivalent on purpose: the question is whether the detector
# generalises across wording, which a keyword rule cannot.
REPHRASE_MAP = {
    "Failed password for": ["Authentication failure for", "Invalid credentials for",
                            "Login attempt rejected for"],
    "Accepted password for": ["Authentication succeeded for", "Login accepted for",
                              "Session established for"],
    "COMMAND=/bin/su root": ["COMMAND=/bin/bash -l", "COMMAND=/usr/bin/sudo -i"],
    "added new user": ["registered account", "provisioned account"],
}

# Benign-looking filler, as (process, message) so it formats like a real line.
NOISE_TEMPLATES = [
    ("CRON", "(root) CMD (run-parts /etc/cron.hourly)"),
    ("CRON", "(root) CMD (/usr/lib/php/sessionclean)"),
    ("systemd", "Started Session {n} of user {user}."),
    ("systemd", "Reloading system manager configuration."),
    ("systemd", "Starting Cleanup of Temporary Directories..."),
]

# Accounts the noise filler names. Overridden by the caller so the synthetic
# corpus and a real captured corpus each use their own population.
NOISE_USERS = ["alice", "bob", "carol", "dave", "admin"]

# Mimicry: rewrite the *distinctive* attack lines into the shape of the single
# most common benign template in this corpus -- "pam_unix(sshd:session): session
# opened for user <u> by (uid=<n>)". The brute-force and enumeration lines are
# left alone because they are already textually identical to benign isolated
# failed passwords; their only tell is structural (volume, one source IP), which
# is what `volume` and `ip_rotate` attack instead.
MIMICRY_MAP = {
    "COMMAND=/bin/su root": "pam_unix(sudo:session): session opened for user root by (uid=0)",
    "added new user": "pam_unix(sudo:session): session opened for user",
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Subnets an attacker could plausibly rotate through (RFC 5737 documentation
# ranges, same convention as generate_logs.py -- never routable).
ROTATION_SUBNETS = ["203.0.113.", "198.51.100.", "192.0.2."]

STRATEGIES = ["temporal", "slow", "rephrase", "mimicry", "noise", "volume", "ip_rotate"]

# The strongest *realistic* attacker: everything that does not require inventing
# novel log wording (which we show backfires).
REALISTIC_COMBO = ["slow", "mimicry", "noise", "volume", "ip_rotate"]

_pid_counter = 1000


def default_pid() -> int:
    """Fallback PID source for callers with no generator of their own.

    The synthetic track passes `generate_logs.next_pid` instead, so that the
    noise filler keeps drawing from the same counter and the same global
    `random` state the rest of that corpus was built from -- changing that
    would renumber every PID and alter the corpus byte for byte.
    """
    global _pid_counter
    _pid_counter += random.randint(1, 9)
    return _pid_counter


# --- The attacker's configuration ------------------------------------------

@dataclass(frozen=True)
class CamouflagePlan:
    """One attacker configuration: which transforms, and how hard each is turned.

    The seven strategies were fixed recipes at fixed magnitudes until Stage 6.
    An *adaptive* adversary (CLAUDE.md section 6) searches over combinations and
    magnitudes instead, so the knobs have to be data rather than module
    constants -- but the defaults below are exactly those constants, so
    `CamouflagePlan(strategies=(...))` reproduces the fixed recipe byte for
    byte. `tests/test_camouflage.py` pins that with SHA-256 over the corpus.

    Frozen because a plan is the identity of a measurement: it is cached on,
    reported, and compared across seeds, and a plan that mutated after being
    scored would attach one score to two different attacks.
    """

    strategies: tuple[str, ...] = ()
    gap_min_minutes: int = CAMOUFLAGE_MIN_GAP_MINUTES
    gap_max_minutes: int = CAMOUFLAGE_MAX_GAP_MINUTES
    slow_gap_min_minutes: int = CAMOUFLAGE_SLOW_MIN_GAP_MINUTES
    slow_gap_max_minutes: int = CAMOUFLAGE_SLOW_MAX_GAP_MINUTES
    noise_ratio: float = CAMOUFLAGE_NOISE_RATIO
    volume_keep: float = CAMOUFLAGE_VOLUME_KEEP

    def __post_init__(self) -> None:
        if any(s not in STRATEGIES for s in self.strategies):
            unknown = sorted(set(self.strategies) - set(STRATEGIES))
            raise ValueError(f"unknown camouflage strategies: {unknown}")
        if self.gap_min_minutes > self.gap_max_minutes:
            raise ValueError("gap_min_minutes above gap_max_minutes")
        if self.slow_gap_min_minutes > self.slow_gap_max_minutes:
            raise ValueError("slow_gap_min_minutes above slow_gap_max_minutes")
        if not 0.0 <= self.volume_keep <= 1.0:
            raise ValueError("volume_keep outside [0, 1]")
        if self.noise_ratio < 0:
            raise ValueError("negative noise_ratio")

    @property
    def sorted_strategies(self) -> tuple[str, ...]:
        """Strategy order in STRATEGIES order, so two spellings of one plan
        produce one cache key. Application order is fixed in `apply_plan` and
        does not depend on this."""
        return tuple(s for s in STRATEGIES if s in self.strategies)

    def with_knob(self, name: str, value) -> "CamouflagePlan":
        return replace(self, **{name: value})

    def label(self) -> str:
        """Short human name. Only knobs that differ from the fixed recipe are
        shown, so a default-magnitude plan reads as the recipe it is."""
        base = "+".join(self.sorted_strategies) or "baseline"
        default = CamouflagePlan(strategies=self.strategies)
        diffs = [f"{k}={getattr(self, k)}" for k in KNOB_NAMES
                 if getattr(self, k) != getattr(default, k)]
        return base + (" [" + ", ".join(diffs) + "]" if diffs else "")

    def as_dict(self) -> dict:
        return {"strategies": list(self.sorted_strategies),
                **{k: getattr(self, k) for k in KNOB_NAMES}}

    @classmethod
    def from_dict(cls, data: dict) -> "CamouflagePlan":
        return cls(strategies=tuple(data.get("strategies", ())),
                   **{k: data[k] for k in KNOB_NAMES if k in data})


KNOB_NAMES = ("gap_min_minutes", "gap_max_minutes", "slow_gap_min_minutes",
              "slow_gap_max_minutes", "noise_ratio", "volume_keep")

# Which knobs any given strategy actually reads. An optimiser that varies a
# knob no active strategy consumes spends a detector query to re-measure the
# identical corpus, so the search space is restricted by this map.
KNOBS_BY_STRATEGY = {
    "temporal": ("gap_min_minutes", "gap_max_minutes"),
    "slow": ("slow_gap_min_minutes", "slow_gap_max_minutes"),
    "noise": ("noise_ratio",),
    "volume": ("volume_keep",),
    "rephrase": (),
    "mimicry": (),
    "ip_rotate": (),
}


# --- Camouflage strategies -------------------------------------------------

def rephrase_message(message: str, rng: random.Random) -> str:
    """Swap one known phrasing for an equivalent alternative.

    Deliberately preserves the "for <user> from <ip>" shape so preprocessing
    still extracts user and IP -- otherwise we would be measuring broken
    parsing rather than evaded detection.
    """
    for original, alternatives in REPHRASE_MAP.items():
        if original.lower() in message.lower():
            return message.replace(original, rng.choice(alternatives))
    return message


def mimic_message(message: str, actor: str) -> str:
    """Rewrite a distinctive attack line as the dominant benign template.

    This is the textbook mimicry attack: rather than inventing new wording
    (which makes a line rarer, and so easier to spot), adopt the wording the
    detector has already learned to consider normal.
    """
    if "COMMAND=/bin/su root" in message:
        return MIMICRY_MAP["COMMAND=/bin/su root"]
    if "added new user" in message:
        # keep the created account name, drop everything that reads as escalation
        created = message.split("'")[1] if "'" in message else actor
        return f"pam_unix(sudo:session): session opened for user {created} by (uid=0)"
    return message


def rotate_ip(message: str, rng: random.Random) -> str:
    """Give this line its own source IP, breaking the source-IP grouping axis."""
    subnet = rng.choice(ROTATION_SUBNETS)
    return IP_RE.sub(f"{subnet}{rng.randint(2, 250)}", message, count=1)


def reduce_volume(events: list[dict], rng: random.Random,
                  keep: float = CAMOUFLAGE_VOLUME_KEEP) -> list[dict]:
    """Drop a share of the repeated middle events, keeping first and last.

    The pivotal lines (first probe, final escalation) are what make the sequence
    an attack, so an evader thins the repetition rather than the payload.
    """
    events = sorted(events, key=lambda e: e["ts"])
    if len(events) <= 2:
        return events
    middle = [e for e in events[1:-1] if rng.random() < keep]
    return [events[0]] + middle + [events[-1]]


def spread_timestamps(events: list[dict], rng: random.Random,
                      min_gap: int = CAMOUFLAGE_MIN_GAP_MINUTES,
                      max_gap: int = CAMOUFLAGE_MAX_GAP_MINUTES) -> list[dict]:
    """Re-space one attack instance so its events no longer burst together."""
    events = sorted(events, key=lambda e: e["ts"])
    current = events[0]["ts"]
    for event in events[1:]:
        current = current + timedelta(minutes=rng.randint(min_gap, max_gap))
        event["ts"] = current
    return events


def make_noise_events(attack_events: list[dict], rng: random.Random,
                      ratio: float = CAMOUFLAGE_NOISE_RATIO,
                      users: list[str] | None = None,
                      pid_fn=None) -> list[dict]:
    """Benign filler spread across the attack's (post-spreading) time range."""
    users = NOISE_USERS if users is None else users
    pid_fn = default_pid if pid_fn is None else pid_fn

    start = min(e["ts"] for e in attack_events)
    end = max(e["ts"] for e in attack_events)
    span_seconds = max(int((end - start).total_seconds()), 60)

    noise = []
    for _ in range(int(len(attack_events) * ratio)):
        process, template = rng.choice(NOISE_TEMPLATES)
        message = template.format(n=rng.randint(1, 254), user=rng.choice(users))
        noise.append({
            "ts": start + timedelta(seconds=rng.randint(0, span_seconds)),
            "process": process,
            "pid": pid_fn() if process != "systemd" else 1,
            "message": message,
            "scenario": None, "instance": None, "user": None, "description": None,
        })
    return noise


def camouflage_events(events: list[dict], strategies: list[str], seed: int,
                      users: list[str] | None = None,
                      pid_fn=None) -> list[dict]:
    """Apply the named strategies at their fixed, published magnitudes.

    This is the v1 interface and every existing caller uses it. It is now a thin
    binding over `apply_plan` with default knobs, which is what keeps the fixed
    recipes and the adaptive adversary's search space the same code rather than
    two implementations that could drift apart (CLAUDE.md section 2d).
    """
    return apply_plan(events, CamouflagePlan(strategies=tuple(strategies)), seed,
                      users=users, pid_fn=pid_fn)


def apply_plan(events: list[dict], plan: CamouflagePlan, seed: int,
               users: list[str] | None = None,
               pid_fn=None) -> list[dict]:
    """Apply one attacker configuration to every attack instance in an event list.

    Benign events are left untouched -- an attacker controls their own traffic,
    not the rest of the host's logs.

    The order of transforms, and the order in which they draw from `rng`, is
    fixed and must stay fixed: the seeded draw sequence is what makes a
    camouflaged corpus reproducible, and every number in `results/` was measured
    on corpora this function produced.
    """
    rng = random.Random(seed)
    events = copy.deepcopy(events)
    strategies = plan.strategies

    attacks: dict[tuple, list[dict]] = {}
    benign = []
    for event in events:
        if event.get("scenario"):
            attacks.setdefault((event["scenario"], event["instance"]), []).append(event)
        else:
            benign.append(event)

    result = list(benign)
    for instance_events in attacks.values():
        if "volume" in strategies:
            instance_events = reduce_volume(instance_events, rng, keep=plan.volume_keep)
        for event in instance_events:
            if "rephrase" in strategies:
                event["message"] = rephrase_message(event["message"], rng)
            if "mimicry" in strategies:
                event["message"] = mimic_message(event["message"], event.get("user") or "root")
            if "ip_rotate" in strategies:
                event["message"] = rotate_ip(event["message"], rng)
        if "slow" in strategies:
            instance_events = spread_timestamps(
                instance_events, rng,
                plan.slow_gap_min_minutes, plan.slow_gap_max_minutes)
        elif "temporal" in strategies:
            instance_events = spread_timestamps(
                instance_events, rng, plan.gap_min_minutes, plan.gap_max_minutes)
        if "noise" in strategies:
            result += make_noise_events(instance_events, rng, ratio=plan.noise_ratio,
                                        users=users, pid_fn=pid_fn)
        result += instance_events

    result.sort(key=lambda e: e["ts"])
    return result
