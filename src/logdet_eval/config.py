"""
config.py (evaluation track)
Knobs that belong to measurement, not to detection: synthetic corpus
generation, the adversarial camouflage suite, the rule baseline's thresholds,
and the benchmark harness.

These are kept out of logdet/config.py deliberately. The pipeline's config is
what the shipping system is tuned by; mixing the baseline's thresholds into it
is the first step towards the baseline leaking into the detector, which would
make every number this project reports meaningless (CLAUDE.md section 5).

Detection settings the harness needs -- CONTAMINATION, INCIDENT_WINDOW_MINUTES,
paths -- are imported from logdet.config rather than duplicated, so a sweep can
never drift from what the pipeline actually runs.
"""

# --- Synthetic dataset generation (Phase 2) ---
SYNTHETIC_HOST = "server1"
SYNTHETIC_USERS = ["alice", "bob", "carol", "dave", "admin"]
SYNTHETIC_DAYS = 5                    # simulated days the log spans
SYNTHETIC_TOTAL_LINES = 750           # target total line count, incl. attack lines
SYNTHETIC_INSTANCES_PER_SCENARIO = 3  # how many times each of A/B/C occurs
SYNTHETIC_SEED = 42
SYNTHETIC_YEAR = 2026                 # must match --year passed to preprocessing.py

# --- Adversarial camouflage (Phase 5) ---
# Two temporal spreads on purpose, straddling INCIDENT_WINDOW_MINUTES (30): the
# narrow one stays inside the grouping window, the wide one steps past it. The
# pair is what shows the window is the thing doing the work.
# Defined in camouflage.py, not here, and re-exported for backwards
# compatibility. That module is stdlib-only so the Kali adversary box can
# vendor it as a single file (CLAUDE.md section 2d); a knob it needs cannot
# live in a config module Kali would then also have to carry.
from logdet_eval.camouflage import (  # noqa: E402,F401
    CAMOUFLAGE_MIN_GAP_MINUTES,
    CAMOUFLAGE_MAX_GAP_MINUTES,
    CAMOUFLAGE_SLOW_MIN_GAP_MINUTES,
    CAMOUFLAGE_SLOW_MAX_GAP_MINUTES,
    CAMOUFLAGE_NOISE_RATIO,
    CAMOUFLAGE_VOLUME_KEEP,
)
                               # ("low and slow": make less noise, not different noise)

# --- Rule-based baseline (Phase 7 evaluation only) ---
# These drive logdet_eval/baseline_rules.py, which exists ONLY as the comparison
# baseline. It is deliberately the SIEM this project differentiates from -- nothing
# in logdet may import it (see Anti-Goals in CLAUDE.md, enforced by
# tests/test_layering.py).
BASELINE_BRUTE_FORCE_WINDOW_MINUTES = 5
BASELINE_BRUTE_FORCE_MIN_FAILURES = 3    # N failed passwords for one user in the window
BASELINE_ENUMERATION_WINDOW_MINUTES = 10
BASELINE_ENUMERATION_MIN_USERS = 3       # distinct usernames failing from one source IP
# Substrings a conventional SIEM would alert on. Verified against the synthetic
# corpus: these match attack lines only -- the baseline is not a strawman.
BASELINE_PRIVILEGE_KEYWORDS = (
    "command=/bin/su", "su root", "to group sudo", "to group wheel",
    "useradd", "adduser",
)

# --- Evaluation (Phase 7) ---
EVAL_CONTAMINATION_SWEEP = [0.05, 0.10, 0.15, 0.20, 0.25]
EVAL_SEEDS = 5                # pooled like Phase 5: 9 attack instances move rates in coarse steps

# --- Kill-point attack magnitudes (CLAUDE.md section 1b) ---
# PRE-REGISTERED 2026-08-18, before any differential was computed.
#
# v1's scenarios were sized against v1's own hand-written baseline
# (min_failures=3), which makes them smaller than anything a production SIEM
# alerts on: Wazuh's brute-force rules need 8 events in 120s. Measuring a
# third-party ruleset against a 4-attempt "brute force" and then reporting that
# it missed the attack would handicap the baseline -- the mirror image of
# writing rules for attacks you authored, and equally fatal to the evaluation.
#
# These ranges are realistic for the attacks they represent and clear the
# thresholds of both systems, so neither is judged on something it was never
# built to see.
KILLPOINT_BRUTE_FORCE_FAILURES = (15, 25)   # Wazuh rule 5763 needs 8 in 120s
KILLPOINT_ENUMERATION_PROBES = (10, 12)     # Wazuh rule 5712 chain needs 8

# Enumeration targets for the kill-point corpus. Deliberately a separate list
# from PROBE_USERNAMES: extending that one would change v1's random.sample
# draws and move the pinned regression baseline.
KILLPOINT_PROBE_USERNAMES = [
    "root", "test", "guest", "oracle", "postgres",
    "www-data", "ftpuser", "backup", "deploy", "support",
    "admin", "ubuntu", "mysql", "jenkins", "git",
    "tomcat", "nagios", "zabbix", "elastic", "pi",
]
