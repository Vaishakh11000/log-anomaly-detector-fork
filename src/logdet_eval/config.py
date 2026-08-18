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
CAMOUFLAGE_MIN_GAP_MINUTES = 8
CAMOUFLAGE_MAX_GAP_MINUTES = 20
CAMOUFLAGE_SLOW_MIN_GAP_MINUTES = 35
CAMOUFLAGE_SLOW_MAX_GAP_MINUTES = 90
CAMOUFLAGE_NOISE_RATIO = 1.5   # benign noise lines injected per attack line
CAMOUFLAGE_VOLUME_KEEP = 0.5   # share of repeated mid-sequence attack lines kept
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
