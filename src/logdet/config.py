"""
config.py
Central configuration. All tunable values live here so they aren't
scattered as magic numbers across modules -- makes tuning sessions fast
and keeps AI-assisted edits from drifting values apart across files.
"""

import os
from pathlib import Path

# --- Embedding ---
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_BATCH_SIZE = 64

# --- Anomaly detection ---
CONTAMINATION = 0.20          # tuned in Phase 3 against synthetic ground truth --
                               # see Decision Log: 0.05 gave P=0.62/R=0.36, 0.20 gave
                               # P=0.30/R=0.87. Favors recall: this is an analyst-triage
                               # tool (severity tiers + narrative manage the FP volume),
                               # and a missed attack is worse than an extra alert.
MIN_SAMPLES_PER_USER = 5      # below this, fall back to the global baseline
RANDOM_STATE = 42

# Severity thresholds applied to the (negated) anomaly score.
# Higher value = more anomalous. Tune these in Phase 3 against your ground truth.
SEVERITY_THRESHOLDS = {
    "high": 0.15,
    "medium": 0.05,
    "low": 0.0,
}

# --- Impossible travel check (Phase 3) ---
IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 60   # different subnet within this window = suspicious
TRAVEL_SUBNET_PREFIX_LENGTH = 2         # compare first N octets of IPv4 to judge "different region"

# --- Incident grouping ---
INCIDENT_WINDOW_MINUTES = 30
GROUP_BY_SOURCE_IP = True     # Phase 4: also join anomalies sharing a source IP, not just a
                              # user. Account enumeration varies the username on every line by
                              # design, so a user-only grouping split it into N singleton alerts.
# Parser placeholders that are NOT real identities -- never join two anomalies on these.
NON_IDENTITY_VALUES = {"unknown", "none", "n/a", "-", "?"}

# --- MITRE mapping ---
ENUMERATION_MIN_DISTINCT_USERS = 3   # distinct usernames from one source IP before an
                                     # incident counts as account enumeration (T1087)

# --- LLM ---
OLLAMA_URL = "http://localhost:11434/api/generate"
LLM_MODEL = "phi3"            # switch to "llama3" for final demo if speed allows
LLM_TIMEOUT_SECONDS = 180
LLM_NUM_PREDICT = 400         # hard cap on generated tokens. Without it, phi3 rambles past the
                              # timeout on *sparse* prompts (single-event incidents give it little
                              # to anchor on) -- 2/19 incidents failed that way before this cap.
                              # 4-6 sentences fits comfortably in 400 tokens.
LLM_TEMPERATURE = 0.2         # low: narratives should be reproducible for the demo and the report
NARRATIVE_SENTENCE_RANGE = "4-6"
NARRATIVE_MAX_EVENTS = 25     # cap events pasted into one prompt; the rest are summarised

# Which incidents get an LLM narrative. phi3 costs ~40-60s per incident on this
# CPU, so narrating all 94 would run about an hour -- unusable for a demo or an
# iteration loop. Narrating only high-severity or multi-event incidents covers
# every ground-truth attack instance in the synthetic set, and the measured full
# run is 13-15 min for 19 incidents (measured 13m24s and 15m20s).
NARRATE_SEVERITIES = {"high"}
NARRATE_MIN_EVENTS = 2

# --- Paths ---
# Anchored to the repo root, not the working directory. v1 used bare relative
# strings, which silently wrote to the wrong place whenever a command ran from
# anywhere but the project root -- and pytest runs from wherever it likes.
# Override with LOGDET_PROJECT_ROOT (used by tests that need a scratch tree).
PROJECT_ROOT = Path(
    os.environ.get("LOGDET_PROJECT_ROOT", Path(__file__).resolve().parents[2])
)
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = str(DATA_DIR / "raw")
PROCESSED_DATA_DIR = str(DATA_DIR / "processed")
DEFAULT_INCIDENTS_PATH = str(DATA_DIR / "processed" / "incidents.json")
# New results go here. docs/results.v1/ is the frozen v1 baseline and is never
# written to (CLAUDE.md section 6).
RESULTS_DIR = str(PROJECT_ROOT / "results")

# Fitted detectors persisted by Stage 2 (fit on history, score on stream).
MODELS_DIR = str(PROJECT_ROOT / "models")

# Detector persisted by `logdet-fit` and loaded by `logdet-stream`. The stream
# scores against a model fit on history; it never fits on the traffic it is
# judging, which would let an attacker's own volume define "normal".
DEFAULT_DETECTOR_PATH = str(PROJECT_ROOT / "models" / "detector.joblib")

# --- Streaming ingestion (Stage 2) ---
# A micro-batch closes on whichever limit is reached first: enough lines, or
# enough time. Count alone stalls forever on a quiet log; time alone wastes a
# model call per line during a burst.
STREAM_BATCH_MAX_LINES = 50
STREAM_BATCH_MAX_SECONDS = 5.0
STREAM_POLL_SECONDS = 0.5      # how often the tailer checks the file for new bytes

# How long a scored event stays in memory so later events can be judged against
# it. Impossible travel compares a login with the previous one, and incident
# grouping links events inside a window -- both are blind to anything already
# evicted, so the floor is the larger of the two windows.
STREAM_RETENTION_MINUTES = max(INCIDENT_WINDOW_MINUTES, IMPOSSIBLE_TRAVEL_WINDOW_MINUTES)

# Where the tailer records how far it has read, so a restart neither re-scores
# old lines nor skips the ones written while it was down.
DEFAULT_OFFSET_STORE = str(PROJECT_ROOT / "models" / "stream_offset.json")

# Where journald ingestion records the last entry it scored. Kept apart from the
# file tailer's offset because a cursor and a byte offset are not
# interchangeable resume tokens, and one file holding both would let a file run
# and a journald run overwrite each other's position.
DEFAULT_CURSOR_STORE = str(PROJECT_ROOT / "models" / "stream_cursor.json")
