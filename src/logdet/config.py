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

# --- Template mining (Stage 3, Drain3) ---
# Drain3 mines log templates instead of being handed a regex, which is what
# makes the parser source-agnostic. Nothing in detection reads the mined ids
# yet -- CLAUDE.md section 4 -- so these knobs currently only affect the
# `template_id` column and the template inventory report.
DRAIN_SIM_TH = 0.4            # token-similarity needed to join an existing cluster.
                              # Drain's own default. Higher splits near-identical
                              # lines into separate templates, lower merges
                              # distinct events into one -- both cost signal, in
                              # opposite directions. Measure before moving it.
DRAIN_DEPTH = 4               # parse-tree depth, i.e. how many leading tokens are
                              # treated as fixed structure. Drain's default.
DRAIN_MAX_CHILDREN = 100      # branching factor per tree node
DRAIN_MAX_CLUSTERS = None     # None = unbounded. A bound turns the cluster table
                              # into an LRU, so a rare template can be evicted and
                              # come back with a *new* id -- which would silently
                              # break any model keyed on the id.
DRAIN_PARAMETRIZE_NUMERIC = True   # treat a bare numeric token as a parameter

# --- Sequence model over template IDs (Stage 3) ---
# Learns how often one template follows another for the same actor, and reports
# the surprisal of each observed transition. It re-ranks and re-tiers; it never
# decides `is_anomaly` -- a template ID is a discrete symbol, so keying
# detection on it would rebuild the signature brittleness that `rephrase`
# camouflage exploits, and that win is the whole kill-point result.
SEQUENCE_KEYS = ("user", "source_ip")
                              # In precedence order: the user key scores a row
                              # if it can, and source IP only fills rows it
                              # cannot (enumeration varies the username on every
                              # line, so there is no user sequence to follow).
                              # What the measurement supports is the *ranking of
                              # the keys*, not the combining rule: user alone
                              # separates attack from benign at AUC 0.851
                              # (synthetic) and 0.958 (kill-point OpenSSH),
                              # source IP alone at 0.230 and 0.758. Precedence
                              # and taking the maximum are a wash -- 0.856 vs
                              # 0.852 and 0.912 vs 0.923, each winning one
                              # corpus by about a point -- so precedence is kept
                              # for being the simpler rule to reason about, not
                              # because it measured better. Both combine forms
                              # score more rows (517 and 1175) than the user key
                              # alone (509 and 660): the fallback buys coverage
                              # at lower quality, which is why pooled AUC sits
                              # below user-alone on the kill-point corpus.
SEQUENCE_SMOOTHING = 0.5      # Laplace alpha. Above 0 so an unseen transition
                              # scores high but finite; a zero-probability
                              # transition would make surprisal infinite and
                              # every comparison between rare events collapse.

# Whether the surprisal is allowed to shift a row's severity tier. **Off, on
# measurement.** The signal itself is good -- fitted on a clean history slice it
# separates attack from benign lines at AUC 0.899-0.958 (results/sequence/) --
# but the severity tier is the wrong place to spend it, because an incident
# takes the *highest* tier of any line in it (anomaly_detection.highest_severity).
# Demotion is therefore washed out: an incident keeps its tier as long as one
# line keeps it, and on the synthetic corpus demote-only is an exact no-op.
# Promotion is worse than useless: one promoted line lifts a whole incident, so
# the notable set grew 19 -> 49 on the synthetic corpus and 72 -> 83 on the
# kill-point corpus, and the rank an analyst must read down to see every attack
# grew 16 -> 30 and 65 -> 74. Both directions measured, both recorded, neither
# adopted. The column is still computed so the next consumption point -- one
# that can remove alerts rather than reorder them -- has it to work with.
# Where the signal IS spent: as the last tiebreaker in logdet/triage.py, after
# event count and severity. That leaves precision@5/@10/@20 untouched and
# brings full coverage of the synthetic corpus's 9 attack instances forward
# from rank 16 to rank 12.
SEQUENCE_SEVERITY_SHIFT = False

# Surprisal bands used only to adjust the severity tier, expressed as
# quantiles of the model's OWN fit data rather than as absolute nats. A nats
# threshold is a property of one corpus -- measured on the synthetic set the
# whole defined range is 0.1 to 4.2, so a plausible-sounding "5.0 = rare" never
# fires and "1.0 = routine" happens to sit on the median. A quantile is a
# policy ("rarer than 90% of ordinary traffic") and travels between corpora,
# so the model records the nats values at fit time and carries them.
SEQUENCE_ROUTINE_QUANTILE = 0.50   # at or below the median transition for this
                                   # corpus: ordinary, demote a flagged line
SEQUENCE_RARE_QUANTILE = 0.90      # rarer than 90% of fitted transitions:
                                   # promote

# --- Alert suppression (Stage 3) ---
# The first Stage 3 lever that *shortens* the alert list rather than reordering
# it: clear `is_anomaly` on a flagged line that is alone in its incident and
# whose template transition is not rare. **On, on measurement** -- it is the one
# Stage 3 change that moves line-level P/R/F1, instance detection and incident
# count, so it owed the full CLAUDE.md section 4 suite before its default could
# change, and it was not adopted on clean-corpus evidence.
#
# What it buys (results/suppression/suppression.md), zero attack lines removed
# on either clean corpus:
#   synthetic  P 0.300 -> 0.310, recall 0.867 unchanged, 94  -> 90  incidents
#   OpenSSH    P 0.206 -> 0.248, recall 0.570 unchanged, 194 -> 147 incidents
#
# What it costs (results/suppression/suppression_adversarial.md, 5 seeds):
# instance detection is unchanged on all nine camouflage conditions, and
# unchanged *seed by seed* -- across 45 instance-firings suppression never
# removed the last surviving line of an instance. But it does thin the evidence
# on the two timing-spread conditions, which is where a future strengthening of
# this rule will break first:
#   slow             line rate 0.824 -> 0.790,  8 attack lines removed
#   realistic-combo  line rate 0.776 -> 0.741,  6 attack lines removed
# Every other condition removes zero attack lines. The mechanism is legible:
# spreading an attack in time makes its lines lone, and lone is what puts a line
# in the eligible pool.
#
# Note this switch only has an effect when a sequence model is actually passed,
# so the batch and stream paths that pass none are untouched by it.
SEQUENCE_SUPPRESSION = True

# Which quantile of the fitted history a lone flagged line has to clear to
# survive. 0.90 is the model's existing `rare_threshold`, reused rather than
# introduced: the rule reads "a lone flagged line survives only if its
# transition is in the rarest tenth of history".
#
# The intuitive value, 0.50 ("suppress a *routine* transition"), was measured
# first and is nearly inert -- 0 of 59 eligible rows on the synthetic corpus and
# 13 of 63 on the kill-point corpus clear it. That is structural, not a tuning
# miss: the flagged rows are already the anomalous tail, and a line the
# embedding detector found unusual almost never has a below-median transition.
# The two signals are positively correlated, so conditioning on one shifts the
# other.
#
# **0.99 was measured too, and rejected, and that is the entry worth reading.**
# On clean data it is far the best-looking value -- synthetic F1 0.446 -> 0.624
# and 94 -> 44 incidents, against q0.90's 0.456 and 90. Under camouflage it
# surrenders exactly the margin CLAUDE.md section 4 says clean data hides:
#   slow             instance detection 80.0% -> 66.7% (-13.3pt), line rate
#                    0.824 -> 0.266, 130 attack lines removed
#   ip_rotate        84.4% -> 80.0% (-4.4pt), line rate 0.837 -> 0.601
#   realistic-combo  91.1% -> 88.9% (-2.2pt), line rate 0.776 -> 0.471
# It halves total alert volume across the suite (5,083 -> 2,927 incidents) by
# deleting detections. This is the 2026-08-16 contamination lesson reproduced
# on a different knob: a threshold validated only on clean data is a threshold
# validated on the half of the evidence that saturates.
# See logdet/suppression.py and results/suppression/.
SEQUENCE_SUPPRESSION_QUANTILE = SEQUENCE_RARE_QUANTILE

# Which loneness test decides that a flagged line is uncorroborated. This is
# the guard doing the *safety* work in suppression -- the surprisal threshold
# above is only selectivity (results/suppression/suppression.md: among flagged
# rows the surprisal separates attack from benign at AUC 0.278 on the synthetic
# corpus, i.e. backwards). So this is the knob to move if suppression is to be
# pushed harder, and it is also the one that has to be re-measured under
# camouflage from scratch whenever it moves.
#
#   "incident"  a flagged line is lone when no *other flagged line* shares its
#               user or source IP inside the incident window. This is grouping's
#               own answer, and it is blind to benign traffic: it cannot tell an
#               unknown IP appearing exactly once from a busy known host that
#               also logged one odd line.
#   "share"     a flagged line is lone when the flagged share of its entity
#               neighbourhood -- counted over the *whole* frame, benign lines
#               included, via the Stage 4 entity graph -- is at or below
#               SUPPRESSION_FLAGGED_SHARE. At 0.0 this is exactly "incident"
#               (asserted by a test); above 0.0 it suppresses lines that
#               grouping does corroborate but whose entity is overwhelmingly
#               benign.
#   "quiet"     a flagged line is lone only when *nothing at all* shares its
#               user or source IP inside the window. Strictly the safest and
#               strictly the smallest pool.
#
# **Measured 2026-09-04, and both graph tests were rejected**
# (results/suppression/loneness/). The full section 4 suite was run for each:
# both clean corpora, plus instance detection under camouflage over 5 seeds.
# Instance detection is unchanged on every arm and every condition.
#
#   quiet       strictly dominated. Costs the *same* attack lines as "incident"
#               (8 on `slow`, 6 on `realistic-combo`) while suppressing fewer
#               benign ones, so alert volume goes back up (626 -> 632 incidents
#               on `slow`) for nothing. The attack lines suppression costs are
#               genuinely isolated, so demanding total isolation does not
#               protect them -- which is the finding, and it needed the
#               camouflage suite to see.
#   share@0.50  identical incident counts to "incident" on all nine camouflage
#               conditions, and it removes one attack line on `temporal` and one
#               on `volume`, both previously free (line rates 0.858 -> 0.854 and
#               0.847 -> 0.841). On clean data it looks good -- kill-point 147 ->
#               142 incidents, precision 0.248 -> 0.260 -- and it triples the
#               attack lines admitted into the pool there, 3 -> 9. That is the
#               q0.99 mistake on the guard instead of the threshold.
#
# What the graph did earn: share@0.00 reproduces "incident" exactly on both real
# corpora, so the two code paths agree outside the unit test.
SUPPRESSION_LONENESS = "incident"

# Only read when SUPPRESSION_LONENESS == "share". 0.0 reproduces "incident".
SUPPRESSION_FLAGGED_SHARE = 0.0

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

# Structured (JSON) narrative output. The prose prompt asks the model not to
# invent MITRE technique IDs and it does anyway -- 33% of technique mentions on
# the synthetic corpus, 60% on OpenSSH. With this on, the technique claim moves
# into a named JSON field that code validates against the grounded list, and a
# rejected ID is dropped rather than printed.
#
# On by default since 2026-09-04, measured on both corpora
# (results/faithfulness/arms/), never chosen on the clean corpus alone:
#
#   arm                invented IDs, synthetic   OpenSSH   fabricated summaries
#   prose (baseline)   47 of 142                 119/197   7
#   prose (reworded)   12 of 101                 6/79      2
#   structured JSON    0 of 65                   0/58      0
#
# The cost is brevity: a rendered narrative is ~546 characters against prose's
# ~1287, because a model answering in JSON writes one or two sentences where it
# wrote four. Flip this off to get v1's prose back; a test pins the default so
# the flip is deliberate.
LLM_STRUCTURED_OUTPUT = True

# --- narration tiers (Stage 5 model routing) ---
#
# A full narrative costs ~3.9s per incident on the 4060 and ~18.2s on its CPU
# (section 2c), so narrating all 94 synthetic incidents is minutes of GPU and
# the better part of half an hour of CPU. That is why NARRATE_* exists at all:
# 75 of 94 incidents currently get no prose whatsoever, and an analyst scanning
# the list reads raw fields for them.
#
# The tiers split that budget instead of raising it. A *triage* line is one
# sentence with a hard 80-token cap, which is where nearly all the latency is
# -- the prompt is the same size, only the generation is short. A *full*
# narrative is the structured JSON path, unchanged.
#
# Both models default to LLM_MODEL so this is a token-budget split until a
# second model has been measured on both corpora; pointing the full tier at a
# larger model is a config edit, not a code change.
LLM_TRIAGE_MODEL = LLM_MODEL
LLM_NARRATIVE_MODEL = LLM_MODEL
# The cap ends generation rather than the model ending it, so a sentence the
# model has not finished is cut mid-clause. 80 was the first value tried and it
# cut roughly a fifth of the lines; 120 is the swept one
# (results/routing/cap_sweep/, 94 synthetic incidents, phi3, 4060):
#
#   cap    cut mid-sentence   94 lines took   median   fully faithful
#   80     19.1% (18/94)      83.6s           0.89s    92/94
#   120    1.1%  (1/94)       88.1s           0.90s    91/94
#   160    3.2%  (3/94)       91.9s           0.90s    89/94
#
# The cap is a *tail* control, not a per-line cost: almost every line finishes
# well inside 80 tokens and only the long ones ever reach the limit, so raising
# it buys the tail for 5% of the wall clock and leaves the median untouched.
# 160 buys nothing further. Two figures keep this honest -- cap 80 measured
# 24/94 cut in the previous session and 18/94 here on identical settings, so
# ~6 lines is run-to-run noise and only the 18 -> 1 step is real; and the extra
# generation costs one mistyped source IP (10.00.1.102), which is why the
# faithful column moves down as the cap moves up.
LLM_TRIAGE_NUM_PREDICT = 120   # one sentence finishes; 400 lets phi3 write five
TRIAGE_SENTENCE_RANGE = "1"

# The other way to stop a line being cut: ask for one short enough to finish.
# Measured and not adopted -- "under 25 words" cuts truncation about as well
# (4.3%) and is faster, but it shortens the line 226 -> 178 characters and both
# word-capped arms scored *below* the token-capped ones on faithfulness (89/94
# and 87/94). It also changes the prompt, which raising the cap does not.
TRIAGE_MAX_WORDS: int | None = None

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

# Where a mined Drain3 template set is persisted. Cluster ids are only
# meaningful relative to the state that produced them, so a model keyed on
# template ids and the miner that numbered those templates have to travel
# together or the model scores against a silently renumbered vocabulary.
DEFAULT_TEMPLATE_STATE_PATH = str(PROJECT_ROOT / "models" / "drain3_state.json")

# Transition model over those template ids. Written by `logdet-fit --drain3`
# and carried alongside the miner state it was numbered against -- loading one
# without the other scores transitions under the wrong templates.
DEFAULT_SEQUENCE_MODEL_PATH = str(PROJECT_ROOT / "models" / "sequence_model.json")

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

# --- API service (Stage 2) ---
# Localhost by default: the service has no authentication, and the incidents it
# serves are security findings about the monitored host. Binding it to
# 10.10.10.2 for the two-machine demo (CLAUDE.md 2c) is a deliberate act, not a
# default anyone can fall into.
API_HOST = "127.0.0.1"
API_PORT = 8000
# Per-subscriber buffer on the live event feed. A slow reader drops events
# rather than stalling the scoring thread -- the alert backlog is always
# retrievable from GET /incidents, so dropping is recoverable and blocking the
# detector is not.
# Where POST /collector/ingest appends the lines a remote collector ships
# (CLAUDE.md 2c/2d). One fixed path, never a client-supplied one: the endpoint
# is unauthenticated, so letting a caller choose where bytes land would be an
# arbitrary-file-write hole. The analyzer tails this same file with a normal
# file stream, so ingestion and scoring stay decoupled -- the collector can
# buffer to it before any stream is running, and a stream restart resumes from
# its own offset into it.
COLLECTOR_LOG_PATH = str(PROJECT_ROOT / "data" / "live" / "collector.log")

API_EVENT_QUEUE_SIZE = 1000
API_SSE_POLL_SECONDS = 0.25
