"""
suppression.py
Clears `is_anomaly` on lone flagged lines whose template transition is not rare
(Stage 3).

Every Stage 3 change so far has been forbidden from touching `is_anomaly`, and
that is exactly why none of them moved the number that matters. Precision is
0.29; the synthetic corpus produces 94 incidents for 9 real attacks and the
kill-point OpenSSH corpus produces 194 for the same 9. Re-tiering and
re-ranking reorder that list. Only removing an alert shortens it.

So this module is the first Stage 3 code that changes what the detector says,
and CLAUDE.md section 4 applies to it in full.

The rule
--------

A flagged row is suppressed when **all four** hold:

1. It is not an impossible-travel hit. That signal is a physics check, not a
   semantic score, and it already outranks the ML verdict everywhere else in
   the system (`assign_severity` forces such rows to "high"). It is also the
   only thing that detects Scenario B at all -- the embeddings contribute
   nothing there, because both login legs are identical vectors after IP
   masking. Suppressing one would be removing the only evidence there is.
2. It is **lone**: uncorroborated by the traffic around it. A row that shares a
   user or a source IP with another flagged row inside the incident window is
   corroborated, and corroboration is the evidence the whole grouping layer
   exists to find. *Which* test answers this is `SUPPRESSION_LONENESS` -- the
   shipped one ("incident") is grouping's own answer and sees only the flagged
   rows; "share" and "quiet" ask the Stage 4 entity graph the same question
   over the whole frame, benign lines included. **Both graph tests were
   measured on the full section 4 suite and rejected** -- see config.py and
   results/suppression/loneness/. The short version is that the attack lines
   suppression costs are genuinely isolated, so seeing the benign traffic
   around an alert does not make this guard safer.
3. Its transition surprisal is **defined**. NaN means the model had nothing to
   say -- an unknown template, the first event of a sequence, or no usable
   actor key -- and silence is not evidence in either direction. This is the
   same rule the severity shift follows, and it is what protects account
   enumeration under `ip_rotate`, where both sequence keys change on every line
   and there is no transition to score.
4. Its transition surprisal is **at or below the model's `rare_threshold`**,
   i.e. the transition is not in the rarest tenth of the fitted history.

Why "not rare" rather than "routine"
------------------------------------

The obvious wording of this rule is "suppress a lone flagged line whose
transition is *routine*", meaning at or below the fitted median. Measured, that
rule is nearly inert, and the reason is structural rather than accidental: the
flagged rows are already the anomalous tail, and a line the embedding detector
found unusual almost never has a below-median template transition. On the
synthetic corpus **0 of 59** eligible rows clear a median threshold; on the
kill-point corpus 13 of 63. The two signals are positively correlated, so
conditioning on one shifts the other.

The threshold adopted is therefore the model's existing `rare_threshold` --
already computed, already carried on every fitted model, and already the
boundary the severity shift used for promotion. The rule reads: *a lone flagged
line survives only if its transition is genuinely rare for this actor.*

The two guards are not equal partners, and it matters which is doing the work.
**Loneness is the safety property; the surprisal is the selectivity.** Among
flagged rows the surprisal on its own separates attack from benign *badly* --
AUC 0.278 on the synthetic corpus and 0.645 on the kill-point corpus, i.e. at
or below a coin flip on one of them, with attack lines scoring *lower* than
benign ones. Suppressing on surprisal alone would preferentially delete
attacks. Restricted to lone rows it inverts: AUC 0.987 and 0.954, because the
lone attack lines that exist are impossible-travel hits, which guard 1 removes
from consideration anyway. Any future change that weakens guard 1 or 2 has to
be re-measured from scratch; weakening guard 4 alone is comparatively safe.

Batch only, and the reason is not laziness
------------------------------------------

Nothing in the streaming path calls this, and it must not until the question
below is answered. Loneness is not knowable at emit time: a flagged line that
is alone in this micro-batch may be joined by a line arriving in the next one,
and `StreamProcessor` grows incidents event by event precisely because that
happens. Suppressing on the strength of "alone so far" would withdraw alerts
the batch path keeps, which would break the streamed-equals-batch equivalence
(`tests/test_stream_regression.py`) that is the only thing making streamed
numbers comparable to every number in `results/`. Making it work in a stream
means deferring the decision by at least the incident window and re-verifying
that lock -- a separate piece of work, not a parameter.

One pass, and what that costs under each loneness test
------------------------------------------------------

Suppression is computed against the pre-suppression grouping and applied once.

Under "incident" and "quiet" that is not a simplification, it is exact: the
only rows removed are singleton incidents, and removing a singleton cannot
change any other incident's membership -- no other row was linked to it, or it
would not have been a singleton. So a second pass finds the same singletons it
found the first time, and iterating is provably a no-op.

Under "share" with a threshold above 0 it *is* a choice, and the deliberate
one. That test can withdraw a row from a multi-row incident, which can leave
another row alone, which a second pass would then be free to withdraw as well.
Iterating would let suppression eat a whole incident one line at a time --
precisely the failure mode that destroys attack evidence, and the reason the
loneness guard exists at all. So the rule is applied against the grouping that
was in force before any suppression, once, and a row corroborated at that
moment stays corroborated.
"""

from __future__ import annotations

import pandas as pd

from logdet.config import (
    GROUP_BY_SOURCE_IP,
    INCIDENT_WINDOW_MINUTES,
    SEQUENCE_SUPPRESSION_QUANTILE,
    SUPPRESSION_FLAGGED_SHARE,
    SUPPRESSION_LONENESS,
)
from logdet.entity_graph import EntityGraph
from logdet.sequence_grouping import group_anomalies

SURPRISAL_COLUMN = "transition_surprisal"

# The three answers to "is this alert uncorroborated?". See config.py for what
# each means and results/suppression/suppression_loneness.md for the numbers
# that chose between them.
LONENESS_MODES = ("incident", "share", "quiet")


def lone_flagged_mask(scored: pd.DataFrame, **grouping) -> pd.Series:
    """True for each row that is the *only* flagged row in its incident.

    Uses the shipped grouper rather than a second link rule, so "lone here"
    and "singleton incident in the report" cannot drift apart.
    """
    lone = pd.Series(False, index=scored.index)
    if "is_anomaly" not in scored.columns or not scored["is_anomaly"].any():
        return lone
    # A row the grouper drops (no timestamp) is never reported lone, so it is
    # never suppressed. That is the safe direction on purpose: without a
    # timestamp there is no way to know whether anything corroborates it.

    # group_anomalies resets the index of each incident it returns, so the
    # original row identity has to be carried in a column to get back.
    tagged = scored.copy()
    tagged["_row_id"] = list(scored.index)
    for incident in group_anomalies(tagged, **grouping):
        if len(incident) == 1:
            lone.at[incident["_row_id"].iloc[0]] = True
    return lone


def neighbourhood_counts(scored: pd.DataFrame,
                         window_minutes: int = INCIDENT_WINDOW_MINUTES,
                         group_by_source_ip: bool = GROUP_BY_SOURCE_IP,
                         time_col: str = "timestamp") -> pd.DataFrame:
    """Per flagged row: how much traffic its entities account for.

    Two counts, both over the **whole frame** rather than over the flagged rows
    alone, and that difference is the entire point of building this on the
    Stage 4 entity graph:

      `neighbours`          other events sharing this row's user or source IP
                            inside the incident window, benign ones included
      `flagged_neighbours`  how many of those are themselves flagged

    Union-find only ever held the flagged rows, so it could answer the second
    question and not the first -- an unknown IP appearing exactly once and a
    busy known host that also logged one odd line were the same thing to it.

    Rows with no timestamp are given zero on both counts and are excluded from
    everyone else's, matching the grouper, which drops them. They are protected
    separately by `lone_mask`, which never calls a row without a timestamp lone.
    """
    counts = pd.DataFrame({"neighbours": 0, "flagged_neighbours": 0},
                          index=scored.index)
    if "is_anomaly" not in scored.columns or time_col not in scored.columns:
        return counts

    frame = scored.dropna(subset=[time_col]).sort_values(time_col)
    if frame.empty:
        return counts

    kinds = ("user", "ip") if group_by_source_ip else ("user",)
    row_ids = list(frame.index)
    flagged = frame["is_anomaly"].astype(bool).to_numpy()
    graph = EntityGraph.build(frame.reset_index(drop=True),
                              window_minutes=window_minutes, kinds=kinds,
                              time_col=time_col)

    # Only flagged rows are ever asked about, and the graph query is O(events
    # on that entity), so skipping the benign majority keeps this linear in the
    # number of alerts rather than in the size of the corpus.
    for position in range(len(frame)):
        if not flagged[position]:
            continue
        others = graph.neighbours(position, kinds=kinds)
        counts.at[row_ids[position], "neighbours"] = len(others)
        counts.at[row_ids[position], "flagged_neighbours"] = sum(
            1 for other in others if flagged[other])
    return counts


def lone_mask(scored: pd.DataFrame,
              mode: str = SUPPRESSION_LONENESS,
              flagged_share: float = SUPPRESSION_FLAGGED_SHARE,
              **grouping) -> pd.Series:
    """True for each flagged row the chosen loneness test calls uncorroborated.

    `mode` selects between the three tests described in config.py. "incident"
    is the shipped one and is computed by the grouper itself; "share" and
    "quiet" are graph queries over the whole frame. "share" at 0.0 is the same
    test as "incident" -- asserted in tests/test_suppression.py rather than
    assumed, because the two are computed by different code paths and a drift
    between them would silently change what suppression does.
    """
    if mode not in LONENESS_MODES:
        raise ValueError(f"unknown loneness mode {mode!r}; expected one of {LONENESS_MODES}")
    if mode == "incident":
        return lone_flagged_mask(scored, **grouping)

    lone = pd.Series(False, index=scored.index)
    if "is_anomaly" not in scored.columns or not scored["is_anomaly"].any():
        return lone

    counts = neighbourhood_counts(scored, **grouping)
    flagged = scored["is_anomaly"].astype(bool)
    # A row without a timestamp is invisible to the graph and would otherwise
    # score zero neighbours, i.e. maximally lone -- the opposite of the safe
    # answer. The grouper drops such rows, so exclude them here too.
    time_col = grouping.get("time_col", "timestamp")
    known_time = (scored[time_col].notna() if time_col in scored.columns
                  else pd.Series(False, index=scored.index))

    if mode == "quiet":
        return flagged & known_time & (counts["neighbours"] == 0)

    share = counts["flagged_neighbours"] / counts["neighbours"].where(
        counts["neighbours"] > 0)
    return flagged & known_time & (share.fillna(0.0) <= flagged_share)


def suppression_mask(scored: pd.DataFrame, threshold: float | None,
                     surprisal_col: str = SURPRISAL_COLUMN,
                     loneness: str = SUPPRESSION_LONENESS,
                     flagged_share: float = SUPPRESSION_FLAGGED_SHARE,
                     **grouping) -> pd.Series:
    """Which flagged rows the rule would clear. See the module docstring."""
    blank = pd.Series(False, index=scored.index)
    if threshold is None or surprisal_col not in scored.columns:
        return blank
    if "is_anomaly" not in scored.columns:
        return blank

    surprisal = pd.to_numeric(scored[surprisal_col], errors="coerce")
    eligible = (scored["is_anomaly"].astype(bool)
                & surprisal.notna()
                & (surprisal <= threshold))
    if "impossible_travel" in scored.columns:
        eligible &= ~scored["impossible_travel"].astype(bool)
    if not eligible.any():
        return blank
    return eligible & lone_mask(scored, mode=loneness,
                                flagged_share=flagged_share, **grouping)


def suppress_routine_singletons(scored: pd.DataFrame, threshold: float | None,
                                surprisal_col: str = SURPRISAL_COLUMN,
                                loneness: str = SUPPRESSION_LONENESS,
                                flagged_share: float = SUPPRESSION_FLAGGED_SHARE,
                                **grouping) -> pd.DataFrame:
    """Return `scored` with the suppressed rows' `is_anomaly` cleared.

    `ml_anomaly` is deliberately left as it was: it records what the embedding
    detector said, and evaluation attributes a detection to the model or to the
    rule through it. Overwriting it would erase the evidence that a row was
    flagged and then withdrawn. The withdrawal is recorded in its own column,
    `suppressed`, so the count is readable from the scored frame rather than
    having to be recomputed.
    """
    scored = scored.copy()
    mask = suppression_mask(scored, threshold, surprisal_col=surprisal_col,
                            loneness=loneness, flagged_share=flagged_share,
                            **grouping)
    scored["suppressed"] = mask
    scored.loc[mask, "is_anomaly"] = False
    return scored


def threshold_for(sequence_model, quantile: float = SEQUENCE_SUPPRESSION_QUANTILE
                  ) -> float | None:
    """The nats value this quantile of the model's fitted history resolves to.

    The default is the quantile the model already stores as `rare_threshold`,
    so the common case costs no recomputation and cannot drift from the value
    the severity shift used. Any other quantile is only available if the model
    kept its fitted distribution, which it does not -- so this returns None
    rather than guessing, and the caller is expected to pass a threshold it
    computed itself.
    """
    if sequence_model is None:
        return None
    from logdet.config import SEQUENCE_RARE_QUANTILE, SEQUENCE_ROUTINE_QUANTILE
    if quantile == SEQUENCE_RARE_QUANTILE:
        return sequence_model.rare_threshold
    if quantile == SEQUENCE_ROUTINE_QUANTILE:
        return sequence_model.routine_threshold
    return None
