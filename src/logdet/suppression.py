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
2. It is **lone**: the only flagged row in its incident under the grouping that
   was in force before any suppression. A row that shares a user or a source IP
   with another flagged row inside the incident window is corroborated, and
   corroboration is the evidence the whole grouping layer exists to find.
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

One pass, and it cannot cascade
-------------------------------

Suppression is computed against the pre-suppression grouping and applied once.
That is not a simplification, it is exact: the only rows removed are singleton
incidents, and removing a singleton cannot change any other incident's
membership -- no other row was linked to it, or it would not have been a
singleton. So a second pass would find the same singletons it found the first
time, and iterating is provably a no-op.
"""

from __future__ import annotations

import pandas as pd

from logdet.config import SEQUENCE_SUPPRESSION_QUANTILE
from logdet.sequence_grouping import group_anomalies

SURPRISAL_COLUMN = "transition_surprisal"


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


def suppression_mask(scored: pd.DataFrame, threshold: float | None,
                     surprisal_col: str = SURPRISAL_COLUMN,
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
    return eligible & lone_flagged_mask(scored, **grouping)


def suppress_routine_singletons(scored: pd.DataFrame, threshold: float | None,
                                surprisal_col: str = SURPRISAL_COLUMN,
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
    mask = suppression_mask(scored, threshold, surprisal_col=surprisal_col, **grouping)
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
