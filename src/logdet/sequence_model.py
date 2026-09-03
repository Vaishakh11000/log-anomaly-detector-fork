"""
sequence_model.py
A transition model over mined template IDs (Stage 3).

v1 scores every log line on its own, which is the structural reason precision
is 0.29: one unusual line is inherently weak evidence. An attack is a
*sequence* -- a failed password is unremarkable, forty of them followed by an
acceptance is not -- and nothing in the per-line detector can see that.

This module supplies the missing view. It learns, from a slice of history, how
often one template follows another for the same actor, and reports the
surprisal of each observed transition:

    surprisal = -log P(template_i | template_{i-1})

A routine transition scores near zero. A transition never seen during fitting
scores high.

Three properties are deliberate, and each of them is a silent failure in the
obvious version.

*It never gates detection.* A template ID is a discrete symbol, so rewording a
line moves it to a different cluster -- which is exactly how a signature rule
breaks, and this project's one surviving robustness win (`rephrase`, +31.1pt
against Wazuh) rests on embeddings *not* behaving that way. So the surprisal is
used to rank and to tier severity, never to decide `is_anomaly`. The embedding
path stays the recall path. See CLAUDE.md section 1b.

*An unknown template is neutral, not suspicious.* Treating a never-before-seen
cluster as evidence rebuilds the same brittleness pointing the other way, and
alert volume already climbs under novel wording (179 -> 467 in the bake-off).
Unknown templates return NaN and the severity rule leaves such rows alone; the
unmatched rate is a health number, not a detection.

*Two sequence keys, consulted in precedence order.* Sequences are keyed per
user, falling back to source IP for the lines a user key cannot follow (an
account enumeration varies the username on every line by design, so there is
no per-user sequence to speak of).

What the measurement supports is the *ranking* of the two keys, not the
combining rule. The user key is much the stronger signal -- AUC 0.851 on the
synthetic corpus and 0.958 on the kill-point OpenSSH corpus, against source
IP's 0.230 and 0.758. The rule for putting them together is a wash: precedence
reads 0.856 and 0.912 where taking the maximum across keys reads 0.852 and
0.923, so each rule wins one corpus by about a point. Precedence is kept for
being the simpler rule to reason about, **not** because it scored better, and
this docstring says so rather than dressing a tie as a finding.

Either combining form scores more rows than the user key alone (517 and 1,175
against 509 and 660), so the fallback buys coverage at lower quality -- which
is why the pooled figure sits *below* user-alone on the kill-point corpus. That
is the price of having anything at all to say about enumeration, not a
regression.

The model is keyed on Drain3 cluster IDs, which are only meaningful relative to
the miner state that produced them (see templating.py). `save` therefore stamps
a fingerprint of that vocabulary and `load` refuses a mismatch, for the same
reason PerUserAnomalyDetector refuses a foreign embedding model: scoring
against a silently renumbered vocabulary produces numbers that look fine and
mean nothing.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from logdet.config import (
    NON_IDENTITY_VALUES,
    SEQUENCE_KEYS,
    SEQUENCE_RARE_QUANTILE,
    SEQUENCE_ROUTINE_QUANTILE,
    SEQUENCE_SMOOTHING,
)


def _identity(value) -> str | None:
    """Normalise a key cell to a usable sequence key, or None.

    Shared intent with sequence_grouping._identity: "unknown" is the parser
    reporting no user, not a user. Threading every unattributed line into one
    pseudo-actor's sequence would invent transitions nobody made.
    """
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in NON_IDENTITY_VALUES:
        return None
    return text


def vocabulary_fingerprint(template_ids) -> str:
    """A short, order-independent fingerprint of a template vocabulary.

    Cluster IDs are the model's alphabet. Two miners that mined different
    corpora can hand out the same integers for different templates, so the
    fingerprint is what makes a mismatch loud instead of silent.
    """
    ids = sorted({int(t) for t in template_ids if t is not None and not pd.isna(t)})
    payload = ",".join(str(i) for i in ids).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


class TransitionModel:
    """First-order Markov transition counts over template IDs, per sequence key.

    Fit on history, then score a frame: `surprisal(df)` returns one value per
    row, NaN where there is nothing to say (first event of a sequence, unknown
    template, or no usable key).
    """

    FORMAT_VERSION = 1

    def __init__(self, alpha: float = SEQUENCE_SMOOTHING,
                 keys: tuple[str, ...] = SEQUENCE_KEYS):
        self.alpha = alpha
        self.keys = tuple(keys)
        # key column -> key value -> {(prev_id, curr_id): count}
        self.transitions: dict[str, dict[str, dict[tuple[int, int], int]]] = {}
        # key column -> key value -> {prev_id: count}, the denominator
        self.prefixes: dict[str, dict[str, dict[int, int]]] = {}
        # Backoff for a key value never seen during fitting (a new user, a new
        # source IP). Without it every first-seen actor scores as maximally
        # surprising, which is a cold-start artefact and not evidence.
        self.global_transitions: dict[tuple[int, int], int] = {}
        self.global_prefixes: dict[int, int] = {}
        self.vocabulary: set[int] = set()
        self.fingerprint: str | None = None
        self.fitted_rows: int = 0
        # Nats, read off the fit corpus rather than written down in advance.
        # See SEQUENCE_*_QUANTILE in config.py for why these are not constants.
        self.routine_threshold: float | None = None
        self.rare_threshold: float | None = None

    # --- fitting ----------------------------------------------------------

    def fit(self, df: pd.DataFrame, id_col: str = "template_id",
            time_col: str = "timestamp") -> "TransitionModel":
        if id_col not in df.columns:
            raise ValueError(
                f"no '{id_col}' column -- parse with `logdet-preprocess --drain3` "
                "before fitting a sequence model")

        frame = df[[c for c in (id_col, time_col, *self.keys) if c in df.columns]].copy()
        frame[id_col] = pd.to_numeric(frame[id_col], errors="coerce")

        self.vocabulary = {int(t) for t in frame[id_col].dropna().unique()}
        self.fingerprint = vocabulary_fingerprint(self.vocabulary)
        self.fitted_rows = int(len(frame))

        for key_col in self.keys:
            self.transitions[key_col] = {}
            self.prefixes[key_col] = {}
            if key_col not in frame.columns:
                continue
            for prev_id, curr_id, key_value in self._pairs(frame, key_col, id_col, time_col):
                self.transitions[key_col].setdefault(key_value, {})
                counts = self.transitions[key_col][key_value]
                counts[(prev_id, curr_id)] = counts.get((prev_id, curr_id), 0) + 1
                prefixes = self.prefixes[key_col].setdefault(key_value, {})
                prefixes[prev_id] = prefixes.get(prev_id, 0) + 1
                self.global_transitions[(prev_id, curr_id)] = (
                    self.global_transitions.get((prev_id, curr_id), 0) + 1)
                self.global_prefixes[prev_id] = self.global_prefixes.get(prev_id, 0) + 1

        self._calibrate(frame, id_col, time_col)
        return self

    def _calibrate(self, frame: pd.DataFrame, id_col: str, time_col: str) -> None:
        """Record what "routine" and "rare" mean in nats, for this corpus.

        Scoring the fit data with the model just fitted is deliberate and is
        not a performance claim -- nothing here is evaluated. It is the only
        way to turn a policy ("rarer than 90% of ordinary traffic") into the
        number the severity rule can compare against, and it keeps that number
        travelling with the model instead of sitting in config as a constant
        that is right for one log and wrong for the next.
        """
        values = self.surprisal(frame, id_col=id_col, time_col=time_col).dropna()
        if values.empty:
            self.routine_threshold = None
            self.rare_threshold = None
            return
        self.routine_threshold = float(values.quantile(SEQUENCE_ROUTINE_QUANTILE))
        self.rare_threshold = float(values.quantile(SEQUENCE_RARE_QUANTILE))

    @staticmethod
    def _pairs(frame: pd.DataFrame, key_col: str, id_col: str, time_col: str):
        """Yield (prev_id, curr_id, key_value) for consecutive events per key.

        Sorting by time inside each key is what makes this a sequence rather
        than a bag: the frame arrives in file order, which is global order, and
        two actors interleaved in one file are two independent sequences.
        """
        ordered = frame.copy()
        if time_col in ordered.columns:
            ordered = ordered.sort_values(time_col, kind="stable")
        for raw_key, group in ordered.groupby(key_col, dropna=True, sort=False):
            key_value = _identity(raw_key)
            if key_value is None:
                continue
            ids = [int(t) for t in group[id_col].dropna()]
            for prev_id, curr_id in zip(ids, ids[1:]):
                yield prev_id, curr_id, key_value

    # --- scoring ----------------------------------------------------------

    def transition_surprisal(self, prev_id: int, curr_id: int,
                             key_col: str, key_value: str) -> float:
        """-log P(curr | prev) in nats, with Laplace smoothing.

        Backs off to the global table only when this actor is entirely unseen
        -- a cold start, which is not evidence. An actor that *is* known but
        has never been in this state keeps its own table and scores the
        smoothing floor, log(vocabulary size). Conflating the two would erase
        the signal that matters most here: "this account has never done this"
        would be answered with "but everyone else does it constantly".
        """
        counts = self.transitions.get(key_col, {}).get(key_value)
        prefixes = self.prefixes.get(key_col, {}).get(key_value)
        if not counts or not prefixes:
            counts, prefixes = self.global_transitions, self.global_prefixes

        vocabulary_size = max(len(self.vocabulary), 1)
        numerator = counts.get((prev_id, curr_id), 0) + self.alpha
        denominator = prefixes.get(prev_id, 0) + self.alpha * vocabulary_size
        return -math.log(numerator / denominator)

    def surprisal(self, df: pd.DataFrame, id_col: str = "template_id",
                  time_col: str = "timestamp") -> pd.Series:
        """One surprisal per row of `df`, NaN where the model has nothing to say.

        Keys are consulted in order and the first one that can score a row
        wins; later keys only fill rows the earlier ones left silent. See the
        module docstring for why this beats taking the maximum.
        """
        result = pd.Series(np.nan, index=df.index, dtype=float)
        if id_col not in df.columns or self.fingerprint is None:
            return result

        ids = pd.to_numeric(df[id_col], errors="coerce")
        for key_col in self.keys:
            if key_col not in df.columns:
                continue
            ordered_index = (df.sort_values(time_col, kind="stable").index
                             if time_col in df.columns else df.index)
            previous: dict[str, int] = {}
            for idx in ordered_index:
                key_value = _identity(df.at[idx, key_col])
                if key_value is None:
                    continue
                raw_id = ids.at[idx]
                if pd.isna(raw_id):
                    continue
                curr_id = int(raw_id)
                prev_id = previous.get(key_value)
                previous[key_value] = curr_id
                # An unknown template is neutral: it is a miner that has not
                # seen this wording, not an attacker. Recording it as maximal
                # surprisal would turn novel-but-benign phrasing into alerts.
                if prev_id is None or curr_id not in self.vocabulary:
                    continue
                # First key to speak for this row keeps it. A later key may
                # only fill silence, never overrule.
                if not pd.isna(result.at[idx]):
                    continue
                result.at[idx] = self.transition_surprisal(
                    prev_id, curr_id, key_col, key_value)

        return result

    def unknown_rate(self, df: pd.DataFrame, id_col: str = "template_id") -> float:
        """Share of rows whose template was never seen during fitting.

        A health metric, deliberately not a detection: a rising unknown rate
        means the vocabulary the model was fit on no longer describes the log,
        which is a reason to refit rather than a reason to alert.
        """
        if id_col not in df.columns or df.empty:
            return 0.0
        ids = pd.to_numeric(df[id_col], errors="coerce").dropna()
        if ids.empty:
            return 0.0
        unknown = sum(1 for t in ids if int(t) not in self.vocabulary)
        return unknown / len(ids)

    # --- persistence ------------------------------------------------------

    def save(self, path) -> "TransitionModel":
        """Persist the model together with the vocabulary it is keyed on."""
        if self.fingerprint is None:
            raise RuntimeError("refusing to save an unfitted sequence model")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": self.FORMAT_VERSION,
            "alpha": self.alpha,
            "keys": list(self.keys),
            "vocabulary": sorted(self.vocabulary),
            "vocabulary_fingerprint": self.fingerprint,
            "fitted_rows": self.fitted_rows,
            "routine_threshold": self.routine_threshold,
            "rare_threshold": self.rare_threshold,
            "fitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            # JSON has no tuple keys; "prev>curr" round-trips without pickling,
            # which keeps a stored model readable and diffable.
            "transitions": {
                key_col: {
                    key_value: {f"{p}>{c}": n for (p, c), n in counts.items()}
                    for key_value, counts in by_value.items()
                }
                for key_col, by_value in self.transitions.items()
            },
            "prefixes": {
                key_col: {
                    key_value: {str(p): n for p, n in prefixes.items()}
                    for key_value, prefixes in by_value.items()
                }
                for key_col, by_value in self.prefixes.items()
            },
            "global_transitions": {f"{p}>{c}": n for (p, c), n in self.global_transitions.items()},
            "global_prefixes": {str(p): n for p, n in self.global_prefixes.items()},
        }
        path.write_text(json.dumps(payload, indent=1))
        return self

    @classmethod
    def load(cls, path, expect_fingerprint: str | None = None) -> "TransitionModel":
        """Restore a saved model, refusing a vocabulary it was not fit on.

        `expect_fingerprint` comes from the miner state the caller intends to
        score with. Omitting it is for inspection only -- scoring across a
        renumbered vocabulary is the failure this check exists to stop.
        """
        payload = json.loads(Path(path).read_text())
        stored_version = payload.get("format_version")
        if stored_version != cls.FORMAT_VERSION:
            raise ValueError(
                f"sequence model was written in format {stored_version}, this code "
                f"reads {cls.FORMAT_VERSION}. Refit rather than guessing.")

        stored_fingerprint = payload.get("vocabulary_fingerprint")
        if expect_fingerprint is not None and stored_fingerprint != expect_fingerprint:
            raise ValueError(
                f"sequence model was fit on template vocabulary "
                f"'{stored_fingerprint}' but the miner in use is "
                f"'{expect_fingerprint}'. Cluster IDs are only meaningful "
                "relative to the miner that assigned them, so every transition "
                "would be looked up under the wrong template.")

        model = cls(alpha=payload["alpha"], keys=tuple(payload["keys"]))
        model.vocabulary = set(payload["vocabulary"])
        model.fingerprint = stored_fingerprint
        model.fitted_rows = payload.get("fitted_rows", 0)
        model.routine_threshold = payload.get("routine_threshold")
        model.rare_threshold = payload.get("rare_threshold")
        model.transitions = {
            key_col: {
                key_value: {_split_pair(k): n for k, n in counts.items()}
                for key_value, counts in by_value.items()
            }
            for key_col, by_value in payload["transitions"].items()
        }
        model.prefixes = {
            key_col: {
                key_value: {int(p): n for p, n in prefixes.items()}
                for key_value, prefixes in by_value.items()
            }
            for key_col, by_value in payload["prefixes"].items()
        }
        model.global_transitions = {_split_pair(k): n
                                    for k, n in payload["global_transitions"].items()}
        model.global_prefixes = {int(p): n for p, n in payload["global_prefixes"].items()}
        return model


def _split_pair(key: str) -> tuple[int, int]:
    prev_id, curr_id = key.split(">")
    return int(prev_id), int(curr_id)
