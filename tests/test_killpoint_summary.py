"""Tests for the merged eight-strategy view.

This module exists to stop a summary quietly becoming more flattering than the
measurement, so what is pinned here is mostly about *not losing the losses*:
that timing-dependent strategies come from the instrument that can measure
them, that ties are counted and ordered as ties, and that the win/loss tally
matches the rows.
"""

import pytest

from logdet_eval.killpoint_summary import CONTINUE_BAR, merge, render, tally


def _row(ours: float, siem: float) -> dict:
    return {"ours_drop": ours, "siem_drop": siem, "differential": siem - ours}


def _batch(**strategies) -> dict:
    return {"comparison": {"per_strategy": strategies}}


def _paced(**strategies) -> dict:
    return {"max_events_per_ip": 12, "comparison": {"per_strategy": strategies}}


class TestMerge:
    def test_timing_strategies_come_from_the_paced_instrument(self):
        """Batch rows for these are artefacts -- Wazuh's drop there is 0pt by
        construction -- so they must be replaced, not averaged in."""
        rows = merge(
            _batch(slow=_row(11.1, 0.0), rephrase=_row(2.2, 33.3)),
            _paced(slow=_row(8.9, 0.0)),
        )
        assert rows["slow"]["instrument"] == "paced"
        assert rows["slow"]["ours_drop"] == 8.9

    def test_timing_independent_strategies_come_from_batch(self):
        rows = merge(_batch(rephrase=_row(2.2, 33.3)), _paced())
        assert rows["rephrase"]["instrument"] == "batch"

    def test_every_strategy_survives_the_merge(self):
        rows = merge(
            _batch(rephrase=_row(2.2, 33.3), mimicry=_row(0.0, 0.0),
                   ip_rotate=_row(11.1, 0.0), slow=_row(11.1, 0.0)),
            _paced(slow=_row(8.9, 0.0), temporal=_row(0.0, 0.0)),
        )
        assert set(rows) == {"rephrase", "mimicry", "ip_rotate", "slow", "temporal"}


class TestTally:
    def test_counts_wins_ties_and_losses(self):
        rows = merge(
            _batch(rephrase=_row(2.2, 33.3), mimicry=_row(0.0, 0.0),
                   ip_rotate=_row(11.1, 0.0)),
            _paced(slow=_row(8.9, 0.0), temporal=_row(0.0, 0.0)),
        )
        counts = tally(rows)
        assert counts["wins"] == ["rephrase"]
        assert counts["ties"] == ["mimicry", "temporal"]
        assert counts["losses"] == ["ip_rotate", "slow"]

    def test_a_zero_differential_is_a_tie_not_a_loss(self):
        """`0.0 or -999` is -999 in Python. That bug once sorted every tie
        below every loss, which reads as a worse result than was measured."""
        counts = tally(merge(_batch(mimicry=_row(0.0, 0.0)), _paced()))
        assert counts["ties"] == ["mimicry"]
        assert counts["losses"] == []
        assert counts["best_differential"] == 0.0

    def test_only_differentials_at_or_above_the_bar_are_credited(self):
        rows = merge(_batch(rephrase=_row(2.2, 27.2), mimicry=_row(0.0, 0.0)), _paced())
        assert tally(rows)["clears_registered_bar"] == ["rephrase"]

    def test_the_registered_bar_is_the_one_in_section_1b(self):
        assert CONTINUE_BAR == 25.0

    def test_verdict_comes_from_the_best_differential(self):
        rows = merge(_batch(rephrase=_row(2.2, 33.3), ip_rotate=_row(11.1, 0.0)), _paced())
        assert tally(rows)["verdict"] == "CONTINUE"

    def test_all_losses_is_a_stop(self):
        rows = merge(_batch(ip_rotate=_row(11.1, 0.0)), _paced(slow=_row(8.9, 0.0)))
        assert tally(rows)["verdict"] == "STOP"


class TestRender:
    def _rendered(self) -> str:
        rows = merge(
            _batch(rephrase=_row(2.2, 33.3), mimicry=_row(0.0, 0.0),
                   ip_rotate=_row(11.1, 0.0)),
            _paced(slow=_row(8.9, 0.0), **{"realistic-combo": _row(13.3, 0.0)}),
        )
        return render(rows, tally(rows), _batch(), _paced())

    def test_ties_are_ordered_above_losses(self):
        text = self._rendered()
        assert text.index("| mimicry ") < text.index("| ip_rotate ")

    def test_the_losses_are_named_in_the_prose(self):
        """A summary that reports the tally but not which strategies lost is the
        failure mode this module exists to prevent."""
        text = self._rendered()
        assert "realistic-combo" in text
        assert "ip_rotate" in text

    def test_the_unsupportable_claim_is_stated_as_unsupportable(self):
        assert "Not supportable" in self._rendered()

    def test_both_instruments_are_named_with_their_reason(self):
        text = self._rendered()
        assert "arrival time" in text
        assert "paced" in text and "batch" in text


class TestSweep:
    """The sensitivity view. `rephrase` is the only surviving claim, so whether
    it holds across background densities is the difference between a mechanism
    and a lucky corpus."""

    def _payloads(self) -> dict:
        return {
            "0.01": {"comparison": {"per_strategy": {
                "rephrase": {"ours_drop": 4.4, "siem_drop": 35.6,
                             "differential": 31.2, "timing_dependent": False},
                "ip_rotate": {"ours_drop": 13.3, "siem_drop": 0.0,
                              "differential": -13.3, "timing_dependent": False},
                "slow": {"ours_drop": 15.6, "siem_drop": 0.0,
                         "differential": -15.6, "timing_dependent": True},
            }}},
            "0.2": {"comparison": {"per_strategy": {
                "rephrase": {"ours_drop": 2.2, "siem_drop": 33.3,
                             "differential": 31.1, "timing_dependent": False},
                "ip_rotate": {"ours_drop": 8.9, "siem_drop": 0.0,
                              "differential": -8.9, "timing_dependent": False},
                "slow": {"ours_drop": 22.2, "siem_drop": 0.0,
                         "differential": -22.2, "timing_dependent": True},
            }}},
        }

    def test_spread_is_the_range_across_densities(self):
        from logdet_eval.killpoint_summary import sweep
        rows = sweep(self._payloads())
        assert rows["rephrase"]["spread"] == pytest.approx(0.1)
        assert rows["ip_rotate"]["spread"] == pytest.approx(4.4)

    def test_timing_dependent_rows_are_marked(self):
        """Their spread is our drop moving, not a differential moving, and
        reading it as sensitivity would be wrong in both directions."""
        from logdet_eval.killpoint_summary import sweep
        rows = sweep(self._payloads())
        assert rows["slow"]["timing_dependent"] is True
        assert rows["ip_rotate"]["timing_dependent"] is False

    def test_every_density_appears_for_every_strategy(self):
        from logdet_eval.killpoint_summary import sweep
        rows = sweep(self._payloads())
        for entry in rows.values():
            assert set(entry["by_ratio"]) == {"0.01", "0.2"}

    def test_report_warns_that_timing_rows_are_artefacts(self):
        from logdet_eval.killpoint_summary import render_sweep, sweep
        payloads = self._payloads()
        text = render_sweep(sweep(payloads), payloads)
        assert "artefacts" in text
        assert "0pt by construction" in text

    def test_report_names_the_strategy_that_moves(self):
        from logdet_eval.killpoint_summary import render_sweep, sweep
        payloads = self._payloads()
        text = render_sweep(sweep(payloads), payloads)
        assert "ip_rotate" in text
