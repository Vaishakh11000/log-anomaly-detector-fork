"""
The bake-off grid page runs, and the cells fire what they say they fire.

The failure this file exists to catch is a demo page that only breaks when it
is opened, in front of whoever is watching. Assertions are deliberately thin --
widget layout is not worth pinning -- except for the two things that would
misrepresent a measurement: which cell a button fires, and that the page never
opens a stream against a Wazuh container that is not answering.

No server, no container, no detector: the API client, the session factory and
the container probe are all stubbed.
"""

import pytest

from streamlit.testing.v1 import AppTest

from logdet.config import PROJECT_ROOT
from logdet_eval import bakeoff

PAGE = str(PROJECT_ROOT / "src" / "logdet_eval" / "bakeoff_dashboard.py")

STATUS = {"running": True, "source": "data/live/bakeoff.log", "lines_seen": 40,
          "lines_parsed": 40, "incidents_total": 2, "incidents_open": 0,
          "dropped_events": 0, "seconds_since_last_batch": 1.0, "error": None}


class StubClient:
    def __init__(self, *args, **kwargs):
        pass

    def incidents(self, **kwargs):
        return [{"incident_id": 1}]

    def status(self):
        return dict(STATUS)

    def start_stream(self, **payload):
        return {"started": True}

    def stop_stream(self):
        return {"stopped": True}


class StubRunner:
    """Records what the grid asked for, without writing or scoring anything."""

    def __init__(self, *args, **kwargs):
        self.fired: list[tuple] = []
        self.results: list[dict] = []
        self.session = bakeoff.Session(fanout=bakeoff.Fanout([bakeoff.ListSink()]))
        self.background = bakeoff.BackgroundTraffic(self.session, 0.0)
        self.closed = False

    def fire(self, attack, level, seed=1, repeat=None):
        self.fired.append((attack, level, seed, repeat))
        return True

    def state(self):
        return {"busy": False, "attack": None, "level": None, "instance": 0,
                "repeat": 1, "error": None, "results": len(self.results)}

    def close(self):
        self.closed = True


@pytest.fixture
def stubbed(monkeypatch):
    """A page with every side effect replaced: no HTTP, no docker, no log file."""
    runners: list[StubRunner] = []

    def make_runner(*args, **kwargs):
        runner = StubRunner()
        runners.append(runner)
        return runner

    monkeypatch.setattr("logdet.api_client.ApiClient", StubClient)
    monkeypatch.setattr(bakeoff, "GridRunner", make_runner)
    monkeypatch.setattr(bakeoff, "open_session", lambda *a, **kw: bakeoff.Session(
        fanout=bakeoff.Fanout([bakeoff.ListSink()])))
    monkeypatch.setattr(bakeoff, "build_readers",
                        lambda client, container: bakeoff.Readers(incidents=lambda: []))
    monkeypatch.setattr("logdet_eval.wazuh_runner.container_available", lambda c: True)
    monkeypatch.setattr("logdet_eval.paced_replay.reset_correlation_state",
                        lambda *a, **kw: None)
    return runners


def open_stream(runners) -> AppTest:
    at = AppTest.from_file(PAGE, default_timeout=30).run()
    at.button[0].click().run()          # "Open the stream"
    assert not at.exception
    return at


def test_the_page_renders_before_any_stream_is_open(stubbed):
    at = AppTest.from_file(PAGE, default_timeout=30).run()
    assert not at.exception
    assert any("Open the stream" in str(i.value) for i in at.info)


def test_opening_the_stream_shows_the_whole_grid(stubbed):
    at = open_stream(stubbed)
    keys = {button.key for button in at.button if button.key}
    for attack in bakeoff.ATTACKS:
        for level in bakeoff.LEVELS:
            assert f"fire-{attack}-{level}" in keys


def test_a_cell_fires_the_attack_and_level_it_is_labelled_with(stubbed):
    """The examiner picks the condition; a button wired to the wrong cell would
    make the whole demo a claim about something nobody chose."""
    at = open_stream(stubbed)
    at.button(key="fire-enumeration-rephrase").click().run()
    assert not at.exception
    assert stubbed[0].fired[0][:2] == ("enumeration", "rephrase")


def test_the_grid_refuses_to_open_without_wazuh(stubbed, monkeypatch):
    """Refusing beats degrading: a one-contestant table still looks like a
    comparison (CLAUDE.md Known Issues)."""
    monkeypatch.setattr("logdet_eval.wazuh_runner.container_available", lambda c: False)
    at = AppTest.from_file(PAGE, default_timeout=30).run()
    at.button[0].click().run()
    assert not at.exception
    assert any("not answering" in str(e.value) for e in at.error)
    assert not stubbed


def test_the_timing_levels_are_marked_as_illustration(stubbed):
    at = open_stream(stubbed)
    body = " ".join(str(m.value) for m in at.markdown) + \
        " ".join(str(c.value) for c in at.caption)
    assert "illustration" in body
    assert "killpoint_paced_ambient0.05.md" in body


def test_the_page_states_the_resolution_of_its_own_differential(stubbed):
    """A live figure at n instances moves in 100/n point steps. The page says so
    where the reader sets n, so nobody reads it as a pooled kill-point number."""
    at = AppTest.from_file(PAGE, default_timeout=30).run()
    text = " ".join(str(c.value) for c in at.sidebar.caption)
    assert "33pt" in text          # the default of 3 instances
    assert ">=5 seeds" in text
