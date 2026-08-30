"""
The dashboard script runs, against the API and against a file.

Streamlit's AppTest executes the script the same way the server does and
surfaces anything it raised, which is the failure this file exists to catch: a
dashboard that only breaks when it is opened breaks in front of whoever is
watching. The assertions are deliberately thin -- widget layout is not worth
pinning, "it rendered the incident and did not throw" is.

`ApiClient` is replaced with a stub, so no server, no detector and no network
are involved. Auto-refresh only fires while a stream is running (see the foot
of dashboard.py), so a stub reporting `running: False` runs the script exactly
once and returns.
"""

import json

import pytest

from streamlit.testing.v1 import AppTest

from logdet.config import PROJECT_ROOT

DASHBOARD = str(PROJECT_ROOT / "src" / "logdet" / "dashboard.py")

INCIDENT = {
    "incident_id": 1,
    "summary": "6 events | users: root | source IPs: 10.0.0.9",
    "users": ["root"],
    "source_ips": ["10.0.0.9"],
    "start": "2026-07-14 02:14:00",
    "end": "2026-07-14 02:20:00",
    "event_count": 6,
    "severity": "high",
    "status": "closed",
    "mitre_techniques": [{"technique_id": "T1110", "technique_name": "Brute Force",
                          "tactic": "Credential Access"}],
    "events": [{"timestamp": "2026-07-14 02:14:00", "user": "root",
                "message": "Failed password for root from 10.0.0.9"}],
}

STATUS = {"running": False, "source": "data/live/demo.log", "lines_seen": 80,
          "lines_parsed": 80, "incidents_total": 1, "incidents_open": 0,
          "incidents_closed": 1, "dropped_events": 0,
          "seconds_since_last_batch": 2.0, "error": None}


class StubClient:
    def __init__(self, *args, incidents=(INCIDENT,), status=None, **kwargs):
        self._incidents = list(incidents)
        self._status = dict(status or STATUS)

    def incidents(self, **kwargs):
        return list(self._incidents)

    def status(self):
        return dict(self._status)


@pytest.fixture
def stub_api(monkeypatch):
    monkeypatch.setattr("logdet.api_client.ApiClient", StubClient)


def test_dashboard_renders_live_incidents_from_the_api(stub_api):
    at = AppTest.from_file(DASHBOARD, default_timeout=30).run()
    assert not at.exception
    body = " ".join(str(m.value) for m in at.markdown)
    assert "Showing 1 of 1 incidents" in body


def test_dashboard_shows_the_stream_health_figures(stub_api):
    at = AppTest.from_file(DASHBOARD, default_timeout=30).run()
    labels = {m.label: m.value for m in at.metric}
    assert labels["Lines seen"] == "80"
    assert labels["Lines parsed"] == "80"
    assert labels["Incidents"] == "1"


def test_an_unreachable_api_explains_itself_instead_of_crashing(monkeypatch):
    """The most likely state at demo time is the service not started yet."""
    from logdet.api_client import ApiError

    class Dead:
        def __init__(self, *a, **kw):
            pass

        def incidents(self, **kw):
            raise ApiError("cannot reach http://127.0.0.1:8000/incidents: refused")

        def status(self):
            raise ApiError("cannot reach http://127.0.0.1:8000/stream/status: refused")

    monkeypatch.setattr("logdet.api_client.ApiClient", Dead)
    at = AppTest.from_file(DASHBOARD, default_timeout=30).run()
    assert not at.exception
    assert any("Cannot read the detector service" in str(e.value) for e in at.error)


def test_the_file_source_still_works(stub_api, tmp_path):
    """`incidents.json` from a finished batch run is the path every number in
    results/ came from, so it stays a first-class source."""
    path = tmp_path / "incidents.json"
    path.write_text(json.dumps([INCIDENT]))

    at = AppTest.from_file(DASHBOARD, default_timeout=30)
    at.run()
    at.sidebar.radio[0].set_value("Incidents file").run()
    at.sidebar.text_input[0].set_value(str(path)).run()
    assert not at.exception
    body = " ".join(str(m.value) for m in at.markdown)
    assert "Showing 1 of 1 incidents" in body


def test_a_missing_incidents_file_warns_rather_than_raising(stub_api, tmp_path):
    at = AppTest.from_file(DASHBOARD, default_timeout=30)
    at.run()
    at.sidebar.radio[0].set_value("Incidents file").run()
    at.sidebar.text_input[0].set_value(str(tmp_path / "nope.json")).run()
    assert not at.exception
    assert any("No incidents file found" in str(w.value) for w in at.warning)
