"""
The dashboard's HTTP client: what it sends, and what it does when the service
is down or unhappy.

The layout of a Streamlit page is not worth testing; what the page does when
the detector service is missing, still starting, or answering 503 because
Ollama is not running very much is -- that is the difference between a demo
that says "start logdet-api" and one that shows a stack trace. The client is a
separate module precisely so those branches can be driven here, with no server
and no Streamlit import.
"""

import pytest
import requests

from logdet.api_client import ApiClient, ApiError


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Records requests and returns canned responses in order."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def client(*responses, base_url="http://testhost:8000") -> ApiClient:
    return ApiClient(base_url, session=FakeSession(*responses))


# --- happy paths ------------------------------------------------------------


def test_incidents_returns_the_list_inside_the_envelope():
    api = client(FakeResponse(payload={"total": 2, "incidents": [{"incident_id": 1},
                                                                 {"incident_id": 2}]}))
    assert [i["incident_id"] for i in api.incidents()] == [1, 2]


def test_incidents_asks_for_everything_not_the_default_page():
    """The dashboard's headline counts are computed over what it fetched, so a
    silently truncated page would show a wrong total rather than an error."""
    session = FakeSession(FakeResponse(payload={"incidents": []}))
    ApiClient("http://testhost:8000", session=session).incidents()
    assert session.calls[0]["params"]["limit"] == 10000


def test_notable_is_passed_as_a_lowercase_boolean():
    """FastAPI's bool query parser accepts 'true', not Python's 'True'."""
    session = FakeSession(FakeResponse(payload={"incidents": []}))
    ApiClient("http://h", session=session).incidents(notable=True)
    assert session.calls[0]["params"]["notable"] == "true"


def test_status_and_health_hit_their_endpoints():
    session = FakeSession(FakeResponse(payload={"running": True}),
                          FakeResponse(payload={"status": "ok"}))
    api = ApiClient("http://h", session=session)
    assert api.status() == {"running": True}
    assert api.health() == {"status": "ok"}
    assert [c["url"] for c in session.calls] == ["http://h/stream/status", "http://h/health"]


def test_start_stream_posts_its_payload_as_json():
    session = FakeSession(FakeResponse(payload={"running": True}))
    ApiClient("http://h", session=session).start_stream(source="file", path="/tmp/a.log")
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["json"] == {"source": "file", "path": "/tmp/a.log"}


def test_base_url_trailing_slash_does_not_produce_a_double_slash():
    session = FakeSession(FakeResponse(payload={}))
    ApiClient("http://h:8000/", session=session).status()
    assert session.calls[0]["url"] == "http://h:8000/stream/status"


def test_narrate_gets_a_long_timeout():
    """Narration is an LLM call: ~5s on the dev-box GPU, ~24s on its CPU. The
    ordinary 5s read timeout would abort a request that is working."""
    session = FakeSession(FakeResponse(payload={"narrative": "..."}))
    ApiClient("http://h", session=session).narrate(7)
    assert session.calls[0]["timeout"] >= 60


def test_narrate_asks_for_the_full_tier_unless_told_otherwise():
    session = FakeSession(FakeResponse(payload={"narrative": "..."}))
    ApiClient("http://h", session=session).narrate(7)
    assert session.calls[0]["params"] == {"tier": "full"}


def test_narrate_can_ask_for_the_cheap_tier():
    session = FakeSession(FakeResponse(payload={"triage_line": "..."}))
    ApiClient("http://h", session=session).narrate(7, tier="triage")
    assert session.calls[0]["params"] == {"tier": "triage"}


# --- failure paths ----------------------------------------------------------


def test_a_refused_connection_becomes_an_ApiError_naming_the_url():
    api = client(requests.ConnectionError("refused"))
    with pytest.raises(ApiError) as exc:
        api.status()
    assert "http://testhost:8000/stream/status" in str(exc.value)


def test_a_timeout_becomes_an_ApiError():
    api = client(requests.Timeout("too slow"))
    with pytest.raises(ApiError):
        api.incidents()


def test_an_error_status_carries_fastapis_detail_through():
    """The useful half of a 400 from /stream/start is the detail -- 'no
    detector at models/detector.joblib -- run logdet-fit first'."""
    api = client(FakeResponse(status_code=400,
                              payload={"detail": "no detector at models/detector.joblib"}))
    with pytest.raises(ApiError) as exc:
        api.start_stream(source="file")
    assert "no detector" in str(exc.value)
    assert "400" in str(exc.value)


def test_an_error_body_that_is_not_json_still_reports_something():
    api = client(FakeResponse(status_code=502, text="<html>bad gateway</html>"))
    with pytest.raises(ApiError) as exc:
        api.status()
    assert "502" in str(exc.value)


def test_a_200_that_is_not_json_is_an_error_not_a_crash():
    """A proxy or a wrong port answers 200 with HTML. Letting the ValueError
    escape would show the dashboard a raw traceback."""
    api = client(FakeResponse(status_code=200, text="hello"))
    with pytest.raises(ApiError):
        api.incidents()


def test_narrate_failure_from_a_missing_ollama_is_an_ApiError():
    api = client(FakeResponse(status_code=503,
                              payload={"detail": "narrative generation failed: refused"}))
    with pytest.raises(ApiError) as exc:
        api.narrate(3)
    assert "narrative generation failed" in str(exc.value)
