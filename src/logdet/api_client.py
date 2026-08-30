"""
api_client.py
A thin HTTP client for the detector service, used by the dashboard.

Why this is a module and not five `requests.get` calls inside `dashboard.py`.
A Streamlit script runs top to bottom on every interaction and cannot be
imported without executing, so anything living in it is untestable by
construction -- and the part of the dashboard most likely to break is not the
layout, it is what happens when the service is down, still starting, or
answering with an error body. Those paths are asserted in `tests/test_api_client.py`
against a stub transport, with no server and no Streamlit involved.

The client deliberately does no ranking, filtering or severity logic. The
service already ranks with `triage.triage_key` and the dashboard filters with
the same module, so a third opinion here would be a third thing to drift.
"""

from typing import Any

import requests

from logdet.config import API_HOST, API_PORT

DEFAULT_BASE_URL = f"http://{API_HOST}:{API_PORT}"
DEFAULT_TIMEOUT = 5.0
# Narration runs an LLM: ~5s per incident on the dev-box GPU and ~24s on its
# CPU (CLAUDE.md 3), so the ordinary read timeout would abort a request that is
# working perfectly well.
NARRATE_TIMEOUT = 300.0


class ApiError(RuntimeError):
    """The service could not be reached, or answered with an error.

    One exception type for both because the dashboard's response is the same in
    either case: say what happened and offer the file fallback. The message
    carries the distinction for whoever is reading it.
    """


class ApiClient:
    """Talks to one `logdet-api` instance.

    `session` is injectable so tests can drive every branch -- connection
    refused, a 404, a 503 from a missing Ollama -- without a server.
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, session=None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout

    # -- plumbing ------------------------------------------------------------

    def _request(self, method: str, path: str, timeout: float | None = None,
                 **kwargs) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method, url, timeout=timeout or self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise ApiError(f"cannot reach {url}: {exc}") from exc

        if response.status_code >= 400:
            raise ApiError(f"{method} {path} -> {response.status_code}: "
                           f"{_detail(response)}")
        try:
            return response.json()
        except ValueError as exc:
            raise ApiError(f"{method} {path} returned non-JSON: {exc}") from exc

    # -- endpoints -----------------------------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/health")

    def status(self) -> dict:
        return self._request("GET", "/stream/status")

    def incidents(self, limit: int = 10000, offset: int = 0,
                  notable: bool = False) -> list[dict]:
        """The incident list, already ranked by the service.

        `limit` defaults to the service's maximum rather than its default of
        100: the dashboard's own counters ("94 incidents, 19 notable") are
        wrong if the page is holding a truncated page of them, and a truncation
        that only shows up in a headline number is the kind of quiet error this
        project keeps finding.
        """
        payload = self._request("GET", "/incidents", params={
            "limit": limit, "offset": offset, "notable": str(notable).lower()})
        return payload.get("incidents", [])

    def incident(self, incident_id: int) -> dict:
        return self._request("GET", f"/incidents/{incident_id}")

    def narrate(self, incident_id: int) -> dict:
        return self._request("POST", f"/incidents/{incident_id}/narrate",
                             timeout=NARRATE_TIMEOUT)

    def start_stream(self, **payload) -> dict:
        return self._request("POST", "/stream/start", json=payload)

    def stop_stream(self) -> dict:
        return self._request("POST", "/stream/stop", timeout=30.0)


def _detail(response) -> str:
    """FastAPI puts the reason in a JSON `detail`; anything else is text."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:200]
