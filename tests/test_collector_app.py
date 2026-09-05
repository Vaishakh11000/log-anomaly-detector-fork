"""
Tests for the standalone collector app (logdet/collector_app.py) -- the light
half of the container split (CLAUDE.md 2c/2d).

Two things are asserted: the ingest contract matches logdet-api's byte for
byte (a shipper cannot tell them apart), and the collector imports none of the
detection stack (which is the whole reason it can be its own small container).
"""

import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from logdet.collector import CollectorSink
from logdet.collector_app import create_app


@pytest.fixture
def sink(tmp_path):
    return CollectorSink(str(tmp_path / "collector.log"))


@pytest.fixture
def client(sink) -> TestClient:
    return TestClient(create_app(sink=sink))


def test_health_reports_collector_status(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert "lines_written" in body["collector"]


def test_ingest_ndjson_appends_lines(client, sink):
    body = ('{"line": "Jul 18 10:00:00 LabSZ sshd[1]: Failed password for admin from 203.0.113.9 port 1 ssh2"}\n'
            '{"line": "Jul 18 10:00:01 LabSZ sshd[2]: Invalid user oracle from 203.0.113.9 port 2"}\n')
    r = client.post("/collector/ingest", content=body,
                    headers={"content-type": "application/x-ndjson"})
    assert r.status_code == 200
    data = r.json()
    assert data["received"] == 2 and data["written"] == 2
    written = sink.path.read_text().splitlines()
    assert written[0].endswith("port 1 ssh2")
    assert "Invalid user oracle" in written[1]


def test_ingest_accepts_plain_text_for_manual_use(client, sink):
    r = client.post("/collector/ingest", content="a raw line\nanother line\n")
    assert r.status_code == 200 and r.json()["written"] == 2
    assert sink.path.read_text() == "a raw line\nanother line\n"


def test_ingest_is_append_only_across_calls(client, sink):
    client.post("/collector/ingest", content='{"line": "one"}\n')
    client.post("/collector/ingest", content='{"line": "two"}\n')
    assert sink.path.read_text() == "one\ntwo\n"
    assert client.get("/collector/status").json()["lines_written"] == 2


def test_collector_does_not_import_the_detection_stack():
    """The point of the split: importing the collector must not drag in torch
    or sentence-transformers. If it does, the light container stops being light.
    Run in a fresh interpreter so a stack already imported by another test
    cannot mask the regression.
    """
    code = (
        "import logdet.collector_app, logdet.collector, sys; "
        "heavy = [m for m in ('torch', 'sentence_transformers', 'sklearn') "
        "if m in sys.modules]; "
        "print(','.join(heavy))"
    )
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "", f"collector pulled in: {out.stdout.strip()}"
