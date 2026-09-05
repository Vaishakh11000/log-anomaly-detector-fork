"""
The nginx/Apache access-log source lands on the same internal columns as syslog.

The claim this module makes is that a second format needs no new detection
path: it maps into ECS and comes back out as the eight columns the pipeline
already scores. So the tests check the mapping, the ECS round trip, and the two
places a second source can silently corrupt a corpus -- timezone-aware
timestamps mixed with naive ones, and a template vocabulary that differs by
format. Nothing here touches detection; weblog.py reads no detection code.
"""

from datetime import datetime

import pandas as pd
import pytest

from logdet import ecs
from logdet import weblog
from logdet.entity_graph import normalise_identity
from logdet.preprocessing import LineParser
from logdet.templating import TemplateMiner

COMBINED = ('192.168.1.50 - admin [18/Jul/2026:10:22:31 +0000] '
            '"GET /admin/index.php HTTP/1.1" 200 2326 '
            '"http://example.com/" "Mozilla/5.0"')

DENIED = ('10.0.0.9 - - [18/Jul/2026:10:22:35 +0000] '
          '"POST /wp-login.php HTTP/1.1" 401 190 "-" "curl/8.5.0"')

COMMON = '203.0.113.7 - - [18/Jul/2026:10:23:00 +0000] "GET / HTTP/1.0" 200 12'


# --- the format itself ------------------------------------------------------

def test_combined_line_maps_to_ecs():
    doc = weblog.parse_line(COMBINED, host="web1")
    assert doc["@timestamp"] == "2026-07-18T10:22:31"
    assert doc["source"]["ip"] == "192.168.1.50"
    assert doc["user"]["name"] == "admin"
    assert doc["host"]["name"] == "web1"
    assert doc["process"]["name"] == "nginx"
    assert doc["http"]["request"]["method"] == "GET"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["http"]["response"]["body"]["bytes"] == 2326
    assert doc["url"]["path"] == "/admin/index.php"
    assert doc["user_agent"]["original"] == "Mozilla/5.0"
    assert doc["event"]["original"] == COMBINED


def test_common_log_format_parses_without_referrer_and_agent():
    """One pattern covers `combined` and `common`; the optional tail is optional."""
    doc = weblog.parse_line(COMMON)
    assert doc["source"]["ip"] == "203.0.113.7"
    assert doc["http"]["response"]["status_code"] == 200
    assert "user_agent" not in doc          # pruned, not emitted empty


def test_dash_fields_are_absent_not_the_string_dash():
    """`-` is how an access log writes 'no value'. It is not a username, and a
    consumer must not be handed one."""
    doc = weblog.parse_line(DENIED)
    assert "user" not in doc
    assert "referrer" not in doc.get("http", {}).get("request", {})


def test_unparseable_line_returns_none():
    assert weblog.parse_line("this is not an access log line") is None


def test_malformed_request_is_kept_whole_not_dropped():
    """Scanner and exploit traffic is exactly what fails to parse as a request
    line, so it must survive into the corpus rather than being discarded."""
    line = ('10.0.0.9 - - [18/Jul/2026:10:22:35 +0000] '
            '"\\x16\\x03\\x01" 400 150 "-" "-"')
    doc = weblog.parse_line(line)
    assert doc is not None
    assert doc["url"]["original"] == "\\x16\\x03\\x01"
    assert "method" not in doc["http"].get("request", {})
    assert doc["event"]["outcome"] == "failure"


# --- categorization ---------------------------------------------------------

@pytest.mark.parametrize("status, outcome", [
    (200, "success"), (301, "success"), (404, "failure"), (500, "failure"),
])
def test_outcome_follows_the_status_code(status, outcome):
    assert weblog.categorize_http(status)["outcome"] == outcome


@pytest.mark.parametrize("status", [401, 403])
def test_denied_requests_are_categorized_as_authentication(status):
    """401/403 are authentication events, which is what lets a web line be
    compared with an sshd auth line as the same kind of thing."""
    assert "authentication" in weblog.categorize_http(status)["category"]


def test_message_carries_the_status_name_because_masking_eats_the_number():
    """`template_message` masks every bare number, so a message ending 401 and
    one ending 200 would template identically -- and the status is the whole
    signal on a web line."""
    ok = weblog.WebLogParser().parse(COMBINED)
    denied = weblog.WebLogParser().parse(DENIED)
    assert "OK" in ok["message"]
    assert "Unauthorized" in denied["message"]
    assert ok["template"] != denied["template"]


# --- internal record --------------------------------------------------------

def test_parse_produces_the_pipeline_columns():
    record = weblog.WebLogParser(host="web1").parse(COMBINED)
    for column in ("timestamp", "host", "process", "message", "raw",
                   "user", "source_ip", "template"):
        assert column in record
    assert record["user"] == "admin"
    assert record["source_ip"] == "192.168.1.50"
    assert record["template"].startswith("GET /admin/index.php")


def test_absent_user_becomes_the_same_placeholder_syslog_uses():
    """An access log has no user on nearly every line. It must reach the same
    `unknown` the syslog parser produces, so `normalise_identity` refuses to
    join on it -- an absent identity must never become a shared one."""
    record = weblog.WebLogParser().parse(DENIED)
    assert record["user"] == "unknown"
    assert normalise_identity(record["user"]) is None


def test_columns_match_the_syslog_parsers_columns():
    """The two sources produce the same schema -- the same keys, `pid` included
    and empty -- which is why nothing downstream had to change to read a web
    corpus. A column present in one frame and absent in the other would make the
    two corpora concatenate into a ragged frame."""
    syslog_record = LineParser(year=2026).parse(
        "Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin "
        "from 192.168.1.5 port 51422 ssh2")
    web_record = weblog.WebLogParser(host="web1").parse(COMBINED)
    assert set(web_record) == set(syslog_record)
    assert web_record["pid"] is None


# --- timestamps -------------------------------------------------------------

def test_timestamp_is_naive_and_converted_to_utc():
    """Mixing an aware and a naive timestamp in one frame makes pandas raise on
    every window comparison in the pipeline -- grouping, impossible travel,
    sequence ordering. The offset is resolved, not carried."""
    record = weblog.WebLogParser().parse(
        '1.2.3.4 - - [18/Jul/2026:12:22:31 +0200] "GET / HTTP/1.1" 200 5')
    stamp = datetime.fromisoformat(record["timestamp"])
    assert stamp.tzinfo is None
    assert stamp == datetime(2026, 7, 18, 10, 22, 31)


def test_keep_local_time_keeps_the_wall_clock():
    record = weblog.WebLogParser(keep_local_time=True).parse(
        '1.2.3.4 - - [18/Jul/2026:12:22:31 +0200] "GET / HTTP/1.1" 200 5')
    assert datetime.fromisoformat(record["timestamp"]) == datetime(2026, 7, 18, 12, 22, 31)


def test_web_and_syslog_timestamps_are_comparable_in_one_frame():
    """The prerequisite for correlating two sources: one clock, one dtype."""
    syslog_record = LineParser(year=2026).parse(
        "Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin "
        "from 192.168.1.5 port 51422 ssh2")
    web_record = weblog.WebLogParser(host="web1").parse(COMBINED)
    frame = pd.DataFrame([syslog_record, web_record])
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    assert frame["timestamp"].dt.tz is None
    # The comparison that every window in the pipeline performs.
    assert (frame["timestamp"].max() - frame["timestamp"].min()).total_seconds() == 0


# --- the ECS boundary -------------------------------------------------------

def test_the_record_comes_through_ecs_not_around_it():
    """The document the parser produced maps to exactly the record it returned,
    so ECS is genuinely the path and not decoration beside it."""
    parser = weblog.WebLogParser(host="web1")
    record, doc = parser.parse_with_ecs(COMBINED)
    from_doc = ecs.ecs_to_record(doc)
    for key, value in from_doc.items():
        assert record[key] == value


def test_ecs_documents_are_strict_json():
    docs = [weblog.parse_line(line) for line in (COMBINED, DENIED, COMMON)]
    import json
    for line in ecs.to_ndjson(docs).splitlines():
        json.loads(line)                       # raises on NaN or a stray None


# --- template mining across sources -----------------------------------------

def test_a_shared_miner_gives_both_sources_one_vocabulary():
    """Cluster ids mean nothing across two independent miners, so a multi-source
    corpus has to be mined by one."""
    miner = TemplateMiner()
    web = weblog.WebLogParser(miner=miner)
    syslog = LineParser(year=2026, miner=miner)
    web_record = web.parse(COMBINED)
    syslog_record = syslog.parse(
        "Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin "
        "from 192.168.1.5 port 51422 ssh2")
    assert web_record["template_id"] != syslog_record["template_id"]
    assert miner.cluster_count == 2


# --- file level -------------------------------------------------------------

def test_preprocess_web_file_writes_the_parsed_csv(tmp_path):
    source = tmp_path / "access.log"
    source.write_text("\n".join([COMBINED, DENIED, "garbage", COMMON]) + "\n")
    out = tmp_path / "parsed.csv"
    ecs_out = tmp_path / "events.ndjson"

    frame = weblog.preprocess_web_file(str(source), str(out), host="web1",
                                       ecs_output_path=str(ecs_out))

    assert len(frame) == 3                     # the garbage line is dropped
    reread = pd.read_csv(out)
    assert list(reread["source_ip"]) == ["192.168.1.50", "10.0.0.9", "203.0.113.7"]
    assert len(ecs_out.read_text().strip().splitlines()) == 3
