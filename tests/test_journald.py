"""Tests for journald ingestion.

None of these touch a real journal: `JournaldSource` takes an injected chunk
reader, so the parsing, cursor and partial-line behaviour are all exercised on
fabricated `journalctl -o json` output. That is deliberate -- CI has no
systemd journal, and the parts worth testing are ours, not journald's.
"""

import json

import pytest

from logdet.journald import (
    AUTHPRIV_FACILITY,
    CursorStore,
    JournaldSource,
    build_argv,
    filter_key,
    format_entry,
)
from logdet.preprocessing import parse_line


def entry(message="Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
          cursor="s=abc;i=1", ts=1788080573626100, host="archlinux",
          identifier="sshd", pid="4242", **extra):
    payload = {
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": str(ts),
        "_HOSTNAME": host,
        "SYSLOG_IDENTIFIER": identifier,
        "_PID": pid,
        "MESSAGE": message,
    }
    payload.update(extra)
    return payload


def feed(*entries, trailing_newline=True):
    """One journalctl stdout chunk: newline-delimited JSON."""
    text = "".join(json.dumps(e) + "\n" for e in entries)
    if not trailing_newline:
        text = text.rstrip("\n")
    return text.encode()


def source_from(chunks, **kwargs):
    remaining = list(chunks)
    kwargs.setdefault("follow", True)
    return JournaldSource(chunk_reader=lambda: remaining.pop(0) if remaining else b"",
                          **kwargs)


# --- formatting -----------------------------------------------------------

def test_a_journal_entry_becomes_a_line_the_parser_accepts():
    line = format_entry(entry())
    assert parse_line(line) is not None


def test_the_rebuilt_line_carries_the_fields_the_pipeline_needs():
    parsed = parse_line(format_entry(entry()))
    assert parsed["host"] == "archlinux"
    assert parsed["process"] == "sshd"
    assert parsed["message"].startswith("Failed password")


def test_the_timestamp_comes_from_the_journal_not_the_clock():
    # 1788080573 = 2026-08-30 14:32:53 local
    line = format_entry(entry(ts=1788080573000000))
    assert " 14:32:53 " in line


def test_a_single_digit_day_is_space_padded_like_syslog():
    # 2026-08-05 00:00:00 local, expressed in UTC microseconds is fragile, so
    # assert the shape instead: syslog pads the day, and the parser needs that.
    line = format_entry(entry(ts=1786000000000000))
    assert parse_line(line) is not None


def test_an_entry_with_no_message_is_dropped():
    assert format_entry(entry(message="")) is None


def test_an_entry_with_no_timestamp_is_dropped():
    bad = entry()
    del bad["__REALTIME_TIMESTAMP"]
    assert format_entry(bad) is None


def test_a_byte_array_message_is_decoded():
    payload = entry(message=[104, 105])
    assert format_entry(payload).endswith("hi")


def test_an_entry_with_no_pid_still_parses():
    payload = entry(pid=None)
    del payload["_PID"]
    line = format_entry(payload)
    assert "[" not in line.split(": ")[0]
    assert parse_line(line) is not None


# --- the journalctl invocation --------------------------------------------

def test_the_default_filter_is_the_authpriv_facility():
    assert f"SYSLOG_FACILITY={AUTHPRIV_FACILITY}" in build_argv()


def test_a_unit_filter_replaces_the_facility_filter():
    argv = build_argv(unit="sshd", facility=None)
    assert "-u" in argv and "sshd" in argv
    assert not any(a.startswith("SYSLOG_FACILITY") for a in argv)


def test_json_output_is_always_requested():
    # The cursor only exists in the JSON form, and the cursor is the resume token.
    argv = build_argv()
    assert argv[argv.index("-o") + 1] == "json"


def test_follow_mode_replays_no_history_when_there_is_no_cursor():
    # Measured: `--since now` does NOT restrict journalctl to new entries -- it
    # returns the whole journal, so following a fresh box would re-alert on
    # every historical line. `-n 0` is the primitive that actually does it.
    argv = build_argv(follow=True)
    assert argv[argv.index("-n") + 1] == "0"
    assert "--since" not in argv


def test_an_explicit_since_wins_over_the_no_history_default():
    argv = build_argv(follow=True, since="-1h")
    assert argv[argv.index("--since") + 1] == "-1h"
    assert "-n" not in argv


def test_a_cursor_wins_over_since():
    argv = build_argv(follow=True, since="-1h", after_cursor="s=abc;i=9")
    assert "--after-cursor" in argv
    assert "--since" not in argv


def test_one_shot_mode_does_not_follow():
    assert "-f" not in build_argv(follow=False, since="-1h")


# --- reading --------------------------------------------------------------

def test_entries_arrive_as_parsable_lines():
    source = source_from([feed(entry(), entry(cursor="s=abc;i=2"))])
    lines = source.read_lines()
    assert len(lines) == 2
    assert all(parse_line(line) for line in lines)


def test_a_partial_entry_is_held_until_its_newline_arrives():
    whole = feed(entry()).decode()
    head, tail = whole[:20], whole[20:]
    source = source_from([head.encode(), tail.encode()])

    assert source.read_lines() == []          # half an entry is not a line
    assert len(source.read_lines()) == 1


def test_unparsable_json_is_skipped_without_stopping_the_stream():
    source = source_from([b'{not json}\n' + feed(entry())])
    assert len(source.read_lines()) == 1


def test_nothing_to_read_returns_no_lines():
    assert source_from([]).read_lines() == []


def test_one_shot_mode_ends_at_end_of_output():
    source = source_from([feed(entry()), b""], follow=False)
    assert len(source.read_lines()) == 1
    assert source.read_lines() == []
    assert source.read_lines() == []          # stays ended


# --- the cursor -----------------------------------------------------------

def test_the_cursor_is_only_written_on_commit(tmp_path):
    store = CursorStore(tmp_path / "cursor.json")
    source = source_from([feed(entry(cursor="s=abc;i=7"))], cursor_store=store)
    source.read_lines()

    # Reading is not scoring. A crash here must replay the batch, not skip it.
    assert store.cursor_for(filter_key(None, AUTHPRIV_FACILITY)) is None
    source.commit()
    assert store.cursor_for(filter_key(None, AUTHPRIV_FACILITY)) == "s=abc;i=7"


def test_commit_records_the_last_entry_of_the_batch(tmp_path):
    store = CursorStore(tmp_path / "cursor.json")
    source = source_from([feed(entry(cursor="s=abc;i=1"),
                               entry(cursor="s=abc;i=2"),
                               entry(cursor="s=abc;i=3"))], cursor_store=store)
    source.read_lines()
    source.commit()
    assert store.cursor_for(filter_key(None, AUTHPRIV_FACILITY)) == "s=abc;i=3"


def test_a_restart_resumes_after_the_committed_cursor(tmp_path):
    store = CursorStore(tmp_path / "cursor.json")
    store.save(filter_key(None, AUTHPRIV_FACILITY), "s=abc;i=42")

    argv = build_argv(after_cursor=store.cursor_for(filter_key(None, AUTHPRIV_FACILITY)))
    assert argv[argv.index("--after-cursor") + 1] == "s=abc;i=42"


def test_a_cursor_from_another_filter_is_not_reused(tmp_path):
    # A cursor taken while following sshd says nothing about where authpriv got
    # to; resuming from it would skip everything in between.
    store = CursorStore(tmp_path / "cursor.json")
    store.save(filter_key("sshd", None), "s=abc;i=42")
    assert store.cursor_for(filter_key(None, AUTHPRIV_FACILITY)) is None


def test_a_corrupt_cursor_file_does_not_stop_ingestion(tmp_path):
    path = tmp_path / "cursor.json"
    path.write_text("{ this is not json")
    assert CursorStore(path).cursor_for("anything") is None


def test_commit_without_a_store_is_harmless():
    source = source_from([feed(entry())])
    source.read_lines()
    source.commit()   # no store configured -- must not raise


# --- end to end through the stream loop -----------------------------------

def test_the_stream_loop_scores_journal_entries(monkeypatch):
    """A journald source drives `run_stream` exactly like a file source does."""
    from logdet import stream

    seen = []

    class FakeProcessor:
        lines_seen = 0
        lines_parsed = 0

        def process(self, lines):
            seen.extend(lines)
            return []

        def drain(self):
            return []

    source = source_from([feed(entry(), entry(cursor="s=abc;i=2")), b""],
                         follow=False)
    stream.run_stream(source, FakeProcessor(), once=True,
                      batcher=stream.MicroBatcher(max_lines=1))
    assert len(seen) == 2
