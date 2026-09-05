"""
weblog.py
A second source format -- nginx/Apache access logs -- parsed into ECS and then
onto the internal columns the pipeline already scores (Stage 7).

Why this exists
---------------
Until now every line the detector has seen came from one grammar: syslog auth
lines, parsed by `preprocessing.LineParser`. "Multi-source" cannot be
demonstrated, let alone measured, with one source. `ecs.py` established ECS as
the *boundary* format and gave the ingestion direction a target
(`ecs.ecs_to_record`); this module is the first thing to aim at it.

The path a web line takes is deliberately the long way round:

    raw access-log line
        -> parse_line()        an ECS document (source.ip, url.*, http.*, user.*)
        -> ecs.ecs_to_record() the internal columns (user, source_ip, host, ...)
        -> template_message()  the masked text the embedder sees
        -> the same detection path as an sshd line

It would be shorter to build the internal record directly and skip ECS. Going
through ECS is the point: it proves the boundary carries a format it was not
written for, and it means the next source needs no new code at all if it already
speaks ECS. Nothing in detection changed to accept these records -- they are the
same eight columns, so grouping, the entity graph, the sequence model and
scoring read them unchanged.

What is not here, and why
-------------------------
*The nginx **error** log is not parsed.* The access log is where the events with
identities live -- a source IP on every line, an authenticated user where there
is one, and 401/403 as an explicit authentication outcome. The error log has a
different grammar, usually no user, and its lines are mostly about the server
rather than about a client, so it would add parse surface without adding
anything a detector or a correlation can key on.

*Nothing is invented to fill a field.* An access log carries no hostname, so
`host` comes from `--host` and defaults to the literal `unknown` rather than to
a guess; `remote_user` is `-` on nearly every line, and that maps to the same
`unknown` placeholder `extract_user` already returns for a syslog line with no
user in it, which `entity_graph.normalise_identity` then refuses to join on.

The known limit that follows from that last point is worth stating plainly
rather than discovering later: **web traffic is mostly user-less**, so per-user
baselines -- the thing this detector's per-user Isolation Forest is built on --
have little to work with on a web corpus. Source IP is the identity a web log
actually carries. That is a property of the data, not a defect in the mapping,
and it is exactly the kind of thing multi-source correlation is supposed to fix:
a web line and an auth line join on `source_ip`.
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

from . import ecs
from .preprocessing import template_message
from .templating import TemplateMiner

# The process name recorded for web lines. An access log names no process, but
# the internal `process` column is a node in the entity graph and is what
# `event.module`/`event.dataset` are exported as, so it needs a value.
WEB_PROCESS = "nginx"

# Used when the log carries no hostname and the caller named none. Matches the
# placeholder `extract_user` returns, and `normalise_identity` refuses to join
# on either -- an absent identity must not become a shared one.
UNKNOWN = "unknown"


# nginx's default `combined` format, and the Common Log Format it extends:
#   IP - user [10/Oct/2000:13:55:36 -0700] "GET /p HTTP/1.0" 200 2326 "ref" "ua"
# The referrer/user-agent pair is optional, which is what makes one pattern
# cover both `combined` and `common`. nginx escapes a literal `"` inside those
# fields as `\x22`, so `[^"]*` is safe rather than merely convenient.
ACCESS_LINE_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'\s*$'
)

TIME_LOCAL_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# The request line is `METHOD SP TARGET SP HTTP/VERSION`. Scanner traffic
# frequently sends something else entirely, and those lines are precisely the
# ones worth detecting, so a request that does not match is kept verbatim rather
# than dropped -- see `_split_request`.
REQUEST_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/(?P<version>[\d.]+)$')

# Reason phrases for the statuses a log actually carries in bulk (RFC 9110).
# They exist because `template_message` masks every bare number to `<NUM>`: a
# message ending "... 401" and one ending "... 200" template to the same string,
# and the status is the whole signal on a web line. The phrase is the standard
# name of the code, not an interpretation of it, and it survives masking.
STATUS_REASONS = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
    413: "Payload Too Large", 414: "URI Too Long", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

STATUS_CLASS_REASONS = {
    1: "Informational", 2: "Success", 3: "Redirection",
    4: "Client Error", 5: "Server Error",
}


def status_reason(status: int) -> str:
    """The standard reason phrase for a status code, or its class name."""
    if status in STATUS_REASONS:
        return STATUS_REASONS[status]
    return STATUS_CLASS_REASONS.get(status // 100, "Unknown Status")


def categorize_http(status: int) -> dict:
    """ECS `event.category`/`action`/`outcome` for one HTTP response.

    The counterpart to `ecs.categorize`, which reads a syslog message's text.
    Here the outcome is not a guess at all: the status code states it, so this
    is a translation rather than the best-effort classification the text-based
    one has to be.

    401 and 403 are additionally categorized as `authentication`, because that
    is what they are -- a credential was missing, wrong or insufficient -- and
    it is what lets a web line and an sshd auth line be compared as the same
    kind of event.
    """
    if status in (401, 403):
        return {
            "category": ["web", "authentication"],
            "action": "http-request-denied",
            "outcome": "failure",
        }
    if status >= 400:
        return {
            "category": ["web"],
            "action": "http-request",
            "outcome": "failure",
        }
    return {
        "category": ["web"],
        "action": "http-request",
        "outcome": "success",
    }


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dash_to_none(value: str | None) -> str | None:
    """`-` is how an access log writes "no value". It is not a username."""
    if value is None or value == "-" or value == "":
        return None
    return value


def _split_request(request: str) -> tuple[str | None, str, str | None]:
    """`"GET /a?b=1 HTTP/1.1"` -> (method, target, version).

    A request line that does not parse is returned whole as the target with no
    method and no version. Dropping it would be the wrong call twice over: it
    discards a line, and the lines that fail to parse here are malformed
    requests from scanners and exploit attempts, which is the traffic a detector
    exists for.
    """
    match = REQUEST_RE.match(request.strip())
    if match is None:
        return None, request.strip(), None
    return match.group("method"), match.group("target"), match.group("version")


def render_message(method: str | None, target: str, version: str | None,
                   status: int) -> str:
    """The `message` a web line contributes to detection.

    The internal pipeline embeds `template`, which is `template_message` applied
    to this string, so what goes in here decides what the detector can tell
    apart. It is a rendering of the fields the line already carries -- method,
    path, protocol version, status and that status's standard name -- in the
    order the request line writes them, and nothing else. The query string is
    included because `/login.php?user=admin' OR 1=1` is the anomaly.
    """
    head = f"{method} {target}" if method else target
    if version:
        head = f"{head} HTTP/{version}"
    return f"{head} {status} {status_reason(status)}"


def _parse_time(time_local: str, *, keep_local_time: bool) -> datetime | None:
    """`10/Oct/2000:13:55:36 -0700` -> a **naive** datetime.

    Naive is not laziness. Every timestamp already in this project is naive --
    syslog carries no year, let alone an offset -- and pandas raises
    `TypeError` the moment an aware and a naive timestamp are compared, which
    is every window computation in the pipeline: incident grouping, the
    impossible-travel check, the sequence model's ordering. One frame holding
    both would fail loudly at best and split a corpus into two incomparable
    halves at worst.

    So the offset is resolved, not discarded: by default the time is converted
    to UTC and the tzinfo dropped, which puts a web log and an auth log on one
    clock -- the prerequisite for correlating them. `keep_local_time` instead
    keeps the wall-clock time as written, which is the right choice only when
    the syslog side is known to be local time on the same machine.
    """
    try:
        parsed = datetime.strptime(time_local.strip(), TIME_LOCAL_FORMAT)
    except ValueError:
        return None
    if keep_local_time:
        return parsed.replace(tzinfo=None)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def parse_line(line: str, *, host: str | None = None,
               keep_local_time: bool = False) -> dict | None:
    """One access-log line -> a nested ECS document, or None if it doesn't match.

    This is the whole format-specific part of the module. Everything downstream
    of it -- `ecs.ecs_to_record` and the pipeline behind it -- is shared with
    every other ECS source, which is the reason for going through ECS at all.
    """
    match = ACCESS_LINE_RE.match(line.strip())
    if match is None:
        return None

    parts = match.groupdict()
    status = int(parts["status"])
    method, target, version = _split_request(parts["request"])
    path, _, query = target.partition("?")

    timestamp = _parse_time(parts["time_local"], keep_local_time=keep_local_time)
    message = render_message(method, target, version, status)

    event_block = {
        "kind": "event",
        "module": "web",
        "dataset": WEB_PROCESS,
        "original": line.strip(),
    }
    event_block.update(categorize_http(status))

    doc = {
        "@timestamp": timestamp.isoformat() if timestamp else None,
        "message": message,
        "ecs": {"version": ecs.ECS_VERSION},
        "event": event_block,
        "host": {"name": host or UNKNOWN, "hostname": host or UNKNOWN},
        "process": {"name": WEB_PROCESS},
        "user": {"name": _dash_to_none(parts["remote_user"])},
        "source": {"ip": _dash_to_none(parts["remote_addr"])},
        "url": {
            "original": target,
            "path": path or None,
            "query": query or None,
        },
        "http": {
            "request": {
                "method": method,
                "referrer": _dash_to_none(parts.get("referrer")),
            },
            "response": {
                "status_code": status,
                "body": {"bytes": _int_or_none(parts["body_bytes"])},
            },
        },
        "user_agent": {"original": _dash_to_none(parts.get("user_agent"))},
    }
    if version:
        doc["http"]["version"] = version
    return ecs.prune(doc)


class WebLogParser:
    """Parses access-log lines into the internal records the pipeline scores.

    The counterpart to `preprocessing.LineParser`, with the same
    `parse`/`parse_many` contract so a caller can hold either without caring
    which format it reads. The difference is the middle step: this one goes out
    to ECS and back rather than pulling fields out of a syslog regex directly.

    `miner` is the same optional Drain3 miner `LineParser` takes, and passing
    one *shared between the two parsers* is how a multi-source corpus gets a
    single template vocabulary -- ids are meaningful only relative to the miner
    that assigned them (see templating.py).
    """

    def __init__(self, host: str | None = None, keep_local_time: bool = False,
                 miner: TemplateMiner | None = None):
        self.host = host
        self.keep_local_time = keep_local_time
        self.miner = miner

    def parse_with_ecs(self, line: str) -> tuple[dict, dict] | None:
        """One line -> (internal record, the ECS document it came through).

        The two-value form exists because the ECS document is worth keeping:
        it is what another SIEM would consume and it carries the web fields
        (`url.*`, `http.*`, `user_agent.*`) that the internal columns have no
        room for. `parse` is this with the document dropped.
        """
        doc = parse_line(line, host=self.host,
                         keep_local_time=self.keep_local_time)
        if doc is None:
            return None

        record = ecs.ecs_to_record(doc)
        # `ecs_to_record` deliberately leaves `template` alone -- it is the
        # masked form the embedder sees and `preprocessing` owns it, so every
        # source must mask the same way or two formats produce templates that
        # cannot be compared. That is why this line is here and not there.
        record["template"] = template_message(record["message"])
        if self.miner is not None:
            record["template_id"] = self.miner.add(record["message"])
        return record, doc

    def parse(self, line: str) -> dict | None:
        parsed = self.parse_with_ecs(line)
        return None if parsed is None else parsed[0]

    def parse_many(self, lines) -> list[dict]:
        records = [self.parse(line) for line in lines]
        return [r for r in records if r is not None]


def preprocess_web_file(input_path: str, output_path: str,
                        host: str | None = None,
                        keep_local_time: bool = False,
                        mine_templates: bool = False,
                        template_state_path: str | None = None,
                        miner: TemplateMiner | None = None,
                        ecs_output_path: str | None = None):
    """Parse an access log into the same parsed-CSV shape `preprocess_file` writes.

    Same columns, same order of operations, same output contract -- so
    `logdet-pipeline`, `logdet-fit` and every evaluation script read a web
    corpus with no change at all. `ecs_output_path` additionally writes the
    intermediate ECS documents, which is the artifact another SIEM would
    consume and the evidence that the boundary is real rather than internal.
    """
    import pandas as pd

    if miner is None and mine_templates:
        miner = TemplateMiner()
    parser = WebLogParser(host=host, keep_local_time=keep_local_time,
                          miner=miner)

    docs: list[dict] = []
    records: list[dict] = []
    total = 0
    with open(input_path, "r", errors="ignore") as handle:
        for line in handle:
            if not line.strip():
                continue
            total += 1
            parsed = parser.parse_with_ecs(line)
            if parsed is None:
                continue
            record, doc = parsed
            records.append(record)
            docs.append(doc)

    frame = pd.DataFrame(records)
    frame.to_csv(output_path, index=False)
    print(f"Parsed {len(frame)}/{total} access-log lines -> {output_path}")
    if ecs_output_path:
        Path(ecs_output_path).write_text(ecs.to_ndjson(docs) + "\n")
        print(f"ECS documents -> {ecs_output_path}")
    if miner is not None:
        print(f"Mined {miner.cluster_count} templates")
        if template_state_path:
            miner.save(template_state_path)
            print(f"Template state -> {template_state_path}")
    return frame


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Parse nginx/Apache access logs into the pipeline's parsed CSV, via ECS.")
    parser.add_argument("--input", required=True, help="Path to the access log")
    parser.add_argument("--output", required=True, help="Path to write parsed CSV")
    parser.add_argument("--host", default=None,
                        help=f"Hostname to record (access logs carry none; default '{UNKNOWN}')")
    parser.add_argument("--keep-local-time", action="store_true",
                        help="Keep the log's wall-clock time instead of converting to UTC")
    parser.add_argument("--ecs-output", default=None,
                        help="Also write the intermediate ECS documents as NDJSON")
    parser.add_argument("--drain3", action="store_true",
                        help="Also mine Drain3 templates into a template_id column")
    parser.add_argument("--template-state", default=None,
                        help="Where to write the mined template table (implies --drain3)")
    args = parser.parse_args()

    preprocess_web_file(args.input, args.output, host=args.host,
                        keep_local_time=args.keep_local_time,
                        mine_templates=args.drain3 or bool(args.template_state),
                        template_state_path=args.template_state,
                        ecs_output_path=args.ecs_output)


if __name__ == "__main__":
    cli()
