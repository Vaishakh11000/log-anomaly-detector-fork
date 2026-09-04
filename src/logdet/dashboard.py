"""
dashboard.py
Streamlit dashboard: triage view over detected incidents, with the
LLM-generated attacker narrative and mapped MITRE ATT&CK techniques.

Two sources, one view. By default the dashboard talks to the running
`logdet-api` service and shows incidents *as the stream emits them*, including
the stream's own health -- lines seen, lines parsed, and how long since the
last scored batch. The old behaviour, reading `incidents.json` from a finished
batch run, is still there as the second source: the file is what exists after
`logdet-pipeline`, and every number in `results/` came from that path.

Design note -- this is a *triage* view, not an alert list. The detector runs at
CONTAMINATION=0.20, which deliberately favours recall: on the synthetic corpus
that means ~94 incidents of which 9 are real attacks. Showing all 94 in
timestamp order (the original behaviour) put a singleton false positive at the
top of the screen and buried every real attack. So the default view is ranked
and filtered to the notable set, with an explicit escape hatch to see
everything -- the false positives are not hidden, they are ordered last.

Ranking and the notable filter come from `logdet.triage`, which the API uses
too, so the two interfaces cannot disagree about which incidents matter.

Run with:
    logdet-api                                  # in another terminal
    streamlit run src/logdet/dashboard.py
"""

import json
import time

import pandas as pd
import streamlit as st

from logdet.api_client import DEFAULT_BASE_URL, ApiClient, ApiError
from logdet.config import DEFAULT_DETECTOR_PATH, DEFAULT_INCIDENTS_PATH
from logdet.triage import is_notable, triage_key

st.set_page_config(page_title="LLM Log Anomaly Detector", layout="wide")

SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}
# Past this, the reader is looking at a stream that has stopped producing
# rather than a quiet log. Two micro-batch windows (STREAM_BATCH_MAX_SECONDS)
# plus slack -- short enough to notice during a demo, long enough not to cry
# wolf between bursts.
STALE_BATCH_SECONDS = 30


st.title("🛡️ LLM-Powered Log Anomaly Detector")
st.caption("Embedding-based anomaly detection with attacker narrative reconstruction "
           "(grounded in MITRE ATT&CK)")


# --- Source ----------------------------------------------------------------

st.sidebar.markdown("### Source")
source_mode = st.sidebar.radio(
    "Incidents from", ["Live API", "Incidents file"], index=0,
    help="The API streams incidents as they are detected. The file is the "
         "output of a finished `logdet-pipeline` run.")


def load_from_api(client: ApiClient) -> tuple[list[dict], dict]:
    return client.incidents(), client.status()


def load_from_file(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def _show_dropped(incident: dict) -> None:
    """Say when the model cited a technique the grounded lookup did not hand it.

    Shown as a rejection and never as a technique -- the ID is named so the
    claim is auditable, next to a sentence saying the system does not assert
    it. Without this the enforcement is invisible: an incident where the model
    tried to hallucinate a technique reads exactly like one where it did not.
    """
    dropped = incident.get("narrative_dropped") or []
    if dropped:
        st.caption(
            f"⚠️ The model also cited {', '.join(dropped)}. "
            "Not in this incident's grounded lookup, so it was removed and is "
            "**not** claimed by the system.")


client: ApiClient | None = None
status: dict = {}

if source_mode == "Live API":
    base_url = st.sidebar.text_input("API base URL", DEFAULT_BASE_URL)
    client = ApiClient(base_url)
    try:
        incidents, status = load_from_api(client)
    except ApiError as exc:
        st.error(f"Cannot read the detector service: {exc}")
        st.info("Start it with `uv run logdet-api`, or switch the sidebar to "
                "*Incidents file* to read a finished batch run.")
        st.stop()
else:
    incidents_path = st.sidebar.text_input("Incidents JSON path", DEFAULT_INCIDENTS_PATH)
    try:
        incidents = load_from_file(incidents_path)
    except FileNotFoundError:
        st.warning(f"No incidents file found at `{incidents_path}`. "
                   "Run `logdet-pipeline` first.")
        st.stop()
    except json.JSONDecodeError as e:
        st.error(f"`{incidents_path}` is not valid JSON: {e}")
        st.stop()


# --- Stream health ---------------------------------------------------------
# CLAUDE.md 2c: link health has to be visible, not inferred from an absence of
# alerts. A line count alone stops moving both when the log is quiet and when
# the reader has died, so the seconds-since-last-batch figure is the one that
# separates those two.

if status:
    lag = status.get("seconds_since_last_batch")
    if status.get("error"):
        st.error(f"Stream stopped with an error: {status['error']}")
    elif not status.get("running"):
        st.info("No stream running. Start one in the sidebar.")
    elif lag is None:
        st.info(f"Streaming `{status.get('source')}` — no batch scored yet.")
    elif lag > STALE_BATCH_SECONDS:
        st.warning(f"Streaming `{status.get('source')}` — nothing scored for "
                   f"{lag:.0f}s. Quiet log, or a reader that has stopped.")
    else:
        st.success(f"Streaming `{status.get('source')}` — last batch "
                   f"{lag:.0f}s ago.")

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Lines seen", status.get("lines_seen", 0))
    s2.metric("Lines parsed", status.get("lines_parsed", 0),
              help="Lines that matched the syslog parser. A gap means an "
                   "unfamiliar log format, not a quiet host.")
    s3.metric("Open incidents", status.get("incidents_open", 0),
              help="Still inside the correlation window; may still grow.")
    s4.metric("Dropped pushes", status.get("dropped_events", 0),
              help="Live-feed events dropped for slow subscribers. The "
                   "incidents themselves are never lost.")


# --- Stream control --------------------------------------------------------

if client is not None:
    with st.sidebar.expander("Stream control", expanded=not status.get("running")):
        stream_source = st.selectbox("Read from", ["file", "journald"])
        path = st.text_input("Log file", "data/raw/synthetic.log") \
            if stream_source == "file" else None
        unit = st.text_input("journald unit (blank = authpriv)", "") \
            if stream_source == "journald" else None
        detector_path = st.text_input("Detector", DEFAULT_DETECTOR_PATH)
        once = st.checkbox("Replay once, then stop", value=stream_source == "file",
                           help="Off means follow: keep reading as the source grows.")

        col_start, col_stop = st.columns(2)
        if col_start.button("Start", disabled=status.get("running", False),
                            width="stretch"):
            payload = {"source": stream_source, "detector": detector_path,
                       "once": once, "from_start": once}
            if path:
                payload["path"] = path
            if unit:
                payload["journald_unit"] = unit
            try:
                client.start_stream(**payload)
                st.rerun()
            except ApiError as exc:
                st.error(str(exc))

        if col_stop.button("Stop", disabled=not status.get("running", False),
                           width="stretch"):
            try:
                client.stop_stream()
                st.rerun()
            except ApiError as exc:
                st.error(str(exc))

    st.sidebar.markdown("### Refresh")
    auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
    refresh_seconds = st.sidebar.slider("Every (seconds)", 2, 60, 5,
                                        disabled=not auto_refresh)
    if st.sidebar.button("Refresh now", width="stretch"):
        st.rerun()


notable = [i for i in incidents if is_notable(i)]
narrated = [i for i in incidents if i.get("narrative")]

# --- Headline counts -------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Incidents", len(incidents))
c2.metric("High severity", sum(1 for i in incidents if i.get("severity") == "high"))
c3.metric("Notable", len(notable), help="High severity, or more than one correlated event")
c4.metric("Narrated", len(narrated), help="Incidents with an LLM-generated narrative")

# --- Filters ---------------------------------------------------------------
st.sidebar.markdown("### View")
show_all = st.sidebar.checkbox(
    f"Show all {len(incidents)} incidents", value=False,
    help="Off by default: the detector favours recall, so most single-event "
         "incidents are false positives. They are ranked last, not hidden.")

severities = st.sidebar.multiselect(
    "Severity", ["high", "medium", "low"], default=["high", "medium", "low"])

users = sorted({u for i in incidents for u in i.get("users", [])})
selected_user = st.sidebar.selectbox("Filter by user", ["All"] + users)

only_mitre = st.sidebar.checkbox("Only incidents with MITRE techniques", value=False)

pool = incidents if show_all else notable
filtered = [
    i for i in pool
    if i.get("severity") in severities
    and (selected_user == "All" or selected_user in i.get("users", []))
    and (not only_mitre or i.get("mitre_techniques"))
]
filtered.sort(key=triage_key, reverse=True)

st.markdown(f"**Showing {len(filtered)} of {len(incidents)} incidents**, "
            "highest-corroboration first.")
if not show_all and len(notable) < len(incidents):
    st.caption(f"{len(incidents) - len(notable)} single-event, non-high incidents hidden. "
               "Tick *Show all* in the sidebar to include them.")

if not filtered:
    st.info("No incidents match the current filters.")

# --- Incident list ---------------------------------------------------------
for incident in filtered:
    severity = incident.get("severity", "low")
    who = ", ".join(incident.get("users", [])) or "n/a"
    techniques = incident.get("mitre_techniques", [])
    badge = " ".join(f"`{t['technique_id']}`" for t in techniques)
    state = incident.get("status")

    with st.expander(
        f"{SEVERITY_ICON.get(severity, '⚪')} #{incident['incident_id']} — {who} · "
        f"{incident['event_count']} event(s) · {incident['start']} → {incident['end']}"
        + (" · open" if state == "open" else "")
        + (f" · {badge}" if badge else "")
    ):
        st.caption(incident.get("summary", ""))

        if incident.get("source_ips"):
            st.markdown("**Source IPs:** " + ", ".join(f"`{ip}`" for ip in incident["source_ips"]))

        if techniques:
            st.markdown("**MITRE ATT&CK:** " + " · ".join(
                f"`{t['technique_id']}` {t['technique_name']} ({t['tactic']})"
                for t in techniques
            ))
            # What each matched technique means, in ATT&CK's own words. Quoted
            # from the pinned bundle rather than explained by the LLM: the text
            # is fixed per technique, so a model could only paraphrase it, and
            # paraphrasing is where invention gets in.
            for t in techniques:
                if t.get("description"):
                    st.caption(f"`{t['technique_id']}` — {t['description']} "
                               f"([ATT&CK]({t['url']}))")
            # The same techniques seen as a kill chain: which ATT&CK tactics
            # this incident touches, in matrix order. Descriptive only.
            chain = incident.get("kill_chain") or []
            if chain:
                st.markdown("**Kill chain:** " + " → ".join(
                    f"{t['tactic']} (`{t['tactic_id']}`)" for t in chain))
        else:
            st.caption("No MITRE technique matched — the lookup table is deliberately "
                       "small and keyword-grounded, so unmatched is common and honest.")

        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Raw events")
            st.dataframe(pd.DataFrame(incident["events"]), width="stretch")

            # The benign events this incident was judged against -- for
            # impossible travel, the earlier login from the other subnet.
            # Shown apart from the flagged events, and labelled, because they
            # are evidence and not detections.
            context_events = incident.get("context_events") or []
            if context_events:
                st.caption("Compared against (benign, not flagged)")
                st.dataframe(pd.DataFrame(context_events), width="stretch")

        with col2:
            st.subheader("LLM narrative")
            narrative = incident.get("narrative")
            if narrative:
                st.write(narrative)
                _show_dropped(incident)
            else:
                # The cheap tier, when the pipeline or an earlier click made
                # one: a single sentence, with the techniques stated by the
                # retrieval beside it rather than by the model.
                triage_line = incident.get("triage_line")
                if triage_line:
                    st.caption("Triage line (one sentence, small model)")
                    st.write(triage_line)
                    _show_dropped(incident)

                if client is not None:
                    # On demand, one incident at a time: a full narrative costs
                    # ~3.9s per incident on the demo-box GPU and ~18.2s on its
                    # CPU, so an analyst asks for the ones they care about.
                    if not triage_line:
                        st.info("Not narrated yet.")
                    b1, b2 = st.columns(2)
                    if b1.button("Narrate now", key=f"narrate-{incident['incident_id']}"):
                        with st.spinner("Running the local LLM…"):
                            try:
                                client.narrate(incident["incident_id"])
                                st.rerun()
                            except ApiError as exc:
                                st.error(f"{exc}\n\nIs `ollama serve` running?")
                    if not triage_line and b2.button(
                            "Triage line", key=f"triage-{incident['incident_id']}"):
                        with st.spinner("One sentence on the small model…"):
                            try:
                                client.narrate(incident["incident_id"], tier="triage")
                                st.rerun()
                            except ApiError as exc:
                                st.error(f"{exc}\n\nIs `ollama serve` running?")
                elif not triage_line:
                    st.info("Not narrated — below the narrative budget threshold "
                            "(see `NARRATE_*` in `config.py`). Re-run the pipeline "
                            "with `--narrate-all`, or `--triage-lines` for a "
                            "one-sentence summary of every incident.")

st.sidebar.markdown("---")
st.sidebar.caption(
    "Detection: per-user Isolation Forest over sentence-embedding vectors, plus an "
    "impossible-travel physics rule. Narrative: local LLM (phi3 via Ollama) grounded "
    "in a MITRE ATT&CK keyword lookup table."
)

# --- Auto-refresh ----------------------------------------------------------
# Last statement in the script, deliberately: the page is a snapshot of a
# moving stream, so it has to redraw itself, but only once everything above has
# rendered. Streamlit interrupts a sleeping script when a widget is touched, so
# this costs latency on nothing. A timer fragment was tried first and is wrong
# here -- it fires once on the initial run, which turns "refresh every 5s" into
# a rerun loop with no delay in it.
#
# Only while a stream is actually running. A stopped stream emits nothing, so
# redrawing it forever would burn a thread to show the same page, and the last
# view of a finished replay would keep resetting itself under the reader.
if client is not None and auto_refresh and status.get("running"):
    time.sleep(refresh_seconds)
    st.rerun()
