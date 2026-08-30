"""
bakeoff_dashboard.py
Stage 2b -- the grid the examiner actually clicks.

One page holding both contestants. The examiner picks a cell of the grid
(attack type x camouflage level), the harness fires that attack into the single
log stream this detector and Wazuh are both reading, and the scores appear
beside each other when the firing settles.

Why this page is here and not in `logdet/dashboard.py`. The grid drives the
evaluation track -- it generates attacks, talks to the Wazuh container and
scores both systems -- and CLAUDE.md section 5 runs the dependency one way
only: `logdet_eval` may import `logdet`, never the reverse. A firing button on
the detector's own dashboard would put the injector inside the thing being
measured. So this is a second page, and it reads incidents through the same
public HTTP client the first one uses.

Why the examiner clicks rather than watches. A scripted sequence is
indistinguishable from a recording, and CLAUDE.md Stage 2b lists audience
choice as one of the un-rigging measures alongside third-party rules and
pre-registered camouflage. The grid includes the cells where this system
loses, for the same reason.

Run with:
    logdet-api                                          # in another terminal
    docker start wazuh                                  # and wait ~30s
    streamlit run src/logdet_eval/bakeoff_dashboard.py
"""

import time

import pandas as pd
import streamlit as st

from logdet.api_client import DEFAULT_BASE_URL, ApiClient, ApiError
from logdet_eval import bakeoff, paced_replay, wazuh_runner

st.set_page_config(page_title="Live bake-off", layout="wide")

# While a firing is in flight the page has to keep repainting, or the progress
# and the incident count freeze exactly when somebody is watching them.
REFRESH_SECONDS = 3

st.title("⚔️ Live bake-off — this detector vs Wazuh")
st.caption("One log stream, both systems reading it, the attack chosen from the grid. "
           "Ground truth is automatic because the injector wrote the attack.")


# --- Setup -----------------------------------------------------------------

st.sidebar.markdown("### Stream")
api_url = st.sidebar.text_input("API base URL", DEFAULT_BASE_URL)
live_log = st.sidebar.text_input("Live log", bakeoff.DEFAULT_LIVE_LOG)
use_wazuh = st.sidebar.checkbox("Score Wazuh too", value=True,
                                help="Off means one contestant. The run is not a bake-off.")
container = st.sidebar.text_input("Wazuh container", paced_replay.CONTAINER,
                                  disabled=not use_wazuh)

st.sidebar.markdown("### Firing")
repeat = st.sidebar.number_input(
    "Instances per cell", min_value=1, max_value=25, value=3,
    help="Instance detection over one instance reads 0% or 100%, so the "
         "differential is +0.0pt whatever happened. n instances make the "
         "finest step 100/n points.")
seed = st.sidebar.number_input("Seed", min_value=0, value=1)
benign_rate = st.sidebar.slider("Background lines/second", 0.0, 5.0, 0.5, 0.1)
settle = st.sidebar.slider("Settle after each instance (s)", 0.0, 60.0,
                           bakeoff.SETTLE_SECONDS, 1.0,
                           help="Our micro-batch closes on 5s of quiet and analysisd "
                                "runs ~2s behind the writer.")
compress = st.sidebar.number_input(
    "Time compression", min_value=1.0, value=1.0, step=1.0,
    help="Anything but 1 makes every row an illustration: Wazuh correlates on "
         "arrival time, so compressed time fixes its score by construction.")

st.sidebar.caption(f"Finest differential step at {int(repeat)} instances: "
                   f"{100 / int(repeat):.0f}pt. Admissible pooled figures come from "
                   f"the kill-point runs over >=5 seeds, never from this page.")


def build_runner() -> bakeoff.GridRunner:
    """Open the stream, reset Wazuh's correlation state, and start the background."""
    target = container if use_wazuh else None
    if target is not None and not wazuh_runner.container_available(target):
        raise RuntimeError(
            f"Wazuh container {target!r} is not answering. Start it "
            f"(`docker start {target}`) and wait ~30s for wazuh-analysisd.")

    client = ApiClient(api_url)
    try:
        client.stop_stream()          # a leftover stream would hold the log open
    except ApiError:
        pass
    client.start_stream(source="file", path=live_log, from_start=True,
                        use_offset_store=False)

    session = bakeoff.open_session(live_log, target, seed=int(seed))
    if target is not None:
        paced_replay.reset_correlation_state(target)

    runner = bakeoff.GridRunner(
        session, bakeoff.build_readers(client, target), repeat=int(repeat),
        compress=float(compress), benign_rate=float(benign_rate), settle=float(settle))
    runner.background.start()
    return runner


runner = st.session_state.get("runner")   # a GridRunner, once opened

col_open, col_close = st.columns([1, 5])
if runner is None:
    if col_open.button("Open the stream", type="primary"):
        try:
            st.session_state["runner"] = build_runner()
            st.rerun()
        except (ApiError, RuntimeError) as exc:
            st.error(str(exc))
    st.info("Open the stream to begin. Act 1 is the quiet baseline: background "
            "traffic flowing, both systems reading it, nothing happening.")
    st.stop()

if col_close.button("Close the stream"):
    runner.close()
    try:
        # The service would otherwise keep tailing a log nothing is writing,
        # which reads on the detector's own dashboard as a live stream.
        ApiClient(api_url).stop_stream()
    except ApiError:
        pass
    del st.session_state["runner"]
    st.rerun()


# --- What the stream is doing ----------------------------------------------

state = runner.state()
client = ApiClient(api_url)
try:
    status = client.status()
    incidents = client.incidents()
except ApiError as exc:
    status, incidents = {}, []
    st.error(f"Cannot read the detector service: {exc}")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Lines written", len(runner.session.manifest))
m2.metric("Lines parsed", status.get("lines_parsed", 0))
m3.metric("Our incidents", len(incidents))
m4.metric("Conditions fired", len(runner.results))

if state["error"]:
    st.error(f"Last firing failed: {state['error']}")
elif state["busy"]:
    st.warning(f"Firing **{state['attack']}** / `{state['level']}` — "
               f"instance {state['instance']} of {state['repeat']}. "
               "The firing runs in real time; the attack takes as long as it takes.")
else:
    st.success("Quiet stream. Pick a cell.")


# --- The grid --------------------------------------------------------------

st.markdown("### Pick an attack and a camouflage level")
st.caption("`slow` and `realistic-combo` are shown because a demo that never loses "
           "reads as rigged, but they cannot be *measured* here: Wazuh correlates on "
           "arrival time, so its drop under a timing camouflage is fixed by the "
           "harness. Those rows are marked illustration and the measured figures are "
           "in `results/killpoint/killpoint_paced_ambient0.05.md`.")

header = st.columns([1.4] + [1] * len(bakeoff.LEVELS))
header[0].markdown("**attack**")
for column, level in zip(header[1:], bakeoff.LEVELS):
    mark = "" if level not in bakeoff.TIMING_DEPENDENT else " *"
    column.markdown(f"**`{level}`**{mark}")

for attack in bakeoff.ATTACKS:
    row = st.columns([1.4] + [1] * len(bakeoff.LEVELS))
    row[0].markdown(f"**{attack}**")
    for column, level in zip(row[1:], bakeoff.LEVELS):
        if column.button("Fire", key=f"fire-{attack}-{level}",
                         disabled=state["busy"], width="stretch"):
            runner.fire(attack, level, seed=int(seed), repeat=int(repeat))
            st.rerun()

st.caption("`*` timing-based: illustration only.")


# --- Results ---------------------------------------------------------------

if runner.results:
    st.markdown("### Scores")
    table = []
    for result in runner.results:
        baseline = next((r for r in runner.results
                         if r["attack"] == result["attack"] and r["level"] == "none"), None)
        differential = (bakeoff.differential_vs_baseline(baseline, result)
                        if baseline else None)
        table.append({
            "attack": result["attack"],
            "level": result["level"],
            "instances": bakeoff.instances_pooled(result),
            "ours (inst)": bakeoff.instance_cell(result, "ours"),
            "ours (lines)": bakeoff.line_cell(result, "ours"),
            "Wazuh (inst)": bakeoff.instance_cell(result, "wazuh"),
            "Wazuh (lines)": bakeoff.line_cell(result, "wazuh"),
            "our alerts": result["ours"]["overall"]["alerts"],
            "Wazuh alerts": result["wazuh"]["overall"]["alerts"],
            "differential": "--" if differential is None else f"{differential:+.1f}pt",
            "": "" if result["measured"] else "illustration",
        })
    st.dataframe(pd.DataFrame(table), width="stretch", hide_index=True)
    st.caption("The differential is measured against this attack's own `none` row, so "
               "fire that one first. It is the quantity CLAUDE.md section 1b is "
               "registered in; the line rates are the finer evidence of the same firing.")

    with st.expander("Report as it would be written"):
        st.code(bakeoff.render_report(runner.results), language="markdown")


# --- Repaint ---------------------------------------------------------------
# Last statement, and only while something is moving: a firing runs on a worker
# thread, so the page has to come back to see it finish. A stopped grid repaints
# nothing, which keeps the last table on screen instead of resetting it.
if state["busy"]:
    time.sleep(REFRESH_SECONDS)
    st.rerun()
