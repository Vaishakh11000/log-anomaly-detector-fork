"""
triage.py
The ranking and filtering policy shared by every interface.

The detector runs at CONTAMINATION=0.20, which deliberately favours recall: on
the synthetic corpus that is ~94 incidents of which 9 are real attacks. Any
interface that lists incidents in timestamp order therefore puts a singleton
false positive at the top and buries every real attack, so the ordering below
is not cosmetic -- it is the difference between a usable view and an unusable
one.

It lives here rather than in `dashboard.py` because the API serves the same
incidents and must rank them identically. Two copies of this policy would drift
apart, and then the dashboard and the API would disagree about which incidents
matter, which is exactly the sort of quiet inconsistency a demo exposes.
"""

from logdet.config import NARRATE_MIN_EVENTS, NARRATE_SEVERITIES

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def is_notable(incident: dict) -> bool:
    """Same policy the pipeline uses to decide what gets a narrative
    (pipeline.should_narrate) -- kept in sync via the NARRATE_* config values
    so the default view matches what was actually narrated."""
    return (incident.get("severity") in NARRATE_SEVERITIES
            or incident.get("event_count", 0) >= NARRATE_MIN_EVENTS)


def triage_key(incident: dict):
    """Rank corroborated incidents above loud single lines.

    Event count leads: a multi-event incident is several independent signals
    about the same actor, which is stronger evidence than one line with an
    extreme anomaly score. Severity breaks ties, and the sequence model
    (Stage 3) breaks what is left.

    The transition surprisal is a **tiebreaker only**, which is what the
    measurement supports and no more. Ranked on its own it is much worse than
    this ordering -- every attack instance takes until rank 46 instead of 16 --
    but appended after event count and severity it brings full coverage of the
    9 synthetic attack instances forward from rank 16 to rank 12, with
    precision@5/@10/@20 unchanged. Incidents with no surprisal (the streaming
    path does not compute one yet) sort as 0.0 and the order is exactly what it
    was before.
    """
    return (incident.get("event_count", 0),
            SEVERITY_RANK.get(incident.get("severity"), 0),
            incident.get("max_transition_surprisal") or 0.0)
