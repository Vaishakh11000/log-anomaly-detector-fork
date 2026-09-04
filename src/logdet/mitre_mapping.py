"""
mitre_mapping.py
Maps anomalous log *messages* to MITRE ATT&CK technique IDs, then describes
those IDs from the official ATT&CK bundle rather than from memory.

The split, and why it is drawn here (Stage 4):

  * authored -- the keyword table below: "this log message means this technique
    ID". ATT&CK publishes no keywords for log lines, so nothing can replace it.
    It stays small and deliberate; building an ATT&CK ontology is an anti-goal.
  * ATT&CK  -- every technique's name, tactics, kill-chain position, platforms
    and deprecation status, read from the committed index in `attack.py`, which
    is built from the pinned Enterprise STIX bundle. Hand-typing those was the
    same "the author is the authority" problem that third-party rules removed
    from the baseline, and it had already drifted: ATT&CK 19 renamed the tactic
    of T1070 from Defense Evasion to Stealth, and T1078 carries four tactics,
    not the two that were typed here.

Two levels of mapping:
  * map_to_mitre(message)          -- per-line keyword lookup
  * map_incident_to_mitre(df)      -- the above, plus techniques that are only
                                      visible at incident level (impossible
                                      travel, account enumeration), which no
                                      single log line reveals on its own

The LLM is handed the result and asked to write prose about it; it never picks
an ID. That grounding is only worth something because this module cannot emit
an ID that is absent from the table *and* absent from ATT&CK -- the index
builder refuses an ID ATT&CK does not carry, or has revoked or deprecated.
Reference: https://attack.mitre.org/techniques/enterprise/
"""

import pandas as pd

from logdet.attack import technique as attack_technique
from logdet.config import ENUMERATION_MIN_DISTINCT_USERS

# Keywords are authored; the technique ID is the join key into ATT&CK. Nothing
# here names a technique or a tactic -- those come from the bundle.
MITRE_LOOKUP = [
    {
        "keywords": ["failed password", "authentication failure", "invalid user",
                     "login attempt rejected", "invalid credentials"],
        "technique_id": "T1110",     # Brute Force
    },
    {
        "keywords": ["accepted password", "session opened", "authentication succeeded",
                     "successful auth"],
        "technique_id": "T1078",     # Valid Accounts
    },
    {
        "keywords": ["usermod", "added to group", "gpasswd", "adduser"],
        "technique_id": "T1098",     # Account Manipulation
    },
    {
        "keywords": ["useradd", "new user", "creating user"],
        "technique_id": "T1136",     # Create Account
    },
    {
        "keywords": ["sudo", "command=", "su root", "privilege"],
        "technique_id": "T1548",     # Abuse Elevation Control Mechanism
    },
    {
        # Deliberately NOT the bare word "cron": routine CRON job lines are the
        # single most common benign message in these logs, and matching them
        # tagged half the dataset as Persistence.
        "keywords": ["crontab", "new cron job", "at job", "systemd-run"],
        "technique_id": "T1053",     # Scheduled Task/Job
    },
    {
        "keywords": ["scp", "wget", "curl", "outbound connection"],
        "technique_id": "T1041",     # Exfiltration Over C2 Channel
    },
    {
        "keywords": ["port scan", "nmap", "connection refused"],
        "technique_id": "T1046",     # Network Service Discovery
    },
    {
        "keywords": ["log cleared", "truncated", "history -c", "unset histfile",
                     "shred", "rm /var/log"],
        "technique_id": "T1070",     # Indicator Removal
    },
]

# Techniques attached from structural signals rather than message text. These
# are patterns no single log line can show -- they only exist across an
# incident. The evidence sentence is authored (it describes *our* detector);
# the technique it cites is ATT&CK's.
SIGNAL_LOOKUP = {
    "impossible_travel": {
        "technique_id": "T1021.004",     # Remote Services: SSH
        "evidence": "Successful authentications from geographically implausible "
                    "source IPs within a short window",
    },
    "account_enumeration": {
        "technique_id": "T1087",         # Account Discovery
        "evidence": f"{ENUMERATION_MIN_DISTINCT_USERS}+ distinct usernames probed "
                    "from a single source IP",
    },
}


def authored_technique_ids() -> list[str]:
    """Every technique ID this module can emit. The index is built from exactly
    this list, so an ID added here without a rebuild fails loudly rather than
    reaching an incident with no ATT&CK description behind it."""
    return sorted({entry["technique_id"] for entry in MITRE_LOOKUP}
                  | {entry["technique_id"] for entry in SIGNAL_LOOKUP.values()})


def describe(technique_id: str, **extra) -> dict:
    """One technique as ATT&CK describes it, plus any authored extras.

    `tactic` is kept as a single display string because the incident record,
    the dashboard and the LLM prompt all carry one -- but it is now joined from
    ATT&CK's tactics in matrix order instead of typed by hand.
    """
    entry = attack_technique(technique_id)
    return {
        "technique_id": entry.technique_id,
        "technique_name": entry.name,
        "tactic": entry.tactic,
        "tactics": list(entry.tactics),
        "tactic_ids": list(entry.tactic_ids),
        "kill_chain": list(entry.kill_chain),
        "url": entry.url,
        # ATT&CK's own sentence about the technique, carried so an analyst can
        # read what a matched ID means without leaving the incident and without
        # a network. Retrieval, like everything else here: it is quoted from the
        # pinned bundle, never written by the model.
        "description": entry.description,
        **extra,
    }


def map_to_mitre(message: str) -> list[dict]:
    """Return matching MITRE technique dicts for a single log message."""
    message_lower = str(message).lower()
    return [describe(entry["technique_id"]) for entry in MITRE_LOOKUP
            if any(kw in message_lower for kw in entry["keywords"])]


def detect_incident_signals(incident_df: pd.DataFrame) -> list[str]:
    """Return the names of structural signals present in this incident."""
    signals = []

    if "impossible_travel" in incident_df.columns and incident_df["impossible_travel"].any():
        signals.append("impossible_travel")

    # Account enumeration: many distinct usernames, one source IP.
    if {"user", "source_ip"}.issubset(incident_df.columns):
        for _, rows in incident_df.groupby("source_ip"):
            distinct_users = rows["user"].dropna().nunique()
            if distinct_users >= ENUMERATION_MIN_DISTINCT_USERS:
                signals.append("account_enumeration")
                break

    return signals


def map_incident_to_mitre(incident_df: pd.DataFrame) -> list[dict]:
    """Full grounded technique set for one incident: per-line keyword matches
    plus incident-level structural signals, de-duplicated by technique ID and
    ordered by kill-chain position so the list reads as a progression."""
    matched: dict[str, dict] = {}

    for message in incident_df.get("message", []):
        for entry in map_to_mitre(message):
            matched[entry["technique_id"]] = entry

    for signal in detect_incident_signals(incident_df):
        entry = SIGNAL_LOOKUP[signal]
        matched[entry["technique_id"]] = describe(entry["technique_id"],
                                                  evidence=entry["evidence"])

    return sorted(matched.values(),
                  key=lambda e: (min(e["kill_chain"], default=99), e["technique_id"]))


def kill_chain_of(techniques: list[dict]) -> list[dict]:
    """The tactics a technique set touches, de-duplicated and in ATT&CK matrix
    order -- the kill-chain view of an incident.

    A technique can sit under several tactics (T1078 Valid Accounts is under
    four), so this is not a relabelling of the technique list: it answers
    "where in an attack is this?" where the technique list answers "what is
    it?". Purely descriptive -- nothing downstream detects, groups or scores on
    it.
    """
    seen: dict[str, dict] = {}
    for entry in techniques:
        for name, tactic_id, position in zip(entry["tactics"], entry["tactic_ids"],
                                             entry["kill_chain"]):
            seen.setdefault(tactic_id, {
                "tactic_id": tactic_id, "tactic": name, "position": position,
                "technique_ids": [],
            })["technique_ids"].append(entry["technique_id"])
    return sorted(seen.values(), key=lambda t: t["position"])


if __name__ == "__main__":
    print("--- per-line keyword lookup ---")
    for m in [
        "Failed password for admin from 10.0.0.5 port 51422 ssh2",
        "sudo: alice : COMMAND=/bin/su root",
        "nmap scan detected from 10.0.0.9",
        "CRON[8124]: (root) CMD (run-parts /etc/cron.hourly)",   # benign: expect no match
    ]:
        hits = [f"{e['technique_id']} {e['technique_name']}" for e in map_to_mitre(m)]
        print(f"  {m}\n    -> {hits or 'no match (correct for benign routine lines)'}")

    print("\n--- incident-level signals ---")
    enumeration = pd.DataFrame({
        "user": ["root", "test", "guest", "oracle"],
        "source_ip": ["203.0.113.7"] * 4,
        "impossible_travel": [False] * 4,
        "message": [f"Failed password for {u} from 203.0.113.7 port 5000 ssh2"
                    for u in ["root", "test", "guest", "oracle"]],
    })
    for e in map_incident_to_mitre(enumeration):
        print(f"  {e['technique_id']} ({e['technique_name']}) - {e['tactic']}")
    print("  Expected: T1110 Brute Force + T1087 Account Discovery (signal-derived)")
