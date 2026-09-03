"""
attack.py
Ingests the official MITRE ATT&CK Enterprise STIX bundle and reduces it to a
small committed index the pipeline reads offline.

Why this exists (Stage 4). Until now every technique name and tactic in
`mitre_mapping.py` was hand-typed, so the enrichment layer's authority was the
author -- the same objection §1b removed from the rule baseline. ATT&CK is a
third party and publishes the machine-readable truth, so names, tactics,
kill-chain position, deprecation status, platforms and declared log sources now
come from the bundle.

What STIX can and cannot replace. It cannot replace the *table*: ATT&CK carries
no keywords for log lines, so the authored part -- "this message means this
technique" -- stays authored and stays small (an explicit anti-goal is building
an ATT&CK ontology). The split is:

    authored : which log messages map to which technique ID
    ATT&CK   : what that technique ID is, and where it sits in the matrix

Two files, deliberately:

  * the 54MB bundle, pinned by version and verified by SHA-256, downloaded to
    data/external/ (gitignored, like the LogHub corpora)
  * `data/attack_index.json`, a ~10KB projection of it, *committed*, so the
    pipeline is deterministic and works with no network -- the local-first
    constraint in CLAUDE.md §2 -- and so a bundle refresh is a reviewable diff
    rather than something that changes results silently.

Refresh with `logdet-attack --refresh` after bumping ATTACK_VERSION.
"""

import hashlib
import json
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from logdet.config import DATA_DIR

# Pinned. A moving "latest" would let a technique be renamed, re-tacticked or
# deprecated between two runs and change what an incident says it is.
ATTACK_VERSION = "19.2"
ATTACK_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)

BUNDLE_PATH = DATA_DIR / "external" / f"enterprise-attack-{ATTACK_VERSION}.json"
INDEX_PATH = Path(__file__).resolve().parent / "data" / "attack_index.json"

# The log sources this system actually ingests, in ATT&CK's own naming. Two
# groups, kept apart because they are not equally defensible:
#
#   DECLARED_LOG_SOURCES  -- ATT&CK's name for exactly what we read: sshd/sudo/
#                            su/pam lines out of syslog or journald.
#   EQUIVALENT_LOG_SOURCES -- authored judgement. auditd records the same
#                            *events* (a login attempt, an authentication) from
#                            a different subsystem, and ATT&CK's Linux analytics
#                            for authentication techniques are written against
#                            auditd rather than syslog. Counting these as
#                            visible-to-us is a claim about the event, not about
#                            the file, so the coverage report reports both
#                            denominators and never merges them.
DECLARED_LOG_SOURCES = frozenset({"linux:syslog", "linux:auth", "linuxsyslog", "linux:cron"})
EQUIVALENT_LOG_SOURCES = frozenset({"auditd:USER_LOGIN", "auditd:AUTH", "auditd:USER_AUTH"})


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique, as this project needs it."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]          # display names, in matrix order
    tactic_ids: tuple[str, ...]       # TAxxxx, aligned with `tactics`
    kill_chain: tuple[int, ...]       # matrix position of each tactic, aligned
    platforms: tuple[str, ...]
    log_sources: tuple[str, ...]      # log sources ATT&CK's analytics use
    deprecated: bool
    revoked: bool
    url: str

    @property
    def tactic(self) -> str:
        """The single display string the incident record and the LLM prompt
        carry. Same shape as the hand-typed strings it replaces, now derived."""
        return " / ".join(self.tactics)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_bundle(force: bool = False) -> Path:
    """Download and verify the pinned bundle. Only the index builder needs it."""
    BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not BUNDLE_PATH.exists() or force:
        print(f"Downloading ATT&CK Enterprise {ATTACK_VERSION} (~54MB)...")
        urllib.request.urlretrieve(ATTACK_URL, BUNDLE_PATH)

    actual = sha256_of(BUNDLE_PATH)
    if actual != ATTACK_SHA256:
        raise RuntimeError(
            f"enterprise-attack-{ATTACK_VERSION}.json failed verification.\n"
            f"  expected {ATTACK_SHA256}\n  got      {actual}\n"
            "Refusing to build a technique index from an unverified bundle."
        )
    return BUNDLE_PATH


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _external_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def parse_bundle(bundle_path: Path | None = None) -> dict:
    """Reduce the STIX bundle to plain dicts: techniques, matrix order, and the
    log sources ATT&CK's own detection strategies name for each technique.

    The log-source chain is three hops and is the reason this function exists
    rather than a comprehension: a `detects` relationship joins an
    x-mitre-detection-strategy to a technique, the strategy references
    x-mitre-analytic objects, and only the analytic names its log sources.
    """
    path = bundle_path or BUNDLE_PATH
    with open(path) as handle:
        objects = json.load(handle)["objects"]

    by_id = {obj["id"]: obj for obj in objects}

    # Matrix order, from ATT&CK's own matrix object -- not a list typed here.
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    order = {by_id[ref]["x_mitre_shortname"]: position
             for position, ref in enumerate(matrix["tactic_refs"])}
    tactic_meta = {
        obj["x_mitre_shortname"]: {"name": obj["name"], "tactic_id": _external_id(obj)}
        for obj in objects if obj["type"] == "x-mitre-tactic"
    }

    # Sub-technique parents, so T1021.004 reads "Remote Services: SSH" the way
    # ATT&CK itself displays it rather than the bare "SSH" the object carries.
    parent_of: dict[str, str] = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "subtechnique-of":
            child, parent = by_id.get(obj["source_ref"]), by_id.get(obj["target_ref"])
            if child is not None and parent is not None:
                parent_of[child["id"]] = parent["id"]

    log_sources: dict[str, set[str]] = {}
    for obj in objects:
        if obj["type"] != "relationship" or obj["relationship_type"] != "detects":
            continue
        strategy = by_id.get(obj["source_ref"])
        target = by_id.get(obj["target_ref"])
        if strategy is None or target is None or target["type"] != "attack-pattern":
            continue
        technique_id = _external_id(target)
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = by_id.get(analytic_ref)
            if analytic is None:
                continue
            names = {ref["name"] for ref in analytic.get("x_mitre_log_source_references", [])}
            log_sources.setdefault(technique_id, set()).update(names)

    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        technique_id = _external_id(obj)
        if technique_id is None:
            continue
        shortnames = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])
                      if phase.get("kill_chain_name") == "mitre-attack"]
        shortnames.sort(key=lambda name: order.get(name, len(order)))
        parent = by_id.get(parent_of.get(obj["id"], ""))
        techniques[technique_id] = {
            "technique_id": technique_id,
            "name": f"{parent['name']}: {obj['name']}" if parent else obj["name"],
            "parent_id": _external_id(parent) if parent else None,
            "tactics": [tactic_meta[s]["name"] for s in shortnames if s in tactic_meta],
            "tactic_ids": [tactic_meta[s]["tactic_id"] for s in shortnames if s in tactic_meta],
            "kill_chain": [order[s] for s in shortnames if s in order],
            "platforms": list(obj.get("x_mitre_platforms", [])),
            "log_sources": sorted(log_sources.get(technique_id, ())),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
            "url": _external_url(obj),
        }

    return {
        "attack_version": ATTACK_VERSION,
        "matrix_order": [name for name, _ in sorted(order.items(), key=lambda kv: kv[1])],
        "tactics": tactic_meta,
        "techniques": techniques,
    }


def build_index(technique_ids, bundle_path: Path | None = None) -> dict:
    """Project the bundle down to the techniques the authored table references.

    Raises on an ID ATT&CK does not carry, and on one it has revoked or
    deprecated -- an incident asserting a technique ATT&CK has withdrawn is a
    wrong answer delivered with a citation, which is worse than no citation.
    """
    parsed = parse_bundle(bundle_path)
    missing = sorted(set(technique_ids) - set(parsed["techniques"]))
    if missing:
        raise RuntimeError(
            f"Technique IDs absent from ATT&CK {ATTACK_VERSION}: {missing}. "
            "The authored table cites an ID that does not exist."
        )

    kept = {}
    withdrawn = []
    for technique_id in sorted(set(technique_ids)):
        entry = parsed["techniques"][technique_id]
        if entry["deprecated"] or entry["revoked"]:
            withdrawn.append(technique_id)
        kept[technique_id] = entry
    if withdrawn:
        raise RuntimeError(
            f"ATT&CK {ATTACK_VERSION} has deprecated or revoked: {withdrawn}. "
            "Re-map those messages before rebuilding the index."
        )

    return {
        "attack_version": ATTACK_VERSION,
        "attack_sha256": ATTACK_SHA256,
        "matrix_order": parsed["matrix_order"],
        "tactics": parsed["tactics"],
        "techniques": kept,
    }


def write_index(index: dict, path: Path | None = None) -> Path:
    target = path or INDEX_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return target


@lru_cache(maxsize=1)
def load_index(path: str | None = None) -> dict:
    """The committed index. Cached: the pipeline asks per incident."""
    with open(path or INDEX_PATH) as handle:
        return json.load(handle)


def technique(technique_id: str) -> Technique:
    """One technique, as ATT&CK describes it. KeyError if the authored table
    cites an ID the committed index does not carry -- which the test suite
    forbids, so it should never reach a user."""
    entry = load_index()["techniques"][technique_id]
    return Technique(
        technique_id=entry["technique_id"],
        name=entry["name"],
        tactics=tuple(entry["tactics"]),
        tactic_ids=tuple(entry["tactic_ids"]),
        kill_chain=tuple(entry["kill_chain"]),
        platforms=tuple(entry["platforms"]),
        log_sources=tuple(entry["log_sources"]),
        deprecated=entry["deprecated"],
        revoked=entry["revoked"],
        url=entry["url"],
    )


def matrix_order() -> list[str]:
    """Tactic shortnames in ATT&CK matrix (kill-chain) order."""
    return list(load_index()["matrix_order"])


def cli() -> None:
    import argparse

    from logdet.mitre_mapping import authored_technique_ids

    parser = argparse.ArgumentParser(
        description="Inspect or rebuild the committed ATT&CK technique index.")
    parser.add_argument("--refresh", action="store_true",
                        help="fetch the pinned bundle and rewrite the committed index")
    parser.add_argument("--force-download", action="store_true",
                        help="re-download the bundle even if it is already present")
    args = parser.parse_args()

    if args.refresh:
        fetch_bundle(force=args.force_download)
        index = build_index(authored_technique_ids())
        path = write_index(index)
        print(f"Wrote {path} from ATT&CK {ATTACK_VERSION} "
              f"({len(index['techniques'])} techniques)")

    index = load_index()
    print(f"ATT&CK {index['attack_version']}, {len(index['techniques'])} techniques indexed")
    for technique_id in sorted(index["techniques"]):
        entry = index["techniques"][technique_id]
        print(f"  {technique_id:<10} {entry['name']:<38} {' / '.join(entry['tactics'])}")


if __name__ == "__main__":
    cli()
