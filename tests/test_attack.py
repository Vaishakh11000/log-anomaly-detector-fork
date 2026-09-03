"""
The ATT&CK index -- the grounding contract, one layer below the mapper.

`mitre_mapping.py` guarantees the LLM never picks a technique ID. This file
guarantees the ID it does pick is one ATT&CK still recognises, described the way
ATT&CK describes it, so "grounded in ATT&CK" is checked rather than asserted.

Every test here runs against the *committed* index (no network, no 54MB
bundle), except the parser tests, which build a tiny bundle in memory.
"""

import json

import pytest

from logdet import attack
from logdet.mitre_mapping import authored_technique_ids


def test_the_committed_index_covers_every_id_the_table_can_emit():
    """If this fails, some incident can carry a technique with no description
    behind it. Rebuild with `logdet-attack --refresh`."""
    index = attack.load_index()
    missing = sorted(set(authored_technique_ids()) - set(index["techniques"]))
    assert not missing, f"not in the committed index: {missing}"


def test_the_index_is_pinned_to_the_version_the_code_declares():
    index = attack.load_index()
    assert index["attack_version"] == attack.ATTACK_VERSION
    assert index["attack_sha256"] == attack.ATTACK_SHA256


def test_no_indexed_technique_is_deprecated_or_revoked():
    """An incident citing a technique ATT&CK has withdrawn is a wrong answer
    delivered with a citation, which is worse than no citation."""
    for technique_id in authored_technique_ids():
        entry = attack.technique(technique_id)
        assert not entry.deprecated and not entry.revoked, technique_id


def test_every_technique_carries_at_least_one_tactic():
    for technique_id in authored_technique_ids():
        entry = attack.technique(technique_id)
        assert entry.tactics and len(entry.tactics) == len(entry.tactic_ids)
        assert len(entry.kill_chain) == len(entry.tactics)
        assert all(t.startswith("TA") for t in entry.tactic_ids)


def test_tactics_are_stored_in_matrix_order():
    order = attack.matrix_order()
    assert order[0] == "reconnaissance" and order[-1] == "impact"
    for technique_id in authored_technique_ids():
        positions = attack.technique(technique_id).kill_chain
        assert list(positions) == sorted(positions)


def test_a_multi_tactic_technique_is_not_flattened_to_one():
    """T1078 Valid Accounts sits under four tactics. The hand-typed table said
    two, which is the drift this index exists to stop."""
    entry = attack.technique("T1078")
    assert len(entry.tactics) == 4
    assert entry.tactic == " / ".join(entry.tactics)


def test_a_subtechnique_is_named_the_way_attack_displays_it():
    """The STIX object for T1021.004 is called just 'SSH'; on its own that
    reads as meaningless in an alert."""
    assert attack.technique("T1021.004").name == "Remote Services: SSH"


def test_the_tactic_of_t1070_follows_attack_rather_than_memory():
    """ATT&CK 19 renamed this tactic from Defense Evasion to Stealth. A
    hand-typed table would still say the old name."""
    assert attack.technique("T1070").tactic == "Stealth"


# --- the parser, against a bundle small enough to read ---

def _bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "objects": objects}


def _minimal_objects() -> list[dict]:
    tactic = {
        "type": "x-mitre-tactic", "id": "x-mitre-tactic--ca",
        "name": "Credential Access", "x_mitre_shortname": "credential-access",
        "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
    }
    technique = {
        "type": "attack-pattern", "id": "attack-pattern--bf", "name": "Brute Force",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999",
                                 "url": "https://attack.mitre.org/techniques/T9999"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                               "phase_name": "credential-access"}],
        "x_mitre_platforms": ["Linux"],
    }
    analytic = {
        "type": "x-mitre-analytic", "id": "x-mitre-analytic--a1",
        "x_mitre_log_source_references": [{"name": "linux:syslog"}],
    }
    strategy = {
        "type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--s1",
        "x_mitre_analytic_refs": ["x-mitre-analytic--a1"],
    }
    detects = {
        "type": "relationship", "id": "relationship--r1", "relationship_type": "detects",
        "source_ref": "x-mitre-detection-strategy--s1", "target_ref": "attack-pattern--bf",
    }
    matrix = {"type": "x-mitre-matrix", "id": "x-mitre-matrix--m",
              "tactic_refs": ["x-mitre-tactic--ca"]}
    return [tactic, technique, analytic, strategy, detects, matrix]


@pytest.fixture
def tiny_bundle(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle(_minimal_objects())))
    return path


def test_log_sources_are_followed_through_strategy_and_analytic(tiny_bundle):
    """Three hops: detects -> strategy -> analytic -> log source. Only the
    analytic names the source, which is why this is not a comprehension."""
    parsed = attack.parse_bundle(tiny_bundle)
    assert parsed["techniques"]["T9999"]["log_sources"] == ["linux:syslog"]


def test_build_index_refuses_an_id_attack_does_not_carry(tiny_bundle):
    with pytest.raises(RuntimeError, match="absent from ATT&CK"):
        attack.build_index(["T9999", "T0000"], bundle_path=tiny_bundle)


def test_build_index_refuses_a_deprecated_technique(tmp_path):
    objects = _minimal_objects()
    for obj in objects:
        if obj["type"] == "attack-pattern":
            obj["x_mitre_deprecated"] = True
    path = tmp_path / "deprecated.json"
    path.write_text(json.dumps(_bundle(objects)))
    with pytest.raises(RuntimeError, match="deprecated or revoked"):
        attack.build_index(["T9999"], bundle_path=path)


def test_an_index_round_trips_through_the_file(tmp_path, tiny_bundle):
    index = attack.build_index(["T9999"], bundle_path=tiny_bundle)
    path = attack.write_index(index, tmp_path / "index.json")
    attack.load_index.cache_clear()
    try:
        assert attack.load_index(str(path))["techniques"]["T9999"]["name"] == "Brute Force"
    finally:
        attack.load_index.cache_clear()
