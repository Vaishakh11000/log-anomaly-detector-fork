"""Tests for Drain3 template mining (Stage 3).

Nothing in detection reads a mined template id yet, so these tests pin the two
properties a *later* stage would depend on and that fail silently if they break:
the id is stable while the template text is not, and a persisted miner numbers
clusters the same way after a restart.
"""

import pytest

from logdet import config
from logdet.preprocessing import LineParser
from logdet.templating import TemplateMiner, mine_messages


FAILED = [
    "Failed password for admin from 192.168.1.5 port 51422 ssh2",
    "Failed password for root from 10.0.0.9 port 22 ssh2",
    "Failed password for alice from 172.16.4.2 port 4000 ssh2",
]
ACCEPTED = "Accepted password for alice from 172.16.4.2 port 4000 ssh2"


def test_same_event_different_identifiers_shares_one_cluster():
    ids, _ = mine_messages(FAILED)
    assert len(set(ids)) == 1


def test_failed_and_accepted_stay_separate():
    """The distinction this project detects on must survive templating.

    A merge here would leave a sequence model unable to tell a brute-force
    burst from ordinary logins, which is the entire signal.
    """
    ids, _ = mine_messages(FAILED + [ACCEPTED])
    assert ids[-1] not in ids[:-1]


def test_variable_fields_are_masked_out_of_the_template():
    _, miner = mine_messages(FAILED)
    template = miner.templates()[0]["template"]
    assert "<IP>" in template and "<PORT>" in template
    assert "192.168.1.5" not in template


def test_single_occurrence_still_masks_ip_and_port():
    """Masking is explicit, not discovered from seeing two values.

    Drain only generalises a position once it has seen it vary, so without the
    masking instructions a corpus with one IP would mine that IP into the
    template -- and the cluster numbering would depend on how varied the
    traffic happened to be rather than on the log's grammar.
    """
    _, miner = mine_messages(FAILED[:1])
    template = miner.templates()[0]["template"]
    assert "<IP>" in template and "<PORT>" in template


def test_cluster_id_is_stable_while_template_text_widens():
    miner = TemplateMiner()
    first_id = miner.add(FAILED[0])
    first_text = miner.template_for(first_id)
    second_id = miner.add(FAILED[1])

    assert second_id == first_id
    assert miner.template_for(first_id) != first_text, (
        "the template widened, which is exactly why the id and not the text "
        "is what gets recorded per line"
    )


def test_blank_messages_are_not_clustered():
    miner = TemplateMiner()
    assert miner.add("") is None
    assert miner.add("   ") is None
    assert miner.add(None) is None
    assert miner.cluster_count == 0


def test_match_does_not_mine():
    """Scoring against a frozen template set must not grow that set."""
    _, miner = mine_messages(FAILED[:2])
    known = miner.templates()[0]["template_id"]
    assert miner.match(FAILED[2]) == known
    assert miner.match("Some entirely unrelated daemon message here") is None
    assert miner.cluster_count == 1


def test_match_needs_a_widened_template():
    """A cluster mined from one line has no wildcards, so it matches only that
    exact shape. A template set frozen too early therefore reports novelty it
    has not earned -- see `TemplateMiner.match`."""
    miner = TemplateMiner()
    miner.add(FAILED[0])
    assert miner.match(FAILED[1]) is None

    miner.add(FAILED[1])
    assert miner.match(FAILED[2]) is not None


def test_state_round_trips_and_keeps_the_numbering(tmp_path):
    _, miner = mine_messages(FAILED + [ACCEPTED])
    before = miner.templates()

    path = tmp_path / "state.json"
    miner.save(path)

    restored = TemplateMiner()
    restored.load(path)
    assert restored.templates() == before
    assert restored.match(FAILED[0]) == before[0]["template_id"]


def test_config_is_not_read_from_a_stray_ini(tmp_path, monkeypatch):
    """Drain3 loads `drain3.ini` from the working directory if one exists.

    That would make mined templates depend on where the command was run from,
    so the config is built in code instead.
    """
    (tmp_path / "drain3.ini").write_text("[DRAIN]\nsim_th = 0.99\ndepth = 10\n")
    monkeypatch.chdir(tmp_path)
    ids, _ = mine_messages(FAILED)
    assert len(set(ids)) == 1


def test_max_clusters_unbounded_so_ids_are_never_recycled():
    """A bounded cluster table is an LRU: an evicted template returns with a
    new id, silently renumbering the vocabulary under any model keyed on it."""
    assert config.DRAIN_MAX_CLUSTERS is None


# --- the parsed column -------------------------------------------------------

RAW = [
    "Jul 18 10:22:31 server1 sshd[1382]: Failed password for admin from 192.168.1.5 port 51422 ssh2",
    "Jul 18 10:22:33 server1 sshd[1383]: Failed password for root from 10.0.0.9 port 22 ssh2",
]


def test_parser_omits_template_id_unless_a_miner_is_given():
    """The default parse must produce exactly the columns every number in
    `results/` was computed from."""
    record = LineParser(year=2026).parse(RAW[0])
    assert "template_id" not in record


def test_parser_adds_template_id_when_a_miner_is_given():
    parser = LineParser(year=2026, miner=TemplateMiner())
    records = [parser.parse(line) for line in RAW]
    assert records[0]["template_id"] == records[1]["template_id"]


def test_template_id_is_additive_and_changes_no_other_column():
    plain = LineParser(year=2026).parse(RAW[0])
    mined = LineParser(year=2026, miner=TemplateMiner()).parse(RAW[0])
    assert {k: v for k, v in mined.items() if k != "template_id"} == plain
