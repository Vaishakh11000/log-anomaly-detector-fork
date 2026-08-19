"""
The Wazuh adapter.

Parsing is tested against captured logtest output rather than a live container,
so these run in CI. The container-dependent test is marked slow and skips when
Wazuh is not up.
"""

import pytest

from logdet_eval import wazuh_runner
from logdet_eval.wazuh_runner import LineVerdict, _parse_block, flagged_lines, rule_counts

# A real logtest block, trimmed. Tabs matter -- the parser anchors on them.
BLOCK = """: Completed pre-decoding.
\tfull event: 'Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186'
\ttimestamp: 'Dec 10 06:55:46'
\thostname: 'LabSZ'
\tprogram_name: 'sshd'

**Phase 2: Completed decoding.
\tname: 'sshd'
\tsrcip: '173.234.31.186'

**Phase 3: Completed filtering (rules).
\tid: '5710'
\tlevel: '5'
\tdescription: 'sshd: Attempt to login using a non-existent user'
\tmitre.id: '['T1110.001', 'T1021.004']'
**Alert to be generated.
"""

NO_RULE_BLOCK = """: Completed pre-decoding.
\tfull event: 'Dec 10 06:55:47 LabSZ sshd[1]: Connection closed by 10.0.0.5 [preauth]'
\thostname: 'LabSZ'

**Phase 2: Completed decoding.
\tname: 'sshd'
"""


def test_parses_rule_level_and_alert_flag():
    verdict = _parse_block(BLOCK, line_number=7)
    assert verdict.line_number == 7
    assert verdict.rule_id == "5710"
    assert verdict.level == 5
    assert verdict.alerted is True


def test_parses_wazuhs_own_mitre_attribution():
    """Wazuh ships MITRE IDs on its rules, so this is its attribution, not ours
    -- which is what makes a coverage comparison meaningful."""
    assert _parse_block(BLOCK, 1).mitre == ["T1110.001", "T1021.004"]


def test_a_line_matching_no_rule_is_not_an_alert():
    verdict = _parse_block(NO_RULE_BLOCK, line_number=2)
    assert verdict.rule_id is None
    assert verdict.level == 0
    assert verdict.alerted is False


def test_flagged_lines_respects_the_level_threshold():
    verdicts = [
        LineVerdict(1, "5710", 5, True),
        LineVerdict(2, "5763", 10, True),
        LineVerdict(3, "5715", 3, True),
        LineVerdict(4, None, 0, False),
    ]
    assert flagged_lines(verdicts, 3) == {1, 2, 3}
    assert flagged_lines(verdicts, 7) == {2}
    assert flagged_lines(verdicts, 11) == set()


def test_unalerted_matches_are_never_flagged():
    """A rule can match without generating an alert -- Wazuh's `ignore` timers
    do exactly this. Counting a suppressed match as a detection would credit
    Wazuh with alerts an analyst never saw."""
    verdicts = [LineVerdict(1, "5763", 10, False)]
    assert flagged_lines(verdicts, 3) == set()


def test_rule_counts_tallies_matches():
    verdicts = [LineVerdict(1, "5710", 5, True), LineVerdict(2, "5710", 5, True),
                LineVerdict(3, "5763", 10, True), LineVerdict(4, None, 0, False)]
    assert rule_counts(verdicts) == {"5710": 2, "5763": 1}


@pytest.mark.slow
def test_alignment_is_asserted_against_the_live_container(tmp_path):
    """One verdict per input line, in order. If this ever breaks, ground-truth
    line numbers point at the wrong lines and every number is silently wrong."""
    if not wazuh_runner.container_available():
        pytest.skip("wazuh container not running")

    log = tmp_path / "mini.log"
    log.write_text("\n".join(
        f"Dec 10 06:55:{i:02d} LabSZ sshd[{100 + i}]: Invalid user probe{i} from 203.0.113.9"
        for i in range(10)
    ) + "\n")

    verdicts = wazuh_runner.analyze(str(log))
    assert [v.line_number for v in verdicts] == list(range(1, 11))
