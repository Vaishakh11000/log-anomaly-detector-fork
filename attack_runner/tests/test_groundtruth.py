"""Attribution: identity + time, conservative on purpose."""

from datetime import datetime

from attack_runner.groundtruth import AttackRecord, CapturedLine, attribute


def L(n, ts, ip=None, user=None):
    return CapturedLine(line_number=n, raw=f"line {n}", ts=ts, source_ip=ip, user=user)


def test_lines_in_window_from_attack_ip_are_attributed():
    rec = AttackRecord(scenario="A", instance=1, source_ips=["10.10.10.1"],
                       t_start=datetime(2026, 9, 4, 10, 0, 0),
                       t_end=datetime(2026, 9, 4, 10, 5, 0))
    lines = [
        L(1, datetime(2026, 9, 4, 10, 1, 0), "10.10.10.1"),   # in
        L(2, datetime(2026, 9, 4, 10, 2, 0), "10.10.10.1"),   # in
        L(3, datetime(2026, 9, 4, 9, 59, 0), "10.10.10.1"),   # before window
        L(4, datetime(2026, 9, 4, 10, 3, 0), "8.8.8.8"),      # wrong IP
    ]
    result = attribute(lines, [rec])
    assert set(result["labels"]) == {1, 2}
    assert result["per_instance"]["A:1"] == 2


def test_instance_that_produced_no_lines_is_visible():
    """The tool ran but the sshd swallowed its lines -- distinct from not run."""
    rec = AttackRecord(scenario="C", instance=2, source_ips=["10.10.10.1"],
                       t_start=datetime(2026, 9, 4, 10, 0, 0),
                       t_end=datetime(2026, 9, 4, 10, 5, 0))
    result = attribute([], [rec])
    assert result["labels"] == {}
    assert result["per_instance"]["C:2"] == 0


def test_first_matching_instance_wins():
    a = AttackRecord(scenario="A", instance=1, source_ips=["10.10.10.1"],
                     t_start=datetime(2026, 9, 4, 10, 0), t_end=datetime(2026, 9, 4, 10, 5))
    b = AttackRecord(scenario="C", instance=1, source_ips=["10.10.10.1"],
                     t_start=datetime(2026, 9, 4, 10, 6), t_end=datetime(2026, 9, 4, 10, 9))
    line = L(1, datetime(2026, 9, 4, 10, 2), "10.10.10.1")
    result = attribute([line], [a, b])
    assert result["labels"][1]["scenario"] == "A"


def test_line_without_timestamp_is_skipped():
    rec = AttackRecord(scenario="A", instance=1, source_ips=["10.10.10.1"],
                       t_start=datetime(2026, 9, 4, 10, 0), t_end=datetime(2026, 9, 4, 10, 5))
    assert attribute([L(1, None, "10.10.10.1")], [rec])["labels"] == {}
