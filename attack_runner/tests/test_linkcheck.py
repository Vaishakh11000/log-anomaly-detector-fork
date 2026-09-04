"""Link verifier: layer by layer, with injected transport."""

import json

from attack_runner.linkcheck import (
    http_health, local_interface_on_subnet, ping, run_checks, stream_lag,
)


def fake_ip_runner(stdout):
    class Proc:
        pass
    def run(cmd, **kw):
        p = Proc(); p.stdout = stdout; p.returncode = 0
        return p
    return run


def test_l2_finds_interface_by_address_not_name():
    # thunderbolt0, not enp3s0 -- still passes, because we match the address.
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
           "2: thunderbolt0    inet 10.10.10.1/24 scope global thunderbolt0\n")
    ok, detail = local_interface_on_subnet("10.10.10.0/24", runner=fake_ip_runner(out))
    assert ok and "thunderbolt0" in detail


def test_l2_fails_when_no_interface_on_subnet():
    out = "2: enp3s0    inet 192.168.1.5/24 scope global enp3s0\n"
    ok, _ = local_interface_on_subnet("10.10.10.0/24", runner=fake_ip_runner(out))
    assert not ok


def test_l3_ping():
    def run(cmd, **kw):
        class P: returncode = 0
        return P()
    ok, _ = ping("10.10.10.2", runner=run)
    assert ok


def test_l7_health():
    ok, _ = http_health("http://10.10.10.2:8000", opener=lambda u, t: (200, "ok"))
    assert ok
    bad, _ = http_health("http://10.10.10.2:8000", opener=lambda u, t: (503, "no"))
    assert not bad


def test_lag_distinguishes_stalled_from_healthy():
    healthy = lambda u, t: (200, json.dumps({"running": True, "seconds_since_last_batch": 1.2}))
    ok, detail = stream_lag("http://x", opener=healthy)
    assert ok and "1.2s" in detail

    idle = lambda u, t: (200, json.dumps({"running": False}))
    ok, detail = stream_lag("http://x", opener=idle)
    assert ok and "no stream" in detail


def test_run_checks_all_pass_gives_link_ok():
    ip_out = "2: eth0    inet 10.10.10.1/24 scope global eth0\n"
    def runner(cmd, **kw):
        class P: pass
        p = P()
        if cmd[0] == "ip":
            p.stdout = ip_out; p.returncode = 0
        else:   # ping
            p.returncode = 0
        return p
    opener = lambda u, t: (200, json.dumps({"running": False})) if "status" in u else (200, "ok")
    ok, lines = run_checks("10.10.10.0/24", "10.10.10.2", "http://10.10.10.2:8000",
                           runner=runner, opener=opener)
    assert ok
    assert lines[-1] == "LINK OK"


def test_run_checks_l7_down_gives_link_down():
    ip_out = "2: eth0    inet 10.10.10.1/24 scope global eth0\n"
    def runner(cmd, **kw):
        class P: pass
        p = P()
        if cmd[0] == "ip":
            p.stdout = ip_out; p.returncode = 0
        else:
            p.returncode = 0
        return p
    opener = lambda u, t: (503, "")
    ok, lines = run_checks("10.10.10.0/24", "10.10.10.2", "http://10.10.10.2:8000",
                           runner=runner, opener=opener)
    assert not ok and lines[-1] == "LINK DOWN"
