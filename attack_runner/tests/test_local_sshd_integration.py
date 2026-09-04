"""
End-to-end on one box: real sshd, real ssh attempts, real captured lines.

This is the "unit-test with a local sshd on this box" the Stage 6 kick-off
asked for, and it is the only test here that touches a real service. It:

  1. starts a throwaway non-root sshd on 127.0.0.1:2222 (own host key, own
     config, logging to the system journal in syslog form),
  2. runs `attacks.enumeration` for real -- actual ssh subprocesses against it,
     producing authentic "Invalid user <u> from 127.0.0.1" lines,
  3. captures those lines from the journal and attributes them to the launch
     record by identity + time.

It proves the authentic-output path (CLAUDE.md section 2d): nothing here
fabricates a log line; the sshd wrote them. Everything is skipped rather than
failed when the environment cannot support it (no sshd/ssh, sshd will not
start, journal not readable) -- a bare CI runner has none of these, and this
check only needs to hold where a real sshd exists.
"""

import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from attack_runner import attacks
from attack_runner.capture import capture_journald
from attack_runner.groundtruth import attribute

PORT = 2222


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def _journal_readable() -> bool:
    try:
        r = subprocess.run(["journalctl", "-n", "1", "--no-pager"],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


needs = pytest.mark.skipif(
    not (shutil.which("sshd") and shutil.which("ssh") and shutil.which("ssh-keygen")
         and _journal_readable() and _port_free(PORT)),
    reason="needs sshd+ssh+ssh-keygen, a readable journal, and port 2222 free",
)


@pytest.fixture
def local_sshd(tmp_path):
    keygen = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(tmp_path / "hostkey"), "-N", "", "-q"],
        capture_output=True, text=True)
    assert keygen.returncode == 0, keygen.stderr

    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        f"Port {PORT}\nListenAddress 127.0.0.1\n"
        f"HostKey {tmp_path / 'hostkey'}\nPidFile {tmp_path / 'sshd.pid'}\n"
        "LogLevel VERBOSE\nUsePAM no\nPasswordAuthentication yes\n"
        "PermitRootLogin no\nStrictModes no\n")

    # sshd refuses a bare argv[0]; it must be invoked by absolute path.
    sshd_path = shutil.which("sshd")
    proc = subprocess.Popen([sshd_path, "-f", str(cfg), "-D"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        if not _port_free(PORT):
            break
        time.sleep(0.1)
    else:
        proc.terminate()
        pytest.skip("sshd did not come up on this box")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@needs
def test_real_enumeration_is_captured_and_attributed(local_sshd):
    year = datetime.now().year
    users = ["oracle", "postgres", "gituser"]

    record = attacks.enumeration("127.0.0.1", PORT, users,
                                 source_ip="127.0.0.1", instance=1)
    assert record.tool == "ssh"
    # widen the window a little either side to absorb clock granularity
    record.t_start -= timedelta(seconds=2)
    record.t_end += timedelta(seconds=2)

    time.sleep(0.5)   # let journald flush
    since = record.t_start.strftime("%Y-%m-%d %H:%M:%S")
    lines = capture_journald(None, year, since=since)

    invalid = [ln for ln in lines
               if ln.user in users and ln.source_ip == "127.0.0.1"]
    assert invalid, "sshd produced no attributable Invalid user lines"

    result = attribute(lines, [record])
    assert result["per_instance"]["C:1"] >= len(invalid)
    # every attributed line is a real one the sshd actually wrote
    assert all("127.0.0.1" in lines[n - 1].raw or lines[n - 1].source_ip == "127.0.0.1"
               for n in result["labels"])
