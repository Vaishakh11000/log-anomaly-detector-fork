"""
attacks.py
Drive real tools against a real sshd, recording ground truth as we go.

CLAUDE.md section 2d: the base attacks must be *authentic tool output*, not
fabricated log lines. So each driver shells out to a standard tool and returns
an AttackRecord describing what it launched -- never a list of log lines it
claims were produced. The lines are read back from the sshd's own auth stream
by capture.py and attributed by identity + time. That separation is the whole
point: we do not get to decide what the log says.

  brute_force (scenario A)  hydra/medusa if present, else ssh in a loop --
                            authentic Failed password bursts from one IP
  enumeration (scenario C)  ssh with a username list -- authentic Invalid user
  impossible_travel (B)     a real login, plus a second login the runner cannot
                            genuinely source from a distant IP, so that leg is
                            marked synthetic (section 2d says to state this)

Only the camouflage layer is authored, and it is applied by the caller to the
*captured* lines via the vendored camouflage.py -- identical transforms to the
synthetic track (section 2d), one source of truth.

Every subprocess call goes through an injected `runner` so the drivers are
unit-testable with no sshd and no network; the real path passes
subprocess.run. The tool a driver actually used is recorded on the AttackRecord
so the write-up can say which lines are hydra's and which are ssh's.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime

from .groundtruth import AttackRecord


def _which(*names: str) -> str | None:
    for n in names:
        if shutil.which(n):
            return n
    return None


def brute_force(target_host: str, target_port: int, user: str, source_ip: str,
                instance: int, attempts: int = 20, camouflage=None,
                runner=subprocess.run, now=datetime.now) -> AttackRecord:
    """Authentic failed-password burst against `target_host`.

    Prefers hydra/medusa (Kali carries both); falls back to a bounded ssh loop
    on a box that has only openssh, which produces the same Failed password
    lines one at a time. `source_ip` is recorded for attribution -- it is the
    address the analyzer will see, which on a direct link is the Kali box's own
    link IP.
    """
    t_start = now()
    tool = _which("hydra", "medusa") or "ssh"

    if tool in ("hydra", "medusa"):
        # A short list of wrong passwords -- a real brute force tries a wordlist,
        # not one password, and each wrong password is a separate "Failed
        # password" line in the auth log. `attempts` sets the list length. A
        # single `-p` (the earlier form) produced exactly one Failed-password
        # line, which understated how much signal an authentic burst carries;
        # a rate-limiting modern sshd (srclimit_penalise) still caps the burst,
        # which is itself an authentic finding, so we do not fight the penalty.
        import tempfile
        pw = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        pw.write("\n".join(f"wrongpass{i}" for i in range(attempts)) + "\n")
        pw.close()
        cmd = [tool, "-l", user, "-P", pw.name, "-t", "4",
               f"ssh://{target_host}:{target_port}"]
        runner(cmd, capture_output=True, text=True)
    else:
        for _ in range(attempts):
            cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=2", "-b", source_ip, "-p", str(target_port),
                   f"{user}@{target_host}", "true"]
            runner(cmd, capture_output=True, text=True)

    t_end = now()
    return AttackRecord(
        scenario="A", instance=instance,
        camouflage=list(camouflage or []),
        target_user=user, source_ips=[source_ip],
        t_start=t_start, t_end=t_end, tool=tool,
        description=f"brute force, {attempts} attempts via {tool}",
    )


def enumeration(target_host: str, target_port: int, users: list[str],
                source_ip: str, instance: int, camouflage=None,
                runner=subprocess.run, now=datetime.now) -> AttackRecord:
    """Authentic account enumeration -- one ssh attempt per candidate user.

    Invalid users produce "Invalid user <u> from <ip>"; the varied username is
    exactly why the source-IP key matters for this scenario (Stage 3 report).
    """
    t_start = now()
    for user in users:
        # `-b source_ip` binds the local source address, so each instance can run
        # from a distinct loopback source (127.0.0.11, .12, ...). sshd's
        # PerSourcePenalties is keyed per source /32, so a distinct source per
        # instance stops one instance's failed-auth penalty from clipping the
        # next -- which is what emptied C_2/C_3 on the first capture run (all
        # three fired back-to-back from 127.0.0.1). Enumeration is still one
        # source varying the username within an instance, so scenario C's shape
        # is unchanged.
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=2", "-b", source_ip, "-p", str(target_port),
               f"{user}@{target_host}", "true"]
        runner(cmd, capture_output=True, text=True)
    t_end = now()
    return AttackRecord(
        scenario="C", instance=instance,
        camouflage=list(camouflage or []),
        target_user=None, source_ips=[source_ip],
        t_start=t_start, t_end=t_end, tool="ssh",
        description=f"enumeration of {len(users)} candidate users",
    )


def impossible_travel(target_host: str, target_port: int, user: str,
                      home_ip: str, distant_ip: str, instance: int,
                      camouflage=None, runner=subprocess.run,
                      now=datetime.now) -> AttackRecord:
    """One genuine login from the home IP; the distant leg is synthetic.

    A single box cannot truthfully originate a login from a geographically
    distant address, so the second IP is authored and the record says so
    (`synthetic=True`). This is the one scenario section 2d flags as partly
    synthetic by necessity, and the honesty is in the flag, not in pretending
    otherwise.
    """
    t_start = now()
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=2", "-p", str(target_port),
           f"{user}@{target_host}", "true"]
    runner(cmd, capture_output=True, text=True)
    t_end = now()
    return AttackRecord(
        scenario="B", instance=instance,
        camouflage=list(camouflage or []),
        target_user=user, source_ips=[home_ip, distant_ip],
        t_start=t_start, t_end=t_end, tool="ssh",
        synthetic=True,
        description=f"impossible travel: real login from {home_ip}, "
                    f"synthetic distant leg from {distant_ip}",
    )
