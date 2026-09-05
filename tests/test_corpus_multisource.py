"""The two-source corpus: web + ssh attacks from one IP, injected and correlated.

These exercise the corpus builder's structure and the correlation it exists to
make measurable -- not detection, which needs the embedding model and is the
Kali measurement's job. The captures are tiny fixtures in the exact shape
`attack_runner` writes (ssh syslog + web access, each with a ground-truth CSV).
"""

import pandas as pd
import pytest

from logdet.config import INCIDENT_WINDOW_MINUTES
from logdet.sequence_grouping import group_anomalies
from logdet_eval.corpus_multisource import (
    build_multisource_corpus,
    load_web_capture,
)

pytestmark = pytest.mark.slow  # load_classified parses the corpus source


def _write_ssh_capture(dirpath):
    log = dirpath / "A_1.log"
    gt = dirpath / "A_1_gt.csv"
    log.write_text(
        "Jul 18 03:10:00 labsz sshd[900]: Failed password for root from 127.0.0.1 port 40000 ssh2\n"
        "Jul 18 03:10:02 labsz sshd[900]: Failed password for root from 127.0.0.1 port 40001 ssh2\n"
        "Jul 18 03:10:04 labsz sshd[900]: Failed password for root from 127.0.0.1 port 40002 ssh2\n"
    )
    gt.write_text(
        "line_number,timestamp,user,scenario,instance,description\n"
        "1,2026-07-18T03:10:00,root,A,1,brute force\n"
        "2,2026-07-18T03:10:02,root,A,1,brute force\n"
        "3,2026-07-18T03:10:04,root,A,1,brute force\n"
    )
    return str(log), str(gt)


def _write_web_capture(dirpath):
    log = dirpath / "W_1.log"
    gt = dirpath / "W_1_gt.csv"
    log.write_text(
        '203.0.113.66 - - [18/Jul/2026:03:13:00 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "curl"\n'
        '203.0.113.66 - - [18/Jul/2026:03:13:01 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "curl"\n'
        '203.0.113.66 - - [18/Jul/2026:03:13:02 +0000] "POST /wp-login.php HTTP/1.1" 401 20 "-" "curl"\n'
    )
    gt.write_text(
        "line_number,timestamp,user,scenario,instance,description\n"
        "1,2026-07-18T03:13:00,,W,1,web brute\n"
        "2,2026-07-18T03:13:01,,W,1,web brute\n"
        "3,2026-07-18T03:13:02,,W,1,web brute\n"
    )
    return str(log), str(gt)


def _tiny_ssh_source(tmp_path):
    """A small real-shaped ssh log for the benign background."""
    src = tmp_path / "bg.log"
    lines = []
    for i in range(12):
        lines.append(f"Jul 18 0{i%6}:0{i%6}:00 labsz sshd[{i}]: "
                     f"Accepted password for root from 192.168.1.{i+2} port 22 ssh2")
    for i in range(3):
        lines.append(f"Jul 18 05:0{i}:00 labsz sshd[{i}]: "
                     f"Failed password for guest from 8.8.8.{i} port 22 ssh2")
    src.write_text("\n".join(lines) + "\n")
    return str(src)


def test_load_web_capture(tmp_path):
    log, gt = _write_web_capture(tmp_path)
    caps = load_web_capture(log, gt)
    assert len(caps) == 1
    cap = caps[0]
    assert cap.scenario == "W" and len(cap.lines) == 3
    # offsets preserved from the capture's own spacing
    assert cap.lines[0][0].total_seconds() == 0
    assert cap.lines[2][0].total_seconds() == 2
    assert cap.lines[0][1]["process"] == "nginx"


def test_build_multisource_corpus_labels_both_sources(tmp_path):
    ssh = _write_ssh_capture(tmp_path)
    web = _write_web_capture(tmp_path)
    merged, gt, manifest = build_multisource_corpus(
        [ssh], [web], shared_ip="203.0.113.66",
        ssh_source=_tiny_ssh_source(tmp_path), seed=1)

    # both sources present in one parsed frame
    procs = set(merged["process"].dropna())
    assert "nginx" in procs and "sshd" in procs

    # ground truth carries both an ssh scenario and the web scenario
    scenarios = set(gt["scenario"])
    assert "A" in scenarios and "W" in scenarios
    assert len(gt) == 6                                # 3 ssh + 3 web attack lines

    # every attack line carries the shared IP, and its line number is real
    for _, row in gt.iterrows():
        pos = int(row["line_number"]) - 1
        assert merged.iloc[pos]["source_ip"] == "203.0.113.66"


def test_web_and_ssh_halves_correlate_into_one_incident(tmp_path):
    ssh = _write_ssh_capture(tmp_path)
    web = _write_web_capture(tmp_path)
    merged, gt, _ = build_multisource_corpus(
        [ssh], [web], shared_ip="203.0.113.66",
        ssh_source=_tiny_ssh_source(tmp_path), seed=1)

    # the question the whole module exists to answer: given both halves flagged,
    # does the grouper put the web 401 burst and the ssh brute force in ONE
    # incident? It must, because they share source_ip within the window.
    attack_positions = [int(n) - 1 for n in gt["line_number"]]
    attack = merged.iloc[attack_positions].copy()
    attack["is_anomaly"] = True
    incidents = group_anomalies(attack)

    cross = [g for g in incidents
             if set(g["process"].dropna()) >= {"nginx", "sshd"}]
    assert len(cross) == 1, "web and ssh halves did not correlate into one incident"
    span = cross[0]["timestamp"].max() - cross[0]["timestamp"].min()
    assert span <= pd.Timedelta(minutes=INCIDENT_WINDOW_MINUTES)
