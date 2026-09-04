# attack_runner

The Kali adversary component of the log-anomaly detector's adversarial track
(CLAUDE.md §2d). It runs **real attack tools against a real sshd**, captures
the genuine auth lines they produce, records **ground truth at generation
time**, and ships the lines to the analyzer over the §2c link.

Only the *camouflage* layer is authored — and it is the shared, vendored
`camouflage.py`, identical to the synthetic track's, so the two evaluation
tracks stay comparable. Base attacks are authentic tool output; the impossible-
travel second IP is synthetic by necessity, and the ground-truth record says so.

## Why it is a separate, stdlib-only project

The dev SSD is single-occupancy (CLAUDE.md §2c): during a bake-off it is in the
analyzer laptop, so this code runs on the Kali box **without the repo checked
out**. Therefore:

- **Zero third-party dependencies.** Everything is Python 3.11+ stdlib; HTTP
  shipping uses `urllib`, not `requests`. `pip install -r requirements.txt` is a
  no-op. Copy this directory to Kali and it runs.
- **`camouflage.py` is a vendored copy** of `src/logdet_eval/camouflage.py`,
  kept byte-identical by `tests/test_camouflage_vendor.py`. One source of truth;
  drift is a test failure.

## Layout

| file | role |
|---|---|
| `attacks.py` | drive hydra/medusa/nmap/ssh; return an `AttackRecord`, never fake log lines |
| `capture.py` | read the sshd auth stream (file or journald) into attribution fields |
| `groundtruth.py` | `AttackRecord`, and attribution by identity + time |
| `ship.py` | disk-backed, resumable HTTP shipper (retry, byte offset, link health) |
| `linkcheck.py` | transport-agnostic link verifier — L2 → L3 → L7 → lag |
| `camouflage.py` | vendored shared camouflage transforms |
| `cli.py` | `attack-run`: launch → capture → attribute → ship |

## Run

```bash
# on a bare Kali box, no install needed:
python3 -m attack_runner.cli enumeration --target-host 127.0.0.1 --target-port 22 \
    --source-ip 10.10.10.1 --journald-unit sshd \
    --peer http://10.10.10.2:8000 --spool ./spool

# verify the link to the analyzer before a run:
python3 -m attack_runner.linkcheck --peer 10.10.10.2 --port 8000
python3 -m attack_runner.linkcheck --loopback          # self-test on one box

# tests (needs pytest; the local-sshd test needs sshd+ssh+a readable journal):
pytest
```

## Status

Scaffold, Stage 6 start. The boxes are not cabled together yet (§2c: the SSD
moves and the two-box split lands at Stage 6). Everything here runs and is
tested on one box against a local sshd; when the link exists, only `--peer` and
`--source` change. The analyzer-side `POST /collector/ingest` endpoint the
shipper POSTs to is built (`logdet-api`) and the whole loop
(launch → capture → attribute → ship → ingest → detect) is verified on one box
over loopback; the only thing pending hardware is the real cross-machine link.
