# attack_runner

> **Setting this up on Kali? Jump to [KALI_RUNBOOK.md](KALI_RUNBOOK.md).**
> That is the full step-by-step: what to install, start the sshd, run the
> attacks, and carry the results back to the analyzer. A short setup summary is
> in the [Kali quick start](#kali-quick-start) below.


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

## Kali quick start

### Driving this with Claude Code on Kali (recommended)

This repo ships a **`CLAUDE.md`** written for the Kali box. Clone the repo, open
Claude Code inside it, and the agent has the full playbook — it can check the
environment, start the sshd, run the attacks, and leave a bundle for you to carry
back, all with the honesty rules baked in.

```bash
# on Kali, one time
sudo apt update && sudo apt install -y git python3 openssh-server hydra
gh auth login                       # this repo is private
git clone https://github.com/Vaishakh11000/log-anomaly-attack-runner.git
cd log-anomaly-attack-runner

# install Claude Code if it is not already on this box, then:
claude                              # opens a chat in this directory; it reads CLAUDE.md
```

Then just tell it what you want, e.g. *"run three brute-force and three
enumeration instances against the local sshd and bundle the captures"*. It will
confirm before touching the system. To update the code later: `git pull`.

If you would rather run the commands yourself, the manual steps are below and the
full walkthrough is in **[KALI_RUNBOOK.md](KALI_RUNBOOK.md)**.

Full details in **[KALI_RUNBOOK.md](KALI_RUNBOOK.md)**. In short, on the Kali box:

```bash
# 1. one-time: install what is needed (Kali usually has all of these already)
sudo apt update
sudo apt install -y git python3 openssh-server hydra   # hydra optional; ssh loop is the fallback

# 2. get the code (this repo is private, so log in to GitHub on Kali first)
gh auth login                       # or use an HTTPS personal-access token
git clone https://github.com/Vaishakh11000/log-anomaly-attack-runner.git
cd log-anomaly-attack-runner
python3 -m attack_runner.cli --help # sanity check -- stdlib only, no pip install

# 3. start a real sshd to attack (nothing gets cracked; failed logins only)
sudo systemctl start ssh
ss -ltnp | grep :22

# 4. run an authentic attack against it, writing a scoreable pair to disk
mkdir -p capture
sudo python3 -m attack_runner.cli brute_force \
     --target-host 127.0.0.1 --target-port 22 --user root \
     --source-ip 127.0.0.1 --instance 1 \
     --auth-file /var/log/auth.log --year "$(date +%Y)" \
     --corpus-out capture/A_1.log --ground-truth-out capture/A_1_gt.csv \
     --records-out capture/A_1_rec.json
```

Then copy `capture/` back to the analyzer and score it there
(`results/kali/score_captured.py` in the main project). Updating later on Kali is
just `git pull`. The two-box live link (`--peer`) is not needed for any of this.

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
