# Kali Runbook — authentic attacks, no link yet

This is the step-by-step for generating **real** attack traffic on the Kali box
and turning it into a scoreable corpus, while the two machines are **not** cabled
together (CLAUDE.md §2c: the direct link lands later). Instead of shipping the
lines over the link, the runner writes a `corpus.log` + `ground_truth.csv` on
Kali, and you carry those two files back to the analyzer (USB stick, or any
ordinary network — this is a one-off file copy, not the demo link).

Everything here needs only Python 3's standard library. There is **no**
`pip install` and no virtualenv on the Kali side — that is the whole point of
`attack_runner` being dependency-free (§2d), because the SSD that holds the repo
can only be in one machine at a time and Kali does not have the repo.

## What you get out of it

Real `hydra`/`ssh` output — genuine `Failed password` bursts and `Invalid user`
enumeration produced by a real sshd — with ground truth captured at the moment
the attack runs. On the analyzer this replaces the *injected synthetic* attack
lines used up to now, which is the last self-authored ingredient in the
un-camouflaged evaluation (§2d). Only the camouflage layer stays authored, and
that is the layer this project is meant to own.

---

## Step 0 — copy the bundle to Kali

On the analyzer (this machine), build the bundle:

```bash
uv run python attack_runner/make_bundle.py        # writes attack_runner_kali.tgz
```

Copy `attack_runner_kali.tgz` to the Kali box (USB stick is fine), then on Kali:

```bash
tar xzf attack_runner_kali.tgz
cd attack_runner
python3 -m attack_runner.cli --help               # sanity check, stdlib only
```

If `--help` prints usage, you are done — nothing else to install.

---

## Step 1 — have a real sshd to attack

Kali ships OpenSSH. Start it (root):

```bash
systemctl start ssh          # or: /usr/sbin/sshd
ss -ltnp | grep :22          # confirm it is listening
```

We attack it over the loopback address `127.0.0.1`, so no network is involved
and nothing leaves the box. The attacks make **failed** logins only — no account
is cracked and nothing is changed on the host.

Confirm you can read the auth log (this is where sshd writes the lines we
capture):

```bash
sudo tail -n 3 /var/log/auth.log          # Debian/Kali path
# if that file does not exist, this box logs auth to the journal instead:
journalctl -u ssh -n 3
```

Use whichever one shows sshd lines. The commands below show the `auth.log`
version; the journald alternative is noted under each.

---

## Step 2 — run the attacks and capture them

Run each instance, capturing straight after so the ground-truth window is tight.
`--source-ip 127.0.0.1` is required for a loopback attack, because that is the
address the sshd records and the runner attributes on. (On the real two-box link
later, this becomes the Kali box's link address `10.10.10.1` — the only thing
that changes.)

### Brute force (scenario A) — three instances

```bash
for i in 1 2 3; do
  sudo python3 -m attack_runner.cli brute_force \
    --target-host 127.0.0.1 --target-port 22 --user root \
    --source-ip 127.0.0.1 --instance $i \
    --auth-file /var/log/auth.log --year "$(date +%Y)" \
    --corpus-out       capture/A_${i}.log \
    --ground-truth-out capture/A_${i}_gt.csv \
    --records-out      capture/A_${i}_rec.json
done
```

`brute_force` uses `hydra` (or `medusa`) if present — both ship on Kali — and
falls back to a plain `ssh` loop otherwise. The `records-out` file records which
tool actually ran, so the write-up can say so.

Journald box: drop `--auth-file …` and add `--journald-unit ssh` instead.

### Enumeration (scenario C) — three instances

```bash
for i in 1 2 3; do
  sudo python3 -m attack_runner.cli enumeration \
    --target-host 127.0.0.1 --target-port 22 \
    --users admin test oracle postgres git deploy \
    --source-ip 127.0.0.1 --instance $i \
    --auth-file /var/log/auth.log --year "$(date +%Y)" \
    --corpus-out       capture/C_${i}.log \
    --ground-truth-out capture/C_${i}_gt.csv \
    --records-out      capture/C_${i}_rec.json
done
```

Each run prints something like `attributed 6 line(s) to instance 2`. If it says
`attributed 0`, the capture source is wrong (see Step 1) or the sshd is not
writing to it — fix that before moving on, because a zero-line instance is an
attack that produced no evidence, not one that hid.

### Impossible travel (scenario B) — partly synthetic, optional

Skip this for the first pass. A single box cannot truthfully originate a login
from a distant IP, so this scenario's second leg is authored, and the runner
marks it `synthetic=True` (§2d). Run it only when you want that scenario, and
state the synthetic leg in any write-up.

---

## Step 3 — carry the files back

Copy the whole `capture/` directory back to the analyzer. Each scenario/instance
is a `.log` (the raw captured lines) plus a `_gt.csv` (ground truth, line numbers
matching the `.log`). The `_rec.json` files are the launch records — keep them,
they are the provenance.

---

## Step 4 — score them on the analyzer

On the analyzer (this machine, with the repo and the fitted detector):

```bash
uv run python results/kali/score_captured.py \
  capture/A_1.log:capture/A_1_gt.csv \
  capture/A_2.log:capture/A_2_gt.csv \
  capture/A_3.log:capture/A_3_gt.csv \
  capture/C_1.log:capture/C_1_gt.csv \
  capture/C_2.log:capture/C_2_gt.csv \
  capture/C_3.log:capture/C_3_gt.csv
```

It runs this project's real detection chain over each captured corpus and prints
instance/line detection per pair, then pools by scenario through the kill point's
own pooler. These numbers are directly comparable to the injected-synthetic
numbers in `results/`, because they go through the identical scorer.

---

## When the link exists (later)

Nothing above is wasted. On the cabled two-box setup, the same runner ships lines
live instead of writing files: add `--peer http://10.10.10.2:8000` (the
analyzer's `logdet-api` collector endpoint, which already exists and is tested),
change `--source-ip` to the Kali link address `10.10.10.1`, and drop the
`--corpus-out` file dance. Verify the link first with:

```bash
python3 -m attack_runner.linkcheck --peer http://10.10.10.2:8000
```

---

## Notes / gotchas

- **Loopback source IP.** Local attacks are attributed on `127.0.0.1`. If you
  forget `--source-ip 127.0.0.1`, attribution finds nothing (the record expects
  `10.10.10.1`) and you get `attributed 0`.
- **Same auth.log across runs.** Each `--auth-file` run reads the whole file, so
  a later instance's `corpus.log` also contains earlier instances' lines. That is
  harmless: the ground truth only labels the lines in *that* instance's time
  window, and the scorer ignores unlabelled lines (they act as background, the
  same as the kill-point corpus's real background). Score each pair on its own.
- **Nothing is cracked.** Every attempt uses a wrong password or a nonexistent
  user. The attacks generate failed-auth log lines and change nothing on the
  host.
- **hydra vs ssh.** If `hydra` is missing the brute force still works via an
  `ssh` loop, producing the same `Failed password` lines one at a time. The
  `_rec.json` says which tool ran.

---

## Continuing work on Kali via git

`attack_runner` now also lives in its own private GitHub repo, so the Kali box can
pull it directly instead of copying a tarball each time:

    https://github.com/Vaishakh11000/log-anomaly-attack-runner  (private)

On Kali, first time (needs a GitHub login on that box — `gh auth login`, or an
HTTPS token):

    git clone https://github.com/Vaishakh11000/log-anomaly-attack-runner.git
    cd log-anomaly-attack-runner
    python3 -m attack_runner.cli --help        # stdlib only, no install

To pick up later changes on Kali:

    git pull

Running attacks needs only Python 3's standard library. `pytest` is optional and
only needed if you want to run the test suite on Kali (`pip install pytest`); it
is not needed to generate attacks.

### Keeping the two copies in step (maintainer note — do this on the analyzer)

This standalone repo is a **mirror** of the `attack_runner/` directory inside the
private `log-anomaly-detector-fork`. The fork is the source of truth; the mirror
is what Kali pulls. After changing anything under `attack_runner/` in the fork
(and committing it there), push the update to the mirror:

    git subtree push --prefix=attack_runner kali main

`kali` is the git remote pointing at the standalone repo (added once with
`git remote add kali https://github.com/Vaishakh11000/log-anomaly-attack-runner.git`).
This never touches the fork's own `origin`.

**The one thing that can silently rot:** `attack_runner/attack_runner/camouflage.py`
is a vendored byte-for-byte copy of `src/logdet_eval/camouflage.py`. The drift
test (`tests/test_camouflage_vendor.py`) guards it **only inside the fork**, where
the original is present; on the standalone clone it skips. So whenever
`src/logdet_eval/camouflage.py` changes: re-copy it into the vendored path, let
the fork's drift test confirm they match, commit, **then** run the subtree push
above. Do not edit the vendored copy directly.
