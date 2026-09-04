# CLAUDE.md — Kali attack-runner box

> **Read this first.** You are Claude Code running on the **Kali adversary box**
> of a log-anomaly-detection project. This repo (`attack_runner`) is the *only*
> part of that project present here. Your job on this machine is to generate
> **authentic** attack traffic against a local sshd, capture the real log lines
> it produces with ground truth, and leave a scoreable bundle for the human to
> carry back to the analyzer machine. You do **not** do detection or scoring on
> this box — there is no detector, no embedding model, and no dataset here.

## 0. Where this fits (so you don't look for things that aren't here)

The full project lives in a separate **private** repo the analyzer machine holds
(`log-anomaly-detector-fork`). This box deliberately has only `attack_runner`,
because the project's dev SSD can only be in one machine at a time, so the Kali
side must run **standalone, with no main repo checked out**. Consequences you
must respect:

- **This repo is a read-derived mirror.** The source of truth is the fork. Do
  **not** try to "improve" the attack/camouflage logic here — a change made on
  this box cannot be merged back cleanly and will silently diverge. Fix bugs
  only if they block a run, keep the diff tiny, and tell the human it needs
  porting to the fork. Normal edits to logic belong on the analyzer, not here.
- **`attack_runner/camouflage.py` is a vendored byte-for-byte copy** of the
  fork's `src/logdet_eval/camouflage.py`. Never edit it here. The drift test
  that guards it (`tests/test_camouflage_vendor.py`) only runs where the fork's
  original is present, so it will *skip* on this box and cannot protect you.
- **The detector, the scorer, and the results live on the analyzer.** When you
  produce a capture, your deliverable is files for the human to carry back;
  scoring happens there with `results/kali/score_captured.py`.

## 1. What "authentic" means here — the one rule that matters

The whole reason this box exists is that the attack *base* must be **real tool
output**, not fabricated log lines. So:

- Attacks are launched by driving real tools (`hydra`/`medusa`, or an `ssh`
  loop) against a real sshd. `attacks.py` returns an `AttackRecord` describing
  *what it launched* — it never writes a log line it claims was produced.
- The log lines come from the **sshd's own auth stream** (`/var/log/auth.log` or
  journald), read by `capture.py`.
- Ground truth is attribution **by identity + time** (`groundtruth.py`): a
  captured line belongs to an attack when its source IP is one the attack used
  and its timestamp is in the attack's window. This is deliberately
  conservative — ambient traffic from the same IP in the window is swept in,
  because the log genuinely cannot tell them apart, and pretending otherwise
  would flatter the result.
- **Only the camouflage layer is authored**, and it is the shared vendored
  transforms. Impossible-travel's distant leg is synthetic by necessity and the
  record marks it so.

**Never fabricate, hand-edit, or "top up" captured log lines to make a run look
better.** If an attack produced no lines, that is a real finding (the sshd config
swallowed them, or the capture source is wrong) — report it, do not paper over
it.

## 2. Nothing gets cracked

Every attack uses wrong passwords or nonexistent usernames. The point is to
generate *failed*-auth log lines. Do not attempt a real credential crack, do not
target anything other than the local sshd on this box unless the human explicitly
sets up a specific target, and change nothing on the host.

## 3. The environment you should expect

- Kali Linux, `python3` 3.11+. The package is **stdlib-only** — no `pip install`
  is needed to run it (`requirements.txt` is a no-op). `pytest` is needed only to
  run the test suite, not to run attacks.
- Run it as a module from the repo root: `python3 -m attack_runner.cli ...`.
- The two boxes are **not cabled together yet**, so the live shipping path
  (`--peer`) is not available. Use the **offline path** (`--corpus-out`), which
  writes files to disk.

## 4. Your tasks on this box

Confirm the session goal with the human before running attacks. Typical flow:

### 4a. Check the environment
```bash
python3 --version
python3 -m attack_runner.cli --help
command -v hydra medusa ssh sshd    # hydra/medusa optional; ssh is the fallback
```

### 4b. Ensure a real sshd is listening (needs root)
```bash
sudo systemctl start ssh || sudo /usr/sbin/sshd
ss -ltnp | grep ':22'
sudo tail -n 3 /var/log/auth.log 2>/dev/null || journalctl -u ssh -n 3
```
Installing packages or starting system services changes the machine — say what
the command does and get the human's go-ahead before running it, per the harness
rules on outward/system-changing actions.

### 4c. Run authentic attacks, offline (writes scoreable pairs)
Loopback attacks are attributed on `127.0.0.1`, so pass `--source-ip 127.0.0.1`
(forgetting it yields `attributed 0`). Three instances per scenario is what the
analyzer's evaluation wants.

```bash
mkdir -p capture
for i in 1 2 3; do
  sudo python3 -m attack_runner.cli brute_force \
    --target-host 127.0.0.1 --target-port 22 --user root \
    --source-ip 127.0.0.1 --instance $i \
    --auth-file /var/log/auth.log --year "$(date +%Y)" \
    --corpus-out capture/A_${i}.log \
    --ground-truth-out capture/A_${i}_gt.csv \
    --records-out capture/A_${i}_rec.json
done
for i in 1 2 3; do
  sudo python3 -m attack_runner.cli enumeration \
    --target-host 127.0.0.1 --target-port 22 \
    --users admin test oracle postgres git deploy \
    --source-ip 127.0.0.1 --instance $i \
    --auth-file /var/log/auth.log --year "$(date +%Y)" \
    --corpus-out capture/C_${i}.log \
    --ground-truth-out capture/C_${i}_gt.csv \
    --records-out capture/C_${i}_rec.json
done
```
On a journald-only box, drop `--auth-file …` and add `--journald-unit ssh`.
After each run, check the printed `attributed N line(s)` is non-zero.

### 4d. Verify and hand off
- Confirm each `capture/*_gt.csv` has attack rows and each `capture/*.log` exists.
- Do **not** score here — there is no detector. Tell the human to copy the whole
  `capture/` directory back to the analyzer and run
  `results/kali/score_captured.py` there.
- Write a one-line summary per instance (scenario, tool used from the
  `_rec.json`, lines attributed) so the human knows what the bundle contains.

### 4e. When the link is later connected
Verify it before anything else, then attacks can ship live instead of writing
files:
```bash
python3 -m attack_runner.linkcheck --peer http://10.10.10.2:8000   # analyzer's link IP
# then attacks with --peer http://10.10.10.2:8000 and --source-ip 10.10.10.1
```
Recording the verified transport belongs in the fork's §2c on the analyzer, not
here.

## 5. Anti-goals — stop and check with the human before doing any of these

- ❌ Fabricating or hand-editing captured log lines. The base must be real tool
  output (§1).
- ❌ Editing `attack_runner/camouflage.py` or the attack/scoring logic to change
  results. Bug-blocking fixes only, minimal, flagged for porting to the fork.
- ❌ Real credential cracking, or attacking anything but the agreed local target.
- ❌ Scoring, "detecting", or drawing robustness conclusions on this box — no
  detector or ground-truth-free corpus exists here; that is the analyzer's job.
- ❌ Committing/pushing from here as if this were the source of truth. This is a
  mirror; pushes go through the fork on the analyzer.
- ❌ Installing packages or starting services without saying what and why first.

## 6. Keep the human informed

The human is not an expert in the detection maths or the git topology — explain
in plain language, lead with the meaning before the number, and never hide a bad
result (an attack that produced no lines, a capture that attributed nothing).
Say what a command will do before running it.
