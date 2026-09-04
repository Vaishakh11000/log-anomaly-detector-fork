# First authentic Kali attacks, scored — reading the result

Interpretation kept out of any generator (bake-off precedent). The numbers in
`score.txt` are computed; the reading below is authored.

Run: 2026-09-04. Real attacks launched on the Kali box against its own sshd
(`attack_runner`, offline `--corpus-out` path — the boxes are not cabled yet),
captured with ground truth, carried back here, and scored through this project's
real detection chain (`results/kali/score_captured.py` → `detect_on_log` +
`logdet_eval.scoring`, the same code every number in `results/` uses).

- 3× brute force via **hydra**, 3× enumeration via **ssh** (from the `_rec.json`).
- Base attacks are genuine tool output; nothing here is fabricated or camouflaged.

## The headline

| scenario | tool | instance detection | line detection |
|---|---|---|---|
| A brute force | hydra | **0% (0/3)** | 0% |
| C enumeration | ssh | **33% (1/3)** | 16% |

Against the synthetic corpus's 100% instance detection on the same scenarios.
**This is not directly comparable to that 100%, and the gap is mostly the corpus,
not the detector — but part of it is a genuine detector weakness.** Both halves
matter; taking either alone would be dishonest.

## What went right (do not lose this in the bad number)

- **The authentic pipeline works end to end with no link.** Real hydra/ssh →
  real modern-sshd auth lines → attribution → a scoreable pair → scored here.
  This is the §2d goal (real tool output replacing injected synthetic lines) and
  it is achieved.
- **Modern sshd parses cleanly.** The lines are OpenSSH 9.x
  (`sshd-session[pid]`, `srclimit_penalise`, penalty drops), which this project
  had never seen. `preprocess_file` still extracts user and IP correctly, e.g.
  `Failed password for root from <IP> port <PORT> ssh2` → user=root, ip set. So
  the misses below are **not** a parse bug.

## Why the number is not comparable to synthetic 100%

Three confounds, each real, listed strongest first.

1. **No benign per-user baseline.** Each capture is ~90–130 lines, almost all of
   it sshd startup and the attack itself; the attacked accounts (`root`, and the
   enumerated users) have essentially **no normal history** in the corpus. The
   per-line Isolation Forest flags a user's *unusual* lines, so if a user's
   *only* lines are the attack, a brute-force burst is the norm for that user and
   nothing stands out. On the synthetic and kill-point corpora the attack is
   injected into rich real benign traffic, which is exactly what gives the burst
   something to be anomalous against. A bare capture removes that, so the
   attacker's own traffic becomes the entire definition of "normal".
2. **A brute-force burst is a dense cluster, not an outlier.** This is the
   project's known precision weakness (0.29, §Known Issues) seen from the other
   side: 20 near-identical `Failed password for root` lines are self-similar, so
   an outlier detector ranks them as inliers. What flagged instead were the
   *rare* lines — the one-off `Invalid user admin`, the startup banners, the
   `srclimit_penalise` messages — i.e. the enumeration lines and noise, not the
   brute force. It is the reason grouping + the impossible-travel rule + the
   sequence model exist; none of those help a bare burst with no baseline.
3. **Whole-auth.log captures overlap.** Each `--auth-file` run read the entire
   growing `auth.log`, so a later instance's corpus also contains earlier
   instances' lines, and each is scored only against its own ground-truth window.
   This is documented and harmless for a single instance, but it means the
   per-file "flagged" set includes other instances' lines, muddying per-instance
   attribution. Injecting one attack into a fixed background removes this too.

## The genuine detector finding inside the confound

Even discounting the corpus problem, **a real hydra brute force against a modern
sshd is quieter than the synthetic one.** OpenSSH 9.x rate-limits
(`srclimit_penalise`, `drop connection … penalty`), so a 20-attempt hydra run
produced only ~1 `Failed password` plus benignly-phrased `Received disconnect` /
`Connection closed by authenticating user` lines per instance. The synthetic
generator emits a clean burst of 15–25 `Failed password` lines. So authentic
brute force presents *less* of the signal the detector keys on — a finding worth
keeping regardless of the baseline issue.

## The comparable measurement (next step, not done here)

Inject these **authentic captured attack lines** into the real OpenSSH benign
background — exactly what `corpus_openssh.build_killpoint_corpus` does with
*synthetic* scenario generators, but with real captured lines — then score. That
gives the per-user benign baseline back and removes the overlap, making the
number directly comparable to the synthetic and kill-point results. It needs a
new injection path (interleave captured lines into the background, re-stamp
consistently, renumber ground truth) and is real Stage 6 work. Until then, the
table above is a **standalone lower bound**, not this detector's score on
authentic attacks.

## Bug found and fixed on the way

The Kali agent found a real defect in `AttackRecord.covers()`: it compared
whole-second syslog timestamps against microsecond attack windows, so every
sub-second enumeration attributed **0 lines**. Fixed by flooring the start bound
to the whole second (`groundtruth.py`, +1 regression test). The captures scored
above were generated with the fix, so their ground truth is correct. Runner-usage
note recorded there too: space instances into distinct whole seconds.
