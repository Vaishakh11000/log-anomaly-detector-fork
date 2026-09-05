# Reading the adversarial results

Interpretation lives here rather than in `adversarial.py`'s report generator,
following the bake-off precedent: a generator that writes conclusions is
scripting the narrative.

## The 2026-09-05 re-cut, and why the artifact had stopped reproducing

The committed 2026-08-18 `adversarial_results.json` no longer reproduced at
HEAD. One condition disagreed:

| condition | committed 2026-08-18 | fresh run at HEAD |
|---|---|---|
| `realistic-combo` | 703 flagged lines, 670 incidents | **705 flagged lines, 673 incidents** |
| the other eight | identical | identical |

Line detection (0.776) and instance detection (0.911) were identical in both,
so nothing about what the system *detects* had moved — only how many lines it
flagged in total, and how many incidents those grouped into.

The suspected cause on file was the 2026-08-30 preprocessing widening (the
process field accepting parentheses), which had been verified byte-identical on
`synthetic.log` and `SSH.log` but never on a camouflaged corpus, and
`noise`/`realistic-combo` inject `CRON`/`systemd` filler those corpora do not
contain.

**That hypothesis is false.** Three checks, each eliminating one suspect:

1. **Corpus generation is identical.** All 45 (5 seeds × 9 conditions)
   camouflaged corpora were rebuilt at HEAD and at the artifact's own commit
   (`40b0318`) and hashed: **45/45 byte-identical**, log file and ground-truth
   CSV both.
2. **Parsing is identical.** The five `realistic-combo` corpora were parsed with
   HEAD's `LOG_LINE_RE` and with the pre-widening one, and every parsed record
   hashed: **identical on all five seeds**. The widening is not implicated — the
   CRON filler's parentheses are in the *message* (`(root) CMD (...)`), which the
   old pattern already accepted, not in the process field.
3. **The old code gives the new numbers.** Running the artifact's own commit
   against those same corpora *today* reads **705 / 673** — HEAD's numbers, not
   the committed ones. Same code, different answer, so what changed is the
   environment, not the repository.

### The actual cause: CPU thread count

| `OMP_NUM_THREADS` | flagged lines | incidents |
|---|---|---|
| 1, 4, 8 | **703** | **670** |
| 16, 20 (this box's default; `nproc` = 20) | 705 | 673 |

The committed artifact reproduces **exactly** at 8 threads or fewer. It was cut
on a narrower CPU; the current demo box is an i7-13650HX, 14c/20t. BLAS and
torch change their reduction order with the thread count, embeddings differ in
the last few float bits, and rows whose anomaly scores are near-tied reorder
around the `contamination` cutoff.

Reproduce the old figures on this machine:

```bash
OMP_NUM_THREADS=8 MKL_NUM_THREADS=8 OPENBLAS_NUM_THREADS=8 \
    uv run logdet-adversarial --seeds 5 --output-dir /tmp/adv8
```

### What flips is benign traffic only

The differing lines, across every seed, are `Failed password for admin ...` and
`systemd[1]: Started Session N of user admin` — **zero attack lines**. They sit
in the `admin` per-user bucket, which the `noise` strategy floods with
near-duplicate filler, so that bucket carries the largest band of near-tied
scores at the cutoff.

This is why the disagreement showed up in the incident count and the flagged-line
count while line and instance detection stayed bit-identical: the sensitivity is
entirely on the precision side and never touches whether an attack is found.

`realistic-combo` is the only condition affected because it is the only one that
combines `noise` (which creates the ties) with the volume and timing transforms
that shift scores; the other eight have no ties close enough to the cutoff to
flip.

### What was decided

The artifact is **re-cut at the box's natural configuration** — no thread pinning.
Pinning `OMP_NUM_THREADS` would make the old numbers come back, but which lines
get flagged would then depend on an environment variable, which is a
detection-affecting knob smuggled in as configuration; every other result in
`results/` was produced without it.

Standing caveat this establishes, worth carrying into any write-up: **incident
counts and flagged-line counts in this project are reproducible to about ±0.5%
across machines, not exactly.** Detection rates — line and instance — are exact.
When quoting an alert-volume figure, quote it as approximate, and state the
machine.
