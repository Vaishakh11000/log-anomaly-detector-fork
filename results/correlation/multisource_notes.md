# Multi-source correlation — the corpus Stage 4 lacked, built at Stage 7

Stage 4 declined multi-source correlation and recorded why (this directory's
`notes.md`): the only real multi-service log here, `Linux.log`, carries **one**
genuine cross-service link in 9,666 events, so the graph would have nothing to
correlate, and any measurable link would have to be an attack the author planted
across two logs — the trap §1b/§8 exist to keep out.

Stage 7 removes the blocker on both counts.

## The format gap is closed, and correlation needs no detection change

`logdet/weblog.py` parses nginx/Apache access logs into the same eight internal
columns an sshd line reduces to. The entity graph keys grouping on `source_ip`
and never cared which parser produced a row, so a web line and an ssh line from
one IP already group into one incident with **no change to detection, grouping
or scoring**. Proven directly:

- A hand-built corpus (a 401 credential-stuffing burst + an ssh brute force from
  one IP, both flagged) groups into a **single `nginx`+`sshd` incident**
  (`tests/test_corpus_multisource.py`).
- A naive concatenation of a web parsed CSV and an auth parsed CSV feeds
  `logdet-pipeline` unchanged — the two parsers emit different timestamp string
  forms (web ISO-`T`, syslog space-separated) and `parse_dates` reads both, so
  no concat fix is owed.

So this stage is **corpus + measurement**, not detection code. §4 does not apply.

## The attack gap is closed authentically, not by planting one

Both halves of the cross-source attack are authentic tool output captured on the
Kali box:

- **ssh half** — `attack_runner brute_force`/`enumeration` (scenarios A/C), as
  before.
- **web half** — new `attack_runner web_bruteforce` (scenario **W**): a real
  `hydra http-post-form` or `curl` credential-stuffing burst, captured from the
  server's own access log by `capture.capture_access_file`, attributed by the
  same identity+time rule as the ssh captures.

Only two things are authored, and both are stated:

1. **The shared source IP.** Two captures on one box do not share an
   internet-routable address, so the attack rows of both halves are overwritten
   onto one IP. This is safe for detection — `template` masks every IP before
   the embedder sees it — and it is the whole point for correlation, which is
   the graph's `source_ip` join. Only the *attack* rows are overwritten, so the
   join is not made trivial by giving all traffic one address.
2. **When each pair is injected**, drawn from the same distribution
   `corpus_captured` uses; the ssh and web halves are placed a few minutes apart
   (`CROSS_SOURCE_GAP`, inside the 30-minute incident window), because a real
   "web probe then ssh brute force from the same host" is a sequence, not one
   instant.

`corpus_multisource.build_multisource_corpus` does the injection into the real
OpenSSH benign background — the same background `corpus_captured` uses, so the
ssh half's target (`root`) gets its genuine per-user baseline, the thing a bare
standalone capture lacked. An optional real benign nginx background can be added
for the web side (`--web-background`).

## Wiring proven end to end; the real numbers await the Kali captures

`results/kali/multisource_run.py --smoke` builds a corpus from tiny
authentic-shaped fixtures, runs the **real** detection chain (embed → Isolation
Forest → grouping), scores each source, and reports cross-source incidents. On
the smoke fixtures it reads **1 cross-source incident, overall line rate 1.000**
— both halves detected and correlated into one alert.

That is a wiring check, not a measurement: one toy instance per source is not
§4-admissible. The real measurement is one command, and it has now been run —
see below.

## The real measurement (2026-09-05)

Authentic captures were produced on the Kali box (`KALI_RUNBOOK.md` Step 2b):
three `web_bruteforce` instances (W_1..W_3) captured from a live nginx access
log, paired by index with three real ssh brute-force instances (A_1..A_3). Both
halves were injected into the real OpenSSH benign background sharing one source
IP, and the full detection chain (embed → Isolation Forest → grouping) was run
over five seeds:

```bash
uv run python results/kali/multisource_run.py \
  --ssh results/kali/capture/A_{1,2,3}.log:..._gt.csv \
  --web results/kali/capture/W_{1,2,3}.log:..._gt.csv --seeds 5
```

Result (`results/kali/multisource_AW.json/multisource.json`):

| seed | cross-source incidents | ssh (A) instances | web (W) instances | overall line rate |
|---|---|---|---|---|
| 42–46 (each) | **3 / 3** | 3/3 (line 0.60) | 3/3 (line 1.00) | 0.956 |

**Every ssh+web pair from one IP was correlated into a single alert, on all five
seeds.** Each such incident carries both an `nginx` line and an ssh line
(`sshd-session` on the modern captures) on the shared IP `203.0.113.66` — one
host attacking two services is one incident, not two, which is the Stage 7
question answered as a number. The web half is detected at 100% of its lines (an
anomalous 401 burst grouped by source IP, exactly as predicted for user-less
traffic); the ssh half at 100% of instances (0.60 of lines, the authentic
brute-force shape — few `Failed password` lines against a rate-limiting modern
sshd, as in every authentic run). ~187–191 incidents per seed overall.

**One counter bug found and fixed.** The first run reported 0 cross-source
incidents while both halves were plainly detected: the correlation counter
required the literal process name `sshd`, but authentic modern-OpenSSH captures
log the per-connection worker as `sshd-session`. The counter now matches any
`sshd`-prefixed process. The correlation itself never failed — the grouping had
produced the three `nginx`+`sshd-session` incidents all along.

**Honest scope.** This is authentic on both sides and ≥5 seeds, but the five
seeds are five placements of the *same* three ssh + three web captures, so the
effective independent sample is three per source (§4's ≥5-seed rule met in
letter; the fix is capture variety, as for every authentic run). The web attack
ran against a user-space nginx on Kali (`127.0.0.1:8080`, no sudo available for
the system service) via the `curl` path, because `hydra http-post-form` bails on
a bare-401 endpoint; both produce the same authentic same-IP 401 burst.

### What the Kali session produced

`attack_runner/KALI_RUNBOOK.md` Step 2b: start nginx, run `web_bruteforce` three
times (W_1..W_3) capturing from `access.log`, alongside the A_*/C_* ssh captures.
Carried `capture/W_*` back and ran the command above.

## A second pairing: enumeration × web (2026-09-05)

The A×W run pairs a brute force with the web attack; correlation joins on
`source_ip` and does not read scenario, so it should hold for *any* ssh scenario
from the shared IP. Confirmed by pairing the enumeration captures (scenario **C**,
`capture_v2/C_1..C_3`) with the same three web captures over five seeds:

```bash
uv run python results/kali/multisource_run.py \
  --ssh results/kali/capture_v2/C_{1,2,3}.log:..._gt.csv \
  --web results/kali/capture/W_{1,2,3}.log:..._gt.csv --seeds 5 \
  --output results/kali/multisource_CW
```

Result (`results/kali/multisource_CW/multisource.json`):

| seed | cross-source incidents | ssh (C) instances | web (W) instances | overall line rate |
|---|---|---|---|---|
| 42–46 (each) | **3 / 3** | 3/3 (line 0.889–1.00) | 3/3 (line 1.00) | 0.98–1.00 |

**Every enumeration+web pair from one IP correlated into a single alert, on all
five seeds** — same 3/3 as the brute-force pairing. Each cross-source incident
carries an `nginx` line and an `sshd`/`sshd-session` line on the shared IP. The
enumeration half detects at a higher line rate than the brute-force half (0.889–
1.00 against A's 0.60), because authentic `Invalid user` enumeration lines are
individually more anomalous than the thin `Failed password` shape a rate-limiting
sshd leaves. Same honest scope: five placements of the same 3 C + 3 W captures,
so the effective independent sample is three per source.

### Limits carried in advance (the same shape as every authentic run)

- Web traffic is mostly **user-less**, so the per-user Isolation Forest has
  little to work with on the web half — it is detected as an anomalous 401 burst
  and grouped by source IP, which is exactly what correlation is for.
- The captures are placed N ways from a small number of real captures, so the
  effective independent sample is the number of *distinct* captures, not the
  seed count (§4's ≥5-seed rule met in letter; the fix is capture variety).
- Scenario B (impossible travel) stays synthetic by necessity (§2d) and is not
  part of the cross-source corpus.

## Reproducing the wiring check

```bash
uv run python results/kali/multisource_run.py --smoke --seeds 1
uv run pytest tests/test_corpus_multisource.py attack_runner/tests/test_web_attacks.py -q
```
