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
§4-admissible (needs ≥5 recorded seeds over real captures, and one instance has
no independent sample). The real measurement is one command once the authentic
captures exist:

```bash
uv run python results/kali/multisource_run.py \
  --ssh capture/A_1.log:capture/A_1_gt.csv ... \
  --web capture/W_1.log:capture/W_1_gt.csv ... --seeds 5
```

### What the Kali session must produce

`attack_runner/KALI_RUNBOOK.md` Step 2b: install/start nginx, run
`web_bruteforce` three times (W_1..W_3) capturing from `access.log`, alongside
the usual A_*/C_* ssh captures. Carry `capture/` back and run the command above.

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
