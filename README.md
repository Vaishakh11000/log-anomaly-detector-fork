# log-anomaly-detector-fork

Development fork of **LLM-Powered Log Anomaly Detector with Attack Narrative &
Adversarial Robustness**.

Detects anomalies in system/auth logs using embedding-based unsupervised learning,
stitches related anomalies into a MITRE ATT&CK-mapped attacker narrative via a local
LLM, and — the part that distinguishes it — **continuously measures how much detection
degrades when the attacker actively tries to hide.**

> **Building this with AI assistance? Read [`CLAUDE.md`](CLAUDE.md) first.** It holds
> project state, constraints, the staged roadmap, and the benchmark rule that keeps the
> numbers honest.

## The result, up front

Full reading in **[`docs/FINDINGS.md`](docs/FINDINGS.md)** — read that before anything
else here.

Against **Wazuh** (the real manager, its own rules and engine) on real LogHub OpenSSH
traffic with attacks injected, pooled over 5 seeds:

> **Against reworded attacks, signature rules break and embeddings do not — a real,
> explainable, reproducible mechanism. Against timing and IP rotation the embedding
> detector is the *weaker* system. Under an attacker that optimises rather than picking
> from a fixed menu, the advantage disappears entirely. And precision resists five
> separate fixes, each measured and rejected because it cost adversarial margin.**

Three numbers qualify that, and they are stated first on purpose:

| | Number |
|---|---|
| Tally across the eight camouflage strategies | **1 win, 4 ties, 3 losses** |
| `realistic-combo` — the strategy closest to a real attacker — is a loss | **−13.3pt** |
| Conservative differential under an *optimising* attacker | **−2.2pt** (negative) |

The one win is `rephrase` at **+31.1pt**, which clears the pre-registered ≥25pt bar
(`CLAUDE.md` §1b) and is why the roadmap continued. It is **one mechanism, not a general
property**: Wazuh's sshd rules match literal strings, so rewording a line drops it out
of the decoder, while an embedding of a reworded line stays near the original.

**Four results are not differentials and cannot come back negative** — 1,415 incidents
against Wazuh's 4,546 alerts on the clean corpus (~3.2× more from the SIEM); Wazuh's
100% being level-3 saturation, since at level 7 it detects 11.1% on the *clean* corpus;
invented MITRE technique IDs going 47/142 and 119/197 → **0 and 0** under structured,
validated output, on two corpora and two models; and authentic `hydra`/`ssh` attacks
holding **100% instance detection on all nine camouflage conditions** (50/50 pooled).
[`docs/FINDINGS.md`](docs/FINDINGS.md) §4.

Caveat that travels with every alert-volume figure here: **incident and flagged-line
counts reproduce to about ±0.5% across machines; detection rates are exact**
(`results/adversarial_notes.md`).

## Where things live

| Repo | Role |
|---|---|
| `Project` @ `v1.0-submission` | Submitted academic artifact. Frozen; report writing only. |
| `log-anomaly-detector-demo` | Standalone frozen demo. Ships `data/processed/`, runs offline. See its `RUN.md`. |
| **this repo** | Active development. |

Inherited context lives in [`docs/`](docs/):
`CLAUDE.v1.md` (original project doc — its Decision Log is still authoritative history),
`results.v1/` (the evaluation baseline every future change is measured against),
`DEMO.v1.md` (v1 runbook, kept for its honest-answers Q&A).

## Status

**All eight stages are closed** (foundation, benchmark platform, live ingestion, live
bake-off, detection depth, correlation + ATT&CK, LLM maturity, adversarial platform,
multi-source + deployment). The project is in **finishing** mode, not building mode: the
default answer to "what next" is nothing, and `CLAUDE.md` §3 records which remaining
ideas were declined and on what measured grounds.

What was built, in order: foundation → benchmark platform (third-party SIEM baselines,
real LogHub data) → live ingestion → detection depth (Drain3, sequence modelling) →
entity-graph correlation + ATT&CK STIX → LLM faithfulness evaluation → adaptive
adversary + authentic Kali attacks over a two-machine link → multi-source + Docker
split.

Benchmark platform came before detection work on purpose: without automated measurement
you cannot tell whether a change helped, and detection changes *feel* better far more
often than they measure better.

**The roadmap was gated.** A kill point was pre-registered in `CLAUDE.md` §1b before any
Stage 1 code existed: ≥25pt differential against a ruleset the author did not write →
build the rest; &lt;10pt → stop and publish the negative result. It returned **CONTINUE
at 31.1pt on 2026-08-19**, on one strategy, with three losses beside it — see
[`docs/FINDINGS.md`](docs/FINDINGS.md).

## The numbers to beat

| Metric | v1 |
|---|---|
| Line-level P / R / F1 | 0.29 / 0.86 / 0.43 |
| Instance detection, clean | 100% (9/9) |
| Instance detection, worst camouflage | 80% |
| Recall under realistic camouflage — system vs rule baseline | 0.78 vs 0.07 |
| Alert volume | 94 incidents for 9 real attacks |

Precision is no longer an open target: **five levers were tried against it and five were
measured and rejected**, four because clean data hid a cost the camouflage suite could
see. What survived is alert suppression at q0.90 — real but modest (194 → 147 incidents
on the real corpus, precision 0.206 → 0.248, recall untouched). Table in
[`docs/FINDINGS.md`](docs/FINDINGS.md) §4.

Robustness under camouflage is the strongest result here and must not regress to fix
precision — but it is **one mechanism** (`rephrase`), not a general property.

## Setup

```bash
export PATH="$HOME/.local/bin:$PATH"   # uv is not on PATH in fresh shells
uv sync
```

Narrative generation needs a local LLM via Ollama:

```bash
ollama serve
ollama pull phi3
```

## Layout

Two packages, and the boundary between them is load-bearing:

```
src/logdet/        the detection pipeline -- parsing, embeddings, detection,
                   grouping, MITRE mapping, narrative, interfaces
src/logdet_eval/   the evaluation track -- synthetic corpus, camouflage suite,
                   rule baselines, benchmark harness
tests/             pytest; runs in ~30s with no model download
```

`logdet_eval` imports `logdet` freely. **The reverse is forbidden** — measuring a system
with code that system depends on is how benchmarks lie (`CLAUDE.md` §5). The rule is
enforced statically in `tests/test_layering.py`, not left to discipline.

## Run

```bash
uv run pytest                        # ~30s, no model download

uv run logdet-preprocess --input data/raw/synthetic.log \
    --output data/processed/parsed.csv --year 2026
uv run logdet-pipeline --input data/processed/parsed.csv --no-llm
uv run logdet-adversarial            # robustness eval, 5 seeds, ~8 min
uv run logdet-adversarial --seeds 1  # quick pass while iterating
uv run logdet-evaluate               # baseline comparison, ~5 min
uv run logdet-generate               # regenerate the synthetic corpus
uv run streamlit run src/logdet/dashboard.py
```

Live mode fits a detector on history, then scores a tailed log against it — the
stream never re-fits, so a long-running attack cannot teach the model that it is
normal:

```bash
uv run logdet-fit --input data/processed/parsed.csv      # -> models/detector.joblib
uv run logdet-stream --input /var/log/auth.log           # follow, alert as it goes
uv run logdet-stream --input data/raw/synthetic.log --once   # replay a file, then exit
```

The tailer records its byte offset, so a restart neither re-alerts on old lines nor
skips what arrived while it was down. Incidents are emitted `open` while they can
still grow and `closed` once nothing further can join them.

Paths in `config.py` resolve against the repo root, so these work from any directory.
New results land in `results/`; `docs/results.v1/` is frozen and never written to.

## Hardware

The dev environment lives on a **portable USB SSD**, so the analyzer role is wherever
the SSD boots. Two roles, split by **role, not clustered** (`CLAUDE.md` §2c-2d):

- **Analyzer** — gaming laptop, RTX 4060 8GB, booting the SSD. Detector, embeddings,
  sequence models, Ollama, UI.
- **Adversary + monitored host + SIEM** — office laptop, Kali on its own NVMe. Runs real
  attack tools (hydra/nmap), emits logs, runs the third-party SIEM.

Linked by a direct gigabit ethernet cable, no switch. Not campus WiFi; client isolation
commonly blocks laptop-to-laptop traffic. Move the SSD to the gaming laptop at the start
of Stage 2 — not before; Stages 0-1 and the kill point are one-machine, CPU-fine.

**CPU single-box is the supported floor and must always work.** The GPU, the second
machine, and the link are accelerators, never requirements — "runs on a laptop with no
GPU" is a differentiator worth protecting.
