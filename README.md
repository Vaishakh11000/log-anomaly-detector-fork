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

**Stage 0 — foundation.** Package restructure, test suite, and CI are in; the
persistence layer is deferred to Stage 2, where streaming actually needs it. Detection
behaviour is unchanged from v1 and verified so — see the stage checklist in
`CLAUDE.md` §3.

Roadmap in brief: foundation → benchmark platform (third-party SIEM baselines, real
LogHub data) → live ingestion → detection depth (Drain3, sequence modelling) →
entity-graph correlation + ATT&CK STIX → LLM faithfulness evaluation → adaptive
adversary → multi-source.

Benchmark platform comes before detection work on purpose: without automated
measurement you cannot tell whether a change helped, and detection changes *feel*
better far more often than they measure better.

**The roadmap is gated.** A kill point is pre-registered in `CLAUDE.md` §1b: Stage 1
tests whether v1's robustness gap survives against a ruleset the author did not write,
in batch mode on one machine, within 4 weeks. ≥25pt differential → build the rest;
&lt;10pt → stop and publish the negative result. Everything past Stage 1 is contingent
on that number.

## The numbers to beat

| Metric | v1 |
|---|---|
| Line-level P / R / F1 | 0.29 / 0.86 / 0.43 |
| Instance detection, clean | 100% (9/9) |
| Instance detection, worst camouflage | 80% |
| Recall under realistic camouflage — system vs rule baseline | 0.78 vs 0.07 |
| Alert volume | 94 incidents for 9 real attacks |

Precision and alert volume are the weakest and the main target. Robustness under
camouflage is the strongest and must not regress to fix them.

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
