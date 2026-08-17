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

**Stage 0 — foundation.** The code here is currently v1's code, unmodified. See the
stage checklist in `CLAUDE.md` §3.

Roadmap in brief: foundation → benchmark platform (third-party SIEM baselines, real
LogHub data) → live ingestion → detection depth (Drain3, sequence modelling) →
entity-graph correlation + ATT&CK STIX → LLM faithfulness evaluation → adaptive
adversary → multi-source.

Benchmark platform comes before detection work on purpose: without automated
measurement you cannot tell whether a change helped, and detection changes *feel*
better far more often than they measure better.

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

## Run

v1 entry points, valid until Stage 0 restructures the package:

```bash
uv run python src/preprocessing.py --input data/raw/synthetic.log \
    --output data/processed/parsed.csv --year 2026
uv run python src/pipeline.py --input data/processed/parsed.csv --no-llm
uv run python src/adversarial.py     # robustness eval, 5 seeds, ~8 min
uv run python src/evaluate.py        # baseline comparison, ~5 min
uv run streamlit run src/dashboard.py
```

## Hardware reality

CPU-only, 16GB RAM, **~5GB actually free** with a desktop session running. This is the
binding constraint on the roadmap — Ollama, a full Wazuh/Elastic stack, and multi-source
ingestion cannot all run at once on this machine. Check free memory before adding a stack.
