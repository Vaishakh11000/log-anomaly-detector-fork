# Collector / analyzer split (Docker Compose)

This is the deployment half of Stage 7: the ingestion role and the detection
role run as two separate containers, split by **role, not clustered for
compute** (CLAUDE.md §2c). It makes physical the decoupling the single-box code
already had between `CollectorSink` (writes a file) and the stream (reads and
scores it).

```
  Kali shipper  ──HTTP──▶  collector  ──shared file──▶  analyzer  ──HTTP──▶  dashboard / API
 attack_runner            (light, :8001)   (volume)    (heavy, :8000)
```

## The two services

| | collector | analyzer |
|---|---|---|
| Image | `Dockerfile.collector`, ~240 MB | `Dockerfile.analyzer`, ~2 GB (CPU torch) |
| Imports | web stack only — **no detection code** | full detection stack |
| Starts in | well under a second | tens of seconds (torch import) |
| Does | receives `POST /collector/ingest`, appends to the shared file | tails that file, scores it, serves `/incidents` |
| Port | 8001 | 8000 |

The two meet **at the file on the `collector-log` volume, never on the
network**. That is the durability the split buys: the collector stays up and
keeps buffering while the analyzer restarts, and the analyzer's stream resumes
from its own byte offset into the file, so a restart neither skips nor
re-scores. That byte-offset store lives on the writable `collector-log` volume
(`data/live/stream_offset.json`), **not** under `models/` — which is mounted
read-only and would crash the stream on its first offset commit if the offset
went there (found and fixed when the image was first built and run).

## Prerequisites (stated honestly)

- **A fitted detector at `./models/detector.joblib`.** Run `logdet-fit` on the
  host first; it is mounted read-only into the analyzer. Without it the
  analyzer's API still comes up, but `/stream/start` fails — visibly, on
  `/stream/status` — rather than scoring nothing in silence.
- **Narration (the LLM) is optional and not wired here.** Point the analyzer at
  a host Ollama if you want per-incident narratives; without one, `/narrate`
  degrades to a 503 and everything else works.

## Run

```bash
# on the host, once: fit a detector the analyzer will mount
uv run logdet-preprocess --input data/raw/synthetic.log --output data/processed/parsed.csv --year 2026
uv run logdet-fit --input data/processed/parsed.csv        # -> models/detector.joblib

docker compose up --build           # first analyzer build is slow (torch)

# ship a line at the collector (what Kali's attack_runner does over the link)
curl -s -X POST localhost:8001/collector/ingest \
     -H 'content-type: application/x-ndjson' \
     --data-binary '{"line": "Jul 18 10:00:00 LabSZ sshd[1]: Failed password for root from 10.10.10.1 port 22 ssh2"}'

# read what the analyzer made of the shipped stream
curl -s 'localhost:8000/incidents?notable=true&limit=5'
curl -s  localhost:8000/stream/status
```

For the two-machine demo (CLAUDE.md §2c) the collector runs on the box the
attacks are launched from and publishes 8001 on the direct link; the analyzer
runs on the GPU box. The collector image is the only thing that needs to be on
the monitored side, which is why it carries none of the detector.

## What is verified, and what is not

The collector image is built and exercised in CI-shaped tests
(`tests/test_collector_app.py`), including a check that importing it pulls in
**no** torch / sentence-transformers / scikit-learn.

The analyzer image is now **built and verified end to end** (2026-09-05,
~4.3 GB on disk). Booted from the fitted detector mounted read-only, its
entrypoint auto-started a follow-stream on the shared collector file with no
manual `/stream/start`; a `Failed password` burst appended to that file was
parsed 14/14, scored, and grouped into one incident (`incidents_total: 1`,
`error: null`). The offset-store bug above surfaced on that first run and is
fixed in `analyzer-entrypoint.sh`.

`docker compose` was not available on the build box, so the compose file was
validated as YAML and the collector and analyzer images were each built and run
directly (`docker build -f docker/Dockerfile.<role>`); `docker compose up
--build` is the intended one-command path once the plugin is installed.
