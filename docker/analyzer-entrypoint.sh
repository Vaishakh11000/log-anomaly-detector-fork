#!/usr/bin/env bash
# Boot the analyzer API, then auto-start a follow-stream on the shared collector
# file so lines the collector has buffered (before this container came up, or
# across a restart) start being scored with no manual /stream/start. The stream
# resumes from its own byte offset into that file, so a restart neither skips
# nor re-scores.
set -euo pipefail

COLLECTOR_LOG="${LOGDET_PROJECT_ROOT:-/app}/data/live/collector.log"
# The stream's byte-offset store must live on a writable path. models/ is mounted
# read-only (it carries only the fitted detector), so the offset goes on the
# shared collector-log volume, which is writable and is where the tailed file is.
OFFSET_STORE="${LOGDET_PROJECT_ROOT:-/app}/data/live/stream_offset.json"
API="http://127.0.0.1:8000"

# The API owns the stream; run it in the background and auto-start once healthy.
uv run logdet-api --host 0.0.0.0 --port 8000 &
API_PID=$!

# Wait for health rather than sleeping a fixed time -- torch import is slow and
# variable.
for _ in $(seq 1 60); do
    if curl -sf "${API}/health" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# The file must exist before a file source will tail it; the collector may not
# have written yet, so create it empty. Harmless if the collector already did.
mkdir -p "$(dirname "${COLLECTOR_LOG}")"
touch "${COLLECTOR_LOG}"

# from_start so a restart replays nothing it has an offset past, but a first
# boot reads what the collector already buffered. Follow mode (once=false) keeps
# tailing. A non-zero here (e.g. no fitted detector mounted) is logged, not
# fatal -- the API stays up so the failure is visible on /stream/status.
curl -sf -X POST "${API}/stream/start" \
    -H 'content-type: application/json' \
    -d "{\"source\":\"file\",\"path\":\"${COLLECTOR_LOG}\",\"from_start\":true,\"offset_store\":\"${OFFSET_STORE}\"}" \
    || echo "analyzer: /stream/start failed -- is a detector mounted at models/detector.joblib? API stays up; check /stream/status"

wait "${API_PID}"
