#!/usr/bin/env bash
#
# reveal-credential.sh — owner-only raw credential reveal for a completed run.
#
# Raw credential values are, by design, only revealable over the api container's
# LOOPBACK interface (never across the public network). This helper runs the
# reveal call *inside* the api container, where the request originates from
# 127.0.0.1 and therefore satisfies the loopback owner gate.
#
# Prerequisites:
#   - ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true in .env.production
#   - the run has reached a state with captured/emailed credential references
#
# Usage:
#   ./scripts/reveal-credential.sh <run_id>
#   COMPOSE=compose.yaml ./scripts/reveal-credential.sh <run_id>   # local dev
#
# Output: a JSON object { "run_id": ..., "credentials": { kind: value, ... } }.
# Handle the output as a secret — it is the one deliberate raw-secret boundary.
set -euo pipefail

RUN_ID="${1:?usage: reveal-credential.sh <run_id>}"
COMPOSE_FILE="${COMPOSE:-compose.prod.yaml}"

docker compose -f "$COMPOSE_FILE" exec -T api python - "$RUN_ID" <<'PY'
import json, os, sys, urllib.error, urllib.request

run_id = sys.argv[1]
token = os.environ.get("OPS_INTERNAL_API_TOKEN")
if not token:
    print("OPS_INTERNAL_API_TOKEN is not set in the api container", file=sys.stderr)
    raise SystemExit(1)

request = urllib.request.Request(
    f"http://127.0.0.1:8000/api/runs/{run_id}/credentials/reveal",
    method="POST",
    headers={"X-Ops-Internal-Token": token},
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print(json.dumps(json.loads(response.read().decode()), indent=2))
except urllib.error.HTTPError as exc:
    body = exc.read().decode(errors="replace")
    print(f"reveal failed: HTTP {exc.code}\n{body}", file=sys.stderr)
    raise SystemExit(1)
PY
