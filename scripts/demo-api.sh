#!/usr/bin/env bash
#
# demo-api.sh - scripted, secret-safe walkthrough of the Ops control-plane API.
#
# It creates a real run, then fetches run details, timeline, and output against a
# running FastAPI instance. It prints only sanitized API responses. It never reads,
# echoes, or transmits provider keys or vault values. The request body references the
# company work email as a vault:// reference, never a plaintext address.
#
# Usage:
#   scripts/demo-api.sh [API_BASE_URL] [APP_NAME]
#
# Examples:
#   scripts/demo-api.sh
#   scripts/demo-api.sh http://127.0.0.1:8000 HubSpot
#
# Environment overrides (all optional; safe defaults below):
#   DEMO_WORK_EMAIL_REF   vault:// reference for the company work email
#   DEMO_COMPANY_NAME     legal company name
#   DEMO_COMPANY_WEBSITE  https company website
#   DEMO_CALLBACK_URL     https OAuth callback URL
#   DEMO_SCOPE_POLICY     minimum | recommended | maximum
#   DEMO_EXECUTION_MODE   plan_only | execute_when_configured
#
set -euo pipefail

API_BASE_URL="${1:-http://127.0.0.1:8000}"
APP_NAME="${2:-HubSpot}"

# Normalize: strip a single trailing slash from the base URL.
API_BASE_URL="${API_BASE_URL%/}"

WORK_EMAIL_REF="${DEMO_WORK_EMAIL_REF:-vault://demo/work_email/primary}"
COMPANY_NAME="${DEMO_COMPANY_NAME:-Demo Integrations Inc}"
COMPANY_WEBSITE="${DEMO_COMPANY_WEBSITE:-https://demo.example.com}"
CALLBACK_URL="${DEMO_CALLBACK_URL:-https://demo.example.com/oauth/callback}"
SCOPE_POLICY="${DEMO_SCOPE_POLICY:-recommended}"
EXECUTION_MODE="${DEMO_EXECUTION_MODE:-plan_only}"

# --- helpers ----------------------------------------------------------------

have_jq() { command -v jq >/dev/null 2>&1; }

# Pretty-print JSON with jq when available; otherwise pass through untouched.
show() {
  if have_jq; then
    jq "${1:-.}"
  else
    cat
  fi
}

hr() { printf '%s\n' "------------------------------------------------------------"; }

section() {
  hr
  printf '>> %s\n' "$1"
  hr
}

# Generate a fresh idempotency key: idem_ + 32 lowercase hex chars.
new_idempotency_key() {
  local hex=""
  if command -v openssl >/dev/null 2>&1; then
    hex="$(openssl rand -hex 16)"
  elif [ -r /dev/urandom ] && command -v xxd >/dev/null 2>&1; then
    hex="$(head -c 16 /dev/urandom | xxd -p -c 32)"
  elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    hex="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
  else
    echo "error: need openssl, xxd, or od to generate an idempotency key" >&2
    exit 1
  fi
  printf 'idem_%s\n' "$hex"
}

require_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required" >&2
    exit 1
  fi
}

# Extract run_id from the create response without requiring jq.
extract_run_id() {
  if have_jq; then
    jq -r '.run.run_id // empty'
  else
    # Fall back to a tolerant grep for run_<32 hex>.
    grep -o 'run_[0-9a-f]\{32\}' | head -n 1
  fi
}

# --- preflight --------------------------------------------------------------

require_curl

if ! have_jq; then
  echo "note: jq not found; printing raw JSON responses." >&2
fi

echo "API base URL : ${API_BASE_URL}"
echo "App name     : ${APP_NAME}"
echo "Execution    : ${EXECUTION_MODE} (dry-run planning; no live vendor email)"

# --- 0. health --------------------------------------------------------------

section "0. Health check"
curl -sS "${API_BASE_URL}/api/system/health" | show '.'

# --- 1. create a run --------------------------------------------------------

section "1. Create run"
IDEMPOTENCY_KEY="$(new_idempotency_key)"
echo "Idempotency-Key: ${IDEMPOTENCY_KEY}"

REQUEST_BODY="$(
  cat <<JSON
{
  "app_name": "${APP_NAME}",
  "company": {
    "legal_name": "${COMPANY_NAME}",
    "website": "${COMPANY_WEBSITE}",
    "work_email_ref": "${WORK_EMAIL_REF}",
    "use_case": "Demonstrate authorized integration onboarding",
    "callback_urls": ["${CALLBACK_URL}"]
  },
  "requested_scope_policy": "${SCOPE_POLICY}",
  "execution_mode": "${EXECUTION_MODE}"
}
JSON
)"

CREATE_RESPONSE="$(
  curl -sS -X POST "${API_BASE_URL}/api/runs" \
    -H 'Content-Type: application/json' \
    -H "Idempotency-Key: ${IDEMPOTENCY_KEY}" \
    --data "${REQUEST_BODY}"
)"

printf '%s\n' "${CREATE_RESPONSE}" | show '.run'

RUN_ID="$(printf '%s\n' "${CREATE_RESPONSE}" | extract_run_id)"
if [ -z "${RUN_ID}" ]; then
  echo "error: could not determine run_id from the create response" >&2
  printf '%s\n' "${CREATE_RESPONSE}" >&2
  exit 1
fi
echo "Created run_id: ${RUN_ID}"

# --- 2. run details ---------------------------------------------------------

section "2. Run details"
curl -sS "${API_BASE_URL}/api/runs/${RUN_ID}" \
  | show '{run, phases, provider_states, security}'

# --- 3. timeline ------------------------------------------------------------

section "3. Timeline"
curl -sS "${API_BASE_URL}/api/runs/${RUN_ID}/timeline" | show '.'

# --- 4. output (IntegratorBundle) -------------------------------------------

section "4. Output (IntegratorBundle)"
echo "Note: the bundle is returned only when readiness is evidenced."
echo "Otherwise the API replies with a typed phase_unavailable (HTTP 409)."
# Do not abort the script on the expected 409 before the run is ready.
curl -sS "${API_BASE_URL}/api/runs/${RUN_ID}/output" | show '.' || true

hr
echo "Done. run_id=${RUN_ID}"
echo "Open the UI at: ${API_BASE_URL%:*}:3000/runs/${RUN_ID} (adjust host/port as needed)"
