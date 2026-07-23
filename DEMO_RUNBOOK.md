# Demo Runbook

Operator guide for running a real, secret-safe demonstration of the Composio Toolkit
Ops Agent. This runbook drives the existing runtime only. It does not add code and it
does not change behavior.

Ground rules for the demo:

- Never paste raw keys or secrets into the terminal history, screenshots, or chat.
  Keep them in `.env` and the deployment secret store only.
- Public credential material is referenced with exact `vault://<app>/<kind>/<id>`
  values, never plaintext.
- Live vendor email stays disabled. This runbook never sends Gmail.
- Paid Browser Use sessions are opt-in and are the only intentionally "paid" step. Start
  one only when you explicitly want to demonstrate live browser HITL, and stop it when
  done.
- A configured key is not proof of provider success. Trust the timeline and output
  states, not the presence of a key.

---

## 1. Prerequisites

- Python 3.11 with the project virtual environment installed.
- Node.js 22 (20.9+ works) with the committed `web` lockfile installed.
- `curl` and, ideally, `jq` for the API demo script.
- A populated `.env` at the repository root. Copy from `.env.example` and inject real
  keys through your private terminal or secret manager. Do not commit `.env`.

One-time install (from the repository root):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements-dev.txt
python -m playwright install chromium
cp .env.example .env            # then inject real keys privately
cd web && npm ci --no-audit --no-fund && cp .env.example .env.local && cd ..
```

Provider/key matrix (only what a given demo step needs):

| Step | Env required | Policy flag |
|---|---|---|
| Perplexity discovery | `PERPLEXITY_API_KEY` | none |
| Gemini extraction | `GOOGLE_GENAI_API_KEY` (plus Perplexity for discovery) | none |
| Composio toolkit/account preflight | `COMPOSIO_API_KEY`, `COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID` | none for read-only preflight |
| Browser Use live session | `BROWSER_USE_API_KEY` | `ALLOW_LIVE_BROWSER=true` |
| Encrypted checkpoints / HITL resume | `LANGGRAPH_AES_KEY` | none |
| Vault + credential validation | `SECRET_VAULT_KEY` | none |
| Live Gmail send | intentionally out of scope | `ALLOW_LIVE_VENDOR_EMAIL` stays `false` |

---

## 2. Exact local startup commands

Run each block in its own terminal from the repository root.

### 2.1 Startup wiring audit (no network calls)

Prove that configured settings inject the real runtime classes before touching any
provider. This uses placeholder keys and makes no provider request.

```bash
source .venv/bin/activate
PYTHONPATH=. .venv/bin/python scripts/wiring_audit_demo.py
```

Expected: a `SANITIZED STARTUP WIRING AUDIT` table with `dependency | class |
configured | runtime_wired` rows and no secret values. Capture this for the screenshot
checklist.

### 2.2 Core health check

```bash
source .venv/bin/activate
python -m ops.cli doctor
```

### 2.3 FastAPI control plane

```bash
source .venv/bin/activate
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

Health probe (separate terminal):

```bash
curl -s http://127.0.0.1:8000/api/system/health | jq .
```

With `OPS_ENABLE_API_DOCS=true`, local docs are at `http://127.0.0.1:8000/docs`
(loopback only).

### 2.4 Next.js operator UI

```bash
cd web
npm run dev
```

Open `http://127.0.0.1:3000`. `OPS_API_URL` is server-only and must point at the API
(`http://127.0.0.1:8000`).

Equivalent convenience commands: `make api`, `make web`, `make streamlit`.

---

## 3. Exact real provider smoke order

Run smokes one provider at a time using the existing `scripts/live_smoke.py`. Each smoke
makes at most one bounded request, prints sanitized evidence only, and skips truthfully
when a key is missing. Gmail sending is deliberately excluded. The proof app is
`HubSpot`.

Run in this order so each step's evidence feeds the next:

```bash
source .venv/bin/activate

# 1. Perplexity: bounded official-document discovery (external call, no secrets printed)
PYTHONPATH=. .venv/bin/python scripts/live_smoke.py perplexity

# 2. Gemini: structured extraction over fetched official evidence
PYTHONPATH=. .venv/bin/python scripts/live_smoke.py gemini

# 3. Composio: read-only toolkit + connected-account preflight (external_action=False)
PYTHONPATH=. .venv/bin/python scripts/live_smoke.py composio

# 4. Browser Use: PAID live session. Only run when demonstrating live browser HITL.
#    Requires ALLOW_LIVE_BROWSER=true. Leaves the session alive for owner interaction.
PYTHONPATH=. .venv/bin/python scripts/live_smoke.py browser
```

Run all configured providers at once (skips missing keys, still runs the paid browser
step if enabled):

```bash
PYTHONPATH=. .venv/bin/python scripts/live_smoke.py all
```

Expected smoke evidence (sanitized):

- `perplexity: external_action=True sanitized_result_count=<n>` plus discovered URLs.
- `gemini: capability=<status> reason=<code> documents=<n>` plus sanitized auth/scope
  fields.
- `composio: toolkit_slug=<slug> toolkit_available=<bool> active_account=<bool>
  state=<state> reason=<code> external_action=False`.
- `browser: session_id=<id> live_view_available=<bool>` with the signed live URL kept
  ephemeral and never printed or persisted.

If a key is absent the smoke prints `SKIPPED (<VAR> missing)` and exits cleanly. That is a
truthful "not verified", not a failure.

---

## 4. One-app end-to-end demo sequence (HubSpot)

This exercises the public API exactly as the frontend does. Live IDs are placeholders to
be filled by the backend agent that runs the demo.

### 4.1 Confirm the app is in the verified P1 snapshot

```bash
curl -s "http://127.0.0.1:8000/api/apps/search?q=HubSpot" | jq .
curl -s "http://127.0.0.1:8000/api/apps/hubspot/research" | jq '.app, .provenance'
```

### 4.2 Create a run

Use the helper script (preferred) or a raw request. The request body requires a
`vault://` reference for the work email; never a plaintext address.

```bash
./scripts/demo-api.sh http://127.0.0.1:8000 HubSpot
```

Raw equivalent for reference:

```bash
curl -s -X POST http://127.0.0.1:8000/api/runs \
  -H 'Content-Type: application/json' \
  -H "Idempotency-Key: idem_$(openssl rand -hex 16)" \
  -d '{
    "app_name": "HubSpot",
    "company": {
      "legal_name": "Demo Integrations Inc",
      "website": "https://demo.example.com",
      "work_email_ref": "vault://hubspot/work_email/primary",
      "use_case": "Demonstrate authorized integration onboarding",
      "callback_urls": ["https://demo.example.com/oauth/callback"]
    },
    "requested_scope_policy": "recommended",
    "execution_mode": "plan_only"
  }' | jq '.run'
```

Record the returned `run.run_id` (format `run_<32 hex>`) as `<RUN_ID>`.

### 4.3 Walk the run

```bash
RUN_ID="<RUN_ID>"                       # from step 4.2
curl -s "http://127.0.0.1:8000/api/runs/$RUN_ID" | jq '.run, .phases, .provider_states'
curl -s "http://127.0.0.1:8000/api/runs/$RUN_ID/timeline" | jq .
```

### 4.4 Provider-gated actions (each fails closed unless configured)

```bash
# HITL resume: available only with LANGGRAPH_AES_KEY; otherwise configuration_required
curl -s -X POST "http://127.0.0.1:8000/api/runs/$RUN_ID/resume" | jq .

# Email poll: available only with Composio Gmail config + ALLOW_LIVE_VENDOR_EMAIL
curl -s -X POST "http://127.0.0.1:8000/api/runs/$RUN_ID/poll-email" | jq .

# Retry a capability: research | browser | email | validation
curl -s -X POST "http://127.0.0.1:8000/api/runs/$RUN_ID/retry" \
  -H 'Content-Type: application/json' -d '{"capability":"validation"}' | jq .
```

### 4.5 Fetch the IntegratorBundle

```bash
curl -s "http://127.0.0.1:8000/api/runs/$RUN_ID/output" | jq '.integrator_bundle'
```

The bundle appears only when readiness is evidenced. Otherwise the API returns a typed
`phase_unavailable` with `available_in: ["output"]`.

### 4.6 Show it in the UI

Open `http://127.0.0.1:3000/runs/<RUN_ID>` and walk the phases, provider states,
timeline, and (when ready) the bundle.

---

## 5. Expected statuses

Run status (`run.status`) and phase/provider states are truthful. Common outcomes:

| Surface | Value | Meaning |
|---|---|---|
| Research phase | `ready` | App found in verified P1 snapshot; routing available |
| Research phase | `waiting` | App absent from P1; one bounded enrichment probe pending |
| Browser phase | `configuration_required` | Needs `BROWSER_USE_API_KEY` + `ALLOW_LIVE_BROWSER=true` |
| Browser phase | `unavailable` | Configured, but SDK cannot prove domain allowlist; fails closed |
| HITL phase | `ready` / `configuration_required` | Needs `LANGGRAPH_AES_KEY` for durable resume |
| Email phase | `ready` / `configuration_required` | Needs Composio Gmail config + live-email opt-in |
| Output phase | `waiting` / `complete` | Bundle only after credential validation reaches terminal state |
| Provider state | `not_configured` / `disabled` / `configured_not_verified` / `ready` / `schema_incompatible` | Key/policy presence, never verified success |
| `resume` / `poll-email` | HTTP 409 `configuration_required` or `phase_unavailable` | Fails closed until configured/available |
| `retry` | `configuration_required` / `no_change` | No fabricated retry side effects |
| `output` | HTTP 409 `phase_unavailable`, `available_in:["output"]` | No bundle until evidenced |
| Health | `healthy` / `degraded` | Storage, owner-only permissions, snapshot integrity |

Security fields to show on camera: `security.raw_secrets_exposed: false`,
`security.live_vendor_email: "disabled"`, `security.redaction: "enabled"`,
`security.owner_only_storage: "verified_owner_only"`.

---

## 6. Rollback and retry steps

Everything runs on owner-only local SQLite under `private/`. Nothing here pushes,
deploys, or sends email.

- Stop the API / UI: press `Ctrl+C` in each terminal.
- Stop a live Browser Use session: this is the only paid resource. End it explicitly from
  the Browser Use dashboard (or your session teardown) as soon as the HITL demo is done.
  The smoke intentionally leaves it alive for owner interaction.
- Retry a gated capability without side effects:
  ```bash
  curl -s -X POST "http://127.0.0.1:8000/api/runs/$RUN_ID/retry" \
    -H 'Content-Type: application/json' -d '{"capability":"research"}' | jq .
  ```
  A `configuration_required` receipt means the provider/policy is missing; a `no_change`
  receipt means there is no recorded failed operation to retry. Neither replays a live
  action blindly.
- Idempotency: re-sending `POST /api/runs` with the same `Idempotency-Key` and identical
  body returns the same run. Reusing the key with a different body returns HTTP 409
  `idempotency_conflict`. Generate a fresh key for a genuinely new run.
- Reset local demo state (destructive, local only): stop the API, then remove the private
  databases so the next run starts clean. Confirm you want to discard local run history
  first.
  ```bash
  rm -f private/ops.db private/checkpoints.db private/secret_vault.db private/provider_effects.db
  ```
- Ambiguous provider outcome: do not blindly re-run the external action. Re-read the run
  timeline and provider state first, then reconcile. The runtime records truthful receipts
  rather than assuming success.

---

## 7. Related documents

- `docs/LIVE_EVIDENCE_CHECKLIST.md` — required live proof and the honest completion table.
- `scripts/demo-api.sh` — scripted create/fetch/timeline/output walkthrough.
- `README.md` — full architecture, security boundary, and verification gate.
