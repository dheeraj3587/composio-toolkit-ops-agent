# Composio Toolkit Ops Agent

Private operations control plane for turning the provenance-locked P1 toolkit research snapshot
into safe, explainable integration-access runs.

Phase 2 is implemented: the service verifies and strictly parses the immutable P1 snapshot,
performs exact case-insensitive app/slug lookup, converts only known P1 facts into operational
research, and selects an explainable deterministic access route. The product surface consists of a
FastAPI backend and a Next.js 16 dashboard. The original Streamlit ledger remains available as an
internal debugging interface.

Browser automation, HITL orchestration, email, secret capture, and final integrator output remain
unavailable. Their API actions return typed, honest phase-unavailable responses and never fabricate
provider activity.

## Capability boundary

| Capability | Status |
|---|---|
| P1 provenance, SHA-256 integrity, and strict 19-field parsing | Available |
| Exact app/name lookup with typed `found` / `not_found` result | Available |
| Deterministic routing with one bounded unknown probe | Available |
| Strict request/response contracts and recursive redaction | Available |
| Fernet-encrypted exact-reference vault | Available; not exposed over HTTP |
| Sanitized SQLite run and audit ledger | Available |
| FastAPI run API and Next.js operations dashboard | Available for trusted access |
| Streamlit internal debugging ledger | Available for trusted local access |
| LangGraph durable HITL | Phase 3 unavailable |
| Composio Gmail | Phase 4 unavailable |
| Browser Use and Playwright capture | Phase 5/6 unavailable |

## Architecture and security boundary

```text
Browser
  |
  v
Next.js server -- server-only OPS_API_URL --> FastAPI -- sanitized contracts --> ops domain core
                                                                                  |          |
                                                                                  |          +-- encrypted vault
                                                                                  +-- private run ledger
                                                                                  |
                                                                                  +-- immutable data/p1
```

- The browser receives sanitized product state only. `OPS_API_URL` is a server-only Next.js
  variable and must never be renamed with a `NEXT_PUBLIC_` prefix.
- The dashboard does not store run or credential material in `localStorage` or `sessionStorage`,
  has no secret-reveal control, and does not call the vault.
- FastAPI disables its schema/docs endpoints, applies `Cache-Control: no-store`, uses restrictive
  response headers, and serializes only declared response models. It never returns environment
  values, local paths, vault values, or raw provider payloads.
- Raw credential values may cross only the vault boundary. General application contracts accept
  exact `vault://<app>/<kind>/<id>` references.
- `data/p1/results.json` and `data/p1/composio_coverage.json` are canonical copied artifacts.
  `data/p1/SNAPSHOT.json` records their source commit and digests; Phase 2 pins and verifies that
  provenance before every lookup and never rewrites the artifacts.
- Missing operational URLs, scopes, credential fields, approval facts, or contacts stay unknown.
  The router gives verified operational signals priority and permits at most one injected probe
  when evidence remains insufficient.
- Logs and audit payloads are recursively sanitized. Local databases, environment files, browser
  state, recordings, screenshots, and frontend build artifacts are excluded from Git and Docker
  build context.
- `ALLOW_LIVE_VENDOR_EMAIL=false` remains the safe default. Phase 2 makes no browser, email, or
  paid-provider call.

The FastAPI and Next.js services do **not** implement user authentication yet. Both are intended for
local or otherwise trusted private-network access only. Do not expose ports 8000, 3000, or 8501
directly to the public internet.

## Local setup

Python 3.11 and Node.js 20.9 or newer are required. Node.js 22 is used by the frontend container.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
cp .env.example .env

cd web
npm ci
cp .env.example .env.local
cd ..
```

Set `SECRET_VAULT_KEY` to a valid Fernet key before explicitly using the vault. Keep the key outside
Git. `COMPANY_WORK_EMAIL_REF`, when configured, must be a vault reference rather than a plaintext
address. Neither value is needed to browse the Phase 2 dashboard with sanitized local fixtures.

## Run the product locally

Start the API from the repository root:

```bash
source .venv/bin/activate
uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal, start the dashboard:

```bash
cd web
npm run dev
```

Open `http://127.0.0.1:3000`. The frontend talks to FastAPI from the Next.js server using
`OPS_API_URL`; the value is not placed in the browser bundle.

The internal Streamlit ledger and CLI remain available:

```bash
streamlit run streamlit_app.py --server.address 127.0.0.1
python -m ops.cli doctor
python -m ops.cli run "HubSpot"
python -m ops.cli status <run_id>
```

## HTTP API

All responses are sanitized typed models.

| Method | Path | Behavior |
|---|---|---|
| `POST` | `/api/runs` | Create a local Phase 2 dry run from a strict request |
| `GET` | `/api/runs` | List sanitized runs |
| `GET` | `/api/runs/{run_id}` | Read sanitized run state |
| `GET` | `/api/runs/{run_id}/timeline` | Read the sanitized audit timeline |
| `POST` | `/api/runs/{run_id}/resume` | Typed Phase 3-unavailable response |
| `POST` | `/api/runs/{run_id}/poll-email` | Typed Phase 4-unavailable response |
| `GET` | `/api/runs/{run_id}/output` | Typed unavailable response until real output exists |
| `GET` | `/api/system/health` | Service, security, phase, and snapshot health |

Interactive OpenAPI and documentation routes are intentionally disabled in this trusted-only
foundation.

## Verification

Run the complete local gate after installing both Python and frontend dependencies:

```bash
./scripts/security_gate.sh
```

It scans tracked and untracked source files for secrets, runs Ruff and formatting verification,
pytest, strict mypy and Python compilation for `api/` and `ops/`, dependency auditing, the targeted
credential grep, and the frontend dependency audit, ESLint, TypeScript, and production build.

Individual frontend checks are:

```bash
cd web
npm run lint
npm run typecheck
npm run build
```

Paid/live tests remain opt-in for later phases with `RUN_LIVE_TESTS=1`. Phase 2 contains no paid or
live provider verification.

## Containers

`Dockerfile.api` runs FastAPI as an unprivileged user with owner-only state in `/private`.
`web/Dockerfile` builds Next.js standalone output and runs it as the unprivileged Node user.
`compose.yaml` connects the two services, mounts a private named volume, drops Linux capabilities,
uses read-only root filesystems, and publishes both ports on host loopback only.

```bash
docker compose up --build
```

Optional host-port overrides are `OPS_API_PORT` and `OPS_WEB_PORT`. Container configuration contains
no credentials; supply future secrets through the deployment platform rather than Compose source.
Docker and Compose are not installed on the development Mac, so image builds and Compose startup
remain unverified locally.

The older root `Dockerfile` is retained for the trusted-only Streamlit debugging interface. It also
lacks application authentication and should remain bound to host loopback or protected by a trusted
authenticated private-access layer.

See [PLAN.md](PLAN.md) for the phase contract and [DECISIONS.md](DECISIONS.md) for implementation
decisions and deliberate deviations.

## Repository policy

- Keep the GitHub repository private.
- Never commit `.env`, `private/`, databases, browser state, credential exports, raw messages,
  screenshots, recordings, or real provider responses.
- Sanitized fixtures must follow the policies under `fixtures/`.
- Never claim browser completion, email delivery, provider approval, or credentials without evidence
  from the exact opt-in live action.
