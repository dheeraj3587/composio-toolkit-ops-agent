# Composio Toolkit Ops Agent

Private operations control plane for turning the provenance-locked P1 toolkit research snapshot
into explainable integration-access runs. The product combines a strict Python domain/security
core, durable LangGraph orchestration, a sanitized FastAPI boundary, and a Next.js operator UI.
Streamlit remains an internal debugging surface.

The repository is designed to fail closed. Missing credentials or provider connectivity produce a
typed `configuration_required` or `unavailable` state. They never produce a synthetic email,
browser session, credential, validation result, or ready integrator bundle.

## Truthful capability status

| Capability | Runtime status |
|---|---|
| P1 snapshot integrity, strict parsing, and exact app lookup | Available offline |
| Deterministic routing with bounded reclassification | Available offline |
| Recursive redaction, owner-only SQLite, and Fernet vault | Available offline; keys required for encrypted operations |
| Durable LangGraph checkpointing and HITL resume contract | Implemented; encrypted checkpoint key required |
| P1-backed operational research | Available offline |
| Perplexity discovery and Gemini structured extraction | Configuration-gated; not called by normal tests |
| Composio Gmail adapter | Configuration-gated; no live send was performed without explicit credentials and opt-in |
| Browser Use Cloud navigation | Configuration-gated and additionally guarded by `ALLOW_LIVE_BROWSER=false` |
| Playwright credential capture | Restricted adapter; no live vendor credential was captured in this environment |
| Credential validation and `IntegratorBundle` | Emitted only after real evidence; otherwise honestly not ready |
| FastAPI and Next.js control plane | Available for trusted local/private-network use |
| Streamlit operations ledger | Available for trusted local debugging |

Normal test execution is deterministic and offline-safe. Provider adapters are exercised with
sanitized fixtures and injected fakes. That proves application behavior at the boundary; it does
not prove a live provider account, delivered message, completed onboarding, or accepted vendor
credential.

## Architecture and security boundary

```text
Browser
  |
  v
Next.js server -- server-only OPS_API_URL --> FastAPI -- sanitized contracts --> ops domain core
                                                                                  |          |
                                                                                  |          +-- encrypted vault
                                                                                  +-- run/audit ledger
                                                                                  +-- encrypted checkpoints
                                                                                  +-- immutable data/p1
                                                                                  +-- gated provider adapters
```

- The browser receives declared, sanitized response models only. `OPS_API_URL` is a server-only
  Next.js variable and must never gain a `NEXT_PUBLIC_` alias.
- The UI stores no run or credential material in `localStorage` or `sessionStorage`, has no
  secret-reveal control, and never calls the vault.
- Raw credentials may exist only inside the narrow capture, vault, and validator boundaries. All
  general application contracts accept exact `vault://<app>/<kind>/<id>` references.
- Logs, audit records, checkpoints, API errors, provider observations, and browser-visible state
  are sanitized. Provider response payloads are not persisted or returned.
- `data/p1/results.json` and `data/p1/composio_coverage.json` are immutable copied artifacts.
  `data/p1/SNAPSHOT.json` records the pinned source commit and SHA-256 digests.
- CORS has no ambient wildcard. Origins come only from the explicit `OPS_CORS_ORIGINS` allowlist.
- OpenAPI documentation can be enabled for loopback development only. It is disabled in the
  container configuration.
- Live vendor email and Browser Use remain separately disabled by default.
- API, dashboard, and Streamlit do not implement public-user authentication. Keep them on loopback
  or behind an authenticated private-access layer.

## Prerequisites

- Python 3.11
- Node.js 22 (Node.js 20.9+ is supported by the installed Next.js release)
- npm with the committed lockfile
- Playwright Chromium for local capture tests
- Docker only if using the container stack

## Dependency groups

The Python dependencies are intentionally split:

- `requirements.txt`: secure core, API runtime, CLI, and Streamlit.
- `requirements-providers.txt`: LangGraph, Composio, Browser Use, Playwright, Gemini, and
  Perplexity adapters.
- `requirements-dev.txt`: both runtime groups plus test, typing, lint, audit, and secret-scanning
  tools.
- `requirements-api.txt`: complete API/container runtime, including provider adapters.

Install the complete development environment:

```bash
cd /Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements-dev.txt
python -m playwright install chromium
cp .env.example .env
cd web
npm ci --no-audit --no-fund
cp .env.example .env.local
cd ..
```

Equivalent convenience commands are `make venv`, `make install-dev`, and
`make install-browser` after activating the virtual environment.

## Configuration

`.env.example` contains names and safe defaults only. Never commit `.env` or paste values into
issues, logs, fixtures, screenshots, prompts, or frontend configuration.

### Security and local runtime

| Variable | Purpose | Safe/default behavior |
|---|---|---|
| `SECRET_VAULT_KEY` | Fernet key for the exact-reference secret vault | Required only for vault operations; missing is reported as configuration-required |
| `LANGGRAPH_AES_KEY` | AES key for encrypted LangGraph checkpoint serialization | Required for durable encrypted workflow execution |
| `LANGGRAPH_STRICT_MSGPACK` | Reject unsupported checkpoint values | `true` |
| `OPS_DB_PATH` | Private run/audit SQLite file | `./private/ops.db` |
| `CHECKPOINT_DB_PATH` | Private checkpoint SQLite file | `./private/checkpoints.db` |
| `SECRET_VAULT_DB_PATH` | Private vault SQLite file | `./private/secret_vault.db` |
| `PROVIDER_EFFECTS_DB_PATH` | Private side-effect idempotency ledger | `./private/provider_effects.db` |
| `OPS_CORS_ORIGINS` | Comma-separated exact browser origins | Explicit local origins in `.env.example`; no wildcard |
| `OPS_ENABLE_API_DOCS` | Enable `/docs`, `/redoc`, and schema locally | Set `true` only for loopback development; checked-in containers set `false` |
| `RUN_LIVE_TESTS` | Permit tests marked `live` | `0`; CI always keeps it disabled |
| `ALLOW_LIVE_BROWSER` | Permit paid/live Browser Use execution | `false` |
| `ALLOW_LIVE_VENDOR_EMAIL` | Permit an actual vendor recipient | `false` |

Generate vault and checkpoint keys using the relevant library tooling in a private terminal, then
inject them through the local process manager or deployment secret store. Do not add generated keys
to any repository file.

### Provider configuration

| Variable | Needed for |
|---|---|
| `PERPLEXITY_API_KEY` | Official-document discovery |
| `GOOGLE_GENAI_API_KEY` | Structured operational extraction/classification |
| `COMPOSIO_API_KEY` | Composio Gmail session |
| `COMPOSIO_USER_ID` | Stable Composio user scope |
| `COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID` | Pre-authorized Gmail connected account |
| `BROWSER_USE_API_KEY` | Browser Use Cloud session |
| `OUTREACH_RECIPIENT_OVERRIDE` | Controlled test recipient for gated email flows |
| `COMPANY_WORK_EMAIL_REF` | Canonical company email vault reference, never plaintext |

Having a key configured is not evidence that a provider action succeeded. The run timeline and
output remain in configuration-required, waiting, failed, or not-ready states until the exact
adapter records sanitized evidence.

## Run locally

Start FastAPI from the repository root:

```bash
source .venv/bin/activate
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

Start Next.js in another terminal:

```bash
cd web
npm run dev
```

Open `http://127.0.0.1:3000`. With `OPS_ENABLE_API_DOCS=true`, local API documentation is at
`http://127.0.0.1:8000/docs`. Never enable it solely to expose the service publicly.

The trusted debugging interfaces remain available:

```bash
streamlit run streamlit_app.py --server.address 127.0.0.1
python -m ops.cli doctor
python -m ops.cli run "HubSpot"
python -m ops.cli status <run_id>
```

`make api`, `make web`, and `make streamlit` provide the same loopback-only commands.

## HTTP API

All success and error responses use declared, sanitized models.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/system/health` | Sanitized core, snapshot, and provider configuration status |
| `GET` | `/api/apps/search?q=` | Exact/P1-backed application search |
| `GET` | `/api/apps/{slug}/research` | Verified research, route evidence, and missing fields |
| `POST` | `/api/runs` | Create an idempotent operations run |
| `GET` | `/api/runs` | List sanitized runs |
| `GET` | `/api/runs/{run_id}` | Read sanitized run state |
| `GET` | `/api/runs/{run_id}/timeline` | Read the sanitized event timeline |
| `POST` | `/api/runs/{run_id}/resume` | Resume the same durable HITL thread |
| `POST` | `/api/runs/{run_id}/poll-email` | Poll a configured Gmail thread without exposing raw messages |
| `POST` | `/api/runs/{run_id}/retry` | Retry the allowed failed/configuration-gated step |
| `GET` | `/api/runs/{run_id}/output` | Return a non-secret bundle only when readiness is evidenced |

## Live-provider safety

Normal tests never send email, start a paid Browser Use session, call Gemini/Perplexity, create a
provider application, or validate against an unknown destructive endpoint. Live tests require all
three conditions:

1. `RUN_LIVE_TESTS=1`.
2. The exact provider configuration for that test.
3. The provider-specific safety gate, such as `ALLOW_LIVE_BROWSER=true` or a controlled
   `OUTREACH_RECIPIENT_OVERRIDE` while vendor email remains disabled.

Use a controlled account and recipient. Review the test marker and intended side effect before
opting in. A passing fixture test must never be presented as a live-provider result.

## Verification

Run the complete local gate after installing Python and frontend dependencies:

```bash
./scripts/security_gate.sh
```

The default gate runs:

- the audited detect-secrets baseline hook and recursive scan;
- Ruff lint and formatting verification;
- normal pytest coverage with the live-test flag forced off;
- strict mypy and Python compilation;
- dependency audits for the complete Python environment and frontend lockfile;
- a targeted credential-pattern regression scan;
- frontend lint, TypeScript, tests, and production build.

The CI workflow runs the same policy as independent backend/security and frontend jobs. It installs
local Chromium but provides no credentials and forces all live-action flags off.

Useful focused commands:

```bash
./scripts/security_gate.sh backend
./scripts/security_gate.sh frontend
make test
make frontend-check
make audit
```

## Containers

`Dockerfile.api` runs `uvicorn api.main:app` as an unprivileged user. `web/Dockerfile` builds the
standalone Next.js artifact and runs as the unprivileged Node user. `compose.yaml`:

- publishes both services on host loopback only;
- mounts private state in a named volume;
- sets API docs and live actions off in the checked-in service environment;
- uses read-only root filesystems and constrained temporary filesystems;
- drops Linux capabilities and prevents privilege escalation;
- enables init handling and a process limit.

The Docker build context excludes local environments, private state, browser artifacts, tests,
fixtures, development tooling, repository metadata, and the secret-scanner baseline. Each image
then copies only its declared runtime files.

```bash
docker compose up --build
```

Optional host-port overrides are `OPS_API_PORT` and `OPS_WEB_PORT`. Compose does not embed or pass
provider secrets. Supply production values through the deployment platform's secret manager and
retain the same fail-closed flags. Docker is not installed on the development Mac used for this
delivery, so image build, container health, and Compose startup are not claimed as verified.

The root `Dockerfile` is retained only for the internal Streamlit interface.

## Known limitations

- There is no application-level public-user authentication or multi-tenant authorization. Deploy
  only on a trusted private network or behind an authenticated gateway.
- Provider availability depends on separately provisioned accounts, quotas, connected-account
  state, and vendor behavior. None can be inferred from a configured key.
- Live Gmail delivery, Browser Use onboarding, provider approval, generated credentials, and
  vendor validation require explicit opt-in evidence and cannot be guaranteed by offline CI.
- Docker validation remains pending on a Docker-capable host.
- The P1 copy is intentionally immutable; newly discovered operational facts belong in run state,
  not in `data/p1`.

See [PLAN.md](PLAN.md) for the product contract and [DECISIONS.md](DECISIONS.md) for implementation
decisions and deliberate deviations.

## Repository policy

- Keep the GitHub repository private.
- Never commit `.env`, `private/`, databases, cookies, browser state, credential exports, raw
  messages, screenshots, recordings, or real provider responses.
- Keep fixtures sanitized and deterministic.
- Never claim provider access, sent email, received replies, browser completion, generated
  credentials, validation success, or bundle readiness without evidence from that exact action.
