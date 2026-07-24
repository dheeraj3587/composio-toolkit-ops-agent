# Composio Toolkit Ops Agent — Application Guide

A secure, owner‑operated **operations control plane** that turns *"I want to integrate app X"* into
either **usable API credentials** (obtained autonomously in a real browser, with the human stepping
in only when a provider demands it) or, when an app has no self‑serve path, a **single controlled
outreach email** to the provider. Every credential is captured behind an encrypted vault and every
external surface is sanitized: raw secrets never appear in API responses, run state, checkpoints, or
logs.

This guide explains **what the system does, how it works, the technology behind it, how to run and
operate it, and its security model.**

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [How it works](#2-how-it-works)
3. [Architecture](#3-architecture)
4. [Technology stack](#4-technology-stack)
5. [Repository layout](#5-repository-layout)
6. [Configuration](#6-configuration)
7. [Running locally](#7-running-locally)
8. [Using the API](#8-using-the-api)
9. [The web interface](#9-the-web-interface)
10. [Security model](#10-security-model)
11. [Production deployment](#11-production-deployment)
12. [Testing and quality gates](#12-testing-and-quality-gates)
13. [Operational notes and limitations](#13-operational-notes-and-limitations)
14. [Application readiness matrix](#14-application-readiness-matrix)
15. [Obtaining a captured credential](#15-obtaining-a-captured-credential)

---

## 1. What it does

The platform is the **P2 (operations)** stage of a three‑stage pipeline:

| Stage | Responsibility |
| ----- | -------------- |
| **P1 — Research** | An immutable, verified snapshot of ~100 SaaS apps (auth methods, access model, official doc URLs, buildability). Committed under `data/p1/` and never mutated at runtime. |
| **P2 — Operations** *(this app)* | Given an app, decide the access route and either drive a bounded browser session to the credentials page, capture and validate the credential into an encrypted vault, or send a controlled outreach email. |
| **P3 — Integrator handoff** | Emit a strict, reference‑only `IntegratorBundle` (auth scheme, endpoints, scopes, `vault://` credential references) that a downstream integrator consumes. |

Given an **app name**, a run produces one of three honest outcomes:

- **Self‑serve** → a bounded, host‑restricted browser session navigates the provider's official site
  to the API‑credentials page. When a human‑only gate appears (login, CAPTCHA, OTP), the run pauses
  for human input; the owner can submit login credentials that the agent uses to **sign in
  autonomously**.
- **Gated** (approval/partner‑only) → a single, idempotent **Composio Gmail** outreach to a
  controlled recipient.
- **Blocked / unknown** → the run stops and reports the truthful reason; no provider is contacted.

Runs are **side‑effect‑free by default** (`plan_only`). Provider actions happen only in
`execute_when_configured` mode **and** only when the relevant credentials/policy flags are present.

---

## 2. How it works

### 2.1 The run lifecycle

```
create run ─► research (P1 + optional enrichment) ─► deterministic routing
     └─► self-serve ─► browser session ─► navigate to credentials page
                              │
                              ├─ human-only gate ─► waiting_for_hitl ─► owner submits login
                              │                         └─► agent signs in autonomously ─► resumes
                              └─ credentials page ─► capture ─► validate ─► IntegratorBundle
     └─► gated ─────────► controlled Composio Gmail outreach ─► waiting_for_reply
     └─► blocked/unknown ► stop with a verified reason
```

Run **status** progresses through a single, validated state machine:

`created → researching → route_selected → browser_running → waiting_for_hitl →`
`(credentials_ready | outreach_sent → waiting_for_reply) → completed`, with
`configuration_required`, `blocked`, and `failed` as truthful off‑ramps. Every transition is checked
by one authority (`ops/state.py`); the operations ledger is a *projection* of the durable workflow,
never the source of truth.

### 2.2 Human‑in‑the‑loop with autonomous login injection

When the browser agent hits a sign‑in wall, the run pauses at `waiting_for_hitl`. The owner then
submits the app login (`email` + `password`) on the resume call. Those values are injected into
Browser Use as **secure `sensitive_data` placeholders** — the agent types the bare placeholder keys
(`x_login_email`, `x_login_password`, and, when an emailed code is fetched, `x_login_otp`) which the
provider substitutes with the real values at the DOM layer. **The model never sees the values**, and
they are held in memory for a single resume call only — never written to run state, the encrypted
checkpoint, audit events, or logs. Gates that genuinely require a person (CAPTCHA, MFA/OTP, passkeys,
device approval, billing, legal consent) still pause for HITL.

### 2.3 Deterministic routing

Routing (`ops/routing.py`) is explainable and evidence‑based — it never guesses a URL or an approval
fact. Priority: API unavailable → *blocked*; production approval required (with/without signup) →
*hybrid/approval_required*; contact‑only → *partner_gated*; verified signup + developer portal →
*self_serve*; otherwise the P1 evidence‑derived classification, with at most one bounded enrichment
probe for unknowns.

### 2.4 Capability preflight and gated outreach

Before any gated outreach, a read‑only **Composio capability preflight** answers "can Composio
already integrate this app?" It fails **closed**: a provider error or missing configuration yields
`configuration_required` and no external action, so an outage can never fabricate readiness. Gated
outreach is sent through a least‑privilege Gmail boundary and is redirected to a controlled override
recipient — a discovered vendor address is never contacted directly.

### 2.5 Credential capture, validation, and the bundle

On reaching the credentials page, a deterministic capture reads the credential over CDP and writes
it straight into the encrypted vault, returning only a `vault://` reference. A read‑only validator
confirms the credential against the provider's documented endpoint. The result is an
`IntegratorBundle`: auth scheme, base URL, authorization/token URLs, scopes, callback URLs, and
`credential_refs` (references only) plus non‑secret metadata.

---

## 3. Architecture

```
                        Internet (HTTPS)
                              │
                    ┌─────────▼─────────┐
                    │   Caddy (reverse  │  automatic TLS, Basic Auth,
                    │   proxy, :80/:443)│  security headers, /healthz
                    └─────────┬─────────┘
                              │  (only the web tier is published)
                    ┌─────────▼─────────┐        private opsnet bridge
                    │  web — Next.js UI │◄──────────────┐
                    │  (server-side     │               │
                    │   API proxy)      │               │
                    └─────────┬─────────┘               │
                              │ X-Ops-Internal-Token     │
                    ┌─────────▼─────────┐                │
                    │  api — FastAPI    │  NOT publicly exposed
                    │  control plane    │
                    └─────────┬─────────┘
        ┌─────────────────────┼───────────────────────────────┐
        │                     │                                │
┌───────▼────────┐  ┌─────────▼──────────┐          ┌──────────▼─────────┐
│ LangGraph      │  │ Providers (opt-in) │          │ Encrypted stores   │
│ durable        │  │ • Browser Use v3   │          │ • secret vault     │
│ workflow       │  │ • Composio (Gmail) │          │   (Fernet)         │
│ (encrypted     │  │ • Gemini / OpenRtr │          │ • checkpoints (AES)│
│  SQLite        │  │ • Perplexity       │          │ • ops ledger       │
│  checkpoints)  │  │ • Playwright/CDP   │          │ • effect ledger    │
└────────────────┘  └────────────────────┘          └────────────────────┘
```

- **Caddy** is the only publicly reachable service; it terminates TLS, enforces Basic Auth on every
  route except `/healthz`, and proxies **only** the Next.js UI. FastAPI is never exposed to the
  internet.
- **Next.js** renders the UI and proxies to the API **server‑side**, attaching the shared internal
  token. The browser never talks to the API directly and never receives provider secrets.
- **FastAPI** is the sanitized application boundary shared by HTTP, CLI, and the durable workflow.
- **LangGraph** owns the durable, resumable workflow with **encrypted** SQLite checkpoints, enabling
  same‑thread human‑in‑the‑loop resume.
- **Effect ledger** makes external actions (browser session start, Gmail send) effectively‑once with
  explicit outcome‑unknown semantics.

The production ASGI entry point (`api/main.py`) layers three assignment adapters over the
conservative core runtime: `install_assignment_runtime()`, `install_assignment_live_bootstrap()`,
and `install_assignment_projection()`.

---

## 4. Technology stack

| Layer | Technology |
| ----- | ---------- |
| **API / core** | Python 3.11, FastAPI, Uvicorn, Pydantic v2 |
| **Workflow** | LangGraph 1.x + encrypted SQLite checkpointer |
| **Persistence** | SQLite (ops ledger, checkpoints, secret vault, effect ledger) |
| **Crypto** | `cryptography` (Fernet vault), `pycryptodome` (AES checkpoint serializer) |
| **Browser automation** | Browser Use Cloud v3 SDK, Playwright (CDP‑connect only) |
| **Providers** | Composio (toolkit preflight + Gmail), Google Gemini / OpenRouter (structured extraction), Perplexity (bounded discovery) |
| **Web UI** | Next.js (App Router), React, TypeScript, Tailwind, Zod, Vitest |
| **Edge / deploy** | Caddy 2 (automatic HTTPS), Docker + Docker Compose |
| **Internal interface** | Streamlit (trusted, local operator console) |
| **Quality** | pytest, ruff, mypy (strict), detect‑secrets, pip‑audit |

---

## 5. Repository layout

```
api/            FastAPI app, request/response models, service boundary,
                assignment runtime + live-evidence + projection adapters
ops/            Domain core:
  routing.py            deterministic access routing
  graph.py              durable LangGraph workflow + HITL resume
  run_service.py        application service (create/resume/submit/reveal/poll)
  browser_worker.py     Browser Use v3 boundary + login-secret placeholders
  composio_capability.py  read-only Composio capability preflight
  gmail_worker.py       least-privilege Composio Gmail boundary
  credential_capture.py / credential_validator.py   capture + read-only validation
  secret_store.py       Fernet-encrypted vault (vault:// references)
  effect_ledger.py      effectively-once external actions
  redaction.py          deterministic secret redaction
  integrator.py / models.py / state.py   bundle, models, state machine
  p1_adapter.py         verified P1 snapshot loader
web/            Next.js control-plane UI (server-side API proxy)
data/p1/        immutable verified P1 research snapshot
scripts/        deploy / update / backup / demo utilities
tests/          offline-safe test suite (live tests opt-in)
compose.prod.yaml, deploy/Caddyfile, Dockerfile.api, web/Dockerfile
```

---

## 6. Configuration

All configuration is environment‑driven (`ops/config.py`), with conservative, side‑effect‑free
defaults. Copy `.env.example` to `.env` for local use, or `.env.production.example` to
`.env.production` for deployment. **Never commit these files** — they are gitignored.

### Core / security

| Variable | Purpose |
| -------- | ------- |
| `OPS_INTERNAL_API_TOKEN` | Shared token required on **every** `/api/*` request (server‑only). |
| `LANGGRAPH_AES_KEY` | 16/24/32‑byte key encrypting durable checkpoints. Keep stable across deploys. |
| `SECRET_VAULT_KEY` | Fernet key (44‑char url‑safe base64) encrypting the credential vault. Keep stable. |
| `ALLOW_LOCAL_CREDENTIAL_SUBMISSION` | Opt‑in for the owner‑only credential submit / reveal / live‑view / autonomous‑login endpoints. |
| `OPS_CORS_ORIGINS`, `OPS_ENABLE_API_DOCS` | CORS allow‑list; API docs stay disabled in production. |

### Providers (all optional; features stay off until configured)

| Variable | Enables |
| -------- | ------- |
| `GOOGLE_GENAI_API_KEY` / `GEMINI_MODEL` (or `OPENROUTER_API_KEY` / `OPENROUTER_MODEL`) | Structured research enrichment. |
| `PERPLEXITY_API_KEY` | Bounded official‑document discovery. |
| `BROWSER_USE_API_KEY`, `ALLOW_LIVE_BROWSER`, `BROWSER_USE_MODEL`, `BROWSER_USE_MAX_COST_USD` | Live browser onboarding. |
| `COMPOSIO_API_KEY`, `COMPOSIO_USER_ID`, `COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID` | Composio preflight + Gmail. |
| `OUTREACH_RECIPIENT_OVERRIDE`, `ALLOW_LIVE_VENDOR_EMAIL`, `EMAIL_POLL_INTERVAL_SECONDS` | Controlled outreach + reply polling. |
| `COMPANY_*`, `OAUTH_CALLBACK_URLS` | Company profile used in outreach / bundle. |

### Reverse proxy (production)

| Variable | Purpose |
| -------- | ------- |
| `DOMAIN` | Public hostname for automatic HTTPS (use `:80` for an IP‑only bring‑up). |
| `OPS_BASIC_AUTH_USER` / `OPS_BASIC_AUTH_HASH` | Caddy Basic Auth (generate the hash with `caddy hash-password`). |
| `OPS_API_URL` | Internal API address the web tier proxies to (e.g. `http://api:8000`). |

> **Key generation.** Fernet vault key: `python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"`. AES checkpoint key: a 32‑byte value, e.g. `python -c "import os;print(os.urandom(32).hex())"[:32]` (any 16/24/32‑byte string). Rotating either key makes previously encrypted data unreadable — back up first.

---

## 7. Running locally

Requires **Python 3.11** and Node.js 20+.

```bash
# Python core, API, and interfaces
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt          # core + providers + dev tooling

# Environment
cp .env.example .env                          # then fill in keys you want to exercise

# Run the API (control plane)
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000

# Run the web UI (separate shell)
cd web && npm ci && npm run dev               # needs web/.env.local (OPS_API_URL, OPS_INTERNAL_API_TOKEN)

# Trusted local operator console (optional)
python -m streamlit run streamlit_app.py --server.address 127.0.0.1
```

With no provider keys set, everything runs in a safe, plan‑only mode — routing and research work,
and any provider‑dependent action truthfully reports `configuration_required`.

---

## 8. Using the API

**Every `/api/*` request requires the header** `X-Ops-Internal-Token: <OPS_INTERNAL_API_TOKEN>`.
Owner‑only endpoints additionally require `ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true` and a
loopback / owner‑token caller (see [Security model](#10-security-model)).

| Method & path | Purpose |
| ------------- | ------- |
| `POST /api/runs` | Create a run (`execution_mode`: `plan_only` \| `execute_when_configured`). |
| `GET /api/runs` · `GET /api/runs/{id}` | List / fetch a run's sanitized projection. |
| `GET /api/runs/{id}/timeline` | Human‑readable, sanitized event timeline. |
| `POST /api/runs/{id}/resume` | Continue a `waiting_for_hitl` run; optionally inject `browser_login`. |
| `POST /api/runs/{id}/credentials` | **Owner‑only.** Submit credentials into the vault. |
| `POST /api/runs/{id}/credentials/reveal` | **Owner‑only, loopback.** Return raw values for the owner to use. |
| `GET /api/runs/{id}/live-view` | **Owner‑only.** Ephemeral signed live browser URL. |
| `POST /api/runs/{id}/poll-email` · `POST /api/runs/{id}/retry` | Poll the controlled inbox / retry a capability. |
| `GET /api/runs/{id}/output` | The reference‑only `IntegratorBundle`. |
| `GET /api/apps/search` · `GET /api/apps/{slug}/research` | Search / inspect the verified P1 catalog. |
| `GET /api/system/health` | Health, snapshot provenance, provider states. |

### Example: create a run

```bash
curl -sS -X POST http://127.0.0.1:8000/api/runs \
  -H "X-Ops-Internal-Token: $OPS_INTERNAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "Pipedrive",
    "company": {
      "legal_name": "Example Labs, Inc.",
      "website": "https://example.com",
      "work_email_ref": "vault://company/work_email/profile_1",
      "use_case": "Authorized CRM integration via the developer API."
    },
    "execution_mode": "execute_when_configured"
  }'
```

### Example: resume with autonomous login (owner‑only)

```bash
curl -sS -X POST http://127.0.0.1:8000/api/runs/$RUN_ID/resume \
  -H "X-Ops-Internal-Token: $OPS_INTERNAL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"browser_login": {"email": "owner@corp.example", "password": "••••••"}}'
```

The agent signs in autonomously and continues toward the credentials page. Because this is an
owner‑only action, it must originate from a loopback/owner context and requires the opt‑in flag.

---

## 9. The web interface

The Next.js UI provides a run dashboard, a new‑run form, per‑run detail panels (research, phases,
security posture, capability, HITL, output), a sanitized timeline, and app search. It renders only
**sanitized DTOs** — provider sessions, vault values, and signed URLs are never sent to the browser.
Owner‑only actions (credential submission, live view) are surfaced as controls but, by design, are
reachable only from a trusted owner context, not from an ordinary internet visitor.

---

## 10. Security model

Security is the product's defining constraint:

- **Reference‑only credentials.** Obtained secrets are encrypted in a Fernet vault and represented
  everywhere as `vault://` references. The `IntegratorBundle`, run state, checkpoints, timeline, and
  API responses carry references and non‑secret metadata only.
- **Deterministic redaction.** A central redaction filter scrubs recognized secret material from
  logs, persisted payloads, and error text.
- **Owner‑only, loopback‑gated reveal.** Raw credential values cross the boundary through exactly one
  deliberate endpoint (`/credentials/reveal`), gated to an opted‑in, loopback owner request, and
  audited by kind only (never value).
- **Login secrets are ephemeral.** Injected sign‑in credentials live in memory for a single resume
  call, are domain‑scoped to the app's allowlisted hosts via secure placeholders, and are never
  persisted or logged.
- **Least‑privilege providers.** The Gmail boundary enables only an explicit tool allowlist and
  always redirects to a controlled recipient. The Composio preflight is read‑only and fails closed.
- **Bounded browsing.** Every browser task is constrained to a reviewed per‑app host allowlist; the
  agent is instructed never to read, copy, or report a secret value.
- **Hardened runtime.** Containers run read‑only, non‑root, with `cap_drop: ALL`,
  `no-new-privileges`, tmpfs scratch space, and 0700 private volumes. Only Caddy is exposed, and
  every route but `/healthz` requires Basic Auth; the API additionally requires the internal token.

---

## 11. Production deployment

The reference deployment is a single host running Docker Compose behind Caddy.

```bash
# On the host, in the repo directory:
cp .env.production.example .env.production     # fill DOMAIN, auth hash, token, keys, provider creds
./scripts/deploy-droplet.sh                    # build images, start services, wait for health
```

- `compose.prod.yaml` defines three services — `api`, `web`, `caddy` — on a private `opsnet`
  bridge; only Caddy publishes ports (80/443). Persistent SQLite state lives in the `ops_data`
  volume; Caddy certificate state in `caddy_data`.
- **Update an existing deployment:** `./scripts/update-droplet.sh main` (pulls, rebuilds, rolls out;
  volumes are preserved).
- **Back up persistent data:** `./scripts/backup-production-data.sh --quiesce`.

Because the API is not publicly exposed and owner‑only endpoints are loopback‑gated, operator‑only
actions (credential submission, reveal, live view) are performed from the host — for example via
`docker compose -f compose.prod.yaml exec api ...` against `127.0.0.1:8000` with the internal token.

---

## 12. Testing and quality gates

```bash
RUN_LIVE_TESTS=0 python -m pytest -q          # offline-safe suite (no live provider calls)
ruff check . && ruff format --check .          # lint + format
mypy ops api streamlit_app.py                  # strict type checking
./scripts/security_gate.sh                      # detect-secrets + lint + tests + mypy + pip-audit
cd web && npm run lint && npm run typecheck && npm run test && npm run build
```

The suite is **offline‑safe**: browser, Composio, Gmail, and validation adapters are faked, so no
live call or side effect occurs. Live, opt‑in checks are gated behind `RUN_LIVE_TESTS=1` and the
relevant provider configuration.

---

## 13. Operational notes and limitations

- **Provider configuration gates features.** Browser onboarding needs `ALLOW_LIVE_BROWSER=true` + a
  Browser Use key; gated outreach needs Composio + a connected Gmail account + a recipient override.
  Absent configuration is reported truthfully as `configuration_required`, never silently skipped.
- **Owner‑only endpoints are not internet‑facing.** Credential submission, reveal, live view, and
  autonomous‑login resume are owner operations performed from a trusted loopback/owner context (host
  shell), not from the public UI.
- **Deterministic capture/validation coverage is per‑app.** Fully automated capture and read‑only
  validation are implemented for specific reviewed apps; for others the owner submits the obtained
  credential explicitly, which still produces the same reference‑only bundle.
- **State is durable but keys are load‑bearing.** Losing or rotating `SECRET_VAULT_KEY` or
  `LANGGRAPH_AES_KEY` renders previously encrypted vault entries and checkpoints unreadable — treat
  them as long‑lived secrets and back up before any rotation.
- **External providers are best‑effort.** Research enrichment, Composio, and email all degrade
  gracefully to the verified P1 baseline (or `configuration_required`) on outage rather than failing
  a run or fabricating a result.

---

## 14. Application readiness matrix

Readiness reflects what the deployed system does **end‑to‑end today**. All browser apps support
autonomous login injection; they differ in how far the credential is then carried automatically.

| App | Access route | Autonomous login | Auto‑capture | Read‑only validation | End‑to‑end status |
| --- | ------------ | :--------------: | :----------: | :------------------: | ----------------- |
| **Pipedrive** | self‑serve (browser) | ✓ | ✓ | ✓ | **Fully autonomous** — navigate → capture → validate → bundle |
| **HubSpot** | self‑serve (browser) | ✓ | manual submit | ✓ | Browser onboarding; owner submits, credential validated |
| **Attio** | self‑serve (browser) | ✓ | manual submit | — | Browser onboarding; owner submits the credential |
| **Twenty** | self‑serve (browser) | ✓ | manual submit | — | Browser onboarding; owner submits the credential |
| **Zendesk** | self‑serve (browser) | ✓ | manual submit | — | Browser onboarding; owner submits the credential |
| **Salesforce** | approval (browser) | ✓ | manual submit | — | Browser onboarding; owner submits the credential |
| **Hubstaff** *(live‑demo seed)* | self‑serve (browser) | ✓ | manual submit | — | Browser onboarding; owner submits the credential |
| **Google Ads** | gated | n/a | n/a | n/a | Controlled Composio Gmail outreach |
| **WhatsApp Business** | gated | n/a | n/a | n/a | Controlled Composio Gmail outreach |
| **Close** | gated | n/a | n/a | n/a | Controlled Composio Gmail outreach |
| **Sherlock** | blocked | n/a | n/a | n/a | Blocked — verified to have no API |

> **"Manual submit"** means the agent drives the browser to the credentials page (logging in
> autonomously when creds are provided), and the owner then submits the obtained value through the
> owner‑only credential endpoint, which stores it as a `vault://` reference and builds the same
> reference‑only bundle. Auto‑capture + validation are being extended app‑by‑app; Pipedrive is the
> reference end‑to‑end path.

### Test account for browser onboarding

Browser onboarding of the self‑serve apps above uses a **shared operator test login**. The account
email is `anikatyonzon111@gmail.com`; the password is held in the operator's **gitignored**
`private/TEST_ACCOUNT.md` (never committed) and is submitted at the HITL step (see
[§8](#8-using-the-api), *resume with autonomous login*). Provision the account on each target app
before running its onboarding.

---

## 15. Obtaining a captured credential

Once a run has captured (or been submitted) a credential, the value lives **only** in the encrypted
vault; the API, bundle, timeline, and UI expose `vault://` references, never the raw value. Raw
values cross the boundary through exactly one deliberate, **owner‑only, loopback** endpoint — so in a
container deployment the reveal is performed **from the host**, where the request originates on the
api container's loopback interface:

```bash
# Requires ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true in .env.production
./scripts/reveal-credential.sh <run_id>
# → { "run_id": "...", "credentials": { "access_token": "<raw value>", ... } }
```

The helper runs the reveal inside the `api` container over `127.0.0.1`, satisfying the loopback owner
gate without exposing the endpoint to the network. Treat its output as a secret — this is the single
intentional raw‑secret boundary in the system. (A browser‑UI reveal is intentionally **not**
provided, to keep raw secrets off the network tier; exposing it there would be an explicit,
separate security decision.)
```
