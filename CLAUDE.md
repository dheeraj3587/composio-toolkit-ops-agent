# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A recipe-driven operator control plane for onboarding reviewed app integrations. Runs are bound to an immutable 50-app recipe catalog (`ops/app_recipes.json`), execute through explicit provider boundaries, and expose only sanitized state and `vault://` credential references. The stack is: FastAPI API (`api/`) + Next.js operator UI (`web/`) + isolated browser service (`browser_service/`) + Caddy reverse proxy, all wired via `compose.prod.yaml`.

## Commands

**Setup (Python 3.11 required):**
```bash
python3.11 -m venv .venv && source .venv/bin/activate
make install-dev          # pip deps + npm ci
cp .env.example .env
cp web/.env.example web/.env.local
```

**Run locally:**
```bash
make api    # FastAPI on 127.0.0.1:8000
make web    # Next.js on :3000
```

**Test:**
```bash
make test                                        # offline-safe tests only (excludes live/browser)
python -m pytest tests/test_routing.py -v        # single file
python -m pytest -k "test_decide_access" -v      # single test by name
RUN_LIVE_TESTS=1 python -m pytest -m live        # opt-in live tests (require real API keys)
```

**Lint / types / build:**
```bash
make lint           # ruff check + format --check
make typecheck      # mypy strict on ops/ and api/
make frontend-check # Next.js lint + types + vitest + build
make security       # full local security gate (scripts/security_gate.sh)
```

**Playwright (local debug only, not production path):**
```bash
make install-browser
# In .env: BROWSER_PROVIDER=playwright, ALLOW_LIVE_BROWSER=true, PLAYWRIGHT_IN_PROCESS_SANDBOX=true
```

**Docker (local compose):**
```bash
make docker-up      # compose.prod.yaml + compose.local.yaml against .env.production
```

## Architecture

### Request flow

```
Next.js (web/) → FastAPI (api/) → CanonicalRuntime (ops/) → LangGraph workflow (ops/graph.py)
                                                           → ComposioManagedAuthProvider
                                                           → Browser Service (browser_service/)
                                                           → GmailWorker / outreach
```

Every API request carries `X-Ops-Internal-Token`; Caddy is the only public-facing service in production.

### Core execution model

1. **Recipe catalog** (`ops/app_recipes.json` + `ops/app_recipes.py`) — Immutable versioned recipes for 50 apps. Each recipe declares its `route_kind` (`managed_auth`, `playwright`, `gated`), `readiness_tier`, auth style, credential fields, HITL gates, and optional browser API trace.

2. **P1 snapshot** (`data/p1/`) — Locked, SHA-256-verified research snapshot from an external run. The adapter (`ops/p1_adapter.py`) validates provenance before any field is used. This is the source of `OperationalResearch` for plan-only runs without live enrichment.

3. **Deterministic router** (`ops/routing.py`) — Priority-rule classifier that maps `OperationalResearch` → `AccessRoute` (`self_serve`, `approval_required`, `partner_gated`, `hybrid`, `blocked`, `unknown`). Produces an auditable `RoutingDecision` with a `reason_code`. No LLM is involved.

4. **LangGraph workflow** (`ops/graph.py`) — Encrypted AES-backed SQLite checkpoint (`LANGGRAPH_AES_KEY`). State is `OperationsState` (a `TypedDict` in `ops/state.py`). Helpers split across `ops/graph_checkpoints.py`, `ops/graph_state_updates.py`, `ops/graph_outreach.py`; all re-exported from `ops/graph.py` for backward compatibility. `WorkflowDependencies` carries injected adapters (browser, Gmail, research loader, effect store) — this is the test injection boundary.

5. **Canonical runtime** (`ops/canonical_runtime.py`) — The new execution path for all current runs. `ops/run_service.py` is the single application boundary wired by `api/service.py` and the CLI.

6. **Storage layer** — Four SQLite files under `private/`:
   - `ops.db` — Run ledger via `ops/storage.py`
   - `checkpoints.db` — Encrypted LangGraph checkpoints
   - `secret_vault.db` — Fernet-encrypted credential vault (`ops/secret_store.py`); external code only sees `vault://app/kind/id` references
   - `provider_effects.db` — Durable effect ledger (`ops/effect_ledger.py`) for effectively-once external actions

### Provider boundaries

- **Managed auth** — `ops/composio_managed_auth.py`. OAuth connections delegated to Composio; produces a `vault://` reference on completion.
- **Playwright** — In production, the API sends authenticated RPC to the **isolated browser service** (`browser_service/`), which runs Chromium in its own container. The browser service reuses `ops/playwright_worker.py` for host policy, risk scoring, egress rules, and DLP. In-process Chromium (`PLAYWRIGHT_IN_PROCESS_SANDBOX=true`) is local debug only.
- **Gmail / outreach** — `ops/gmail_worker.py` (split into `ops/gmail_*.py` modules). Sends are guarded by the effect ledger; reads use bounded retry. Live sends require `ALLOW_LIVE_VENDOR_EMAIL=true` plus `COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID`.
- **Research enrichment** — `ops/operational_research.py`. Perplexity → You.com (Search/Contents/Research, each opt-in) → Gemini extraction. Results cached in `private/research_cache.db`.

### Safety invariants to preserve

- `OperationsState` has no field for raw credential material — credentials cross the workflow boundary only as `vault://` references. The vault resolve step happens in-process; values never appear in API responses.
- `ops/redaction.py` installs a log filter (`install_redacting_filter`) at the API/CLI startup boundary. Do not bypass it.
- Missing configuration must fail explicitly (`ConfigurationRequiredError`, `PhaseUnavailableError`) — never silently switch routes or providers.
- Live flags (`ALLOW_LIVE_BROWSER`, `ALLOW_LIVE_VENDOR_EMAIL`) are hard off by default; a configured API key alone must not start spending.
- Screenshot suppression (`ops/playwright_live_mask.py`) must be active before any credential surface is reached.
- The effect ledger (`ops/effect_ledger.py`) guards all external side-effecting actions; retries must not create duplicate work.

### Settings

`ops/config.py::Settings` is a frozen Pydantic model loaded once via `Settings.from_env()`. All environment variables are parsed through explicit helpers (`_boolean`, `_secret`, `_choice`, etc.) that reject typos rather than silently using defaults. The `ops/` and `api/` packages read settings only from a `Settings` instance passed through — no `os.getenv` scattered through business logic.

### Testing conventions

- Tests are offline by default: `conftest.py` patches out `.env` loading and sets safe defaults for all live-capability flags.
- Live tests are in `tests/live/` and require `@pytest.mark.live`; browser integration tests use `@pytest.mark.browser`.
- `WorkflowDependencies` is the injection seam for browser, Gmail, and research adapters in tests — pass fakes rather than mocking internal methods.
- The `set_env` autouse fixture in `conftest.py` ensures `ALLOW_LIVE_BROWSER=false` and empty secret values for every test.

### Run status machine

Statuses and legal transitions are declared in `ops/state.py::_LEGAL_STATUS_TRANSITIONS`. Violations raise `IllegalStatusTransition`. The storage layer enforces them; do not write raw SQL status updates that bypass this.
