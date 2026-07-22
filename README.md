# Composio Toolkit Ops Agent

Private P2 operations foundation that consumes a provenance-locked P1 research snapshot and
prepares secure, reference-only inputs for a future P3 integrator.

This repository currently implements **Phase 0/1 only**: strict contracts, encrypted local
secret storage, sanitized run/audit persistence, recursive redaction, a local dry-run CLI, and an
editorial Streamlit operations ledger. Browser automation, research models, Gmail, LangGraph, and
all other provider integrations are deliberately unavailable and make no external calls.

## Current capability boundary

| Capability | Status |
|---|---|
| P1 snapshot provenance and integrity | Available |
| Strict Pydantic P2/P3 contracts | Available |
| Fernet-encrypted exact-reference vault | Available |
| Sanitized SQLite run and audit ledger | Available |
| Local dry-run CLI and Streamlit shell | Available |
| Deterministic P2 routing | Phase 2 unavailable |
| Operational research providers | Phase 2 unavailable |
| LangGraph/HITL | Phase 3 unavailable |
| Composio Gmail | Phase 4 unavailable |
| Browser Use and Playwright capture | Phase 5/6 unavailable |

Unavailable boundaries raise an explicit `PhaseUnavailableError`; they never return invented
research, browser sessions, emails, credentials, or integration output.

## Data and security boundaries

```text
immutable data/p1 snapshot
          |
          v
strict request/contracts --> local dry-run ledger --> sanitized UI/CLI
          |                         |
          |                         +-- private/ops.db (mode 0600)
          +-- vault:// references ------ private/secret_vault.db (Fernet encrypted)
```

- `data/p1/results.json` and `data/p1/composio_coverage.json` are copied artifacts. They are never
  enriched or rewritten in place. `data/p1/SNAPSHOT.json` locks their source commit and SHA-256
  digests.
- Raw secret values may cross only the vault boundary. Contracts and persisted run output accept
  exact `vault://<app>/<kind>/<id>` references.
- Logs and audit payloads are recursively sanitized. There is no vault enumeration API and no UI
  secret-reveal control.
- Local databases, browser state, recordings, screenshots, and environment files are ignored by
  Git and excluded from Docker build context.
- `ALLOW_LIVE_VENDOR_EMAIL=false` is the safe default. Phase 0/1 never invokes a provider SDK,
  sends email, launches a browser, or makes a paid API call.

See [PLAN.md](PLAN.md) for the full implementation contract and [DECISIONS.md](DECISIONS.md) for
the scoped bootstrap decisions.

## Local setup

Python 3.11 is required.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
cp .env.example .env
```

Set `SECRET_VAULT_KEY` to a valid Fernet key before using the vault. Keep the key outside Git.
`COMPANY_WORK_EMAIL_REF`, when configured, must be a vault reference—not a plaintext address.

Run the local checks and interfaces:

```bash
python -m ops.cli doctor
python -m ops.cli run "Example App"
python -m ops.cli status <run_id>
streamlit run streamlit_app.py
```

`run` records a local dry run only. `resume`, `poll-email`, and `show-output` report unavailable
provider phases unless a local result already exists; no command silently falls through to an
external service.

## Verification

The full Gate A command is:

```bash
./scripts/security_gate.sh
```

It runs secret scanning, Ruff checks and formatting verification, pytest, mypy, compile checks,
`pip-audit`, and the targeted tracked-file secret grep. Individual checks can also be run directly:

```bash
pytest -q
ruff check .
ruff format --check .
mypy ops streamlit_app.py
python -m compileall -q ops streamlit_app.py
detect-secrets scan --all-files
pip-audit -r requirements.txt
```

Paid/live tests remain opt-in for later phases with `RUN_LIVE_TESTS=1`; none exist or run in this
foundation. The Dockerfile runs as an unprivileged user with persistent state mounted at
`/private`. Docker image verification is deferred because Docker is not installed on the bootstrap
machine.

### Deployment boundary

The Phase 0/1 Streamlit shell has **no application authentication**. It is intended for local or
otherwise trusted access only and is not safe to expose directly to the public internet. Docker's
unprivileged user and private volume harden the runtime but do not add user authentication. Publish
the container port only on host loopback (for example, `127.0.0.1:8501`) or place it behind a
trusted, authenticated private-access layer; never bind this foundation directly to a public
interface.

## Repository policy

- Keep the GitHub repository private.
- Do not commit `.env`, `private/`, databases, browser state, credential exports, raw messages,
  screenshots, recordings, or real provider responses.
- Fixture contributions must follow the policies under `fixtures/`; sanitized placeholders are not
  optional.
- Do not claim provider access, email delivery, browser completion, or credentials unless a later
  opt-in live phase records evidence for that exact action.
