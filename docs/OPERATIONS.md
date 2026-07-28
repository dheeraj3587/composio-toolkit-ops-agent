# Operations

This runbook covers the canonical 50-recipe control plane. It does not cover the retired assignment overlays, Browser Use execution, or dynamic You.com research.

## Runtime topology

```text
Internet
  |
  v
Caddy :80/:443
  |-- Basic-Auth-protected UI ----------> Next.js :3000
  |                                         |
  |                                         v
  |                                      FastAPI :8000
  |                                         |
  |                                         +--> SQLite volumes
  |                                         +--> Composio managed auth
  |                                         +--> Playwright RPC
  |
  +-- signed HITL WebSocket ------------> browser-worker :8081
```

Only Caddy publishes host ports. FastAPI, the web service, and the Playwright RPC service share the private `opsnet` network. The one signed browser WebSocket path is protected by Basic Auth and bound to the browser-service owner.

## Local planning

Create the environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
make install-dev
cp .env.example .env
cp web/.env.example web/.env.local
```

Add the same private `OPS_INTERNAL_API_TOKEN` to both environment files. Leave these disabled for offline planning:

```dotenv
ALLOW_LIVE_BROWSER=false
ALLOW_LIVE_VENDOR_EMAIL=false
ALLOW_LOCAL_CREDENTIAL_SUBMISSION=false
```

Start FastAPI and Next.js in separate terminals:

```bash
source .venv/bin/activate
make api
```

```bash
make web
```

Open `http://127.0.0.1:3000`. Use `plan_only` while checking recipe selection or company input. A plan-only run cannot connect an account, start a browser, send outreach, submit credentials, resume, or retry an external capability.

## Local Playwright debugging

The supported production path is the isolated browser service. The in-process worker is only for local debugging and browser tests.

```bash
source .venv/bin/activate
make install-browser
```

Set the following only in the local private environment:

```dotenv
BROWSER_PROVIDER=playwright
ALLOW_LIVE_BROWSER=true
PLAYWRIGHT_IN_PROCESS_SANDBOX=true
```

Set `ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true` only when the operator needs the credential or login submission controls. Local in-process mode does not reproduce the production noVNC transport or container isolation.

## Production configuration

Create the untracked environment file:

```bash
cp .env.production.example .env.production
```

Configure these groups before deployment:

| Group | Required values |
| --- | --- |
| Edge | `DOMAIN`, `OPS_BASIC_AUTH_USER`, the Caddy password hash, and the matching deploy-probe password |
| Internal trust | one random `OPS_INTERNAL_API_TOKEN` shared by API and web |
| Encryption | independent, stable `LANGGRAPH_AES_KEY` and `SECRET_VAULT_KEY` values |
| Playwright RPC | one random `BROWSER_SERVICE_TOKEN` and the same `BROWSER_SERVICE_OWNER` for API, worker, and Caddy |
| Managed auth | `COMPOSIO_API_KEY`, `COMPOSIO_USER_ID`, and a public HTTPS `MANAGED_AUTH_CALLBACK_BASE_URL` |
| Browser decisions | at least one supported inference key available only to the browser worker |

Production is hard-limited to one Playwright session and one display slot for this rollout. Changing that invariant requires a separately reviewed deployment change, not an environment override.

Enable live actions deliberately:

- `ALLOW_LIVE_BROWSER=true` permits reviewed Playwright recipes.
- `ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true` permits owner login and credential submission controls; additional owner gates still apply.
- `ALLOW_LIVE_VENDOR_EMAIL=true` does not make an unreviewed gated recipe sendable. A reviewed contact and controlled recipient policy remain mandatory.

The canonical production runtime uses only Playwright for browser work. It has no automatic browser-provider or research-provider fallback.

## Deploy

`scripts/deploy-droplet.sh` requires Docker, the Compose plugin, Git, a clean worktree, and `.env.production`.

```bash
./scripts/deploy-droplet.sh
```

The script:

1. validates `compose.prod.yaml`;
2. records the exact Git revision;
3. builds API, browser-worker, and web images for that revision;
4. starts the stack with orphan cleanup;
5. waits for API, browser-worker, web, and Caddy health;
6. verifies image revision labels and the one-session invariant;
7. verifies public TLS, unauthenticated HTTP 401 enforcement, and an authenticated `/system` response.

Before changing a deployed revision, create a consistent recovery archive:

```bash
./scripts/backup-production-data.sh
```

The archive quiesces both SQLite writers and contains the operations volume, encrypted vault volume, the deployed SHA, and that SHA's non-secret Compose/Caddy configuration. Encryption keys and `.env.production` remain outside the archive and must stay in the production secret manager.

For a configuration-only preview:

```bash
docker compose -f compose.prod.yaml --env-file .env.production config
```

## Verify production

Check containers:

```bash
docker compose -f compose.prod.yaml --env-file .env.production ps
```

Check the public edge without authentication:

```bash
curl -fsS https://your-domain.example/healthz
```

Open `https://your-domain.example/system` through Basic Auth to inspect sanitized storage and provider posture.

FastAPI is intentionally not exposed by Caddy. To verify it directly without printing the internal token:

```bash
docker compose -f compose.prod.yaml --env-file .env.production exec -T api \
  python -c 'import json, os, urllib.request; r=urllib.request.Request("http://127.0.0.1:8000/api/system/health", headers={"X-Ops-Internal-Token": os.environ["OPS_INTERNAL_API_TOKEN"]}); print(json.load(urllib.request.urlopen(r))["status"])'
```

Check the isolated browser service:

```bash
docker compose -f compose.prod.yaml --env-file .env.production exec -T browser-worker \
  python -c 'import json, urllib.request; print(json.load(urllib.request.urlopen("http://127.0.0.1:8081/internal/health"))["state"])'
```

Inspect bounded logs when a service is unhealthy:

```bash
docker compose -f compose.prod.yaml --env-file .env.production logs --tail=200 api browser-worker web caddy
```

Review logs before sharing them even though application logging is designed to sanitize provider and credential data.

## Operate each route

### Managed authentication

1. Create an `execute_when_configured` run for one of the 25 managed apps.
2. Select **Connect account**.
3. Complete the provider authorization in the returned Composio flow.
4. Return to the run and select **Check connection**.
5. Treat the run as complete only after Composio reports the account `ACTIVE`.

The final bundle contains a provider account identifier. It does not expose OAuth tokens.

### Pipedrive Playwright flow

Pipedrive is the only complete browser recipe today. It has a reviewed login URL, credential-management URL, structured success predicate, automatic capture specification, and read-only validation policy.

The remote surface is view-only during autonomous work. Control is available only when the run records a human gate, such as CAPTCHA, MFA, device approval, or account selection. After the operator finishes the gate, disconnect control and resume the same run.

Do not call the run successful until the sanitized timeline records credential capture and validation and the output endpoint returns a bundle.

### Owner-submit entry routes

The 13 owner-submit recipes open only the reviewed public account entry. They do not claim to log in, navigate to credential settings, create a credential, capture it, or validate it.

After independently obtaining the expected credential, submit it once through the owner-only encrypted form. The run reaches `credentials_ready`; the bundle records that validation was not reviewed.

### Gated routes

Four gated recipes have reviewed email contacts: Close, Freshdesk, Ahrefs, and Brex. They still send only to the configured controlled sink and only after an explicit owner action. The other seven remain `outreach_review_required`; provider keys or a recipient override must never upgrade that catalog readiness.

When a future recipe adds a reviewed contact, sending must still use the controlled recipient policy and an explicit owner action.

## Interpret run states

| State | Operator meaning |
| --- | --- |
| `route_selected` | Planning completed; no provider work is implied. |
| `connection_required` | Managed authorization has not yet been confirmed active. |
| `browser_running` | A Playwright session exists; inspect the phase and authorized action. |
| `waiting_for_hitl` | Complete only the stated human step, then resume. |
| `credentials_ready` | A credential reference exists, but the recipe did not complete reviewed live validation. |
| `configuration_required` | A required provider, policy flag, vault, or service is unavailable; no fallback occurred. |
| `blocked` | Recipe or policy forbids continuing. |
| `failed` | The selected route ended unsuccessfully; inspect the sanitized reason code. |
| `completed` | The managed connection or reviewed validation predicate reached its terminal success condition. |

The backend-authorized primary action is the only supported next step. Do not infer authority from status text or browser appearance.

## Credential handling

- Never place app passwords, API keys, cookies, OTPs, or tokens in a run description, callback URL, log, issue, or screenshot.
- App sign-in credentials are transient browser inputs.
- Captured and owner-submitted values are written directly into the encrypted vault.
- API responses, run state, audit events, and bundles carry only exact `vault://` references.
- Raw credential values are never returned by an API endpoint; authorized integrations resolve references inside the trusted backend boundary.
- Keep encryption keys stable across redeployments; rotating them without migration makes existing state unreadable.

## Restarts and persistent state

The production stack uses named volumes for operations state, browser profiles, the encrypted credential vault, and Caddy state. Preserve those volumes and their matching encryption keys across redeployments.

Restarting the API should not terminate an isolated browser-worker session. Restarting the browser-worker can invalidate active browser sessions; finish or explicitly abandon live runs before doing so.

Use the deployment helper for reviewed releases rather than manually recreating individual containers.
