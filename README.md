# Composio Toolkit Ops Agent

A private operator control plane for onboarding reviewed application integrations. New runs are bound to a versioned 50-app recipe catalog, execute through explicit provider boundaries, and expose only sanitized state and `vault://` credential references.

The canonical production runtime uses:

- Composio managed authentication for reviewed OAuth connections;
- an isolated Playwright browser service for reviewed browser routes;
- owner-only ordinary SQLite for canonical run state and effect receipts, plus a
  separate SQLite credential vault whose secret payloads are Fernet-encrypted;
- a FastAPI control plane behind a Next.js operator UI and Caddy.

Browser Use and You.com are not runtime providers in this rollout. Production disables both; they are not fallback paths for canonical runs.

## Current readiness

Catalog membership is not a claim that every app is fully autonomous or live-verified. The 50 recipes have four deliberately different capabilities:

| Capability | Apps | Current behavior |
| --- | ---: | --- |
| Managed authentication | 25 | Start a Composio authorization link, poll the connected account, and produce a reference-only bundle after Composio reports it active. |
| Complete Playwright browser flow | 1 | Pipedrive has a reviewed login-to-credential trace, automatic secret capture, read-only validation, and encrypted vault handoff. |
| Playwright entry plus owner submission | 13 | Open the reviewed public sign-in entry, then let the owner submit the independently obtained credential into the encrypted vault. These recipes do not claim credential-page navigation, automatic capture, or live validation. |
| Gated/outreach | 11 | No browser automation. Four reviewed email routes support explicit controlled-sink outreach; seven remain truthfully review-required. |

See [docs/APP_RECIPES.md](docs/APP_RECIPES.md) for the exact app matrix and promotion requirements.

## Run model

1. The app name resolves to one immutable recipe.
2. `plan_only` records research and routing without provider side effects.
3. `execute_when_configured` exposes only the action authorized by the recipe and current backend state.
4. CAPTCHA, MFA, passkeys, account selection, billing, legal consent, and ambiguous steps pause or fail closed.
5. External actions use durable effect identities so retries do not silently create duplicate work.
6. Outputs contain provider identifiers and `vault://` references, never raw credential values.

## Local startup

Prerequisites are Python 3.11, Node.js 22, and npm.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
make install-dev
cp .env.example .env
cp web/.env.example web/.env.local
```

Generate one random `OPS_INTERNAL_API_TOKEN` of at least 32 characters and set
that same value in `.env` and `web/.env.local`. Keep it independent from every
browser token, and keep live-action flags disabled for planning.

Start the services in separate terminals:

```bash
source .venv/bin/activate
make api
```

```bash
make web
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). The API listens on loopback port 8000 and requires the internal token on every `/api/` request.

For local Playwright debugging only, install Chromium and explicitly enable the in-process sandbox:

```bash
make install-browser
```

Then set `ALLOW_LIVE_BROWSER=true`, `BROWSER_PROVIDER=playwright`, and `PLAYWRIGHT_IN_PROCESS_SANDBOX=true` in the private local environment. Production never runs Chromium in the API process.

## Production startup

The production topology is defined entirely by `compose.prod.yaml`.

```bash
cp .env.production.example .env.production
./scripts/deploy-droplet.sh
```

Before deploying, configure the domain and application login (including its
independent Base32 TOTP secret), one shared internal API token, the stable
private keys required by the credential, browser-storage, and recovery
boundaries, the browser-service token and owner, and only the providers you
intend to use. Managed routes require Composio configuration and a public HTTPS
callback base. Live Playwright additionally requires `ALLOW_LIVE_BROWSER=true`
and at least one configured browser-decision model.

The deployment helper refuses a dirty worktree, validates bounded Playwright capacity, builds the exact Git revision, waits for all four services, verifies image revisions, and proves public TLS plus the application-auth boundary.

Operational verification and incident commands are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Safety boundaries

- Caddy is the only public service; FastAPI and browser RPC remain on the private Docker network.
- Every API request requires a server-only internal token.
- Public pages and server actions are protected by a signed HTTP-only application session except `/healthz` and `/login`.
- A candidate deployment can answer health and login probes, but cannot mutate a run, use the browser-secret broker, or mint a live-view grant until its exact revision-and-nonce acceptance marker exists.
- Canonical run state and effect receipts are ordinary SQLite records. Their
  boundary is owner-only filesystem and container access, not application-layer
  encryption. Credential values are encrypted separately in the Fernet vault.
- App login values never enter run state, checkpoints, audit events, screenshots,
  or model prompts. Reusable email/password pairs may be retained only in the
  encrypted account-scoped vault; OTPs and verification links remain one-time.
- Captured and owner-submitted credentials cross directly into the encrypted vault.
- Sensitive browser surfaces suppress screenshots before capture.
- Interactive browser control is granted only during a recorded human-in-the-loop pause.
- Raw credential values never cross an API response; trusted backend integrations resolve `vault://` references in process.
- Missing configuration never switches routes or providers; it produces an explicit unavailable or configuration-required state.

## Verification

```bash
make lint
make typecheck
make test
make frontend-check
make security
```

Offline tests use fakes and fixtures. They do not prove a live vendor login, provider authorization, credential validity, or production deployment. Live claims require a sanitized run timeline and host-specific deployment evidence.
