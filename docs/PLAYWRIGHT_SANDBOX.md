# Playwright sandbox (evaluation only)

The self‑hosted Playwright harness is an **alternative** browser backend to the paid
Browser Use cloud. It is **not** production‑enabled.

> **Deployment status.** Browser Use remains the primary production harness.
> Production keeps `BROWSER_PROVIDER` unset (defaulting to `browser_use`), and
> `compose.prod.yaml`, the deploy scripts, the Caddyfile, and `.env.production` are
> untouched. Do **not** switch production to Playwright: the separate browser‑service
> RPC, API‑independent restart survival, and real deployment remain future phases.

## Why a separate image

`pip install playwright` does **not** install a browser binary, so the hardened API
image cannot launch Chromium — and should not. A browser in the control‑plane
container means a Chromium crash or memory spike can take down the API. Chromium
therefore lives in `Dockerfile.browser`, and `Dockerfile.api` stays browser‑free.

## Running it

```bash
cp .env.playwright.sandbox.example .env.playwright.sandbox

# Build the browser image (installs Chromium + OS deps).
docker compose -f compose.playwright.sandbox.yaml --env-file .env.playwright.sandbox build

# Prove Chromium really launches, renders, and screenshots in this image.
docker compose -f compose.playwright.sandbox.yaml --env-file .env.playwright.sandbox \
  run --rm browser-sandbox
```

A successful probe prints `ready: chromium_launch_verified …` and exits `0`. It exits
non‑zero (never "skipped") when the browser cannot launch.

The sandbox compose publishes **no ports**, mounts **no production volume**, runs as
the non‑root `ops` user with `cap_drop: ALL` and a read‑only root filesystem, uses
`init: true` plus `shm_size: 1gb` (Chromium needs both), and keeps
`ALLOW_LIVE_BROWSER=false` by default.

## What the harness does

Navigation is **trace‑first deterministic**; the LLM is a fallback, not the driver:

1. Inspect the page into a bounded, secret‑free snapshot (max 40 interactive
   elements: role, accessible name, input type, and whether a **non‑secret** field is
   filled). Input values, cookies, storage, and headers are never collected.
2. Verify the URL against the app's reviewed host allowlist.
3. Check the app's reviewed **success signals** — the only way
   `credential_page_ready` is ever returned.
4. Stop for a hard human gate (CAPTCHA, OTP, MFA, passkey, billing, legal consent,
   account selection).
5. Match the current STRICT APP TRACE checkpoint. A **unique** match is clicked with
   no model call at all.
6. Only when ambiguous, ask the bounded inference chain for **one**
   schema‑validated action, then validate and execute it.

Bounds: 20 steps, 180 s wall clock, 3 repeats of the same page state, 2 model
failures. The loop always terminates.

### The model cannot declare success

A `report_credential_page` action is re‑verified against the reviewed success
signals. Without a signal actually present on the page, the claim is discarded and
the loop continues.

## Security properties

| Area | Behaviour |
| --- | --- |
| Egress | Off‑allowlist **active** requests (document, fetch/XHR, WebSocket, EventSource, script, unknown) are aborted; only passive assets (image/font/stylesheet/media) load. Service workers are blocked. |
| Secrets | Injected by code only, after verifying the login origin, a single visible+enabled password field, and that the form does not post off‑allowlist. Never in a prompt, snapshot, log, audit event, or screenshot. A model may not type into a credential‑bearing field. |
| Screenshots | Viewport‑only, with password/token/secret/key/otp/code fields masked. If masking fails, **no** screenshot is produced. Size‑capped, memory‑only, cleared on teardown. |
| Actions | Closed set (`click`, `type`, `press`, `goto`, and three report kinds). No JavaScript execution, shell, arbitrary selectors, uploads, or downloads. `press` accepts only a reviewed key list; `goto` must be absolute HTTPS, credential‑free, fragment‑free, and allowlisted. |
| Capture | Reviewed selectors plus host, path‑prefix, and heading checks, with `fullmatch` on the value pattern. Only a `vault://` reference leaves. Pipedrive only. |

## Known limitations (honest)

- **No restart survival.** The browser runs in‑process, so an API restart destroys the
  session. The provider declares `supports_restart_reattach = False`, and startup
  reconciliation moves both `browser_running` and `waiting_for_hitl` runs to
  `configuration_required` with reason `playwright_session_lost_on_restart` rather
  than pretending they can resume. Browser Use behaviour is unchanged.
- **No hosted live URL.** HITL uses the authenticated screenshot endpoint
  (`GET /api/runs/{run_id}/live-view/screenshot`, owner‑gated, `no-store`).
- **Hands‑off capture covers Pipedrive only.** Other apps use owner submission until
  each app's selectors are verified live.
- **API health does not launch Chromium** (the API image has none). Playwright reports
  `configured_not_verified`; the browser image's own probe is the readiness proof.

## Live sandbox runs

Only with a **disposable** test account, `ALLOW_LIVE_BROWSER=true`, and supervision.
Never against a production or untrusted vendor account, and never in public CI.
