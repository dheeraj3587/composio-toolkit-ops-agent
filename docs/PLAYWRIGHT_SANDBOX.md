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

## Release-gate hardening (implemented)

| Item | Status |
| --- | --- |
| 1. Model-input DLP boundary | **Done.** `ops/model_input_dlp.py` is the single gate every page-derived value passes before inference: URLs lose query+fragment and suspicious path segments, provider keys / bearer tokens / auth codes / JWTs / high-entropy blobs are redacted, credential field names become semantic placeholders (`<secret-field:password>`), and text from `code`/`pre`/`textarea`/`contenteditable`/copy controls is dropped wholesale. A final `contains_secret_material` assertion refuses to send a prompt that still trips it. Prompts are never logged or persisted. 68 adversarial canary tests. |
| 2. Policy-generated candidates | **Done.** `ops/browser_candidates.py` derives a bounded candidate set per checkpoint (opaque id, action type, semantic target, expected element identity, risk, expected postcondition, trace version). The model may reply only with a candidate id, `report_hitl`, or `report_blocked` — `CandidateChoice` has no field for a selector, URL, or value. `goto` comes only from the reviewed trace, `type` only from an approved non-secret value reference, `press` only a reviewed key bound to a reviewed element. Billing / legal / permission-escalation / destructive / key-revocation / account-deletion controls are emitted as `requires_hitl` and are never executable. |
| 3. DOM generation + TOCTOU | **Done.** Every inspection carries a monotonic generation id. Before executing, the page is re-inspected, the URL re-confirmed, and the target re-resolved by stable role/name/type identity requiring exactly one unique match — a stale positional locator is never used, and any change forces a replan. |
| 5. Screenshot hardening | **Done.** Sensitive/success detection runs *before* capture; reaching an authenticated or credential-bearing state clears the previous frame and disables further capture for the session; capture is refused (no image) when safety cannot be established. Verified against credentials rendered as plain text, `code`, `pre`, `textarea`, `contenteditable`, a custom component and a copy button. |
| 6. Staged egress | **Done.** Pre-auth allows reviewed vendor hosts plus reviewed passive asset hosts; post-credential blocks **every** off-allowlist request kind including images, fonts, stylesheets, media, WebSockets and EventSource. Service workers stay blocked. A live adversarial page attempting exfiltration through image, stylesheet, font, media, WebSocket, form and fetch reaches the unapproved host **zero** times. A stage-provider error fails closed. |
| 7. Lifecycle | **Partly done.** Capacity admission is a race-free bounded semaphore released exactly once, a TTL janitor reaps independently, and concurrency tests cover navigate-vs-teardown, capture-vs-expiry, screenshot-vs-stop and simultaneous close. The explicit ACTIVE/CLOSING/CLOSED lease registry is modelled on the session but not yet the sole entry point for every operation. |
| 8. Structural gates | **Done.** Gates require an *actionable* surface: a footer "Terms of Service" link and a passive reCAPTCHA badge no longer trigger HITL, while an interactive CAPTCHA, a real OTP input, an account-selection control, a billing control, a consent button and a passkey control all do. |

## Not yet implemented (do not assume these)

| Item | Status |
| --- | --- |
| 4. Trace schema v2 | **Deferred.** Success still matches reviewed signal strings (multiple signals exist per app, and success is only claimed from a freshly inspected page), but the structured-predicate schema — required role/name, stable selector ids, forbidden states, minimum independent predicates, UI variants — is not built. `credential_page_ready` therefore does not yet require multiple *independent structural* predicates. |
| 9. Deadline-bounded inference | **Deferred.** The action loop is bounded (20 steps / 180 s / 3 repeats / 2 model failures) and providers have per-request timeouts, but there is no single decision-level deadline shared across the fallback chain, no `Retry-After` handling, and no circuit breaker. |
| 10. Sanitized observability | **Deferred.** No metrics record is emitted yet. |
| 11. Real browser CI | **Written, NOT active.** The job exists locally but could not be pushed (the integration lacks GitHub Actions `workflows` permission) and its actions are not yet pinned to immutable SHAs. **There is currently no browser-image CI gate on this repository.** |
| 12. Durable worker RPC | **Done (Phase 3).** See below. |
| 13. Release benchmark | **Deferred.** |

## Phase 3: the isolated browser service

Chromium now runs in its **own container** (`browser-worker`), not in the API process.
That single change is what makes a session survive an API restart, and it stops a
Chromium crash or memory spike from threatening the control plane.

- **`browser_service/`** is a small FastAPI app (`browser_service.main:app`) that drives
  the *same* `PlaywrightBrowserWorker`. All Phase 1/2 safety logic — reviewed host
  policy, opaque candidate policy, risk gate, staged egress, dialog/popup/download
  guards, DLP boundary — is reused unchanged rather than reimplemented.
- **Authenticated RPC.** Every `/internal/...` route requires the shared
  `X-Browser-Service-Token` (constant-time compare) plus an owner header, and enforces
  per-session ownership. A caller who does not own a session gets **404, not 403**, so
  another run's session existence is never confirmed. With no token configured the
  service refuses everything — unconfigured means inert, not open.
- **Credential values never cross the boundary.** The API sends only `vault://`
  references; the service resolves them internally and clears them immediately after
  the operation.
- **Verified reattachment.** `BrowserServiceClient.supports_restart_reattach = True`,
  but a persisted session id is *never* trusted on its own: startup reconciliation
  queries the service and only leaves a run resumable when it reports `ACTIVE`. A
  missing session becomes `browser_service_session_lost`; an **unreachable** service is
  treated as inconclusive and the run is left alone (a transient outage must not
  destroy a live session).
- **Lifecycle safety.** Every operation takes a lease. Closing is
  `ACTIVE → CLOSING → bounded drain → cancel → close → CLOSED → release capacity once`,
  so the janitor can never close a session mid-action and a slot cannot be
  double-released.
- **Interactive HITL.** A screenshot cannot solve a CAPTCHA, an account chooser or an
  MFA prompt, so real remote control is available — gated by an HMAC-signed token bound
  to one session id, one owner, and a few minutes' expiry. It is **off by default**
  (`BROWSER_INTERACTIVE_HITL_ENABLED=false`); when off, Xvfb/x11vnc are never even
  started. x11vnc binds to container loopback (`-localhost`) and the container
  publishes **no port**, so the only path in is the authenticated WebSocket relay.
  Opens, closes and denials are audited by reason code; the grant URL is returned once
  and never durably persisted.
- **Why not websockify?** Verified against its source, not assumed:
  `auth_plugins.BasePlugin.authenticate(headers, target_host, target_port)` receives
  only headers, so a URL grant token cannot be validated there; `token_plugins` is a
  routing hook whose failure path logs the token verbatim
  (`"Token '%s' not found"`). It cannot satisfy "no unauthenticated noVNC" *and*
  "never log the token" simultaneously, so the relay lives in `browser_service/novnc.py`
  behind the same verification the RPC routes use.
- **Storage state is treated as secret material.** Fernet-encrypted at rest, `0600`
  inside a `0700` directory, bound to `(app, account, owner)` so it cannot leak
  sideways, expiry-tracked, and invalidated on logout or auth failure. With no key it
  is simply **not persisted** rather than written in the clear.

## Known limitations (honest)

- **In-process provider still has no restart survival.** When Playwright runs inside the
  API (no browser service configured), the browser dies with the process:
  `supports_restart_reattach = False` and reconciliation moves both `browser_running`
  and `waiting_for_hitl` runs to `configuration_required` with reason
  `playwright_session_lost_on_restart`. Restart survival is a property of the
  **browser service** deployment, not of Playwright as such. Browser Use behaviour is
  unchanged in both cases.
- **No hosted live URL.** HITL uses the authenticated screenshot endpoint
  (`GET /api/runs/{run_id}/live-view/screenshot`, owner‑gated, `no-store`), or the
  short-lived interactive grant above when explicitly enabled.
- **Hands‑off capture covers Pipedrive only.** Other apps use owner submission until
  each app's selectors are verified live.
- **API health does not launch Chromium** (the API image has none). Playwright reports
  `configured_not_verified`; the browser service's own health endpoint is the readiness
  proof.
- **The Docker gates for Phase 3 were not executed.** `docker compose config` and
  `docker compose build` could not run in the authoring environment (no `docker` binary,
  no `/var/run/docker.sock`). `Dockerfile.browser`, the entrypoint and the
  `browser-worker` service are validated **structurally** by
  `tests/test_browser_service_phase3.py::TestContainerIsolationShape` (YAML parse plus
  assertions that no port is published, the container is non-root and read-only, the
  display stack is installed, VNC binds to loopback, and every dangerous switch
  defaults to off). Those tests check the declared configuration, **not a running
  container** — a real `docker compose build` is still required before deployment.
- **Production is not switched.** `browser_provider` still defaults to `browser_use`,
  `compose.prod.yaml` is untouched, and `browser-worker` exists only in the sandbox
  stack.

## Live sandbox runs

Only with a **disposable** test account, `ALLOW_LIVE_BROWSER=true`, and supervision.
Never against a production or untrusted vendor account, and never in public CI.
