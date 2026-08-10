# Operations

This runbook covers the canonical 50-recipe control plane. It does not cover the retired assignment overlays, Browser Use execution, or dynamic You.com research.

## Runtime topology

```text
Internet
  |
  v
Caddy :80/:443
  |-- UI + signed app session ----------> Next.js :3000
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

Only Caddy publishes host ports. FastAPI and Next.js share the private control
network. The API and Playwright RPC service share a separate internal browser
control network, while Chromium gets outbound vendor access through a
browser-only egress network. Next.js protects the UI and server actions with a
signed HTTP-only session. The one direct browser WebSocket path requires a
short-lived, session-bound signed grant. `BROWSER_SERVICE_OWNER` is a stable
tenant/storage namespace; HTTP session RPCs additionally require a capability
derived for that exact run.

## Local planning

Create the environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
make install-dev
cp .env.example .env
cp web/.env.example web/.env.local
```

Add the same random, at-least-32-character `OPS_INTERNAL_API_TOKEN` to both
environment files, keep it independent from every browser token, and leave
these disabled for offline planning:

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

Generate independent values; run each command separately and place its output
only in the matching untracked environment entry:

```bash
# OPS_INTERNAL_API_TOKEN, BROWSER_SERVICE_TOKEN,
# BROWSER_SESSION_CAPABILITY_KEY, BROWSER_SECRET_BROKER_TOKEN,
# OPS_AUTH_SESSION_SECRET
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'

# SECRET_VAULT_KEY (Fernet format)
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'

# LANGGRAPH_AES_KEY (exactly 32 UTF-8 bytes; recovery/legacy tooling only)
python3 -c 'import secrets; print(secrets.token_hex(16))'

```

Configure these groups before deployment:

| Group | Required values |
| --- | --- |
| Edge | `DOMAIN` and optional `ACME_EMAIL` |
| Application auth | `OPS_AUTH_USERNAME`, a unique `OPS_AUTH_PASSWORD` of at least 20 characters, and a stable random `OPS_AUTH_SESSION_SECRET` of at least 32 characters |
| Internal trust | one random `OPS_INTERNAL_API_TOKEN` shared by API and web |
| Stored-state keys | a stable `SECRET_VAULT_KEY` for credential ciphertext; optional `BROWSER_STORAGE_STATE_KEY` for encrypted browser storage state; and the stable `LANGGRAPH_AES_KEY` currently required by recovery tooling for legacy checkpoint artifacts |
| Playwright RPC | one random `BROWSER_SERVICE_TOKEN`; one independent stable `BROWSER_SESSION_CAPABILITY_KEY` available only to API; and the same tenant/storage `BROWSER_SERVICE_OWNER` for API, worker, and Caddy |
| Browser secret broker | a separate random `BROWSER_SECRET_BROKER_TOKEN` shared only by API and browser worker; never reuse either internal token |
| Managed auth | `COMPOSIO_API_KEY`, `COMPOSIO_USER_ID`, and `MANAGED_AUTH_CALLBACK_BASE_URL` set to the public HTTPS origin on the exact `DOMAIN` host |
| Browser decisions | at least one supported inference key available only to the browser worker |
| Signup inbox | `COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID` plus its exact `GMAIL_SIGNUP_ADDRESS`; set `COMPOSIO_GMAIL_API_KEY` and `COMPOSIO_GMAIL_USER_ID` too when this inbox belongs to a different Composio project or external user |

Canonical run state in `OPS_DB_PATH` and effect receipts in
`PROVIDER_EFFECTS_DB_PATH` are ordinary SQLite records. They are protected by
owner-only filesystem permissions, private volumes, and service boundaries; they
are not application-layer encrypted. `SECRET_VAULT_KEY` Fernet-encrypts reusable
credential payloads in the separate vault. `BROWSER_STORAGE_STATE_KEY` encrypts
browser storage-state payloads when that feature is configured.

`LANGGRAPH_AES_KEY` is retained for recovery validation of possible legacy
checkpoint artifacts. The production `LocalRunService` does not initialize a
LangGraph workflow or legacy checkpoint reader, and canonical runs do not write
`CHECKPOINT_DB_PATH`. Supplying this key proves configuration only; it is not a
checkpoint-encryption or legacy-reader readiness signal.

Production has no non-TLS or localhost exception for managed-auth callbacks.
Deployment rejects HTTP, credentials in the URL, nonstandard ports, paths,
queries, fragments, example placeholders, and callback hosts that differ from
`DOMAIN`.

`PLAYWRIGHT_MAX_SESSIONS` is the single browser-capacity setting. The browser
service and display entrypoint derive their capacity from it, and every session
leases its own X display and pair of loopback-only VNC listeners. The supported
range is 1–10; production defaults to two. Use one on a small Droplet and raise
capacity only after observing memory, process, and shared-memory headroom.

The production resource defaults target an 8 GiB, 4 vCPU host:

| Service | Memory ceiling | CPU ceiling |
| --- | ---: | ---: |
| browser-worker | 4 GiB | 2.0 |
| API | 1.5 GiB | 1.0 |
| web | 1 GiB | 0.75 |
| Caddy | 0.5 GiB | 0.25 |

The memory ceilings total 7 GiB, leaving about 1 GiB for the host kernel and
Docker. CPU ceilings are throttling limits, not reservations. Override them
with `BROWSER_MEM_LIMIT`, `BROWSER_CPUS`, `API_MEM_LIMIT`, `API_CPUS`,
`WEB_MEM_LIMIT`, `WEB_CPUS`, `CADDY_MEM_LIMIT`, and `CADDY_CPUS`. Keep
browser-worker's allocation largest and reduce `PLAYWRIGHT_MAX_SESSIONS` before
raising the aggregate limits on this host class. Its private `BROWSER_SHM_SIZE`
defaults to 2 GiB inside the 4 GiB browser ceiling.

Keep `BROWSER_SESSION_CAPABILITY_KEY` stable across API restarts. The API uses it
to re-derive a run's session capability without persisting that bearer value; the
browser service stores only its digest. Rotate the key only after draining active
browser sessions for at least `BROWSER_SESSION_MAX_AGE_SECONDS`, unless the
deployment implements an active/previous key ring. Never provide the master key to
browser-worker, web, or Caddy. Changing it while sessions are active intentionally
makes those sessions impossible for the restarted API to reattach.

Set `BROWSER_SERVICE_OWNER` explicitly. It must match
`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`; deployment refuses to proceed unless the
rendered API, browser-worker, and Caddy values are identical.

Browser timeout ordering is intentional and must remain nested:

| Layer | Default budget |
| --- | ---: |
| Browser operation | 300 seconds |
| API browser RPC client | 315 seconds |
| Next.js run action | 330 seconds |
| Caddy response header | 345 seconds |

This ordering ensures the inner service returns a structured timeout result
before an outer transport aborts the request.

### Autonomous onboarding reliability

Release 2 adds the following bounded settings. Invalid values are rejected at
configuration load rather than silently replaced with defaults.

| Environment setting | Default | Allowed range | Operator purpose |
| --- | ---: | ---: | --- |
| `ONBOARDING_TAKEOVER_ENABLED` | `true` | boolean | Enables observation-only autonomous continuation after a human clears a gate. This is not a live-capability flag and remains gated by startup automation and deployment acceptance. |
| `ONBOARDING_TAKEOVER_INTERVAL_SECONDS` | `5` | 1–30 seconds | Maximum interval between clearance polls for an attached paused run. |
| `ONBOARDING_TAKEOVER_PROBE_TIMEOUT_SECONDS` | `5.0` | 1.0–15.0 seconds | Bounds one clearance probe; a timeout keeps the run waiting rather than treating the gate as cleared. |
| `ONBOARDING_WORKER_ENABLED` | `true` | boolean | Enables the queue pump that claims and drives runs created with `onboarding: true`. It never touches a run nobody enqueued, and stays gated by startup automation and deployment acceptance. |
| `ONBOARDING_WORKER_INTERVAL_SECONDS` | `5` | 1–60 seconds | How long the pump waits after it finds the onboarding queue empty. Claim jitter is added on top. |
| `ONBOARDING_WORKER_MAX_CONCURRENT_RUNS` | `3` | 1–10 runs | How many onboarding runs one worker process drives at once. Each holds one browser container for the length of a phase. |
| `ONBOARDING_PROGRESS_STALE_SECONDS` | `180` | 30–1800 seconds | Marks a non-terminal, non-waiting run stale after this long without progress. |
| `ONBOARDING_PROGRESS_WINDOW` | `50` | 1–200 events | Caps the newest-first progress events returned with a run timeline. |
| `ONBOARDING_STEP_OBSERVE_TIMEOUT_SECONDS` | `20` | 5–60 seconds | Deadline for the observation step of one browser operation. |
| `ONBOARDING_STEP_DECIDE_TIMEOUT_SECONDS` | `20` | 5–60 seconds | Deadline for the decision step; it must also be at least the 15-second loop decision budget. |
| `ONBOARDING_STEP_ACT_TIMEOUT_SECONDS` | `40` | 5–90 seconds | Deadline for the browser action and navigation settle. |
| `ONBOARDING_STEP_VERIFY_TIMEOUT_SECONDS` | `20` | 5–60 seconds | Deadline for the fresh post-action verification. |
| `ONBOARDING_PLAN_DECISION_TOTAL_SECONDS` | `20.0` | 5.0–60.0 seconds | Total inference budget for the one pre-browser plan decision. |
| `ONBOARDING_PLAN_DECISION_PROVIDER_SECONDS` | `8.0` | 2.0–30.0 seconds | Per-provider cap inside the plan decision budget. |
| `ONBOARDING_PLAN_MAX_PROVIDERS` | `3` | 1–5 providers | Maximum providers attempted for one plan decision. |

The four browser-step deadlines default to 100 seconds in total. Their sum
must remain below `BROWSER_SERVICE_CLIENT_TIMEOUT_SECONDS` and the decide
step must remain at least the loop decision budget; configuration loading
names and rejects the conflicting values. Keep the defaults below the tighter
120-second browser-service operation ceiling as well as the 315-second client
budget.

The timeline exposes progress separately from audit items, newest first, and
returns at most `ONBOARDING_PROGRESS_WINDOW` entries: 50 by default and never
more than 200. Each entry contains only the step index, closed loop stage
(`observe`, `candidates`, `decide`, `act`, `verify`, `gate`, or `exhausted`),
elapsed milliseconds, onboarding phase, and recorded time. It contains no
prompt, page content, provider payload, or credential material.

Use these new reason codes as follows:

| Reason code | Operator meaning and action |
| --- | --- |
| `takeover_step_unavailable` | The human gate cleared, but the recorded phase could not be re-entered. Inspect the timeline, then reset or retry the current step. |
| `session_lifetime_exceeded` | The attached paused browser reached its absolute maximum age and was closed. Reset the run so it can create a new session. |
| `run_progress_stale` | No progress event arrived within the configured stale window. Inspect recent progress and decision attempts; retry only after confirming no worker still holds the run. |
| `decision_provider_unconfigured` | No inference provider key is configured for the action loop. Configure a supported provider before retrying. |
| `decision_provider_failed` | Configured action-loop providers were called but none returned a usable decision. Check quota, authentication, outage, and attempt telemetry, then retry the step. |
| `decision_unusable` | A provider response failed schema validation or selected no candidate action. Inspect attempt outcomes and retry the step; do not infer an action manually from provider text. |
| `plan_surface_not_in_catalog` | Pre-flight planning named no complete catalog-approved route or a surface outside the reviewed recipe. Fix or extend the recipe; no browser session was started. |
| `plan_provider_unconfigured` | No planning provider key is configured, so the run used the reviewed recipe-only plan. No intervention is required unless model planning is expected. |
| `plan_decision_failed` | Planning providers were called and failed, so the run used the reviewed recipe-only plan. Inspect provider health if model planning is expected. |
| `plan_decision_unusable` | The planning response was invalid or named no surface, so the run used the reviewed recipe-only plan. Inspect decision telemetry if this repeats. |
| `route_replanned` | The observed route diverged and the run consumed its single automatic re-plan and one attempt. Monitor the replacement route; no immediate action is required. |
| `route_divergence_unresolved` | The route diverged again after the one allowed re-plan, or the observed surface could not be safely recorded. Inspect the reviewed recipe and decide whether to reset or update it. |
| `signup_policy_absent` | The app recipe declares no reviewed signup policy. Do not retry signup; add and review recipe policy first. |
| `signup_postcondition_unmet` | Signup submitted, but a fresh observation did not satisfy the recipe postcondition. Inspect the provider state; a retry skips the already-recorded submission rather than creating another account. |
| `control_withheld` | A paused run's capability could not be proven and no more specific closed reason applied. Inspect the run phase, bound session, and attempt budget before resetting or retrying. |

The seven new sanitized timeline event types are:

| Event type | Operator meaning |
| --- | --- |
| `onboarding_takeover_continued` | Clearance was observed and the API committed autonomous continuation. |
| `onboarding_takeover_withheld` | Takeover did not continue because a closed safety condition withheld it. |
| `onboarding_attachment_changed` | A live-view client attached or detached from the bound session. |
| `onboarding_route_divergence` | The observed bounded host/path differed from the active plan. |
| `onboarding_progress_stale` | The liveness sweep marked the run stale. |
| `onboarding_plan_recorded` | A validated plan revision became active. |
| `onboarding_plan_superseded` | A re-plan replaced the prior active plan revision. |

These events use fixed timeline summaries. Their payloads are restricted to
run id, gate type, phase, reason code, session id, attachment outcome, plan
revision, and bounded divergence fields; they never contain full URLs, signed
live-view grants, page text, or credentials.

### Human gates: solving one, and handing it back

CAPTCHAs are solved by a person. No third-party solving service is integrated
and none should be: `captcha` is a permanent member of the human-only gate set
in `ops/access/gate_policy.py`, alongside phone OTP, billing, passkeys, and
security keys.

What you do **not** have to do is disconnect or click resume afterwards. The
takeover sweep polls each attached paused run every
`ONBOARDING_TAKEOVER_INTERVAL_SECONDS` and continues it as soon as it can
observe that the gate is gone from the page. Solve the CAPTCHA and the agent
resumes on its own, typically within five seconds. It continues only on an
observed change, never because time passed, so walking away from a gate you did
not finish leaves the run parked rather than driving it blind. Closing the tab
mid-gate is also safe: the run records a one-shot debt and probes once more on
detach, which covers "solved it, then closed the window".

The agent and a human never hold the page at the same moment. One Chromium on
one private X display is the whole surface, so an open control connection is a
live keyboard on the page the agent is about to act on. Every verb that moves
the browser — navigate, act, resume — first revokes control and drains any open
control connection; only then does it touch the page. In practice:

- Your control session ends by itself when the agent takes back over. You will
  see the live view close with reason `agent_navigating`, `agent_acting`, or
  `hitl_resumed`. That is the handover working, not a fault.
- **View-only watchers are not disconnected.** Watching an autonomous run is not
  interfering with it, so the read-only stream stays up for the whole drive.
  Control and view are served by separate listeners, and the view listener is
  started `-viewonly`, so a modified client cannot promote itself.
- Requesting a live view while the agent is driving returns a view grant with
  `control_allowed: false`. Control is minted only while the run records a gate.
- If a control connection refuses to close, the agent **stops** rather than
  driving alongside it: the request fails with `live_attachment_drain_failed`
  and the run stays at its gate where you can still reach it. Re-check the
  console for a stuck live-view tab, close it, and retry.

### Standing signup authorization

By default a run that finds nothing in the vault to sign in with stops at
`awaiting_admission` and asks a person whether to create an account. That prompt
is the boundary where somebody accepts the provider's terms of service, so it is
never answered by the software: `decided_by="system"` on a signup route is
refused by the dataclass, by the `onboarding_admission_decisions` CHECK, and by
the gate policy, and it will stay refused.

What can move is *when* the person answers. A standing authorization is the
owner deciding once, in advance, per app, that account creation is approved —
recorded as deployment configuration rather than an API call, so granting and
revoking are both reviewed deploys and the running system cannot grant itself
anything:

```dotenv
ONBOARDING_SIGNUP_AUTHORIZED_APPS=apify,firecrawl   # or * for the whole catalog
ONBOARDING_SIGNUP_AUTHORIZED_BY=dheeraj
ONBOARDING_SIGNUP_AUTHORIZED_AT=2026-08-09T00:00:00+00:00
```

All three are required together. Configuring apps without a name and a timestamp
fails startup validation, because an authorization nobody signed is not one.
Unknown slugs are dropped rather than trusted, and `*` is expanded against the
catalog at load — the wildcard is never stored on a decision row.

A covered run records a real admission decision with
`decided_by="standing_authorization"`, `actor_owner_id` naming whoever granted
it, and `decided_at` stamped with when they granted it — not with when the run
happened to reach the phase. Reading a signup back, you can always tell the two
human authorities apart: `operator` answered a question about *that run*,
`standing_authorization` approved *the app* beforehand. Runs already parked at
`awaiting_admission` are released by the next sweep after the deploy; they do not
need a reset. An operator decision that already exists is never overwritten.

An authorization also reaches runs that paused *mid-flight* on a
`signup_authorization` gate, which it did not before 2026-08-09. The autonomous
sweep classifies each paused gate through `ops/access/gate_policy.py`, and that
policy grants a profile-authorized gate only when it can confine the decision to
the profile's own registrable domain — which means it needs the URL the gate was
observed on. Nothing persisted one: the run row's only URL column is the
live-view link. So the sweep passed no authority, the policy answered
`human_only` for every run, and a perfectly good standing authorization was
invisible to exactly the runs it was granted for. The pause payload now records
the observed page, so the sweep builds the same authority the driver builds and
the two agree.

Nothing was widened to do it. All six checks still have to hold — a committed
profile, an admission decision naming *that* profile, an affirmative signup route
decided by `operator` or `standing_authorization`, and a gate URL inside the
profile's one registrable domain — and any one of them missing yields
`human_only`. Runs that paused before the field existed have no recorded URL and
stay human-only, which is the answer they were already getting; clear them by
hand or retry them.

Understand what this buys and what it spends. It buys unattended signup: the
agent fills the form with the deployment's identity, accepts that provider's
terms in the owner's name, and completes email verification with no human in the
loop. It spends the per-run record of who agreed. The per-app row is the trail
that remains. Leave `ONBOARDING_SIGNUP_AUTHORIZED_APPS` empty and every signup
goes back to asking; that is the fail-closed default and the pre-2026-08-09
behaviour.

### Provider profile research

A standing authorization only helps an app the agent can actually drive, and for
an app with no reviewed recipe that takes a provider profile. The confinement
allow-list a browser session runs under *is* `profile.allowed_hosts()`, so with
no profile the driver raises `PhaseNotDrivable` before the browser is asked to do
anything. Profiles are built by research adapters, and every adapter is opt-in:

```dotenv
ONBOARDING_RESEARCH_PERPLEXITY_ENABLED=true      # needs PERPLEXITY_API_KEY
ONBOARDING_RESEARCH_HOMEPAGE_ANCHORS_ENABLED=true
```

With both false, `research_adapters()` raises `research_adapters_not_configured`
at startup and no recipe-free app is drivable at all — which is loud on purpose.
A flag turned on without its key raises there too, rather than degrading into a
mid-run `research_adapters_unavailable` that reads like a provider outage.

Do not confuse these with the `YOU_*` flags. Those enrich a *reviewed* catalog
entry using the official host list that entry already carries. These start from a
provider name and nothing else, which is the only input an unreviewed app has.
The Perplexity adapter is the one that makes an unknown app drivable; the
homepage-anchor harvester is keyless and spends nothing but needs a seed URL, so
it supplements discovery rather than replacing it. It is off by default because
it is the first adapter that makes a stock deployment issue outbound HTTP to a
host chosen from data.

### Application authentication

Application auth is the single human login boundary. Caddy handles TLS and
routing; it does not add another browser password prompt. Release 3 makes this
boundary single-factor: one leaked operator password grants full control-plane
access, including the live browser view and live email, with no compensating
second factor in the application.

Retained controls are address and identity throttles with escalating lockout,
the 20-character deploy-side password minimum, HMAC-signed sessions with an
exact 12-hour lifetime, and owner-only and loopback-only surfaces. These controls
reduce exposure but do not make a leaked password safe; rotate a suspected
password immediately and terminate its sessions.

`OPS_AUTH_TOTP_SECRET` is no longer read by the application. During migration it
may remain harmlessly in a deployed `.env.production` until the next secret
rotation.

Caddy sends a one-year HSTS policy after a successful HTTPS visit. Container
JSON logs rotate at 10 MiB with five files per service by default; tune
`CONTAINER_LOG_MAX_SIZE` and `CONTAINER_LOG_MAX_FILES` only after checking host
disk headroom.

Enable live actions deliberately:

- `ALLOW_LIVE_BROWSER=true` permits reviewed Playwright recipes.
- `ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true` permits owner login and credential submission controls; additional owner gates still apply.
- `ALLOW_LIVE_VENDOR_EMAIL=true` does not make an unreviewed gated recipe sendable. A reviewed contact and controlled recipient policy remain mandatory.

The canonical production runtime uses only Playwright for browser work. It has no automatic browser-provider or research-provider fallback.

Production Compose enables delayed runtime maintenance. API startup only wires
providers and creates interruptible background threads; it performs no Gmail or
browser-provider call in the startup call path. Those threads wait
`OPS_AUTOMATION_START_DELAY_SECONDS` (60 seconds by default), then remain
fail-closed until the transactional deploy writes an owner-only acceptance
marker bound to both the exact image revision and a fresh deployment nonce.
A stale marker cannot accept a same-revision redeploy, and a manual Compose
start receives an inert nonce that cannot unlock maintenance. The API uses that
same marker as its release fence: run mutations, browser-secret broker calls,
and live-view grant minting return a retryable `503` without invoking the
service or a provider until the candidate is accepted. Read-only health and
public deployment probes remain available. Only after public TLS,
authentication routing, image identity, and health checks pass does one
worker reconcile persisted browser sessions and sweep long-idle browser runs,
while the Gmail worker resolves bound OTPs and ingests authenticated replies.
Each Gmail cycle is capped by
`EMAIL_POLL_MAX_RUNS_PER_CYCLE`, each OTP gets one read batch per cycle, and
provider reads retain their bounded exponential retry/backoff.

### Browser credential isolation

The browser container does not mount the credential-vault volume and never
receives `SECRET_VAULT_KEY`, `SECRET_VAULT_DB_PATH`, or
`OPS_INTERNAL_API_TOKEN`. Its dedicated broker token is necessary but not
sufficient: every handoff also carries the active browser RPC's run capability,
which the API re-derives and binds to the exact run, app, and browser session.
The broker exposes exactly two private operations:

- atomically consume one transient login secret whose reference, app, kind, and
  run scope all match; and
- store one captured credential only after the canonical runtime durably
  reserves that run's capture side effect and its kind matches the reviewed app
  recipe, receiving only the new `vault://` reference.

There is no broker operation to read, list, search, or delete durable vault
entries. The API remains the only service with the vault volume and encryption
key. Browser control traffic uses an internal Docker network; Chromium uses a
separate browser-only egress network for vendor sites. Chromium's sandbox is
enabled by default, and the browser container does not share the host IPC
namespace.

### Chromium seccomp and AppArmor provenance

`deploy/chromium-seccomp.json` is reviewed from Playwright v1.61.0's official
[`utils/docker/seccomp_profile.json`](https://github.com/microsoft/playwright/blob/v1.61.0/utils/docker/seccomp_profile.json),
matching the pinned Python package in `requirements-providers.txt`. It extends
Docker's default policy only with the namespace syscalls Playwright documents
for Chromium's user sandbox and `chroot`. The latter is required after Chromium
enters its private user namespace: a production-host acceptance probe proved
that the sandbox fails closed at `sys_chroot("/proc/self/fdinfo/")` without it
and completes a real render with it. The container receives no host
`CAP_SYS_CHROOT`; the operation is usable only inside Chromium's isolated
namespace. The reviewed file's SHA-256 is:

```text
48f49fe40f3c2f66984b05a431d25f26280841590244e05e4aa574624d301d1d
```

Verify it after checkout:

```bash
sha256sum deploy/chromium-seccomp.json
```

When upgrading Playwright, fetch the profile from the same release tag, reapply
and review the host-proven `chroot` addition, update the checksum here and in
the scaffold test, and run the browser container acceptance job. Production and
CI both run non-root, keep
`no-new-privileges`, drop all Linux capabilities, avoid host IPC, and leave
`PLAYWRIGHT_DISABLE_SANDBOX=false`.

Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor. Chromium
needs one for its primary Linux sandbox, so
`deploy/composio-ops-browser.apparmor` copies Docker's current
`docker-default` boundary and adds the single `userns` permission. The deployer
installs it as the revisioned `composio-ops-browser-v1` host policy and Compose
attaches it only to browser-worker. Do not disable
`kernel.apparmor_restrict_unprivileged_userns` globally and do not set
`PLAYWRIGHT_DISABLE_SANDBOX=true` for production open-web browsing.

## Deploy

`scripts/deploy-droplet.sh` runs as root and requires Docker, the Compose plugin,
Git, curl, Python 3, `flock`, Trivy, `apparmor_parser`, a clean worktree, and
`.env.production`. Root is required to install and load the reviewed browser
AppArmor policy under `/etc/apparmor.d`; application containers remain
non-root. The
environment file must be a non-symlink regular file owned by the deploy user,
readable by that user, and have no group/other permission bits (`0600` or
stricter). The backup and restore helpers enforce the same rule. Deploy,
backup, and restore share one exclusive operation lock, so two state-changing
release operations cannot overlap. Every Compose invocation in the helpers runs with an empty
environment and receives only `PATH` plus the small Docker daemon/context
allowlist; deployment additionally passes its verified `APP_REVISION`. The
standalone backup applies that isolation to its direct Docker operations too.
Ambient shell `COMPOSE_*`, application, provider, and feature-flag values
therefore cannot override the validated `.env.production` inputs.

The reviewed `requirements-runtime.lock` targets
`x86_64-manylinux_2_36`. Production deployment therefore requires an
x86_64 host and an amd64 Docker daemon; the deploy helper checks both before
building. Recompile and review the hash lock for the target platform before
supporting an arm64 Droplet.

```bash
sudo ./scripts/deploy-droplet.sh
```

The script:

1. installs the reviewed browser-only AppArmor policy, records the exact Git
   revision, and validates the rendered Compose security contract, including
   delayed, acceptance-gated startup maintenance;
2. records all four previous container image IDs, freezes that revision's
   Compose and Chromium-seccomp files plus the exact prior container
   environments/runtime limits in an owner-only tmpfs bundle, and rejects
   partial, mixed-revision, or rollback-incompatible stacks before building;
3. builds revision-tagged API, browser-worker, web, and Caddy candidates while
   the current release remains online, then verifies their image IDs and revision
   labels, scans those exact image IDs with Trivy, and launches a credential-free,
   network-isolated browser probe that must prove headed Chromium, its sandbox,
   and the interactive display stack on the actual host;
4. atomically blocks new browser admissions and waits for active browser capacity
   to reach zero;
5. closes Caddy before stopping either writer, creates a unique pre-deploy
   archive, leaves both writers stopped, and runs the restore helper's
   non-mutating integrity and decryption validation using the current private
   encryption keys;
6. activates only the pre-built internal images with `--no-build`,
   and verifies container health, exact image IDs, and revision labels;
7. starts the verified edge and checks public TLS, a same-origin `/login`
   redirect for the protected system page, and the public login page; and
8. atomically records the exact revision-and-nonce acceptance marker, which is
   the only event that releases autonomous Gmail and reconciliation maintenance.

The Trivy gate fails on every `HIGH` or `CRITICAL` vulnerability for which the
package vendor publishes a fixed version. Unfixed vendor advisories remain
visible in the scan report but do not make a rebuild permanently undeployable;
they are mitigated by the runtime's non-root user, read-only filesystem,
dropped capabilities, seccomp policy, and network boundaries until an upstream
package becomes available. Python build-only packaging tools are removed from
the API and browser runtime images after the locked dependencies are installed.
The web build uses npm in isolated builder stages, but the npm/npx CLI and its
dependency tree are removed from the final image before it runs as `node`.
The edge image retains the official Caddy 2.11.4 runtime layout but rebuilds
that release with Go 1.26.5, `golang.org/x/text` 0.39.0, and gRPC 1.82.1, then
requires the vendor-fixed Alpine c-ares and curl packages before validating the
baked Caddyfile.

Any failure after the edge closes recreates the previous revision with the
frozen Git topology, seccomp profile, prior runtime environment/limits, and exact
previous image IDs. If candidate activation began, it first restores the exact
pre-deploy data archive. The rollback API receives a fresh transaction nonce, so
autonomous maintenance and mutating API routes remain blocked while internal
health and public routing at the previous Caddy container's frozen `DOMAIN` are
rechecked; only then is a new acceptance marker written for the verified
rollback. If data restore or rollback validation fails—even after rollback
Caddy started—both Compose contracts order every production service stopped and
the deploy exits fatally. A drain timeout happens before backup or activation;
the script reopens admission and leaves the current release running.
`DEPLOY_DRAIN_TIMEOUT_SECONDS` and `DEPLOY_DRAIN_POLL_SECONDS` bound this wait.
Do not use `--leave-stopped` directly; that backup option is an internal handoff
between the transactional deploy and backup helpers.

The deploy helper creates and validates its own pre-deploy archive. To create an
additional operator-requested archive without deploying:

```bash
./scripts/backup-production-data.sh
```

The standalone helper establishes the same authenticated browser drain, waits
for zero active sessions, stops both SQLite writers, creates the archive, and
then restarts the services that were originally running. The archive contains
the ordinary-SQLite operations volume, credential-vault volume whose sensitive
payloads are Fernet-encrypted, browser storage-state volume whose state payloads
are encrypted when configured, deployed SHA, and that SHA's non-secret
Compose/Caddy configuration.
Backup and checksum files are forced back to the invoking user's UID/GID with
owner-only permissions even though the pinned archive helper reads the named
volumes as container root. Existing timestamp targets and non-private or
symlinked output directories are rejected rather than overwritten.
Encryption keys and `.env.production` remain outside the archive and must stay
in the production secret manager. A recovery is incomplete unless the matching
stable `SECRET_VAULT_KEY`, any configured `BROWSER_STORAGE_STATE_KEY`, and the
recovery-only `LANGGRAPH_AES_KEY` required by the current tooling are restored
from that manager.

Validate a recovery archive without changing a container or volume:

```bash
./scripts/restore-production-data.sh --dry-run \
  backups/<release>/production-state-YYYYMMDDTHHMMSSZ.tar.gz
```

This is a decryption test, not only a tar/checksum preview. It requires the
private `.env.production`, the current API image from exactly one local
production API container, and access to Docker. It mounts an isolated archive
extraction read-only with no network, validates both SQLite databases, decrypts
every vault entry, staged login, checkpoint/write, and browser storage-state
record with the current keys, and never stops a service or mutates a volume.

Restore only after that validation succeeds:

```bash
./scripts/restore-production-data.sh --confirm-restore \
  backups/<release>/production-state-YYYYMMDDTHHMMSSZ.tar.gz
```

The restore stages a private immutable copy of both input files before
validation, then stops the edge and all writers, creates a private safety
archive, replaces only the three application data volumes, decrypt-validates
the result, and restarts dependencies in order. Automatic restart is permitted
only when the archived acceptance marker matches the exact revision and
deployment nonce already running; the API verifies that marker again before web
or Caddy starts. A same-revision archive from another deployment nonce is not
interchangeable. Safety archives receive the same invoking-user ownership and
owner-only permission checks; restore refuses unsafe recovery directories or
same-second evidence/archive collisions before stopping a service.

To recover an archive from another revision or deployment nonce, use
`--confirm-restore --leave-stopped`, keep every service stopped, check out the
SHA recorded under the private `restore-evidence` directory, and run the normal
transactional deploy for that exact reviewed revision. Never manually edit or
recreate the acceptance marker. Any failure triggers a decrypt-validated safety
rollback and leaves the entire stack stopped; inspect the private recovery
evidence before starting anything.

The standalone wait defaults to 300 seconds with a two-second poll. Configure
`BACKUP_DRAIN_TIMEOUT_SECONDS` (1–3600) and `BACKUP_DRAIN_POLL_SECONDS` (1–30)
only in the private `.env.production`; ambient values from the launch shell are
ignored.

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

Sign in at `https://your-domain.example/login`, then open `/system` to inspect sanitized storage and provider posture.

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

The browser container is healthy only after Chromium can launch, the session
janitor is running, and the cached readiness state is `ready` or
`capacity_exhausted`. `configured_not_verified` is not production readiness.
The API container likewise requires its storage and snapshot checks to report
`healthy`; an HTTP 200 carrying `degraded` does not pass the container check.

Inspect bounded logs when a service is unhealthy:

```bash
docker compose -f compose.prod.yaml --env-file .env.production logs --tail=200 api browser-worker web caddy
```

Review logs before sharing them even though application logging is designed to sanitize provider and credential data.

## Operate each route

### Managed authentication

1. Create an `execute_when_configured` run for one of the 7 managed-authentication apps.
2. Select **Connect account**.
3. Complete the provider authorization in the returned Composio flow.
4. Return to the run and select **Check connection**.
5. Treat the run as complete only after Composio reports the account `ACTIVE`.

The final bundle contains a provider account identifier. It does not expose OAuth tokens.

### Managed key

The other half of the managed set: 23 apps whose credential is a long-lived key
you mint yourself on the vendor's own settings page. There is no OAuth redirect,
no browser session, and no **Connect account** step — Composio reports the
connection `ACTIVE` synchronously when the key is published.

1. Create an `execute_when_configured` run. It stops at phase
   `key_submission_required`, and the run page shows the **Managed key** panel.
2. Mint the key at the app's reviewed credential-management URL — the per-app
   table in `docs/APP_RECIPES.md` names it.
3. Paste it once into the panel and select **Publish key to Composio**.
4. Treat the run as complete only after the panel reports the connected account
   active. Anything else leaves the run at `configuration_required` with a
   sanitized reason code.

The key is written to the encrypted vault before the provider call, so a publish
whose outcome is unknown stays recoverable; only a `vault://` reference reaches
run state, the timeline, and the bundle. As with the OAuth path, the bundle
carries a provider account identifier and never the credential.

Publication requires the deployment's owner-credential gate
(`ALLOW_LOCAL_CREDENTIAL_SUBMISSION`), not the agent-action gate that
`POST /api/runs/{id}/connect` uses. The distinction is what the request body
carries: `/connect` asks the deployment to mint a link,
`POST /api/runs/{id}/managed-key` hands it a live credential. For the same
reason the route is withheld on an unaccepted release, alongside
`POST /api/runs/{id}/credentials`.

16 of the 23 can be published today. The remaining 7 — Jira, Harvest, Discord,
Mailchimp, Linear, Close, and Plain — return a disabled action naming the
specific obstacle (a companion non-secret field, an unreviewed header prefix, or
no reviewed validation request to read the auth scheme from). This is deliberate:
publishing a key under a guessed scheme produces a connection Composio reports
`ACTIVE` that fails authentication on every later tool call, which is worse than
not connecting at all. `MANAGED_KEY_SCHEME_UNREVIEWED` in
`ops/recipes/app_recipes.py` records what each one is waiting on.

### Gmail signup and verification

The signup inbox is configured independently of outbound outreach:

```dotenv
COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID=<connected-account-id>
COMPOSIO_GMAIL_USER_ID=<external-user-id-that-owns-the-connection>
GMAIL_SIGNUP_ADDRESS=<exact-inbox-address>
GMAIL_SIGNUP_PREFLIGHT_TIMEOUT_SECONDS=10
GMAIL_VERIFICATION_REQUIRE_BINDING=true
GMAIL_VERIFICATION_REQUIRE_AUTHENTICATED_SENDER=true
```

The connected-account ID authorizes inbox reads. The exact address binds a
candidate OTP or magic-link message to the signup/login recipient recorded for
the run. Configure both values together or neither. Do not use
`OUTREACH_RECIPIENT_OVERRIDE` as a verification identity; it remains a
controlled outbound-delivery sink.

The new-run page reports this provider as ready only after `GMAIL_GET_PROFILE`
proves the configured signup address is the connected mailbox and a bounded,
real `GMAIL_FETCH_EMAILS` no-match query succeeds. Successful readiness is
cached for 60 seconds; failures are cached for 10 seconds. Executable
create-account runs repeat the preflight before generating any vendor password.

An OTP or magic link is accepted only when Gmail returns trusted
`Authentication-Results` showing aligned DMARC, DKIM, or SPF authentication.
DMARC pass is preferred. Preserved ARC evidence is accepted only when Gmail's
own trusted result reports `arc=pass`; the self-declared `cv` text in an
ARC-Seal is not treated as cryptographic proof. Missing, failed, unaligned, or
untrusted authentication evidence leaves the run at its human gate with a
sanitized reason code. This authentication check is additive to exact recipient,
freshness, reviewed sender-domain, and reviewed link-host binding. If the
connected provider payload omits those headers, autonomous verification remains
unavailable rather than assuming the sender authenticated.

### Pipedrive Playwright flow

Pipedrive is the only complete browser recipe today. It has a reviewed login URL, credential-management URL, structured success predicate, automatic capture specification, and read-only validation policy.

The remote surface is view-only during autonomous work. Control is available only when the run records a human gate, such as CAPTCHA, MFA, device approval, or account selection. Finish the gate and stop there — the agent observes the clearance and continues the same run by itself, and it terminates your control connection when it does. See "Human gates: solving one, and handing it back" above.

Do not call the run successful until the sanitized timeline records credential capture and validation and the output endpoint returns a bundle.

### Owner-submit entry routes

The 7 owner-submit recipes — bright-data, dataforseo, klaviyo, neo4j, shopify, telegram, and xero — open only the reviewed public account entry. They do not claim to log in, navigate to credential settings, create a credential, capture it, or validate it. They are Playwright recipes whose `browser.scope` is `entry_only`; that field, not the readiness tier, is what the runtime branches on.

After independently obtaining the expected credential, submit it once through the owner-only encrypted form. The run reaches `credentials_ready`; the bundle records that validation was not reviewed.

### Gated routes

One gated recipe has a reviewed email contact: Freshdesk. It still sends only to the configured controlled sink and only after an explicit owner action. The other five — Help Scout, Meta Ads, LinkedIn Ads, Snowflake, and Ramp — remain `outreach_review_required`; provider keys or a recipient override must never upgrade that catalog readiness. Close, Ahrefs, and Brex left this route for `managed_key` once their credential-management pages were reviewed.

`OUTREACH_RECIPIENT_OVERRIDE` is deployment-wide and is never supplied by the
run-creation form or API. Reply polling accepts only an exact parsed RFC sender
mailbox matching that sink; when live vendor sending is explicitly enabled
without a sink, it instead binds to the immutable reviewed recipe contact. Each
immutable Gmail message is globally reserved by
connected account and thread before the selected message's credential-shaped
values are atomically written to the encrypted vault.

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
- Keep `SECRET_VAULT_KEY` stable across redeployments; rotating it without a
  credential migration makes stored credential payloads unreadable. Apply the
  same rule to `BROWSER_STORAGE_STATE_KEY` when encrypted browser storage state
  is enabled. Preserve `LANGGRAPH_AES_KEY` only for recovery of legacy
  checkpoint artifacts; it does not encrypt canonical run or effect state.

## Restarts and persistent state

The production stack uses named volumes for ordinary-SQLite operations/effect
state, browser profiles, the credential vault, and Caddy state. Preserve the
volumes across redeployments and preserve the matching keys for payloads that
are actually encrypted.

Restarting the API should not terminate an isolated browser-worker session. Restarting the browser-worker can invalidate active browser sessions; finish or explicitly abandon live runs before doing so.

Release tooling controls browser admission through the authenticated
`/internal/drain` contract on browser-worker:

- `POST` atomically stops new session admission while existing session RPCs keep
  working.
- `GET` returns only `accepting_new_sessions`, `capacity_in_use`, and
  `capacity_total`; wait for `capacity_in_use` to reach zero before replacing the
  worker.
- `DELETE` reopens admission after a successful release or a rollback.

These calls use `BROWSER_SERVICE_TOKEN` and `BROWSER_SERVICE_OWNER`; they do not
use or receive the API-only browser-session capability master key.

Use the deployment helper for reviewed releases rather than manually recreating individual containers.
