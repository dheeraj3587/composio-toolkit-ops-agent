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

# OPS_AUTH_TOTP_SECRET (160-bit Base32, enroll in the operator authenticator)
python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))'
```

Configure these groups before deployment:

| Group | Required values |
| --- | --- |
| Edge | `DOMAIN` and optional `ACME_EMAIL` |
| Application auth | `OPS_AUTH_USERNAME`, a unique `OPS_AUTH_PASSWORD` of at least 20 characters, a stable random `OPS_AUTH_SESSION_SECRET` of at least 32 characters, and an independent Base32 `OPS_AUTH_TOTP_SECRET` enrolled in the operator authenticator |
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

Application auth is the single human login boundary. Caddy handles TLS and
routing; it does not add a second browser password prompt. The login requires
the configured username and password plus a six-digit TOTP. Generate an
independent 160-bit Base32 secret, enroll it in the operator's authenticator, and
store the same stable value only in the production secret manager and private
`.env.production`:

```bash
python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))'
```

Set that output as `OPS_AUTH_TOTP_SECRET`. Deployment rejects missing, malformed,
placeholder, or reused TOTP secrets. The value is available only to the web
container; API, browser-worker, and Caddy never receive it.

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

`deploy/chromium-seccomp.json` is vendored byte-for-byte from Playwright
v1.61.0's official
[`utils/docker/seccomp_profile.json`](https://github.com/microsoft/playwright/blob/v1.61.0/utils/docker/seccomp_profile.json),
matching the pinned Python package in `requirements-providers.txt`. It extends
Docker's default policy only with the namespace syscalls Playwright documents
for Chromium's user sandbox. The vendored file's SHA-256 is:

```text
cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849
```

Verify it after checkout:

```bash
sha256sum deploy/chromium-seccomp.json
```

When upgrading Playwright, fetch the profile from the same release tag, review
the diff, update the checksum here and in the scaffold test, and run the browser
container acceptance job. Production and CI both run non-root, keep
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

1. Create an `execute_when_configured` run for one of the 25 managed apps.
2. Select **Connect account**.
3. Complete the provider authorization in the returned Composio flow.
4. Return to the run and select **Check connection**.
5. Treat the run as complete only after Composio reports the account `ACTIVE`.

The final bundle contains a provider account identifier. It does not expose OAuth tokens.

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

The remote surface is view-only during autonomous work. Control is available only when the run records a human gate, such as CAPTCHA, MFA, device approval, or account selection. After the operator finishes the gate, disconnect control and resume the same run.

Do not call the run successful until the sanitized timeline records credential capture and validation and the output endpoint returns a bundle.

### Owner-submit entry routes

The 13 owner-submit recipes open only the reviewed public account entry. They do not claim to log in, navigate to credential settings, create a credential, capture it, or validate it.

After independently obtaining the expected credential, submit it once through the owner-only encrypted form. The run reaches `credentials_ready`; the bundle records that validation was not reviewed.

### Gated routes

Four gated recipes have reviewed email contacts: Close, Freshdesk, Ahrefs, and Brex. They still send only to the configured controlled sink and only after an explicit owner action. The other seven remain `outreach_review_required`; provider keys or a recipient override must never upgrade that catalog readiness.

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
