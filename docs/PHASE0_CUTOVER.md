# Phase 0 cutover: turning the live capabilities on

**This runbook is the owner's to execute. The agent prepared the templates and
the Compose passthroughs; it does not, and will not, edit `.env.production`,
run a deploy, or flip a switch.** `.env.production` holds real secrets, is
gitignored, and lives only on the Droplet — nothing in this repository can
change it. Every command below is meant to be run by a human with SSH access.

What "cutover" means here: the deployment already runs with every live
capability fail-closed. Turning them on is three boolean flags plus the
companions each one needs to be more than a flag.

---

## 0. Before you start

| Fact | Value |
| --- | --- |
| Host checkout | `/opt/composio-ops` (override: repo var `DEPLOY_APP_PATH`) |
| Config file | `/opt/composio-ops/.env.production` — host-only, never in Git |
| Template | `.env.production.example` in this repo (comments say what each flag breaks) |
| Release | `scripts/deploy-droplet.sh`, driven by the **Deploy** workflow |

Read `.env.production.example` alongside this document. Each variable below
carries a comment there stating exactly what fails when it is unset or false,
with the call site named.

```bash
ssh <you>@<droplet>
cd /opt/composio-ops
cp .env.production ".env.production.bak.$(date -u +%Y%m%dT%H%M%SZ)"
chmod 600 .env.production.bak.*
```

Keep that backup until the cutover is verified. It is the fastest rollback for
a configuration mistake — faster than a redeploy.

---

## 1. Generate `BROWSER_STORAGE_STATE_KEY`

The code feeds this value straight to `cryptography.fernet.Fernet`
(`ops/browser/storage_state.py`), so the format is not free-form: **32 random
bytes, urlsafe-base64 encoded — a 44-character string ending in `=`**. Anything
else fails with `storage_state_key_invalid` and storage state silently stops
persisting.

Generate it on the Droplet, inside the container that already has
`cryptography` installed:

```bash
cd /opt/composio-ops
docker compose -f compose.prod.yaml exec -T browser-worker \
  python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Paste the output into `.env.production`:

```dotenv
BROWSER_STORAGE_STATE_KEY=<the 44-character key>
```

Rules for this key:

- **Generate it independently.** Never reuse `SECRET_VAULT_KEY`,
  `LANGGRAPH_AES_KEY`, or any token.
- **browser-worker only.** The deploy gate refuses a release where the API
  container can see it (`BROWSER_STORAGE_STATE_KEY must not be available to the
  API container`); `compose.prod.yaml` blanks it there deliberately.
- **Changing it discards saved sessions.** Old blobs become undecryptable; runs
  simply log in again. That is a cost, not a corruption.
- **Leaving it blank is safe, not broken.** `EncryptedStorageStateStore.enabled`
  is False, nothing is written in the clear, and every run logs in from scratch —
  which means a vendor that mails an OTP per new session asks for one every run.

---

## 2. Bind the public identity

These three must agree or the release is refused before anything starts.

```dotenv
DOMAIN=composio.dheerajjoshi.dev
OPS_CORS_ORIGINS=https://composio.dheerajjoshi.dev
MANAGED_AUTH_CALLBACK_BASE_URL=https://composio.dheerajjoshi.dev
ACME_EMAIL=<a mailbox you actually read>
```

- `DOMAIN` is the Caddy site address and the name TLS is issued for.
  `deploy-droplet.sh` rejects it when empty or still `your-domain.example`.
- `MANAGED_AUTH_CALLBACK_BASE_URL` **host must equal `DOMAIN` exactly** — the
  deploy gate compares them. It must be `https`, standard port, no path.
  Without a valid one, managed Composio OAuth reports unconfigured and every app
  whose only route is managed auth stops at a human gate.
- `OPS_CORS_ORIGINS` should be `https://` + `DOMAIN`. Nothing in the normal
  Caddy → web → api path depends on it, so a wrong value hides until something
  calls the API directly and then fails CORS with no server-side error.
- `ACME_EMAIL` is optional; unset only costs you certificate-expiry notices.

---

## 3. Flip the switches

Set these three in `.env.production`. What each one unblocks:

### `ALLOW_LIVE_BROWSER=true`

The master switch for the autonomous browser. While false,
`ops/playwright/worker.py::_require_configuration` raises
`live_browser_opt_in_required` before a single page opens, and
`/api/system/health` reports the `playwright` provider as not configured.

The flag alone is **not** "configured". `browser_configuration_state` also
requires all three of:

```dotenv
BROWSER_SERVICE_TOKEN=<random, >= 32 chars, no "replace-with"/"example">
BROWSER_SESSION_CAPABILITY_KEY=<random, independent, API-only>
# BROWSER_SERVICE_URL is pinned by Compose to http://browser-worker:8081
```

and at least one inference key, or the action loop has no backend and every
ambiguous page becomes a human gate:

```dotenv
MERCURY_API_KEY=<primary — first in every chain>
GROQ_API_KEY=<fallback>
```

### `ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true`

Unblocks the operator's ability to *act* on a paused run: OTP submission,
login-credential submission, autonomous-login injection, and raw-credential
reveal. While false, `api/browser_ui.py` computes `can_submit_otp`,
`can_submit_login` and `can_submit_credential` as False regardless of run state,
so the UI shows a paused run with no controls at all and the run can only be
abandoned. It does **not** enable the browser itself.

Companions:

```dotenv
BROWSER_INTERACTIVE_HITL_ENABLED=true   # else live view is screenshot-only
BROWSER_SERVICE_OWNER=production-owner  # must match across api/browser-worker/caddy
```

The deploy gate enforces that owner match across the three containers.

### `ALLOW_LIVE_VENDOR_EMAIL=true`

Lets outreach reach real vendor mailboxes. While false,
`ops/gmail/worker.py::_actual_recipient` raises `controlled_recipient_required`
for every outbound mail — **unless** `OUTREACH_RECIPIENT_OVERRIDE` names a sink,
in which case mail goes to the sink and this flag is never consulted.

**Rehearse with the sink first.** Set `OUTREACH_RECIPIENT_OVERRIDE` to a mailbox
you own, confirm the outreach loop composes and sends what you expect, and only
then decide whether real vendors should receive real mail.

Companions: `COMPOSIO_GMAIL_API_KEY` (or `COMPOSIO_API_KEY`) and a Gmail
connected-account id — without a mailbox there is nothing to send from.

### Business identity (not a switch, but it decides whether signups finish)

`ops/playwright/actions.py` runs inside browser-worker and types these into
vendor signup forms. Unset means the field is left blank and a signup that asks
for it stops at a human gate on a page the run had everything else it needed:

```dotenv
COMPANY_LEGAL_NAME=
COMPANY_WEBSITE=
COMPANY_USE_CASE=
COMPANY_EXPECTED_VOLUME=
```

---

## 4. Validate the rendered configuration before deploying

This renders Compose and runs no containers:

```bash
cd /opt/composio-ops
docker compose -f compose.prod.yaml --env-file .env.production config >/dev/null \
  && echo "compose renders"
```

Confirm the browser-worker container will actually see what you just set.
**browser-worker has no `env_file`** — it only receives what `compose.prod.yaml`
lists explicitly — so this check is the point of the whole exercise:

```bash
docker compose -f compose.prod.yaml --env-file .env.production config --format json \
  | python3 -c '
import json, sys
env = json.load(sys.stdin)["services"]["browser-worker"]["environment"]
for name in (
    "ALLOW_LIVE_BROWSER", "MERCURY_API_KEY", "BROWSER_STORAGE_STATE_KEY",
    "BROWSER_INTERACTIVE_HITL_ENABLED", "COMPANY_LEGAL_NAME",
    "BROWSER_AGENT_MAX_STEPS", "ONBOARDING_ACTION_DECISION_TOTAL_SECONDS",
):
    print(name, "->", "set" if env.get(name) else "EMPTY")
'
```

`EMPTY` for `MERCURY_API_KEY` means the deploy gate will refuse the release
anyway — it asserts that key in both `api` and `browser-worker`.

---

## 5. Deploy

`.env.production` never leaves the host; the workflow only tells the host which
reviewed revision to activate.

- **Normal path:** push the reviewed revision to `main`. CI must go green; the
  **Deploy** workflow then runs `scripts/deploy-droplet.sh` on the Droplet.
- **Config-only change (this cutover):** nothing in Git changed, so trigger
  **Deploy → Run workflow** manually (`workflow_dispatch`) to re-activate the
  current revision with the new environment.

`deploy-droplet.sh` is transactional: it validates the rendered contract, drains
in-flight browser work, verifies a restorable backup, activates the exact
pre-built images, proves public TLS and the auth boundary, and rolls back to the
previous image identities on any failure.

---

## 6. Post-deploy verification

### 6a. Health reports a browser provider

The API is not publicly exposed, so ask it from inside the container (the token
is read from the process environment and never appears in your shell history):

```bash
cd /opt/composio-ops
docker compose -f compose.prod.yaml exec -T api python -c '
import json, os, urllib.request
request = urllib.request.Request(
    "http://127.0.0.1:8000/api/system/health",
    headers={"X-Ops-Internal-Token": os.environ["OPS_INTERNAL_API_TOKEN"]},
)
payload = json.load(urllib.request.urlopen(request, timeout=10))
print("status:", payload["status"])
for provider in payload.get("providers", []):
    if provider["provider"] == "playwright":
        print("playwright:", json.dumps(provider, indent=2))
print("browser_service:", json.dumps(payload.get("browser_service"), indent=2))
'
```

**Pass:** a `playwright` entry appears in `providers` and is configured/ready,
and `browser_service` is populated rather than null. If `playwright` is missing
or reports unconfigured, one of the three companions from step 3 is absent —
the flag alone never satisfies `browser_configuration_state`.

### 6b. A `pipedrive` run's live view returns a grant

Sign in to `https://<DOMAIN>` with `OPS_AUTH_USERNAME` / `OPS_AUTH_PASSWORD`,
start a run for the `pipedrive` app, and open its live view once the run reaches
a browser step.

**Pass:** the live view renders an interactive session — `GET
/api/runs/{run_id}/live-view` answers with `mode: "interactive_remote"` and an
`interactive_url` grant, and the viewer is embedded on the run page.

**`mode: "screenshot"`** means the browser is live but interactive HITL is off:
set `BROWSER_INTERACTIVE_HITL_ENABLED=true` and redeploy. You get masked PNG
frames, not control.

**`mode: "unavailable"`** means no viewer exists at all — recheck
`ALLOW_LIVE_BROWSER` and the browser-worker health.

**A `502 INVALID_INTERACTIVE_GRANT`** means the grant's origin did not match
what the frontend expects. All three of the API's `BROWSER_SERVICE_URL`, the
worker's `BROWSER_NOVNC_BASE_URL`, and the web container's `BROWSER_SERVICE_URL`
must name the same origin; `compose.prod.yaml` pins all three to
`http://browser-worker:8081` for exactly this reason.

Control is only offered while the run is in HITL. A view-only stream on a
running session is the designed behaviour, not a failure.

---

## 7. Turning it back off

Every switch is independently reversible. Set the flag back to `false` in
`.env.production` and re-run the Deploy workflow; the next release starts
fail-closed again. `BROWSER_STORAGE_STATE_KEY` is the one exception worth
thinking about: blanking it stops persistence immediately, and the saved blobs
on the `browser_profiles` volume become unreadable if you later set a *different*
key. Keep the original key with your other secrets.

If a cutover goes wrong, restoring the backup from step 0 and re-running Deploy
is faster than debugging the live stack:

```bash
cd /opt/composio-ops
cp .env.production.bak.<timestamp> .env.production
# then re-run the Deploy workflow
```
