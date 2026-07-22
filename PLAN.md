# PLAN.md — Composio Autonomous Toolkit Access Pipeline

> Codex execution plan for the private P2 repository. Verified against current official documentation on 2026-07-22.


## 0. Repository Boundary and Exact Local Setup

### Current P1 source repository

```text
/Users/dheerajjoshi/composio
```

This is the existing research repository. It already contains the locked 19-field P1 dataset in `out/results.json`. The current `AppRecord` contains broad auth/access/buildability fields but does not contain all operational fields required by P2, such as exact signup URL, OAuth endpoints, scope definitions, contact address, and credential field names.

### New private P2 repository

Create a separate Desktop repository. Do not run the new Codex implementation inside the public P1 repository.

```text
/Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent
```

Bootstrap commands:

```bash
cd /Users/dheerajjoshi/Desktop
mkdir -p composio-toolkit-ops-agent
cd composio-toolkit-ops-agent

git init -b main
mkdir -p data/p1 private ops tests fixtures scripts

gh repo create dheeraj3587/composio-toolkit-ops-agent \
  --private \
  --source=. \
  --remote=origin
```

Copy only the P1 data snapshot, not the P1 application code:

```bash
cp /Users/dheerajjoshi/composio/out/results.json data/p1/results.json
cp /Users/dheerajjoshi/composio/out/composio_coverage.json data/p1/composio_coverage.json
```

Record provenance so P2 can show exactly which P1 snapshot it consumed:

```bash
P1_SHA=$(git -C /Users/dheerajjoshi/composio rev-parse HEAD)
RESULTS_SHA=$(shasum -a 256 data/p1/results.json | awk '{print $1}')
COVERAGE_SHA=$(shasum -a 256 data/p1/composio_coverage.json | awk '{print $1}')

cat > data/p1/SNAPSHOT.json <<EOF
{
  "source_repository": "dheeraj3587/composio-ai-product-ops",
  "source_commit": "$P1_SHA",
  "results_sha256": "$RESULTS_SHA",
  "coverage_sha256": "$COVERAGE_SHA",
  "copied_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
```

Place this file at:

```text
/Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent/PLAN.md
```

The P2 repository must not include:

- `interview2.md`
- `INTERVIEW_PREP.md`
- meeting transcripts
- raw provider credentials
- P1 dashboard/report code
- P1 hand-check artifacts unless a specific test needs a small sanitized fixture

### P1 data contract used by P2

P2 reads these existing fields:

```text
app
slug
auth_methods
access_model.kind
access_model.note
api_type
buildability
main_blocker
recommended_next_action
evidence_urls
primary_docs_url
confidence
verification_status
```

P2 must not edit `data/p1/results.json`. Operational enrichment is stored separately under `private/runs` or the operations database.

### First commit

```bash
cp /path/to/downloaded/PLAN.md ./PLAN.md
cat > README.md <<'EOF'
# Composio Toolkit Ops Agent

Private P2 operations layer consuming the verified P1 research snapshot.
See PLAN.md for the implementation contract.
EOF

cat > .gitignore <<'EOF'
.env
.env.*
!.env.example
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
private/
*.db
*.sqlite
*.sqlite3
storage_state.json
auth.json
cookies.json
recordings/private/
screenshots/private/
.DS_Store
EOF

git add PLAN.md README.md .gitignore data/p1

git commit -m "chore: bootstrap private P2 operations agent"
git push -u origin main
```

---

## 1. Goal

Extend the existing `composio-ai-product-ops` research repository into a working **P1 → P2 → P3 pre-integrator pipeline**.

The system accepts an app name and:

1. Reuses or runs P1 API research.
2. Determines whether access is self-serve, approval-based, partner-gated, hybrid, blocked, or unclear.
3. For self-serve apps, navigates the developer onboarding flow, creates the auth/developer app, selects scopes, and obtains credential material.
4. For gated apps, finds the official contact and manages outreach/back-and-forth through Gmail using Composio.
5. Invokes HITL correctly for unavoidable human steps such as CAPTCHA, OTP, passkey, legal acceptance, billing, or provider verification.
6. Never exposes passwords, API keys, client secrets, access tokens, refresh tokens, cookies, or authorization codes to the LLM, logs, UI, GitHub, screenshots, normal JSON, or unencrypted checkpoints.
7. Produces a standardized **IntegratorBundle** for P3.

Assignment-quality success means:

- 10 apps researched and routed correctly.
- At least one real Browser Use onboarding flow.
- At least one real Composio Gmail outreach flow.
- One demonstrated HITL pause/resume.
- One credential-capture demonstration that returns only a secret reference.
- Private GitHub repository and live working demo.

---

## 2. Confirmed P1 → P2 → P3 Scope

### P1 — Research

Input:

```json
{"app_name": "Example App"}
```

Output should include:

- API availability/type/base URL.
- Auth method.
- OAuth authorization/token URLs.
- Scopes.
- Developer portal and signup URL.
- Self-serve versus gated access.
- Production approval requirements.
- Official contact path.
- Existing Composio coverage.
- Evidence URLs and confidence.

### P2 — Operations

#### Self-serve

```text
P1 result
→ signup/login
→ developer console
→ create developer/auth app
→ configure callback URL and scopes
→ generate credentials
→ capture/store securely
→ validate safely
→ IntegratorBundle
```

#### Gated

```text
P1 result
→ official contact discovery
→ email through Composio Gmail
→ preserve thread ID
→ read and answer follow-ups
→ receive access/setup link/credentials
→ secure storage
→ IntegratorBundle
```

### P3 — Integrator

P3 is not the main assignment. The deliverable is the structured input it needs:

- Auth scheme.
- API endpoints.
- Scopes.
- Callback URLs.
- Credential references.
- Access/readiness status.
- Evidence and operational notes.

Do not spend time building a general toolkit generator before P1/P2 works.

---

## 3. Main Architecture Decision

Build a **bounded deterministic workflow with agentic workers**, not one unrestricted agent.

Use deterministic code for:

- State transitions.
- Routing.
- Retry limits.
- HITL interrupts/resume.
- Idempotency.
- Secret storage/redaction.
- Final validation.

Use LLM/browser agents for:

- Understanding unfamiliar developer portals.
- Research enrichment.
- Finding correct contact/access pages.
- Drafting outreach.
- Interpreting sanitized email replies.

```text
LangGraph workflow
├── existing P1 functions
├── Browser Use navigation agent
├── Playwright deterministic actions over CDP
├── Composio Gmail worker
├── encrypted persistence/secret vault
└── Pydantic contracts
```

---

## 4. Preserve the Existing Research Contract

The repository already has a locked 19-field `AppRecord`, verified results, reasoning logs, and a static report.

**Do not modify `schema.py` or rewrite canonical research artifacts.**

Add a separate layer:

```text
AppRecord
   ↓
P1OperationalAdapter
   ↓
OperationalResearch
   ↓
P2 graph
```

`OperationalResearch` adds execution-specific fields without changing P1:

- `developer_portal_url`
- `signup_url`
- `api_base_url`
- `authorization_url`
- `token_url`
- detailed scopes with sources
- credential field names
- production approval flag
- contact email/form URL
- required signup/account information

---

## 5. Technology Stack and Locked Versions

Use Python 3.11 for the new private repository. The package set below was checked against current official PyPI/project documentation on 2026-07-22.

### Runtime dependencies

```text
google-genai==2.12.1
perplexityai==0.42.0
pydantic==2.12.5
python-dotenv==1.2.2
tenacity==9.1.4

langgraph==1.2.9
langgraph-checkpoint-sqlite==3.1.0
pycryptodome>=3.23,<4

browser-use-sdk==3.10.0
playwright==1.61.0

composio==0.18.0

streamlit==1.59.2
aiosqlite==0.22.1
cryptography==48.0.1
httpx>=0.28,<1
```

### Development dependencies

```text
pytest>=8.4,<9
pytest-asyncio>=1.1,<2
ruff>=0.12,<1
mypy>=1.17,<2
pip-audit>=2.9,<3
detect-secrets>=1.5,<2
```

Create `requirements.txt` with the runtime dependencies and `requirements-dev.txt` with:

```text
-r requirements.txt
pytest>=8.4,<9
pytest-asyncio>=1.1,<2
ruff>=0.12,<1
mypy>=1.17,<2
pip-audit>=2.9,<3
detect-secrets>=1.5,<2
```

Install:

```bash
cd /Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python -m playwright install chromium
```

After the first passing integration run, freeze transitive dependencies:

```bash
pip freeze > requirements-lock.txt
```

Do not change versions during implementation unless a verified incompatibility exists. Record every change in `DECISIONS.md`.

### Model allocation

| Task | Model/API | Reason |
|---|---|---|
| Missing operational-field enrichment | `gemini-3.1-pro-preview` | Strong reasoning and structured output |
| Email drafting and sanitized reply classification | `gemini-3.5-flash` | Lower latency/cost; structured output |
| Official documentation discovery | Perplexity Search API | Raw ranked URLs; application retains control |
| Browser navigation | Browser Use Cloud v3 agent | Handles unfamiliar portals |
| Deterministic form/secret handling | Playwright over CDP | No LLM access to secret values |
| Gmail operations | Composio Python SDK session | Authentication and Gmail tool execution |

Do not use Sonar-generated prose as evidence when raw Search API results and official pages are available. Search discovers URLs; the application fetches official pages; Gemini extracts structured fields from the fetched evidence.

### Explicitly excluded

- Celery and Redis
- PostgreSQL for the assignment MVP
- Vector databases and RAG
- Playwright MCP in addition to Browser Use
- A second browser automation provider
- LangChain agent executors; use LangGraph directly

---

## 5A. Documentation Reading Order

Codex must read the following official pages before implementing the corresponding phase. It must not infer SDK signatures from memory.

### Before LangGraph work

1. `https://docs.langchain.com/oss/python/langgraph/persistence`
   - Threads and `thread_id`
   - `AsyncSqliteSaver`
   - checkpoint history
   - `EncryptedSerializer.from_pycryptodome_aes`
2. `https://docs.langchain.com/oss/python/langgraph/interrupts`
   - `interrupt()`
   - `Command(resume=...)`
   - same-thread resume
   - node restart behavior
   - idempotent side effects before an interrupt
3. `https://pypi.org/project/langgraph-checkpoint-sqlite/`
   - `LANGGRAPH_STRICT_MSGPACK=true`

### Before Browser Use work

1. `https://docs.browser-use.com/cloud/quickstart`
2. `https://docs.browser-use.com/cloud/agent/human-in-the-loop`
   - live URL
   - same session follow-up
   - 15-minute inactivity timeout
   - 4-hour maximum duration
3. `https://docs.browser-use.com/cloud/guides/authentication`
   - persistent profiles
   - profile state is saved when the session is stopped
4. `https://docs.browser-use.com/cloud/guides/secrets`
   - domain-scoped secrets
   - `allowed_domains`
5. `https://docs.browser-use.com/cloud/browser/playwright-puppeteer-selenium`
   - `browsers.create()`
   - `cdp_url`
   - `live_url`
   - Playwright `connect_over_cdp()`

### Before Composio work

1. `https://docs.composio.dev/docs/how-composio-works`
   - session lifecycle
   - session reuse
2. `https://docs.composio.dev/docs/configuring-sessions`
   - enabling only specified Gmail tools
   - raw tool schema inspection
3. `https://docs.composio.dev/docs/authentication`
4. `https://docs.composio.dev/docs/programmatic-auth-configs`
   - custom OAuth credentials
   - callback URL
   - required auth fields
5. `https://docs.composio.dev/docs/auth-configuration/connected-accounts`
6. `https://docs.composio.dev/toolkits/gmail`

### Before LLM extraction work

1. `https://ai.google.dev/gemini-api/docs/structured-output`
2. `https://ai.google.dev/gemini-api/docs/models/gemini-3.1-pro-preview`
3. `https://docs.perplexity.ai/docs/search/quickstart`
4. `https://docs.perplexity.ai/docs/sonar/prompt-guide`

### Before secret capture

1. `https://playwright.dev/python/docs/api/class-browsertype#browser-type-connect-over-cdp`
2. `https://cryptography.io/en/latest/fernet/`

---

## 6. High-Level System

```text
┌──────────────────────────────────────────────────────┐
│ Streamlit                                             │
│ app input · timeline · live browser · resume · email │
└──────────────────────────┬───────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────┐
│ LangGraph P2                                          │
│ stable thread ID · durable checkpoints · interrupts  │
└───────┬─────────────────┬────────────────────┬───────┘
        ▼                 ▼                    ▼
  P1 adapter       Browser Use + PW      Composio Gmail
        └─────────────────┬────────────────────┘
                          ▼
                Security/storage layer
                          ▼
                   IntegratorBundle
```

---

## 7. Graph State Machine

### Top level

```text
START
→ load_or_run_p1
→ enrich_operational_fields
→ validate_evidence
→ classify_access
   ├─ self_serve → self_serve_subgraph
   ├─ approval_required → gated_subgraph
   ├─ partner_gated → gated_subgraph
   ├─ hybrid → self_serve_subgraph → gated_subgraph
   ├─ blocked → finalize_blocked
   └─ unknown → one_browser_probe → reclassify_once
→ validate_integrator_bundle
→ persist_sanitized_result
→ END
```

### Self-serve

```text
prepare_profile
→ create_browser_session
→ signup/login
→ challenge detected?
   ├─ yes → HITL interrupt → resume same browser/thread
   └─ no
→ developer console
→ create/reuse developer app
→ configure callback URLs/scopes
→ generate credentials
→ Playwright secure capture
→ encrypted vault
→ safe credential validation
→ IntegratorBundle
```

### Gated

```text
discover official contact
→ compose outreach
→ send with Composio Gmail
→ persist Gmail thread ID
→ poll/fetch thread
→ extract/store secrets before LLM
→ classify sanitized reply
   ├─ more info → answer → reply → poll
   ├─ meeting → record/reply from configured availability
   ├─ setup link → transition to browser flow
   ├─ credentials → store/validate
   ├─ rejected → blocked
   └─ unclear → retry once → manual review
→ IntegratorBundle
```

---

## 8. Core State

Create `ops/state.py`.

```python
from typing import Literal, TypedDict

AccessRoute = Literal[
    "self_serve", "approval_required", "partner_gated",
    "hybrid", "blocked", "unknown"
]

RunStatus = Literal[
    "created", "researching", "route_selected", "browser_running",
    "waiting_for_hitl", "outreach_sent", "waiting_for_reply",
    "credentials_ready", "blocked", "failed", "completed"
]

class OperationsState(TypedDict, total=False):
    run_id: str
    thread_id: str
    app_name: str
    app_slug: str

    p1_record: dict
    operational_research: dict
    evidence_urls: list[str]
    missing_fields: list[str]

    access_route: AccessRoute
    route_reason: str
    status: RunStatus

    browser_profile_id: str
    browser_session_id: str
    browser_live_url: str
    current_url: str
    browser_attempts: int

    hitl_request: dict | None
    hitl_count: int

    gmail_session_id: str
    gmail_thread_id: str
    intended_recipient: str
    actual_recipient: str
    outreach_round: int
    latest_reply_class: str

    credential_refs: dict[str, str]
    validation_status: str

    integrator_bundle: dict | None
    errors: list[dict]
    audit_events: list[dict]
```

### Mandatory restriction

Never put these raw values in state:

- Password
- API key
- Client secret
- Access/refresh token
- TOTP seed
- Cookie
- Authorization code

Only store references:

```json
{
  "client_id": "vault://app/client_id/123",
  "client_secret": "vault://app/client_secret/456"
}
```

---

## 9. Pydantic Contracts

Create `ops/models.py`; use `extra="forbid"`.

```python
class CompanyProfile(BaseModel):
    legal_name: str
    website: str
    work_email_ref: str
    use_case: str
    expected_volume: str | None = None
    callback_urls: list[str] = []

class OperationsRequest(BaseModel):
    app_name: str
    company: CompanyProfile
    requested_scope_policy: Literal["minimum", "recommended", "maximum"] = "maximum"
    dry_run: bool = True
    outreach_recipient_override: str | None = None
```

```python
class ScopeRequirement(BaseModel):
    name: str
    description: str | None = None
    required: bool | None = None
    source_url: str

class OperationalResearch(BaseModel):
    app_name: str
    app_slug: str
    api_available: bool | None
    api_type: str
    api_base_url: str | None
    auth_methods: list[str]
    authorization_url: str | None
    token_url: str | None
    credential_fields: list[str]
    scopes: list[ScopeRequirement]
    developer_portal_url: str | None
    signup_url: str | None
    access_route: AccessRoute
    production_approval_required: bool | None
    contact_email: str | None
    contact_url: str | None
    evidence_urls: list[str]
    confidence: float
```

```python
class IntegratorBundle(BaseModel):
    app_name: str
    app_slug: str
    readiness: Literal[
        "credentials_ready", "awaiting_provider",
        "human_action_required", "blocked", "failed"
    ]
    api_type: str
    api_base_url: str | None
    auth_scheme: str
    authorization_url: str | None
    token_url: str | None
    scopes: list[str]
    callback_urls: list[str]
    credential_refs: dict[str, str]
    access_route: AccessRoute
    provider_account_id: str | None
    developer_app_id: str | None
    evidence_urls: list[str]
    operational_notes: list[str]
    created_at: str
```

---

## 10. P1 Adapter

Create `ops/p1_adapter.py`.

Responsibilities:

1. Normalize app name/slug.
2. Find an existing record in `out/results.json`.
3. Reuse it when present.
4. Otherwise call the existing single-app research pipeline.
5. Perform operational enrichment using only official evidence.
6. Validate with Pydantic.
7. Keep canonical and operational output separate.

```python
async def get_operational_research(app_name: str) -> OperationalResearch:
    ...
```

Prompt rules:

- Never invent scopes.
- Every scope needs an official source URL.
- Use `unknown` when unsupported.
- Separate public docs from self-serve credential availability.
- Separate sandbox from production access.
- Treat sales/contact/application review as gated.
- Detect custom OAuth-app requirements.

---

## 11. Deterministic Routing

```python
def classify_access(r: OperationalResearch) -> AccessRoute:
    if r.api_available is False:
        return "blocked"
    if r.production_approval_required is True:
        return "hybrid" if r.signup_url else "approval_required"
    if (r.contact_email or r.contact_url) and not r.signup_url:
        return "partner_gated"
    if r.signup_url and r.developer_portal_url:
        return "self_serve"
    return "unknown"
```

For unknown:

- One bounded browser probe.
- Reclassify once.
- Stop instead of infinite retries.

---

## 12. Browser Use + Playwright

### Why both

- Browser Use understands unknown pages and navigates.
- Playwright executes exact deterministic actions and captures secrets without involving an LLM.

### Lifecycle

```text
create/reuse Browser Use profile
→ create Browser Use browser/session
→ save session ID/live URL
→ navigate with Browser Use
→ attach Playwright through CDP
→ deterministic form/credential actions
→ stop cleanly to persist profile
```

### Security rules

- Use `allowed_domains`.
- Pass existing credentials as domain-scoped Browser Use secrets or direct Playwright values.
- Never place credentials in natural-language tasks.
- Disable vision on login/security/credential pages.
- Keep one operational browser profile and store only its ID.

Create `ops/browser_worker.py`:

```python
class BrowserWorker:
    async def start(self, profile_id: str | None): ...
    async def navigate_onboarding(self, context, research): ...
    async def resume_after_hitl(self, context, signal: str): ...
    async def stop(self, context): ...
```

---

## 13. HITL

Invoke HITL for:

- CAPTCHA
- Email/phone OTP
- Passkey/security key
- Device approval
- Provider verification
- Legal acceptance
- Billing/payment
- Ambiguous account selection or irreversible action

Do not pause every normal action.

Use a durable checkpointer, stable `thread_id`, `interrupt()`, and `Command(resume=...)`.

```python
human_result = interrupt({
    "type": "email_otp",
    "app_name": state["app_name"],
    "message": "Complete verification in the live browser.",
    "live_url": state["browser_live_url"],
    "expected_completion_signal": "Developer dashboard is visible"
})
```

Important LangGraph behavior: an interrupted node restarts from its beginning on resume.

Therefore:

- Put external side effects in separate nodes.
- Never send email/create app before an interrupt in the same node.
- Persist external IDs immediately.
- Check for existing app/message before creating again.

Use encrypted SQLite checkpoints and still keep secrets out of state.

---

## 14. Developer App Creation

Create `ops/developer_app_worker.py`.

Responsibilities:

1. Find/create developer application.
2. Fill company/app/use-case fields.
3. Configure callback URLs.
4. Select scope policy.
5. Submit idempotently.
6. Save provider app ID.
7. Open credentials page.

Idempotent name:

```text
Composio Integration - <app_slug>
```

Search existing apps before creating duplicates.

Scope policies:

- `minimum`
- `recommended`
- `maximum`

Persist requested and granted scopes separately.

---

## 15. Secure Credential Capture

The LLM must never read generated credentials.

```text
Browser Use reaches credentials page
→ Browser Use stops before reading values
→ Playwright attaches via CDP
→ deterministic selector reads value
→ value encrypted immediately
→ local variable discarded
→ graph gets vault reference only
```

Create `ops/credential_capture.py`:

```python
class CredentialCapture:
    async def capture_and_store(
        self,
        cdp_url: str,
        app_slug: str,
        field_selectors: dict[str, str],
    ) -> dict[str, str]:
        ...
```

Keep app-specific selectors in `ops/app_adapters/<app>.py`.

### Credentials arriving in email

```text
Composio fetches raw message deterministically
→ secret detector extracts/stores suspected values
→ placeholders replace raw values
→ sanitized body goes to LLM classifier
```

---

## 16. Secret Store and Redaction

Create `ops/secret_store.py`.

```python
class SecretStore(Protocol):
    def put(self, *, app_slug: str, kind: str, value: str) -> str: ...
    def get(self, reference: str) -> str: ...
    def delete(self, reference: str) -> None: ...
```

MVP:

- SQLite vault.
- `cryptography.fernet.Fernet` encryption.
- key from `SECRET_VAULT_KEY`.
- reference format: `vault://<app>/<kind>/<id>`.

Create `ops/redaction.py` to redact:

- API key patterns
- JWTs
- Bearer tokens
- OAuth secrets
- Authorization headers
- Private keys
- Password assignments
- token-bearing URLs

Never expose secrets in exceptions, repr, validation errors, logs, Streamlit state, screenshots, fixtures, or JSON output.

---


## 16A. Security Threat Model and Non-Negotiable Controls

### Threats this assignment must handle

1. A browser agent leaks credentials in its output or screenshot.
2. Raw secrets enter LangGraph checkpoints.
3. Email credentials received from a provider are sent to Gemini for classification.
4. Logs/exceptions print authorization headers or form values.
5. Streamlit stores secret values in session state.
6. A resumed graph duplicates account creation or sends duplicate email.
7. Browser navigation is redirected to a malicious domain.
8. Private SQLite databases are committed or deployed without encryption.
9. Demo mode accidentally contacts a real vendor.
10. Codex adds sample secrets to fixtures.

### Controls

#### Secret type boundary

Raw secret values may exist only inside:

```text
credential_capture.py local variables
secret_store.py encryption/decryption boundary
credential_validator.py request-construction boundary
composio_auth_config.py in-memory SDK call boundary
```

All other modules receive only `vault://...` references.

#### Pydantic enforcement

`IntegratorBundle.credential_refs` values must match:

```regex
^vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+$
```

Add a model validator that rejects likely raw JWTs, API keys, bearer tokens, private keys, or strings longer than the allowed reference format.

#### Browser agent boundary

- The agent stops at `credential_page_ready`.
- The output schema has no field capable of returning credential values.
- `allowed_domains` is mandatory.
- Vision is disabled for login/security/credential pages where supported.
- CAPTCHA, OTP, TOTP, passkey, security key, billing, and legal acceptance invoke HITL.
- Do not use Browser Use automatic TOTP generation for this project, even if supported; the interviewer explicitly asked for correct HITL and no secret exposure.

#### Email boundary

Raw Gmail messages are processed in this exact order:

```text
Composio fetch
→ deterministic secret detector
→ secret values stored in vault
→ replacements inserted: [REDACTED_SECRET:client_secret]
→ sanitized thread persisted
→ sanitized thread passed to Gemini
```

#### Logging

Install one logging filter at application startup. It redacts:

- `Authorization` headers
- query parameters named `token`, `code`, `key`, `secret`, `password`
- JWT-like values
- PEM private-key blocks
- known provider key prefixes
- fields matching Pydantic `SecretStr`

Structured audit logs contain event type, run ID, provider, sanitized status, and external IDs only.

#### Checkpoint protection

- Raw secrets never enter graph state.
- Use `EncryptedSerializer.from_pycryptodome_aes(key=...)` with `AsyncSqliteSaver`.
- Set `LANGGRAPH_STRICT_MSGPACK=true`.
- Store checkpoint DB under `private/` with mode `0600`.

#### Secret vault

- Use a separate Fernet key from `SECRET_VAULT_KEY`.
- Set `os.umask(0o077)` at process start.
- Create DB and directories with owner-only permissions.
- Never expose a generic `list_all_secrets` method.
- `get()` requires a precise reference and is used only by boundary modules.

#### Demo email policy

Default:

```text
ALLOW_LIVE_VENDOR_EMAIL=false
OUTREACH_RECIPIENT_OVERRIDE=<your controlled test inbox>
```

The pipeline remains autonomous. This environment policy prevents a development run from contacting a real vendor accidentally; it is not a human approval step.

#### Automated security gates

Before every push:

```bash
detect-secrets scan --all-files > .secrets.baseline
ruff check .
pytest -q
pip-audit -r requirements.txt

git grep -nEi '(client_secret|access_token|refresh_token|api[_-]?key|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' \
  -- ':!PLAN.md' ':!.secrets.baseline'
```

The grep may find field names in source code. The security test must distinguish schema names from assigned secret-looking values.

---

## 17. Composio Gmail

Create a Composio session scoped only to Gmail. Enable/preload only:

- `GMAIL_CREATE_EMAIL_DRAFT`
- `GMAIL_SEND_DRAFT`
- `GMAIL_SEND_EMAIL`
- `GMAIL_FETCH_EMAILS`
- `GMAIL_FETCH_MESSAGE_BY_THREAD_ID`
- `GMAIL_REPLY_TO_THREAD`
- `GMAIL_LIST_THREADS`

Create `ops/gmail_worker.py`:

```python
class GmailWorker:
    async def ensure_connected(self) -> str: ...
    async def send_outreach(self, recipient, subject, body, idempotency_key): ...
    async def fetch_thread(self, thread_id): ...
    async def reply(self, thread_id, body, idempotency_key): ...
```

Connect Gmail once through a Composio Connect Link. Store only Composio session/connected-account IDs; Composio manages OAuth tokens.

### Demo protection

```env
OUTREACH_RECIPIENT_OVERRIDE=controlled-test-address
ALLOW_LIVE_VENDOR_EMAIL=false
```

Persist both intended and actual recipient. This is a deployment policy, not per-email approval.

Subject correlation:

```text
[API Access Request][run:<short_run_id>] <App> × Composio
```

Persist `gmail_thread_id`.

---

## 18. Outreach Conversation State

Create `ops/outreach.py` and `ops/reply_classifier.py`.

Reply classes:

```python
Literal[
  "no_reply", "more_information_required", "meeting_requested",
  "approved_setup_required", "credentials_received", "rejected",
  "automated_response", "unclear"
]
```

Rules:

- Use only configured company facts.
- Never invent customers, certifications, partnerships, legal commitments, or volume.
- Keep replies in the same Gmail thread.
- `approved_setup_required` transitions to browser onboarding.
- `credentials_received` runs secure extraction before LLM classification.
- `unclear` retries once, then stops.

Limits:

```env
MAX_OUTREACH_ROUNDS=5
MAX_UNCLEAR_RETRIES=1
```

MVP reply monitoring:

- Streamlit “Check for reply” button.
- CLI poll command.

Composio trigger is bonus, not a blocker.

---

## 19. Credential Validation

Create `ops/credential_validator.py`.

Validate with a harmless read-only endpoint:

1. `/me` or identity endpoint.
2. workspace/account list.
3. health endpoint.

Never perform writes/deletes/purchases.

Persist only status, endpoint, HTTP code, and timestamp—not private response bodies.

---

## 20. Storage

Create `ops/storage.py`.

```sql
CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  thread_id TEXT UNIQUE NOT NULL,
  app_name TEXT NOT NULL,
  app_slug TEXT NOT NULL,
  status TEXT NOT NULL,
  access_route TEXT,
  browser_session_id TEXT,
  browser_live_url TEXT,
  gmail_session_id TEXT,
  gmail_thread_id TEXT,
  integrator_bundle_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

```sql
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  sanitized_payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

Audit events include research loaded, route selected, browser started, HITL requested/resumed, outreach sent, reply received, credential stored/validated, and completed.

---

## 21. Repository Layout

```text
ops/
├── __init__.py
├── cli.py
├── models.py
├── state.py
├── graph.py
├── routing.py
├── p1_adapter.py
├── operational_research.py
├── browser_worker.py
├── developer_app_worker.py
├── credential_capture.py
├── credential_validator.py
├── gmail_worker.py
├── outreach.py
├── reply_classifier.py
├── secret_store.py
├── redaction.py
├── storage.py
├── config.py
└── app_adapters/
    ├── base.py
    └── <demo_app>.py

streamlit_app.py
fixtures/{p1,browser,gmail}/
tests/test_ops_*.py
Dockerfile
.env.example
PLAN.md
```

---

## 22. CLI and UI

CLI:

```bash
python -m ops.cli run "Example App"
python -m ops.cli status <run_id>
python -m ops.cli resume <run_id>
python -m ops.cli poll-email <run_id>
python -m ops.cli show-output <run_id>
```

Streamlit should show:

- Input/company profile.
- Sanitized timeline.
- Access route.
- Browser live URL/embed.
- HITL instruction and resume button.
- Email intended/actual recipient and thread status.
- Check-for-reply button.
- Final IntegratorBundle with refs only.

Never add a reveal-secret button.

---

## 23. Environment and Git Ignore

`.env.example`:

```env
PERPLEXITY_API_KEY=
GOOGLE_GENAI_API_KEY=
COMPOSIO_API_KEY=
BROWSER_USE_API_KEY=
LANGGRAPH_AES_KEY=
LANGGRAPH_STRICT_MSGPACK=true
SECRET_VAULT_KEY=
COMPOSIO_USER_ID=ops-assignment-user
COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID=
COMPANY_LEGAL_NAME=
COMPANY_WEBSITE=
COMPANY_WORK_EMAIL=
COMPANY_USE_CASE=
COMPANY_EXPECTED_VOLUME=
OAUTH_CALLBACK_URLS=
OUTREACH_RECIPIENT_OVERRIDE=
ALLOW_LIVE_VENDOR_EMAIL=false
MAX_OUTREACH_ROUNDS=5
MAX_BROWSER_ATTEMPTS=2
MAX_HITL_COUNT=3
OPS_DB_PATH=./private/ops.db
CHECKPOINT_DB_PATH=./private/checkpoints.db
SECRET_VAULT_DB_PATH=./private/secret_vault.db
```

`.gitignore` additions:

```gitignore
.env
.env.*
!.env.example
private/
*.db
*.sqlite
*.sqlite3
auth.json
storage_state.json
cookies.json
secrets/
recordings/private/
screenshots/private/
```

---

## 24. Tests

### Unit

- Pydantic rejects extra/raw-secret fields.
- Routing tests all access classes.
- Unknown route probes once.
- Secret DB has no plaintext.
- Wrong vault key cannot decrypt.
- Redaction handles keys/JWT/bearer/private keys/passwords.
- HITL persists and resumes same thread.
- Resume does not duplicate side effects.
- Gmail send is idempotent.
- Demo recipient override works.
- Raw email is sanitized before model call.

### Integration

Fixtures for:

- Developer portal observations.
- OTP challenge.
- Credential page.
- Provider approval/rejection emails.
- Credential-bearing email.

Paid live tests are opt-in:

```bash
RUN_LIVE_TESTS=1 pytest -m live
```

Add a secret-regression scan that fails if generated/committed output contains secret-like patterns.

---

## 25. Ten-App Demo Matrix

Select from existing verified results instead of memory:

| Category | Count |
|---|---:|
| Self-serve + Build Now | 4 |
| OAuth self-serve | 2 |
| Partner/approval gated | 2 |
| Hybrid | 1 |
| Blocked/unknown | 1 |

Depth:

- All 10: enrichment + routing.
- 2: Browser Use launched.
- 1: HITL pause/resume.
- 1: developer app attempted/completed.
- 1: Composio Gmail send to controlled test address.
- 1: reply fetched/classified.
- 1: test credential encrypted and represented only by `vault://` reference.

Do not claim all 10 produced real credentials unless true.

---

## 26. Deployment

Use Docker on the existing DigitalOcean droplet or Render.

```bash
streamlit run streamlit_app.py \
  --server.address 0.0.0.0 \
  --server.port ${PORT:-8501}
```

Mount persistent `/private` storage for ops DB, checkpoints, and encrypted vault.

Set secrets through host settings only.

---


## 26A. Phase Gates — Codex Must Stop at Each Gate

Codex does not proceed automatically from one phase to the next.

### Gate A — Skeleton security

Evidence required:

```text
all existing tests pass
new model/storage/redaction tests pass
secret vault DB contains no plaintext fixture value
no raw secret is representable in IntegratorBundle
```

### Gate B — P1 snapshot adapter

Evidence required:

```text
HubSpot lookup returns the copied P1 row
Salesforce lookup returns Gated
unknown app returns a typed not_found result
P1 JSON remains byte-for-byte unchanged
```

### Gate C — LangGraph HITL

Evidence required:

```text
run interrupts
Python process exits
new process loads same thread_id
resume continues
mock email/app side effect count remains exactly 1
```

### Gate D — Composio Gmail

Evidence required:

```text
connected Gmail profile validated with GMAIL_GET_PROFILE
test email sent through Composio to override recipient
thread ID persisted
reply fetched by thread ID
sanitized reply reaches classifier
```

### Gate E — Browser Use

Evidence required:

```text
persistent profile created/reused
live_url displayed
allowed_domains enforced
HITL interruption occurs on a controlled challenge
session stopped in success and exception paths
```

### Gate F — Secret capture

Evidence required:

```text
Playwright reads a test secret from controlled fixture
only vault ref enters state/output
plaintext absent from logs/checkpoints/ops DB/UI snapshot
wrong vault key cannot decrypt
```

### Gate G — Real app demo

Evidence required:

```text
one real self-serve developer portal reaches a truthful state
one gated flow sends a controlled test outreach
10 P1 apps are routed and displayed
limitations identify which paths were simulated versus real
```

---

## 27. Implementation Phases

### Phase 0 — Security first

- Private branch/repo.
- `.gitignore` and `.env.example`.
- Check no secret is already tracked.
- Add secret scan.

### Phase 1 — Contracts/storage

Implement models, state, storage, vault, redaction, tests. No external APIs.

### Phase 2 — P1 adapter/routing

Reuse `out/results.json`, fallback to existing one-app research, enrich operational fields, route deterministically.

### Phase 3 — LangGraph/HITL

Encrypted SQLite checkpoints, mock workers, interrupt/resume, idempotency tests.

### Phase 4 — Composio Gmail

Real controlled email, preserve thread, fetch/reply, classify sanitized reply.

### Phase 5 — Browser Use

Profile/session, allowlist, live URL, onboarding, HITL, clean stop.

### Phase 6 — Playwright secure capture

CDP attach, one app adapter, deterministic actions, encrypted credential capture.

### Phase 7 — Streamlit

Input, timeline, HITL/resume, Gmail polling, final bundle.

### Phase 8 — Ten apps/deploy

Run breadth, deploy, README, demo recording, final secret scan.

---

## 28. Time-Boxed Order

| Time | Task |
|---|---|
| 0:00–0:30 | Repo safety/env |
| 0:30–2:00 | Models/vault/redaction |
| 2:00–3:00 | P1 adapter/routing |
| 3:00–4:30 | LangGraph/HITL |
| 4:30–6:30 | Composio Gmail |
| 6:30–9:00 | Browser Use |
| 9:00–10:00 | Playwright capture |
| 10:00–11:00 | Streamlit |
| 11:00–12:30 | Ten-app run |
| 12:30–14:00 | Deploy/docs/demo |

If behind schedule, reduce full portal adapters—not security, HITL, Gmail, or the real browser demo.

---

## 29. Definition of Done

### Functional

- [ ] App-name input.
- [ ] P1 reused.
- [ ] Operational enrichment.
- [ ] Deterministic route.
- [ ] Browser Use self-serve route.
- [ ] Composio Gmail gated route.
- [ ] Reply fetch/classification.
- [ ] Durable HITL resume.
- [ ] Deterministic credential capture.
- [ ] Valid IntegratorBundle.
- [ ] Ten sanitized app results.
- [ ] Live deployment.

### Security

- [ ] No committed secret.
- [ ] No raw secret in JSON/state/log/UI/screenshot.
- [ ] Encrypted checkpoint and vault.
- [ ] Domain-restricted browser.
- [ ] Secret references only.
- [ ] Demo email override.

### Quality

- [ ] Existing/new tests pass.
- [ ] Ruff/compileall pass.
- [ ] README explains architecture and limitations.
- [ ] Private repo shared.
- [ ] Live URL works in incognito.

---

## 30. Non-Goals

- Universal portal automation.
- CAPTCHA bypass or OTP interception.
- Payment automation.
- Automatic legal acceptance.
- All 100 integrations.
- Full P3 toolkit generator.
- Production multi-tenant RBAC/secret platform.
- Distributed queues.
- Vector DB/RAG.
- Perfect UI.

---


## 30A. Production Prompt Library

All prompts are versioned files under `prompts/`. Do not keep long prompt strings embedded in Python modules.

```text
prompts/
├── operational_enrichment.system.md
├── operational_enrichment.user.md
├── browser_onboarding.md
├── browser_resume.md
├── outreach_email.system.md
├── outreach_email.user.md
├── reply_classifier.system.md
├── reply_classifier.user.md
└── scope_planner.system.md
```

Every model call must record:

```text
prompt_name
prompt_version
model
input evidence URL list
response schema name
latency
token usage
sanitized error
```

Never record full emails before redaction and never record secret values.

### Prompt 1 — Operational enrichment

`prompts/operational_enrichment.system.md`

```text
You are an API access operations analyst preparing an app for an integration engineer.

Use ONLY the supplied P1 record and Evidence Pack. Do not use memory. Do not guess.
A claim is allowed only when one supplied official source supports it.

Your task is to extract operational facts needed to obtain credentials:
- developer portal and signup URLs
- API base URL
- OAuth authorization and token URLs
- exact documented scopes
- credential field names
- production approval requirement
- official partnership/contact path
- whether access is self-serve, gated, hybrid, blocked, or unknown

Rules:
1. Prefer first-party developer documentation.
2. Public documentation does not prove self-serve credential access.
3. A sales form, partner application, app review, paid-plan prerequisite, or manual approval is gated.
4. If a field is not supported, return null/unknown.
5. Each scope must include its supporting source URL.
6. Never output or request real credential values.
7. Never add fields outside the supplied JSON schema.
8. Keep reasoning concise and evidence-specific.
```

`prompts/operational_enrichment.user.md`

```text
APP
{{app_name}}

P1 RECORD
{{p1_record_json}}

EVIDENCE PACK
{{evidence_documents_json}}

Return one OperationalResearch object that validates against the supplied schema.
```

Use Gemini structured output with `OperationalResearch.model_json_schema()`. Do not parse free-form JSON from markdown.

### Prompt 2 — Browser onboarding

`prompts/browser_onboarding.md`

```text
You are operating the official developer onboarding flow for {{app_name}}.

Goal:
- sign up or log in using only the provided domain-scoped credentials
- reach the developer console
- find or create one developer/auth application named exactly {{developer_app_name}}
- configure these callback URLs: {{callback_urls}}
- select these documented scopes: {{requested_scopes}}
- reach the page where client ID/API key/client secret can be generated

Hard boundaries:
- stay only on {{allowed_domains}}
- do not open unrelated links
- do not solve or bypass CAPTCHA
- do not generate or enter OTP, TOTP, passkey, security-key, billing, or legal-consent values
- when any such step appears, stop and return human_action_required
- do not read, copy, summarize, print, or return any credential value
- when the credential page appears, stop before exposing values and return credential_page_ready
- do not create duplicate apps; search for {{developer_app_name}} first
- do not change/delete existing applications

Return only BrowserObservation:
- status
- current_url
- page_title
- developer_app_id if visible and non-secret
- human_action_type if required
- human_instruction
- credential_field_labels
- stable selector hints that Playwright can use
- non-secret notes
```

The Browser Use output schema must not contain generic `dict[str, Any]` fields that could accidentally hold secrets.

### Prompt 3 — Resume after HITL

`prompts/browser_resume.md`

```text
The human completed the requested action in the same live browser session.
Verify the expected completion signal: {{expected_completion_signal}}.
Continue the existing onboarding task without repeating completed side effects.
Search for the existing developer app named {{developer_app_name}} before creating anything.
Stop again if another HITL condition appears.
Stop before reading or revealing any credential value.
Return only BrowserObservation.
```

### Prompt 4 — Outreach email

`prompts/outreach_email.system.md`

```text
Write a concise professional API-access request using only supplied facts.
Do not invent customers, volume, security certifications, existing partnerships,
legal commitments, or timelines. Do not claim to represent Composio unless the
configured sender identity is authorized to do so.

The message must clearly state:
- who is requesting access
- which app/API is being integrated
- intended AI-agent/toolkit use case
- requested authentication type and scopes
- callback URL if relevant
- exact question about production access and credential issuance

Return subject and plain-text body only through the supplied schema.
```

`prompts/outreach_email.user.md`

```text
COMPANY PROFILE
{{company_profile_json}}

APP RESEARCH
{{operational_research_json}}

RECIPIENT
{{recipient}}

REQUESTED SCOPES
{{requested_scopes}}
```

### Prompt 5 — Reply classifier

The input must be sanitized before this prompt is called.

`prompts/reply_classifier.system.md`

```text
Classify a sanitized reply in an API-access conversation.
The strings [REDACTED_SECRET:<type>] indicate that deterministic code already
removed and stored a possible secret. Never ask for or reconstruct the value.

Allowed classes:
- no_reply
- more_information_required
- meeting_requested
- approved_setup_required
- credentials_received
- rejected
- automated_response
- unclear

Extract:
- explicit questions asked by the provider
- official setup URLs
- stated approval/rejection reason
- required next action
- whether a browser onboarding flow should start

Use only the supplied email thread. Return the exact schema; no prose.
```

`prompts/reply_classifier.user.md`

```text
APP
{{app_name}}

SANITIZED THREAD
{{sanitized_thread_json}}

KNOWN COMPANY FACTS
{{company_profile_json}}
```

### Prompt 6 — Scope planner

`prompts/scope_planner.system.md`

```text
Select scopes only from the supplied documented scope catalog.
Never invent a scope. Respect requested policy:
- minimum: smallest set required for the target starter tools
- recommended: read/write coverage for the target starter tools without account-admin scopes
- maximum: all documented integration scopes except billing, organization ownership,
  destructive admin, or security-management scopes unless the target tools explicitly require them

Return requested scopes, excluded scopes with reason, and source URL for every scope.
```

The default assignment policy is `maximum`, because the interviewer discussed broad toolkit access. Keep the policy configurable and display the selected policy in the final output.

---

## 30B. Exact External API Contracts

### Perplexity Search API

Use the native `perplexityai` SDK and raw Search API for missing P2 fields.

```python
from perplexity import AsyncPerplexity

client = AsyncPerplexity()
result = await client.search.create(
    query=[
        f"{app_name} official developer portal API authentication",
        f"{app_name} official OAuth scopes authorization token URL",
        f"{app_name} API partner access contact production approval",
    ],
    max_results=5,
)
```

Filter candidate URLs in application code:

1. HTTPS only.
2. Official registrable domain or verified vendor-owned documentation domain.
3. Reject SEO pages, aggregators, blogs, and community answers as final evidence.
4. Fetch the selected official pages with `httpx`.
5. Limit each cleaned page to relevant headings/sections before Gemini extraction.

### Gemini structured output

Use the official `google-genai` SDK. The response must validate directly against Pydantic.

```python
from google import genai

client = genai.Client()
response = client.models.generate_content(
    model="gemini-3.1-pro-preview",
    contents=rendered_prompt,
    config={
        "response_mime_type": "application/json",
        "response_json_schema": OperationalResearch.model_json_schema(),
        "temperature": 0,
    },
)
record = OperationalResearch.model_validate_json(response.text)
```

Codex must confirm the exact SDK method/config names against the installed `google-genai==2.12.1`; if the SDK exposes the newer Interactions API in the implementation environment, use the documented equivalent rather than inventing parameters.

### Browser Use v3 session

```python
from browser_use_sdk.v3 import AsyncBrowserUse

client = AsyncBrowserUse()
profile = await client.profiles.create(
    name=f"composio-ops-{operator_id}",
)
session = await client.sessions.create(profile_id=profile.id)

result = await client.run(
    rendered_browser_prompt,
    session_id=session.id,
    allowed_domains=allowed_domains,
    secrets=domain_scoped_secrets,
)

live_url = session.live_url
await client.sessions.stop(session.id)
```

Always stop sessions in `finally`; Browser Use profile state is persisted when the session is stopped. A session has a 15-minute inactivity timeout and a maximum duration of four hours, so the run state must store expiry metadata and surface it in the UI.

### Playwright over Browser Use CDP

For secret-sensitive deterministic steps, create a raw Browser Use browser and connect Playwright:

```python
from browser_use_sdk.v3 import AsyncBrowserUse
from playwright.async_api import async_playwright

client = AsyncBrowserUse()
remote = await client.browsers.create(profile_id=profile_id, timeout=60)

try:
    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(remote.cdp_url)
        context = browser.contexts[0]
        page = context.pages[0]
        # Deterministic selectors only. Never log values.
finally:
    await client.browsers.stop(remote.id)
```

If the onboarding uses an agent session instead of a raw browser, Codex must verify how to obtain/attach to its CDP endpoint from the installed SDK. Do not silently launch a second unrelated browser.

### Composio Gmail session

Use only this tool allowlist:

```text
GMAIL_SEND_EMAIL
GMAIL_CREATE_EMAIL_DRAFT
GMAIL_SEND_DRAFT
GMAIL_FETCH_EMAILS
GMAIL_FETCH_MESSAGE_BY_THREAD_ID
GMAIL_LIST_THREADS
GMAIL_REPLY_TO_THREAD
GMAIL_GET_PROFILE
```

Create/reuse a session scoped to the configured Gmail connected account:

```python
from composio import Composio

composio = Composio()
session = composio.sessions.create(
    user_id=composio_user_id,
    tools={
        "gmail": {
            "enable": [
                "GMAIL_SEND_EMAIL",
                "GMAIL_CREATE_EMAIL_DRAFT",
                "GMAIL_SEND_DRAFT",
                "GMAIL_FETCH_EMAILS",
                "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
                "GMAIL_LIST_THREADS",
                "GMAIL_REPLY_TO_THREAD",
                "GMAIL_GET_PROFILE",
            ]
        }
    },
    connected_accounts={"gmail": [gmail_connected_account_id]},
)
```

Before executing any Gmail tool, inspect its current input schema:

```python
tool = composio.tools.get_raw_composio_tool_by_slug("GMAIL_SEND_EMAIL")
assert tool.input_parameters
```

Do not hardcode argument names from an old SDK or screenshot. Add an adapter that converts the project’s stable internal email model to the current Composio tool schema.

### Composio custom auth config output for P3

When P2 obtains provider OAuth credentials, the final bundle should contain secret references and enough non-secret metadata for P3 to create a custom auth config. Composio currently uses the callback:

```text
https://backend.composio.dev/api/v3.1/toolkits/auth/callback
```

P2 must not call `auth_configs.create()` with raw secrets taken from graph state. A boundary function resolves vault references immediately before the SDK call, passes them in memory, zeroes local references where practical, and never serializes the request.

---

## 31. Codex Rules

Codex must:

1. Read this plan and existing README/code first.
2. Work one phase at a time.
3. Preserve the locked P1 schema/artifacts.
4. Add tests with each phase.
5. Never print or commit secret values.
6. Never fake successful external actions.
7. Inspect current provider/tool schemas instead of guessing.
8. Run tests/lint/compile checks after each phase.
9. Summarize changed files and unresolved risks.

---

## 32. Codex Prompts

### Prompt 1

```text
Read PLAN.md, README.md, schema.py, pipeline.py, config.py, and tests.
Implement Phase 0 and Phase 1 only.
Do not modify AppRecord. Add ops/models.py, state.py, storage.py,
secret_store.py, redaction.py, tests, env and gitignore updates.
No Browser Use, Composio Gmail, LangGraph, or Streamlit yet.
Run all tests, ruff, and compileall. Report changes and security assumptions.
```

### Prompt 2

```text
Implement Phase 2. Reuse out/results.json or existing one-app research,
produce separate OperationalResearch, add deterministic routing, do not
mutate canonical artifacts, use mocks for paid providers, and show one
sanitized sample output.
```

### Prompt 3

```text
Implement Phase 3 with encrypted SQLite checkpointing, stable thread IDs,
mock browser/Gmail workers, real interrupt()/Command(resume=...), and tests
proving pause, process restart, resume, and no duplicated side effects.
```

### Prompt 4

```text
Implement Phase 4 using the current Composio SDK. Use a Gmail-scoped session,
only required Gmail tools, configured connected account, send/fetch/reply,
demo recipient override, thread persistence, idempotency, pre-LLM sanitization,
fake normal tests, and opt-in live test. Inspect tool schemas at runtime.
```

### Prompt 5

```text
Implement Browser Use Cloud SDK v3 and Playwright over CDP. Reuse a persistent
profile, restrict domains, expose live_url, stop sessions cleanly, use HITL,
prevent Browser Use from reading generated secrets, capture with Playwright,
store immediately, and put only vault refs in state. Add one app adapter and
security regression tests.
```

### Prompt 6

```text
Implement Streamlit and deployment. Show input, sanitized timeline, live browser,
HITL resume on same thread, Gmail status/polling, and final IntegratorBundle with
refs only. Add Dockerfile, limitations, ten-app table, full tests/lint/secret scan.
```

---

## 33. Demo Script

1. Open live app.
2. Start self-serve app.
3. Show P1 loaded and route.
4. Launch live browser.
5. Hit OTP/CAPTCHA/test checkpoint.
6. Show graph paused.
7. Complete and resume same thread.
8. Reach credential page.
9. Show only vault references.
10. Start gated app.
11. Show official contact and Composio Gmail send to controlled recipient.
12. Reply from test mailbox.
13. Poll/classify reply.
14. Show final bundle.
15. Show private repo/tests and honest limitations.

---


## 33A. Exact Commands to Start Codex

After moving `PLAN.md` into the new private repo:

```bash
cd /Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent
codex
```

First message to Codex:

```text
Read PLAN.md fully. Then inspect only the current repository files.
Do not implement anything yet.

Return:
1. your understanding of P1/P2/P3 boundaries,
2. files you will create in Phase 0 and Phase 1,
3. security invariants you must preserve,
4. any contradictions or SDK signatures that require verification,
5. a short execution checklist.

Do not edit files until I approve the checklist.
```

After reviewing its answer, use Prompt 1 from the Codex Prompts section.

Do not give Codex all phases in one prompt. Each phase must end with tests and a diff review.

---

## 34. Official Research References

- LangGraph persistence: https://docs.langchain.com/oss/python/langgraph/persistence
- LangGraph interrupts: https://docs.langchain.com/oss/python/langgraph/interrupts
- LangGraph checkpointers: https://docs.langchain.com/oss/python/integrations/checkpointers
- Browser Use Cloud: https://docs.browser-use.com/cloud/agent/quickstart
- Browser Use HITL: https://docs.browser-use.com/cloud/agent/human-in-the-loop
- Browser profiles: https://docs.browser-use.com/cloud/guides/authentication
- Browser Use secrets: https://docs.browser-use.com/cloud/guides/secrets
- Browser Use + Playwright: https://docs.browser-use.com/cloud/browser/playwright-puppeteer-selenium
- Composio sessions: https://docs.composio.dev/docs/how-composio-works
- Composio authentication: https://docs.composio.dev/docs/authentication
- Composio session configuration: https://docs.composio.dev/docs/configuring-sessions
- Composio Gmail toolkit: https://docs.composio.dev/toolkits/gmail
- Composio triggers: https://docs.composio.dev/docs/triggers
- Playwright CDP: https://playwright.dev/python/docs/api/class-browsertype


## 35. Version Verification Sources

- https://pypi.org/project/langgraph/
- https://pypi.org/project/langgraph-checkpoint-sqlite/
- https://pypi.org/project/browser-use-sdk/
- https://pypi.org/project/playwright/
- https://pypi.org/project/composio/
- https://pypi.org/project/google-genai/
- https://pypi.org/project/perplexityai/
- https://pypi.org/project/streamlit/
- https://pypi.org/project/cryptography/
- https://pypi.org/project/aiosqlite/
- https://pypi.org/project/python-dotenv/
- https://pypi.org/project/tenacity/

The versions in this plan are a reproducible starting point, not a license to ignore compatibility failures. If one exact pin conflicts with another package, Codex must show the resolver error, change only the minimum necessary pin, update `requirements-lock.txt`, and record the reason in `DECISIONS.md`.
