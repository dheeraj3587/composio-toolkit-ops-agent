# The Playwright autonomous browser harness

> **Per-run provider selection.** Older API and CLI calls still default to
> `browser_use`. The website prefers Playwright when its isolated production
> service is ready. Both adapters may be wired concurrently; a run never changes
> provider or falls back after creation.
>
> **The LLM can only select policy-generated candidate IDs.** No model can author a
> selector, a URL, typed text, JavaScript, shell, a credential value, an OTP or a
> magic link. That is enforced by the candidate policy, not by prompt instructions.

This document describes the harness built across the four hardening phases. It is
written to be read by someone deciding whether to switch the provider on — so it is
explicit about what is proven, what is merely written, and what is deferred.

---

## 1. Architecture

Three processes, deliberately separated:

```
┌─────────────────┐        authenticated RPC          ┌──────────────────────┐
│   API (Phase 3) │ ───── X-Browser-Service-Token ──▶ │   browser service    │
│                 │       vault:// refs only          │  (Chromium lives     │
│ ops/run_service │ ◀──── sanitized observations ──── │   HERE, own image)   │
└─────────────────┘                                   └──────────────────────┘
        │                                                       │
        │ LangGraph checkpoints                                 │ Playwright
        ▼                                                       ▼
   encrypted state                                        the vendor site
```

Why the separation matters: Chromium in the API container means a browser crash or
memory spike can take down the control plane, and an API restart kills a live
session mid-login. With the service split out, an API restart is survivable and a
Chromium crash is contained.

| Component | Responsibility |
| --- | --- |
| `ops/browser_api_trace_catalog.py` | Reviewed per-app checkpoints + structured predicates (schema 2.0) |
| `ops/browser_snapshot.py` | Ranked, frame-aware accessible snapshot (roles/names/state, no values) |
| `ops/browser_candidates.py` | Bounded candidate set with opaque IDs; identity resolution tiers |
| `ops/browser_risk.py` | Risk classification; irreversible controls become `requires_hitl` |
| `ops/browser_login.py` | Deterministic login state machine (email-first, password, OTP, magic link) |
| `ops/browser_egress.py` | Four-stage egress policy; unknown resource kinds fail closed |
| `ops/browser_pages.py` | Popups, dialogs, downloads; frame-origin review |
| `ops/playwright_worker.py` | The action loop, the real route guard, deterministic capture |
| `browser_service/` | FastAPI RPC, session lifecycle, HITL grants (Phase 3) |
| `ops/browser_metrics.py` | Sanitized decision events and metrics (Phase 4) |
| `ops/browser_replay.py` | Deterministic replay fixtures (Phase 4) |
| `ops/browser_shadow.py` | Plan-only shadow evaluation (Phase 4) |
| `ops/browser_canary.py` | Canary gates and rollout stages (Phase 4) |

---

## 2. The candidate-only LLM boundary

This is the single most important property of the design.

The model never sees a selector and never produces one. Each step:

1. `build_ranked_snapshot` produces `SnapshotElement`s — role, accessible name,
   visibility/enabled/checked state, frame path, test id, href **path**. No element
   values, no HTML, no page text dump.
2. `generate_candidates` derives a bounded set of actions from those elements,
   filtered to the current checkpoint's expected signals. Each candidate gets an
   **opaque ID**: `c_` plus 12 hex characters of a SHA-256 over reviewed inputs.
3. The model is shown `render_candidates(...)` — IDs and semantics only — and must
   reply with one ID.
4. `select_candidate` refuses any ID outside the generated set, and refuses a
   `requires_hitl` candidate even if the model picks it.

Consequences that fall out of this structure rather than from instructions:

- A model cannot invent a target: an unknown ID raises
  `ValueError("selected candidate id is not in the generated policy set")`.
- A model cannot type a credential: the LLM can select a policy-generated fill
  candidate only when the current checkpoint explicitly authorizes a reviewed
  **non-secret** value reference (`APPROVED_VALUE_REFS`: `company_name`,
  `company_website`, `application_name`, `use_case`, `expected_volume` — the
  trace catalog rejects anything else at parse time). Passwords, OTPs, magic
  links and account credentials **never become candidate values**; they are
  inserted only by the deterministic login state machine
  (`ops/browser_login.py`), never via a candidate.
- A model cannot reach a secret field at all: elements marked `secretish` are never
  emitted as `type`/`fill` candidates.
- A model cannot widen the allowlist: hosts come only from reviewed static data,
  never from model output, page HTML, redirect history, JavaScript or You.com.

Verified by `tests/test_browser_integration_real.py`:
`test_model_cannot_select_a_candidate_outside_the_generated_set`,
`test_candidate_ids_are_opaque_and_carry_no_selector_or_url`,
`test_credential_value_never_appears_in_a_snapshot_or_candidate`,
`test_secret_fields_are_never_offered_as_type_candidates`.

---

## 3. Trace predicates

Schema 2.0 replaced "does the page contain this string" with a structured
`CheckpointPredicate`:

```python
CheckpointPredicate(
    url_path_contains=("/settings/api",),
    title_contains=(),
    visible_text_contains=("API token",),
    required_accessible_names=(),
    forbidden_text=(),
)
```

Rules that make progression trustworthy:

- A checkpoint advances **only** when its predicate is proven against a freshly
  inspected page. `checkpoint_index` is never incremented optimistically.
- A predicate needs at least one positive condition (`has_positive_condition()`),
  so an empty predicate cannot mean "success".
- `forbidden_text` vetoes success even when the path matches — this is what stops a
  login-error page at the right URL being read as a win.
- Apps whose predicates have not been verified live are marked `requires_hitl: true`
  with an empty success predicate. **Only `pipedrive` currently has real
  predicates**, because it is the only app tested live. The other 24 are honest
  placeholders rather than invented evidence.

---

## 4. Login and OTP flow

`ops/browser_login.py` is a deterministic state machine, not a model loop:

```
inspect_login → LoginState ∈ {
    unknown, email_required, password_required, credentials_ready,
    submitted, otp_required, magic_link_required,
    account_selection_required, authenticated, authentication_failed
}
```

- **Credentials** are injected by code into fields the inspector identified. They
  are never in a prompt, a log, an audit event, a checkpoint or run state.
- **OTP** handling covers a single `one-time-code` input and per-character field
  groups (one digit per field, in order). `inject_otp` submits the form itself.
- **Magic links** are opened only when `magic_link_is_safe` confirms the URL is on a
  reviewed host. A link to any other origin is refused however plausible it looks.
- **Unreviewed frames** never receive credentials: `frame_path_is_reviewed` gates
  injection, and the worker raises `login_frame_unreviewed` rather than typing into
  an origin nobody reviewed.
- **Ambiguity fails closed**: two password fields is `unknown`, not a guess.

The OTP value specifically never enters LLM prompts, logs, audit events,
checkpoints or run state.

---

## 5. Network stages

`BrowserEgressPolicy` has four monotonic stages — it tightens, never loosens.

| Stage | Passive assets (image/font/css/media) | Script | Active (document/fetch/xhr/ws) |
| --- | --- | --- | --- |
| `PRE_AUTH` | vendor + reviewed asset hosts | vendor + reviewed script hosts | vendor + reviewed API hosts |
| `AUTHENTICATING` | + reviewed IdP hosts | + reviewed IdP hosts | + reviewed IdP hosts |
| `AUTHENTICATED` | + reviewed post-auth hosts | + post-auth | + post-auth |
| `CREDENTIAL_SURFACE` | **vendor only** | **vendor only** | **vendor only** |

- An **unknown resource kind fails closed** (returns no patterns at all).
- Non-`https` is refused outright.
- `EgressStageTracker.advance_to` ignores any attempt to move backwards.
- Post-auth tightening closes the pixel/CSS/font beacon channel: once a credential
  could be in the DOM, a third-party image is aborted even though the same request
  was allowed pre-auth.

This asymmetry was **verified empirically**, not assumed — see
`test_post_auth_stage_also_blocks_passive_assets`, which observes that the
third-party server received `pixel.png` pre-auth and did **not** receive it
post-auth.

---

## 6. The browser service

`browser_service/` (Phase 3), reachable only on the private Compose network.

- **Auth**: `X-Browser-Service-Token` in a header (never a query string),
  `secrets.compare_digest`, plus an owner header. A non-owner receives **404, not
  403**, so another run's session existence is never confirmed. With no token
  configured the service refuses everything — unconfigured means inert, not open.
- **Credential values never cross the boundary.** The API sends only `vault://`
  references; the service resolves them internally and clears them immediately.
- **Request bounds**: declared `Content-Length` and actual body length are both
  checked, so a lying header cannot smuggle a large payload.
- **No published port.** `compose.playwright.sandbox.yaml` has no `ports:`; the RPC
  surface (8081) and the VNC port (5900) are private.
- Endpoints: create / status / navigate / resume / screenshot / live-view / delete,
  plus unauthenticated-but-secret-free `/internal/health`.

---

## 7. HITL

**Screenshot HITL**:
`GET /internal/browser/sessions/{id}/screenshot`, owner-gated. When no frame is
available it returns **409 `screenshot_unavailable`** rather than serving a stale
frame from a previous page. Availability is truthful: `screenshot_available` is
False until a real, non-sensitive frame has been captured.

**Interactive remote — configuration-gated.** The assignment deployment enables a
single-session, same-origin noVNC client only while a Playwright run is paused for
human action. FastAPI requests a private, short-lived grant from the browser service;
the Next.js server validates that exact internal URL and returns only the relative
same-origin path to the client. Caddy terminates Basic Auth, strips its Authorization
header, injects the fixed browser owner, and proxies that one WebSocket route. The
grant remains bound to the owner and session, while x11vnc and browser RPC ports stay
private. Resume disconnects the client before continuing automation, and an expired
grant requires an operator-initiated reconnect.

The container has one X display, so interactive configuration is valid only with
`PLAYWRIGHT_MAX_SESSIONS=1`. Other deployments may leave
`BROWSER_INTERACTIVE_HITL_ENABLED=false` and retain screenshot-only HITL.

---

## 8. Session lifecycle

Every operation takes a **lease**. Closing is a state machine:

```
ACTIVE → CLOSING (refuse new leases) → bounded drain → cancel remainder
       → close context/browser → CLOSED → release capacity EXACTLY once
```

- The janitor never closes a session mid-action: `expired_session_ids` skips any
  session with `active_operations > 0`, catching it on a later sweep.
- Capacity is released exactly once even across repeated close attempts.
- Idle expiry and max-age expiry are distinguished
  (`session_idle_expired` vs `session_max_age_exceeded`).
- A drain timeout is recorded as `…:operations_cancelled` rather than reported as a
  clean close.

---

## 9. Restart behavior

| Deployment | `supports_restart_reattach` | On API restart |
| --- | --- | --- |
| Browser Use (default) | `True` | Cloud session reattached by provider session id |
| Playwright in-process | `False` | `browser_running` **and** `waiting_for_hitl` → `configuration_required`, reason `playwright_session_lost_on_restart` |
| Browser service | `True` (**verified**) | Service is queried; only `ACTIVE` is resumable |

The important nuance: the capability flag alone is not evidence. `reconcile_session`
**queries the service**, and a persisted id is never trusted on its own.

- service says `ACTIVE` → resumable
- service says 404 → `browser_service_session_lost`
- service **unreachable** → *inconclusive*, and the run is left alone. Tearing a run
  down because the service was briefly unreachable would destroy a live session.

---

## 10. Storage-state security

Playwright storage state contains session cookies: it is a bearer credential.

- **Fernet-encrypted at rest.** Without a key it is **not persisted at all** rather
  than persisted in the clear.
- **Owner-only permissions**: directory `0700`, file `0600`, written via a private
  temp file then `replace()` so a reader never sees a partial blob.
- **Bound to (app, account, owner)** by a SHA-256 fingerprint, so state cannot leak
  sideways between runs or accounts. A tampered fingerprint raises
  `storage_state_binding_mismatch`.
- **Expiry tracked**; stale state is deleted, not merely refused.
- Invalidated on logout or auth failure. Never logged, never returned across an API
  boundary, never committed (it lives under `/browser-data`).

---

## 11. Failure reason codes

Typed throughout; no bare exceptions and no `provider_request_failed` catch-all.

**Action loop** (`ActionReasonCode`): `target_not_found`, `target_ambiguous`,
`target_stale`, `action_timeout`, `navigation_timeout`, `policy_blocked`,
`postcondition_failed`, `authentication_failed`, `model_unavailable`,
`model_invalid_choice`.

**Inference** (`DecisionReasonCode`): `rate_limited`, `authentication_failed`,
`provider_timeout`, `invalid_json`, `schema_invalid`, `all_providers_failed`.

**Worker / provider**: `live_browser_opt_in_required`, `playwright_not_installed`,
`browser_launch_timeout`, `browser_capacity_exceeded`, `session_missing`,
`login_frame_unreviewed`, `unrecognized_resume_signal`, `verified_research_required`.

**Service**: `browser_service_token_not_configured`, `invalid_browser_service_token`,
`missing_session_owner`, `request_too_large`, `session_not_found`, `session_closing`,
`capacity_exhausted`, `browser_launch_failed`, `operation_timeout`,
`screenshot_unavailable`, `browser_service_unreachable`, `browser_service_session_lost`.

**HITL grant**: `interactive_hitl_disabled`, `live_view_secret_missing`,
`malformed_token`, `invalid_signature`, `session_mismatch`, `owner_mismatch`,
`token_expired`, `vnc_unavailable`, `vnc_target_not_loopback`.

**Storage state**: `storage_state_key_missing`, `storage_state_key_invalid`,
`storage_state_binding_mismatch`, `storage_state_expired`,
`storage_state_undecryptable`, `storage_state_corrupt`, `storage_state_too_large`.

Programming errors (`TypeError`, `AttributeError`, `AssertionError`, `NameError`)
**propagate** rather than being masked as provider failures.

---

## 12. Metrics

`BrowserDecisionEvent` records structure and outcomes only:

```python
session_id, checkpoint_order, page_fingerprint, candidate_ids,
selected_candidate_id, selection_source ∈ {deterministic, llm, hitl},
inference_provider, action_type, result_code, latency_ms
```

**Never recorded**: page text, element values, prompts, model reasoning, cookies,
credentials, query strings, raw URLs, HTML.

`page_fingerprint` is a truncated SHA-256 over host + a **normalized** path with
numeric/UUID/hex segments collapsed to `:id`. So two accounts on the same logical
page group together, a magic-link token in a query cannot influence it, and the
value is not reversible into a URL.

The metric set (`BrowserRunMetrics.snapshot()`): completion rate, HITL rate, model
calls per run, deterministic-action rate, checkpoint retry rate, stale-target rate,
postcondition-failure rate, blocked-navigation rate, median session duration,
browser crashes, capacity rejections, per-provider inference latency.

Metrics are **computed from events** rather than incremented ad hoc, so a number can
never silently disagree with the record it came from. An undefined rate is `0.0`.

---

## 13. Replay fixtures

A fixture persists only: checkpoint number, page fingerprint, bounded safe snapshot,
candidate metadata, selected candidate ID, typed outcome.

`replay_fixture` re-runs the **real** production functions — `generate_candidates`,
`BrowserActionRiskPolicy.classify`, `select_candidate` — so a policy regression
surfaces as a mismatch rather than a silent behaviour change. It reproduces candidate
generation, deterministic matching, risk classification, choice validation and
checkpoint progression.

Element persistence uses an **allowlist** of fields, so adding a value-bearing field
to `SnapshotElement` cannot silently start leaking it. `has_value` and `secretish`
are booleans; the value never enters a fixture. Never persisted: real credentials or
complete vendor HTML. An unsupported `version` is refused rather than compared
against different semantics.

---

## 14. CI

Two jobs, deliberately different:

- **`ci.yml` → `backend`** is browser-free and fast (this branch removes its
  Chromium install). Backend unit tests are allowed to skip browser
  integration; real Chromium is enforced only in the dedicated browser-image
  job.
- **`browser-image.yml` → `browser-image`** is the mandatory real-Chromium gate:
  validates the compose file, builds `Dockerfile.browser`, proves Chromium launches
  *inside the image*, starts the browser service, waits for cached readiness,
  asserts an unauthenticated RPC call is refused, runs the real-browser suite in a
  private `browser-integration-tests` container on the same network and shared
  ephemeral vault, **fails if any browser test skipped** (`scripts/assert_zero_skips.py`),
  runs the RPC/lifecycle suites, asserts the service log is secret-free
  (`scripts/assert_secret_free_log.py`), checks for orphaned Chromium in the
  container (`scripts/assert_no_orphan_chromium.py`), and tears everything down
  with `--volumes`.

`REQUIRE_REAL_BROWSER_TESTS=1` turns "Chromium is missing" from a skip into a
failure — every browser test routes through `tests/browser_app/harness.require_chromium`,
verified by forcing an unavailable Chromium and observing a FAIL, not a skip. The
zero-skip assertion is a separate, explicit check on the JUnit XML, because GitHub
treats a skipped check as successful.

> **`browser-image.yml` is committed locally but is NOT on the remote.** The
> integration used to push this branch lacks the GitHub Actions `workflows`
> permission, so pushing any file under `.github/workflows/` returns
> `403 Resource not accessible by integration`. Blocked alongside it, in the
> same local commits, is the matching `ci.yml` change that removes the
> backend job's Chromium install — the two must land together so backend CI
> only goes browser-free at the moment the dedicated browser-image gate
> exists. Both workflow files must be pushed by someone with that permission
> — a normal `git push` of this branch is enough (the four `scripts/*.py`
> helpers are already on the remote).
>
> **Then make `browser-image` a required status check on the protected branch**
> (strict mode, so the branch must be current with main). Until both happen,
> **there is no browser-image CI gate on this repository** — the job is written and
> locally verified, not running, and the remote `ci.yml` still installs Chromium in
> the backend job (so browser tests currently run there rather than skipping). The
> Docker-based gates likewise cannot run in the authoring sandbox (no Docker), so
> they are validated structurally, not executed.

---

## 15. Canary

Three independent gates, all required, all fail-closed:

```
RUN_LIVE_PLAYWRIGHT_CANARY=1
ALLOW_LIVE_BROWSER=true
BROWSER_PROVIDER=playwright
```

Plus an explicitly asserted target: owned test account, non-production workspace,
reviewed app, and `contains_production_data=False`. Every flag defaults to the
**pessimistic** value, so an unset assertion never means "yes".

The envelope: read-only actions only (`click`, `focus`, `goto`, `press`,
`scroll_into_view`, `wait_for`). Forbidden by name — billing changes, legal
acceptance, credential rotation, revocation, invitation, purchase, deletion,
ownership transfer, and credential reveal. An unrecognised operation fails closed.

**Initial objective**: log in, navigate to the reviewed developer/API settings page,
verify it structurally — and **stop before any mutation or credential reveal**.
Reaching the page *is* the result being measured. One concurrent session maximum,
and never in ordinary CI.

---

## 16. Rollout

The single "Activated" column was misleading (it conflated "code exists" with
"proven in production"). Four distinct columns instead — **Implemented**, **CI
verified**, **Live verified**, **Production activated**:

| Stage | Implemented | CI verified | Live verified | Production activated |
| --- | --- | --- | --- | --- |
| 0 — Local deterministic tests | yes | yes | n/a | no |
| 1 — Offline shadow planner library | yes | yes | no | no |
| 2 — Read-only canary gates | yes | yes | no | no |
| 3 — Login + read-only navigation | yes | local/RPC only | no | no |
| 4 — Credential capture | app-specific only | local only | no | no |
| 5 — Production canary | no | no | no | no |

"CI verified" for stages that touch a browser is contingent on the browser-image
job actually running on the remote (see §14 — it is not yet pushed). No stage has
been **live verified**: the canary has never executed against a real vendor.
Stage 5 is *defined* so the plan is reviewable, but `production_canary_activated()`
returns `False` and a test asserts it; activating it is a separate, explicit
decision.

Interactive HITL is a transport for an existing human-action pause rather than a
separate autonomous rollout stage, so it is intentionally absent from this table.

**Shadow mode (stage 1)** is safe structurally, not procedurally: `ShadowPlanner`
has no page, no browser and no execution path. It is a pure function from a
sanitized observation to a plan. It cannot launch a second vendor login, type a
credential or mutate anything, because the capability is absent — and
`planner.execute()` raises `ShadowExecutionForbidden` so a future mis-wiring fails
loudly. Comparison covers checkpoint interpretation, candidate set, risk
classification, expected next action and HITL decision, entirely offline. A shadow
planning failure is captured as a reason code and never propagates into the run.

---

## 17. Rollback

Reverting is a configuration change, not a deployment:

1. Set `BROWSER_PROVIDER=browser_use` (the default — so *unsetting* it is enough).
2. Restart the API. Browser Use's own path is byte-for-byte unchanged by all four
   phases.
3. The browser service can be left running or stopped; nothing in the Browser Use
   path talks to it.
4. In-flight Playwright runs reconcile to `configuration_required` with a typed
   reason rather than hanging.

There is no schema migration to undo: all new state is additive and defaulted.

---

## 18. Known limitations

Stated plainly, because the value of this document depends on it.

1. **Only Pipedrive has verified trace predicates.** The other 24 apps in the
   catalog are marked `requires_hitl` with empty success predicates. They are
   placeholders, not evidence.
2. **The live canary has never been executed.** The gates, envelope and objective
   are implemented and unit-tested; no real vendor account has been touched by the
   Playwright path.
3. **Docker gates were not executed in the authoring environment** (no `docker`
   binary, no `/var/run/docker.sock`). `Dockerfile.browser`, the entrypoint and the
   `browser-worker` service are validated *structurally* by
   `TestContainerIsolationShape` — which checks the declared configuration, **not a
   running container**. The `browser-image` CI job is what will actually execute
   `docker compose config` and `docker build`.
4. **The real-Chromium suite runs against a local test app, not a real vendor.** It
   uses RFC 2606 `.example` hostnames over real TLS mapped to loopback. That is
   deliberate and it proves the guards work; it does not prove any particular
   vendor's UI is navigable.
5. **Interactive HITL remains deployment-gated** (see §7). The assignment stack
   enables it with one browser session and a private display; the base production
   stack does not expose it unless that override and its required secrets are
   configured. Live vendor verification is recorded separately from local tests.
6. **Shadow mode is not wired into the live Browser Use path.** The planner and
   comparison exist and are tested; emitting a shadow plan during a real Browser Use
   run is a follow-up.
7. **No metrics backend.** `BrowserRunMetrics` computes the numbers and
   `emit_snapshot()` logs them; nothing scrapes or stores them yet.
8. **The `browser-image` workflow is not on the remote and is not a required
   check.** The pushing integration lacks the Actions `workflows` permission
   (`403 Resource not accessible by integration`), so the file exists in local
   history only. Someone with that permission must push it, and then mark the job
   required in branch protection. Until then the gate does not run at all.
9. **Chromium's own sandbox is disabled in CI** (`PLAYWRIGHT_DISABLE_SANDBOX=true`)
   because the runner cannot support it. The image keeps it **enabled** by default.

## 19. Deferred work

- Verify trace predicates live for the remaining 24 apps.
- Complete the controlled assignment smoke test against the owned Pipedrive account
  and record whether it reaches the reviewed target or a truthful security handoff.
- Wire shadow planning into live Browser Use runs and collect divergence data.
- Ship a metrics sink and dashboards; add alerting on HITL and completion rates.
- Pin CI actions to immutable SHAs and make `browser-image` a required check.
- Release benchmark: a scored accuracy suite across the self-serve app set.

## 13. Account-aware browser start target

`ops/browser_target_selection.py` is the single selector used by Browser Use and
Playwright. It derives account state only from trusted local facts: a successful
restored Playwright storage state (`authenticated`), supplied login credentials
(`existing_account`), an explicit `account_creation_requested` request
(`account_creation_required`), or `unknown`. It never asks an LLM or infers state
from page content.

The reviewed order is: authenticated → credential management, developer portal,
trace start, login, signup; existing account → login, credential management,
developer portal, trace start, signup; account creation → signup, login,
developer portal, credential management, trace start; unknown → login, signup,
developer portal, credential management, trace start. Field-level verified
`operational_url_claim`s are preferred. Every candidate must be HTTPS, pass the
existing app host policy, and have no userinfo, fragment, or sensitive query
parameter. The existing trace and conservative provider-specific unverified
fallback rules remain in force.
