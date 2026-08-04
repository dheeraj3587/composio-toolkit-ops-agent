# Knowledge Base: why the agent doesn't work, and what to fix

Status as of 2026-08-02, branch `fix/production-ci-cd` with uncommitted changes.
Findings below are marked **[verified]** (read the code and/or ran it) or **[inferred]**.

## Goal

An autonomous agent that removes the repetitive part of dev onboarding: go to a
service, create an account, log in, generate credentials, store them. Today no run
reaches credentials. This document is the diagnosis and the fix order.

**Owner's stance, taken as a given for this work:** the P1 snapshot is *information*,
not a contract to obey. Premium models are available, so plan quality is not the
constraint. Blockers that exist only to enforce the snapshot are fair game.

---

## The headline: the agent stops in a stub, not in a policy

The single reason nothing completes. **[verified]**

`ops/onboarding/runtime.py:419-430`:

```python
class _UnavailableBrowserHandler:
    async def __call__(self, *, run_id, phase, profile, lease, deps) -> PhaseStep:
        del run_id, phase, profile, lease, deps
        return PhaseStep.pause("browser_adapter_unavailable")
```

Registered at `ops/onboarding/runtime.py:511-512` for **both** terminal branches:

```python
"route_selected_login": _UnavailableBrowserHandler(),
"signup":               _UnavailableBrowserHandler(),
```

Six later phases — `email_verification`, `authenticated`, `developer_app`,
`credential_generation`, `vault_storage`, `credential_validation` — have **no handler
registered at all**, and the session factory is `_NoBrowserSessions`
(`runtime.py:276-285`), which raises if ever reached.

So the mounted onboarding path researches the provider, builds a profile, asks for
admission, selects a route — then pauses forever by construction. This is not a
guard rail we can switch off. **The browser execution seam was never implemented on
this path.** No configuration substitutes for missing code.

Working implementations *do* exist elsewhere (`SignupPhaseHandler`,
`DeveloperAppPhaseHandler`, `CredentialLifecycleDeps`, `_drive_verification` at
`ops/onboarding/driver.py:5085`) and are wired up in
`tests/test_onboarding_end_to_end.py:724-742`. Production just never binds them.

## The second trap: `paused` is a state with no exit

Even after the browser seam lands, every run already parked is lost. **[verified]**

```
paused targets                      = ['cancelled', 'research']
targets - _NON_CONTINUATION_PHASES  = []          -> resume button withheld
'paused' in storage sweep phases    = False       -> no background driver
```

Three independent mechanisms combine:

| Location | Effect |
| --- | --- |
| `ops/onboarding/phase.py:195` | `paused` only leads to `research` (a restart) or `cancelled` |
| `api/service.py:113,1568` | `can_resume = waiting and bool(targets - _NON_CONTINUATION_PHASES)` → `False` |
| `ops/core/storage.py:2009` | sweep queries only `research, vault_check, awaiting_admission, route_selected_signup` |

`_is_mounted_request` (`runtime.py:626`) still accepts `paused`, so the run *looks*
alive in the console while nothing will ever touch it again. The diff comment at
`api/service.py:1561-1565` says this change fixed a spurious 409 on resume — it
traded a visible error for silent permanent stalling.

## The catalog is far narrower than "50 apps" suggests

**[verified]** by running the real loader (`load_app_recipe_catalog()`):

```
total 50   route_kind: managed_auth 25, playwright 14, gated 11
readiness:  managed_auth_ready 25, browser_ready 7, owner_submit_ready 7,
            outreach_review_required 7, outreach_ready 4

playwright recipes WITH a signup url: ['pipedrive']          <- 1 of 14
playwright recipes WITHOUT signup:    telegram, klaviyo, shopify, dataforseo,
                                      apify, firecrawl, bright-data, vercel,
                                      cloudflare, neo4j, datadog, coda, xero
```

Consequences:

1. **Legacy static path**: `ops/workflow/canonical_runtime.py:724-731` requires a
   `playwright` recipe *with* a signup URL, else `ProviderReadinessError`. Only
   **pipedrive** qualifies. Every other `create_account` request is diverted to the
   mounted path — which is the stub above.
2. **Planner path**: 7 of the 14 playwright recipes have no
   `urls.credential_management`, and `ops/planner/decide.py:192-199,213-215` returns
   `None` on that alone → `decide.py:426-432` converts it to a hard `PlanRefusal`
   *before* any model is consulted. Verified refusals: `telegram, klaviyo, shopify,
   dataforseo, bright-data, neo4j, xero` with `detail=recipe_route_not_browser`.

Note the producer/validator contradiction: `ops/planner/validator.py:180-190`
already handles `browser.scope == "credential_surface"` and derives credential paths
from `browser.success.url_path_contains`. `decide.py:192` has no such branch — the
validator is prepared for a case the producer refuses to build. **This is a real bug,
not a policy.**

## The production path is broken independently of the stub

Two scopes that must be kept separate. **[verified]**

| Scope | Setting | Browser path |
| --- | --- | --- |
| Your local `.env` | `PLAYWRIGHT_IN_PROCESS_SANDBOX=true` | in-process Chromium, `BrowserServiceClient` **bypassed** |
| Production | `compose.prod.yaml:94` forces `"false"`, `BROWSER_SERVICE_URL=http://browser-worker:8081` | RPC to `browser_service/` |

So locally the mounted-seam stub is the whole story. In production, even `pipedrive`
— the one app that reaches real execution — breaks at the first captcha or OTP pause.
Both layers need fixing and neither hides the other.

Paths, verbs and auth headers are all clean (11 client paths resolve, all three header
names agree). The breaks are payload-level, and every server model is `extra="forbid"`
(`browser_service/models.py:57-58`), so a mismatch is a hard 422.

**1. HITL resume always 422s. [verified by execution]**
`ResumeRequest.research` is `dict | None = None` (`models.py:241`) and the client omits
it when `None` (`service_client.py:471-474`). The handler then does `payload.research or {}`
(`main.py:810`) → `OperationalResearch.model_validate({})`, which I ran directly:

```
OperationalResearch.model_validate({}) -> 18 errors
sample missing: ['app_name', 'app_slug', 'api_available', 'api_type', ...]
```

This is the call that continues a run after a human gate. In production it cannot succeed.

**2. `setup_fields` cap is smaller than the client's own allowlist. [verified by execution]**
Server caps at `max_length=20` (`models.py:211`, `:247`); the client's normalizer
`normalize_browser_setup_fields` admits 22:

```
provider keys: 18   company keys: 4   merged: 22
server max_length = 20 -> MISMATCH
overflow keys: ['team_name', 'use_case']
```

**3. `recipe_snapshot` optional in model, required in handler.** Defaults to `None`
(`models.py:66`), client omits it when absent (`service_client.py:291`), handler 422s
with `recipe_snapshot_required` (`main.py:536-540`).

**Why none of this was noticed — fix this first.** `_reason`
(`ops/browser/service_client.py:238-249`) only accepts `detail` when
`isinstance(detail, str)`, but FastAPI validation errors return `detail` as a *list*.
Every strict-model 422 therefore collapses to an opaque `f"http_{status_code}"` with no
field name. This is what let three contract breaks sit undetected.

**Silent correctness bug: idle expiry is misreported.** `service_client.py:336` reads
`payload.get("maximum_expires_at")` into `inactivity_expires_at`, and the server does
the same substitution at `main.py:1419`. `_INACTIVITY_WINDOW` is only applied in the
in-process worker (`ops/browser/worker.py:299`). On the RPC path a session appears to
never idle-expire. **[verified: no server payload key for inactivity exists]**

**Smaller ones:**
- `provider_session_id` (`service_client.py:917-920`) is
  `return handle if handle in self._sessions or handle else None` — the `or handle` is
  truthy for any non-empty string, so an unknown session id returns itself, never `None`.
- `close()` (`:910-915`) never closes an owned `_sync_client`.
- `_request` builds a fresh `httpx.AsyncClient` per RPC (`:220-224`) — new TLS
  handshake every call, no pooling.
- Event-loop blocking: the secret broker uses a sync `httpx.Client`
  (`browser_service/secret_broker.py:39`) called from `async def _drive`
  (`main.py:1423`) — one blocking round trip per credential ref on every navigate and
  resume. Same for storage-state load/save (`main.py:583`, `:1329`, `:1524`).

**Security item needing your decision.** `/internal/ready` (`main.py:1291-1297`) has no
auth dependency and calls `_refresh_readiness()`, which **launches Chromium under a
lock** (`main.py:1202,1217`) — an unauthenticated resource-consuming endpoint. Bodies
are capability-state only, and Caddy is the sole public service in production, so the
network boundary is the only control. `/internal/live` is genuinely cheap and launches
nothing; the container healthcheck should call that one. Confirm the exposure is intended.

## What is *not* the problem

Worth stating plainly, because it redirects effort:

- **The P1 snapshot verifies and is not blocking the existing 50 apps.** **[verified]**
  Provenance and both content hashes match; all 50 slugs resolve through
  `recipe_to_operational_research` with **zero** failures. P1 does not need to be
  torn out to make the current catalog work.
- **Playwright is installed and healthy.** **[verified]** `playwright 1.61.0`,
  `chromium-1228` and `chromium_headless_shell-1228` present in
  `~/Library/Caches/ms-playwright`. "Playwright not working" is about code paths, not
  a missing dependency.
- **The planner is fully wired, not dead code.** **[verified]** All four ports
  (`plans`, `planner`, `plan_validator`, `adherence`) are non-`None` in both binding
  sites (`ops/runs/service.py:430-436`, `ops/onboarding/composition.py:622-645`).
  It runs; it just refuses or degrades.
- **DLP and redaction abort nothing.** **[verified]** Zero raise sites in
  `ops/core/redaction.py` or `ops/core/model_input_dlp.py`. DLP refuses as a *value*,
  never as an exception. (Note: CLAUDE.md references `ops/core/dlp.py`, which does not
  exist — stale doc.)

Where the owner's instinct **is** right: P1 makes app **#51** impossible without a
code change. `ops/recipes/app_recipes.py:743-745` requires every slug to exist in P1;
`ops/research/p1_adapter.py:218,238,240` hash-pins P1 to an external commit; and
`app_recipes.py:655-672` pins the catalog to a 50-slug matrix with
`min_length=50, max_length=100`. That is a three-way deadlock. It blocks *catalog
growth*, not the 50 apps already present.

## Test baseline

Project gate is `-m "not live and not browser"` (`Makefile:36`). Bare `pytest tests/`
**hangs past 600s** — it pulls in browser tests. Use the gate.

**[verified by me directly]**, full gate, 80s:

```
63 failed, 1696 passed, 6 skipped, 82 deselected
```

Failure breakdown — every one accounted for:

| Count | File | Real? |
| --- | --- | --- |
| 40 | `test_transactional_deploy.py` | No — macOS `stat -c` |
| 14 | `test_restore_production_data.py` | No — macOS `stat -c` |
| 5 | `test_owner_credential_submission.py` | **Yes** |
| 1 | `test_onboarding_end_to_end.py` | **Yes** |
| 1 | `test_provider_profile.py` | **Yes** |
| 1 | `test_production_container_hardening.py` | No — stale test |
| 1 | `test_playwright_worker.py` | **Yes, small** |

**54 are environmental**: `scripts/{backup,restore}-production-data.sh` use GNU
`stat -c`, which BSD/macOS `stat` rejects (`stat: illegal option -- c`).

The 7 product failures, **[verified by me directly]**:

| Test | Meaning |
| --- | --- |
| `test_onboarding_end_to_end.py::test_one_signup_run_reaches_a_validated_credential` | `AssertionError: the onboarding walkthrough must not reach the network` — the new profile planner dials a live LLM mid-walk |
| `test_provider_profile.py::test_allowed_hosts_refuse_to_substitute_a_reviewed_recipes_authority` | `DID NOT RAISE BrowserPolicyInactiveError` — **security regression** |
| `test_owner_credential_submission.py` ×5 | plain playwright run ends `configuration_required`, expected `browser_running` |

Two that earlier passes left unclassified, **[both verified by me]**:

- `test_production_container_hardening.py::test_totp_secret_is_withheld_...` —
  `KeyError: 'OPS_AUTH_TOTP_SECRET'`. **Stale test, not a bug.** Commit `cd5604f`
  ("Remove TOTP from production authentication") dropped the var from `.env.example`,
  and no app code reads it (only `redaction.py` regexes mention `totp`). But
  `compose.prod.yaml:58` still sets `OPS_AUTH_TOTP_SECRET: ""` while the test also
  expects a template entry that no longer exists. Delete the test's template
  assertions, and drop the dead compose line.
- `test_playwright_worker.py::test_chromium_child_environment_excludes_worker_secrets_in_every_launch_mode`
  — **real, small.** `chromium_launch_environment(display, *, headless)`
  (`ops/browser/process_hardening.py:75-81`) takes `headless` and **never reads it** —
  verified: the name appears exactly once, in the signature. So it falls back to
  `os.environ.get("DISPLAY")` even for headless launches, leaking the host `DISPLAY`
  into a headless Chromium. The docstring at `ops/playwright/worker.py:440` states
  "headless Chromium receives no `DISPLAY` at all"; the code doesn't honour it. Fix:
  `if not headless and (display or os.environ.get("DISPLAY"))`.

### The security regression, in detail

**[verified]** via `git diff ops/browser/host_policy.py`. The new
`profile_authority: bool = False` branch at `host_policy.py:276-283` skips **both**
the app-slug mismatch guard and the `get_browser_policy(app_slug)` reviewed lookup:

```python
if profile_authority:
    policy = discovered_policy_from_research(app_slug, research)   # no recipe check
else:
    if recipe is not None and recipe.app_slug != app_slug: raise ...
    policy = browser_policy_from_recipe(recipe) if recipe else get_browser_policy(app_slug)
```

For `pipedrive` — which *has* a reviewed recipe, and is also the only app on the
legacy signup path — a profile-derived allowlist now silently substitutes for the
reviewed authority instead of refusing. Keep this guard. It is not snapshot
bureaucracy; it stops a researched URL from overriding a reviewed one.

## Config blockers on the critical path

| # | Where | Default | Symptom | Fix |
| --- | --- | --- | --- | --- |
| 1 | `api/app.py:185` `len(expected) < 32` | `OPS_INTERNAL_API_TOKEN` **unset** | **HTTP 503 `internal_api_unavailable` on every `/api/*` call** | config |
| 2 | `canonical_runtime.py:742-746` | API default `browser_use` (`api/models.py:274`) | 409 `playwright_required_for_reviewed_signup` | send `browser_provider="playwright"`, or change the default |
| 3 | `canonical_runtime.py:752-757` | `GMAIL_SIGNUP_ADDRESS` unset | 409 `gmail_signup_address_not_configured` | config |
| 4 | `ops/runs/service.py:764-770` | `OPS_STARTUP_AUTOMATION_ENABLED=false` | **silent** — no error, no reason code, runs park forever | config + emit a reason |
| 5 | `ops/deploy/acceptance.py:64-69` | default path `./private/...` is **relative**, checked with `is_absolute()` | acceptance can *never* succeed at defaults | **code** |

Current `.env` state **[verified]**: `ALLOW_LIVE_BROWSER=true`,
`BROWSER_PROVIDER=playwright`, `PLAYWRIGHT_IN_PROCESS_SANDBOX=true`,
`ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true`, vault + AES keys set.
`GROQ/CEREBRAS/OPENROUTER/PERPLEXITY/GEMINI` keys all present — so the inference chain
*is* configured locally, which is exactly why the E2E test reaches the network.
Missing: `OPS_INTERNAL_API_TOKEN`, `GMAIL_SIGNUP_ADDRESS`,
`OPS_STARTUP_AUTOMATION_ENABLED`.

## Other real bugs found

- **`evidence` is dead.** `ops/planner/decide.py:102-125` pipes an `evidence` arg
  through DLP, but `RunPlanner.plan_for` (`driver.py:1897-1903`) has no such
  parameter and no caller supplies one — it is always `""`. Research never reaches
  planning. **[verified: zero `evidence=` hits on the planning path]**
- **`inference` is always `None` at both planner construction sites**
  (`composition.py:643`, `ops/runs/service.py:433`), so `decide.py:433-437` builds a
  fresh LLM chain *inside every planning call, on the request path*, unsubstitutable
  in tests. This is the direct cause of the E2E network failure.
- **Illegal status writes.** `ops/core/storage.py:1897-1976` `_update_run` whitelists
  `status` but never calls `validate_status_transition`. Replaying the mounted walk
  produces two illegal writes that persist silently: `researching → waiting_for_hitl`
  and `waiting_for_hitl → route_selected`. Violates the CLAUDE.md invariant that
  storage enforces transitions.
- **Vocabulary leak.** `canonical_runtime.py:862` writes
  `reason_code="profile_research_required"`, which is not a member of
  `OnboardingReasonCode` (`phase.py`). It escapes the closed vocabulary because it is
  written via `update_run` (plain TEXT) rather than `commit_phase`.
- **One reason code for ten causes.** `PlanRefusalDetail` (`validator.py:31-42`) has
  10 values, all constructed, **none ever read** — every consumer takes only
  `reason_code`, which is the single constant `plan_surface_not_in_catalog`. This is
  why these failures are undiagnosable from the console.
- **Selector false positive.** `ops/credentials/capture.py:209` rejects any selector
  containing the substring `script`, so `[data-testid='script-token']` is refused.
- **DLP hex patterns.** `ops/core/model_input_dlp.py:57-58` flags any bare 32/40-char
  hex — i.e. any git SHA or MD5 in page text. Six consecutive refusals exhaust the
  no-progress budget (`action_loop.py:198`).

## Guard rails to keep

Not snapshot bureaucracy — these are load-bearing:

- `ops/access/gate_policy.py:98-118` `HUMAN_ONLY_GATES` (captcha, phone OTP, passkey,
  billing, provider verification…) and the fail-closed default at `:264-272`. Captcha
  automation is anti-bot defeat; billing gates spend money and accept contracts.
- `api/browser_secret_broker.py:311-321` capture field allowlist + value pattern.
- `ops/credentials/capture.py:130-137` rollback of partial vault refs on exception.
- `ops/onboarding/admission.py:285-293` `signup_authorization_required` — this is the
  intended human decision point and it *is* operator-resolvable.
- The reviewed-recipe guard in `host_policy.py` (see security regression above).

## What the previous dev was mid-build on

The uncommitted diff is **not** more blockers. It is the beginning of the escape hatch
this project needs: a **second route authority** (`ProviderProfile`) alongside the
reviewed recipe, so apps with no static recipe can be onboarded.

- `ops/core/models.py` +17 — `onboarding: bool`, `provider_hint_url` on
  `OperationsRequest`, forcing `account_mode='create_account'`
- `ops/planner/{plan,decide,validator}.py` — `PlanSource` gains `"profile"`;
  `decide_profile_plan`, `profile_route_plan`, `validate_profile_plan`, new refusal
  codes `host_not_in_profile`, `surface_count_exceeds_profile`,
  `profile_binding_mismatch`
- `ops/core/storage.py` +86 — `RUN_PLAN_SOURCE_VALUES` widened; new `execution_path`
  column; `_migrate_run_plan_vocabularies` rebuilds the table because SQLite cannot
  `ALTER` a `CHECK`
- `ops/research/operational_research.py` +49 — HTML parser now harvests `<a href>` /
  `<form action>` so signup/login targets survive excerpt truncation
- Untracked: `ops/onboarding/runtime.py` (646 lines, the mounted runtime),
  `tests/test_mounted_dispatch_boundary.py`, `tests/test_run_plan_vocabulary_migration.py`

**All imports resolve; no stale callers; no `NotImplementedError`.** The refactor is
structurally coherent and roughly 80% done. It stops exactly at the browser phases.

## Fix order

Ordered so that each step is verifiable and nothing is wasted.

**Phase 0 — make failures legible (do this first, it is 10 lines)**
0. Fix `_reason` (`ops/browser/service_client.py:238-249`) to handle FastAPI's
   *list* `detail` and surface the field name. Without this every RPC contract break
   is an opaque `http_422`, and Phases 1-3 get debugged blind.

**Phase 1 — make one run complete end-to-end (pipedrive, local sandbox)**
1. Set `OPS_INTERNAL_API_TOKEN` (≥32 chars) and `GMAIL_SIGNUP_ADDRESS`; default
   `browser_provider` to `playwright` in `api/models.py:274`.
2. Fix the 5 `test_owner_credential_submission` failures
   (`canonical_runtime.py:797-800,977`) — plain playwright runs must reach
   `browser_running`, not `configuration_required`.
3. Restore the reviewed-recipe guard under `profile_authority`
   (`host_policy.py:276`) — fixes the security regression and its test.
4. Inject `ports.inference` into `SettingsRunPlanner` / `decide_profile_plan`
   (`composition.py:379`, `ops/runs/service.py:433`) — fixes the E2E network failure
   and removes a 20s synchronous LLM call from the request path.

**Phase 1b — repair the production RPC contract (independent of Phase 1)**
Only bites when `PLAYWRIGHT_IN_PROCESS_SANDBOX=false`, i.e. in production.
1b-i. Make `ResumeRequest.research` required, or have the handler reuse the session's
   stored research instead of `payload.research or {}` (`main.py:810`). **This is the
   HITL resume path — captcha/OTP continuation cannot work until it is fixed.**
1b-ii. Raise the `setup_fields` cap from 20 to ≥22 (`models.py:211`, `:247`), or derive
   it from `len({**_PROVIDER_LIMITS, **_COMPANY_LIMITS})` so the two cannot drift again.
1b-iii. Align `recipe_snapshot`: either require it in the model or let the handler
   accept its absence (`models.py:66` vs `main.py:536-540`).
1b-iv. Give the RPC path a real idle bound, or drop `inactivity_expires_at` rather than
   substituting the absolute lifetime (`service_client.py:336`, `main.py:1419`).
1b-v. Add a contract test that round-trips every client payload through the server model
   — all three breaks above would have been caught by one such test.

**Phase 2 — stop losing runs**
5. Make `paused` recoverable: add it to the sweep (`storage.py:2009`) and/or give it
   a forward target (`phase.py:195`) and/or drop it from `_NON_CONTINUATION_PHASES`.
6. Enable `OPS_STARTUP_AUTOMATION_ENABLED`, fix the relative-marker-path bug
   (`acceptance.py:64-69`), and emit a reason code instead of returning silently
   (`ops/runs/service.py:764-770`).

**Phase 3 — the real work: implement the browser seam**
7. Build the generic browser adapter (observe / act / signup) and replace
   `_UnavailableBrowserHandler` (`runtime.py:511-512`) and `_NoBrowserSessions`
   (`runtime.py:516`).
8. Register the six missing phase handlers in `runtime.py:499-513`, reusing the
   implementations the E2E test already wires.
9. Enforce transitions in `_update_run` (`storage.py:1897`) and add the two needed
   edges to `ops/core/state.py:58,94`.

## Coverage: the real numbers (2026-08-02, verified)

The "50 app catalog" is not an arbitrary limit — it is exactly the set Composio has
a toolkit for. Measured against `data/p1/results.json`:

```
catalog 50      composio_toolkit: Yes = 50
non-catalog 50  composio_toolkit: No  = 49, Yes = 1
all 100         Self-Serve 65, Gated 35
```

That coupling matters: managed OAuth needs a Composio toolkit, so the 49 apps with
`toolkit: No` have **no OAuth route at all** — browser is their only path.

| Group | Count | Route | Status |
| --- | --- | --- | --- |
| catalog, managed_auth | 25 | Composio OAuth | **routing fixed** (see below) |
| catalog, playwright | 13 | mounted profile path | seam landed, untested live |
| catalog, playwright + signup URL | 1 | legacy static | pipedrive |
| catalog, gated | 11 | outreach | untouched by choice |
| non-catalog, Self-Serve | 31 | browser via profile path | **blocked, see Phase 4** |
| non-catalog, Gated | 19 | outreach | untouched |

Realistic autonomous target: **~70** (25 OAuth + 45 browser), 30 outreach.

**Correction to an earlier claim in this document:** P1 does *not* block app #51. All
100 apps are already in `data/p1/results.json`, so the membership check at
`app_recipes.py:743` passes for every one of them, the field bound is
`max_length=100`, and nothing needs to edit P1 — only read more of it. The hash lock
is not involved. The real blocker is the recipe requirement (Phase 4 below).

### Done: managed_auth no longer diverted to browser signup

`canonical_runtime.py:725` — `profile_onboarding` and `executable_signup` both now
exclude `route_kind == "managed_auth"`. Verified before/after:

```
BEFORE: managed_auth -> mounted browser signup  25
AFTER:  managed_auth -> mounted browser signup   0
        managed_auth -> readiness error          0
```

Both hunks are required: without the `executable_signup` one, all 25 raise
`reviewed_signup_recipe_not_available` for a signup recipe they never needed.

**Phase 4 — widen coverage beyond the catalog**
10. Fix `_recipe_credential_surface` (`decide.py:192`) to honour `browser.scope` and
    `success.url_path_contains`, as the validator already does — recovers 7 apps.
11. **Off-catalog onboarding — three coupled edits, not one.** Attempted as a small
    change and abandoned: doing only the API edit turns a clean 404 into a 500,
    which is precisely the regression the existing guard's comment says it prevents.
    All three are required together:

    a0. `ops/runs/service.py:1520` — **the gate that decides whether canonical is
       reached at all**, and the one the rest of this item is useless without:
       `if self._canonical.recipe_for_request(request) is not None:`. An off-catalog
       request never enters `canonical.create_run`, so edits (a)-(c) below are not
       even executed. It needs `or request.onboarding`. Note the failure mode differs
       by mode: `:1527` raises `CredentialSubmissionError("reviewed_recipe_required")`
       for `execute_when_configured`, while `plan_only` silently downgrades to a
       research-only run at `:1531`.
    a1. `ops/workflow/canonical_runtime.py:985` — `persisted_recipe =
       self._recipe_for_run(created)` raises
       `CredentialSubmissionError("immutable_recipe_snapshot_missing")`
       unconditionally, and it runs BEFORE the `not profile_onboarding` branch on
       `:991` that would skip it. Same shape as the trap below, one layer down.
    a. `api/service.py:2196` — consult `request.onboarding` before raising
       `AppNotFoundError`. **[verified]** `CreateRunRequest` already carries
       `onboarding` and `provider_hint_url`, and `recipe` is used for nothing else
       in `create_run`, so this edit alone is trivial.
    b. `ops/workflow/canonical_runtime.py:677-679` — `recipe = recipe_for_request(...)`
       then `if recipe is None: raise KeyError(...)`, and `recipe_for_request`
       (`:450-453`) consults the catalog only. **This is what turns the API edit into
       a 500.** Needs a recipe-optional path for `request.onboarding`, which means
       every downstream `recipe.` read in `create_run` needs a profile-derived
       answer or an explicit absence.
    c. `ops/onboarding/runtime.py:557-561` — `recipe_from_run(record)` raises
       `RecipeSnapshotError` and the run is blocked with
       `research_adapters_unavailable`. A run with no recipe snapshot must instead
       proceed on `provider_hint_url` alone.

    Do NOT write 50 new recipes instead. A playwright recipe carries reviewed
    `browser.exact_hosts`, `steps`, a `success` predicate and `capture` selectors —
    per-app manual review work, weeks for 50 apps. The `ProviderProfile` path exists
    precisely to onboard an app from live research without a pre-written recipe, and
    it is already wired to the browser seam. Making that path recipe-optional is the
    cheaper and intended route to the other 31 self-serve apps.
12. Surface `PlanRefusalDetail` in the API response so failures are diagnosable.
13. Decide the P1 question: to onboard app #51, the hash lock
    (`p1_adapter.py:218,238,240`), the P1-membership check
    (`app_recipes.py:743-745`) and the 50-slug matrix (`app_recipes.py:655-672`) all
    have to give. Recommended: keep P1 as *evidence* the profile path may consult,
    drop it as a *gate* on catalog membership.

**Housekeeping**
13b. Honour `headless` in `chromium_launch_environment`
    (`ops/browser/process_hardening.py:75-81`) so a headless launch gets no `DISPLAY`,
    as its own docstring already promises. Small, self-contained, has a failing test.
13c. Retire the TOTP leftovers: drop `OPS_AUTH_TOTP_SECRET: ""` from
    `compose.prod.yaml:58` and the template assertions in
    `tests/test_production_container_hardening.py:252-262`. Commit `cd5604f` removed the
    feature; only the scaffolding remains.
14. Replace GNU `stat -c` in `scripts/{backup,restore}-production-data.sh` — recovers
    54 local test failures.
15. Fix CLAUDE.md: `ops/core/dlp.py` does not exist (it is `model_input_dlp.py`), and
    note that `make test` is the only working pytest invocation.
16. RPC hygiene: pool one `httpx.AsyncClient` instead of one per call
    (`service_client.py:220-224`); close the owned `_sync_client` (`:910-915`); fix the
    dead membership check in `provider_session_id` (`:917-920`); move the secret broker
    and storage-state IO off the event loop (`secret_broker.py:39`, `main.py:583,1329,1524`).
17. Decide on `/internal/ready` exposure (`main.py:1291-1297`) — unauthenticated and
    launches Chromium. Point container healthchecks at `/internal/live` regardless.

## Gotchas for whoever works here next

- `source .venv/bin/activate` **silently fails** in this shell and falls through to a
  system Python 3.14 with no pytest → "No module named pytest" looks like a broken
  suite. Always use `./.venv/bin/python -m pytest`.
- Bare `pytest tests/` hangs past 600s. Use `make test` or
  `-m "not live and not browser"`.
- zsh: quote glob args to grep (`grep -r --include='*.py'`) — unquoted globs error out
  and look like zero results.
- `ops/recipes/app_recipes.json` raw entries have no `urls` key; go through
  `load_app_recipe_catalog()`, whose `.apps` entries are the real model.
