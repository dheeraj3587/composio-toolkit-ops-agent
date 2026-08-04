# Autonomy Blocker Audit — consolidated report

Repo: `composio-toolkit-ops-agent` · branch `fix/production-ci-cd` · HEAD `8108782`
Measured: 133,577 lines across `ops api web/src browser_service tests` (`ops/` 66,974 · `tests/` 44,101 · `web/src` 12,689 · `api/` 5,772 · `browser_service/` 4,041)

Prepared against `semantic-review/autonomy-blocker-audit-prompt.md`. Part A (what stops an unattended run) outranks Part B (what can be deleted).

## Provenance and how to read this

Produced by six parallel audits, each required to execute rather than infer. Scratch probes and captured output live under `.audit_work/`. Findings that could not be traced to a real run outcome are labelled UNVERIFIED; there are two.

**The working tree is dirty and that matters.** 19 tracked files carry uncommitted changes (`api/models.py`, `api/service.py`, `ops/browser/host_policy.py`, `ops/core/models.py`, `ops/core/storage.py`, `ops/onboarding/composition.py`, `ops/onboarding/driver.py`, `ops/onboarding/phase.py`, `ops/planner/{decide,plan,validator}.py`, `ops/providers/profile.py`, `ops/research/operational_research.py`, `ops/workflow/canonical_runtime.py`, `ops/you/candidates.py`, plus 4 web files), and `ops/onboarding/runtime.py` is untracked. Two red tests behave differently at HEAD than in the tree, so each is attributed explicitly below. Line numbers are the working tree.

**Verified baseline.** `RUN_LIVE_TESTS=0 .venv/bin/python -m pytest -q -m "not live and not browser"` → 63 failed / 1696 passed / 6 skipped / 82 deselected in 227s. 54 failures are the macOS environment noise in `test_transactional_deploy.py` and `test_restore_production_data.py` and are excluded per the brief. Nine are real and every one is root-caused here. `.venv/bin/mypy ops api` → clean, 156 files. `.venv/bin/ruff check ops api tests` → clean. `npm test` in `web/` → 132/133, one stale assertion. So no defect below is visible to the type checker or the linter: they are all runtime predicates, wiring gaps, or config defaults.

## Corrections to the brief's premises

Seven, because acting on the brief as written would send work to the wrong places.

1. **"There is no `api_key` handling anywhere today" is false.** It exists at four layers: `FlowKind`/`CredentialKind` including `api_key`, `personal_access_token`, `client_credentials_pair` (`ops/providers/profile.py:74,78-84`), `FlowSpec.produces` (`:147`), `_FLOW_PRODUCES` mapping (`ops/providers/profile_builder.py:293-299`), `ONBOARDING_VAULT_KINDS` with anchored per-kind value patterns (`ops/onboarding/credentials.py:153-156`), and 7 recipes declaring concrete capture fields that `ops/playwright/worker.py:2477-2479` actually vaults. What is missing for goal step 5 is narrower and stated as finding A28: no cross-run reader.

2. **`route_selected_signup` does not map to the pausing handler.** It maps to `_SelectSignupHandler` (`ops/onboarding/runtime.py:405`), which advances unconditionally. The pausing handler `_UnavailableBrowserHandler` (`:419`) is bound to `route_selected_login` **and** `signup`. The signup route therefore gets one phase further than the brief states, then dead-ends at the same place.

3. **The credential-lifecycle functions are not in `ops/onboarding/credentials.py`.** `_reusable_login_values` → `ops/runs/login_secrets.py:122`; `_stage_signup_login` → `:161`; `_promote_staged_signup_login` → `:215`; `_finalize_captured_credentials` → `ops/runs/credentials.py:219`. The live orchestrator for the login path is `ops/workflow/canonical_runtime.py`, not `driver.py`.

4. **The `plan_only` deletion hazard is inverted.** `web/src/app/runs/new/actions.ts:68-73` fails closed to `plan_only`, and `api/models.py:273` defaults to it. Deleting the UI selector alone makes *every* run plan-only — no live spending, but no live runs either. The live-spend risk appears only if the `actions.ts` fallback is also flipped. Correct sequence is in cluster B9.

5. **`test_provider_profile.py::test_allowed_hosts_refuse_to_substitute_a_reviewed_recipes_authority` passes at HEAD.** The working-tree change to `ops/providers/profile.py:258` (`profile_authority=True`) is what makes it fail. The reason code it asserts, `reviewed_browser_policy_supersedes_profile`, does not exist anywhere in the tree. See A44.

6. **`ops/browser/provider.py` has zero importers**, confirmed independently by AST import-graph scan and by direct grep. Every `browser.provider` hit across `ops api browser_service scripts tests` is the `browser_provider` settings field; the `BrowserProvider` symbol everyone imports is the `Literal` at `ops/core/state.py:19`, not the Protocol at `ops/browser/provider.py:23`. It is the only orphan module in the repo.

7. **`plan_only` is the default execution mode**, not an opt-in. `api/models.py:273`, `ops/runs/creation.py:133`, `ops/runs/service.py:1506` all default to it, and the mounted walk never reads it. See A12.

## The one-paragraph answer

Under a plain `docker compose -f compose.prod.yaml up`, nothing runs at all: the release-acceptance gate can only be satisfied by `scripts/deploy-droplet.sh`, so every `POST /api/runs` returns 503 and three of four background sweeps never enter their loop (A6). Past that, a run reaches phase `signup` or `route_selected_login` and stops, because both are wired to a handler whose only behaviour is `pause("browser_adapter_unavailable")` and the session factory is a stub that raises (A2). Reset is the only forward control, and it walks straight back to the same pause (A8). For the login route the run does not even get that far for half the catalog: 7 of the 14 Playwright recipes are refused a credential surface before any session exists, which is also the root cause of the five red `test_owner_credential_submission` tests (A1). Every failure path that should leave a recoverable `blocked` boundary instead raises, because two call sites commit a phase without a valid profile digest — and one raising run permanently starves the drain loop for every healthy run behind it (A3, A4, A5). None of this is visible to mypy, ruff, or the 1,696 passing tests.

---

# Part A — defects that prevent an unattended run

Severity is autonomy impact: **BLOCKER** (cannot complete for common apps), **STALL** (halts needing a human who should not have been needed), **SILENT** (wrong outcome, no error surfaced), **LATENT** (correct today, breaks under crash/retry/concurrency).

## A1 [BLOCKER] Every `entry_only` recipe is refused a credential surface before a session exists — 7 of 14 Playwright apps, and the cause of 5 red tests

**Where:** `ops/planner/decide.py:192-197` (`_recipe_credential_surface`) → `:213-215` (`recipe_route_plan` returns `None`) → `:426-432` (`decide_run_plan` refuses). Same gate mirrored at `ops/planner/validator.py:178-182`. Consumed at `ops/workflow/canonical_runtime.py:1127-1136`.

**Trigger:** operator picks Login on telegram, klaviyo, shopify, dataforseo, bright-data, neo4j, or xero. The failing predicate is one line: `recipe.urls.credential_management is None`. All seven carry `null` there.

**Consequence:** `_start_playwright` writes `status=configuration_required, phase=plan_refused, reason_code=plan_surface_not_in_catalog` and returns **before** `worker.start`. No session, so `entry_reached` never happens, so `submit_owner_credentials` is unreachable forever. Half the browser catalog cannot begin an autonomous login run.

**Evidence:** two agents reached this independently. Real `decide_run_plan` over all 14 recipes (`.audit_work/out_a2.txt`):

```
refused: 7/14 -> telegram, klaviyo, shopify, dataforseo, bright-data, neo4j, xero
   all: plan_surface_not_in_catalog/recipe_route_not_browser@0
admissible: pipedrive, apify, firecrawl, vercel, cloudflare, datadog, coda
route_kind: playwright | browser is None: False | scope: entry_only
urls.credential_management: None
```

And the red test, dying in the shared `_entry_reached` helper at line 88:

```
tests/test_owner_credential_submission.py:88: AssertionError
assert 'configuration_required' == 'browser_running'
```

The catalog proves the gate is wrong rather than the recipes: `scope=entry_only` ⇔ `readiness_tier=owner_submit_ready` (7/7) and `scope=credential_surface` ⇔ `browser_ready` (7/7). An `entry_only` recipe is *designed* to stop at the entry page and let the owner paste the token. It has no credential surface by construction, and plan admission demands one from exactly those recipes.

**Secondary defect, same site:** the refusal detail is a diagnostic lie. It reports `recipe_route_not_browser` while `route_kind == "playwright"` and `browser is not None`. The correct code `credential_surface_not_declared` does not exist; `credential_surface_unprovable` at `validator.py:34-43` is the nearest.

**Fix:** in `recipe_route_plan`, when `browser.scope == "entry_only"` and `capture.mode == "owner_submit"`, emit the plan with the entry surface as the credential surface — or make `RunPlan.credential_surface` optional for `owner_submit_ready` recipes. Change producer and validator together; `_validate_recipe_plan` already has the scope branch. Add the distinct detail code.

## A2 [BLOCKER] The production phase-handler map binds `signup` and `route_selected_login` to a pause-only stub

**Where:** `ops/onboarding/runtime.py:511-512` — `"route_selected_login": _UnavailableBrowserHandler(), "signup": _UnavailableBrowserHandler()`. Handler body at `:419-430` is `return PhaseStep.pause("browser_adapter_unavailable")`. Session factory is `_NoBrowserSessions` (`:276`, injected at `:517`), which raises `RuntimeError` for every phase. `drive_run` has exactly one production caller, `:524`.

**Trigger:** every mounted run, both routes, every app. Run #1: `awaiting_admission → route_selected_signup → signup`. Run #2 with credentials in the vault: `vault_check → route_selected_login`.

**Consequence:** the walk commits `→ paused` and stops. Both product-goal legs — drive a browser to log in or sign up, and reuse stored credentials on the next run — never execute. Every mounted run terminates `paused / browser_adapter_unavailable`. Compounding, `stranded_mounted_run_ids` (`ops/core/storage.py:2009-2018`) selects only `('research','vault_check','awaiting_admission','route_selected_signup')`, so a paused run also leaves the sweep set and nothing re-drives it.

**Evidence:** captured walks (`.audit_work/scratch1.txt`):

```
WALK: [... (5,'route_selected_signup','signup','operator_approved_signup'),
           (6,'signup','paused','browser_adapter_unavailable')]
ROW phase/status/reason: paused waiting_for_hitl browser_adapter_unavailable
swept again?: False

WALK: [... (4,'route_selected_login','paused','browser_adapter_unavailable')]
```

**What a real deployment needs.** None of it is settings-driven — the map is a dict literal with no conditionals:

1. A `PhaseHandler` for both phases. `SignupPhaseHandler` exists at `ops/browser/signup.py:1694` and is wired into **no** handler map anywhere (`grep -rn "handlers=" ops api --include='*.py'` → only `runtime.py:517` and `composition.py:531`; the class is instantiated only in `tests/test_onboarding_signup_phase.py:215` and `tests/test_onboarding_end_to_end.py:729`).
2. A real `LoopSessionFactory` in place of `_NoBrowserSessions`.
3. `deps_for(..., logins=, verification_binding=)` — both default `None` at `:513-518`, so `_verification_is_wired` (`driver.py:5124`) is `False` and `email_verification` would fall through to the action loop and the missing factory.
4. No production adapter implements the `SignupSubmitter` protocol: `grep -rn "async def submit_signup"` returns the protocol at `signup.py:1510` plus two test fakes.
5. Handlers for `vault_storage` and `credential_validation` (A22).

**Fix:** this is a wiring gap, not a bug, and there is no narrow change. Wire `SignupPhaseHandler` plus a real session factory behind the existing `browser_configuration_state` check, and extend `stranded_mounted_run_ids` to the post-admission phases. Until then the honest move is to stop advertising the signup route as autonomous.

## A3 [BLOCKER] A research failure cannot commit its `blocked` boundary — the exception escapes and the run looks alive forever

**Where:** `ops/onboarding/runtime.py:325` returns `PhaseStep.advance("blocked", outcome.reason_code)` with no `profile_digest`; `ops/onboarding/driver.py:2472-2474` then raises.

```python
digest = step.profile_digest or (profile.profile_digest if profile else None)
if digest is None:
    raise PhaseNotDrivable(phase, "a phase transition requires a profile digest")
```

**Trigger:** any mounted app, common path. Evidence fetch fails or corroborates fewer than twice → `ResearchInconclusive`. Unconditional: this branch is reachable only when no profile is committed, so `profile` is always `None` and `step.profile_digest` is always `None`.

**Consequence:** `PhaseNotDrivable` escapes `advance()`. Phase history is **empty**, the run row is byte-identical, and reset, retry and cancel are all refused. The run reads as still researching, permanently. This is the fix listed as already-landed in the brief — the `blocked` return is there; it cannot commit.

**Evidence** (`.audit_work/scratch5.txt`):

```
ESCAPED advance(): PhaseNotDrivable phase 'research' is not drivable:
    a phase transition requires a profile digest
WALK: []
ROW: research researching profile_research_required
updated_at unchanged: True
reset: False   retry: False   cancel: False
still swept (stays first, ORDER BY updated_at ASC): True
```

**Fix:** `PhaseStep.advance("blocked", reason, profile_digest=NO_PROFILE_DIGEST)` with `NO_PROFILE_DIGEST = "0" * 64`. `""` will not work — see A4.

## A4 [BLOCKER] `_block_main_run` commits `profile_digest=""`, which the store's own validator rejects

**Where:** `ops/onboarding/runtime.py:592` passes `profile_digest=""`; `ops/onboarding/driver.py:1387-1390` raises `ValueError("profile digest must be a sha256 hex digest")`.

**Trigger:** the two pre-walk failures this function exists for — an unreadable recipe snapshot (`runtime.py:461`) and an app absent from the P1 snapshot (`:466`).

**Consequence:** the `ValueError` fires on the `commit_phase` call, so the following `update_run` never executes. No boundary, no status change, exception out of `advance()`. Reached from `create_run` (`api/service.py:2247`) the 500 propagates and `web/src/app/runs/new/actions.ts:165` renders "we could not confirm whether the run was persisted" with no redirect — while the row exists and the drain retries it every ~20s forever.

**Evidence** (`.audit_work/scratch6.txt`, corroborated by `.audit_work/probe_digest.py`):

```
PROFILE_DIGEST_LENGTH: 64
ESCAPED _block_main_run: ValueError profile digest must be a sha256 hex digest
history: ()
ROW: research researching profile_research_required
```

The docstring at `runtime.py:589-590` calls `""` "the driver's own convention for a boundary with none to carry." The driver has no such convention.

**Fix:** same 64-zero sentinel, used in both places.

## A5 [BLOCKER] One raising run starves the entire mounted drain cycle, permanently

**Where:** `api/service.py:669-681` — the `try` wraps the whole `for` loop. `ops/core/storage.py:2009-2018` orders by `updated_at ASC`.

**Trigger:** any run that makes `advance()` raise, i.e. A3 or A4. Because the raise skips `_sync_main_projection` (`runtime.py:525`), the poison run's `updated_at` never moves, so it stays **first** in the sweep list on every cycle.

**Consequence:** every healthy mounted run behind it is never advanced. Not degraded — never driven, at any tick, until a human deletes the row.

**Evidence** (`.audit_work/scratch3.txt`, exercising the real `LocalRunService._drain_mounted_runs`):

```
sweep order (updated_at ASC): ('run_d250...', 'run_f685...')
advance() called for: ['run_d250...']
healthy run ever advanced: False
```

**Fix:** move the `try/except` inside the loop, one guard per run.

## A6 [BLOCKER] Shipped compose defaults make release acceptance unsatisfiable — 503 on every write, and three sweeps never start

**Where:** `ops/deploy/acceptance.py:64-70` (`_configuration`), `compose.prod.yaml:100,107-109`, `api/service.py:684-697` (`deployment_mutations_allowed`), `api/app.py:216-255` with `_MUTATION_GATED_PREFIXES = ("/api/", "/internal/browser-secret-broker/")`. Gated loops: `ops/runs/advance.py:107`, `ops/runs/takeover.py:135`, `ops/runs/email.py:138`.

**Trigger:** `docker compose -f compose.prod.yaml up`, with or without `compose.local.yaml`, even with `.env.production.example` fully filled in.

**Consequence:** two independent rejections, either alone sufficient. `APP_REVISION` defaults to `local-uncommitted`, which fails the 40-hex `_REVISION` regex. `OPS_DEPLOY_ACCEPTANCE_NONCE` defaults to the literal sentinel `manual-unaccepted`, rejected by name at `acceptance.py:68`. `OPS_STARTUP_AUTOMATION_ENABLED` is the hard literal `"true"` at `compose.prod.yaml:100` — not `${...:-}` — so the gate is armed and `deployment_mutations_allowed()` is permanently `False`. Every `POST /api/runs` returns `503 {"error":"deployment_not_accepted"}`: the operator cannot create the run that starts the goal. `advance_autonomous_runs`, `reconcile_idle_browser_runs`, `mark_stale_runs`, `_reconcile_stranded_runs`, the CAPTCHA takeover sweep and the Gmail verification poller all return before their `while` loop.

**Evidence** (`.audit_work/prove_acceptance_dead.txt`):

```
app_revision          : local-uncommitted
nonce                 : manual-unaccepted
sentinel constant     : manual-unaccepted
startup automation on : True
deployment_is_accepted: False
marker write          : refused -> deployment_acceptance_configuration_invalid
template-only nonce   : None          template-only accepted: False
deploy-script shape accepted: True
```

Autonomy is dead on arrival under a plain compose up — proved, not inferred. It is **not** dead in general: `scripts/deploy-droplet.sh:1184-1189` mints a conforming nonce and `:918-939` writes the marker inside the API container after its own health and public checks.

**Fix:** the sentinel design is sound; the gap is discoverability. Surface the unaccepted state on health/readiness with an actionable reason code, and ship `APP_REVISION=` / `OPS_DEPLOY_ACCEPTANCE_NONCE=` in `.env.production.example` annotated "generated by deploy-droplet.sh — leave blank." Today the operator sees a permanent 503 with no named cause.

## A7 [BLOCKER] `vault_check` blocks terminally without a vault key, and `blocked` admits nothing

**Where:** `ops/onboarding/runtime.py:355-356`; `ops/onboarding/phase.py:197` — `"blocked": frozenset()`; `ops/runs/reconciliation.py:712-723` (`_reset_path` returns `None` for terminal).

**Trigger:** `SECRET_VAULT_KEY` unset. It defaults to `None` (`ops/core/config.py:141`) and both `.env.example:11` and `.env.production.example:84` ship it blank. `build_onboarding_ports` then leaves `vault=None` and `_VaultHandler` blocks every run.

**Consequence:** the run terminates at `blocked / capture_spec_unavailable` on its **second** phase. Because `blocked` has zero outbound edges, all four operator controls refuse it — after fixing the config the operator cannot revive the run and must create a new one. The same trap catches the recoverable research and plan refusals: `plan_provider_unconfigured` is a missing API key and `research_adapters_unavailable` is a deployment gap, both fixable in seconds, both requiring the run to be abandoned.

**Evidence** (`.audit_work/scratch2.txt`):

```
ports.vault is None: True
WALK: [(1,None,'research',...), (2,'research','vault_check',...),
       (3,'vault_check','blocked','capture_spec_unavailable')]
reset accepted: False phase_replay_noop
retry accepted: False phase_replay_noop
cancel accepted: False phase_replay_noop
pause accepted: False phase_replay_noop
```

`ops/onboarding/runtime.py:322-324` states the intent verbatim: raising "left the run with no committed `blocked` transition, so `_onboarding_state` returned nothing and the console lost its reset and retry controls — the run became unrecoverable." Committing `blocked` reproduces that outcome by a different route.

**Fix:** a missing deployment capability is not a run outcome. Either fail `build_onboarding_ports` closed with `ConfigurationRequiredError` so no run is created, or add `blocked -> {research, cancelled}` and make `can_reset` true there. Keep `blocked` terminal only for genuinely unrecoverable refusals.

## A8 [BLOCKER] Every non-CAPTCHA pause is unresumable by construction — goal step 6 works for CAPTCHA only

**Where:** `api/service.py:1568`, `ops/onboarding/phase.py:169` (`"paused": frozenset({"research","cancelled"})`), `ops/runs/resume.py:864-901`.

`can_resume = waiting and bool(targets - _NON_CONTINUATION_PHASES)` where `_NON_CONTINUATION_PHASES = {research, cancelled, paused}` (`service.py:113`). The set difference is empty for `paused`, always.

**Trigger:** any `PhaseStep.pause(...)`. `PhaseStep.__post_init__` (`driver.py:1600-1603`) enforces that a pause always targets `paused`, so all 38 pause reason codes land there.

**Consequence:** the goal's "human only for CAPTCHA, MFA, billing, legal consent" holds for CAPTCHA alone. An operator who pays the bill, clears the MFA prompt or accepts the ToS in the live browser gets **no continue button**. The only exits are Cancel and Reset, and Reset releases the authenticated session (`reconciliation.py:576`) and restarts at research, discarding the human work. Worse, for a mounted run Reset is a closed loop: reset → `research` → the drain re-walks → `route_selected_login`/`signup` → `_UnavailableBrowserHandler` → `paused` again (A2). The UI even predicts it: "expected route on restart: Login" (`actions.ts:314-316`).

**Evidence:** UI and backend agree — `resume_from_pause` returns `accepted=False, PHASE_REPLAY_NOOP` for `paused` — so this is a model gap, not a projection mismatch. `resume.py:857-861` documents it as intended: "Such a run leaves `paused` through reset or cancel."

**Fix:** add `paused -> {every phase a pause can interrupt}`, mirroring how `captcha_paused` already fans out, and gate re-entry on `phase_at_pause` as `resume_from_pause` already does. Generalise `_withheld_resume_reason` from `phase == "captcha_paused"` to all of `WAITING_PHASES` so a withheld resume always says why.

## A9 [BLOCKER] No mid-run signup affordance — a login run that finds no account cannot route to signup

**Where:** `ops/workflow/canonical_runtime.py:724-728`, `api/models.py:319-320`, `ops/onboarding/phase.py:150` (`route_selected_login` targets), `web/src/app/runs/new/actions.ts:139`, `web/src/components/browser-hitl-forms.tsx:60`.

**Trigger:** operator picks "I have an account." `actions.ts:139` sends `onboarding: accountMode === "create_account"` → false. `api/models.py:319` refuses `onboarding` unless `account_mode == "create_account"`. `canonical_runtime.py:724` requires both for `execution_path="profile_mounted"`.

**Consequence:** the run is `legacy_static`, so no phase boundary exists, so `_onboarding_state` returns `None`, so `onboarding` and `controls` are null and the run detail page never renders the onboarding console or the admission form. The one "Create an account" button in the codebase (`browser-hitl-forms.tsx:96`) is gated on `can_decide_admission`, which requires `phase == "awaiting_admission"` — reachable only from `vault_check`. And `_LEGAL_PHASE_TRANSITIONS["route_selected_login"] = {authenticated, captcha_paused, paused, cancelled}` has no edge to signup or admission. The reason vocabulary has `signup_rejected_duplicate_account` for the inverse case but **no** code for login finding no account: the backend cannot express the condition, so no UI can offer the control. Goal step 4 has no implementation.

**Evidence:** `grep -rn 'execution_path' web/src --include='*.ts' --include='*.tsx'` → **0 hits**. The UI has no access to the resolved path at all; it uses `onboarding !== null` as a proxy.

**Fix:** add reason code `login_account_not_found` and transition `route_selected_login -> awaiting_admission`; make `can_decide_admission` true for that boundary; relabel the admission prompt from "No credential is in the vault" to the observed cause.

## A10 [BLOCKER] One flag gates every operator credential path, and every shipped env file sets it false

**Where:** `ops/core/config.py:238` (`allow_local_credential_submission: bool = False`), enforced in `api/app.py:573-591` via `_environment_flag("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", default=False)`. `.env.example:38` false, `.env.production.example:221` false, `compose.prod.yaml:76` `${...:-false}`. The local `.env:45` is true, which is why this passes locally and fails deployed.

**Consequence:** 403 on `create_run` with `browser_login` (`api/app.py:533`), on `resume` with `browser_login` or `browser_verification` (`:669`), and on `submit_credentials` (`:615`). `api/browser_ui.py:145,152,159` zeroes `can_submit_login`, `can_submit_otp`, `can_submit_credential`. Goal step 3 — a dialog collects credentials once, mid-run — is refused outright in every shipped configuration, and the OTP/verification-link path shares the gate so part of step 6 goes with it. The run parks at `browser_running / owner_credential_submission_disabled` (`api/service.py:789-798`). No deploy manifest overrides it.

**Fix, narrower than removing the gate:** split inbound submission from raw-secret *reveal*. Inbound submission writes straight to the vault and is never read back — `api/app.py:604-613` already documents exactly this — so it can be authorized by the existing mandatory `OPS_INTERNAL_API_TOKEN` owner gate and default on. Keep reveal loopback-only.

## A11 [BLOCKER] The evidence fetcher's allow-list comes only from the P1 record, so the reviewed login page is unfetchable for 10 of 14 apps

**Where:** `ops/onboarding/runtime.py:470` builds the policy from `OfficialURLPolicy.from_p1_record(p1_record)` (`ops/research/operational_research.py:177-193` — hosts from `primary_docs_url` plus P1 `evidence_urls` only), while `:471` and `:611-624` (`_reviewed_evidence_urls`) hand the discovery adapter a **wider** set that also includes `recipe.evidence_urls`. `_RequestedOfficialFetcher.fetch_many` (`:88-96`) drops each refusal silently.

**Trigger:** any app whose reviewed login or console host is not the docs host.

**Consequence:** the page a login run must understand is never read, so it contributes zero corroboration. `login_url` can then only be corroborated if two *other* fetched documents happen to link the identical string — and there are only 2 to 7 fetchable candidates per app. Combined with A17 and A18 the practical outcome is `research_no_evidence → blocked`, reported as if the provider published nothing.

**Evidence** (`.audit_work/out_a3.txt`, real policy and real `_reviewed_evidence_urls`): reviewed login/signup URL is not a fetchable candidate for **10/14** — pipedrive, telegram, klaviyo, shopify, apify, vercel, cloudflare, neo4j, datadog, xero. Host outright refused for 9 of those:

```
klaviyo    candidates=3 fetchable=2  REFUSED https://www.klaviyo.com/login
cloudflare candidates=7 fetchable=6  REFUSED https://dash.cloudflare.com/login
xero       candidates=5 fetchable=4  REFUSED https://login.xero.com/identity/user/login
neo4j      candidates=6 fetchable=5  REFUSED https://console.neo4j.io/
   ...each: URL host is outside the verified official allowlist
P1 missing: 0/14
```

klaviyo is left with 2 fetchable documents total — the exact minimum for a 2-corroboration field, with no margin.

**Fix, and it does not widen SSRF exposure:** build the policy from the same set the discovery adapter already gets — `OfficialURLPolicy(exact_hosts=hosts_of(_reviewed_evidence_urls(recipe, p1_record)))` using the **strict** `exact_hosts` class rather than the legacy exact-or-subdomain one. Every added host is a checked-in reviewed recipe URL, the DNS, private-address, port and redirect checks in `validate_for_request` are untouched, and the result is *narrower* per host than today.

## A12 [STALL] `plan_only` is the default, and the mounted walk is blind to it

**Where:** default at `api/models.py:273`, `ops/runs/creation.py:133`, `ops/runs/service.py:1506`; persisted as `local_dry_run` (`ops/runs/projections.py:41-45`). `grep -c 'execution_mode\|plan_only'` is **0** in `driver.py`, `runtime.py`, `composition.py`, and `ops/planner/decide.py`. `stranded_mounted_run_ids` filters on `execution_path` and `phase` only.

**Real work reached with `execution_mode == "plan_only"`:** live outbound HTTPS to provider sites (`runtime.py:494-498`), Perplexity discovery when configured (`:481-489`), a real model call for extraction (`:505`), vault inspection via `probe_login_refs` (`:508` → `admission.py:216-236`), the admission decision and operator prompt (`:509`, `:530-535`), and a **second** live inference call through `plan_admission` (`driver.py:2452` → `composition.py:379` → `decide.py:393` → `ops/core/inference.py:530`).

**Trigger:** `POST /runs` with `onboarding=true, account_mode=create_account` and no `execution_mode`. `canonical_runtime.py:723` sets `profile_onboarding` without consulting `execution_mode`, and `:843-857` lets it win for both status and phase → `execution_path='profile_mounted'`, `phase='research'`. The drain then advances it.

**Consequence:** the UI says "Creates a plan without opening websites" (`new-run-form.tsx:347`) and "Research and planning are side-effect free" (`:486-487`) while the run fetches vendor sites, spends two inference budgets, reads the vault and posts an operator prompt.

**Evidence:** the repo's own e2e test proves the network hit, and it is one of the nine real failures:

```
AssertionError: the onboarding walkthrough must not reach the network
driver.py:2452 → driver.py:2302 → composition.py:379 → decide.py:393
    → inference.py:530 → socket.connect(('104.18.38.236', 443))
```

`ALLOW_LIVE_BROWSER` and `ALLOW_LIVE_VENDOR_EMAIL` are irrelevant here — neither guards `httpx` research or `inference.generate`, so offline and live behave identically on this leg.

**Fix:** short-circuit `_ResearchHandler` and `plan_admission` on `execution_mode == 'local_dry_run'` and exclude it from `stranded_mounted_run_ids`; or delete the mode and default to `execute_when_configured`. Do not leave the label.

## A13 [BLOCKER] The mounted drain is the one background loop with no acceptance gate, and it spends

**Where:** `api/service.py:639` starts `_drain_mounted_runs()` unconditionally in `startup`; the loop body at `:654-682` never calls `wait_for_deployment_acceptance`, unlike `ops/runs/advance.py:107`, `takeover.py:135` and `email.py:138`.

**Trigger:** any API container start with stranded mounted runs — including an unaccepted candidate container mid-deploy.

**Consequence:** `advance` opens an `httpx.AsyncClient` (`runtime.py:494`) and engages Perplexity discovery when configured (`:483-489`). This directly contradicts `acceptance.py:3-5` ("Gmail polling and browser reconciliation must remain inert until the transactional deploy has verified..."). The gate is inverted relative to intent: the loop that spends is ungated, while the operator who cannot spend is 503'd (A6).

**Fix:** wrap the drain in the same `wait_for_deployment_acceptance`, or start the task only when `deployment_mutations_allowed()`.

## A14 [STALL] Planner inference is an unmediated network seam inside `drive_run`

**Where:** `ops/onboarding/driver.py:2300-2304` → `ops/onboarding/composition.py:367-380` → `ops/planner/decide.py:385-393`. Both construction sites pass no chain — `composition.py:643` and `ops/runs/service.py:433` are `SettingsRunPlanner(settings)` — so `inference` is always `None` and `build_json_inference` builds one internally per call.

**Trigger:** any profile-mounted run whose settings carry any inference key.

**Consequence:** planning reaches a live vendor from a path the deployment cannot substitute, observe, or budget through `OnboardingPorts`. The e2e fixture replaces four outbound seams (research, decider, verification, validator); the planner is a fifth it cannot reach. Compounding: `decide_profile_plan` catches only `DecisionFailed`, while `ops/core/inference.py:371-377` lists `AssertionError`, `TypeError`, `AttributeError` as `_PROGRAMMING_ERRORS` re-raised at `:539-540` — such an exception escapes `plan_admission` and kills the walk instead of falling back to `profile_route_plan`.

**Evidence:** forcing the chain absent makes the failing e2e test pass with nothing else changed — `with ops.planner.decide.build_json_inference monkeypatched to return None: 1 passed in 0.38s`.

**Fix:** thread the composed chain in as `SettingsRunPlanner(settings, inference=...)` at both sites, and broaden both `decide_*_plan` functions to fall back on any backend exception, not only `DecisionFailed`.

## A15 [STALL] A crash between `reserve()` and `complete()` strands the effect key forever — no reaper, TTL, or reconciler exists

**Where:** `ops/core/effect_ledger.py:85-129`. A `pending` row falls through to `return EffectReservation(status="reconcile_required")` at `:128`. `plan_for_reservation` maps that to `disposition="reconcile"` (`ops/onboarding/effects.py:325-326`), and `ops/browser/signup.py:1777-1780` and `ops/gmail/worker.py:502-506` both refuse: pause, or `ProviderOperationError("reconciliation_required")`.

**Trigger:** process kill, container restart, or OOM between reserve and complete — the exact window the ledger exists for.

**Consequence:** permanent. Every later attempt, in this process and after restart, gets `reconcile_required`. Signup pauses with `outcome_unknown`; every subsequent outreach send under that key raises. Nothing ages the row out.

**Searches run, all negative:**

```
grep -rn "reap|sweep|stranded|stale_reservation|reservation_ttl|effect_ttl|expire" \
     --include='*.py' ops api            # zero effect-ledger hits
grep -rn "reconcile_completed_effect\(" ops api      # 0 production callers
grep -n  "updated_at" ops/core/effect_ledger.py      # written :121,:187,:258; never in a SELECT or WHERE
grep -rn "probe=" ops api    # only reconciliation.py:519 (a super().__init__ forward)
```

The one reconciler that would act on `reconcile` is `recover_run` / `recover_runs` (`driver.py:4830, 4997`) — zero callers outside `driver.py`. `EffectOutcomeProbe` is never wired, so `_settle_reserved_effects` always takes the `else` branch at `resume.py:1041`.

**Fix:** wire a read-only `EffectOutcomeProbe` into both control constructors and call `recover_runs` from the lifespan drain; add an age-based reconcile sweep over `external_effects.updated_at` that **probes** rather than resends.

## A16 [SILENT] The transactional reserve-with-commit path has no production caller, so every control's effect settlement settles nothing

**Where:** `SQLitePhaseHistoryStore.commit_phase_with_reservation` (`ops/onboarding/driver.py:601`) — the documented mechanism that couples the boundary commit to the reservation inside one `BEGIN IMMEDIATE` (`:625-640`) — has zero non-test callers. `drive_run` calls the plain `deps.phases.commit_phase(...)` at `:2475`.

**Consequence:** `phases.reservations(run_id=...)` always returns `()`. `_settle_reserved_effects` (`ops/runs/resume.py:1015-1058`, called at `:778`) iterates nothing and `PauseOutcome.settlements == ()` — "settle every in-flight submission before the run stops" is a no-op that reports success. `retry_current_step`'s ambiguity guard (`ops/runs/reconciliation.py:652`) never fires. `AutonomyOutcome.effects_skipped_as_duplicate` is permanently 0. The only effect state production writes is `external_effects` in a different file, which no control reads. Its absence also means production currently *has* the double-submission window the docstring says it closes.

**Fix:** use `commit_phase_with_reservation` in `drive_run` for `EFFECT_BEARING_PHASES`, and have handlers consume the returned `ReservedPhaseCommit.plan` instead of calling `plan_effect` against the second ledger.

## A17 [STALL] Corroboration is keyed on the raw URL string, so one page cited twice with a trailing slash fails the threshold

**Where:** `ops/providers/profile_builder.py:888-896` — `key = (field, value)` where `value` is `validate_https_url(claim.value)` with no canonicalization. The repo already owns the folding that fixes this: `ops.onboarding.effects._canonical`, reused by `plan.canonical_surface` (`plan.py:98-106`) precisely so "one URL yields one surface."

**Trigger:** two evidence documents linking the same login page, one as `/login` and one as `/login/` — the normal case, since `_extract_visible_text` preserves whatever the href said.

**Consequence:** one vote splits into two, each at 1 of the required 2 (`MIN_CORROBORATIONS = 2`, `:255`), `_REQUIRED_FIELDS` is unsatisfied, `build_profile` returns `ResearchInconclusive("research_no_evidence")`, and `_ResearchHandler` commits `blocked`. The run never reaches the vault, so run #2 has nothing to reuse.

**Evidence** (`.audit_work/out_a4.txt` PROOF 4a vs `.audit_work/out_a5.txt` CONTROL 4a) — the only difference between failure and success is the trailing slash:

```
/login vs /login/  -> research_no_evidence
   field_uncorroborated login_url corroborations=1/2   (twice)
byte-identical URLs -> ProviderProfile, login_url=https://www.acme.com/login
```

**Fix:** key on the folded identity — `support.setdefault((field, _canonical(value) if field in _URL_FIELDS else value), set())` — and carry the most-cited raw form as the stored value. Reuses the reviewed folder rather than adding a second implementation.

## A18 [STALL] `login_url` and `signup_url` are both hard-required regardless of the route chosen

**Where:** `ops/providers/profile_builder.py:262-264` — `_REQUIRED_FIELDS = {registrable_domain, signup_url, login_url}`, enforced at `:640-644`. `build_profile` takes no route or account-mode argument (`:432-449`).

**Consequence:** a create_account run must corroborate `login_url` twice; an existing_account run must corroborate `signup_url` twice. Providers that link only one of the two block on the field the run will never use, and the facts name a field it had no need for.

**Evidence** (`.audit_work/out_a4.txt` PROOF 4b): signup corroborated by two documents, no login link anywhere → `research_no_evidence`, `field_uncorroborated login_url required_field_missing`.

**Fix:** pass the admission route into `build_profile` and require `{registrable_domain} | {signup_url if create_account else login_url}` at 2, keeping the other at 1 when present. Note `_resolve_domain` (`:791-813`) only lets required fields vote on the registrable domain, so dropping a field from the required set must not drop it from the domain quorum.

## A19 [STALL] `vault_check` projects Pause and nothing else — no cancel, no reset

**Where:** `ops/onboarding/phase.py:149` — `frozenset({"route_selected_login","awaiting_admission","blocked"})`; controls at `api/service.py:1560,1562`.

**Consequence:** `"cancelled" ∉ targets` → `can_cancel=False`; neither `research` nor `paused` in targets → `can_reset=False`; not in `_RETRYABLE_STEP_FOR_PHASE` → `can_retry_step=False`. The operator cannot cancel or reset their own run. The only control is Pause, which moves it to `paused` where cancel and reset reappear — an undiscoverable two-step. `research` has the same gap for pause and cancel.

**Evidence** (`.audit_work/scratch2.txt`, run standing at `vault_check`): `reset: False  cancel: False  pause: True  retry: True`.

**Fix:** add `cancelled` to `vault_check`'s legal targets; every other non-terminal phase has it.

## A20 [SILENT] The pause request nobody reads

**Where:** `ops/runs/resume.py:793-802` and `:821`.

**Consequence:** pause reports `accepted=True` with `committed=False`, writes an `onboarding_pause_requested` audit row, and the run keeps driving — because **no production code calls `pause_requested`**. Searching returns only its own definition, its own docstring, and one assertion in `tests/test_onboarding_run_controls.py:205`. `drive_run` never consults it.

**Fix:** have `drive_run` call `deps.pause_requested(run_id)` at the top of each iteration and take the pause path.

## A21 [SILENT] `_profile_credential_surface` falls back to a page that mints nothing, and never reads `FlowSpec.produces`

**Where:** `ops/planner/decide.py:266-271`.

```python
for flow in profile.flows():
    if flow.supported and flow.entry_url is not None:      # 267-268
        return canonical_surface(flow.entry_url, purpose="credential")
fallback = profile.developer_portal_url or profile.login_url or profile.signup_url   # 270
return None if fallback is None else canonical_surface(fallback, purpose="credential")
```

`produces` is never consulted — not in the loop (the first *supported* flow wins regardless of what it mints) and not in the fallback, which ignores `supported` entirely.

**Trigger:** any Signup run whose research corroborated no flow entry URL. `profile_builder._flow` (`:965-980`) declares `supported=False, entry_url=None, produces=()` for every flow with no admitted claim, and a flow entry URL needs only 1 corroboration while not being a required field — so "no flow at all" is the common profile, not the exception. All 13 profile-mounted apps.

**Consequence:** the plan's `credential_surface` becomes the developer portal, or the login page, or the signup page, labelled `purpose="credential"`. `validate_profile_plan` accepts it (it checks only host/path membership and navigability, `validator.py:232-238`), it is persisted as the run's credential authority, and the run drives to it. Nothing mints there, so the credential phase burns its action-loop budget on a page with no key, and the capture path then refuses independently with `flow_entry_url_absent` (`ops/onboarding/capture_specs.py:171-172`) — a code describing the profile, not the plan that claimed otherwise.

**Corollary:** the `credential_surface_unprovable` refusal at `decide.py:379-384` is **unreachable for any committed profile** — `login_url` is in `_REQUIRED_FIELDS`, so a profile that exists always has one, so the fallback is never `None`. The planner cannot say "I have no credential route." 0 of 14.

**Evidence** (`.audit_work/out_a4.txt` PROOF 2): all four flows unsupported yields `PlannedSurface(host='developers.acme.com', path='/portal', purpose='credential')`; with no portal, `/login`; with only signup, `/signup`.

**Fix:** return the first flow with `flow.supported and flow.entry_url and flow.produces` matching the requested credential kind; if none, return `None` and let `decide_profile_plan` refuse with `credential_surface_unprovable` — which also restores that refusal to a reachable state.

## A22 [SILENT] `profile_success_digest` hashes the URL vocabulary, so a profile-driven run has no success predicate

**Where:** `ops/planner/plan.py:140-149`. Payload is `{app_slug, profile_digest, operational_urls}`. Compare `success_digest` (`:108-122`), which digests a real `SuccessPredicate` with `url_path_contains`, `title_contains`, `visible_text_contains`, `required_accessible_names`.

**Consequence:** the only consumer for a profile plan is the binding check at `validator.py:220`, i.e. it proves *which profile the plan came from* and nothing about the page. A run cannot detect "I reached the credential surface" from its plan; success is decided only by `PHASE_POSTCONDITIONS` in the action loop, a per-phase classification rather than a per-surface predicate. Concretely, arrival on A21's fallback surface is indistinguishable from arrival on a real key page — the digest changes if a URL changes, and does not change if the page stops minting.

**Evidence** (`.audit_work/out_a4.txt` PROOF 3): recomputing sha256 over the URL list alone reproduces the digest exactly.

**Fix:** rename it `profile_route_digest` and stop treating the `success_digest` column as a success authority for profile-sourced plans, or derive a real predicate — `url_path_contains = (credential_surface.path,)` plus the profile's corroborated flow-page heading.

## A23 [SILENT] The response-size cap drops a whole document instead of truncating it

**Where:** `ops/research/operational_research.py:314` and `:320` raise at 256 KiB; `ops/onboarding/runtime.py:93-96` catches `ValueError` and `continue`s.

**Trigger:** any provider whose API-reference page exceeds 256 KiB — routine for single-page reference docs, which are exactly the pages carrying login and signup links.

**Consequence:** the document silently disappears from the candidate set. `MAX_EXCERPT_CHARACTERS` is 24,000, so at most 24 KB of that page was ever going to be used: the cap discards a document whose usable part was well within bounds. With only 2 to 7 fetchable candidates per app, losing one usually drops a required field below 2 and the run blocks with `research_no_evidence`, which reads as "the provider documents nothing." No fact records the drop, so the exclusion is unattributable.

**Evidence** (`.audit_work/out_a4.txt` PROOF 4c): real `OfficialEvidenceFetcher`, two URLs requested, one oversized → `got 1`.

**Fix, without weakening the guard:** keep the 256 KiB read ceiling and keep refusing an oversized declared content-length elsewhere. On the evidence path only, stop reading at the ceiling and return the excerpt built from what was read, plus a `ResearchFact("candidate_truncated", …)`. SSRF and redirect checks untouched; the difference is truncate versus discard.

## A24 [SILENT] Writer and reader derive different account keys; reuse survives only via a fallback that ignores the key

**Where:** writer `ops/browser/account_binding.py:52-59` (`acct_` HMAC) at call site `ops/workflow/canonical_runtime.py:792-801`; reader fallback branch `account_binding.py:64-67` (`run_` sha256) at the same site; rescue `ops/core/secret_store.py:1291` invoked at `canonical_runtime.py:818`.

`BrowserLoginInput` is only email plus password (`api/models.py:229-230`), so run #1 always has exactly one identity and gets `acct_`; run #2 has none and gets a fresh `run_` per run.

**Evidence** (`.audit_work/reuse_out.txt`):

```
run1 account_ref = acct_c363977427e8f0fdd54b4e171ba8959e
run2 DERIVED     = run_fa06f690de7c58f99869771dff0459a2
run2 direct read at derived ref: {} <-- MISS
run2 fallback lookup HIT: account_ref=acct_c363977...
```

**Consequence:** run #2 self-heals via the app-wide `get_unique_account_login_pair` scan, so no orphan is created on the static path — but this is why that scan is load-bearing and why A25's ambiguity poison exists at all.

**Latent, not live:** two further derivers write the same key space — `ops/runs/creation.py:437-439` via `graph_state_updates.py:30-40` (`acct_{sha256(work_email_ref)}`, no app, no login identity) and `ops/runs/resume.py:204` (`account_ref=run_id` raw). Both unreachable today: `ops/runs/service.py:1528-1532` forces `browser_login=None` into legacy creation and `:1864-1870` refuses legacy resume.

**Fix:** persist the resolved `account_ref` as a first-class run input so the reader re-derives the writer's key.

## A25 [SILENT] `stored_login_account_ambiguous` is permanent, with no operator remedy

**Where:** `ops/core/secret_store.py:1332` raises it; consumed at `canonical_runtime.py:978-982` and `:626-641`.

**Trigger:** both mundane. Two operator identities for one app across runs; or a signup run (binds `acct_hmac(app, gmail_signup_address)`, `canonical_runtime.py:786-791`) plus an existing-account run for the same app (binds `acct_hmac(app, owner_email)`).

**Consequence:** every later run without submitted credentials goes to `configuration_required / phase="login_account_selection"`. `delete_account_login` (`secret_store.py:1593`) has exactly one caller in the repo — a test (`tests/test_autonomous_login_reuse.py:124`). No route, no CLI. Only hand-editing SQLite clears it.

**Evidence** (`.audit_work/reuse_out.txt` scenario B): two complete durable accounts for `pipedrive` → `run3 fallback lookup RAISED: stored_login_account_ambiguous`.

**Fix:** an owner endpoint listing bindings **by reference only** — `account_login_references` (`secret_store.py:1554`) is already value-free — to select or forget one, persisting the chosen `account_ref`.

## A26 [SILENT] The 7 `entry_only` apps never promote credentials, so they re-prompt forever

**Where:** `ops/workflow/canonical_runtime.py:2139` requires `observation.status == "credential_page_ready"`, whereas the signup branch accepts both statuses at `:2084-2087`. `ops/playwright/worker.py:980-993` returns `developer_console_ready` for `scope == "entry_only"`, never `credential_page_ready`.

**Consequence:** the staged pair stays `status='pending'`, no `account_login_*` row is written, and run #2 prompts again. Compounds with A10, since `canonical_runtime.py:1766-1785` sends these apps to `phase="entry_reached" / owner_credential_submission_available` — the path that 403s.

**Evidence** (`.audit_work/scope_out.txt`): the 7 `entry_only` apps are exactly the 7 `capture.mode=="owner_submit"` apps, and their `success` predicates are bare URL-path checks **on the login page itself** — klaviyo `/login`, shopify `/store-login`, dataforseo `/login`, xero `/identity/user/login`, bright-data `/cp/start`, telegram `/`, neo4j `/`.

**Fix:** the `:2139` gate is correct — the comment at `:2141-2145` is right that a public entry page is not authentication evidence. Fix the **catalog**: give those 7 a post-authentication success predicate. This is a data-completeness ceiling, not a code bug.

## A27 [SILENT] Mounted runs get a fresh run-scoped binding because `GMAIL_SIGNUP_ADDRESS` ships empty

**Where:** `canonical_runtime.py:786-791` sets the binding only when `gmail_signup_address is not None`; the reader `ops/onboarding/runtime.py:361` → `admission.py:232` → `probe_login_refs` (`:219-243`) is **exact-ref with no app-wide fallback**. `api/models.py:317` forbids `browser_login` on `create_account`, so with no configured address there is no identity at all. The readiness check that would catch it (`canonical_runtime.py:748-752`, `gmail_signup_address_not_configured`) sits inside `if executable_signup and not profile_onboarding:` — skipped for exactly the mounted path.

**Evidence** (`.audit_work/mounted_out.txt`):

```
configured:      run1 acct_1ac95746…  run2 acct_1ac95746…  identical: True   credentials_present=True
shipped default: run1 run_acda0985…   run2 run_96bb4f3d…   identical: False  credentials_missing
```

`.env.example:26` and `.env.production.example:120` both ship it empty; `ops/core/config.py:156` defaults `None`.

**Fix:** apply the same readiness check to the `profile_onboarding` branch so creation fails closed, or derive the mounted binding from `work_email_ref` plus `app_slug` under the vault-key HMAC.

## A28 [LATENT] A captured API key is written to the vault but unreadable by any later run — goal step 5 unmet

**Where:** `ops/playwright/worker.py:2477-2481` calls `store.put(app_slug, kind=field_kind, value=raw_value)`; `ops/core/secret_store.py:316-333` (`put`) is INSERT-only with a random id and NULL `account_ref`, and `:1875-1892` (`get`) resolves only an exact `vault://app/kind/id`.

**Consequence:** no `(app_slug, kind)` reader exists — `grep -rn "existing_credential|already_captured|reuse_credential|latest_credential|credential_refs_for_app" ops api` returns zero hits. The reference survives only in that run's `IntegratorBundle`, so run #2 for `firecrawl` re-drives the whole flow and writes a duplicate row. "Credentials and the app's API key are captured into the vault, so the next run reuses them" is unmet for the API key specifically.

**Precisely what is missing for step 5:** (a) this cross-run reader; (b) `capture.mode=="automatic"` on only 7 of 50 recipes, the rest depending on owner submission which production 403s (A10); (c) the mounted path — 49 of 50 apps for create_account — cannot reach `credential_generation` at all (A2).

**Fix:** a narrow reference-only `latest_active_credential_reference(app_slug, kind)` over `one_time=0 AND credential_status='active'`, mirroring `account_login_references`, consulted before reserving the capture effect.

## A29 [SILENT] The mounted projection bypasses the status validator and does a non-atomic read-modify-write

**Where:** `ops/onboarding/runtime.py:539-569` — `get_run` at `:550`, then a separate `update_run(..., state_revision=int(record.get("state_revision",0))+1)` at `:556-568`. `_block_main_run` repeats it at `:578`/`:598`. `ops/core/storage.py:1897-1974` issues `UPDATE runs SET ... WHERE run_id = ?` with no status validation and no revision predicate.

**Trigger:** two concurrent `advance()` calls — the drain tick (`api/service.py:677`) racing the resume endpoint (`:1887`) or the decision endpoint (`:2247`); or a mounted projection racing a *fenced* writer such as `pause_stale_run` (`canonical_runtime.py:2410-2415`).

**Consequence:** two projectors each read revision *N* and write *N+1*, so one boundary's revision is lost and `last_projected_revision` stops distinguishing them. Separately an unvalidated status write can cross an edge `ops/core/state.py:126` forbids — the mounted path is the only projector skipping the check that `resume.py:1136` and `state_projection.py:126` both apply. The sequence fence at `:551-552` stops a replay; it does nothing about a concurrent RMW on a different column.

**Evidence:** a probe writes `completed → researching` unopposed, and two reads of revision 7 both write 8. `validate_status_transition` and `unit_of_work` are both absent from `runtime.py`.

**Fix:** do the read and write inside `storage.unit_of_work()`, add `WHERE state_revision = ?`, and route the status through `validate_status_transition`.

## A30 [SILENT] A legacy sweep writes a non-vocabulary phase into a mounted run row and silently unmounts it

**Where:** `ops/runs/reconciliation.py:313-317` — `transaction.update_run(run_id, status="configuration_required", phase="session_lost", ...)`; selectors at `ops/onboarding/runtime.py:626-641` and `ops/core/storage.py:2009`.

**Trigger:** a mounted run whose row status is `browser_running` sits idle past `max(600, browser_use_task_timeout_seconds * 4)`; `reconcile_idle_browser_runs` claims it.

**Consequence:** `"session_lost"` is not an `OnboardingPhase`. It goes straight into the row with no boundary and no phase-authority check, after which `_is_mounted_request` is `False` and the sweep skips the run forever — silently unmounted while its phase history still reads `developer_app`.

**Evidence** (`.audit_work/scratch4.txt`):

```
'session_lost' is an OnboardingPhase: False
ROW after the legacy sweep: session_lost configuration_required idle_browser_run_reconciled
mounted claim: False   swept: False
```

**Fix:** select mounted work from the durable phase (`onboarding_phase_history`) rather than `runs.phase`, and stop letting the legacy reconciler write `runs.phase` for `execution_path='profile_mounted'` rows.

## A31 [SILENT] Backend admission does not gate `create_account` on the preconditions the UI checks

**Where:** the boundary is `ApiRunService._decision_sync` (`api/service.py:1671-1751`) → `ops/onboarding/admission.py:decide_from_operator:313-343`. Its only refusals are profile-digest mismatch (`:1696`), replay or cancel-over-approved-signup (`:1709-1725`), and `phase != "awaiting_admission"` (`:1726-1735`). Then `decide_from_operator` mints `route="signup"` unconditionally.

**What the UI checks and the backend does not** (`web/src/components/new-run-form.tsx:463-489`): app present in the verified catalog, capabilities resolved, `accountCreationSupported`, and for non-plan-only runs `gmailSignupReadiness(...).ready`.

**Trigger:** `POST /runs/{id}/decision` with `{"decision":"create_account"}` from anything that is not that form — curl, a stale tab, the CLI.

**Consequence:** the run is authorized for signup with no Gmail signup inbox, no catalog eligibility, and no browser readiness. Creation-time readiness does not cover it either: `canonical_runtime.py:735-780` is guarded by `if executable_signup and not profile_onboarding:`, so the autonomous mounted path skips all of it.

**Fix:** re-evaluate the same four preconditions inside `_decision_sync` before `decide_from_operator`, refusing with the existing `PhaseUnavailableError` and reason code.

## A32 [SILENT] `PlanRefusal.detail` and `ordinal` are never persisted, so all 19 refusal causes look identical

**Where:** `ops/planner/validator.py:31-46` defines the details; `grep -rn '\.detail\b' ops api | grep -i 'refus\|plan'` returns **nothing**. Every consumer reads only `reason_code`: `runtime.py:327-333`, `driver.py:2452-2458`, `canonical_runtime.py:1131-1136`. And `reason_code` is the single constant `plan_surface_not_in_catalog` (`validator.py:28`).

**Consequence:** a run blocks or pauses with one code, and nothing distinguishes "the recipe declares no credential URL" from "the model picked an undeclared path" from "the profile binding drifted." This is what makes A1's mislabelling unrecoverable in practice: the correct information exists on the value and is discarded at every write.

**Fix:** write `detail` and `ordinal` into the audit event beside the boundary. Both are closed data by construction — no provider string, no URL — so this adds no redaction surface.

## A33 [SILENT] `ProfileResearchPorts.fetcher` and `.extractor` are unconditionally `None`, so the research-unavailable signal is always set and never true

**Where:** `ops/onboarding/composition.py:395-415` (both default `None`), `:661-677` (the single construction site passes only `discovery`), `:617-618` (`if not research.is_complete: unavailable["research"] = RESEARCH_UNAVAILABLE`). `is_complete` requires all three, so it is `False` in every production composition.

**Consequence:** two things at once. `unavailable["research"]` is permanently present, so it carries no information — an operator cannot distinguish a genuinely unconfigured deployment from a working one. And the `is_complete` guard is inert, because `MountedOnboardingRuntime.advance` never reads `self._ports.research`: it builds its own `_RequestedOfficialFetcher` (`runtime.py:466-472`) and `_InferenceProfileExtractor` (`:498`) inline. The "honest degradation" the dataclass docstring describes is unreachable, and the two fields are dead with a docstring explaining a decision no code implements.

**Fix:** bind the runtime's own fetcher and extractor construction into `_research_ports` so `is_complete` means something, or delete the two fields and report availability from `discovery` alone.

## A34 [SILENT] A missing P1 record and an unreadable snapshot report the same wrong cause, and a snapshot integrity failure escapes uncaught

**Where:** `ops/onboarding/runtime.py:459-467`. Both `RecipeSnapshotError` and `not isinstance(lookup, P1LookupFound)` call `_block_main_run(run_id, "research_adapters_unavailable")`, and `_block_main_run` additionally writes `route_reason_code="profile_research_inconclusive"` with the explanation "Profile research stopped without enough corroborated route evidence."

**Consequence:** neither statement is true — no adapter was constructed and no document was fetched. Two distinct pre-walk failures are indistinguishable, and the explanation points at research configuration instead of the snapshot. The function's own docstring names the real cause while the code reports something else.

**Also:** `lookup_p1_record` → `load_verified_snapshot` raises `SnapshotIntegrityError` (a bare `RuntimeError`, `ops/research/p1_adapter.py:45,170-257`) on hash mismatch, oversize, symlink, or duplicate key. Line 465 is unguarded. `api/service.py:677` catches `Exception` but the `for` loop is inside the `try` (A5), so one corrupt snapshot aborts the whole drain cycle. `api/service.py:1887` (decide_admission, immediately after the operator approves signup) and `:2246` (create_run) are **unguarded**: a 500 surfaces, and in the create case the row is already persisted with no boundary, so it has no `blocked` transition and no controls.

**Evidence:** static, read at the cited lines. All 14 catalog slugs resolve today (`.audit_work/out_a3.txt`: `P1 missing: 0/14`), so this is reachable for unknown providers and for a tampered snapshot. UNVERIFIED: the 500 was not observed, because that requires writing to a tracked file.

**Fix:** add `snapshot_unavailable` and `provider_not_in_snapshot` reason codes and report them separately; wrap line 465 in `except SnapshotIntegrityError`; set `route_explanation` per cause.

## A35 [SILENT] Swallowed exceptions on the maintenance path

`ops/runs/advance.py:111,116,120,124` — four `except Exception: pass` with **no log line at all**. A persistent failure in `advance_autonomous_runs`, `reconcile_idle_browser_runs`, or `mark_stale_runs` is invisible forever. `ops/runs/liveness.py:85` (`except Exception: continue`, per-run) is benign. `ops/onboarding/runtime.py:95` (`except (httpx.HTTPError, OSError, ValueError): continue`) drops an evidence document silently and is the feeder for A3, A11 and A23: a transient fetch error is indistinguishable from "the provider published nothing."

**Fix:** log with the run id at each site; add a `ResearchFact` for the dropped candidate.

## A36 [SILENT] Headless Chromium inherits the parent `DISPLAY` — the `headless` argument is dead

**Where:** `ops/browser/process_hardening.py:75-91` — `chromium_launch_environment(display, *, headless)` never references `headless`; `:79-81` does `target_display = display or os.environ.get("DISPLAY")` unconditionally. The caller `ops/playwright/worker.py:430-443` documents the opposite: "headless Chromium receives no `DISPLAY` at all."

**Consequence:** a launch believed headless renders to the parent X server, so headed/headless is not an isolation boundary, and any future policy hung on the flag silently does nothing. Inert in the production container, which has no `DISPLAY`.

**Evidence** — one of the nine real failures:

```
tests/test_playwright_worker.py:141: assert headless == safe_environment
Left contains 1 more item: {'DISPLAY': ':77'}
```

**Fix:** `target_display = display if display else (None if headless else os.environ.get("DISPLAY"))`.

## A37 [LATENT] `profile_authority=True` widens the reviewed allow-list for the 14 slugs that have a narrower recipe

**Where:** `ops/browser/host_policy.py:276-279` — the new branch skips `browser_policy_from_recipe`/`get_browser_policy` entirely; `ops/providers/profile.py:253-262` passes the flag.

**Consequence:** the run gets `*.<registrable-domain>` plus apex from the profile instead of the recipe's exact host tuple. For klaviyo the reviewed policy is `('www.klaviyo.com',)` and the profile yields `('klaviyo.com','*.klaviyo.com')`, which admits `marketing.klaviyo.com`. A reviewed boundary is silently widened, and nothing records which authority served the list. Also makes `driver.py:2280-2281` (`selected_recipe = _catalog_recipe(profile.app_slug)`) dead code, so a mounted run for a recipe-backed slug is never validated against its recipe.

**Evidence** (`.audit_work/out_a5.txt` and `out_test6.txt`):

```
reviewed exact_hosts: ('www.klaviyo.com',)
profile patterns:     ('klaviyo.com', '*.klaviyo.com')
   https://marketing.klaviyo.com/x -> True
tests/test_provider_profile.py:530: Failed: DID NOT RAISE BrowserPolicyInactiveError
```

**Attribution:** this test **passes at HEAD**. The working-tree change introduced the widening. The reason code the test asserts, `reviewed_browser_policy_supersedes_profile`, exists nowhere in the tree.

**Both readings are load-bearing and they contradict each other**, which is why the test fails rather than being merely stale. Honoured literally, `allowed_hosts()` raises and `validate_profile_plan` returns `navigation_denied` for all 13 mounted Signup apps.

**Fix:** **intersect**, do not replace. Keep serving the profile allow-list but narrow it by the reviewed recipe's `exact_hosts` when `get_browser_policy(app_slug)` is active, so a profile can only narrow a reviewed policy. Then rewrite the test to assert the intersection and add the missing reason code for an empty result. Refusing outright blocks 13 of 14 and should not be chosen.

## A38 [LATENT] Port identity is dropped at three sites

**Where:** all three confirmed. `ops/research/operational_research.py:355-364` rebuilds every link as `urlunsplit(("https", parsed.hostname or "", ...))` — `hostname` excludes the port. `ops/planner/plan.py:98-106` stores `host` and `path` only; `PlannedSurface` has no port field. `ops/browser/host_policy.py:396-424` folds `parsed.hostname` and never reads `parsed.port`.

**Consequence, both directions honestly.** *Safety:* the port is erased before any check, so a claim is minted for a URL no document contained; `_literal_route_claims` then attributes the port-stripped URL to that document, and `_verified_claims` passes because it re-checks against the already-rewritten excerpt. *Autonomy:* this erasure is the only reason such a link is usable at all — `sanitize_candidate` refuses `port not in (None, 443)` (`operational_research.py:216-217`), so preserving the port makes these links unfetchable. So the current behaviour is a silent authority substitution, not a convenience.

**Evidence** (`.audit_work/out_a4.txt` PROOF 6):

```
canonical_surface('https://www.acme.com:8443/signup') -> host='www.acme.com', path='/signup'
evaluate_navigation(:8443) allowed = True
_extract_visible_text rebuilt link -> https://www.acme.com/signup
literal claims: [('signup_url','https://www.acme.com/signup'), ...]
```

`tests/test_provider_profile.py:471-480` bakes the same blindness into a passing test.

**Fix:** rewrite the link with `parsed.netloc` rather than `parsed.hostname`, so a non-standard port survives into the excerpt and is refused by the existing port check at the fetch boundary rather than laundered. Separately, have `evaluate_navigation` refuse `parsed.port not in (None, 443)`.

## A39 [LATENT] A post-click `failed` classification re-opens the ledger row, authorizing a second signup

**Where:** `ops/browser/signup.py:815`, `:1034`, `:1260` return `status="failed", reason_code="signup_submit_outcome_unknown"` from the `except` around `await submit.click(...)` — after the click was dispatched. `:558` returns `signup_navigation_blocked` from `_classify_after_submit`, i.e. after submission. `:1852-1853` maps any `failed` to `mark_effect_failed` with the comment "Provably did not reach the provider." `ops/core/effect_ledger.py:117-125` then re-opens a `failed` row to `pending` and returns `reserved`.

**Consequence:** the next arrival at the same operation key gets `disposition="execute"` and submits the form again — a second account, which `SignupSubmission`'s own docstring (`:1428-1431`) says `failed` must never mean. The reason code literally says `outcome_unknown` while the ledger transition says `failed`.

**Why LATENT:** no production adapter implements `SignupSubmitter`, and the mounted runtime never dispatches the signup handler (A2). It goes live the moment that handler is wired.

**Fix:** in `_step_for`, map only pre-submit failures to `mark_effect_failed`; route `signup_submit_outcome_unknown` and `signup_navigation_blocked` to `mark_effect_outcome_unknown`. The email path already gets this right (`ops/gmail/worker.py:509-518`).

## A40 [LATENT] `pause()` poisons every in-flight effect to an unresolvable state, and no control clears it

**Where:** `_settle_reserved_effects` (`ops/runs/resume.py:1015-1058`) marks every reservation whose disposition is in `{"execute","reconcile"}` as `pause_outcome_unknown`, because `self._probe is None` in every production wiring. `retry_current_step` then refuses outright (`reconciliation.py:652-655`), and `reset_run` never touches reservations.

**Trigger:** the operator presses Pause while an effect is reserved. Settlement runs at `resume.py:778`, *before* the boundary is attempted, so it happens even when the phase table refuses the `paused` edge — `research` and `vault_check` have no such edge, so the run keeps its drivable phase and gets poisoned anyway.

**Consequence:** `retry_current_step` refused forever, `reset_run` also refused from `vault_check` (`phase_replay_noop`), `submission_count` pinned at 1 so the key can never execute again. The run has no control that can move it.

**Why LATENT:** requires a reservation row, which nothing writes today (A16).

**Fix:** wire the probe, or refuse the pause when an in-flight reservation exists rather than poisoning it, and give `reset_run` a path that re-opens `pause_outcome_unknown` after an explicit operator attestation.

## A41 [LATENT] The lease is renewed only between steps, and `commit_phase` carries no fencing token

**Where:** `LEASE_TTL = 60` and `LEASE_RENEW_INTERVAL = 20` (`ops/onboarding/lease.py:75,81`). Acquired once at `driver.py:2377`; renewed only inside `LeaseGuard.before_step()` (`:1244-1284`), which `drive_run` calls once per loop iteration at `:2413`. No renewal anywhere inside `_drive_phase` (`:5064-5100`). `commit_phase` (`:491-524`) takes no fencing token or lease argument.

**Trigger:** one `research` step — `httpx` fetches at 10s each plus an inference call — exceeding 60s. `plan_admission`'s inference call sits in the same unrenewed window.

**Consequence traced:** the lease expires mid-step; `_CLAIM_SQL`'s `OR deadline < ?` (`lease_store.py:81-92`) lets worker B claim with `fencing_token + 1`. Worker A finishes and commits anyway. Both drive the same phase. Because the boundary key is `UNIQUE (run_id, from_phase, to_phase, attempt, correlation_id)` and `correlation_id` is deterministic, the second commit is discarded as a replay — **including its `profile_digest`**. The loser keeps driving under its own in-memory profile while history records the winner's digest. Every effect key derives from the in-memory digest (`signup.py:1756` → `signup_submit_key`) while a later worker reloads it from history (`driver.py:2394`). Two digests for one run means two `signup_submit` keys, and the ledger cannot collide them — two accounts.

Separately, with different *targets* neither uniqueness constraint rejects the second commit, so `resumption_phase` takes the later row and `is_duplicate_account_reroute(history[-1])` reads `False` — so `adopt_signup_references_for_login` (`:2441`) never runs and duplicate-account recovery degrades to a credential prompt.

**Evidence** (`.audit_work/scratch2.txt`): injected clock at +90s, B claims with `token+1`, A's next `before_step()` returns `fenced`, A's `release()` is a no-op. And:

```
A committed: True  B committed: True
WALK: [... (6,'signup','route_selected_login','signup_rejected_duplicate_account'),
           (7,'signup','email_verification','signup_submitted')]
resumption_phase: ('email_verification', 0)
reroute armed from history tail: False
```

**Fix:** renew inside long steps (pass the guard into `_drive_phase` and renew around each network and inference call), and add the fencing token to `commit_phase` with a `WHERE fencing_token = ?` predicate.

## A42 [LATENT] `vault_storage` and `credential_validation` have neither a handler nor a loop goal

**Where:** `ops/onboarding/driver.py:1493-1500` — `PHASE_SUCCESSORS` maps `credential_generation → vault_storage`, and `vault_storage` is not a key. Neither phase is in the handler map, `PHASE_SUCCESSORS`, or `SESSION_BEARING_PHASES`. `:5091` raises `PhaseNotDrivable(phase, "no handler is registered and no loop goal is declared")`.

**Consequence:** the same poison as A5, arriving at the last two phases before `completed`. A run that successfully generates a credential cannot store or validate it.

**Evidence** (`.audit_work/scratch1.txt`):

```
vault_storage in PHASE_SUCCESSORS: False
credential_validation in PHASE_SUCCESSORS: False
RAISED: phase 'vault_storage' is not drivable: no handler is registered and no loop goal is declared
still swept (poison, oldest updated_at first): ('run_4e91...',)
```

**Fix:** register the credential-lifecycle handlers. `ops/onboarding/credentials.py:950` already produces `CredentialStep.advance("completed", "credential_valid")`.

## A43 [LATENT] `OperationsStorage.create_run` silently drops `execution_path`

**Where:** `ops/core/storage.py:1681` declares `execution_path: str = "legacy_static"`; the forwarding block to `_create_run` at `:1697-1728` omits it. The unit-of-work wrapper does forward it (`:1142,1185`).

**Consequence:** a caller outside `unit_of_work()` asking for `profile_mounted` gets a `legacy_static` row, so `stranded_mounted_run_ids` and `_is_mounted_request` both skip it forever — an autonomous run never driven, showing no error. Latent because production goes through `transaction.create_run`.

**Fix:** add `execution_path=execution_path` to the forwarding call.

## A44 [LATENT] Six SQLite files, three hold effect state, controls settle exactly one

`private/ops.db`, `checkpoints.db`, `secret_vault.db`, `provider_effects.db`, `research_cache.db` (`ops/core/config.py:269,484-487`) and `provider_profiles.db` (`api/service.py:1420`).

| file | table | writer | settled by controls? |
|---|---|---|---|
| `ops.db` | `onboarding_effect_reservations` | `commit_phase_with_reservation` — **no production caller** | yes, and therefore nothing |
| `provider_effects.db` | `external_effects` | `signup.py:1765`, `gmail/worker.py:493`, `composio_managed_auth.py` | **no** |
| `ops.db` | `side_effect_intents` | `canonical_runtime.update_side_effect:1944` | **no** |

`_control` (`ops/runs/service.py:358-365`) and `_run_controls` (`api/service.py:1447-1457`) both wire `effects=` to the phase-history store over `storage.db_path` only. `reset_run` additionally passes `workflow=None` (`:1454`), so `checkpoints.db` is never cleared and reset honestly reports `workflow_state_cleared=False`.

**Fix:** land A16 first, then have the controls settle `external_effects` through the probe from A15.

## A45 — UI truth defects on the stopped-run path

One structural cause: `_onboarding_controls` (`api/service.py:1546-1585`) derives every control from **`state.phase` alone**, and `reason_code` is copied through to be rendered as display text only (`hitl-live-controls.tsx:319`). So ~38 distinct pause reason codes collapse onto one control set. The vocabulary is closed and rich (`ops/onboarding/phase.py:196-330`); the projection discards all of it.

| # | Sev | Claim | Where | Consequence |
|---|---|---|---|---|
| a | SILENT | Progress rail cannot represent a stopped run | `web/src/components/run-progress.tsx:11-16,47,49` | `TERMINAL_STATUSES` excludes `waiting_for_hitl`, so a paused run renders `LoaderCircle animate-spin`, the badge reads "Auto-updating every 4s", and `router.refresh()` fires every 4s **forever** on a run that will never advance. The headline signal says working; the run is dead. |
| b | SILENT | Rail branches on the client's `account_mode`, not the resolved route | `run-progress.tsx:51-57`, `api/service.py:708-713` | `_summary` falls back to `stored_request["account_mode"]` — the request echo. A `create_account` run that finds credentials and routes to login is labelled "Create account · Verify email" while the agent signs in. Exactly the class the brief flags; `_primary_action:745` and `_phases:1128` both use `execution_path` correctly with a comment saying so. This one surface was missed. |
| c | SILENT | Every mounted run renders "No action available … read-only legacy adapter" | `api/service.py:745-758`, `canonical-primary-action.tsx:57-60` | `_primary_action` short-circuits to `kind="none"` for *all* mounted runs, and the copy names the legacy adapter. The flagship autonomous path is narrated as a legacy read-only run, with a permanently disabled button, directly above a control bar offering real controls. |
| d | SILENT | Capability panel hardcodes the adapter-gap message for every mounted run | `api/service.py:1147-1170` | `status` correctly special-cases `browser_adapter_unavailable`, but `detail` is unconditional. A healthy mounted run at `credential_generation` shows `status: ready` beside text saying the deployment cannot run browser effects, with `available=False`. |
| e | SILENT | "The agent is driving this session" with no session | `hitl-live-controls.tsx:229-232`, `page.tsx:77-82`, `api/browser_ui.py:203-204` | `_lifecycle` maps `waiting_for_hitl` → `human_action_required` without consulting session existence, so `hasBrowserSession` is true for a run whose factory never created one. The live surface then polls `openLiveView` every 3s and the run detail every 5s for a session that does not exist. |
| f | SILENT | HITL panel says "no human action request" while the header says Waiting for HITL | `api/service.py:1328-1332`, `run-detail-panels.tsx:209-211` | `_hitl_view` requires `record["hitl_request"]`; a phase-machine pause writes a boundary, not that payload. Same response renders both statements. |
| g | SILENT | 403 "local credential submission is disabled" renders as "The credential could not be submitted" | `web/src/app/runs/[runId]/actions.ts:576-578` | A hard server policy refusal is indistinguishable from a rejected token, so the operator retypes the credential. `submitBrowserLoginAction` in the *same file* (`:526-529`) does it correctly — the pattern exists and was not applied. |
| h | SILENT | A successful vault write is announced as an error | `actions.ts:565-570` | `tone: status === "completed" ? "neutral" : "error"` with `role="alert"`, so "Credential stored. Run status: credentials ready." is read out as a failure and may be resubmitted. |
| i | LATENT | The autonomy verdict is projected, typed, parsed, and rendered nowhere | `api/service.py:1972`, `api-schemas.ts:400-408`, `types.ts:332-340` | The single measurement of the stated goal — did this run complete without a human — is fetched over the wire and discarded. `grep -rn 'autonomy' web/src` → 9 hits, all in schemas/types/tests, **zero** in `app/` or `components/`. |
| j | LATENT | `paused` renders no per-control reason for the missing resume | `api/service.py:1569-1572`, `hitl-live-controls.tsx:216-234` | `_withheld_resume_reason` is consulted only for `captcha_paused`, so the resume button is silently absent. `control_withheld` exists in the vocabulary as "the total fallback … so a paused page always says why" and is unreachable from `paused`. |

**Negative result worth recording:** no case was found where the onboarding console offers a control the backend refuses. `can_reset`, `can_resume` and `can_retry_step` all match their handlers. The projection is genuinely capability-first. One legacy caveat: `isRetryable()` (`page.tsx:425-427`) infers retryability client-side from phase status strings instead of the backend `retryable` flag — harmless only because that surface is unreachable (cluster B3).

---

# Reference tables

## Phase transition graph, as derived

From `ops/onboarding/phase.py:161-200`, `:71-95`, and `ops/onboarding/driver.py:1493-1523`.

| phase | status | outbound targets | forward targets | driver treatment |
|---|---|---|---|---|
| research | researching | blocked, cancelled, vault_check | vault_check | handler; **blocked branch raises** (A3) |
| vault_check | researching | awaiting_admission, blocked, route_selected_login | both | handler; **no paused/cancelled edge** (A19) |
| awaiting_admission | waiting_for_hitl | cancelled, paused, route_selected_signup | route_selected_signup | handler, defers 300s |
| route_selected_login | route_selected | authenticated, cancelled, captcha_paused, paused | authenticated | **mounted handler pauses** (A2) |
| route_selected_signup | route_selected | cancelled, paused, signup | signup | handler, advances unconditionally |
| signup | browser_running | cancelled, captcha_paused, email_verification, paused, route_selected_login | email_verification, route_selected_login | **mounted handler pauses** (A2) |
| email_verification | browser_running | authenticated, cancelled, captcha_paused, paused | authenticated | mailbox path unwired → loop → missing factory |
| authenticated | browser_running | cancelled, captcha_paused, developer_app, paused | developer_app | loop |
| developer_app | browser_running | cancelled, captcha_paused, credential_generation, paused | credential_generation | effect-bearing, loop |
| credential_generation | browser_running | cancelled, captcha_paused, paused, vault_storage | vault_storage | effect-bearing, loop |
| vault_storage | browser_running | cancelled, credential_validation, paused | credential_validation | **no handler, no goal → raises** (A42) |
| credential_validation | browser_running | cancelled, completed, credential_generation, paused | completed, credential_generation | **no handler, no goal → raises** (A42) |
| captcha_paused | waiting_for_hitl | 8 phases | all | woken only by `sweep_onboarding_takeover`, and only while `runs.phase` literally reads `captcha_paused` |
| completed | completed | — | — | terminal |
| paused | waiting_for_hitl | cancelled, research | research | **no resume possible** (A8) |
| blocked | blocked | — | — | terminal; **no control can leave it** (A7) |
| cancelled | blocked | — | — | terminal |

Enter-but-cannot-leave-without-a-human: `awaiting_admission` (by design), `paused`, `captcha_paused`. No outbound edge: `completed`, `blocked`, `cancelled`. Waiting phases nothing wakes: `paused` for mounted runs, since it is outside the drain's phase set and `resolve_gate(None)` → `human_only` in the autonomous sweep.

## The literal phase → handler map

`ops/onboarding/runtime.py:499-512`, the only production wiring. Dynamic dispatch by string key, so plain grep misses it.

| key | handler | site | can return FORWARD? |
|---|---|---|---|
| research | `_ResearchHandler` | `:300` | yes → `vault_check`; blocked branch at `:325` raises |
| vault_check | `_VaultHandler` | `:341` | yes → `route_selected_login` \| `awaiting_admission`; blocks at `:356/:359/:363` |
| awaiting_admission | `_AdmissionHandler` | `:381` | yes → 3 targets; `defer(300s)` with no decision |
| route_selected_signup | `_SelectSignupHandler` | `:405` | yes → `signup`, unconditionally |
| route_selected_login | `_UnavailableBrowserHandler` | `:419` | **no — `pause("browser_adapter_unavailable")` only** |
| signup | `_UnavailableBrowserHandler` | `:419` | **no — same** |

Six phases wired. Unregistered phases fall through `_drive_phase` (`driver.py:5064`) to the unwired mailbox path or to the action loop, whose factory is `_NoBrowserSessions`. A production mounted run can therefore only ever reach `research → vault_check → {route_selected_login | awaiting_admission} → route_selected_signup → signup → paused`. `captcha_paused`, all four credential phases, and `completed` are unreachable today.

## Sweep and drain coverage

| selector | site | keyed on | phases covered |
|---|---|---|---|
| mounted drain | `api/service.py:656` → `storage.py:1992` | `runs.phase` + `execution_path` | research, vault_check, awaiting_admission, route_selected_signup |
| autonomous advance | `ops/runs/advance.py:126` | `status == waiting_for_hitl` + `hitl_request` | none by phase; `resolve_gate(None)` → `human_only`, so mounted pauses are skipped |
| liveness / stale | `ops/runs/liveness.py:67` | all runs minus terminal ∪ waiting | non-terminal, non-waiting |
| idle browser | `ops/runs/reconciliation.py:340` | `status == browser_running` | writes non-vocabulary `session_lost` (A30) |
| captcha takeover | `ops/runs/takeover.py:166` | `runs.phase == captcha_paused` | captcha_paused only |

Mounted phases the runtime claims but the drain never selects: `route_selected_login`, `signup`, `paused`. Phases no selector covers and the mounted runtime refuses outright: `email_verification`, `authenticated`, `developer_app`, `credential_generation`, `vault_storage`, `credential_validation`, `captcha_paused`, and any legacy value such as `session_lost`.

## Planner refusals → condition → apps affected

`reason_code` is the single constant `plan_surface_not_in_catalog` for all 19 (`validator.py:28`). Login = existing_account, recipe authority. Signup = create_account, profile authority.

| # | detail | emitted at | condition | of the 14 |
|---|---|---|---|---|
| 1 | `recipe_route_not_browser` | `decide.py:426-431` | `recipe_route_plan` is None — incl. **`urls.credential_management is None`** | **7 (Login)** — PROVEN |
| 2 | `credential_surface_unprovable` | `decide.py:379-384` | `profile_route_plan` is None | **0** — unreachable, `login_url` hard-required |
| 3-9 | recipe-plan checks | `validator.py:138-175` | slug mismatch, surface count, host/path/navigation | 0 — schema enum confines them first |
| 10 | `credential_surface_unprovable` | `validator.py:178-182` | `scope!="credential_surface"` and no credential URL | **7** — shadowed by #1 |
| 11-14 | profile-plan bindings | `validator.py:212-226` | slug, catalog id, recipe version, success digest, surface count | 0 |
| 15 | `navigation_denied` | `validator.py:227-230` | `allowed_hosts()` raises | 0 today; **13 (Signup)** if A37's test is honoured literally |
| 16-17 | profile host/path | `validator.py:231-238` | not in the profile's canonical set | 0 |
| 18-19 | no authority | `driver.py:2247`, `runs/service.py:470` | neither profile nor recipe | 0 |

Net: 7 of 14 refused on Login, all with a detail naming the wrong cause; **0 refused on Signup because the profile path cannot refuse** — it falls back to a credential surface it never proved (A21). Details 2 and 10 are two halves of the same missing fact, one unreachable and one shadowed.

## Config fail-closed traps

`(a)` refuses correctly and is satisfiable. `(b)` cannot be satisfied by any shipped env file or template default. Every setting listed **is** read by `Settings.from_env` — there are no unwired settings, so no `(b)` of the "no env wiring" kind exists.

| setting | code default | `.env.example` | `.env.production.example` | `compose.prod.yaml` | class | consequence |
|---|---|---|---|---|---|---|
| `ops_deploy_acceptance_nonce` | None | absent | absent | `${...:-manual-unaccepted}` | **(b)** | Sentinel rejected by name. 503 on every `/api/` write; three sweeps never start. Satisfiable only by `deploy-droplet.sh`. |
| `app_revision` | `local-uncommitted` | absent | absent | `${...:-local-uncommitted}` | **(b)** | Fails the 40-hex regex — independent second rejection of the same gate. |
| `ops_startup_automation_enabled` | False | absent | true | hard literal `"true"` | (a) | Not overridable in prod compose, which is what **arms** the two rows above. |
| `browser_domain_discovery_enabled` | False | absent | absent | absent | **(b)** | Off ⇒ any app without a reviewed recipe gets no allow-list. Caps "operator picks any app" at the 50-app catalog. One hand-added line makes it (a); no template mentions it. |
| `onboarding_research_perplexity_enabled` | False | absent | absent | absent | **(b)** | Off ⇒ research runs with only `_CatalogEvidenceDiscovery` over already-reviewed URLs. The "agent researches the provider" leg is inert under every shipped template. |
| `secret_vault_key` | None | blank | blank | passthrough | (a) | Blank ⇒ no vault ⇒ run #2 always prompts, and A7 blocks the run terminally. `deploy-droplet.sh:1113` hard-requires it; `docker compose up` does not. |
| `allow_local_credential_submission` | False | false | false | `${...:-false}` | (a) | A10. Goal step 3 refused in every shipped config. |
| `allow_live_browser` | False | false | false | `${...:-false}` | (a) | `ConfigurationRequiredError(live_browser_opt_in_required)`. Browser leg off out of the box; `conftest.py:82` forces it off so no test exercises live-on. |
| `allow_live_vendor_email` | False | false | false | `${...:-false}` | (a) | No autonomous signup confirmation. |
| `gmail_signup_address` | None | blank | blank | prod | (a) | A27: mounted runs get a fresh run-scoped binding, so reuse can never hit. |
| `playwright_in_process_sandbox` | False | absent | absent | hard `"false"` | (a) | Correct — forces the isolated service, whose URL/token/key are all wired. |
| `you_*_enabled` ×3 | False | absent | false ×3 | passthrough | (a) | Documented staged opt-in; a key alone deliberately does not spend. |
| `browser_use_compatibility_enabled` | False | false | false | `${...:-false}` | (a) | Intentional during the Playwright-only rollout. |
| `OPS_AUTH_TOTP_SECRET` | not a Settings field | absent | absent | hard `""` for api | — | Dead config read by no application code. Source of one red test. |

The `(b)` rows form one chain: the acceptance nonce and revision block the front door; domain discovery and Perplexity research block the research/planning leg for anything outside the catalog. None needs a code change; all four need env lines no shipped template contains.

Also worth flagging: **36 env names `from_env` reads that no shipped file declares**, including `ONBOARDING_LEASE_TTL_SECONDS`, `ONBOARDING_LOOP_MAX_*`, `BROWSER_LOGIN_CREDENTIAL_REUSE`, `AUTONOMOUS_ADVANCE_INTERVAL_SECONDS`, `MAX_AUTONOMOUS_ADVANCES`, and the whole `ONBOARDING_TAKEOVER_*` group. Defaults are sane, so this is not a blocker, but every budget and timeout governing autonomy is undiscoverable from the templates.

## The nine real red tests

| test | root cause | at HEAD | verdict |
|---|---|---|---|
| `test_owner_credential_submission` ×5 | **A1.** `telegram.urls.credential_management is None` → `decide.py:213-215` → `:426-432` → gate `canonical_runtime.py:1127-1135`. All five die in the shared `_entry_reached` helper (line 88) and never reach `submit_owner_credentials`. | fails identically | **product bug** — the gate demands a credential surface from `entry_only`/`owner_submit_ready` recipes that by design have none. The tests encode the intended contract. |
| `test_onboarding_end_to_end::test_one_signup_run_reaches_a_validated_credential` | **A14 + A2.** `plan_admission` reaches Groq inside `drive_run`; the `_no_network` guard's `AssertionError` is re-raised by `inference.py:371-377/539-540`. Terminal phase is `paused`, not `completed`. | fails differently (`paused != completed`) | **product bug** — the working-tree change introduced a live-network seam the composition layer cannot substitute. Sole cause confirmed: passes when `build_json_inference` is forced to `None`. |
| `test_playwright_worker::test_chromium_child_environment_excludes_worker_secrets_in_every_launch_mode` | **A36.** `chromium_launch_environment` ignores its `headless` argument. | fails identically | **product bug** — unimplemented parameter contradicting its caller's docstring. |
| `test_production_container_hardening::test_totp_secret_is_withheld_from_the_api_and_optional_for_web` | `_production_env()["OPS_AUTH_TOTP_SECRET"]` → KeyError. Template never declares it; no code reads it. | fails identically | **stale test** — TOTP was withdrawn and this assertion still demands a placeholder for dead config. Nothing is blocked. Goes with cluster B2, in the same commit, never merely because it fails. |
| `test_provider_profile::test_allowed_hosts_refuse_to_substitute_a_reviewed_recipes_authority` | **A37.** `profile.py:258` now passes `profile_authority=True`, so `host_policy.py:276-279` never consults the recipe. | **passes at HEAD** | **working-tree regression with a real semantic question.** The asserted reason code does not exist in the tree. Fix by intersecting rather than replacing, then rewrite the test. |

---

# Part B — deletion clusters

Read-only analysis; no deletions performed. Ordered safest first, independently landable with a green gate between them.

**Methodology warning.** Compound grep chains in this shell silently truncated output twice during this audit — a search for `access\.gated_route` returned zero hits even though `ops/workflow/canonical_runtime.py:23` imports it. Every claim below was re-verified with standalone plain-substring greps, an observed exit code, and a positive control on the regex shape. That failure mode is exactly how this repo previously produced a wrong "dead code" conclusion.

## B1 [RISK: low] `ops/browser/provider.py` orphan — 59 lines

**Files:** `ops/browser/provider.py`

**Reachability:**

```
$ grep -rnE "(from|import)[[:space:]]+(ops\.)?browser\.provider|from \.provider import" \
       ops api browser_service scripts tests --include='*.py'
NONE
$ grep -rn "BrowserProvider\b" ops api browser_service --include='*.py'
ops/core/state.py:19:  BrowserProvider = Literal["browser_use", "playwright"]   # what everyone imports
ops/browser/provider.py:23: class BrowserProvider(Protocol):                    # the orphan
```

Confirmed independently by an AST import-graph scan across `ops api browser_service scripts tests`: this is the **only** orphan module in the repo. The name collides with the `Literal`, which is why it looked reachable.

**Entry points checked:** routes, CLI, sweeps, settings branches, `web/src`, tests, and the phase-handler/provider dynamic dispatch maps. The file self-documents as "typing/documentation only — it holds no runtime behavior."

**Autonomy impact:** none. It is the interface that was never wired; production uses the concrete `BrowserWorker` as the provider type.

**Blocked by:** nothing.

## B2 [RISK: low] TOTP remnants — ~45 lines

**Files:** `compose.prod.yaml`, `.github/workflows/ci.yml`, `scripts/deploy-droplet.sh`, docs, and 5 test files.

**Reachability:** zero Python readers of `OPS_AUTH_TOTP_SECRET`. `web/src` mentions it once, in `proxy.test.ts:13`. `ops` and `api` never.

**Entry points checked:** all of the above plus the deploy script's passthrough at `:1062/1232`.

**Autonomy impact:** none — application auth is single-factor.

**Must keep:** the `totp` patterns in `ops/core/redaction.py`. They are generic secret-shape regexes; removing them narrows redaction.

**Blocked by:** nothing. The currently-red containment test goes with the removal in the same commit — not because it fails.

## B3 [RISK: low] Unreachable legacy retry/poll surface in the web app — ~62 lines

**Files:** `web/src/app/runs/[runId]/page.tsx` (`isRetryable` 425-427, `RetryControl` 429-436, retry forms at 238/265/433, the five visibility consts 106-112, the "Bounded operations" disclosure 322-352), `actions.ts:131-138`, `web/src/lib/api.ts:309-319`, `web/src/lib/types.ts:648-649`.

**Reachability:** every retry site is guarded by `legacyControls && !primaryAction`, and `primaryAction` is never null.

```
$ grep -rn 'action="retry"' web/src --include='*.tsx' | grep -v '\.test\.'
page.tsx:238  → guard: legacyControls && !primaryAction && isRetryable(browserPhase)
page.tsx:265  → guard: legacyControls && !primaryAction && isRetryable(emailPhase)
page.tsx:433  → inside RetryControl, only when retryControlsVisible
$ grep -n 'retryControlsVisible' 'web/src/app/runs/[runId]/page.tsx'
106:  const retryControlsVisible = legacyControls && !primaryAction    # always false
```

`_primary_action` (`api/service.py:741-834`) returns a `PrimaryAction` on every branch, `_detail` always passes it, there is no `response_model_exclude_none`, and the schema is `.nullish().default(null)` so a present value always parses.

**Entry points checked:** `PhaseActionForm` itself stays — `canonical-primary-action.tsx:143` (`poll_reply`) and `page.tsx:275/:288` are live. Only the `retry` action and the `canPoll` site are dead.

**Autonomy impact:** none. Removes a "Retry authority" panel that can never draw a button, and with it the client-side status inference noted in A45.

**Blocked by:** nothing.

## B4 [RISK: low] `OperationalUrlFieldName` deprecated alias — 2 lines

**Files:** `web/src/lib/types.ts:98-99`

**Reachability:** `grep -rn 'OperationalUrlFieldName' web/src --include='*.ts' --include='*.tsx'` returns only its own declaration.

**Autonomy impact:** none. Keep `OperationalUrlField`, used at `:103`. Closed-source demo, so the `@deprecated` marker is not a reason to keep it.

## B5 [RISK: medium] Runtime research-enrichment seam — ~1,280 lines

**Files:** `_build_research_enricher` and `_run_enrichment_probe` in `ops/runs/`, `OperationalResearchEnricher._enrich_rich`, `scripts/warm_you_research.py`.

**Reachability:** `api/service.py:621` constructs `CoreRunService.from_paths` **without** `research_enricher`, so `service._enricher` is permanently `None`, so the gate at `ops/runs/creation.py:174` is always False and `_run_enrichment_probe → enrich → _enrich_rich → all ops.you imports` is unreachable. `_build_research_enricher`'s only caller is `scripts/warm_you_research.py`, which no Makefile, CI job, or doc references. All three `YOU_*` flags default false in `compose.prod.yaml`.

**Entry points checked:** routes, CLI, sweeps, settings branches, `web/src`, tests, and the discovery/provider registries.

**Autonomy impact:** none on a live run. **Capability loss to confirm with the owner:** this is the recipe-authoring research probe. Deleting it removes the tooling used to author new recipes, not a runtime feature. Flagging rather than assuming.

**Blocked by:** nothing. Blocks B6.

## B6 [RISK: low, blocked by B5] `ops/you/` plus its tests and fixtures — ~3,931 lines

**Files:** `ops/you/**`, `tests/test_you_research.py`, `tests/test_you_eval.py`, fixtures.

**Reachability:** becomes a provable orphan once B5 lands. Today every path into it runs through the permanently-`None` enricher.

**Entry points checked:** `ops/onboarding/runtime.py` has zero `ops.you` references. Verified the load-bearing SSRF/redirect/size guard is `OfficialURLPolicy`/`OfficialEvidenceFetcher` in `ops/research/operational_research.py`, **not** in `ops/you/` — `GuardedHTTPEvidenceFetcher` there is a 14-line batch adapter. Deleting `ops/you/` does not touch the guard.

**Autonomy impact:** none. You.com is documented as research/retrieval only, never a runtime provider, never receives credentials, and cannot select the browser provider (pinned by `tests/test_you_research.py:1247-1252`, which goes with the cluster).

**Blocked by:** B5.

## B7 [RISK: medium] Browser Use Cloud adapter implementation — ~1,060 lines

**Files:** ~809 lines of `ops/browser/worker.py`, plus its cloud-specific helpers. **Keep** the shared observation/session types, which `ops/playwright/*` and `ops/core/storage.py` import.

**Reachability:** the gate at `ops/runs/service.py:1239` plus `BROWSER_USE_COMPATIBILITY_ENABLED=false` in every shipped env means `BrowserWorker` is never constructed in production.

**Autonomy impact:** removes the only fallback browser provider. Given A2 — the self-hosted path's handlers are not wired either — this cluster should not land until A2 is done and verified, or the deployment has no browser provider at all.

**Blocked by:** A2.

## B8 [RISK: medium] `browser-engine-field.tsx` selector — ~135 lines with call sites

**Files:** `web/src/components/browser-engine-field.tsx` (100), call sites in `new-run-form.tsx:12,78-82,307,388-400` and schema line 34, `web/src/app/runs/new/actions.ts:74-77,128`.

**Reachability:** the `browser_use` option is permanently unselectable in every shipped configuration.

```
$ grep -n 'BROWSER_USE_COMPATIBILITY_ENABLED\|BROWSER_PROVIDER' .env.example .env.production.example
.env.example:6:BROWSER_USE_COMPATIBILITY_ENABLED=false
.env.example:7:BROWSER_PROVIDER=playwright
.env.production.example:139:BROWSER_PROVIDER=playwright
.env.production.example:140:BROWSER_USE_COMPATIBILITY_ENABLED=false
```

Chain: `api/service.py:1031-1035` → `browser_use_enabled=False` → `state()` → `status="disabled"`; `browser-engine-field.tsx:12` `selectableProviderStatuses` excludes `"disabled"` → radio disabled, card at `opacity-55`; `new-run-form.tsx:78-82` therefore always resolves `playwright`.

**Entry points checked:** `grep -rn 'BrowserEngineField|browserProviderIsSelectable' web/src` → 7 hits, all in `new-run-form.tsx` and the component. No test targets it directly.

**Autonomy impact:** none, and a small operator improvement — today it is a two-option chooser where one is permanently greyed out. Replace with a static "Self-hosted · Playwright" line and hardcode the provider in `actions.ts:128`.

**Must keep:** `BrowserProvider` as a two-member union. `api/models.py` still emits `browser_use` on historical rows and `provider-state-card.tsx:16,28,54` / `browser-live-surface.tsx:59` render it. Delete the **selector**, not the **type**.

## B9 [RISK: high] `plan_only` execution mode — ~340 Python + ~155 web lines

**Files, Python production (8):** `api/browser_ui.py`, `api/models.py`, `api/service.py`, `ops/core/state.py`, `ops/runs/creation.py`, `ops/runs/projections.py`, `ops/runs/service.py`, `ops/workflow/canonical_runtime.py`. **Tests (13):** `test_api.py`, `test_api_operations.py`, `test_browser_ui_state.py`, `test_canonical_runtime.py`, `test_cli.py`, `test_high_severity_fixes.py`, `test_mounted_dispatch_boundary.py`, `test_outreach_ingestion_integrity.py`, `test_playwright_provider_integration.py`, `test_production_container_hardening.py`, `test_projection.py`, `test_run_service.py`, `test_startup_automation.py`. **Web (10):** `app/page.tsx`, `app/runs/[runId]/page.tsx` + test, `app/runs/new/actions.ts` + test, `components/new-run-form.tsx`, `components/run-progress.tsx` + test, `lib/api-schemas.ts`, `lib/types.ts`. **Docs/CI/specs (6).**

**Two more identifiers must go with it:** the persisted token `local_dry_run` (`api/service.py`, `ops/core/storage.py`, `ops/runs/projections.py`, 2 tests) and the deprecated `dry_run` alias (12 production files, 11 test files).

**Reachability:** fully reachable — a live user-selectable mode, and the **default**.

**Autonomy impact:** removes the operator's only side-effect-free dry run. It also changes signup eligibility: `accountCreationUnavailableReason` (`new-run-form.tsx:486-488`) skips the Gmail readiness gate in plan-only, so with the mode gone "Create a new account" becomes unavailable whenever Gmail is not `ready`. And it backs four `plan_only_run_is_read_only` credential-submission refusals in `canonical_runtime.py`.

**Worst savings-to-risk ratio in the audit.** If the owner insists, the order is: (1) flip the backend default at `api/models.py:273`; (2) flip the `actions.ts:73` fallback; (3) remove the selector and the `isPlanOnly` branches; (4) keep `ExecutionMode`, the zod enum, and `planOnlyPhases` until no `local_dry_run` rows remain, or historical runs render an empty phase grid.

**Blocked by:** A12 must land first. Deleting the mode while the mounted walk is blind to it is a behaviour change stacked on an unfixed bug.

## B10 [RISK: high] Gated route machinery — ~810 lines

11 of 50 catalog apps are `route_kind=gated` (counted from `app_recipes.json`: managed_auth 25 / playwright 14 / gated 11). Deleting narrows the product by 22%. **Flagging the trade-off rather than recommending.** Not included in the cumulative total.

## B11 [RISK: high] The `browser_use` literal itself — not recommended

Quantified across three layers: the `Settings` default (prod overrides to playwright), the `runs.browser_provider` column `DEFAULT 'browser_use'` with six `.get(..., "browser_use")` projection fallbacks, and `getattr(worker, "provider_name", "browser_use")` used for audit-effect attribution. Needs a storage migration and risks misattributing historical audit effects. Excluded.

## UNWIRED-BUT-NEEDED — ~810 lines that must NOT be deleted

The most consequential judgement call in Part B. These have zero production callers and look exactly like dead code. They are the missing implementation of autonomy.

| symbol | lines | why it must stay |
|---|---|---|
| `SignupPhaseHandler` (`ops/browser/signup.py:1694`) | 197 | The signup phase's real handler. A2's fix wires this. |
| `LoginRouteHandler` | 97 | Same for `route_selected_login`. |
| `DeveloperAppPhaseHandler` | 53 | Needed for `developer_app`. |
| `commit_phase_with_reservation` (`driver.py:601`) | 110 | Its absence means production **currently has** the double-submission window its docstring describes (A16). |
| `recover_run` / `recover_runs` + recovery types (`driver.py:4830,4997`) | 343 | The only crash-recovery path; A15's fix calls it from the drain. |
| `reconcile_completed_effect` (`effect_ledger.py`) | 12 | The `reconcile` disposition **is** produced (`effects.py:280,326`) and treated as in-flight (`resume.py:538`), so without this nothing can ever close it out (A15). |
| `CaptchaResumeForm` (`browser-hitl-forms.tsx:123-190`) | 68 | Unreachable today, but the only working implementation of goal step 6; A8's fix generalises it to all waiting phases. |

## Load-bearing, confirmed untouched

The P1 hard block was verified firsthand at `ops/onboarding/runtime.py:465-468`: `advance()` blocks any run without a `P1LookupFound`, and all 50 apps depend on the snapshot. **This is the single most dangerous deletion in the repo and it is not proposed.** It can only go after live discovery replaces it. Also untouched: `SQLiteSecretStore`/`VaultSQLiteSecretStore`, `ops/core/redaction.py`, `model_input_dlp`, the SSRF/redirect/size guard on evidence fetch, `ops/core/effect_ledger.py`, and `semantic-review/`.

No safety control is proposed for removal anywhere in this report. The one guard that genuinely blocks a legitimate flow — the 256 KiB evidence cap discarding a document whose usable 24 KB was in bounds (A23) — is addressed by truncate-instead-of-discard on the evidence path only, with the byte ceiling and every host, DNS and redirect check unchanged.

---

# Closing list 1 — from "picks an app" to "API key in the vault"

The real deliverable. Ordered so each step is verifiable before the next, and so nothing is fixed on top of a bug that hides it. Steps 1-4 are prerequisites in the strict sense: without them you cannot observe whether anything else worked.

1. **Make a plain deployment acceptable** (A6, A13). Surface the unaccepted state on readiness with a named reason code; ship the two env keys annotated in the production template; gate the mounted drain the way the other three sweeps are gated. Until this lands, `POST /api/runs` is 503 and no amount of downstream fixing is observable.
2. **Digest sentinel for boundaries with no profile** (A3, A4). Two one-line changes using `"0" * 64`. This is what makes every other failure path recoverable instead of an escaping exception, so it comes before anything that can fail.
3. **Per-run `try` inside the drain loop** (A5). Move the guard inside the `for`. One raising run currently starves every healthy run behind it forever, which would mask all later work.
4. **Fail closed at creation on a missing vault key**, instead of blocking terminally at `vault_check` (A7). And give `blocked` a `research` edge so a config-fixable refusal is recoverable.
5. **Give `entry_only` recipes a credential surface** (A1). Unblocks 7 of 14 Playwright apps and turns the five red `test_owner_credential_submission` tests green. Add the distinct refusal detail while in there.
6. **Wire the real browser phase handlers and a real session factory** (A2). The largest item: `SignupPhaseHandler` plus a login handler plus a `LoopSessionFactory`, plus `logins=` and `verification_binding=` so email verification is reachable. Nothing downstream of `route_selected` executes until this is done.
7. **Register the credential-lifecycle handlers** for `vault_storage` and `credential_validation` (A42), and **widen `stranded_mounted_run_ids`** to the post-admission phases so the drain keeps driving after `route_selected_signup`.
8. **Open the phase-table exits** (A8, A19): `paused → phase_at_pause` mirroring `captcha_paused`, `cancelled` added to `vault_check` and `research`, and `_withheld_resume_reason` generalised to all waiting phases. This is what makes "human only where unavoidable" true rather than "human, then abandon the run."
9. **Fix research so a profile can actually be built**: policy from the reviewed evidence set using strict `exact_hosts` (A11), canonical corroboration key (A17), route-aware required fields (A18), truncate instead of discard on the size cap (A23). Each is small; together they are the difference between `research_no_evidence` and a committed profile for 10 of 14 apps.
10. **Require a minting flow for the credential surface** (A21) and **persist the refusal detail** (A32). A plan that cannot prove a credential route must say so rather than pointing at a login page.
11. **Make credential reuse real**: persist the resolved `account_ref` (A24), derive the mounted binding without depending on an unset `GMAIL_SIGNUP_ADDRESS` (A27), give the operator a reference-only way to resolve ambiguity (A25), and add a post-authentication success predicate for the 7 `entry_only` recipes so their pairs get promoted (A26). This is what makes run #2 skip the prompt.
12. **Add the cross-run API key reader** (A28) — `latest_active_credential_reference(app_slug, kind)`, reference-only, consulted before reserving the capture effect. This is literally goal step 5 and nothing else in the report substitutes for it.
13. **Split the credential-submission gate** (A10) so inbound vault writes are authorized by the existing owner token and default on, while raw-secret reveal stays loopback-only. Goal step 3 needs this.
14. **Take planner inference off the request path** (A14): inject the composed chain at both `SettingsRunPlanner` sites and broaden the fallback beyond `DecisionFailed`.
15. **Make `plan_only` inert in the mounted walk** (A12), or delete the mode. Do not leave a label that claims no side effects while fetching vendor sites and spending two inference budgets.
16. **Close the effect-durability gaps**: use `commit_phase_with_reservation` in `drive_run` (A16), wire the `EffectOutcomeProbe` and an age-based reconcile sweep that probes rather than resends (A15), and correct the post-click `failed` classification (A39). Before A2 ships, these are theoretical; after it, they are what stops duplicate accounts.
17. **Fence the phase commit and renew the lease mid-step** (A41). Two workers on one phase currently produce two digests and therefore two effect keys the ledger cannot collide.
18. **Add the mid-run signup affordance** (A9): reason code `login_account_not_found`, transition `route_selected_login → awaiting_admission`, and `can_decide_admission` for that boundary. Goal step 4 has no implementation without it.
19. **Enforce admission preconditions at the backend** (A31) so the UI's four checks are not the only thing standing between a curl and an unbacked signup.
20. **Make the UI tell the truth about a stopped run** (A45): stop the 4s poll and the spinner on `waiting_for_hitl`, drive the stage labels from the resolved route rather than `account_mode`, fix the 403 copy, stop announcing a successful vault write as an error, and render the autonomy verdict that is already on the wire.

Items 1-8 are the difference between "no run finishes" and "runs finish when the environment cooperates." Items 9-13 are the difference between that and the stated goal. Items 14-20 are what keeps it true under crash, retry and a second operator.

# Closing list 2 — deletion clusters, safest first

| order | cluster | risk | lines | cumulative |
|---|---|---|---|---|
| 1 | B1 `ops/browser/provider.py` orphan | low | 59 | 59 |
| 2 | B4 `OperationalUrlFieldName` alias | low | 2 | 61 |
| 3 | B2 TOTP remnants | low | 45 | 106 |
| 4 | B3 legacy retry/poll web surface | low | 62 | 168 |
| 5 | B5 research-enrichment seam | medium | 1,280 | 1,448 |
| 6 | B6 `ops/you/` + tests | low after B5 | 3,931 | 5,379 |
| 7 | B8 `browser-engine-field` selector | medium | 135 | 5,514 |
| 8 | B7 Browser Use Cloud adapter | medium | 1,060 | 6,574 |

**6,574 lines, about 4.9% of the measured 133,577.** Excluded with the trade-off named rather than assumed: B9 `plan_only` (~495 lines, high risk, worst ratio), B10 gated routes (~810, narrows the product 22%), B11 the `browser_use` literal (needs a storage migration, risks audit misattribution).

## Where the two lists conflict — stated, not quietly resolved

Three real conflicts, and in each the Part A item wins:

1. **B7/B8 versus A2.** Deleting the Browser Use adapter and its selector removes the only fallback provider while the self-hosted path's handlers are still stubs. If both land before A2, the deployment has no working browser provider at all. **Sequence A2 first**, then B7/B8.
2. **B9 versus A12.** They touch the same code. A12 makes `plan_only` inert in the mounted walk; B9 deletes the mode. Landing B9 first means changing the default execution path while the walk still ignores the mode — and, per correction 4, deleting the UI selector alone silently makes every run plan-only. **A12 first, then B9 if at all.**
3. **B5 versus recipe authoring.** B5/B6 are the largest safe win, 5,211 lines together, and they cost nothing at runtime. But B5 is the probe used to author new recipes, and A1/A26 both conclude with "fix the catalog." If the owner intends to add recipes soon, deleting the authoring probe first makes that harder. **Confirm the recipe-authoring workflow before landing B5.**

Beyond those, Part B does not touch anything on Part A's critical path. The seven UNWIRED-BUT-NEEDED symbols above are the sharpest edge in the repo: every one is invisible to a reachability check and every one is load-bearing for a fix in list 1.
