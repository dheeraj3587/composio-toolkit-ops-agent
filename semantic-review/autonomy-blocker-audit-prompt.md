# Audit prompt: what is stopping this agent from running autonomously?

Paste everything below the line into a fresh agent working in this repository.

---

You have two jobs on this codebase, in this order:

**A. Find every defect that prevents its agent from completing an onboarding run
without a human.** This is not a general code review. A finding only counts if it
stops, stalls, misroutes, or silently no-ops an otherwise-healthy autonomous run.
Elegance, naming, and style are out of scope for part A.

**B. Identify code that can be deleted** without damaging autonomy. The codebase has
grown to roughly 150k lines and carries whole subsystems that are switched off,
superseded, or were never wired. See "Part B" below.

Part A outranks Part B. A deletion that breaks an autonomous path is a worse
outcome than any amount of retained slop.

## The product goal you are measuring against

`composio-toolkit-ops-agent` is a single-operator control plane that onboards app
integrations autonomously. The intended flow, end to end:

1. Operator picks an app and chooses **Login** or **Signup**.
2. The agent researches the provider, builds a corroborated `ProviderProfile`, and
   plans a route (ordered surfaces + a credential surface).
3. For Login: a dialog collects credentials **once**, mid-run. For OAuth apps, a
   Composio managed-auth connect instead.
4. The agent drives a browser to log in. If no account exists, the operator gets a
   **Sign up** button, and the agent creates the account.
5. Credentials **and the app's API key** are captured into the encrypted vault, so
   the next run for that app reuses them and never prompts again.
6. Human-in-the-loop only where genuinely unavoidable: credential entry, CAPTCHA,
   MFA, billing, legal consent.

Steps 4–6 are partially built. Your job is to find what stops steps 1–6 from
running unattended.

## Architecture map

```
Next.js UI (web/) → FastAPI (api/) → CanonicalRuntime (ops/workflow/canonical_runtime.py)
                                   → MountedOnboardingRuntime (ops/onboarding/runtime.py)
                                   → drive_run (ops/onboarding/driver.py, ~5.4k lines)
                                   → browser service / Composio managed auth / Gmail
```

Two execution paths exist and the split matters constantly:

- **legacy_static** — complete static Playwright recipes; dispatched inside
  `CanonicalRuntime.create_run`.
- **profile_mounted** — everything else; owned by `MountedOnboardingRuntime`,
  driven by `drive_run` through a durable phase state machine.

The resolved path is persisted on the run row as `execution_path`. Any code that
decides behaviour from the *client's* `request.onboarding` flag instead of this
column is a bug — that class of defect has already bitten once.

Key files, by weight:
- `ops/onboarding/driver.py` — phase walk, leases, effects (the heart)
- `ops/onboarding/runtime.py` — the mounted seam and its phase handlers
- `ops/onboarding/phase.py` — `OnboardingPhase`, `_LEGAL_PHASE_TRANSITIONS`, `project_status`
- `ops/workflow/canonical_runtime.py` — run creation, browser drive, managed auth
- `ops/planner/{decide,plan,validator}.py` — route planning and its refusals
- `ops/providers/profile_builder.py` — evidence → corroborated profile
- `ops/core/{storage,state,secret_store}.py` — ledger, status machine, vault
- `api/service.py` — projections, controls, admission, the drain loop
- `web/src/components/new-run-form.tsx`, `web/src/app/runs/[runId]/page.tsx`

## Facts already established — trust these, do not re-derive

- The planner **is** wired. `ops/onboarding/composition.py` calls
  `decide_profile_plan`/`decide_run_plan`; `runtime.py` calls `drive_run`;
  `api/service.py` imports `MountedOnboardingRuntime`. (An earlier audit wrongly
  called it dead code because of a broken shell glob — see Tooling below.)
- Recipe catalog is **50 apps**: 25 `managed_auth`, 14 `playwright`, 11 `gated`.
- Of the 14 Playwright apps, **only Pipedrive declares a static signup URL**. The
  other 13 take the `profile_mounted` path.
- **All 50 apps have P1 snapshot records**, so `lookup_p1_record` is not currently
  blocking anything — but it is a hard block for any app lacking one.
- Test baseline: **63 failures**. ~54 are macOS-only environment failures
  (`flock` absent, BSD `stat` vs GNU) in `test_transactional_deploy.py` and
  `test_restore_production_data.py`. **Do not report these.**

## Already fixed — do not re-report

1. Legacy dispatch swallowing profile-onboarding runs (`canonical_runtime.py`, the
   `not profile_onboarding` guard before the Playwright dispatch).
2. `onboarding_run_plans` CHECK rejecting `source='profile'` (rebuild migration).
3. Post-commit onboarding work having no restart recovery (ledger-reconciling drain
   in the API lifespan + `stranded_mounted_run_ids`).
4. Research failure bypassing the phase authority (`_ResearchHandler` now returns a
   blocked `PhaseStep` instead of raising).
5. `_sync_main_projection` not idempotent/fenced (now fenced on boundary sequence).
6. Resume advertised where the phase table forbids it (`can_resume`).
7. Projections branching on client intent rather than `execution_path`.

## Known-open, already triaged — confirm and deepen, don't just restate

- **plan_only still does real work**: mounted plan-only requests fetch websites,
  may call inference, inspect the vault, and expose an admission decision.
- **Account-creation readiness is presentation-only** in `new-run-form.tsx`; not
  enforced at the backend admission boundary.
- **`_profile_credential_surface`** falls back to developer-portal/login/signup when
  no credential-producing `FlowSpec` is supported, so a plan can claim a credential
  route it never proved. `profile_success_digest` hashes URL vocabulary, not an
  observable success predicate.
- **Port identity is lost**: `_extract_visible_text` rebuilds links from
  `parsed.hostname`, `PlannedSurface` stores only host+path, `evaluate_navigation`
  ignores ports — `https://x:8443/signup` can authorise `https://x/signup`.
- **Planner inference blocks the event loop**: `_ResearchHandler` calls synchronous
  `plan_admission` → `JsonInference.generate` directly.

## Where to hunt (highest yield first)

1. **Dead ends in the phase machine.** Walk `_LEGAL_PHASE_TRANSITIONS`. Find phases
   a run can enter but not leave without a human; handlers that `pause()` where the
   table offers no forward target; waiting phases with no actor that ever wakes
   them. `route_selected_login` and `signup` currently map to a handler that always
   pauses — trace what a real deployment needs for them to proceed.
2. **Silent no-ops.** Anywhere an exception is swallowed, a sweep skips a run, a
   lease is lost, or an `if` guard makes work vanish without a status change. A run
   that stops with no reason code and no UI control is the signature failure here.
3. **Effects and retries.** The effect ledger guarantees effectively-once external
   actions. Find paths where a retry duplicates a signup/email, or where a crash
   between reserve and commit strands a reservation forever.
4. **Credential lifecycle.** Trace an existing-account login end to end:
   `_reusable_login_values` → `_stage_signup_login` → `_promote_staged_signup_login`
   → `_finalize_captured_credentials`. Does a second run for the same app actually
   reuse the vault and skip prompting? Where does that break?
5. **API key retrieval.** There is no `api_key` handling anywhere today. Confirm
   this and state precisely what is missing for step 5 of the goal flow.
6. **Config fail-closed traps.** Settings that are hard-off by default and silently
   turn a live route into `configuration_required`. Distinguish "correctly refuses
   without config" from "cannot ever be configured".
7. **The 5 red tests in `tests/test_owner_credential_submission.py`** — they assert
   `browser_running` but get `configuration_required` on a Telegram Playwright
   login. Root-cause these; they sit on the exact path the login/signup UX needs.

## Part B — cleanup scope

The owner wants the line count down substantially. This is a closed-source demo, so
backward compatibility with old releases, deprecation windows, and unused
extensibility seams are **not** reasons to keep code. "A future version might want
it" is not a reason either.

Measured sizes (Python + TS, excluding `node_modules`/`.next`):

| Area | Lines |
| --- | --- |
| `ops/` | 66,837 |
| `tests/` | 43,812 |
| `web/src/` | 12,689 |
| `browser_service/` | 4,041 |
| `api/` | 5,716 |

Largest single files: `ops/onboarding/driver.py` (5,403), `ops/core/storage.py`
(3,270), `ops/workflow/canonical_runtime.py` (3,179), `api/service.py` (2,824),
`ops/playwright/worker.py` (2,641), `ops/browser/signup.py` (1,920).

### Candidates already suspected — verify each before recommending removal

- `ops/you/` (~2,105 lines). You.com is documented as *not* a runtime provider and
  is disabled in production. Confirm nothing on a live path reaches it.
- **Browser Use** provider path (`browser_use` in `ops/core/state.py`, parts of
  `ops/browser/`, `web/src/components/browser-engine-field.tsx`). Production uses
  the self-hosted Playwright browser service. Confirm before cutting.
- **`gated` route machinery** — 11 of 50 recipes are `gated` (partner approval).
  Removing this narrows the product; flag the trade-off rather than assuming.
- **`plan_only` execution mode** — spread across ~20 files. Slated for removal once
  the autonomous path is the only path. Map every site.
- **TOTP remnants** — application auth is single-factor now (`OPS_AUTH_TOTP_SECRET`
  is no longer read). Find leftovers.
- `semantic-review/` — review notes, not code. Never delete these; they are
  deliberate artifacts, and this prompt lives among them.

### Load-bearing — do NOT propose deleting

- **P1 snapshot** (`ops/research/p1_adapter.py`, `data/p1/`). It looks like dead
  research scaffolding. It is not: `MountedOnboardingRuntime.advance` **hard-blocks
  any run without a P1 record**, and all 50 apps currently depend on it. It can only
  go after live discovery replaces it. This is the single most dangerous deletion in
  the repo — say so if you touch the area.
- Vault/`SQLiteSecretStore`, `ops/core/redaction.py`, `model_input_dlp`, the
  SSRF/redirect/size guard on evidence fetch, and `ops/core/effect_ledger.py`. These
  protect the autonomous path — the effect ledger in particular is what stops a
  retrying agent from creating duplicate accounts or re-sending email.

### Rules for every deletion you propose

1. **Prove it is unreachable.** Show the search that establishes no live caller —
   and show the command, because a mistyped search is how this repo already produced
   one wrong "dead code" conclusion (see Tooling). Grep is evidence only if it ran.
2. **Name the entry points you checked**: API routes, CLI (`ops/cli.py`), background
   sweeps/threads, settings-driven branches, `web/src` fetches, tests, and dynamic
   dispatch by string key (phase handler maps, provider registries — these defeat
   plain grep).
3. **Give a line count** for each cluster, so the owner can rank by payoff.
4. **Order by risk**, safest first, and keep clusters independently landable with a
   green gate between them.
5. **Tests count.** `tests/` is 43k lines. Tests for deleted subsystems go with
   them, but never propose deleting a test merely because it fails — the branch has
   real red tests that indicate real bugs.
6. **Do not perform the deletions.** Produce the ranked plan; the owner approves
   cluster by cluster.

## Method — this part is not optional

- **Prove each finding.** Give `file:line`, the concrete trigger, and the observable
  consequence to a run. If you can, write a failing test, or revert a suspected fix
  and show the failure. A finding you have not traced to a real run outcome must be
  labelled `UNVERIFIED`.
- **Distinguish severity by autonomy impact**, not by taste:
  - `BLOCKER` — an autonomous run cannot complete, for common apps.
  - `STALL` — the run halts and needs a human who should not have been needed.
  - `SILENT` — wrong outcome with no error surfaced.
  - `LATENT` — correct today, breaks under crash/retry/concurrency/scale.
- **Do not propose removing safety controls** to gain autonomy. The vault,
  redaction filter, model-input DLP, SSRF/redirect guard, and effect ledger are
  deliberate and stay. If one genuinely blocks a legitimate flow, show the exact
  case and propose a narrower fix, not deletion.
- Prefer a small number of proven blockers over a long speculative list.

## Tooling gotchas that have already caused wrong conclusions

- The shell is **zsh**. `grep -rn "x" ops --include=*.py` **fails** with
  `no matches found` because zsh expands the glob. Always quote: `--include='*.py'`.
  A failed search and a zero-hit search look identical — verify your command ran.
- `cmd | tail` reports **tail's** exit status. A piped test run can look green while
  pytest failed. Read the summary line or use `PIPESTATUS`.
- Offline test command: `RUN_LIVE_TESTS=0 python -m pytest -q -m "not live and not browser"`
  (venv at `.venv`). Also `mypy ops api` and `ruff check ops api tests`.
- Live flags (`ALLOW_LIVE_BROWSER`, `ALLOW_LIVE_VENDOR_EMAIL`) are off by default and
  `conftest.py` forces them off; behaviour you see offline may not be the live path.

## Output

**Part A** — for each defect:

```
[SEVERITY] <one-line claim>
Where:       file:line (plus any second site)
Trigger:     the concrete condition — which app, which route, which phase
Consequence: what the run does instead of completing
Evidence:    test output, trace, or the reverted-fix failure
Fix:         the narrowest change that restores autonomy
```

**Part B** — for each deletion cluster:

```
[RISK: low|medium|high] <cluster name> — ~N lines
Files:       paths (globs fine)
Reachability: the searches you ran and what they returned
Entry points checked: routes / CLI / sweeps / settings branches / web / dynamic dispatch
Autonomy impact: what a live run loses, or "none"
Blocked by:  anything that must land first
```

Close with **two ordered lists**:

1. The shortlist of changes that would take a run from "picks an app" to "API key in
   the vault" with no human beyond credential entry.
2. The deletion clusters, safest first, with cumulative line savings.

The first list is the real deliverable. If the two ever conflict, say so explicitly
rather than quietly choosing.
