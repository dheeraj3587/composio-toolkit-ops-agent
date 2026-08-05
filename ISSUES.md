# Diagnostic sweep — full issue inventory

**Date:** 2026-08-05 · **Commit:** `7eed9b5` (+ uncommitted working-tree changes, see [Note on prior edits](#note-on-prior-edits))
**Host:** macOS (darwin 27.0.0), Python 3.11.15, Node v22.23.2

---

## Summary

**16 issues total: 9 hard blockers, 4 warnings, 3 environmental (not real bugs).**

The codebase is in far better shape than the raw failure count suggests — `ruff check`, `mypy --strict` (165 files, including `browser_service`), `compileall`, shell syntax, detect-secrets, the security gate's secret scan, both npm audit gates, ESLint, `tsc`, all 136 vitest tests, and the production Next.js build **all pass clean**. Of 1758 Python tests, 1690 pass. The 62 pytest failures split into **54 macOS-environmental** (`flock` absent, BSD vs GNU `stat`) and **8 genuine failures that will also fail on Linux CI** — confirmed by re-running the full suite with the security gate's complete env-shadowing, which produced byte-identical results, ruling out `.env` pollution. The blockers cluster around three root causes: an incomplete TOTP-removal migration, a plan-validator contract that contradicts the owner-submit recipe contract (structurally disabling 7 of 50 apps), and a status-vocabulary mismatch that returns HTTP 500 from `GET /api/runs` against real persisted data. One CVE-flagged dependency (`cryptography`) fails the security gate outright.

| Group | Blockers | Warnings | Environmental |
|---|---:|---:|---:|
| Backend | 3 | 0 | 0 |
| CI / Deploy | 2 | 1 | 0 |
| Tests | 4 | 0 | 0 |
| Frontend | 0 | 1 | 0 |
| Documentation | 0 | 1 | 0 |
| Untracked files | 0 | 1 | 0 |
| Environmental | — | — | 3 |
| **Total** | **9** | **4** | **3** |

---

## Note on prior edits

Before this discovery-only instruction was given, two files were already modified in the working tree during the earlier recon pass. **Nothing is committed.** They are listed here as `[ALREADY FIXED]` so the inventory is accurate:

- `.github/workflows/ci.yml` — removed the dead `OPS_AUTH_TOTP_SECRET` substitution (issue **CI-1**)
- `tests/test_run_service.py` — `ruff format` applied (issue **CI-2**)

Also deleted: iCloud conflict-copy files under `web/.next/` (generated, regenerable — issue **ENV-3**).

Everything else in this document is **unmodified and unfixed**.

---

## Backend

Ordered by dependency. **BE-1 is independent. BE-2 causes all 5 failures in TEST-3.**

### BE-1 · `GET /api/runs` returns HTTP 500 on real persisted data — BLOCKER

- **File:** `api/service.py:666` (construction), `ops/core/state.py:22-36` (vocabulary), `ops/core/storage.py` (runs DDL)
- **Tool:** manual runtime probe (FastAPI `TestClient` against the real `private/ops.db`) — **no static check catches this**
- **Exact error:**
  ```
  pydantic_core._pydantic_core.ValidationError: 1 validation error for RunSummary
  status
    Input should be 'created', 'researching', 'route_selected', 'connection_required',
    'browser_running', 'waiting_for_hitl', 'outreach_sent', 'waiting_for_reply',
    'credentials_ready', 'configuration_required', 'blocked', 'failed' or 'completed'
    [type=literal_error]
  ```
  Traceback: `api/app.py:629 list_runs` → `api/service.py:2167 list_runs` → `api/service.py:1870 _list_sync` → `api/service.py:666 _summary`
- **Root cause:** `RunStatus` (`ops/core/state.py:22-36`) declares 13 statuses; `cancelled` is **not** among them. The `runs` table declares `status TEXT NOT NULL` with **no CHECK constraint**, so out-of-vocabulary values persist silently. `private/ops.db` currently holds 3 such rows:
  ```
  run_4a977b04bc014f17b361da66ee025055  Resend  cancelled  2026-08-02T03:58:44.051600Z
  run_7bf0a71baa584c2cbfeedb966216fed8  Resend  cancelled  2026-08-02T04:27:24.173414Z
  run_52caac39ad9f4158950e84b699654545  Resend  cancelled  2026-08-02T14:18:47.793476Z
  ```
  `_summary()` has no defensive handling, and `_list_sync` builds the list eagerly — so **one bad row makes the entire run list unusable**, not just that row. This breaks the `/runs` console page as well as the API.
- **Also note:** `Resend` is not in the 50-app catalog, so these rows came from a path that bypassed catalog binding — worth understanding before fixing, as it may indicate a second defect.
- **Blocker:** yes — runtime 500 on a core endpoint. Not caught by CI (no test exercises a non-vocabulary status).

### BE-2 · Plan validator structurally refuses all 7 owner-submit recipes — BLOCKER

- **File:** `ops/planner/validator.py:172-175`
- **Tool:** manual repro + pytest (`tests/test_owner_credential_submission.py`)
- **Exact error** (observed run state for a Telegram run):
  ```
  status         : configuration_required
  phase          : plan_refused
  route_reason   : plan_surface_not_in_catalog
  ```
  Failing branch:
  ```python
  else:
      declared = _path_of(recipe.urls.credential_management)
      if declared is None:
          return _refuse("credential_surface_unprovable", CREDENTIAL_SURFACE_ORDINAL)
  ```
- **Root cause:** For any recipe whose `browser.scope != "credential_surface"` (i.e. every `entry_only` recipe), the validator **requires** `recipe.urls.credential_management`. But `docs/APP_RECIPES.md:83` states the opposite contract: *"An owner-submit recipe **must not** contain a credential-management URL, automatic capture specification, or validation policy."* The two contracts are mutually exclusive, so every owner-submit recipe is refused before a browser session is created.
- **Blast radius —** verified against the live catalog, 7 of 14 Playwright recipes are refused:
  ```
  bright-data, dataforseo, klaviyo, neo4j, shopify, telegram, xero
  ```
  (The other 7 — `apify`, `cloudflare`, `coda`, `datadog`, `firecrawl`, `pipedrive`, `vercel` — are `credential_surface` scope and pass.)
- **Blocker:** yes — 7 of 50 catalogued apps cannot start a run at all.
- **⚠ Dependency:** fixing BE-2 should resolve **all 5 failures in TEST-3**. Fix BE-2 first and re-check TEST-3 before touching those tests. May also affect **TEST-4**.

### BE-3 · `cryptography` 48.0.1 — 3 known CVEs, fails the security gate — BLOCKER

- **File:** `requirements-runtime.lock:247`, `requirements.txt:7`
- **Tool:** `pip-audit --disable-pip --require-hashes -r requirements-runtime.lock` (invoked by `scripts/security_gate.sh`)
- **Exact error:**
  ```
  Found 3 known vulnerabilities in 1 package
  Name         Version ID              Fix Versions
  ------------ ------- --------------- ------------
  cryptography 48.0.1  PYSEC-2026-3552 50.0.0
  cryptography 48.0.1  PYSEC-2026-3553 49.0.0
  cryptography 48.0.1  PYSEC-2026-3554 49.0.0
  ```
- **Root cause:** pinned dependency behind three published advisories. Fixed in 49.0.0 (two) / 50.0.0 (one).
- **Relevance:** `cryptography` is not incidental here — it provides the Fernet primitives for the credential vault and the `LANGGRAPH_AES_KEY` boundary.
- **Blocker:** yes — `make security` / the CI security gate exits non-zero. Requires regenerating the hash-locked `requirements-runtime.lock`.

---

## CI / Deployment config

### CI-1 · `ci.yml` required an env key that no longer exists — BLOCKER · **[ALREADY FIXED]**

- **File:** `.github/workflows/ci.yml:458-460` (pre-fix)
- **Tool:** GitHub Actions log (job `91203325933`, "Full production Compose smoke", failed in 6s)
- **Exact error:** `##[error]Process completed with exit code 1` — raised by the workflow's own guard:
  ```python
  if replaced != set(replacements):
      raise SystemExit(1)
  ```
- **Root cause:** commit `cd5604f` ("Remove TOTP from production authentication") deleted `OPS_AUTH_TOTP_SECRET` from `.env.production.example`, but `ci.yml` still listed it as a required substitution key. Nothing to replace → guard trips → the whole Compose smoke job dies before building anything.
- **Verified after fix:** all 14 remaining replacement keys resolve against `.env.production.example` (97 keys). Cross-checked `compose.prod.yaml` and `scripts/deploy-droplet.sh` for the same class of drift — see [Verified-clean](#verified-clean-not-issues).

### CI-2 · `ruff format --check` failed the backend gate — BLOCKER · **[ALREADY FIXED]**

- **File:** `tests/test_run_service.py:55`
- **Tool:** `ruff format --check .` (via `scripts/security_gate.sh` and CI job `91203325955`)
- **Exact error:**
  ```
  unformatted: File would be reformatted
    --> tests/test_run_service.py:55:12
  1 file would be reformatted, 312 files already formatted
  ##[error]Process completed with exit code 1
  ```
- **Root cause:** an `assert service.observe_run_surface(...).action == "proceed"` call that ruff wants wrapped in parentheses. Committed without running the formatter.
- **Verified after fix:** `ruff format --check ops api tests` → 295 files already formatted; `tests/test_run_service.py` still passes (27 passed).

### CI-3 · Real-browser CI job hangs indefinitely — BLOCKER

- **File:** `.github/workflows/ci.yml:100-105` (the `pytest -m browser` step), `.github/workflows/ci.yml:58` (`timeout-minutes: 75`)
- **Tool:** GitHub Actions log (job `91203326022`, ran 54m30s before manual cancellation)
- **Exact evidence:** last output at `15:55:38` —
  ```
  tests/test_playwright_action_loop.py::test_login_bound_navigation_enters_authentication_stage_before_first_document PASSED [ 70%]
  ```
  then complete silence until `16:47:25` when the run was cancelled by the operator:
  ```
  ##[error]The operation was canceled.
  ```
  The downstream skip-assertion then failed as a consequence:
  ```
  could not read JUnit report: FileNotFoundError
  ##[error]Process completed with exit code 2
  ```
- **Root cause:** the suite stalls at the test immediately following the last pass — `tests/test_playwright_action_loop.py:410 test_loop_reports_hitl_for_a_captcha_page`. Because no JUnit XML is ever written, `scripts/assert_zero_skips.py` fails too — that second error is a symptom, not a separate defect.
- **Blocker:** yes — this job can never go green, and it consumes the full 75-minute budget on every run.
- **⚠ Dependency:** **CI-4 must be fixed first.** Without a per-test timeout there is no diagnostic output to work from — the hang is currently invisible.

### CI-4 · No pytest timeout anywhere in the repo — WARNING (but gates CI-3)

- **File:** `pyproject.toml:15-23` (`[tool.pytest.ini_options]` — no `timeout` setting), `requirements-dev.txt` (no `pytest-timeout`)
- **Tool:** manual config audit
- **Exact finding:** `pytest-timeout` is not installed (`pip list | grep -i timeout` → empty) and `grep -n timeout pyproject.toml` returns nothing.
- **Root cause:** never configured. A hung browser test therefore produces zero diagnostics and burns the entire job budget silently.
- **Blocker:** not by itself, but it is the reason CI-3 is undiagnosable. Fix this first.

---

## Tests

All 8 confirmed real (identical results with and without the security gate's full env-shadowing — **not** `.env` pollution). Ordered by dependency.

### TEST-1 · TOTP leftover in container-hardening test — BLOCKER

- **File:** `tests/test_production_container_hardening.py:262`
- **Tool:** pytest
- **Exact error:**
  ```
  >       assert template_environment["OPS_AUTH_TOTP_SECRET"] == ("replace-with-base32-totp-secret")
  E       KeyError: 'OPS_AUTH_TOTP_SECRET'
  ```
- **Root cause:** same incomplete TOTP migration as CI-1 — the test still asserts the key exists in the `.env.production.example` template, but commit `cd5604f` removed it. Note the test's *other* assertions (lines 252-260, that the API container must **not** receive the secret) are still correct and intentional per `docs/OPERATIONS.md:276-278`; only the template assertion at line 262 is stale.
- **Blocker:** yes — fails the backend gate.

### TEST-2 · Chromium launch env now leaks `DISPLAY`, contradicting its own test — BLOCKER

- **File:** `tests/test_playwright_worker.py:141`; implementation `PlaywrightBrowserWorker._launch_env`
- **Tool:** pytest
- **Exact error:**
  ```
  >       assert headless == safe_environment
  E       AssertionError: assert {'DISPLAY': '...C.UTF-8', ...} == {'HOME': '/tm...in:/bin', ...}
  E         Omitting 9 identical items, use -vv to show
  E         Left contains 1 more item:
  E         {'DISPLAY': ':77'}
  ```
- **Root cause:** commit `8e34657` ("fix: ensure chromium_launch_environment inherits DISPLAY when set") made `_launch_env` pass `DISPLAY` through, but this test asserts the **headless** launch env contains nothing beyond the 9 safe keys. The test is a deliberate secret-boundary check, so this needs a judgment call: either headless should not inherit `DISPLAY` (code bug), or the test's allow-list needs `DISPLAY` for the headed cases only (test bug). **Decide intent before editing either side.**
- **Note:** the test uses `patch.dict(os.environ, ..., clear=True)`, so this is genuinely environment-independent.
- **Blocker:** yes — fails the backend gate.

### TEST-3 · 5 owner-credential-submission failures — BLOCKER · symptom of BE-2

- **File:** `tests/test_owner_credential_submission.py:88` (shared `_entry_reached` helper; 5 tests fail through it)
- **Tool:** pytest
- **Failing tests:**
  ```
  test_owner_submission_vaults_reference_without_claiming_validation
  test_owner_submission_never_persists_raw_value
  test_owner_submission_requires_exact_recipe_fields
  test_owner_submission_after_restart_uses_creation_time_field_schema
  test_owner_submission_cannot_be_replayed
  ```
- **Exact error:**
  ```
  >       assert stored["status"] == "browser_running"
  E       AssertionError: assert 'configuration_required' == 'browser_running'
  E         - browser_running
  E         + configuration_required
  ```
- **Root cause:** **BE-2.** The Telegram run is refused with `plan_surface_not_in_catalog` / phase `plan_refused` before a browser session exists.
- **⚠ Dependency:** do **not** fix these tests directly. Fix **BE-2** and re-run — these should clear on their own. If they do not, the residue is a separate issue.

### TEST-4 · Onboarding end-to-end run pauses instead of completing — BLOCKER

- **File:** `tests/test_onboarding_end_to_end.py:785`
- **Tool:** pytest
- **Exact error:**
  ```
  >       assert outcome.terminal_phase == "completed"
  E       AssertionError: assert 'paused' == 'completed'
  E         - completed
  E         + paused
  ```
- **Root cause:** not yet isolated. The run reaches `awaiting_admission` correctly (earlier assertions pass) and then terminates at `paused` rather than `completed`. Given BE-2 refuses plans in a nearby code path, **re-check this after BE-2 is fixed** — it may share the root cause or may be independent.
- **Blocker:** yes — fails the backend gate. This is the single test asserting the headline "one signup run reaches a validated credential" claim.
- **⚠ Dependency:** re-evaluate after BE-2.

---

## Frontend

### FE-1 · 6 npm advisories, below both gate thresholds — WARNING

- **File:** `web/package-lock.json`
- **Tool:** `npm audit`
- **Exact finding:**
  ```
  npm audit --omit=dev --audit-level=high      EXIT=0   (2 moderate: postcss <=8.5.22 via next)
  npm audit --audit-level=critical             EXIT=0   (no critical)
  npm audit --audit-level=high                 EXIT=1   (6 total: 4 moderate, 2 high — undici)
  ```
  The 2 high advisories are all in `undici` (GHSA-8xcm-r25x-g524, GHSA-4cwx-7wf7-3272, GHSA-m8rv-5g2x-5cg5, GHSA-jr45-8vmc-qm54, GHSA-v3r7-h72x-cjcm).
- **Root cause:** dev-only / non-runtime transitive dependencies. `scripts/security_gate.sh` deliberately runs `--omit=dev --audit-level=high` plus `--audit-level=critical`, with an explicit in-file comment explaining that forcing ESLint 10 would break `eslint-config-next`. **Both configured gates pass.**
- **Blocker:** no — this is the documented, intentional posture. Listed only so the delta is visible. `npm audit fix` reportedly resolves the `undici` ones without a breaking change.

**Everything else in the frontend passes clean:** `tsc --noEmit`, `eslint . --max-warnings=0`, 136/136 vitest tests across 23 files, and `next build` (12 routes, standalone output).

---

## Documentation

### DOC-1 · Readiness counts are stale — WARNING (but a truthfulness defect)

- **Files:** `README.md:96`, `README.md:97`, `docs/APP_RECIPES.md:10`, `docs/APP_RECIPES.md:52-62`
- **Tool:** manual cross-check against the live catalog
- **Exact discrepancy:**
  ```
  docs claim : 25 managed_auth_ready, 1 browser_ready, 13 owner_submit_ready, 4 outreach_ready, 7 outreach_review_required
  catalog has: 25 managed_auth_ready, 7 browser_ready,  7 owner_submit_ready, 4 outreach_ready, 7 outreach_review_required
  ```
  (catalog id `approved-50-routes-2026-07-28`, schema `1.0`; route split 25/14/11 matches the docs.)
  Six recipes — `apify`, `cloudflare`, `coda`, `datadog`, `firecrawl`, `vercel` — were promoted to `browser_ready` but the docs still list them under "Playwright entry plus owner submission" and still assert *"Pipedrive is the only recipe allowed to claim full browser readiness"* (`docs/APP_RECIPES.md:54`).
- **Root cause:** catalog promoted without updating the two documents that describe it. `tests/test_app_recipes.py` validates the catalog against its own expected matrix, so nothing catches doc drift.
- **Blocker:** no — but this repo treats readiness claims as a correctness contract ("Catalog membership is not a claim that every app is fully autonomous or live-verified"), so understating *and* misattributing capability is a substantive defect, not cosmetic.

---

## Untracked files

### UNT-1 · `scripts/verify_console_trace.py` will break the backend gate on commit — WARNING

- **File:** `scripts/verify_console_trace.py`
- **Tool:** `ruff format --check`
- **Exact error:** `Would reformat: scripts/verify_console_trace.py` — `1 file would be reformatted, 310 files already formatted`
- **Other checks:** `ruff check` passes; `mypy` passes (`Success: no issues found in 1 source file`).
- **Root cause:** never formatted. Currently untracked so CI does not see it — but `scripts/security_gate.sh` scans untracked files via `git ls-files --others`, so `make security` fails locally **today**.
- **Other untracked files** (no gate impact): `.qwen/settings.json`, `web/scripts/dev-session-cookie.mjs` (not covered by ESLint's configured scope).

---

## Environmental — not real bugs

These fail only on this macOS host and pass on CI's `ubuntu-latest`. **Do not "fix" them.**

### ENV-1 · 40 failures in `tests/test_transactional_deploy.py` — macOS has no `flock`

- **Tool:** pytest · **Guard:** `scripts/deploy-droplet.sh:210` and `:1037`
- **Exact error:** `[deploy] ERROR: flock is required for production operations.`
- **Confirmed:** `which flock` → not found. 70 occurrences of the message across the suite run. `flock` is util-linux; macOS does not ship it.

### ENV-2 · 14 failures in `tests/test_restore_production_data.py` — BSD vs GNU `stat`

- **Tool:** pytest · **Source:** `scripts/restore-production-data.sh`
- **Exact error:**
  ```
  stat: illegal option -- c
  usage: stat [-FLnq] [-f format | -l | -r | -s | -x] [-t timefmt] [file ...]
  [restore] ERROR: The archive must be a private regular file owned by the restore user.
  ```
- **Root cause:** the script uses GNU `stat -c`; macOS ships BSD `stat`, which spells it `-f`. 20 occurrences across the run; 3 tests in the file still pass.

### ENV-3 · iCloud conflict copies break `tsc` — **[ALREADY CLEANED]**

- **Tool:** `tsc --noEmit`
- **Exact error:**
  ```
  .next/dev/types/cache-life.d 2.ts(3,1): error TS6200: Definitions of the following identifiers conflict with those in another file: unstable_cache, updateTag, revalidateTag, ...
  .next/dev/types/routes.d 2.ts(62,8): error TS2300: Duplicate identifier 'LayoutProps'.
  ```
- **Root cause:** the repo lives under `~/Desktop`, a symlink into iCloud Drive, which creates `" 2"` / `" 3"` conflict duplicates. Those under `web/.next/` were deleted (generated files). **Duplicates remain under `web/node_modules/`** (`enhanced-resolve`, `unbox-primitive`, `siginfo`, `supports-preserve-symlinks-flag`, and others) — currently harmless, but they will reappear in `.next/` and re-break `tsc` after future builds.

---

## Verified-clean (not issues)

Checked explicitly and found correct — recorded so they are not re-investigated:

| Check | Result |
|---|---|
| `ruff check .` | All checks passed (312 files) |
| `mypy ops api browser_service` (strict) | Success: no issues found in **165** source files |
| `python -m compileall ops api browser_service` | clean |
| `bash -n` on all `scripts/*.sh` + `docker/*.sh` | clean |
| `detect-secrets-hook` (463 files vs `.secrets.baseline`) | EXIT=3 (pass) |
| security gate secret grep (1306 candidate lines) | `SECRET GATE: PASS` |
| `ci.yml` replacement keys vs `.env.production.example` | none missing *(after CI-1)* |
| `compose.prod.yaml` `${VARS}` vs example | `APP_REVISION`, `BROWSER_DISPLAY_NUM`, `DISPLAY`, `OPS_DEPLOY_ACCEPTANCE_NONCE` — all runtime-injected, **correct** |
| `deploy-droplet.sh` `OPS_AUTH_TOTP_SECRET` refs (`:1062`, `:1232`) | **intentional** — `\|\| true` migration tolerance + an assertion the API container must *not* receive it; documented at `docs/OPERATIONS.md:276-278` |
| API endpoints probed | `/api/system/health` 200 (3/3 integrity checks pass), `/api/apps` 200, `POST /api/runs` correctly 422s a malformed body, auth correctly 401s without `X-Ops-Internal-Token` |

---

## Suggested fix order

Dependency-respecting order (independent of the bottom-to-top traversal you prefer):

1. **CI-4** (add pytest timeout) → makes **CI-3** diagnosable
2. **BE-2** (plan validator ↔ owner-submit contract) → should clear **TEST-3**, re-check **TEST-4**
3. **TEST-1**, **TEST-2** (independent; TEST-2 needs an intent decision first)
4. **BE-1** (status vocabulary + defensive `_summary` + consider a DB CHECK)
5. **BE-3** (`cryptography` bump + regenerate hash-locked runtime lock)
6. **CI-3** (browser hang — with CI-4's diagnostics in hand)
7. **DOC-1**, **UNT-1** (low risk, no dependencies)
