# Minimum end-to-end: one app, login → API key in vault

Paste everything below the line into a fresh agent in this repository.

---

## The one goal

Make **exactly one** app work end to end, on the login path:

```
create run (app + credentials)
  → agent logs in
  → agent reaches the app's credential page
  → agent obtains the API key
  → key stored as a vault:// reference
  → SECOND run for the same app: zero credential prompts
```

That is the whole job. When those two runs pass, **stop and report** — do not
continue to anything else.

## Pick the app first

Choose **one** Playwright recipe that declares a `credential_management` URL. There
are exactly seven: `pipedrive`, `apify`, `firecrawl`, `vercel`, `cloudflare`,
`datadog`, `coda`.

Pick one, name it in your first message, and make only that one work. A declared
credential URL means you do not have to discover the credential surface — that is
the point of this narrowing. Do not pick an `entry_only` recipe.

## What you may change — and nothing else

1. **The login-route rejection.** `onboarding=True` with
   `account_mode="existing_account"` is refused at `ops/core/models.py:168` and
   `api/models.py:340`. Remove those two refusals, then follow the chain: check that
   `profile_onboarding` in `ops/workflow/canonical_runtime.py` (~line 791) also
   resolves such a run to `execution_path="profile_mounted"`, and that
   `_is_mounted_request` (`ops/onboarding/runtime.py`) and
   `stranded_mounted_run_ids` (`ops/core/storage.py`) both claim
   `route_selected_login`.

2. **Handlers for the phases your chosen app actually walks through**, and no
   others. Likely `developer_app` → `credential_generation` → `vault_storage`.
   Before writing anything, check what already exists: there is a credential handler
   under construction near `ops/onboarding/runtime.py:890` and in
   `ops/onboarding/credentials.py`. **Report what you found before adding code.**
   Copy the shape of `SignupPhaseHandler` (`ops/onboarding/runtime.py:900`).

3. **Whatever else is genuinely on that one app's path** and blocks it.

Credentials arrive at create time via the existing `browser_login` argument on
`create_run`. Do not build a mid-run credential dialog.

`api_key_flow` already exists as a `FlowSpec` on `ProviderProfile`
(`ops/providers/profile.py:181`). Read `FlowSpec.supported` / `entry_url`. You are
wiring an existing flow, not inventing one.

## Explicitly NOT in scope — do not touch

- The signup path, email verification, CAPTCHA handling
- The Strategist / goal-selection tier
- You.com, research adapters, the P1 gate
- `plan_only` cleanup, port identity, credential-surface proof, planner-off-the-event-loop
- Any de-slop, deletion, refactor, or rename
- The 61 pre-existing test failures — **leave every one of them alone**
- Any app other than the one you picked
- Frontend work beyond what the two runs require

## Rules of engagement — these matter more than speed

- **Narrowest change that works.** This is a demo skeleton, not a finished product.
  A hardcoded value with a `# TODO(minimum-e2e)` comment is acceptable when it
  unblocks the one path. A general solution is not required and not wanted.
- **Found a bug that is not blocking your one app? Write it down, do not fix it.**
  Append it to `semantic-review/found-while-building.md` with file:line and move on.
  Fixing it is out of scope even if it is small, even if it is obviously wrong.
- **Do not refactor anything you did not have to change.** No renames, no tidying,
  no "while I was here".
- **Do not improve test coverage** beyond the tests that prove your two runs.
- If you find yourself editing a fifth file, stop and ask whether you are still on
  the path.
- If you are blocked for more than one approach, stop and report the blocker rather
  than working around it in a way that widens scope.

## Non-negotiable even in minimum mode

- Raw credentials and the raw API key never cross a boundary — only `vault://`
  references appear in projections, audit rows and logs.
- Reserve the phase's operation key before any provider-visible action; adopt a
  completed reservation instead of repeating it.
- `drive_run` stays the single phase authority. Handlers return a `PhaseStep` and
  never write phase history.
- CAPTCHA, MFA, billing and legal consent still pause for a human.

## Do not run a live browser

`ALLOW_LIVE_BROWSER` and `ALLOW_LIVE_VENDOR_EMAIL` are set in this deployment's
`.env`. A live run would touch a real vendor with real credentials. **Prove
everything with injected fakes** at the existing seams (`WorkflowDependencies`,
`OnboardingPorts`, `CandidateDecider`, `JsonInference`, the browser worker). The
live smoke test is a separate, deliberate step that the owner will run.

## Verify

Capture the baseline **before** touching anything:

```bash
RUN_LIVE_TESTS=0 ./.venv/bin/python -m pytest -q -m "not live and not browser"
```

It is currently **61 failed, 1813 passed** (~54 of those failures are macOS-only:
`flock` missing, BSD vs GNU `stat`). Save the failing set, diff against it at the
end, and report the diff. Zero new failures is the bar. Never say "unchanged"
without showing the diff.

Then `./.venv/bin/mypy ops api` and `./.venv/bin/ruff check ops api tests`.

Prove your fix by reverting it and showing the test fail.

**Tooling traps that have already produced wrong conclusions in this repo:**
- zsh: `grep --include=*.py` **errors** with `no matches found` unless quoted as
  `--include='*.py'`. A failed search is indistinguishable from a zero-hit search —
  this has caused two false "this code doesn't exist" conclusions here.
- `source .venv/bin/activate` falls back to a pytest-less Python 3.14. Use
  `./.venv/bin/python`.
- `cmd | tail` reports tail's exit code, not the command's.

## Deliver, then stop

1. The name of the app you made work.
2. A test proving run 1 reaches a `vault://` API-key reference.
3. A test proving run 2 emits **zero** credential prompts.
4. The baseline diff.
5. `semantic-review/found-while-building.md` — everything you noticed and did not fix.

Then stop. Do not start the next thing.
