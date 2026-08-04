# Next session: unblock the login route, and walk the credential tail to the vault

Paste everything below the line into a fresh agent in this repository.

---

Two jobs. Together they turn a demo that shows half an arc into one that shows the
whole thing: pick an app → sign in (or sign up) → **API key lands in the vault**.

Read `semantic-review/autonomous-architecture.md` for the layer model before you
start. Do **not** re-derive the architecture; it is settled.

## Job 1 — the login route is rejected at two validators

`onboarding=True` combined with `account_mode="existing_account"` is refused in two
places:

- `ops/core/models.py:168` — `"autonomous onboarding requires account_mode='create_account'"`
- `api/models.py:340` — `"onboarding is only accepted when account_mode='create_account'"`

This makes the entire "I already have an account → sign in" path unreachable, which
is the primary demo flow. Removing the two raises is necessary but **not
sufficient**. Trace and fix the whole chain:

1. **`profile_onboarding` in `ops/workflow/canonical_runtime.py`** (~line 791) is
   currently `request.onboarding AND account_mode == "create_account" AND (...)`.
   An existing-account onboarding run must also resolve to
   `execution_path="profile_mounted"`, or it silently stays on the legacy path and
   the mounted seam never sees it.
2. **`_is_mounted_request`** (`ops/onboarding/runtime.py`) and
   **`stranded_mounted_run_ids`** (`ops/core/storage.py`) both match on hard-coded
   phase lists. Confirm `route_selected_login` is claimable by both — see Job 3.
3. **`_VaultHandler` → `admit_from_vault`** already routes to
   `route_selected_login` with `credentials_present` when the vault holds a complete
   login pair. Verify that path end to end; the point of Job 1 is that a second run
   for the same app prompts **zero** times.

**Credentials for now come at create time**, through the existing `browser_login`
argument on `create_run` (the new-run form still has the email/password fields). The
mid-run credential dialog is separate Phase B UI work — do not build it here.

**Preserve:** account creation still requires an explicit operator admission
decision. Job 1 must not make signup decidable by a system actor.

## Job 2 — handlers for the credential tail

The walk currently dies after authentication. Wire the remaining phases so a
generated API key actually reaches the vault:

```
authenticated → developer_app → credential_generation → vault_storage
```

`credential_validation → completed` is a bonus if it falls out cheaply; the
must-have is a `vault://` reference for the app's API key.

**Check what already exists before writing anything.** There is a credential
handler under construction — see the comment near `ops/onboarding/runtime.py:890`
("capture threads its own operation key explicitly") and
`ops/onboarding/credentials.py`. Some of this may already be bound. Report what you
found before adding code.

**`api_key_flow` is already a first-class `FlowSpec`** on `ProviderProfile`
(`ops/providers/profile.py:181`, `ops/providers/profile_store.py:99`). You are
wiring an existing flow, not inventing one. Read `FlowSpec.supported` and
`FlowSpec.entry_url` rather than guessing a URL.

**Follow the existing pattern**, do not invent a new one: `SignupPhaseHandler`
(bound at `ops/onboarding/runtime.py:900`) is the reference for how a phase handler
is constructed, takes its vault/effects/binding, and is registered in the handler
map.

Rules for each handler:

- **Reserve the phase's operation key before the provider-visible action.** A
  completed reservation must be adopted and the action skipped — no retry may
  create a second developer app or a second API key.
- **Return a `PhaseStep`. Never write phase history.** `drive_run` is the single
  phase authority; every boundary goes through `validate_phase_transition`.
- **Store through the vault**: `SQLiteSecretStore.put(app_slug=..., kind=...,
  value=...)`, and let only the `vault://` reference cross any boundary. The raw key
  must never appear in a projection, an audit row, or a log line.
- **Human gates still escalate**: CAPTCHA, MFA, billing, legal consent pause for a
  person, unchanged.

## Job 3 — the ordering dependency you must not skip

`stranded_mounted_run_ids` (`ops/core/storage.py`) sweeps a **hard-coded** phase
list: `research`, `vault_check`, `awaiting_admission`, `route_selected_signup`.

The moment Job 2 adds handlers for `developer_app` and `credential_generation`, a
run that crashes in those phases becomes **invisible to the sweep** — no status
change, no log line. Derive the eligible set from the phase vocabulary instead
(non-terminal, non-human-gated), so it cannot fall behind again.

Same check for `_is_mounted_request`'s phase set.

This is not optional cleanup; it lands with Job 2 or Job 2 ships a silent hole.

## Verify

Baseline **before** you touch anything:

```bash
RUN_LIVE_TESTS=0 ./.venv/bin/python -m pytest -q -m "not live and not browser"
```

Current state is **61 failed, 1813 passed** — roughly 54 of those failures are
macOS-only environment noise (`flock` missing, BSD vs GNU `stat`). Capture the
failing set and diff against it. Never assume green; never report "unchanged"
without the diff.

Also: `./.venv/bin/mypy ops api` and `./.venv/bin/ruff check ops api tests`.

**Prove every fix by reverting it and showing the test fail.** A regression test
that passes without the fix is worthless.

### Tooling traps that have already caused wrong conclusions here

- The shell is **zsh**. `grep -rn "x" ops --include=*.py` **errors** with
  `no matches found` — the glob is expanded by the shell. Always quote:
  `--include='*.py'`. A failed search looks exactly like a zero-hit search, and this
  has produced two false "this code does not exist" conclusions in this repo.
- `source .venv/bin/activate` silently falls back to a pytest-less Python 3.14. Use
  `./.venv/bin/python` directly.
- `cmd | tail` reports *tail's* exit status, not the command's.

## Deliver

1. A run for one reviewed Playwright app that reaches a `vault://` API-key
   reference, proven by a test with injected fakes at the existing seams.
2. A second run for the same app that emits **zero** credential prompts.
3. A short note: which phases now have handlers, which still do not, and the
   remaining human touches with the reason each must stay human.

Do **not** run a live browser session against a real vendor as part of this work.
`ALLOW_LIVE_BROWSER` and `ALLOW_LIVE_VENDOR_EMAIL` are set in this deployment's
`.env`, and a live run creates a real account on a real service. Keep everything on
injected fakes; the live smoke test is a separate, deliberate step.
