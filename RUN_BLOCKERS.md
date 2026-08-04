# RUN_BLOCKERS.md — actionable checklist to one completed onboarding run

`KNOWLEDGE_BASE.md` is the diagnosis. This file is the ordered work list. Every
symptom below was reproduced in this session; nothing is inherited from the KB
without re-verification. Two KB claims did NOT survive re-checking and are
corrected inline (see B1 and the note under "Corrections").

Baseline for regression comparison, verified 2026-08-02:

```
RUN_LIVE_TESTS=0 ./.venv/bin/python -m pytest -m "not live and not browser" -q
=> 61 failed, 1729 passed, 6 skipped, 82 deselected in 118.33s
```

Failure set (byte-identical to session start; saved to `/tmp/base2.txt`):

| Count | File | Real? |
| --- | --- | --- |
| 40 | `test_transactional_deploy.py` | No — macOS `stat -c` |
| 14 | `test_restore_production_data.py` | No — macOS `stat -c` |
| 5 | `test_owner_credential_submission.py` | Yes, not run-blocking |
| 1 | `test_playwright_worker.py` | Yes — DISPLAY leak, not run-blocking |
| 1 | `test_production_container_hardening.py` | No — stale TOTP test |

`1729` passed rather than the `1705` in the prompt: the difference is the 24
tests added for off-catalog onboarding earlier in this branch. Failure set is
unchanged, so the baseline is the same baseline.

---

## Run-blocking, in order

### - [x] B1. `a2` digest bug — no mounted onboarding run can advance

**Where:** `ops/onboarding/driver.py:2485-2487` (guard),
`ops/onboarding/driver.py:1387-1390` (`_profile_digest`),
`ops/onboarding/runtime.py:367` (`_ResearchHandler`),
`ops/onboarding/runtime.py:805` (`_block_main_run`).

**Symptom observed.** Creating a mounted onboarding run over HTTP returns
**500**, for both off-catalog and on-catalog (`Telegram`, `onboarding=true`).
The run *is* persisted (`execution_path=profile_mounted`, phase `research`);
the failure is in `advance()` afterwards:

```
PhaseNotDrivable: phase 'research' is not drivable:
a phase transition requires a profile digest
  ops/onboarding/runtime.py:761 in advance -> drive_run
  ops/onboarding/driver.py:2487
```

**Verified how.** Direct reproduction, no fakes:

```
$ ./.venv/bin/python -c "<create Telegram onboarding run; MountedOnboardingRuntime.advance>"
ON-CATALOG advance RAISED: PhaseNotDrivable phase 'research' is not drivable:
a phase transition requires a profile digest
```

**CORRECTION to the stated plan — option (b) does not work as described.**
The prompt says `_block_main_run` "already works because it commits through the
phase authority". It does not. `_profile_digest` (`driver.py:1387`) requires a
digest of *exactly* 64 characters, and `commit_phase` runs it at `driver.py:506`.
`_block_main_run` passes `profile_digest=""`, so it raises too:

```
$ ./.venv/bin/python -c "<SQLitePhaseHistoryStore.commit_phase(profile_digest='')>"
empty digest commit RAISED: ValueError profile digest must be a sha256 hex digest

$ ./.venv/bin/python -c "<MountedOnboardingRuntime._block_main_run(run_id, ...)>"
_block_main_run RAISED: ValueError profile digest must be a sha256 hex digest
```

So routing research failures through `_block_main_run` would swap
`PhaseNotDrivable` for `ValueError` — the same 500. The prompt's warning that
`profile_digest=""` is not a fix is correct, and it is correct for a second
reason too: not only does `or` short-circuit on the falsy `""` at line 2485, the
write validator independently refuses `""`.

**What the code already believes.** The empty digest is an established
convention on the *read* side — `AutonomyOutcome.__post_init__`
(`driver.py:1671-1676`):

```python
# Empty is admitted for a run that never got as far as building a
# profile; anything else must be a real content address.
if self.profile_digest:
    _profile_digest(self.profile_digest)
```

And the storage column has no length constraint —
`ops/core/storage.py:1526` is plain `profile_digest TEXT NOT NULL`. So the
durable layer and the outcome layer both already accept `""`; only the write
validator refuses it. The write path is the outlier, not the convention.

**Fix plan (shape (a), applied at the two places that disagree).**
1. Add a digest validator that admits the documented pre-profile empty value,
   and use it *only* at the `commit_phase` write boundary — leaving
   `_profile_digest` strict everywhere a real profile must exist.
2. At `driver.py:2485`, resolve the digest to `""` instead of raising **only**
   when the target phase is one that by construction cannot have a profile
   (`blocked`, `cancelled`). Any other phase missing a digest stays a
   `PhaseNotDrivable` — that would be a real wiring defect.

`research`'s legal targets are `{vault_check, blocked, cancelled}`
(`phase.py:167`), so a research-stage failure can only ever land on the two
phases this admits. `vault_check` is reached only *with* a committed profile.

Diff to be shown before editing — this is shared driver code on the path every
mounted run takes.

**Blocks:** every mounted run, on- and off-catalog. Nothing downstream (B3,
STEP 4, any live run) is reachable until this is fixed.

**FIXED. verified:** the fix needed **four** edits, not one — each was found by
the previous one moving the failure down a layer:

1. `driver.py` — new `_committed_profile_digest(value, *, to_phase)` admitting the
   empty digest only for `_PRE_PROFILE_TERMINAL_PHASES = {blocked, cancelled}`,
   used at the `commit_phase` write boundary. `commit_phase_with_reservation`
   stays strict (reserving an effect implies a session, so a profile exists).
2. `driver.py:2485` — resolve the digest to `""` instead of raising, for those two
   target phases only.
3. `driver.py:2567` — skip the profile-store lookup on an empty digest. This was
   the next failure: `profile_store.get(profile_digest="")` hit the store's own
   content-address check and raised the same `ValueError` one line later.
4. `api/models.py` + `web/src/lib/api-schemas.ts` — new `Sha256DigestOrAbsent` /
   `sha256DigestOrAbsent` for `OnboardingStateView.profile_digest`. This surfaced
   only *because* the fix worked: the boundary now commits, so `_onboarding_state`
   (`api/service.py:1502`) projects it, and `Sha256Digest` demanded exactly 64
   chars. Without this the API returned 500 and the console could not render a
   blocked run at all.

`_ResearchHandler` and `_block_main_run` needed no change — they already pass what
the write boundary now accepts.

Direct `advance()`, both paths:

```
Telegram          -> OK status=blocked phase=blocked reason=research_domain_disagreement
                     boundaries: research>blocked(research_domain_disagreement)
Unreviewed Vendor -> OK status=blocked phase=blocked reason=research_no_evidence
                     boundaries: research>blocked(research_no_evidence)
```

Over HTTP — the original 500 symptom, now gone:

```
ON-CATALOG Telegram onboarding  -> 201  status=blocked phase=blocked reason=research_domain_disagreement
OFF-CATALOG + hint              -> 201  status=blocked phase=blocked reason=research_no_evidence
LEGACY HubSpot no onboarding    -> 201  status=route_selected phase=route_selected
```

(`blocked` is correct in the offline gate: research genuinely cannot reach the
network there. The point is the run now reaches a durable, diagnosable boundary
instead of crashing.)

Gate: `61 failed, 1741 passed, 6 skipped` — failure set byte-identical to
baseline, zero regressions, zero pre-existing failures fixed. New coverage:
`tests/test_pre_profile_boundary.py`, 12 passed, pinning both that the empty
digest is admitted on the two terminal phases and that it is still refused on
`vault_check`/`awaiting_admission`/`route_selected_signup`/`signup`/`completed`
and for a malformed digest.

Frontend: `npx vitest run` → `1 failed | 132 passed`. The one failure
(`new-run-form.test.tsx`, "disables account creation when the selected app lacks
a reviewed signup route") is **pre-existing** — verified by reverting
`api-schemas.ts` to HEAD and reproducing it, then restoring. It belongs to the
uncommitted console work, not to this fix. `tsc --noEmit` reports only
`.next/types/... 2.ts` duplicate-artifact errors, no source errors.

---

### - [x] B2. Configuration — five missing values

**Where:** `.env`, `web/.env.local`.

**Symptom observed.** Verified by reading `.env` directly; every key below is
absent or empty:

```
OPS_INTERNAL_API_TOKEN            = <MISSING/EMPTY>   -> 503 on every /api/*
GMAIL_SIGNUP_ADDRESS              = <MISSING/EMPTY>   -> 409 on create_account
OPS_STARTUP_AUTOMATION_ENABLED    = <MISSING/EMPTY>   -> paused runs never swept
OPS_AUTH_USERNAME                 = <MISSING/EMPTY>   -> console cannot sign in
OPS_AUTH_PASSWORD                 = <MISSING/EMPTY>   -> console cannot sign in
OPS_AUTH_SESSION_SECRET           = <MISSING/EMPTY>   -> console cannot sign in
web/.env.local                    = MISSING           -> console cannot reach API
```

Already correct, left alone: `ALLOW_LIVE_BROWSER`, `BROWSER_PROVIDER`,
`PLAYWRIGHT_IN_PROCESS_SANDBOX`, `ALLOW_LOCAL_CREDENTIAL_SUBMISSION`.

**Fix plan.** Write the values into `.env`; `cp web/.env.example
web/.env.local` and set the same `OPS_INTERNAL_API_TOKEN` in both.
`OPS_AUTH_PASSWORD` must be ≥20 chars — the supplied `Dheeraj@8782` is 12, so
it needs extending before the console will accept it. Leave
`OPS_AUTH_TOTP_SECRET` empty (feature removed in `cd5604f`).

**Blocks:** STEP 4 entirely. The API answers 503 without the internal token, so
no run can be created at all.

**FIXED (with one deliberate exception). verified:** wrote six values into `.env`
and created `web/.env.local` from the example, with the SAME
`OPS_INTERNAL_API_TOKEN` in both. Both files are gitignored and untracked
(`git check-ignore` → `.gitignore:2:.env`, `web/.gitignore:34:.env*`;
`git ls-files .env` → not known to git), so no secret enters the repo.

```
OPS_INTERNAL_API_TOKEN len : 56
GMAIL_SIGNUP_ADDRESS set   : True
startup automation         : False (must be False locally — see B4)
playwright in-process      : True
allow live browser         : True
browser provider           : playwright
```

`OPS_AUTH_PASSWORD=Dheerajjoshi@8782` (17 chars) is accepted: the application
minimum is **8**, at `web/src/lib/auth-session.ts:60`. The 20-character rule the
KB cites is deploy-side only (`scripts/`-enforced, for production), so no padding
was needed for local dev. `OPS_AUTH_TOTP_SECRET` left empty — removed in
`cd5604f`.

**`OPS_STARTUP_AUTOMATION_ENABLED` was deliberately NOT set** — see B4. Setting
it as the prompt asked would have made the first live run impossible.

---

### - [x] B8. The loop denies its own pre-navigation page and stops

**Where:** `ops/onboarding/action_loop.py:702`, `ops/browser/host_policy.py:480`.

**Symptom observed.** With B7 fixed the run advanced past admission into the
browser seam and paused one step later:

```
route: signup    reason_code: operator_approved_signup
onboarding : paused    reason_code: browser_url_not_https_or_malformed
```

`action_loop.py:702` evaluates navigation policy against
`observation.current_url` — "where we actually are". On the FIRST iteration that
is the fresh `about:blank`, which no app allow-list contains:

```
about:blank                allowed=False reason=browser_url_not_https_or_malformed
https://resend.com/signup  allowed=True  reason=host_in_app_policy
```

`not here.allowed` returns `denied_fatal`, so the loop stops before generating a
single candidate — on every run, for every app.

**Verified how.** `evaluate_navigation` called directly with the run's real
allow-list (table above), plus the paused run's own reason code.

**Fix plan (shared driver code — diff below, not yet applied).** Admit the
pre-navigation blank page at the "where we are" check ONLY. The two
`evaluate_navigation` calls in this file answer different questions and only one
is the security boundary:

* `:702` — *where we are*. A blank tab is not a place the agent navigated to; it
  is the absence of a location. `sanitize_browser_url` already admits
  `about:blank` as a representable observation URL.
* `:836` — *where we may go*, checked per candidate before acting. This is the
  load-bearing check and must stay strict. `about:blank` is not a reviewed
  `goto` target, so nothing can navigate TO it.

Why this unblocks rather than spins: `goto` candidates come from
`reviewed_goto_urls` and need no page elements (`candidates.py:577`), and the
signup goal supplies `(profile.signup_url,)` = `https://resend.com/signup`
(`composition.py:333`), which policy allows. The first iteration therefore
navigates to the reviewed signup URL instead of dying.

**Blocks:** the remainder of STEP 4 — signup submission onward.

**FIXED. verified:** `_PRE_NAVIGATION_URLS = frozenset({"", "about:blank"})` plus
`pre_navigation = actions == 0 and observation.current_url in _PRE_NAVIGATION_URLS`
at the `:702` check. `:836` untouched.

Both constraints reproduced before writing the fix. The shared reason code:

```
'about:blank'               allowed=False reason=browser_url_not_https_or_malformed
''                          allowed=False reason=browser_url_not_https_or_malformed
'about:srcdoc'              allowed=False reason=browser_url_not_https_or_malformed
'chrome://settings'         allowed=False reason=browser_url_not_https_or_malformed
'data:text/html,x'          allowed=False reason=browser_url_not_https_or_malformed
'file:///etc/passwd'        allowed=False reason=browser_url_not_https_or_malformed
'about:blank#x'             allowed=False reason=browser_url_not_https_or_malformed
'https://resend.com/signup' allowed=True  reason=host_in_app_policy
'https://evil.com/x'        allowed=False reason=browser_host_not_in_app_policy
```

`actions` is initialized at `:647` and incremented only at `:858`, after a
candidate executes, so `actions == 0` is exactly "before the first navigation".

**Correction to the stated rationale — the exact-match constraint is still
required, but for a narrower reason than "data:/file:// would be admitted".**
`sanitize_browser_url` runs inside `BrowserObservation.__post_init__`, so most of
those URLs can never reach `:702` at all:

| URL | observation construction | reaches `:702`? |
| --- | --- | --- |
| `about:blank` | `'about:blank'` | yes |
| `about:srcdoc` | `'about:srcdoc'` | **yes — the real threat** |
| `about:blank#x` | `'about:blank'` (fragment stripped) | yes, as `about:blank` |
| `""` | raises `ValueError` | no |
| `chrome://settings` | raises `ValueError` | no |
| `data:text/html,x` | raises `ValueError` | no |
| `file:///etc/passwd` | raises `ValueError` | no |

So `data:`, `file://`, `chrome://` and `""` are blocked one layer earlier. What
makes exact matching load-bearing is `about:srcdoc` alone: it survives
sanitization, shares the reason code, and carries attacker-controlled inline HTML.
That single case also rules out an `about:` prefix test, exactly as stated. `""`
is kept in the predicate as defence in depth — it costs nothing and does not
depend on the sanitizer's current behavior.

New coverage: `tests/test_loop_pre_navigation.py`, **11 passed** —
`about:blank` reaches its first action (`goto https://resend.com/signup`, zero
denials); a blank page *after* acting is still `denied_fatal`; `about:srcdoc` is
`denied_fatal` with nothing executed; a disallowed HTTPS host pre-navigation is
`denied_fatal` with `browser_host_not_in_app_policy`; the shared-reason-code
premise is pinned so a refactor cannot silently invalidate it.

Gate: `61 failed, 1752 passed, 6 skipped` — failure set byte-identical to
baseline, zero regressions.

---

### - [x] B11. The signup phase cannot fill a signup form (bypassed, not widened)

**Where:** `ops/onboarding/composition.py:304-311`,
`ops/browser/candidates.py:485-510`, `ops/browser/candidates.py:150`
(`APPROVED_VALUE_REFS`).

**Why this is the next blocker.** B10's attribution (below) says the model
declined. The real Resend signup page shows why it had nothing useful to pick:

```
controls: [Log in with Google] [Log in with GitHub]
          input[type=email]  input[type=password]  [Show value]  [Create account]
text:     "Create a Resend account ... At least 12 characters — not satisfied"
```

A `fill` candidate is only generated for a text/email field when the goal carries
a matching `allow_value_refs` entry (`candidates.py:491`). Two verified facts mean
that can never happen for signup:

1. `composition.py:304-311` builds every phase goal WITHOUT `allow_value_refs`.
   The only wiring anywhere is `driver.py:3553`, `(DEVELOPER_APP_NAME_REF,)`, for
   the `developer_app` phase.
2. `APPROVED_VALUE_REFS` contains no email or password member at all — the 22
   entries are names, URLs, regions and plans (`account_name`, `company_name`,
   `use_case`, `callback_url`, …). Verified by enumerating the frozenset.

So the loop's executable options on a signup page reduce to clicking
`Create account` against an EMPTY form (the page itself says the password rule is
"not satisfied"), or re-navigating. Declining was a defensible model decision, not
a malfunction.

**Deliberately not fixed here.** Signup credentials are generated in the backend
and staged in the encrypted vault (`canonical_runtime.py` `_stage_signup_login`),
and secret injection is the broker's path, not the loop's — `loop_session.py`'s own
docstring says the loop resolves "only APPROVED NON-SECRET value references" and
deliberately withholds the secret store. So the fix is NOT to add an email or
password value ref: that would put credential material on the loop's value path
and cross a boundary the design keeps closed. How the staged signup identity is
meant to reach the form is a design question, and the answer is not in the code
today. **[the absence is verified; the intended mechanism is not]**

**Blocks:** signup submission, and therefore everything after it.

---

### - [x] B10. Signup pauses at the risk gate after the model answers

**Where:** `ops/onboarding/action_loop.py:807` or `:833` (not yet attributed).

**Symptom observed.** With B8 applied the run reached a genuinely new outcome.
Full phase walk, first time ever:

```
1  research              -> vault_check           profile_corroborated
2  vault_check           -> awaiting_admission    signup_authorization_required
3  awaiting_admission    -> route_selected_signup operator_approved_signup
4  route_selected_signup -> signup                operator_approved_signup
5  signup                -> paused                candidate_risk_requires_human
```

`onboarding_navigation_denials`: **0 rows** — B8's fix confirmed on the live path;
this is where the run previously died as `denied_fatal`.

**What the durable evidence establishes.** `onboarding_decision_attempts` has one
row: `phase=signup purpose=action provider=groq outcome=usable latency_ms=712`.
`onboarding_progress_events` has one row: `step_index=1 stage=gate elapsed_ms=725`.
So the loop generated candidates, passed the DLP screen, called the model, and the
model answered usably — then a gate fired. That rules out `:760` (the
"no executable options" gate, which fires with zero model calls) and leaves:

* `:807` — the model returned `report_hitl`, or
* `:833` — the model named a candidate that is not executable.

**Not yet attributed, and not guessed.** Distinguishing the two needs the selected
candidate id, which is not in the tables read so far. `hitl_request` on the run
detail is `null`, and `browser.reason_code` is the generic `human_action_required`.

**A synthetic page did NOT reproduce it** — worth recording so the next session
does not repeat the attempt. Four elements including an OAuth button and a
card-capture button yielded `generated=3 executable=3`, all `risk=low`, so no gate
fired. The real Resend signup page is what differs.

**Latent divergence noticed while checking (unverified as the cause).** `:789`
builds the schema enum from `candidates` (all of them) while `:777` renders the
prompt from `options` (executable only). When those sets differ, the model can name
an id it was never shown, and `:833` then gates it. That is consistent with the
observed outcome but NOT demonstrated to be what happened here.

**ATTRIBUTED. verified: `:807` — the model declined. NOT `:833`.**

The discriminator made this a one-run answer instead of a guess:

```
route      : signup | operator_approved_signup
phase      : paused
GATE CAUSE : candidate_gate_model_declined
```

Durable phase history for `run_00cbc4d6eed24b12b09f997836c31b2a`:

```
1  research               -> vault_check            profile_corroborated
2  vault_check            -> awaiting_admission     signup_authorization_required
3  awaiting_admission     -> route_selected_signup  operator_approved_signup
4  route_selected_signup  -> signup                 operator_approved_signup
5  signup                 -> paused                 candidate_gate_model_declined
```

`onboarding_decision_attempts`: one row, `groq`/`usable`/884ms.
`onboarding_navigation_denials`: 0 rows.

**The `:789`/`:777` divergence is NOT the cause — hypothesis disproved.** It
remains a real latent defect (the schema enum still offers ids whose descriptions
the prompt withholds), but it did not fire here: `:833` would have reported
`candidate_gate_selection_not_executable`. No diff was shown for aligning the two
sets, because nothing observed yet justifies changing the model's choice set.

**Also disproved: my earlier claim that `:760` "fires with zero model calls" made
it the only page-attributable cause.** That is still true, but the reason the
synthetic page did not reproduce anything was different and worth recording:
`generate_candidates` filters elements against `checkpoint_signals` BEFORE it
classifies risk (`candidates.py:435`), so an irreversible control whose name
matches no signal yields ZERO candidates rather than a `requires_hitl` one. With a
matching signal it behaves as documented:

```
delete + matching signal   gen=1 exec=0 risks=['requires_hitl']
billing + matching signal  gen=1 exec=0 risks=['requires_hitl']
mixed page                 gen=2 exec=1 risks=['low', 'requires_hitl']
classify_irreversible('Delete account')      -> (True, 'account_deletion')
classify_irreversible('Add payment method')  -> (True, 'billing')
```

This cost two test failures in the first draft and is the kind of thing that reads
as a product bug when it is a fixture bug.

**Implementation.** Three new members of the closed `OnboardingReasonCode`
vocabulary, and `_gate` now takes a REQUIRED `cause` argument so a future gate site
cannot silently inherit another's meaning:

| site | cause | attributable to |
| --- | --- | --- |
| `:760` | `candidate_gate_no_executable_option` | the page (no model call) |
| `:807` | `candidate_gate_model_declined` | the decision |
| `:833` | `candidate_gate_selection_not_executable` | the schema/prompt divergence |

`candidate_risk_requires_human` is retained: rows written before this change still
carry it, and it stays the fallback when a PAGE names its own human action.

**Storage safety, verified rather than assumed.** New vocabulary members do not
appear in the CHECK lists of a DB created earlier, and only `onboarding_run_plans`
has a rebuild migration:

```
BEFORE onboarding_navigation_denials    missing 3/3
BEFORE onboarding_autonomy_outcomes     missing 3/3
BEFORE onboarding_run_plans             missing 3/3
AFTER  initialize(): navigation_denials missing 3/3
AFTER  initialize(): autonomy_outcomes  missing 3/3
AFTER  initialize(): run_plans          missing 0/3
```

That is safe because a gate cause never reaches either frozen table:

* `onboarding_phase_history` — where a gate's reason actually lands — has **no**
  reason_code CHECK. Confirmed writable with a new code on a copy of the real DB.
* `onboarding_navigation_denials` — refuses the new codes, and never receives them:
  both `telemetry.denial` call sites pass `_host_reason(...)` output, which is
  drawn from host-policy codes only.
* `onboarding_autonomy_outcomes` — refuses them, and is written only when
  `phase in TERMINAL_PHASES`; `paused` is not terminal
  (`TERMINAL_PHASES = {blocked, cancelled, completed}`).

All three codes also satisfy the API/web projection patterns (≤64 chars,
`^[a-z0-9][a-z0-9_:-]{0,63}$`), and the web schema uses an open `safeToken`, so no
frontend change was needed.

New coverage: `tests/test_loop_gate_causes.py`, **8 passed** — each site pinned to
its own cause, `no_executable_option` asserted to occur with zero model calls,
`model_declined` with exactly one, the gated candidate asserted unexecuted, and
`options == executable subset` pinned as the premise the third cause's proof rests
on.

Gate: `61 failed, 1760 passed, 6 skipped` — failure set byte-identical to
baseline, zero regressions.

---

### - [x] B9. `make api` ran the wrong interpreter

**Where:** `Makefile:4,30`.

**Symptom observed.** `make api` → `No module named uvicorn`, exit 2, while
`./.venv/bin/python -m uvicorn ...` worked. `PYTHON ?= python3.11` resolved to a
PATH interpreter with none of the project's dependencies, so every documented
`make` command read as a broken app rather than a broken interpreter choice.

**Fixed. verified:**

```
$ make -n api    -> .venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
$ make -n test   -> RUN_LIVE_TESTS=0 .venv/bin/python -m pytest -q -m "not live and not browser"
$ make -n venv   -> python3.11 -m venv .venv          (bootstrap preserved)
```

`BOOTSTRAP_PYTHON` is kept for `venv` (the venv cannot be its own creator) and
`PYTHON` prefers `.venv/bin/python` when present, falling back to PATH before
`make venv` has run.

---

### - [x] B7. The loop's first observation has no page title, and is rejected

**Where:** `ops/playwright/loop_session.py:369,376,384` (was
`page_title=inspection.title`), `ops/browser/worker.py:173`.

**Symptom observed.** Approving admission returned HTTP 500. The traceback shows
the loop reached **real Chromium on a real page** and died in classification, not
in wiring:

```
action_loop.py:667   seen = await observe(...)
loop_session.py:358  classify_inspection -> BrowserObservation
worker.py:173        ValueError: browser page title is invalid
```

**Verified how.** The loop's first `observe` runs before any navigation, against
a fresh page:

```
fresh page url  : 'about:blank'
fresh page title: ''  -> empty: True
```

`BrowserObservation.__post_init__` rejects an empty title. The real pages are
fine (`'Sign up · Resend'`, `'Resend'`), so this is a first-tick ordering bug, not
a page problem. Note the internal contradiction: `sanitize_browser_url`, in the
SAME `__post_init__`, explicitly admits `about:blank` — one validator accepts the
pre-navigation page while the other rejects the empty title it must have.

**Fix applied.** `_observed_title(inspection)` → `inspection.title or "Untitled
page"`, at all three projection sites in `loop_session.py`. This follows the
convention the codebase already uses three times —
`ops/playwright/worker.py:990` (`"Reviewed public entry"`), `:1020`
(`"Credential page"`), `ops/playwright/gates.py:82` (`"Human action required"`).
`loop_session.py` is the previous dev's new untracked file and omitted it. The
shared validator in `ops/browser/worker.py` was deliberately NOT weakened, and
the label is a constant so it carries no page content.

**verified:**

```
about:blank      -> status=navigating  page_title='Untitled page'
real signup page -> page_title='Sign up · Resend'   (preserved)
```

---

### - [x] B6. You.com Contents displaces the only fetcher that harvests route links

**Where:** `ops/onboarding/runtime.py:586-637` (`_evidence_fetcher`),
`ops/research/operational_research.py` (`FallbackEvidenceContentFetcher`),
`ops/onboarding/runtime.py:143-174` (`_literal_route_claims`).

**Symptom observed.** B5's seeding alone did NOT fix the run — it still blocked
with `research_no_evidence`. Same four documents, same claim harvester, but the
citation counts differ entirely depending on which fetcher produced them:

```
fetcher = _RequestedIdentityFetcher (You.com Contents first):
   login_url   docs=1  FAIL      signup_url  docs=1  FAIL     registrable_domain docs=2 OK
fetcher = _RequestedOfficialFetcher (guarded HTTP only):
   login_url   docs=3  OK        signup_url  docs=3  OK       registrable_domain docs=4 OK
```

`_literal_route_claims` harvests URLs found inside `relevant_text`, and only the
guarded-HTTP parser preserves `<a href>` / `<form action>` targets. You.com
Contents returns rendered PROSE, so the cross-links vanish. Because
`FallbackEvidenceContentFetcher` puts Contents FIRST and falls back only for URLs
Contents *missed*, guarded HTTP never ran for any of the four pages — the fallback
is per-URL, not per-quality.

**Verified how.** Built the exact fetcher `advance()` builds
(`rt._evidence_fetcher(...)`) and ran the real claim harvester over its output,
with `YOU_CONTENTS_ENABLED` true then false. Table above.

**Fix applied.** `YOU_CONTENTS_ENABLED=false` in `.env`. This is a configuration
choice, not a workaround of a required dependency: CLAUDE.md states You.com is
"opt-in, **not a production runtime provider**", and `_evidence_fetcher`'s own
docstring calls guarded HTTP "the floor and ... always what a deployment falls
back to".

**Still open as a code issue (not run-blocking).** A deployment that turns
Contents on silently loses route corroboration. The durable fix is for
`_literal_route_claims` to be fed the guarded-HTTP excerpt regardless of which
fetcher served the document, or for the fallback to prefer link-bearing text.
Filed here rather than fixed because it changes research composition for every
provider.

---

### - [x] B5. Corroboration is unreachable for a two-page provider

**Where:** `ops/onboarding/runtime.py:143-174` (`_literal_route_claims`),
`ops/providers/profile_builder.py:255` (`MIN_CORROBORATIONS = 2`), `:262`
(`_REQUIRED_FIELDS`), `:900`.

**Symptom observed.** The first real API run was created successfully (201, no
500 — B1 confirmed on the live path) but blocked immediately:

```
run_id : run_c6d5b56809ed4101abfebd57d992d8d3
status : blocked   phase: blocked   reason: research_no_evidence
```

Its own audit trail names the cause exactly:

```
field_uncorroborated  login_url    corroborations=1/2
field_uncorroborated  signup_url   corroborations=1/2      (x18, different values)
field_uncorroborated  login_url    required_field_missing
```

**Verified how.** Fetching the two candidate pages under the real policy and
inspecting which URLs each excerpt literally contains:

```
https://resend.com/signup  excerpt_len=491  contains /signup: False  contains /login: True
https://resend.com/login   excerpt_len=383  contains /signup: True   contains /login: False
```

That is the whole problem, and it is structural rather than a tuning issue.
`_literal_route_claims` harvests URLs found *inside* `relevant_text` and never
credits the document's own `source_url`. A signup page does not link to itself,
so:

* `signup_url` is cited only by the `/login` document → 1 citation
* `login_url` is cited only by the `/signup` document → 1 citation

Both are `_REQUIRED_FIELDS`, both need 2 DISTINCT documents, so a provider whose
signup/login pages cross-link exactly once can never corroborate either — no
matter how many discovery adapters run. Perplexity IS configured and did
contribute (18 distinct `signup_url` candidates), but each appeared once, which
is the "many candidates, no agreement" shape rather than a missing-adapter shape.

Compounding it: `https://resend.com/docs/introduction` — the obvious third
document — is refused by `MAX_RESPONSE_BYTES = 256 * 1024`
(`operational_research.py:31,314`), so the natural third citation is unavailable.

**Fix plan.** Seed additional CANDIDATE URLs on the hint's own registrable
domain, so more than one document can cite each route. Verified to work:

```
  fetched https://resend.com/signup          len=491
  fetched https://resend.com/login           len=383
  fetched https://resend.com/about           len=6182
  fetched https://resend.com/contact         len=1779

  registrable_domain   4  OK
  signup_url           3  OK
  login_url            3  OK
```

All three required fields corroborate. This touches no claim semantics, no
`MIN_CORROBORATIONS`, and **does not widen the host policy**: the policy is
derived from the hosts in `static_urls`, and every added URL is on the hint's
already-authoritative registrable domain, so the host set is unchanged.

**Two fix shapes I checked and rejected:**

* *Credit a document's own `source_url` as a claim.* Does not work.
  `_admitted_claims` (`profile_builder.py:775-787`) requires a claim's value to
  occur literally in the cited excerpt, and a signup page does not print its own
  URL — verified: `value == source_url present in own excerpt? False`. The claim
  would be discarded as `value_absent_from_excerpt`.
* *Lower `MIN_CORROBORATIONS`.* Weakens double-corroboration for every provider
  to work around a seeding gap affecting one path.

Also worth noting for N2: `/about` is 245KB and passes the 256KB guard, but
`/docs/introduction` (299KB) and `/pricing` (499KB) do not. The size limit is
doing real work here and should not be raised casually.

**Blocks:** STEP 4. This is now the only thing between the seam and a real
Chromium page — the run reaches `research` and dies there, so the browser phases
are still unexercised.

**FIXED. verified:** added `_SAME_ORIGIN_ROUTE_CANDIDATES` +
`_same_origin_candidates(hint_url)` in `ops/onboarding/runtime.py`, folded into
`static_urls` alongside the hint. Only the hint's scheme+host are reused, so the
resolved host set is provably unchanged:

```
candidates : 4
host set   : {'resend.com'} -> single host: True
```

Necessary but NOT sufficient on its own — B6 was the second half. With both
applied, the real API run reached a corroborated profile (see STEP 4 below).

Gate after this change: `61 failed, 1741 passed, 6 skipped` — zero new failures.

---

### - [ ] B4. `OPS_STARTUP_AUTOMATION_ENABLED=true` blocks every gated write locally

**Where:** `ops/deploy/acceptance.py:55-70` (`_configuration`),
`api/app.py:234-246` (the gate), `api/service.py:696-698`.

**Symptom observed.** This is the opposite of what the prompt expected: enabling
the flag does not unblock paused runs, it **503s every gated write**, including
run creation. `_configuration` returns `None` unless the marker path
`is_absolute()`, and the default is relative:

```
marker path default      : 'private/deploy-acceptance.json'
is_absolute              : False
accepted with automation off : False
accepted with automation ON  : False
=> mutations_allowed with automation ON: False
```

`api/app.py:243` then answers `503` for every gated write. So the flag is a
prerequisite for the background sweep but, at default settings, a hard block on
creating the run in the first place.

**Verified how.** `Settings(ops_startup_automation_enabled=True)` +
`deployment_is_accepted(...)` → `False`, and reading the gate at
`api/app.py:234-246`.

**Fix plan.** Make the acceptance marker path absolute-by-default (resolve the
relative default against the repository root) so acceptance can succeed at
defaults, then enable the flag. Until then it stays unset, which is why B3's
sweep half cannot be tested end to end yet.

**Blocks:** B3's background-sweep half, and the durable resume path. Does NOT
block the first live run, because with the flag unset `mutations_allowed`
returns `True`.

---

### - [x] B3. `paused` is a dead end

**Where:** `ops/onboarding/phase.py:195`, `api/service.py:1568`,
`ops/core/storage.py:2009`.

**Symptom observed.** Three independent mechanisms, all confirmed by reading:

```
phase.py:195   "paused": frozenset({"research", "cancelled"})   # forward = restart only
storage.py:2009 phases = ("research","vault_check","awaiting_admission","route_selected_signup")
                                                                # 'paused' absent -> no sweep
api/service.py:1568  can_resume = waiting and bool(targets - _NON_CONTINUATION_PHASES)
```

A paused run is claimed by `_is_mounted_request` (it lists `paused`), so it
looks alive in the console while nothing will advance it.

**Fix plan.** Add `paused` to the sweep phases, and give it a forward target so
resume is offered instead of only restart-or-cancel. Decide against the legal
transition table rather than by loosening `_NON_CONTINUATION_PHASES` blindly.

**Blocks:** recovery of any run that pauses — which, until the browser seam
lands, is every run that reaches `signup`/`route_selected_login`. Not blocking
the *first* run reaching research, so it sits below B2.

**FIXED. verified.** The whole resume mechanism already existed:
`OnboardingRunControlService.resume_from_pause` (`ops/runs/resume.py:838`) reads
`phase_at_pause` from the last committed boundary and re-enters it. Only the
transition table refused. `captcha_paused` was the working template — it already
fans back out to every phase a challenge can interrupt, and the two waiting phases
differ in WHY they parked, not in what continuing means.

Three edits:

1. `ops/onboarding/phase.py` — `paused` now targets the six drivable phases plus
   `research` (reset) and `cancelled`, i.e. `captcha_paused`'s set minus `paused`
   itself. This does not widen what a resume may DO: `resume_from_pause`
   independently refuses any target the table does not admit, so a run can only
   re-enter a phase it actually stood in.
2. `api/service.py` — `paused` removed from `_NON_CONTINUATION_PHASES`. This is the
   409-at-source fix the old comment asked for: the spurious 409 came from
   `can_resume` reading true while no forward target existed. Now `can_resume` is
   true exactly when `resume_from_pause` will accept.
3. `ops/core/storage.py` — `paused` added to the mounted sweep phases, so a parked
   run is reclaimed by a background worker instead of needing a new run.

```
paused -> signup                   True
paused -> email_verification       True
paused -> authenticated            True
paused -> developer_app            True
paused -> credential_generation    True
paused -> route_selected_login     True
paused -> research                 True
paused -> cancelled                True
paused -> vault_storage            False   <- still refused
paused -> completed                False
paused -> blocked                  False
paused -> awaiting_admission       False
```

Live resume over HTTP: a run parked from `signup` returns **200** and re-enters
`("signup", 2)` — a fresh attempt, not a replay; a run parked from `vault_storage`
still returns **409** `phase_replay_noop` and stays at `("paused", 3)`.

One test needed updating rather than fixing:
`test_resume_route_continues_a_paused_run_through_the_phase_machine` asserted 409
*because* "`paused` fans out to `research` and `cancelled` only" — it pinned the
dead-end itself. It now pins the new contract on both sides: re-entry succeeds for a
legal phase-at-pause and is still refused for an illegal one.

Gate: `61 failed, 1776 passed, 6 skipped` — failure set byte-identical.

---

### Correction: `legal_acceptance` is NOT human-only

Stated wrongly in earlier sessions (by me, more than once). Verified:

```
HUMAN_ONLY_GATES        : account_selection, billing, captcha, device_approval,
                          passkey, phone_otp, provider_verification, security_key,
                          signup_authorization
PROFILE_DECLARABLE_GATES: legal_acceptance          <- sole member
_AUTONOMOUS_RESOLUTION['legal_acceptance'] = 'recipe_declared'
```

`ops/access/gate_policy.py` gives the reason: approving account creation IS
approving the terms that creation is subject to, so the operator's admission
decision already covers it. The autonomous path also already existed —
`resolve_gate(..., profile_authority=...)` returns `profile_declared` when the
decision names the same profile digest, is an operator `signup` route, and the gate
URL is inside the profile's registrable domain. Verified all four cases:

```
resend + matching admission -> profile_declared
resend + digest mismatch     -> human_only
resend + off-domain gate url -> human_only
pipedrive (recipe wins)      -> recipe_declared
```

---

## Capture boundary extraction (done)

`api/browser_secret_broker.py:349` was the ONLY caller of
`SQLiteSecretStore.capture_with_grant`, and `_capture_sync` was the only place a
`value_pattern` gated a vault write — `capture_with_grant` itself applies no pattern.
So the local in-process path had no route from a read value to a vault row at all.

Extracted the validate-then-store body into
`ops/credentials/capture_boundary.py::capture_validated_credential`, which both
transports now call. This preserves the property the old comment asserted — "re-apply
the recipe's exact value contract at the API/vault boundary so a compromised worker
cannot persist arbitrary material" — and makes it *more* checkable, because one
function provably serves both paths instead of two that could drift.

Two constraints held deliberately:

* **No parameter can skip the check.** No `validate: bool`, no optional pattern, no
  trusted-caller flag. The order is fixed: resolve the field from the spec, then
  `re.fullmatch` the whole value, then store.
* **One refusal for all three failure modes** (`CaptureRefused`): unknown field,
  pattern mismatch, refused grant binding. The broker translates it to its own
  `BrowserCaptureNotAuthorized` so the RPC response vocabulary is unchanged.

**verified** — refusals write nothing:

```
valid api key       : STORED  writes=1
too short           : REFUSED writes=0
key + trailing text : REFUSED writes=0
unknown kind        : REFUSED writes=0
```

Gate: `61 failed, 1776 passed, 6 skipped` — byte-identical failure set.

### Known gap: `arm_credential_surface` does not revoke live-view grants

Its protocol docstring (`ops/onboarding/credentials.py:789-797`) says arming
"revoke[s] every live-view grant issued before now". **Nothing in the codebase revokes
anything** — `grep revoke` finds only a status enum value that nothing sets, plus
prose. So that half of the postcondition is not delivered.

Recorded rather than asserted, deliberately: a comment claiming a fact the code does
not deliver is worse than a documented gap, and it is the same defect class as
`PlanRefusalDetail`'s ten never-read values. The implementation's docstring states
what is actually true — it gates on the postcondition and does not revoke.

Exposure: local runs are loopback-only, so this matters on the production RPC path,
which is already covered by N2.

---

## Second half — signup submit through credential validation

Nothing below has ever executed. Verified state of the vault before any of this
work (the claim was "`secrets` table missing"; the real shape is that the table
exists under a different name and is empty):

```
private/secret_vault.db tables: vault_entries, staged_signup_logins,
                                staged_existing_logins, gmail_message_ingestions,
                                browser_secret_grants
vault_entries          rows=0     <- no credential was ever captured
staged_signup_logins   rows=125   <- staging DOES work, 125 times over
browser_secret_grants  rows=0     <- no grant was ever issued
gmail_message_ingestions rows=0   <- no verification email was ever read
```

So the boundary is exact: credential *staging* works and everything past it is
untouched.

### Phase-by-phase drivability

`_drive_phase` (`driver.py:5143-5157`) dispatches in one order: a registered
handler wins, then the mailbox path for `email_verification`, then the loop —
and a phase absent from `PHASE_SUCCESSORS` (`driver.py:1525`) raises
`PhaseNotDrivable` before the loop is reached.

| phase | in `PHASE_SUCCESSORS` | loop goal | handler registered | drivable today |
| --- | --- | --- | --- | --- |
| `signup` | yes → `email_verification` | yes | no | loop only — declines (B10/B11) |
| `email_verification` | yes → `authenticated` | yes | no | falls back to loop; mailbox path unwired |
| `authenticated` | yes → `developer_app` | yes | no | loop runs, postcondition unreachable (S4) |
| `developer_app` | yes → `credential_generation` | yes | no | pauses `flow_unsupported` (S3) |
| `credential_generation` | yes → `vault_storage` | yes | no | unreachable |
| `vault_storage` | **no** | **no** | no | **`PhaseNotDrivable`** |
| `credential_validation` | **no** | **no** | no | **`PhaseNotDrivable`** |

**Correction to the brief:** `vault_storage` and `credential_validation` *are*
present in the legal transition table `_LEGAL_PHASE_TRANSITIONS` (`phase.py:166`)
with real successors — `vault_storage → credential_validation → completed`. What
they lack is a `PHASE_SUCCESSORS` entry and a loop goal, and `PHASE_SUCCESSORS`
lives in `driver.py:1525`, not `phase.py`. The transitions are legal; the driver
just has no way to drive them. Verified:

```
vault_storage          successors ['cancelled','credential_validation','paused']  loop_goal False
credential_validation  successors ['cancelled','completed','credential_generation','paused']  loop_goal False
```

### Port binding — what production actually has

`build_onboarding_ports` binds more than expected. Verified against
`Settings.from_env()`:

```
verification     BOUND: GmailVerificationProvider
vault            BOUND: SQLiteSecretStore
validator        BOUND: ProfileBoundCredentialValidator
plans/planner/plan_validator/adherence/inference/decider/goals  all BOUND
unavailable: {'research': 'research_adapters_unavailable'}
```

And on the composed `deps` the mounted runtime actually builds:

```
effects   BOUND: SQLitePhaseHistoryStore     outcomes  BOUND: LedgerAutonomyOutcomes
vault     BOUND: SQLiteSecretStore           pauses    BOUND: SQLitePhaseHistoryStore
verification BOUND: GmailVerificationProvider
verification_binding  None      <- the ONLY thing _verification_is_wired lacks
logins                None
```

Seven adapters are Protocol-only with **zero** implementations anywhere in `ops/`
(verified by grep for non-Protocol references): `SignupRunBinding`,
`SignupMailboxBinder`, `SignupSubmitter`, `DeveloperAppBinding`,
`VerificationBinding`, `CredentialSurfaceSession`,
`ProviderConfigurationPublisher`.

`OnboardingDeps` has **no** credential-lifecycle field at all —
`capture_store_validate_publish` takes its own `CredentialLifecycleDeps`
(`journal, effects, vault, validator, publisher, budgets, research_endpoint,
grant_ttl_seconds, retry_delay_seconds, clock`) and its only callers today are
two tests. So step 3 needs a handler that composes those deps, not a port on
`OnboardingDeps`.

---

### - [x] S1. `verification_binding` is never passed to `deps_for()`

**Where:** `ops/onboarding/runtime.py:775-779`, `driver.py:5186-5200`
(`_verification_is_wired`), `composition.py:506-515` (`deps_for` accepts it).

**Symptom (verified).** The mounted runtime passes only `sessions=` and
`handlers=`. `_verification_is_wired` needs all three of
`verification_binding`, `vault`, `verification`; the latter two are bound, so the
binding alone is what makes `email_verification` fall back to the generic loop
instead of the mailbox path. `_drive_verification` (`driver.py:5203`) is already
written and never reached.

**Fix plan.** Build a `VerificationBinding` over the run's existing
`PlaywrightLoopSessions` session and pass it. Session identity is the
requirement (R7.30, "continue on the same Browser_Session_ID") and the factory
already satisfies it — verified: same run two phases → `a is b` True, different
run → False.

**Blocks:** `email_verification`, and therefore everything after it.

**DONE. verified:**

```
BEFORE (no binding): _verification_is_wired = False
AFTER  (binding)   : _verification_is_wired = True
binding satisfies protocol verbs        : True
session satisfies VerificationSession   : True
```

Two parts, because the stated scope ("one arg plus one flag") assumed a seam that
did not exist — see the ordering note above.

**The shared browser seam.** `PlaywrightLoopSession` had only
`['_observation', 'act', 'observe', 'session_id']`; `VerificationSession` needs four
members. Added:

* `ops/playwright/worker.py` — `fill_secret_for(context, *, element_index,
  inspection, resolve)` and `navigate_resolved_for(context, *, resolve)`. Both take
  a `resolve` callable, invoke it exactly once, and pass the result straight into
  Playwright as a single expression. Same confinement the reviewed candidate path
  already uses at the `locator.fill(_approved_or_raise(), ...)` call in that module,
  so this is an established local pattern rather than a new one.
* `ops/playwright/loop_session.py` — `GrantedSecretConsumer` (the transport
  boundary), `fill_from_grant`, `inject_one_time_code`,
  `navigate_verification_link`. The factory threads `secrets` and `allowed_hosts`
  into every per-run session, so signup's fill and verification's injection share
  one grant path and one allow-list.

Value discipline, as required: signatures are `(reference, kind, grant)` and return
`None`; nothing binds, stores, logs, or returns a value; a target is chosen by
element index from the bounded inspection so no selector string crosses. Both
optional ports fail CLOSED when absent (`secret_consumer_unavailable`,
`verification_allow_list_unavailable`) rather than degrading to a weaker check.

`navigate_verification_link` performs the allow-list check **explicitly** via
`evaluate_navigation`, with the docstring stating why it is not borrowed from the
candidate path: a provider-issued magic link is not a model-chosen candidate, and
`NAVIGATION_ACTIONS` covers candidates only. Routing it through the candidate path
to inherit that guard would misrepresent it as a planned action.

The in-process exception is documented on `GrantedSecretConsumer`: where the
plaintext materialises is a property of the TRANSPORT. On the RPC path the browser
container resolves the grant and this process holds only the triple; in-process
there is no second process by definition, so the single-expression confinement is
the whole mitigation — and the comment says explicitly that it is not the enforcing
mechanism and must not be lifted into `browser_service/`.

**The binding (`_RunVerificationBinding`).** Reads `session_id` and
`browser_account_ref` from the run's ledger row and the signup address from the
staged pair via `vault.get_staged_signup_login_pair` — Fernet-decrypted through the
vault, not readable from raw SQL. A comment records why it reads there rather than
from `SignupMailboxBinder` (that binder's durable store does not exist yet; the
staged pair is the same fact, keyed by exactly `(app_slug, account_ref, run_id)`)
and that the two must never disagree. Fails closed if the staged address is missing
rather than falling back to the configured address — a context bound to an address
this run did not sign up with is how one run consumes another's code.

Bound to the same session factory the loop uses, so verification continues on the
session signup submitted (R7.30). A transportless run (`_NoBrowserSessions`) is
offered no binding and keeps its honest pause.

Gate: `61 failed, 1776 passed, 6 skipped` — byte-identical failure set.

**One self-inflicted regression, caught and fixed.** Extending
`_with_operator_credential_surface` to fill `developer_portal_url` (the S4 fold-in)
broke my own S3 test, which asserted exactly two slots: `62 failed` with
`test_one_declaration_fills_both_flow_slots` as the single new failure. Renamed to
`test_one_declaration_fills_three_slots` and updated to pin all three slots plus
their operator attribution. Also note: an earlier gate run used `tail -60`, which
truncated the FAILED list and produced two bogus "FIXED" entries — always capture
the full list with `grep -E '^FAILED|passed|failed'`.

### - [ ] S2. `ALLOW_LIVE_VENDOR_EMAIL=false`

**Symptom (verified).** `allow_live_vendor_email: False`, while
`gmail_signup_address` and `composio_gmail_connected_account_id` are both set.
So the mailbox provider is configured but hard-off, per the live-flag invariant.

**Fix plan.** Set it to `true` in `.env` immediately before the first live
verification run, and run exactly one run at a time — concurrent runs share one
mailbox and could pick each other's code.

**Blocks:** S1's path actually reading a message.

### - [x] S3. The committed profile declares no credential flow at all

**Where:** `ops/providers/profile_builder.py:274-287`, `driver.py:3501-3524`
(flow-pair selection), `driver.py:3323` (`flow_unsupported`).

**Symptom (verified).** The real committed Resend profile
(`086dd1bc…`) carries only two URLs and **all four flows unsupported**:

```
signup_url       : https://resend.com/signup
login_url        : https://resend.com/login
developer_portal : None
developer_docs   : None
developer_app_flow  supported=False entry_url=None
oauth_flow          supported=False entry_url=None
api_key_flow        supported=False entry_url=None
pat_flow            supported=False entry_url=None
operational_urls(): ('https://resend.com/signup', 'https://resend.com/login')
```

The selector returns `None` the moment `developer_app_flow.supported` is false,
so `developer_app` pauses `flow_unsupported` and reserves nothing. Consequently
`_reviewed_urls` yields `()` for `email_verification`, `authenticated`,
`developer_app` and `credential_generation` — those phases get **no** `goto`
candidate, which is the same starvation shape as B11 one layer later.

This is not a wiring bug. Research only claims a flow when a corroborated
document names its entry URL, and Resend's signup/login pages do not link to
`/api-keys`. **This is the deepest issue in the second half**: even with S1, S2
and the adapters done, the walk stops here.

**DECIDED: operator-supplied `credential_surface_url`**, gated by the same
`onboarding_hint_domain` function that gates `provider_hint_url`. Rationale:
nothing past `developer_app` has ever executed (`vault_entries=0`,
`browser_secret_grants=0`, `gmail_message_ingestions=0`), so the whole downstream
is unknown; adding an autonomous discovery mechanism at the same time would mean
debugging two unknowns at once.

**Why same-origin seeding (the B5 mechanism) was rejected — verified, and NOT for
the reason first assumed.** The pages are not 404s; they fetch successfully and
carry no usable content pre-auth:

```
https://resend.com/api-keys           OK len=383 mentions_api_keys=False
https://resend.com/settings/api-keys  OK len=383 mentions_api_keys=False
https://resend.com/dashboard          404
https://resend.com/docs/api-reference/introduction  exceeds 256KB size limit
```

383 chars is the same excerpt length as the login page, i.e. these paths render
login content to an unauthenticated fetch. So seeding them yields a fetched
document with no `/api-keys` claim in it, and the flow stays `supported=False`
anyway.

**Correction to the stated rationale:** the obstacle is NOT "two successful
fetches are unobtainable". Flow fields are absent from `_REQUIRED_FIELDS`, so a
flow entry URL needs only **1** citation, not `MIN_CORROBORATIONS = 2` — verified:

```
_REQUIRED_FIELDS : ['login_url', 'registrable_domain', 'signup_url']
flow fields      : api_key_flow, developer_app_flow, oauth_flow, pat_flow  -> 1 citation each
```

The obstacle is that no pre-auth fetch of those paths contains the URL to cite.

**Why the operator URL cannot enter as a research claim.** `_admitted_claims`
(`profile_builder.py:786`) discards any claim whose value does not occur literally
in a fetched excerpt (`value_absent_from_excerpt`), and `_flow_spec` (`:999`) marks
a flow `supported=True` only with a `FieldEvidence`. So the URL must enter as an
explicit operator declaration, recorded as adapter `"operator"` with
`corroborations=1`, rather than being dressed up as corroborated research.

**Blocks:** `developer_app`, `credential_generation`, and everything after.

**IMPLEMENTED. verified.** `credential_surface_url` on `CreateRunRequest` /
`OperationsRequest`, validated by the same `validate_operational_url` as
`provider_hint_url` and gated at the mounted runtime by the same
`onboarding_hint_domain` check. Threaded
`api/service.py` → `OperationsRequest` → `runtime.py` (`_ResearchHandler`) →
`build_profile(credential_surface_url=...)` →
`_with_operator_credential_surface`.

Recorded as a declaration, never as research —
`_operator_declared_evidence` sets `adapters=("operator",)`, `corroborations=1`,
and cites itself, so a reader of the committed profile can tell it from a
corroborated excerpt without consulting anything else:

```
1. on-domain admitted, off-domain refused
   https://resend.com/api-keys       -> evidence(adapters=('operator',), corrob=1)
   https://app.resend.com/api-keys   -> evidence(adapters=('operator',), corrob=1)
   https://evil.com/api-keys         -> REFUSED
   http://resend.com/x               -> REFUSED
   https://resend.com.evil.io/x      -> REFUSED
2. one declaration fills BOTH flow slots -> ['api_key_flow', 'developer_app_flow']
3. corroborated research WINS            -> https://resend.com/researched
4. off-domain declaration changes nothing -> (none)
5. developer_app_flows: BEFORE None -> AFTER SELECTED creation=developer_app credential=api_key
```

Item 2 is load-bearing and was not in the original plan: `developer_app_flows`
selects a **pair** and returns `None` unless `developer_app_flow.supported` holds
as well as the credential flow's, so filling only `api_key_flow` would have left
`developer_app` pausing `flow_unsupported` and changed nothing. Verified directly:
`developer_app_flows(api_key only) -> None`, `(both) -> SELECTED`.

Gate: `61 failed, 1776 passed, 6 skipped` — failure set byte-identical, zero
regressions. New coverage: `tests/test_operator_credential_surface.py`, 16 passed.

**S3 alone does NOT unblock the walk — two gaps remain, verified after the change:**

```
reviewed_goto_urls           BEFORE -> AFTER
  authenticated              ()     -> ()                              <- still starved
  developer_app              ()     -> ('https://resend.com/api-keys',)
  credential_generation      ()     -> ('https://resend.com/api-keys',)

expectations_for(profile)                     : None ()                <- still empty
expectations_for(profile, credential_url=URL) : ('resend.com','/api-keys') ()
```

* `authenticated` still gets no `goto` URL: its source is `developer_portal_url`,
  which research did not corroborate and this declaration does not set. It will
  depend on S4 (or on the post-login page's own links — the S3 follow-up).
* **S4 needs the credential URL passed as a SEPARATE argument.** Handing
  `expectations_for` the profile alone still yields an empty
  `credential_surface`; only `expectations_for(profile, credential_url=...)`
  populates it. `console_urls` stays empty either way, because it reads
  `developer_portal_url`/`developer_docs_url`.

### - [ ] S3 follow-up. Autonomous credential-surface discovery (do AFTER the chain is proven)

The real autonomous answer, deliberately deferred until the full walk works with an
operator-supplied URL. Cheaper than a first estimate suggests, but for a different
reason than "`_tier_href_path` already resolves link candidates" — that function
(`candidates.py:225`) is an identity RESOLUTION tier, used to re-find an
already-chosen element in a fresh DOM, not a candidate source.

**What actually makes it cheap (verified).** Anchors already become ordinary
`click` candidates, so no new candidate-source machinery is needed:

```
signals=('API Keys',)  -> 1 candidate: [('click','API Keys','low')]
signals=()             -> 2 candidates: [('click','API Keys','low'), ('click','Settings','low')]
```

The whole lever is the signal filter at `candidates.py:435`: add the right signals
to the `authenticated`/`developer_app` goal prose in `ProfileGoals._PROSE` and the
in-app navigation links become selectable.

**One thing to know before building it.** `NAVIGATION_ACTIONS` is `{"goto"}` only
(verified), so a link *click* does NOT pass through the per-candidate navigation
check at `action_loop.py:836`. It is caught one tick later by the where-we-are
check at `:702`, against the same allow-list. The boundary still holds, but
post-hoc rather than pre-emptively — worth deciding deliberately whether a
link-click that leaves the allow-list should be refused before it executes.

### Ordering change — the agreed S1→S6 sequence assumed a seam that does not exist

`S1` was scoped as "one arg plus one flag". It is not: building a
`VerificationBinding` requires a `VerificationSession`, and that protocol has FOUR
members while `PlaywrightLoopSession` has one of them:

| `VerificationSession` requires | `PlaywrightLoopSession` has |
| --- | --- |
| `session_id` | yes |
| `observe()` | yes (returns `LoopObservation`, correct type) |
| `navigate_verification_link(link: SecretStr)` | **missing** |
| `inject_one_time_code(reference, kind, grant)` | **missing** |

Verified: its verbs are exactly `['_observation', 'act', 'observe', 'session_id']`.
The worker has no public equivalent either — `navigate_onboarding` is a 9-parameter
recipe flow and `_inject_credentials` is private and takes a plaintext
`Mapping[str, str]`, which is the wrong shape for a grant-backed fill.

Those same two verbs are what `SignupSubmitter` (S5) needs. So the order is now:

**shared browser seam → S1b (binding) → S5 (adapters)**

rather than S1 → … → S5. Building a verification-only adapter first would mean
writing grant-backed secret handling twice and refactoring it the second time,
which is the worst place to do rework.

Everything downstream of the seam is already present, verified:
`vault.put_transient`, `vault.reserve_browser_secret_grant`,
`vault.consume_transient_with_grant`, broker `POST /consume`, and `deps.vault` /
`deps.verification` both BOUND in production.

### - [x] S4. `expectations_for(None)` makes `authenticated` unsatisfiable

**Where:** `ops/onboarding/runtime.py:582`, `loop_session.py`
(`classify_inspection`), `action_loop.py` (`_AUTHENTICATED_STATUSES`).

**Symptom (verified).** The mounted runtime builds its session factory with
`expectations=expectations_for(None)`, which yields
`credential_surface=None console_urls=()`. `classify_inspection` can then only
ever return `navigating`, and the `authenticated_session` postcondition requires
a status in `{developer_console_ready, credential_page_ready}`:

```
expectations_for(None): credential_surface=None console_urls=()
classified status for https://resend.com/api-keys : navigating
authenticated_session predicate holds             : False
```

So `authenticated` and `email_verification` (whose postconditions include
`authenticated_session`) can never report `done` on this path, independent of S3.

**RESOLVED — but NOT by passing expectations alone. My original fix plan was
wrong, and the correction matters.**

I assumed recognition was sufficient: the browser is already on a post-auth page,
so populating `expectations_for` would let `authenticated` report `done`. It would
not. `run_action_loop` never checks postconditions against the FIRST observation —
`check_postconditions` is called at exactly one place, `action_loop.py:898`,
strictly AFTER `session.act` at `:892`. The order per iteration is budget → allow
list → candidate generation → DLP → model call → act → *then* verify. There is no
early exit for an already-satisfying page.

So `authenticated` needs **two** independent things, not one:

1. at least one executable candidate per iteration, and
2. a post-action observation whose URL folds to `credential_surface` (plus a
   `secretish` label) or to a `console_urls` entry.

With zero candidates the loop takes `action_loop.py:750-754` — no model call, no
action, `no_progress += 1` — and after `MAX_NO_PROGRESS = 6` ticks ends
`exhausted` / `loop_no_progress_budget_exhausted`. The `goto` branch
(`candidates.py:576-593`) is the ONLY element-independent candidate source, so on a
post-signup page whose control names miss `goal.signals`, a reviewed `goto` URL is
the only way to get (1).

**Both are satisfied by declaring the operator surface as the developer portal as
well.** Verified end to end:

```
flows only      authenticated_goto=()   console_urls=()                     status=navigating           postcond=False
flows + portal  authenticated_goto=('https://resend.com/api-keys',)
                console_urls=(('resend.com','/api-keys'),)                  status=developer_console_ready postcond=True
```

`developer_portal_url` is what feeds BOTH `_reviewed_urls("authenticated")` (giving
the goto) and `console_urls` (giving the recognition), so one declaration closes
both halves. Note `developer_console_ready` needs no credential labels, while
`credential_page_ready` does — so recognising it as the console is the more robust
of the two paths.

Consequence for S3's implementation: `_with_operator_credential_surface` should
also fill `developer_portal_url` from the declaration when research corroborated
none. That is a strict extension of what already shipped and is folded in with the
seam work.

### - [x] S5. Four signup adapters have no implementation

**Where:** `ops/browser/signup.py:1485` (`SignupRunBinding`), `:1492`
(`SignupMailboxBinder`), `:1504` (`SignupSubmitter`), `driver.py:3444`
(`DeveloperAppBinding`).

**Symptom (verified).** Protocol-only, zero implementations in `ops/`. The
already-written pieces they plug into are real:
`generate_signup_credentials` (`signup.py:1527`),
`stage_signup_credentials` (`signup.py:1545`),
`SignupPhaseHandler` (`signup.py:1694`),
`DeveloperAppPhaseHandler` (`driver.py:3633`).

Protocol shapes confirmed by introspection:
`SignupIdentity(account_ref, session_id, signup_address)`,
`SignupSecretFill(field, kind, reference, grant)`,
`SignupSubmission(status, human_action_type, receipt)`.

**Fix plan.** Implement the four over `PlaywrightLoopSession`, register
`SignupPhaseHandler` under `"signup"` so the handler — not the loop — owns the
phase, keeping the effect-ledger single-submit guarantee. `submit_signup` must
resolve values inside the browser process via the broker grant; the adapter never
sees a value.

**Blocks:** signup submission — the first thing that has never run.

### - [x] S6. `vault_storage` and `credential_validation` need handlers

**Where:** `driver.py:1525` (`PHASE_SUCCESSORS`), `credentials.py:855`
(`capture_store_validate_publish`), `:832` (`CredentialLifecycleDeps`).

**Symptom (verified).** Absent from `PHASE_SUCCESSORS` and from
`ProfileGoals._PROSE`, so `_drive_phase:5152` raises `PhaseNotDrivable`. These are
I/O steps, not page walks, so a handler is correct rather than a loop goal.

**Fix plan.** Register handlers that call `capture_store_validate_publish` with a
composed `CredentialLifecycleDeps`. `validator` is already bound
(`ProfileBoundCredentialValidator`); `CredentialSurfaceSession` (`:779`) and
`ProviderConfigurationPublisher` (`:809`) still need implementations.

**Blocks:** the credential ever reaching the vault — i.e. the goal.

### Ordering note for confirmation

S1+S2 are small and independent. S5 is the largest but self-contained. **S3 is
the one that decides whether the rest is reachable at all**, and it is the only
item needing a design decision from you — so I would resolve S3's direction
before building S5, rather than after.

---

## Not run-blocking — after a run completes

### - [ ] N1. 5 × `test_owner_credential_submission` failures
Plain playwright runs end `configuration_required`, expected `browser_running`.
KB's stated root cause (an `owner_submit_ready` credential-surface
contradiction) is **unverified** — treat as unknown until reproduced.

### - [ ] N2. Production RPC contract breaks
`ResumeRequest.research` 18 missing fields; `setup_fields` cap 20 vs client 22;
`recipe_snapshot` optional-vs-required. Only bite when
`PLAYWRIGHT_IN_PROCESS_SANDBOX=false`, i.e. not on the local path STEP 4 uses.
Fix `_reason` (`service_client.py:238`) first or these debug blind.

### - [ ] N3. DISPLAY leak
`ops/browser/process_hardening.py:75-81` takes `headless` and never reads it, so
a headless Chromium inherits the host `DISPLAY`. Has a failing test.

### - [ ] N4. Stale TOTP test
`tests/test_production_container_hardening.py` + `compose.prod.yaml:58` still
reference `OPS_AUTH_TOTP_SECRET`, removed in `cd5604f`.

### - [ ] N5. `stat -c` portability
`scripts/{backup,restore}-production-data.sh` use GNU `stat -c`; macOS rejects
it. Recovers 54 local failures.

### - [ ] N6. Protect the P1 lock from formatters
`data/p1/results.json` is byte-exact SHA-256 locked. A whitespace-only
format-on-save breaks every P1 read with `SnapshotIntegrityError`. This already
happened once in this branch. Verified currently intact:
`p1 hash matches lock: True`. Needs a formatter exclusion — check what the repo
actually uses before adding one.

---

## Corrections to KNOWLEDGE_BASE.md

- **P1 hash lock is not a blocker for app #51.** KB already self-corrects this
  at the "Coverage" section; the earlier claim above it is wrong. All 100 apps
  are in `data/p1/results.json` and the bound is `max_length=100`.
- **`_block_main_run` is not a working path.** KB and the prompt both treat it
  as usable for pre-profile failures. It raises `ValueError` on its own
  `profile_digest=""`. See B1.

## Handler registration and capture (done) — and the one blocker left

### S5 / S6 resolved: the second half is now wired

`ops/onboarding/adapters.py` implements every previously protocol-only port, and
`MountedOnboardingRuntime._effectful_handlers` registers three handlers:

| Phase | Handler | Why a handler and not the loop |
| --- | --- | --- |
| `signup` | `SignupPhaseHandler` | reserves `signup_submit`; the loop alone never reserves, so a retry signs up twice |
| `developer_app` | `DeveloperAppPhaseHandler` | reserves `create_dev_app` |
| `credential_generation`, `vault_storage`, `credential_validation` | one `CredentialPhaseHandler` | reserves `generate_credential` |

Verified by construction: **one** `SQLiteEffectStore` across all three, and **one**
`CredentialPhaseHandler` instance for the three credential phases — the lifecycle
commits `vault_storage` and `credential_validation` itself via `STORAGE_BOUNDARIES`,
so a second handler for either would race a boundary the first already wrote.

The runtime comment claiming a handler for these phases "would BYPASS the loop" was
**wrong for these three** and is corrected in place: each reviewed handler's own
docstring says it is meant to be registered, and `drive_developer_app` calls
`run_action_loop` internally — the reservation wraps the loop rather than replacing it.

### Capture: broad read, anchored write

`SessionCredentialSurface` replaces `DeferredCredentialSurface`. Read is broad
(every `secretish` visible element, index-addressed, no selector strings); the write
goes through `capture_validated_credential`, which re-applies the checked-in anchored
pattern. More than one passing candidate → refuse, which the caller turns into a
pause. 12 tests in `tests/test_credential_capture_boundary.py`, all three key
invariants mutation-checked (removing the pattern gate fails 5; picking the first of
two ambiguous candidates fails 1; making arming unconditional fails 1).

One correction to the read side: `read_pattern_matched_values_for` used
`pattern.search` on free text, which **can never match** an `\A`/`\Z`-anchored
pattern. It now splits text into whitespace tokens and `fullmatch`es each, so a key
inside a sentence is readable and every returned value is a whole-string match for
the exact pattern the write re-applies. Stripping the anchors instead would have
applied a weaker pattern on the read than on the write.

`resolve_capture_contract` (in `ops/onboarding/capture_specs.py`) now holds the
reviewed-recipe-then-profile authority order once, and both transports call it.

### Known gap: capture cannot read a key rendered outside an input

The inspection collects INTERACTIVE elements only (`INTERACTIVE_SELECTOR`), so a key
in a readonly `<input>` is capturable and a key in a `<code>` block is not in
`inspection.elements` at all. Such a run pauses `outcome_unknown` with nothing
stored — fail-closed, not silent. `visible_text` is NOT a usable fallback: it has
already been through `sanitize_page_text`, which redacts exactly the token shapes
being looked for. Widening the selector would change the element set the model sees
on every page, a far larger blast radius than this phase.

### - [x] S7. The in-process transport binds no grant consumer

**Where:** `ops/onboarding/runtime.py::_loop_sessions` (in-process branch),
`ops/playwright/loop_session.py::GrantedSecretConsumer`.

**Symptom (verified by direct execution, not inspection):**

```
fill_from_grant            -> blocked secret_consumer_unavailable
navigate_verification_link -> blocked verification_allow_list_unavailable
```

`PlaywrightLoopSessions` is constructed with neither `secrets=` nor
`allowed_hosts=`, and both fail closed by design. So `signup` cannot type the staged
email/password, and `email_verification` cannot open a magic link.

**Why the production RPC broker is not the answer for an onboarding run** — two
independent structural reasons, both verified:

1. `_bound_active_run` requires `phase == "credential_capture_reserved"` (capture) or
   `"authentication_submitted"` (consume). Neither is an `OnboardingPhase`; both are
   *canonical runtime* phases. An onboarding run is never in either.
2. `_current_operation_key` recomposes the key from the run row's `effect_identity`.
   `grep effect_identity ops/onboarding/ ops/browser/signup.py` returns **nothing** —
   the onboarding path never writes it.

So the in-process consumer is the only route, which is what the
`GrantedSecretConsumer` docstring already anticipates ("on the local in-process path
there is no second process by definition").

**The hard part, and why this is not a two-line fix.**
`consume_transient_with_grant` requires `expected_operation_key`, and the vault
validates the full binding. But `GrantedSecretConsumer.consume` receives only
`(reference, kind, grant)` — no operation key. The signup keys are
`f"{signup_submit_key(run_id, profile, account_ref)}:consume:{field}"`, so a consumer
must be constructed per run with enough context to recompose exactly that, and
`field` derives from `kind.removeprefix("browser_login_")` the same way the broker
does it. Widening the port to carry the key instead would put the key on the wire on
the RPC path too, which is the opposite of the intent.

**Blocks:** `signup` typing anything, therefore everything after it. This is the
single remaining thing between the wired chain and `vault_entries > 0`.

**`ALLOW_LIVE_VENDOR_EMAIL` deliberately left `false`.** Flipping it now would
authorize real vendor email for a run that provably cannot get past the signup fill,
spending live email and real research API budget for a result already known by
direct execution. It should be flipped in the same change that lands S7.


### B11 resolution — the fill left the candidate path entirely

B11's two findings remain TRUE and were not "fixed": `composition.py` still builds
phase goals without `allow_value_refs`, and `APPROVED_BROWSER_VALUE_REFS` still has
no email or password member (22 entries; only `service_account_email`, which is
unrelated). Verified again after the change.

They stopped mattering because the signup fill no longer goes through the candidate
path at all. `SessionSignupSubmitter` calls `PlaywrightLoopSession.fill_from_grant`,
which resolves its target with `_first_fillable_index` (index-addressed, from a
bounded inspection) and redeems a one-shot grant. So the model never proposes a
credential fill and never sees a value.

Adding email/password to `APPROVED_VALUE_REFS` would have been the wrong fix — it
would put credential material on the candidate path, which is the separation the
capture/candidate split exists to maintain.
