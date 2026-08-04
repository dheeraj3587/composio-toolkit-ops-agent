# Last leg: from "works on fakes" to "works, period"

## Verified state (checked in tree, not remembered)

| Thing | State |
|---|---|
| Login route (`existing_account` + onboarding) | ✅ open at both validators |
| Credential tail → vault | ✅ `developer_app → credential_generation → vault_storage → credential_validation` |
| E2E on fakes | ✅ `test_onboarding_login_e2e.py` — run_one captures key, run_two zero prompts |
| Phase anchoring / effect mirror | ✅ fixed |
| Port identity (#8) | ✅ appears done — 11 refs in `plan.py` |
| `/observe` RPC | ✅ `browser_service/main.py:787` |
| `/act` + `ExecutableAction` on wire | ⚠️ only 2 refs — **verify** |
| `_UnavailableBrowserHandler` | ⚠️ still present as fallback |
| Sweep phase list | ⚠️ still a literal tuple (`storage.py:2013`) |
| #7 credential-surface fallback | ❌ open (`decide.py`) |
| #12 `plan_admission` on event loop | ❌ open |
| #3 `plan_only` | ❌ open, 8 files |
| Strategist (Tier 1.5) | ❌ 0 |
| UI (dialog / signup button / key reveal) | ❌ 0 |
| **Live browser run** | ❌ **never done — the real unknown** |

Baseline: **61 failed / 1815 passed**, 61 verified identical at HEAD via stash.

---

## Sequencing principle

**Live first, polish second.** Everything green today is green against injected
fakes. Building the Strategist, the UI and the signup path on top of an arc that has
never touched a real DOM risks building all of it twice. One live run buys more
information than any amount of further offline work.

## Stage 0 — Truth check (1 session)

Run the existing login E2E arc against **one real vendor**, manually, with eyes on it.

- Use the app already chosen for the minimum E2E.
- `ALLOW_LIVE_BROWSER=true`, `PLAYWRIGHT_IN_PROCESS_SANDBOX=true`, real credentials
  for an account **you own on a throwaway/dev tier**.
- Do not fix anything during this stage. **Observe and record only.**

**Exit criterion:** a written list of exactly where it diverged from the fake —
selector misses, timing, redirects, consent banners, rate limits, 2FA prompts,
anything. That list drives Stage 1 and may reorder everything below.

**This stage is allowed to fail.** Failing informatively is the deliverable.

## Stage 1 — Harden what live broke (1–2 sessions)

Fix only what Stage 0 found, in the order it blocks the arc. Expect the bulk to be
in identity resolution (`resolve_identity` tiers), postcondition checks, and
timing/deadlines (`StepDeadlines`, `LoopBudget`).

**Exit criterion:** the same real vendor completes the arc twice — run 1 with one
credential entry, run 2 with zero prompts, API key in the vault both times.

## Stage 2 — Close the open findings (1 session)

Now, not before — these are cheap and none of them block Stage 0/1.

- **#7** `_profile_credential_surface` must refuse rather than fall back to
  developer-portal/login/signup; pause with `flow_unsupported`.
- **#12** `plan_admission` → `asyncio.to_thread`.
- **#3** refuse `plan_only` + `onboarding` at the request boundary.
- **Sweep list** (`storage.py:2013`) — derive from the phase vocabulary
  (non-terminal, non-human-gated). Today's literal silently skips every phase the
  credential tail added.
- **`/act` + `ExecutableAction`** — confirm the wire path is real, or finish it.
- **Docs**: the single-phase-authority invariant now has exactly one sanctioned
  exception (`credentials.py:1086`). Update P4 in the bugfix doc and the
  "handlers never write phase history" line in `autonomous-architecture.md`, and
  note the lease is what makes the `current_phase` re-read safe. Otherwise someone
  "fixes" it back and reintroduces the stale-anchor bug.

## Stage 3 — Strategist (1–2 sessions)

Only worth building once the happy path is real, because its job is handling the
unhappy ones. Contract is already specified in `autonomous-architecture.md`.

Priority cases, in order: login finds no account → signup; authenticated but no key
→ developer_app; route exhausted → replan; human gate → escalate.

Needs a new `OnboardingReasonCode` **and** a `route_selected_login → signup` edge —
and the reason code needs the `_migrate_run_plan_vocabularies` rebuild or an
existing database refuses it.

**Exit criterion:** a run whose login fails for "no account" reaches signup on its
own, with a cap that forces `escalate` rather than oscillating.

## Stage 4 — UI (1–2 sessions)

- Mid-run credential dialog (replaces create-time `browser_login`)
- Sign-up button when the run reports no account
- **API key reveal / copy panel** — this is the demo's punchline and nothing
  surfaces it today
- Strip `plan_only` from the form

## Stage 5 — Signup path live (1–2 sessions)

Hardest and most brittle: real account creation, real verification email, likely
CAPTCHA. Deliberately last, because Stage 3's escalation ladder is what makes its
failures survivable.

## Stage 6 — Generality (1 session)

Two more apps from the seven with a declared `credential_management` URL. This is
what proves the arc is not one-app-shaped. Expect Stage 1-class fixes to recur.

## Stage 7 — De-slop (1–2 sessions)

Only now, with a working arc as the regression oracle. Clusters, safest first, owner
approves each. **Do not delete P1** until live discovery replaces it — it currently
gates every mounted run.

---

## Honest estimate

**7–12 sessions** to "everything fixed", assuming Stage 0 does not detonate. If live
DOM work turns out to be hard, Stages 1 and 5 both grow — that is where the variance
lives, and it is the one thing no amount of planning removes.

Demo-ready (Stages 0–2 + 4) is **4–6 sessions**.

---

# Prompt

Paste below the line into a fresh agent.

---

You are finishing this project. The arc works on injected fakes; it has never
touched a real browser. Read `semantic-review/last-leg-plan.md` and work the stages
**in order**. Do not skip Stage 0.

## Rules that apply to every stage

- **One stage at a time. Finish it, report, stop.** Do not begin the next stage
  without the owner saying so.
- **Found something broken that is not blocking the current stage? Write it to
  `semantic-review/found-while-building.md` with file:line and move on.** Do not fix
  it. This rule has already kept this project on track; it still applies.
- **No refactors, no renames, no "while I was here".**
- **Never touch the 61 pre-existing failures.** Capture the baseline before you
  start, diff at the end, report the diff. Zero new failures is the bar. Never say
  "unchanged" without showing the diff.
- **Prove each fix by reverting it and watching the test fail.**

## Non-negotiable invariants

- Raw credentials and raw API keys never cross a boundary — only `vault://` refs in
  projections, audit rows and logs.
- Reserve the phase's operation key before any provider-visible action; adopt a
  completed reservation rather than repeating it. No retry may create a second
  account, developer app, or credential.
- Phase boundaries are committed only through the phase authority
  (`validate_phase_transition`). There is exactly **one** sanctioned non-driver
  caller — `ops/onboarding/credentials.py:1086`, for the `STORAGE_BOUNDARIES`
  ordering requirement. Do not add a second, and do not "fix" that one back: the
  loop's `current_phase` re-read at `driver.py:2690` depends on it, and removing it
  reintroduces a stale-anchor bug.
- CAPTCHA, MFA, billing and legal consent always pause for a human.
- Every LLM seam degrades deterministically — no provider configured means slower,
  never stopped.

## Stage 0 specifically

Live runs spend real money and touch a real vendor with real credentials.

- **Ask the owner before the first live run.** Confirm which app, and that the
  account is a throwaway/dev-tier one they own.
- During Stage 0 you **observe and record only** — no fixes, even obvious ones.
- Deliver a divergence list: what the real page did that the fake did not.

## Tooling traps that have produced wrong conclusions in this repo

- zsh: `grep --include=*.py` **errors** with `no matches found` unless quoted
  (`--include='*.py'`). A failed search looks exactly like a zero-hit search — this
  has caused two false "this code doesn't exist" conclusions here. Verify every
  negative claim with a control search you know returns hits.
- `source .venv/bin/activate` falls back to a pytest-less Python 3.14 — use
  `./.venv/bin/python`.
- `cmd | tail` reports tail's exit status, not the command's.
- The repo lives in iCloud Drive; `" 2"` conflict copies appear in `node_modules`
  and break `tsc` via `.next/**/types`. Clean them before frontend work.

## Verify, every stage

```bash
RUN_LIVE_TESTS=0 ./.venv/bin/python -m pytest -q -m "not live and not browser"
./.venv/bin/mypy ops api
./.venv/bin/ruff check ops api tests
```

Current baseline: **61 failed, 1815 passed** (~54 macOS-only: `flock`, BSD `stat`).

## Deliver per stage

1. What you changed and why, file:line.
2. The baseline diff.
3. Anything you found and deliberately did not fix.
4. What the next stage should watch out for.

Then stop.
