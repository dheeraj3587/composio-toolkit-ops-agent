# Target architecture: the closed autonomy loop

## The thesis

This system already contains almost every part of an autonomous agent. What it does
not contain is a **closed loop**. Each subsystem hands off to the next, and at five
specific points the chain is open — so a run walks a short distance and stops.

Autonomy here is not a feature to add. It is five existing capabilities that must
each close, in a specific order.

| # | Capability | Question it answers | Why it is open today |
| --- | --- | --- | --- |
| 1 | **Evidence** | What is this app, and where are its pages? | P1 snapshot is a hard gate; You.com is unwired; catalog URLs are the only live source |
| 2 | **Plan** | Which surfaces, in what order? | Works — but refuses `entry_only` recipes and can't replan on the mounted path |
| 3 | **Strategy** | What should the run be *trying to do* now? | Nothing owns it. `_LEGAL_PHASE_TRANSITIONS` is a state machine, not a planner |
| 4 | **Act** | Do the thing on the page | 6 of 12 phases have no handler; two bind a pause-only stub |
| 5 | **Recover** | Wake myself up and carry on | Deferrals are written and never read; the sweep is phase-limited |
| 6 | **Learn** | Be cheaper and quieter next run | Account binding is run-scoped, so the vault never hits on run 2 |

Close all six and the loop runs. Close five and it still stops.

```
        ┌──────────────────────────────────────────────────────────┐
        │                                                          │
        ▼                                                          │
   ① EVIDENCE ──► ② PLAN ──► ③ STRATEGY ──► ④ ACT ──► observe ─────┤
   discovery      RunPlan     next goal      phase      outcome    │
   + profile                  + verdict      handler               │
        ▲                         │                                │
        │                         │ replan                         │
        └─────────────────────────┘                                │
                                                                   │
   ⑤ RECOVER ── queue drain · deferral wake · lease recovery ───────┤
   ⑥ LEARN ──── vault write ► stable binding ► vault hit next run ──┘
```

## Layer model

```
L6  Memory        vault (cross-run credentials), research cache, stable account binding
L5  Recovery      durable queue + drain, deferral honouring, lease recovery, reconciliation
L4  Execution     phase handlers → action_loop (observe→candidates→decide→act→verify→gate)
L3  Strategy      Strategist: goal selection, replan, escalation  ◄── NEW
L2  Planning      route planner → RunPlan → validator → adherence monitor
L1  Evidence      discovery adapters → profile builder → committed ProviderProfile
L0  Substrate     inference chain · effect ledger · vault · DLP · host policy · phase authority
```

L0 is load-bearing for everything above it and does not change. L3 is the only new
component. L1, L4, L5 and L6 are wiring gaps in code that already exists.

---

## L0 — Substrate (unchanged, and the reason the rest is safe)

- **Phase authority.** `drive_run` is the only writer of phase history. Every
  boundary passes `validate_phase_transition` before the target phase's first
  effect is reserved.
- **Effect ledger.** Every provider-visible action is reserved under an operation
  key. A completed reservation is adopted, not repeated — this is what makes
  retries and goal-switching safe.
- **Vault.** Credentials cross boundaries only as `vault://` references.
- **DLP + host policy.** Untrusted text is screened before any prompt; navigation is
  confined to a derived allow-list.
- **Inference chain.** `build_json_inference` → provider order, `DecisionBudget`,
  circuit breaker, `DecisionAttemptSink` telemetry, typed `DecisionFailed`.

**The invariant that makes LLM use safe here:** *the model proposes, deterministic
code disposes.* Every model call has (a) a strict JSON schema whose enums come from
trusted data, (b) a `validate=` callback for bounds the schema can't express, (c) a
DLP-screened prompt, (d) a bounded budget, (e) a deterministic fallback. Untrusted
page text never becomes a schema enum.

## L1 — Evidence: learn about any app, not just the 50

Today the mounted walk builds its adapter list inline and the registry output is
dropped. The fix is one seam, not a rewrite.

```
DiscoveryAdapters (registry-driven, each opt-in by its own flag)
  ├── catalog URLs        always available
  ├── Perplexity search   when configured
  └── You.com search      when configured   ◄── new ProfileDiscovery impl
                ↓ candidate URLs (proposals only)
        OfficialEvidenceFetcher    SSRF + redirect + size guard
                ↓ EvidenceDocument
        extractor (literal claims + optional LLM, DLP-screened)
                ↓ ProfileClaim[]
        build_profile  ── corroboration ≥2, domain confinement ──►  ProviderProfile
```

Three things must be true:

1. The mounted walk takes adapters **from the registry**, not from an inline list —
   otherwise a registered adapter never runs.
2. The You.com adapter must be a **new** `ProfileDiscovery` implementation
   (`(*, app_name: str) -> tuple[str, ...]`). The existing You.com classes all
   require `official_hosts`, which is the very thing profile research exists to
   discover — they cannot be registered as-is.
3. **Evidence sources are additive; the evidence bar is not lowered.** More
   candidates, same `MIN_CORROBORATIONS = 2`, same literal-presence requirement,
   same local re-validation of every provider-returned URL.

**The P1 question you must decide.** A run with no P1 record is blocked before any
research. All 50 catalog apps have records, so it costs nothing today — and blocks
app #51 absolutely. If the goal is "any app", P1 must become *one evidence source
among several* rather than an admission gate. Keep it as a gate only if you can say
why it is a provenance anchor rather than a fail-closed trap.

## L2 — Planning (mostly works)

`ProviderProfile | AppRecipe → RunPlan` (ordered surfaces + credential surface),
validated against exactly one route authority, persisted with revisions, monitored
for divergence by `RouteAdherenceMonitor`.

Two gaps: an `entry_only` recipe has no `credential_management` URL and is refused
outright (it should plan entry + step surfaces with **no** credential surface), and
there is no **profile-shaped replan** — the existing `replan_run_route` takes an
`AppRecipe` and is reachable only from the legacy path.

## L3 — Strategy: the new component

The one thing nothing owns: *the goal just changed.*

```python
StrategyVerdict = Literal["pursue", "replan", "escalate", "complete", "abandon"]
StrategyGoal    = Literal["login", "signup", "email_verification",
                          "developer_app", "credential_generation",
                          "credential_validation"]

@dataclass(frozen=True, slots=True)
class StrategyDecision:
    verdict: StrategyVerdict
    goal: StrategyGoal | None
    reason_code: OnboardingReasonCode     # closed vocabulary; no free text
```

### The decision path

```
reachable_goals(phase, plan, vault_state, budget)   deterministic, no model
        ↓  becomes the schema enum
LLM: given the last outcome, which reachable goal now?
        ↓
validate: goal ∈ reachable  AND  transition legal in _LEGAL_PHASE_TRANSITIONS
        ↓
fallback: first reachable goal in fixed priority order
        ↓
return PhaseStep  ──►  drive_run commits the boundary
```

### The six cases it exists to handle

| Situation | Verdict | Goal |
| --- | --- | --- |
| Login says no such account | `pursue` | `signup` |
| Signup succeeded | `pursue` | `email_verification` → then `authenticated` |
| Authenticated, no key on credential surface | `pursue` | `developer_app` → `credential_generation` |
| Credential stored | `pursue` | `credential_validation` → `complete` |
| Route exhausted / URL keeps diverging | `replan` | — |
| CAPTCHA · MFA · billing · legal consent | `escalate` | — |

Case 1 is currently **inexpressible**: `route_selected_login` has no outbound edge to
signup, and no reason code names "login found no account". Both must be added, and
because storage CHECK constraints are generated from these vocabularies, the new
reason code requires the `_migrate_run_plan_vocabularies` rebuild.

### Two rules that keep it from becoming an agent framework

- **It returns a `PhaseStep`. It never writes phase history.** `drive_run` stays the
  single phase authority. This is not stylistic: bypassing it is precisely the
  defect class that produced unrecoverable runs.
- **Caps live in code, not in the prompt.** Max goal switches, max replans
  (`RunPlanStore.count_plans`), max strategist calls. Exceeding one forces
  `escalate` — a visible status change, never a silent stall. login↔signup
  oscillation is the predictable failure mode and you do not ask a model to police
  it.

## L4 — Execution: every phase gets a handler

The handler map binds 6 phases; 6 more are absent, and two of the bound ones are a
pause-only stub. The target is one handler per non-terminal phase, each reserving
its operation key **before** the provider-visible action:

```
research → vault_check → awaiting_admission
        → route_selected_login | route_selected_signup
        → signup → email_verification → authenticated
        → developer_app → credential_generation
        → vault_storage → credential_validation → completed
```

The tail of that walk is what puts an API key in the vault. Note `api_key_flow` is
already a first-class `FlowSpec` on `ProviderProfile` — this is wiring an existing
flow, not inventing one.

## L5 — Recovery: the heartbeat

**Nothing is autonomous if nothing resumes it.** Three mechanisms, all partly built:

1. **Queue drain.** Deferrals write a ready time that no actor reads. A drain must
   claim due work and re-drive it — verification backoff, credential-validation
   retry, login-gate retry and CAPTCHA takeover resume all depend on this.
2. **Reconciliation from the ledger.** Recovers runs stranded by a crash between
   commit and enqueue. Its eligible-phase set must be **derived from the phase
   vocabulary** (non-terminal, non-human-gated), never a hand-written list — a
   hard-coded list silently stops sweeping the moment new handlers extend the walk.
3. **Lease recovery.** Exactly one worker per run; the loser is fenced before any
   further effect.

## L6 — Learn: quieter every run

The measurable goal is **human touches per successful onboarding**, and the target
is: first run 1 (credential entry), every later run for the same app 0.

That requires the account binding to be derived from facts **stable across runs**.
A run-scoped binding means run 2 probes a different key, misses, and prompts again —
the vault is written but never read.

## Escalation ladder — when the agent may ask a human

Autonomy is not "never ask". It is "ask only when no policy could decide". In
priority order, the agent must exhaust each rung before the next:

1. **Retry** — transient failure, budget remains.
2. **Switch goal** — the Strategist has another reachable goal.
3. **Replan** — the route is wrong; plan a new one (bounded by the replan cap).
4. **Degrade** — no model available; take the deterministic fallback.
5. **Escalate** — only for: credential entry, CAPTCHA, MFA, billing, legal consent,
   an exhausted cap, or an ambiguous external effect that a read-only probe could
   not resolve.

Anything escalating for a reason not on that list is a defect, not a design.

---

# Build prompt

Paste below the line into a fresh agent in this repository.

---

Make this system's onboarding agent run **end to end without a human**, except for
credential entry, CAPTCHA, MFA, billing and legal consent.

Read these first, in order:
1. `semantic-review/autonomous-architecture.md` — the target architecture and the
   six capabilities that must close.
2. The bugfix requirements document — numbered fix checks (2.x) and preservation
   checks (3.x). **Every preservation check must still hold when you are done.**
3. `semantic-review/audit-findings.md` — evidence, file:line, ordering.

## What "done" means

A run for a reviewed Playwright app goes: created → research → profile committed →
plan → login attempted → (if no account) signup → email verification →
authenticated → developer app → credential generated → stored in vault → validated →
completed, with **exactly one** human interaction (credential entry) on the first
run and **zero** on the second run for the same app.

Prove it with an end-to-end test using injected fakes at the existing seams
(`WorkflowDependencies`, `OnboardingPorts`, `CandidateDecider`, `JsonInference`).
Assert the human-touch count, not just the terminal phase.

## Order of work — this ordering is derived from real dependencies

1. **Unblock admission** — `entry_only` recipes must plan without a credential
   surface; `onboarding=True` + `existing_account` must be accepted; omitted
   `browser_provider` must use the deployment's configured engine. Without this,
   most of the catalog never opens a session and you cannot test anything below.
2. **Handlers for every non-terminal phase**, each reserving its operation key
   before the provider-visible action.
3. **Recovery, together with step 2.** The reconciliation sweep's eligible-phase set
   must be derived from the phase vocabulary, not a hand-written list — the current
   list stops at `signup` and will silently skip every phase step 2 adds. Add the
   deferral drain here too, or every backoff and retry stays dead.
4. **The Strategist (L3).** It needs handlers to hand goals to, so it comes after 2.
   Case 1 requires a new `OnboardingReasonCode` **and** a new
   `route_selected_login → signup` edge; the reason code requires the
   `_migrate_run_plan_vocabularies` rebuild or an existing database refuses it.
5. **Stable account binding** so run 2 hits the vault and prompts zero times.
6. **Evidence (L1)**, landable in parallel with 1–5: registry-driven adapters, a new
   `ProfileDiscovery` implementation for You.com that does not require
   `official_hosts`, and the DLP screen on provider text **before** any of it goes
   live. Decide the P1 gate question explicitly.
7. **Correctness fixes** that the above depend on or expose: port identity on
   planned surfaces, `flow_unsupported` when no credential flow is provable,
   planning off the event loop, ambiguous-reservation resolution, refusing
   `plan_only` + `onboarding` at the request boundary.

## Non-negotiable

- **`drive_run` stays the single phase authority.** New components return
  `PhaseStep`; they never write phase history. Bypassing this is what produced
  unrecoverable runs before.
- **The effect ledger is consulted before every provider-visible action.** No number
  of goal switches, replans or retries may create a second account, developer app,
  credential or verification email.
- **Every LLM seam degrades deterministically.** No provider configured must mean
  slower, never stopped. Distinct reason codes per failure cause.
- **The model never emits a URL, a phase name, or free text** — only a value from an
  enum that deterministic code already proved reachable.
- **Untrusted text is screened** (`screen_model_input` / `sanitize_page_text`) before
  any prompt and never becomes a schema enum.
- **`JsonInference.generate` is synchronous** — call it via `asyncio.to_thread`.
  Calling it on the event loop is a known defect, not a pattern to copy.
- **More evidence never means weaker evidence.** Corroboration ≥ 2, literal presence
  in a cited document, local re-validation of every provider-returned URL.
- **Human gates stay human.** CAPTCHA, MFA, billing and legal consent escalate,
  always.

## Verify

Baseline first — `RUN_LIVE_TESTS=0 python -m pytest -q -m "not live and not browser"`
has ~63 pre-existing failures, ~54 of them macOS-only (`flock`, BSD `stat`). Capture
the failing set **before** you change anything and diff against it; never assume
green. Also `mypy ops api` and `ruff check ops api tests`.

Prove each fix by reverting it and showing the test fail. A regression test that
passes without the fix is worthless.

Shell note: this is zsh — `grep --include='*.py'` **must** be quoted or it errors
with `no matches found`, which is indistinguishable from a zero-hit search. That
mistake has already produced two false "this code doesn't exist" conclusions in this
repository. Verify every negative claim with a control search that you know returns
hits.

## Deliver

Working code, tests, and a table of **human touches per phase** — before and after —
naming every remaining human interaction and the reason it must stay human.
