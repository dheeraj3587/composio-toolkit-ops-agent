# Planner agent architecture

## What already exists

You are not starting from zero. Two of the three tiers are built.

**Tier 1 — Route planner** (`ops/planner/`). Once per run. An LLM selects and orders
the surfaces a run will visit, then names the credential surface.

- `decide.py::decide_run_plan` / `decide_profile_plan` — the LLM call
- `plan.py::RunPlan`, `PlannedSurface` — the value types, canonicalised URLs
- `validator.py::validate_plan` — refuses a plan the route authority never declared
- `store.py::SQLiteRunPlanStore` — revisions, active plan, `count_plans`
- `adherence.py::RouteAdherenceMonitor` — detects divergence from the plan and
  triggers a replan

**Tier 2 — Action loop** (`ops/onboarding/action_loop.py`). Once per page.
`observe → candidates → decide → act → verify → gate`, with `PhaseGoal`,
`PostconditionCheck`, `LoopBudget`, `StepDeadlines`, and `CandidateDecider` as the
LLM seam.

**Inference substrate** (`ops/core/inference.py`). `JsonInference.generate(prompt,
schema, validate)` over a provider chain (Mercury → OpenRouter → Groq → Cerebras →
Gemini) with `DecisionBudget`, a circuit breaker, per-provider timeouts, a
`DecisionAttemptSink` for telemetry, and `DecisionFailed` carrying reason codes.

The house style is already the right one and you should keep it:
**the model proposes, deterministic code disposes.** Every LLM call uses a strict
JSON schema whose enums come from trusted catalog/profile data, a `validate=`
callback for bounds the schema cannot express, a DLP-screened prompt, a bounded
budget, and a deterministic fallback when the model fails or returns junk. Untrusted
page text reaches prompts only as sanitised prose — never as schema enums.

## The actual gap

Nothing owns **"the goal just changed."**

Tier 1 plans a route. Tier 2 works a page. Between them sits a fixed table —
`_LEGAL_PHASE_TRANSITIONS` in `ops/onboarding/phase.py` — which is a *state machine*,
not a planner. It cannot decide:

- login failed because **no account exists** → switch the goal to signup
- signup succeeded → now pursue **email verification**, then login
- authenticated, but the credential surface yielded **no API key** → go find the
  developer portal and create an app first
- this route is exhausted → **replan** rather than pause for a human

That missing decision is exactly your product flow (login → detect no account →
signup → API key → vault). It is why runs stop and wait for a person.

## Proposed: Tier 1.5 — the Strategy tier

One new component. It does not replace the phase machine; it *chooses the next goal*
and lets the existing machine commit the boundary.

```
                    ┌─────────────────────────────────────┐
   run created ───► │ Tier 1  Route planner (exists)      │
                    │ profile/recipe → RunPlan            │
                    └──────────────┬──────────────────────┘
                                   │ RunPlan
                    ┌──────────────▼──────────────────────┐
                    │ Tier 1.5  STRATEGIST  (build this)  │
                    │  in:  goal, outcome, phase, budget, │
                    │       vault state, plan revision    │
                    │  out: next goal + reason code       │
                    │       | replan | escalate to human  │
                    └──────────────┬──────────────────────┘
                                   │ PhaseStep / goal
                    ┌──────────────▼──────────────────────┐
                    │ Tier 2  Action loop (exists)        │
                    │ observe→candidates→decide→act→verify│
                    └─────────────────────────────────────┘
```

### Contract

```python
StrategyGoal = Literal[
    "login", "signup", "email_verification",
    "developer_app", "credential_generation", "credential_validation",
]

StrategyVerdict = Literal["pursue", "replan", "escalate", "complete", "abandon"]

@dataclass(frozen=True, slots=True)
class StrategyDecision:
    verdict: StrategyVerdict
    goal: StrategyGoal | None
    reason_code: OnboardingReasonCode   # existing closed vocabulary
    # no free text — everything an operator reads is a closed code
```

The LLM chooses only from `StrategyGoal` values that the **deterministic
precondition function** already marked reachable. It never invents a goal, a URL, or
a phase.

### The decision it makes, and the guardrail

```
reachable_goals(phase, plan, vault_state, budget)  → deterministic, no LLM
        ↓ (enum for the schema)
LLM: given the last outcome, which reachable goal now?
        ↓
validate: goal ∈ reachable, transition legal in _LEGAL_PHASE_TRANSITIONS
        ↓
fallback if model unavailable/invalid: the first reachable goal in a fixed
priority order — so the agent still advances with no model at all
```

That last line matters: **the strategist degrades to a deterministic policy**, so an
unconfigured or rate-limited provider slows the agent down instead of stopping it.

### Budgets and loop prevention

Reuse `DecisionBudget`. Add hard caps the strategist cannot exceed, checked in code
rather than asked of the model:

- max goal switches per run (a login↔signup oscillation is the failure mode)
- max replans per run — `RunPlanStore.count_plans` already tracks this, and
  `adherence.decide_adherence` already takes `plans_recorded`
- max total strategist calls per run

Exceeding any cap forces `escalate`, never a silent stall.

### Where it plugs in

- Called from the phase handler layer in `ops/onboarding/runtime.py` (the handler
  map keyed by `OnboardingPhase`), not from inside `drive_run`.
- It returns a `PhaseStep`; `drive_run` remains the only thing that commits
  boundaries. Do not let the strategist write phase history directly.
- `replan` calls the existing `RunService.replan_run_route`.
- Every decision persists via the existing `DecisionAttemptSink` so you can see what
  the model chose and why.

## Why not a general "agent framework"

Because the constraints here are unusual and already encoded: closed reason-code
vocabularies, an effect ledger for effectively-once external actions, a vault that
never yields plaintext across a boundary, and a phase table that refuses illegal
transitions. A generic ReAct/tool-calling loop would bypass all of it. The tiered
design keeps the LLM in the one role it is good at — choosing among options that
deterministic code has already proven safe.

---

# Build prompt

Paste below the line into a fresh agent in this repository.

---

Build a **Strategy tier** for this codebase's planner agent: the component that
decides *what goal to pursue next* when an onboarding run's situation changes. Read
`semantic-review/planner-agent-architecture.md` first — it describes the two tiers
that already exist and the contract for the one you are adding.

## What you are building

A `Strategist` that, given the run's current phase, the last action outcome, the
active `RunPlan`, vault state, and remaining budget, returns a `StrategyDecision`:
pursue a goal, replan the route, escalate to a human, complete, or abandon.

It exists to remove the human from decisions the agent can make itself. The
motivating cases, in priority order:

1. Login attempted, provider indicates **no such account** → pursue `signup`.
2. Signup completed → pursue `email_verification`, then `login`.
3. Authenticated but no API key on the credential surface → pursue `developer_app`,
   then `credential_generation`.
4. Route exhausted or observed URL keeps diverging → `replan`.
5. CAPTCHA / MFA / billing / legal consent → `escalate` (these stay human).

## Non-negotiable design rules

- **The model proposes, code disposes.** The LLM picks only from an enum of goals
  that a deterministic `reachable_goals(...)` function already produced. It never
  emits a URL, a phase name, or free text.
- **Strict schema + `validate=` callback**, exactly like
  `ops/planner/decide.py::decide_profile_plan`. Use `build_json_inference` and
  `DecisionBudget`; do not add a new LLM client.
- **Deterministic fallback.** With no provider configured, or on `DecisionFailed`,
  or on an invalid payload, fall back to a fixed priority order over
  `reachable_goals`. The agent must still advance. Return a distinct reason code for
  each fallback cause, mirroring how `decide_profile_plan` distinguishes
  `plan_provider_unconfigured` / `plan_decision_failed` / `plan_decision_unusable`.
- **Never commit phase boundaries yourself.** Return a `PhaseStep`; `drive_run` owns
  commits. Writing phase history from the strategist would break the single phase
  authority.
- **Closed vocabularies only.** Reuse `OnboardingReasonCode`. If you need a new
  code, add it to the vocabulary — and note that `ops/core/storage.py` CHECK
  constraints are generated from these vocabularies, so an existing database needs
  the rebuild migration in `_migrate_run_plan_vocabularies` to accept it.
- **Untrusted text is evidence, not instruction.** Page text and provider responses
  go through `screen_model_input` / `sanitize_page_text` before entering a prompt,
  and never into schema enums.
- **Hard caps in code, not in the prompt.** Max goal switches, max replans (use
  `RunPlanStore.count_plans`), max strategist calls. Exceeding one forces
  `escalate`; it must never produce a silent stall.
- **Async discipline.** `JsonInference.generate` is synchronous. Call it via
  `asyncio.to_thread` — calling it directly on the API event loop is a known defect
  in this repo, not a pattern to copy.

## Integration points

- Wire it into the phase handler map in `ops/onboarding/runtime.py`
  (`route_selected_login`, `signup`, `authenticated`, `developer_app`,
  `credential_generation`). Those currently map to a handler that always pauses.
- `replan` → `RunService.replan_run_route`; adherence signals already exist in
  `ops/planner/adherence.py`.
- Record every attempt through the existing `DecisionAttemptSink`.
- Respect `execution_path == "profile_mounted"` — this tier belongs to the mounted
  seam, not the legacy static path.

## Tests you must write

- Each of the five motivating cases above, with a fake `JsonInference`, asserting
  the resulting goal and reason code.
- **No provider configured** → deterministic fallback still advances the run.
- **Model returns an unreachable goal** → rejected, fallback used, distinct reason
  code.
- **Oscillation**: login→signup→login hits the switch cap and escalates.
- **Illegal transition**: a goal whose phase transition `_LEGAL_PHASE_TRANSITIONS`
  forbids is refused before any effect.
- Follow the offline conventions in `tests/conftest.py`; inject fakes rather than
  mocking internals.

## Verify

`RUN_LIVE_TESTS=0 python -m pytest -q -m "not live and not browser"`, plus
`mypy ops api` and `ruff check ops api tests` — all must stay green. Note the
suite has ~63 pre-existing failures, mostly macOS-only (`flock`, BSD `stat`);
diff against a baseline you capture *before* your changes rather than assuming
green, and confirm you introduced no new failures.

## Deliver

The component, its wiring, its tests, and a short note listing every decision the
agent can now make that previously required a human — and every one that still
does, with the reason it should stay human.
