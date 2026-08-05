"""Vocabulary and ports for the autonomous action loop (design LL-3.1).

The loop itself — observe, sanitize, generate candidates, ask the model to pick
one, re-validate the pick against the live snapshot, act, classify — lands in a
later task. What this module owns is the vocabulary that loop is written against,
and the two ports it reaches the outside world through. Four decisions are worth
stating, because each of them is a containment property rather than a style
preference.

The budgets are values, not literals buried in the loop.
    :class:`LoopBudget` carries the five bounds Requirements 4.10 and 5.10 name
    (60 executed actions, 80 model calls, 6 consecutive no-progress observations,
    900 wall-clock seconds, 10 navigation denials). Every bound maps to exactly
    one reason code through :meth:`LoopBudget.exhaustion_reason`, so an exhausted
    outcome always says *which* bound stopped the phase (Requirements 4.11-4.14).
    The runtime source is ``ops.core.config.Settings.onboarding_loop_max_*``; a caller
    holding a ``Settings`` builds its budget with
    :meth:`LoopBudget.from_settings` rather than accepting the defaults, and the
    happy-path test pins the two sets of defaults equal so a change to one that
    is not mirrored in the other fails rather than producing two disagreeing
    budgets.

An outcome is a closed classification, and the counters travel with it.
    :class:`LoopResult` carries the four outcomes and the three counters the
    driver records. The counters are part of the result because the driver — not
    the loop — commits the phase (Requirement 4.20), so the loop has to *hand
    back* everything the durable row needs instead of writing it.

Postconditions belong to the phase, not to the prompt.
    :class:`PhaseGoal` states what must become true for a phase to be done, and
    :data:`PHASE_POSTCONDITIONS` declares that per phase. The model never sees a
    postcondition it can satisfy by assertion: the loop checks postconditions
    against a fresh observation, and ``done`` requires all of them
    (Requirement 4.17). A goal with no postcondition is refused at construction,
    because a phase that cannot fail its own check would be reported done by the
    first action that did not error.

The model and the recorder are ports.
    :class:`CandidateDecider` is the only path from the loop to an inference
    backend, and it takes an already-rendered prompt plus a schema restricted to
    the ids generated in the same iteration (Requirement 4.4) — there is no
    parameter through which a selector, URL, or typed value could come back.
    :class:`LoopTelemetry` is how the loop reports denials, rejections, and DLP
    refusals without knowing whether the sink is an audit table or a counter.

``run_action_loop`` (below) is the one consumer of all of this. The phase handlers
that build goals and the driver that commits transitions live elsewhere: the loop
returns a classified outcome and commits nothing (Requirement 4.20).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from time import monotonic
from typing import TYPE_CHECKING, Final, Literal, Protocol, get_args

from ops.browser.candidates import (
    ActionCandidate,
    executable_candidates,
    generate_candidates,
    render_candidates,
    resolve_identity,
    select_candidate,
)
from ops.browser.decider import (
    SnapshotElement,
    build_choice_prompt,
    build_snapshot,
    candidate_choice_schema,
    render_snapshot,
    validate_choice,
)
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation
from ops.browser.worker import BrowserObservation, HumanActionType
from ops.core.model_input_dlp import (
    sanitize_element_name,
    sanitize_page_text,
    sanitize_url,
    screen_model_input,
)
from ops.core.storage import LOOP_STAGE_VALUES, STEP_DECISION_VALUES
from ops.onboarding.phase import (
    ONBOARDING_REASON_CODES,
    SESSION_BEARING_PHASES,
    OnboardingPhase,
    OnboardingReasonCode,
)

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only so this vocabulary module stays free of the settings/pydantic
    # import chain at runtime; ``from_settings`` needs only attribute access.
    from ops.core.config import Settings


# --- budgets ---------------------------------------------------------------
# Code-level defaults behind ``Settings.onboarding_loop_max_*``. These are the
# numbers Requirements 4.10 and 5.10 state and design LL-3.1 repeats; a caller
# with a ``Settings`` in hand should use ``LoopBudget.from_settings``.
MAX_ACTIONS: Final = 60
MAX_MODEL_CALLS: Final = 80
MAX_NO_PROGRESS: Final = 6
MAX_WALLCLOCK_SECONDS: Final = 900
MAX_NAVIGATION_DENIALS: Final = 10
# Requirement 4.3: at most 8 candidates in one iteration. Restated here rather
# than imported because ``ops.browser.candidates.generate_candidates`` carries it
# as a parameter default; the happy-path test pins the two equal.
MAX_CANDIDATES: Final = 8

LoopOutcome = Literal["done", "gate", "exhausted", "denied_fatal"]
LOOP_OUTCOMES: Final[tuple[LoopOutcome, ...]] = get_args(LoopOutcome)

# Where one iteration ended (reliability R4.1). Asserted equal to the durable
# column's vocabulary, so a stage added here cannot fail a CHECK on a live run.
LoopStage = Literal["observe", "candidates", "decide", "act", "verify", "gate", "exhausted"]
LOOP_STAGES: Final[tuple[LoopStage, ...]] = get_args(LoopStage)
assert LOOP_STAGES == LOOP_STAGE_VALUES, "loop stages must match the progress table's vocabulary"

# How one iteration's decision ended. The first three are what ``validate_choice``
# admits from the model; ``rejected`` is the loop's own verdict on a reply it threw
# away — the model can never author it. Asserted equal to the durable column's
# vocabulary for the same reason the stages above are.
StepDecision = Literal["select_candidate", "report_hitl", "report_blocked", "rejected"]
STEP_DECISIONS: Final[tuple[StepDecision, ...]] = get_args(StepDecision)
assert STEP_DECISIONS == STEP_DECISION_VALUES, (
    "step decisions must match the decision table's vocabulary"
)

# The bound a counter reached, in the loop's own words. Used as the key of the
# bound → reason-code mapping so the two cannot drift apart.
BudgetBound = Literal["actions", "model_calls", "no_progress", "wallclock"]

_EXHAUSTION_REASONS: Final[dict[BudgetBound, OnboardingReasonCode]] = {
    "actions": "loop_action_budget_exhausted",
    "model_calls": "loop_model_call_budget_exhausted",
    "no_progress": "loop_no_progress_budget_exhausted",
    "wallclock": "loop_wallclock_budget_exhausted",
}


@dataclass(frozen=True, slots=True)
class LoopBudget:
    """The five bounds that stop one phase from running forever.

    Every bound is a hard stop, not a hint: the loop checks all of them at the
    top of each iteration and returns rather than acting once any is reached
    (design LL-3.1, invariant I1). ``max_navigation_denials`` is the odd one out
    in that it ends the phase as ``denied_fatal`` rather than ``exhausted``
    (Requirement 5.13) — repeated attempts to leave the allow-list are a
    containment event, not a slow phase.
    """

    max_actions: int = MAX_ACTIONS
    max_model_calls: int = MAX_MODEL_CALLS
    max_no_progress: int = MAX_NO_PROGRESS
    max_wallclock_seconds: int = MAX_WALLCLOCK_SECONDS
    max_navigation_denials: int = MAX_NAVIGATION_DENIALS

    def __post_init__(self) -> None:
        # A zero bound would mean "stop before observing anything", which is a
        # misconfiguration rather than a tighter policy.
        if (
            min(
                self.max_actions,
                self.max_model_calls,
                self.max_no_progress,
                self.max_wallclock_seconds,
                self.max_navigation_denials,
            )
            < 1
        ):
            raise ValueError("every loop budget bound must be at least one")
        # A phase cannot execute more actions than it has model calls to choose
        # them with; the reverse slack is expected (rejected choices cost a call
        # and no action).
        if self.max_model_calls < self.max_actions:
            raise ValueError("the model-call budget cannot be below the action budget")

    @classmethod
    def from_settings(cls, settings: Settings) -> LoopBudget:
        """The budget as the deployment configured it (bounds enforced there)."""
        return cls(
            max_actions=settings.onboarding_loop_max_actions,
            max_model_calls=settings.onboarding_loop_max_model_calls,
            max_no_progress=settings.onboarding_loop_max_no_progress,
            max_wallclock_seconds=settings.onboarding_loop_max_wallclock_seconds,
            max_navigation_denials=settings.onboarding_loop_max_navigation_denials,
        )

    def exhausted_bound(
        self,
        *,
        actions: int,
        model_calls: int,
        no_progress: int,
        elapsed_seconds: float,
    ) -> BudgetBound | None:
        """The first bound these counters have reached, or ``None``.

        Checked in the order design LL-3.1 checks it, so a phase that reaches two
        bounds in the same iteration reports the same one every time.
        """
        if actions >= self.max_actions:
            return "actions"
        if model_calls >= self.max_model_calls:
            return "model_calls"
        if no_progress >= self.max_no_progress:
            return "no_progress"
        if elapsed_seconds >= self.max_wallclock_seconds:
            return "wallclock"
        return None

    @staticmethod
    def exhaustion_reason(bound: BudgetBound) -> OnboardingReasonCode:
        """The reason code that names ``bound`` (Requirements 4.11-4.14)."""
        return _EXHAUSTION_REASONS[bound]


@dataclass(frozen=True, slots=True)
class StepDeadlines:
    """A wall-clock bound on each step of one browser operation (R4.7).

    Defaults mirror the ``Settings.onboarding_step_*_timeout_seconds`` defaults; a
    caller holding a ``Settings`` builds these with :meth:`from_settings`.
    """

    observe_seconds: float = 20.0
    decide_seconds: float = 20.0
    act_seconds: float = 40.0
    verify_seconds: float = 20.0

    def __post_init__(self) -> None:
        if (
            min(self.observe_seconds, self.decide_seconds, self.act_seconds, self.verify_seconds)
            <= 0
        ):
            raise ValueError("every per-step deadline must be positive")

    @classmethod
    def from_settings(cls, settings: Settings) -> StepDeadlines:
        """The deadlines as the deployment configured them (bounds enforced there)."""
        return cls(
            observe_seconds=float(settings.onboarding_step_observe_timeout_seconds),
            decide_seconds=float(settings.onboarding_step_decide_timeout_seconds),
            act_seconds=float(settings.onboarding_step_act_timeout_seconds),
            verify_seconds=float(settings.onboarding_step_verify_timeout_seconds),
        )


DEFAULT_STEP_DEADLINES: Final = StepDeadlines()


@dataclass(frozen=True, slots=True)
class LoopResult:
    """One phase's classified outcome plus the counters the driver records.

    The loop commits nothing (Requirement 4.20), so this value is the whole
    hand-off: the outcome the driver switches on, the reason code it writes, the
    final observation it may project, and the three counters that make an
    exhausted or denied phase explainable after the fact.
    """

    outcome: LoopOutcome
    observation: BrowserObservation
    reason_code: OnboardingReasonCode
    actions_executed: int = 0
    model_calls: int = 0
    navigation_denials: int = 0

    def __post_init__(self) -> None:
        if min(self.actions_executed, self.model_calls, self.navigation_denials) < 0:
            raise ValueError("loop counters cannot be negative")
        # Q2: a gate outcome is only meaningful when the observation says which
        # human action is required, so the driver never has to guess what to ask.
        if self.outcome == "gate" and self.observation.human_action_type is None:
            raise ValueError("a gate outcome requires a typed human action")

    @property
    def terminal_for_phase(self) -> bool:
        """Whether the driver must stop driving this phase (everything but done)."""
        return self.outcome != "done"


# --- phase goals -----------------------------------------------------------
# What must become true for each browser-bearing phase to be done. These are
# postcondition *names*: the loop resolves each against a fresh observation
# through the checker (task 13.3), and `done` requires all of them
# (Requirement 4.17). Declared per phase here so no handler can quietly drive a
# phase against a weaker bar than the one the design states.
PHASE_POSTCONDITIONS: Final[dict[OnboardingPhase, tuple[str, ...]]] = {
    "route_selected_login": ("authenticated_session",),
    "signup": ("signup_submitted",),
    "email_verification": ("verification_completed", "authenticated_session"),
    "authenticated": ("authenticated_session",),
    "developer_app": ("developer_app_present",),
    "credential_generation": ("credential_visible",),
}


@dataclass(frozen=True, slots=True)
class PhaseGoal:
    """The goal one phase is driven toward, and the bar it is judged against.

    Everything the model gets to see about the goal is prose that the loop
    sanitizes before it is rendered (``description``, ``instruction``,
    ``signals``). Everything that decides *whether the phase is done* is the
    postcondition tuple, which the model never influences.
    """

    phase: OnboardingPhase
    provider_name: str
    # Prose for the prompt: what credential this phase is working toward, what
    # the model should be doing right now, and the page signals that suggest the
    # phase is on track. Never a selector and never a URL.
    description: str
    instruction: str
    signals: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    # The code recorded when every postcondition is observed true. Phase-specific
    # (``signup_submitted``, ``credential_generated``, …) because the closed
    # reason list describes what happened, not that a check passed.
    success_reason_code: OnboardingReasonCode = "postcondition_failed"
    # Passed through to ``generate_candidates``: the reviewed URLs a `goto`
    # candidate may use and the approved non-secret value refs a `type` candidate
    # may fill. Both default to empty, which is the fail-closed choice.
    reviewed_goto_urls: tuple[str, ...] = ()
    allow_value_refs: tuple[str, ...] = ()
    max_candidates: int = MAX_CANDIDATES

    def __post_init__(self) -> None:
        if self.phase not in SESSION_BEARING_PHASES:
            raise ValueError("only a session-bearing phase can carry an action-loop goal")
        if not self.provider_name.strip() or not self.description.strip():
            raise ValueError("a phase goal requires a provider name and a description")
        if not self.instruction.strip():
            raise ValueError("a phase goal requires an instruction")
        # P3: an empty postcondition tuple would make `done` unfalsifiable.
        if not self.postconditions:
            raise ValueError("a phase goal requires at least one postcondition")
        if not 1 <= self.max_candidates <= MAX_CANDIDATES:
            raise ValueError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")

    @classmethod
    def for_phase(
        cls,
        phase: OnboardingPhase,
        *,
        provider_name: str,
        description: str,
        instruction: str,
        success_reason_code: OnboardingReasonCode,
        signals: Sequence[str] = (),
        reviewed_goto_urls: Sequence[str] = (),
        allow_value_refs: Sequence[str] = (),
    ) -> PhaseGoal:
        """A goal whose postconditions come from :data:`PHASE_POSTCONDITIONS`.

        This is the constructor handlers should use: the phase's bar is looked up
        rather than restated, so a handler cannot lower it locally.
        """
        postconditions = PHASE_POSTCONDITIONS.get(phase)
        if not postconditions:
            raise ValueError(f"no declared postconditions for phase {phase!r}")
        return cls(
            phase=phase,
            provider_name=provider_name,
            description=description,
            instruction=instruction,
            signals=tuple(signals),
            postconditions=postconditions,
            success_reason_code=success_reason_code,
            reviewed_goto_urls=tuple(reviewed_goto_urls),
            allow_value_refs=tuple(allow_value_refs),
        )


@dataclass(frozen=True, slots=True)
class PostconditionCheck:
    """The result of checking one phase's postconditions against an observation.

    ``any_progress`` is what resets the consecutive no-progress counter, and
    nothing else does (Requirement 4.16, invariant I3) — which is why it is
    reported separately from ``all_met`` rather than derived from it.
    """

    all_met: bool
    any_progress: bool
    satisfied: tuple[str, ...] = field(default_factory=tuple)
    pending: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.all_met and self.pending:
            raise ValueError("all_met cannot hold while a postcondition is pending")


# --- ports -----------------------------------------------------------------


class CandidateDecider(Protocol):
    """The loop's only path to an inference backend.

    Deliberately narrow: a rendered prompt in, a JSON object out. The loop keeps
    ownership of prompt construction (so DLP sanitization cannot be bypassed by
    an implementation) and of validation (so an id outside the generated set is
    rejected locally even when the backend ignores the schema).
    """

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        """Return the backend's JSON reply for ``prompt`` under ``schema``.

        PRE:  ``prompt`` has passed ``contains_secret_material`` (Requirement
              4.19), and ``schema`` enumerates only candidate ids generated in
              the current iteration (Requirement 4.4).
        POST: an unvalidated mapping. The caller validates it with
              ``ops.browser.decider.validate_choice``; an implementation that
              cannot produce a reply raises rather than returning a guess.
        """
        ...


class LoopTelemetry(Protocol):
    """Where the loop reports what it refused, denied, or rejected.

    Every method takes a closed reason code and nothing else, so no page text or
    exception message can reach a sink through this port.
    """

    def denial(self, reason_code: OnboardingReasonCode) -> None:
        """Record one navigation denial (Requirements 5.9, 5.15)."""

    def reject(self, reason_code: OnboardingReasonCode) -> None:
        """Record one discarded model selection (Requirements 4.5, 4.7, 4.8)."""

    def dlp_refusal(self) -> None:
        """Record one refused page projection (`dlp_prompt_refused`, 4.19)."""

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        """Record one executed action and the running count."""

    def model_call(self, *, model_calls: int) -> None:
        """Record one model call and the running count."""

    def progress(self, *, step_index: int, stage: LoopStage, elapsed_ms: int) -> None:
        """Record that one iteration completed, and where it ended (R4.1)."""

    def decision(
        self,
        *,
        step_index: int,
        decision: StepDecision,
        reason_code: OnboardingReasonCode | None = None,
        candidate_label: str | None = None,
        action: str | None = None,
        target_host: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Record what this iteration decided, and the model's stated reason.

        The one method on this port that carries free text. ``reason`` is whatever
        the backend wrote into the ``reason`` field the choice schema requires, so
        it is page-derived and untrusted; the sink quarantines it before storing it
        and the console renders it inert. Every other argument is a closed
        vocabulary or a value the policy generator authored, never the model.
        """


# --- the loop ---------------------------------------------------------------
# Candidate actions that move the page. Only these are checked against the
# allow-list before execution; everything else acts within the current document.
NAVIGATION_ACTIONS: Final[frozenset[str]] = frozenset({"goto"})

# Which observations count as a satisfied postcondition. Each predicate reads only
# the bounded observation — never page text — so a phase cannot be declared done
# by something the provider's HTML said (Requirement 4.17).
_AUTHENTICATED_STATUSES: Final[frozenset[str]] = frozenset(
    {"developer_console_ready", "credential_page_ready"}
)

_POSTCONDITION_PREDICATES: Final[dict[str, Callable[[BrowserObservation], bool]]] = {
    "authenticated_session": lambda observation: (
        observation.status in _AUTHENTICATED_STATUSES and observation.human_action_type is None
    ),
    "signup_submitted": lambda observation: (
        observation.reason_code == "signup_submitted"
        or observation.status in _AUTHENTICATED_STATUSES
    ),
    "verification_completed": lambda observation: (
        observation.reason_code in {"verification_email_found", "captcha_resolved"}
        or observation.status in _AUTHENTICATED_STATUSES
    ),
    "developer_app_present": lambda observation: observation.developer_app_id is not None,
    "credential_visible": lambda observation: (
        observation.status == "credential_page_ready" and bool(observation.credential_field_labels)
    ),
}

# The human action a candidate's irreversible category calls for. Anything not
# named here is a provider-side decision a human must make on the page.
_HITL_CATEGORY_ACTIONS: Final[dict[str, HumanActionType]] = {
    "billing": "billing",
    "legal_acceptance": "legal_acceptance",
}


@dataclass(frozen=True, slots=True)
class LoopObservation:
    """One turn of the browser's own report, plus the raw elements to project.

    The elements arrive raw (per-element mappings) rather than as
    ``SnapshotElement``s because the loop owns the projection: ``build_snapshot``
    is what strips secret-ish values, and a session implementation must not be
    able to skip it.
    """

    observation: BrowserObservation
    raw_elements: tuple[Mapping[str, object], ...] = ()


class LoopSession(Protocol):
    """The loop's only path to the browser: observe the page, act on a candidate.

    ``act`` takes a whole :class:`~ops.browser.candidates.ActionCandidate`, never a
    selector or a URL, so the execution side receives exactly what policy generated
    and the loop re-validated.

    ``session_id`` is read-only and is here because a CAPTCHA the loop classifies
    has to be paused on the session that is holding the challenge: the pause path
    records the bound session and must keep it (Requirement 11.4), so the driver
    needs the id without gaining any verb that could end or replace the session.
    """

    @property
    def session_id(self) -> str:
        """The bound browser session this phase is being driven on."""
        ...

    async def observe(self) -> LoopObservation:
        """Return the current page's bounded observation and raw elements."""
        ...

    async def act(self, candidate: ActionCandidate) -> None:
        """Execute one policy-generated candidate against the live page."""
        ...


def check_postconditions(
    goal: PhaseGoal,
    observation: BrowserObservation,
    *,
    previously_satisfied: Sequence[str] = (),
) -> PostconditionCheck:
    """Check ``goal``'s postconditions against one observation.

    ``any_progress`` is true only when a postcondition that was *not* satisfied
    before is satisfied now — which is the only thing that resets the consecutive
    no-progress counter (Requirement 4.16). An unknown postcondition name is
    treated as unmet rather than ignored, so a typo cannot make ``done`` easier.
    """

    before = set(previously_satisfied)
    satisfied: list[str] = []
    pending: list[str] = []
    for name in goal.postconditions:
        predicate = _POSTCONDITION_PREDICATES.get(name)
        if predicate is not None and predicate(observation):
            satisfied.append(name)
        else:
            pending.append(name)
    return PostconditionCheck(
        all_met=not pending,
        any_progress=any(name not in before for name in satisfied),
        satisfied=tuple(satisfied),
        pending=tuple(pending),
    )


async def run_action_loop(
    *,
    phase: OnboardingPhase,
    goal: PhaseGoal,
    session: LoopSession,
    allowed: BrowserAllowedHosts,
    budget: LoopBudget,
    decider: CandidateDecider,
    telemetry: LoopTelemetry,
    deadlines: StepDeadlines = DEFAULT_STEP_DEADLINES,
    clock: Callable[[], float] = monotonic,
) -> LoopResult:
    """Drive one phase to a classified outcome, or exhaust a bound and stop.

    PRE:
      P1. ``session`` is active and bound to this run's browser session.
      P2. ``allowed`` is the run's committed allow-list and its patterns are
          non-empty.
      P3. ``goal.phase == phase`` and ``goal.postconditions`` is non-empty
          (the latter is guaranteed by ``PhaseGoal``).

    POST:
      Q1. ``done`` implies every postcondition was observed true in the final
          observation, which the model cannot assert into being.
      Q2. ``gate`` implies the returned observation names a typed human action
          (enforced by ``LoopResult``).
      Q3. ``exhausted`` implies a bound was reached and the reason code names it.
      Q4. every navigation executed passed ``evaluate_navigation``.
      Q5. no prompt that tripped the DLP screen was sent.
      Q6. no phase transition is committed here (Requirement 4.20).

    INVARIANTS:
      I1. budgets are checked at the top of every iteration, before observing.
      I2. the observed current URL is re-checked against the allow-list, so a
          provider redirect off-domain ends the phase even though the loop never
          asked to go there.
      I3. no-progress resets only on newly satisfied postconditions.
      I4. the ids the model may return are exactly this iteration's candidates.
      I5. every iteration reports exactly one progress event, including the ones
          that acted on nothing — those are what a stuck run consists of (R4.1).
      I6. every observe, decide, act and verify step is bounded by ``deadlines``,
          so no single step can freeze the phase (R4.7).
    """

    if goal.phase != phase:  # P3
        raise ValueError("the phase goal does not describe the phase being driven")

    started = clock()
    actions = model_calls = denials = no_progress = 0
    satisfied_before: tuple[str, ...] = ()
    iteration = 0
    step_started = started
    stage: LoopStage = "observe"

    def report(ended_at: LoopStage) -> None:
        """One progress row per iteration, so a stalled loop is visible (I5)."""

        progress = getattr(telemetry, "progress", None)
        if callable(progress):
            progress(
                step_index=iteration,
                stage=ended_at,
                elapsed_ms=max(int((clock() - step_started) * 1000), 0),
            )

    def report_decision(
        outcome: StepDecision,
        *,
        reason_code: OnboardingReasonCode | None = None,
        candidate: ActionCandidate | None = None,
        reason: str | None = None,
    ) -> None:
        """Record this iteration's decision beside its progress row.

        Looked up with ``getattr`` for the same reason :func:`report` looks up
        ``progress``: a telemetry sink that predates this port stays usable, and a
        decision that cannot be recorded must never stop the loop from acting.

        Only the candidate's own action and label travel — never its selector, and
        never a URL beyond the host, which the sink reduces.
        """

        record = getattr(telemetry, "decision", None)
        if not callable(record):
            return
        record(
            step_index=iteration,
            decision=outcome,
            reason_code=reason_code,
            candidate_label=None if candidate is None else candidate.semantic_target,
            action=None if candidate is None else candidate.action,
            target_host=None if candidate is None else candidate.url,
            reason=reason,
        )

    async def observe(seconds: float) -> LoopObservation:
        return await asyncio.wait_for(session.observe(), seconds)

    seen = await observe(deadlines.observe_seconds)

    while True:
        observation = seen.observation
        iteration += 1
        step_started = clock()
        stage = "observe"

        try:
            # --- I1: budgets, fail-closed -----------------------------------
            bound = budget.exhausted_bound(
                actions=actions,
                model_calls=model_calls,
                no_progress=no_progress,
                elapsed_seconds=clock() - started,
            )
            if bound is not None:
                report("exhausted")
                return _result(
                    "exhausted",
                    observation,
                    LoopBudget.exhaustion_reason(bound),
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )

            # --- I2: where we actually are, not where we asked to be ---------
            here = evaluate_navigation(observation.current_url, allowed)
            if not here.allowed:
                reason = _host_reason(here.reason_code)
                denials += 1
                telemetry.denial(reason)
                report("observe")
                return _result(
                    "denied_fatal",
                    observation,
                    reason,
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )

            # --- candidates from policy, never from the model ----------------
            stage = "candidates"
            elements = build_snapshot(seen.raw_elements)
            candidates = generate_candidates(
                elements=elements,
                checkpoint_signals=goal.signals,
                checkpoint_order=iteration,
                trace_version=f"phase:{goal.phase}",
                expected_postcondition=goal.postconditions[0],
                reviewed_goto_urls=goal.reviewed_goto_urls,
                allow_value_refs=goal.allow_value_refs,
                max_candidates=goal.max_candidates,
            )
            if not candidates:  # Requirement 4.9: no action executed, observe again
                no_progress += 1
                report("candidates")
                seen = await observe(deadlines.observe_seconds)
                continue
            options = executable_candidates(candidates)
            if not options:
                # Every option on this page is an irreversible or privilege-changing
                # control. Requirement 4.18: hand it to a human, unexecuted.
                report("gate")
                return _gate(
                    candidates[0],
                    observation,
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )

            # --- DLP: the ONLY path from page to model -----------------------
            stage = "decide"
            prompt = build_choice_prompt(
                app_name=goal.provider_name,
                credential_goal=goal.description,
                checkpoint_instruction=goal.instruction,
                checkpoint_signals=goal.signals,
                current_url=sanitize_url(observation.current_url),
                page_title=sanitize_page_text(observation.page_title, origin="title"),
                rendered_candidates=render_candidates(options),
                rendered_page=render_snapshot(_sanitized(elements)),
            )
            screened = screen_model_input(prompt)
            if not screened.allowed:  # Requirement 4.19, Q5
                telemetry.dlp_refusal()
                no_progress += 1
                report("decide")
                seen = await observe(deadlines.observe_seconds)
                continue

            # --- I4: the model may only name an id generated right here -------
            candidate_ids = [candidate.candidate_id for candidate in candidates]
            payload = await asyncio.wait_for(
                decider.choose(screened.prompt, schema=candidate_choice_schema(candidate_ids)),
                deadlines.decide_seconds,
            )
            model_calls += 1
            telemetry.model_call(model_calls=model_calls)
            try:
                choice = validate_choice(payload, candidate_ids=candidate_ids)
            except ValueError:  # Requirement 4.5
                telemetry.reject("action_not_in_candidate_set")
                report_decision("rejected", reason_code="action_not_in_candidate_set")
                no_progress += 1
                report("decide")
                seen = await observe(deadlines.observe_seconds)
                continue

            if choice.decision == "report_hitl":
                report_decision("report_hitl", reason=choice.reason)
                report("gate")
                return _gate(
                    None, observation, actions=actions, model_calls=model_calls, denials=denials
                )
            if choice.decision == "report_blocked":
                # The chain answered and named no candidate action: unusable, not a
                # spent bound (reliability R4.6).
                report_decision("report_blocked", reason=choice.reason)
                report("decide")
                return _result(
                    "exhausted",
                    observation,
                    "decision_unusable",
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )

            assert choice.candidate_id is not None  # guaranteed by validate_choice
            selected = _by_id(candidates, choice.candidate_id)
            if selected is None:  # unreachable while validate_choice holds
                telemetry.reject("action_not_in_candidate_set")
                report_decision("rejected", reason_code="action_not_in_candidate_set")
                no_progress += 1
                report("decide")
                seen = await observe(deadlines.observe_seconds)
                continue
            report_decision("select_candidate", candidate=selected, reason=choice.reason)
            if not selected.executable:  # Requirement 4.18, left unexecuted
                report("gate")
                return _gate(
                    selected, observation, actions=actions, model_calls=model_calls, denials=denials
                )
            # Re-checks executability at the policy boundary rather than trusting the
            # branch above.
            candidate = select_candidate(candidates, choice.candidate_id)

            # --- re-resolve against THIS iteration's snapshot ----------------
            if candidate.identity is not None:  # Requirement 4.6
                resolution, _ = resolve_identity(candidate.identity, elements)
                if resolution != "resolved":  # Requirements 4.7, 4.8
                    unresolved: OnboardingReasonCode = (
                        "candidate_identity_not_found"
                        if resolution == "not_found"
                        else "candidate_identity_ambiguous"
                    )
                    telemetry.reject(unresolved)
                    report_decision("rejected", reason_code=unresolved, candidate=candidate)
                    no_progress += 1
                    report("decide")
                    seen = await observe(deadlines.observe_seconds)
                    continue

            stage = "act"
            if candidate.action in NAVIGATION_ACTIONS:
                decision = evaluate_navigation(candidate.url or "", allowed)
                if not decision.allowed:  # Q4: a denial never becomes an allow
                    reason = _host_reason(decision.reason_code)
                    denials += 1
                    telemetry.denial(reason)
                    if denials >= budget.max_navigation_denials:
                        report("act")
                        return _result(
                            "denied_fatal",
                            observation,
                            reason,
                            actions=actions,
                            model_calls=model_calls,
                            denials=denials,
                        )
                    no_progress += 1
                    report("act")
                    seen = await observe(deadlines.observe_seconds)
                    continue

            # --- act, then classify against a FRESH observation ---------------
            await asyncio.wait_for(session.act(candidate), deadlines.act_seconds)
            actions += 1
            telemetry.action(candidate_id=candidate.candidate_id, actions_executed=actions)

            stage = "verify"
            seen = await observe(deadlines.verify_seconds)
            check = check_postconditions(
                goal, seen.observation, previously_satisfied=satisfied_before
            )
            if check.all_met:  # Q1
                report("verify")
                return _result(
                    "done",
                    seen.observation,
                    goal.success_reason_code,
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )
            if seen.observation.human_action_type is not None:
                # The page itself now needs a human. Its own reason code is kept when
                # it is one of ours (`captcha_detected`, …) so the driver can act.
                report("gate")
                return _result(
                    "gate",
                    seen.observation,
                    _page_gate_reason(seen.observation),
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )
            no_progress = 0 if check.any_progress else no_progress + 1  # I3
            satisfied_before = check.satisfied
            report("verify")
        except TimeoutError:
            # I6: a step that outran its deadline. Only ``act`` may have landed a
            # side effect we cannot see, so only it ends the phase.
            report(stage)
            if stage == "act":
                return _result(
                    "exhausted",
                    observation,
                    "outcome_unknown",
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )
            no_progress += 1


def _result(
    outcome: LoopOutcome,
    observation: BrowserObservation,
    reason_code: OnboardingReasonCode,
    *,
    actions: int,
    model_calls: int,
    denials: int,
) -> LoopResult:
    return LoopResult(
        outcome=outcome,
        observation=observation,
        reason_code=reason_code,
        actions_executed=actions,
        model_calls=model_calls,
        navigation_denials=denials,
    )


def _gate(
    candidate: ActionCandidate | None,
    observation: BrowserObservation,
    *,
    actions: int,
    model_calls: int,
    denials: int,
) -> LoopResult:
    """A gate outcome that always names the human action, candidate unexecuted."""

    return _result(
        "gate",
        _gate_observation(observation, candidate),
        "candidate_risk_requires_human",
        actions=actions,
        model_calls=model_calls,
        denials=denials,
    )


def _gate_observation(
    observation: BrowserObservation, candidate: ActionCandidate | None
) -> BrowserObservation:
    """Project an observation into one that names the human action required.

    The page's own typed human action wins when it has one; otherwise the action
    comes from the candidate's irreversible category, so the driver never has to
    guess what to ask the operator for.
    """

    if observation.human_action_type is not None:
        return observation
    category = ""
    if candidate is not None and candidate.expected_postcondition.startswith("human_decision:"):
        category = candidate.expected_postcondition.split(":", 1)[1]
    human_action: HumanActionType = _HITL_CATEGORY_ACTIONS.get(category, "provider_verification")
    return BrowserObservation(
        status="human_action_required",
        current_url=observation.current_url,
        page_title=observation.page_title,
        human_action_type=human_action,
        human_instruction=(
            f"A human decision is required before continuing: {category or 'provider action'}."
        ),
        reason_code="candidate_risk_requires_human",
    )


def _by_id(candidates: Sequence[ActionCandidate], candidate_id: str) -> ActionCandidate | None:
    for candidate in candidates:
        if candidate.candidate_id == candidate_id:
            return candidate
    return None


def _page_gate_reason(observation: BrowserObservation) -> OnboardingReasonCode:
    if observation.reason_code in ONBOARDING_REASON_CODES:
        return observation.reason_code  # type: ignore[return-value]
    return "candidate_risk_requires_human"


def _sanitized(elements: Sequence[SnapshotElement]) -> tuple[SnapshotElement, ...]:
    """Replace each accessible name with its DLP-sanitized form for the prompt.

    Only the rendered projection is sanitized: candidates and identity resolution
    keep working against the real names, so a placeholder can never become the
    thing we look for in the live DOM.
    """

    return tuple(
        replace(
            element,
            name=sanitize_element_name(
                element.name,
                element_type=element.element_type,
                origin=element.role,
                role=element.role,
            ),
        )
        for element in elements
    )


def _host_reason(reason_code: str) -> OnboardingReasonCode:
    """Narrow a host decision's code to the closed onboarding vocabulary."""

    if reason_code in ONBOARDING_REASON_CODES:
        # The host policy's codes are members of the closed list by construction.
        return reason_code
    return "browser_host_not_in_app_policy"


__all__ = [
    "DEFAULT_STEP_DEADLINES",
    "LOOP_OUTCOMES",
    "LOOP_STAGES",
    "MAX_ACTIONS",
    "NAVIGATION_ACTIONS",
    "MAX_CANDIDATES",
    "MAX_MODEL_CALLS",
    "MAX_NAVIGATION_DENIALS",
    "MAX_NO_PROGRESS",
    "MAX_WALLCLOCK_SECONDS",
    "PHASE_POSTCONDITIONS",
    "BudgetBound",
    "CandidateDecider",
    "LoopBudget",
    "LoopObservation",
    "LoopOutcome",
    "LoopResult",
    "LoopSession",
    "LoopStage",
    "LoopTelemetry",
    "PhaseGoal",
    "PostconditionCheck",
    "StepDeadlines",
    "check_postconditions",
    "run_action_loop",
]
