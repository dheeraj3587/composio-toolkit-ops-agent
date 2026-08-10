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
import logging
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
    MAX_ELEMENTS,
    SnapshotElement,
    build_choice_prompt,
    build_snapshot,
    candidate_choice_schema,
    render_snapshot,
    validate_choice,
)
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation
from ops.browser.risk import ActionAuthorization, BrowserActionRiskPolicy, RiskDecision
from ops.browser.snapshot import rank_raw_elements
from ops.browser.worker import BrowserObservation, HumanActionType
from ops.core.inference import DecisionFailed
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
from ops.onboarding.scratchpad import (
    ScratchpadStore,
    load_scratchpad,
    render_scratchpad,
    save_scratchpad,
)

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    # Typing-only so this vocabulary module stays free of the settings/pydantic
    # import chain at runtime; ``from_settings`` needs only attribute access.
    from ops.core.config import Settings

    # Typing-only for the same reason: ``ops.playwright.actions`` imports
    # ``Settings`` at module scope, and the loop only ever READS ``.status`` and
    # ``.reason_code`` off the value a session hands back — it never constructs
    # one and never isinstance-checks one, so the runtime import would buy
    # nothing and cost the whole settings chain.
    from ops.playwright.actions import ActionExecutionResult


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

# Parity with the OTHER loop that drives a browser, ``ops/playwright/worker.py``'s
# trace loop: ``_MAX_MODEL_FAILURES`` and ``_MAX_ACTION_FAILURES``. Restated here
# rather than imported because importing them would pull the entire Playwright
# worker — Playwright, the session manager, the recipe catalog — into what is
# otherwise a vocabulary module. Before this existed the two loops disagreed by a
# factor of two and one: the worker retried a failed decision twice and a failed
# action three times, while this loop gave up on the FIRST of either, so the same
# provider outage read as "the agent is trying" on one path and "the agent is
# blocked" on the other.
MAX_DECISION_FAILURES: Final = 2
MAX_ACTION_FAILURES: Final = 3

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
    # The exact accessible names a human reviewed as the controls that may create
    # a credential on this phase's pages, and the run's immutable policy on doing
    # so. Both default to the closed answer: with no reviewed control the risk
    # policy refuses every "Create"/"Generate"/"Save" click outright, which is the
    # correct behaviour for a phase whose goal nobody reviewed for that.
    credential_creation_controls: tuple[str, ...] = ()
    credential_creation_policy: str = "reuse_only"
    # The phase itself declares that a human must act on it. Kept here rather than
    # inferred, so a handler can mark a phase HITL without the loop having to
    # discover it from the page.
    requires_hitl: bool = False

    def authorization(self) -> ActionAuthorization:
        """What this goal authorizes, in the risk policy's own vocabulary.

        The loop asks the SAME :class:`~ops.browser.risk.BrowserActionRiskPolicy`
        the worker's trace loop asks. Before this existed the loop's only risk
        signal was ``ActionCandidate.executable``, derived from the substring list
        in ``ops/browser/candidates.py`` — which names neither ``create`` nor
        ``save``, so "Create API key" and "Save" arrived marked low-risk and the
        loop clicked them without ever consulting the credential-creation
        authority.
        """

        return ActionAuthorization.for_phase(
            allowed_value_refs=self.allow_value_refs,
            credential_creation_controls=self.credential_creation_controls,
            requires_hitl=self.requires_hitl,
            credential_creation_policy=self.credential_creation_policy,
        )

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
        credential_creation_controls: Sequence[str] = (),
        credential_creation_policy: str = "reuse_only",
        requires_hitl: bool = False,
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
            credential_creation_controls=tuple(credential_creation_controls),
            credential_creation_policy=credential_creation_policy,
            requires_hitl=requires_hitl,
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


LOGGER = logging.getLogger("composio_ops.onboarding_action_loop")


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
    # ``developer_app_id`` is only ever populated by the in-process trace loop,
    # which reads it out of a provider-specific console. The single-step
    # observe/act path cannot know it, and requiring it made this postcondition
    # unsatisfiable for every run the driver actually drives. Reaching a
    # credential surface or an authenticated console after the developer-app
    # phase acted is the evidence that path CAN produce; the app's real existence
    # is proven downstream anyway, by the capture that fails without it.
    "developer_app_present": lambda observation: (
        observation.developer_app_id is not None
        or (observation.status in _AUTHENTICATED_STATUSES and observation.human_action_type is None)
    ),
    "credential_visible": lambda observation: (
        observation.status == "credential_page_ready" and bool(observation.credential_field_labels)
    ),
}

# The human action a candidate's irreversible category calls for. Anything not
# named here is a provider-side decision a human must make on the page.
_HITL_CATEGORY_ACTIONS: Final[dict[str, HumanActionType]] = {
    "billing": "billing",
    "legal_acceptance": "legal_acceptance",
    # ``ops/browser/risk.py``'s "authorization" family is authorize/approve/
    # allow/grant — an access grant, which now has its own typed action. Mapped
    # here so the operator is asked to grant access rather than to perform an
    # unspecified "provider verification".
    "authorization": "oauth_grant",
}

# The four statuses ``ActionExecutionResult`` declares. Restated as a runtime set
# because the type itself is imported for typing only (see the TYPE_CHECKING block
# at the top): the loop has to be able to REFUSE an unrecognised status, and a
# type annotation cannot do that at runtime.
_ACT_STATUSES: Final[frozenset[str]] = frozenset({"executed", "stale", "blocked", "failed"})

# Exceptions that are always a bug in this repo rather than an outcome of a page.
# The same tuple ``ops/playwright/worker.py`` and ``ops/browser/service_client.py``
# re-raise before their own containment clauses; kept identical so the two loops
# agree about what must never be swallowed.
_PROGRAMMING_ERRORS: Final = (TypeError, AttributeError, AssertionError, NameError, ImportError)

# One executor reason code onto the closed onboarding vocabulary. Only the codes
# with an exact counterpart are mapped; everything else falls back to the caller's
# default, because inventing a near-miss code is worse than a truthful generic one
# — an operator acts on these. ``ops/onboarding/phase.py`` owns the closed list and
# is not this task's to widen, so a transport-level refusal (the service being
# unreachable, say) is reported as the boundary refusal it is.
_ACTION_REASONS: Final[dict[str, OnboardingReasonCode]] = {
    "target_not_found": "candidate_identity_not_found",
    "target_ambiguous": "candidate_identity_ambiguous",
    "policy_blocked": "browser_host_not_in_app_policy",
    "postcondition_failed": "postcondition_failed",
    # Nothing about the page was observed after these, so the action's effect is
    # genuinely unknown rather than known-absent.
    "action_timeout": "outcome_unknown",
    "navigation_timeout": "outcome_unknown",
    "browser_disconnected": "outcome_unknown",
    "page_crashed": "outcome_unknown",
}

# One decision-chain failure onto the code the loop's telemetry records. The
# authority for what the OPERATOR is shown is ``_DECISION_PAUSE_REASONS`` in
# ``ops/onboarding/driver.py``, which reads the same exception after the retry
# bound is spent; this is only the per-attempt reject fact, restated here because
# importing the driver would close an import cycle.
_DECISION_REJECT_REASONS: Final[dict[str, OnboardingReasonCode]] = {
    "invalid_json": "decision_unusable",
    "schema_invalid": "decision_unusable",
}

# What the loop returns when it could not read the page even once. A phase that
# never observed anything still has to hand the driver an observation, and this
# one is deliberately inert: no human action, no credential labels, no developer
# app id, so nothing downstream can mistake it for a page that was seen. The URL
# is ``about:blank`` because ``BrowserObservation`` refuses anything that is not
# https-or-about, and it is the honest answer — no page was read.
_UNOBSERVED: Final = BrowserObservation(
    status="failed",
    current_url="about:blank",
    page_title="unobserved",
    reason_code="outcome_unknown",
)


def _act_status(executed: object) -> str:
    """The typed status of one executed candidate, refusing an untyped answer.

    A ``LoopSession`` that returns ``None`` — which is what every implementation
    did while ``act`` was declared ``-> None`` — is a programming error in the
    adapter, not a page outcome, so it raises rather than defaulting to
    ``executed``. Defaulting is precisely the bug this change exists to remove:
    "the session said nothing" must never read as "the action worked".
    """

    status = getattr(executed, "status", None)
    if status not in _ACT_STATUSES:
        raise TypeError("LoopSession.act must return an ActionExecutionResult")
    return str(status)


def _action_reason(executed: object, *, default: OnboardingReasonCode) -> OnboardingReasonCode:
    """One execution result's reason code, narrowed to the closed vocabulary."""

    reason = getattr(executed, "reason_code", None)
    if isinstance(reason, str):
        return _ACTION_REASONS.get(reason, default)
    return default


def _resumable_intent(pending: str | None, options: Sequence[ActionCandidate]) -> str | None:
    """The retained intent, but only if THIS snapshot still offers it.

    A stale retry is not a replay: the control has to survive re-generation, the
    risk filter, and the avoid list before it may be re-attempted. When it does
    not, the retry is dropped silently and the model decides afresh — which is the
    correct reading of "the element the plan named is gone".
    """

    if pending is None:
        return None
    return next((option.candidate_id for option in options if option.candidate_id == pending), None)


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
    # The page's visible PROSE, when the session can report it. Optional because
    # ``BrowserObservation`` has never carried page text and older sessions have
    # none to give; when it is empty the prompt falls back to the element render.
    # It is sanitized again here rather than trusted, on the same principle as
    # raw_elements: the loop owns the projection.
    page_text: str = ""


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

    async def act(self, candidate: ActionCandidate) -> ActionExecutionResult:
        """Execute one policy-generated candidate and report what happened.

        This used to be declared ``-> None``, and every consequence of that was
        live. ``run_action_loop`` counted an executed action unconditionally, so a
        server-side ``policy_blocked`` — which never touched the page — spent the
        action budget as though it had worked and never reached the denials
        counter. Worse, ``stale``, ``blocked`` and ``failed`` were all
        indistinguishable from success, so the loop's only reaction to any of them
        was to re-observe an unchanged page and conclude that nothing was
        happening. That is the largest single reason the agent "looked like it does
        nothing".

        POST: a typed :class:`~ops.playwright.actions.ActionExecutionResult`. The
              four statuses ask for four different corrections and the caller makes
              all four: ``executed`` verifies the postcondition against a fresh
              observation, ``stale`` re-observes and retries the SAME intent,
              ``blocked`` counts a denial and picks a different candidate, and
              ``failed`` avoids that target and tries a sibling. An implementation
              reports a refusal as a status; it does not raise one.
        """
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
    run_id: str = "",
    scratchpads: ScratchpadStore | None = None,
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
      Q7. ``actions_executed`` counts only actions the session reported as
          ``executed``. A refused or stale action is NOT an action: counting it
          spent the budget that buys the phase its remaining attempts.
      Q8. the only exceptions that leave this function are programming errors and
          a decision chain that failed ``MAX_DECISION_FAILURES`` times. Every
          other failure — a disconnected browser, a crashed page, a session
          adapter raising instead of reporting — becomes a classified outcome,
          because an exception escaping here unwinds ``_drive_phase`` and kills
          the whole run rather than the phase.

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
      I7. a retried intent is re-validated from scratch — regenerated from the
          fresh snapshot, re-risk-classified, re-resolved by identity — so
          "retry" never means "replay a decision made against a page that has
          since moved".
    """

    if goal.phase != phase:  # P3
        raise ValueError("the phase goal does not describe the phase being driven")

    started = clock()
    actions = model_calls = denials = no_progress = 0
    # Consecutive-failure counters, at parity with the worker's trace loop. They
    # are NOT budgets: a decision or an action that eventually succeeds must not
    # leave the phase closer to giving up, so both reset on the first success.
    decision_failures = action_failures = 0
    # 5.3: the candidate this iteration should re-try without asking the model
    # again, set when the page moved under an intent that was otherwise fine.
    # Candidate ids are stable across iterations (the checkpoint order is pinned
    # and the id is hashed from the element's identity), so the same control on a
    # re-rendered page produces the same id and the retry is exact.
    pending_intent: str | None = None
    # Candidate ids that the executor has already refused or failed on. Excluded
    # from later iterations so "pick a different candidate" is enforced rather
    # than hoped for — otherwise the model, shown the same page and the same
    # option list, re-picks the control that just bounced until a budget runs out.
    avoid: set[str] = set()
    satisfied_before: tuple[str, ...] = ()
    # 5.1: this phase's durable working memory. An unwired store or an empty
    # run id leaves it None and the loop drives exactly as it did before.
    memory = (
        load_scratchpad(
            scratchpads,
            run_id=run_id,
            phase=phase,
            goal=goal.instruction,
            postconditions=goal.postconditions,
        )
        if scratchpads is not None and run_id
        else None
    )

    def remember(
        candidate: ActionCandidate,
        status: str,
        *,
        reason_code: str | None = None,
        at: BrowserObservation | None = None,
    ) -> None:
        """Record one step and persist it; a no-op when memory is inert.

        ``at`` is the post-action observation for an executed step and defaults
        to this iteration's observation for the ones that never touched the page.
        Only the candidate's id, action and accessible name travel - never its
        selector - and ``scratchpad`` re-sanitizes all of them anyway.
        """

        nonlocal memory
        if memory is None or scratchpads is None:
            return
        where = observation if at is None else at
        memory = memory.with_step(
            candidate_id=candidate.candidate_id,
            label=candidate.semantic_target,
            action=candidate.action,
            status=status,
            reason_code=reason_code,
            url=where.current_url,
            title=where.page_title,
        )
        save_scratchpad(scratchpads, memory)

    iteration = 0
    step_started = started
    stage: LoopStage = "observe"

    def report(ended_at: LoopStage) -> None:
        """One progress row per iteration, so a stalled loop is visible (I5).

        ``step_index`` is floored at 1 because the durable sink's own bound is
        ``1 <= step_index``, and the PRE-LOOP observation reports at ``iteration
        == 0``. That combination raised ``ValueError`` out of the containment
        clause that exists precisely so an unreadable page cannot end the run —
        straight through ``_drive_phase`` and out of ``drive_run``, where the
        worker recorded ``driver_raised`` and re-deferred forever. The first
        report belongs to step 1.

        Telemetry never decides anything, so a sink that refuses a row must not
        stop the loop. It is logged and swallowed; the same is true of
        :func:`report_decision`.
        """

        progress = getattr(telemetry, "progress", None)
        if not callable(progress):
            return
        try:
            progress(
                step_index=max(iteration, 1),
                stage=ended_at,
                elapsed_ms=max(int((clock() - step_started) * 1000), 0),
            )
        except _PROGRAMMING_ERRORS:
            raise
        except Exception:
            LOGGER.warning("onboarding loop could not record a progress row", exc_info=True)

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
        try:
            record(
                step_index=max(iteration, 1),
                decision=outcome,
                reason_code=reason_code,
                candidate_label=None if candidate is None else candidate.semantic_target,
                action=None if candidate is None else candidate.action,
                target_host=None if candidate is None else candidate.url,
                reason=reason,
            )
        except _PROGRAMMING_ERRORS:
            raise
        except Exception:
            LOGGER.warning("onboarding loop could not record a decision row", exc_info=True)

    async def observe(seconds: float) -> LoopObservation:
        return await asyncio.wait_for(session.observe(), seconds)

    # The candidate whose action the session confirmed it EXECUTED but whose
    # effect was never read back, because the verifying observation timed out or
    # raised. Non-``None`` only inside that window.
    executed_unverified: ActionCandidate | None = None

    def _unverified_action(candidate: ActionCandidate) -> LoopResult:
        """End the phase after an action that ran but could not be verified.

        The alternative — carrying on — meant re-planning against the snapshot
        taken BEFORE the action, whose candidate ids still resolve, so the loop
        could pick the same control again. For an irreversible one ("Create API
        key", "Save") that mints a second credential at the provider and captures
        neither, up to ``MAX_ACTION_FAILURES`` times. ``outcome_unknown`` is the
        code the driver's effect bookkeeping already reads as "a second attempt
        must reconcile rather than repeat", which is exactly the situation.
        """

        remember(candidate, "failed", reason_code="outcome_unknown")
        telemetry.reject("outcome_unknown")
        report_decision("rejected", reason_code="outcome_unknown", candidate=candidate)
        return _result(
            "exhausted",
            observation,
            "outcome_unknown",
            actions=actions,
            model_calls=model_calls,
            denials=denials,
        )

    # Derived once: it is a property of the reviewed goal, not of the page, and
    # nothing inside the loop may widen it mid-phase.
    authorization = goal.authorization()

    # The FIRST observation sits outside the loop and therefore outside the
    # iteration's containment, so a session that cannot be read at all — a browser
    # that died between the phase boundary and here — used to raise straight
    # through ``_drive_phase`` and end ``drive_run``, losing the lease release and
    # the phase's counters with it. Contained on the same terms as every later
    # observation: an unreadable page is a phase that cannot run, not a run that
    # cannot continue (Q8).
    try:
        seen = await observe(deadlines.observe_seconds)
    except _PROGRAMMING_ERRORS:
        raise
    except Exception:
        report("observe")
        return _result(
            "exhausted",
            _UNOBSERVED,
            "outcome_unknown",
            actions=actions,
            model_calls=model_calls,
            denials=denials,
        )

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
            # RANK, then project. ``build_snapshot`` truncates at ``MAX_ELEMENTS``
            # in collection order, so projecting the raw list directly kept the
            # first 40 elements the DOM happened to yield and discarded the rest
            # unseen. On a settings page whose "Create API token" button sits at
            # position 60, the agent was never shown the one control the whole
            # phase exists to click, and every iteration then legitimately reported
            # no useful candidate. The worker path never had this problem because
            # it collects through ``build_ranked_snapshot``; this is the same
            # ranking applied to already-collected elements, which is all the loop
            # has — the locators live in the browser process.
            elements = build_snapshot(
                rank_raw_elements(
                    [dict(raw) for raw in seen.raw_elements],
                    checkpoint_signals=goal.signals,
                    limit=MAX_ELEMENTS,
                )
            )
            candidates = generate_candidates(
                elements=elements,
                checkpoint_signals=goal.signals,
                # A candidate id is hashed from (trace_version, checkpoint_order,
                # action, name). Feeding the iteration counter here gave the SAME
                # control a different id on every turn, so nothing downstream can
                # recognise an option it has already tried or already been denied.
                # The phase is the checkpoint on this path — it is already in
                # trace_version — so the order is pinned and ids stay stable for
                # as long as the page does.
                checkpoint_order=0,
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
            # TWO filters, not one, and the second is the authoritative one.
            # ``executable_candidates`` reads ``ActionCandidate.executable``, which
            # the generator derives from a substring list that names neither
            # ``create``/``generate`` nor ``save``/``apply`` — so on this path
            # "Create API key" and "Save" arrived marked low-risk and were clicked
            # autonomously, bypassing the credential-creation authority entirely.
            # The worker's trace loop has always consulted the real policy; this is
            # that same policy, on the same terms, in front of this loop.
            options, first_denied = _autonomous_options(
                executable_candidates(candidates), elements, authorization
            )
            # 5.3, the "pick a DIFFERENT candidate" half: a control the executor
            # already refused or already failed on is withheld from the model.
            # Dropped wholesale when it would leave nothing to choose from — an
            # avoid set that covers the whole page is stale relative to a page
            # that has since re-rendered, and manufacturing a human gate out of it
            # would be exactly the unnecessary HITL this loop exists to avoid. The
            # budgets, not this filter, are what stop a genuinely stuck phase.
            options = [option for option in options if option.candidate_id not in avoid] or options
            if not options:
                # Every option on this page is an irreversible or privilege-changing
                # control. Requirement 4.18: hand it to a human, unexecuted. The
                # risk verdict names WHICH control and which verb family, so the
                # operator is asked for the decision the page actually needs rather
                # than a generic "provider action".
                report("gate")
                gated, verdict = first_denied if first_denied is not None else (candidates[0], None)
                return _gate(
                    gated,
                    observation,
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                    category=verdict.category if verdict is not None else "",
                )

            # --- 5.3, the "retry the SAME intent" half ------------------------
            # A ``stale`` action means the DOM moved under us, not that the intent
            # was wrong, so the correction is to re-plan the same control against
            # the snapshot we just took — NOT to buy a second opinion. Re-deciding
            # would spend a model call and, on a page that keeps re-rendering,
            # could spend the whole model budget re-answering a question that was
            # already answered correctly. The retry still passes every gate below
            # (risk, identity, navigation): only the model call is skipped (I7).
            chosen_id = _resumable_intent(pending_intent, options)
            pending_intent = None
            choice_reason: str | None = None

            if chosen_id is None:
                # --- DLP: the ONLY path from page to model -------------------
                stage = "decide"
                memory_block = "" if memory is None else render_scratchpad(memory)
                prompt = build_choice_prompt(
                    app_name=goal.provider_name,
                    credential_goal=goal.description,
                    checkpoint_instruction=(
                        f"{memory_block}\n\n{goal.instruction}"
                        if memory_block
                        else goal.instruction
                    ),
                    checkpoint_signals=goal.signals,
                    current_url=sanitize_url(observation.current_url),
                    page_title=sanitize_page_text(observation.page_title, origin="title"),
                    rendered_candidates=render_candidates(options),
                    # Prose when the session reports it — visible text is what tells
                    # "create a key" apart from "here is your key" — and the element
                    # render only as a fallback, since CANDIDATES above already lists
                    # every actionable control.
                    rendered_page=(
                        sanitize_page_text(seen.page_text)
                        if seen.page_text
                        else render_snapshot(_sanitized(elements))
                    ),
                )
                screened = screen_model_input(prompt)
                if not screened.allowed:  # Requirement 4.19, Q5
                    telemetry.dlp_refusal()
                    no_progress += 1
                    report("decide")
                    seen = await observe(deadlines.observe_seconds)
                    continue

                # --- I4: the model may only name an id generated right here ---
                # Over `options`, not `candidates`: the prompt renders only the
                # executable ones, so building the schema enum from the full set
                # offered ids for controls the model was never shown — it picked one,
                # validate_choice accepted it (it IS in the generated set), and the
                # gated candidate then went to a human. The enum and the rendered list
                # have to be the same list.
                candidate_ids = [candidate.candidate_id for candidate in options]
                try:
                    payload = await asyncio.wait_for(
                        decider.choose(
                            screened.prompt, schema=candidate_choice_schema(candidate_ids)
                        ),
                        deadlines.decide_seconds,
                    )
                except DecisionFailed as failure:
                    # Parity with the worker's trace loop, which retries a failed
                    # decision ``_MAX_MODEL_FAILURES`` times. This loop used to let
                    # the FIRST failure propagate out to ``_drive_phase``, so a
                    # single rate-limit on the first provider paused a run that the
                    # very next call would have driven. The failure costs no model
                    # call (none was answered) but does cost a no-progress rung, so
                    # a chain that is down cannot spin here for free.
                    decision_failures += 1
                    unusable = _DECISION_REJECT_REASONS.get(
                        failure.reason_code, "decision_provider_failed"
                    )
                    telemetry.reject(unusable)
                    report_decision("rejected", reason_code=unusable)
                    no_progress += 1
                    report("decide")
                    if decision_failures >= MAX_DECISION_FAILURES:
                        # Re-raised rather than classified: ``step_for_decision_failure``
                        # is the authority on which decision cause the operator is
                        # shown, and it needs the typed exception to say so (R4.5,
                        # R4.6).
                        raise
                    continue
                decision_failures = 0
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
                chosen_id = choice.candidate_id
                choice_reason = choice.reason
                if memory is not None and choice.reason:
                    # The running hypothesis comes from the `reason` the choice
                    # schema ALREADY requires - no new output channel, and the
                    # model still emits only a candidate_id from the closed enum.
                    memory = memory.with_hypothesis(choice.reason)

            selected = _by_id(candidates, chosen_id)
            if selected is None:  # unreachable while validate_choice holds
                telemetry.reject("action_not_in_candidate_set")
                report_decision("rejected", reason_code="action_not_in_candidate_set")
                no_progress += 1
                report("decide")
                seen = await observe(deadlines.observe_seconds)
                continue
            report_decision("select_candidate", candidate=selected, reason=choice_reason)
            if not selected.executable:  # Requirement 4.18, left unexecuted
                report("gate")
                return _gate(
                    selected, observation, actions=actions, model_calls=model_calls, denials=denials
                )
            # Re-checks executability at the policy boundary rather than trusting the
            # branch above.
            candidate = select_candidate(candidates, chosen_id)

            # And re-checks RISK at the same boundary, for the same reason. The
            # filter above decided what the model was allowed to see; this decides
            # what is allowed to run. They are computed from the same authorization
            # and the same snapshot, so they agree — but only this one stands
            # between a model reply and a live click, so it is the one that must be
            # unconditional.
            verdict = _risk_of(candidate, elements, authorization)
            if not verdict.autonomous_allowed:
                telemetry.reject("candidate_risk_requires_human")
                report_decision(
                    "rejected", reason_code="candidate_risk_requires_human", candidate=candidate
                )
                report("gate")
                return _gate(
                    candidate,
                    observation,
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                    category=verdict.category,
                )

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
                    remember(candidate, "not_attempted", reason_code=unresolved)
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
            executed = await asyncio.wait_for(session.act(candidate), deadlines.act_seconds)
            status = _act_status(executed)

            if status == "stale":
                # The page moved between the snapshot the plan was made against
                # and the moment it ran. The INTENT was fine — so it is kept, on
                # ``pending_intent``, and re-validated against the next snapshot.
                # Nothing executed, so nothing is charged to the action budget; a
                # no-progress rung is charged, because a page that keeps moving
                # under us is exactly the shape of a stuck phase.
                remember(candidate, "stale")
                pending_intent = candidate.candidate_id
                no_progress += 1
                report("act")
                seen = await observe(deadlines.observe_seconds)
                continue

            if status == "blocked":
                # The executor's own boundary refused this action, so the page was
                # never touched. This is the counter it belongs in — before, it
                # was counted as an executed action, which both spent the action
                # budget and hid the denial from the run's denial facts entirely.
                reason = _action_reason(executed, default="browser_host_not_in_app_policy")
                remember(candidate, "blocked", reason_code=reason)
                denials += 1
                avoid.add(candidate.candidate_id)
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

            if status == "failed":
                # A typed action failure: the target vanished, the click did
                # nothing, the navigation errored. The intent is what is suspect
                # here (unlike ``stale``), so the target is added to ``avoid`` and
                # the next iteration picks a SIBLING identity. Bounded at parity
                # with the worker's ``_MAX_ACTION_FAILURES``; past that the page is
                # not one this phase can drive, and the reason code says which
                # failure it was rather than a generic exhaustion.
                action_failures += 1
                avoid.add(candidate.candidate_id)
                reason = _action_reason(executed, default="postcondition_failed")
                remember(candidate, "failed", reason_code=reason)
                telemetry.reject(reason)
                report_decision("rejected", reason_code=reason, candidate=candidate)
                no_progress += 1
                report("act")
                if action_failures >= MAX_ACTION_FAILURES:
                    return _result(
                        "exhausted",
                        observation,
                        reason,
                        actions=actions,
                        model_calls=model_calls,
                        denials=denials,
                    )
                seen = await observe(deadlines.observe_seconds)
                continue

            # Q7: only here, where the session reported the action actually ran.
            action_failures = 0
            avoid.discard(candidate.candidate_id)
            actions += 1
            telemetry.action(candidate_id=candidate.candidate_id, actions_executed=actions)

            stage = "verify"
            # Recorded BEFORE the verifying observation, not after. The scratchpad
            # entry used to be written only once ``observe`` returned, so an action
            # that ran and then could not be read left no trace of having run at
            # all — and the next iteration re-planned against the PRE-action
            # snapshot with the same candidate ids, which is how "Create API key"
            # could be clicked more than once. ``executed_unverified`` is what the
            # containment clauses below read to refuse exactly that.
            executed_unverified = candidate
            remember(candidate, "executed")
            seen = await observe(deadlines.verify_seconds)
            executed_unverified = None
            check = check_postconditions(
                goal, seen.observation, previously_satisfied=satisfied_before
            )
            if memory is not None:
                memory = memory.with_postconditions(check.satisfied)
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
            if executed_unverified is not None:
                return _unverified_action(executed_unverified)
            no_progress += 1
        except _PROGRAMMING_ERRORS:
            # The same rule the worker's trace loop keeps: a programming error is
            # never a page outcome. It propagates so tests and monitoring see it,
            # and it is listed BEFORE the containment clause below so the
            # containment cannot swallow it.
            raise
        except DecisionFailed:
            # Re-raised from the decide branch once the retry bound is spent. It
            # is a ``RuntimeError``, so without this clause the containment below
            # would swallow the one exception the driver is written to catch and
            # the operator would be shown "outcome unknown" instead of which
            # decision cause stopped the phase.
            raise
        except Exception:
            # Q8. Until this existed the loop's only handler was ``TimeoutError``,
            # so a disconnected browser, a crashed renderer, a closed target, or a
            # session adapter that raised instead of reporting unwound
            # ``run_action_loop`` -> ``_drive_phase`` -> ``drive_run`` and ended
            # the RUN. A phase that cannot be driven has to report that it cannot
            # be driven; it does not get to take the walk down with it.
            #
            # ``act`` is the one stage whose side effect we cannot see, so it is
            # terminal on the first occurrence and carries ``outcome_unknown`` —
            # the same code its timeout carries, and the code the driver's effect
            # bookkeeping already reads as "a second attempt must reconcile rather
            # than repeat". Every other stage is retried at parity with a failed
            # action, because a transient read is worth re-reading.
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
            if executed_unverified is not None:
                return _unverified_action(executed_unverified)
            action_failures += 1
            no_progress += 1
            if action_failures >= MAX_ACTION_FAILURES:
                return _result(
                    "exhausted",
                    observation,
                    "outcome_unknown",
                    actions=actions,
                    model_calls=model_calls,
                    denials=denials,
                )


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


_RISK_POLICY: Final = BrowserActionRiskPolicy()


def _risk_of(
    candidate: ActionCandidate,
    elements: Sequence[SnapshotElement],
    authorization: ActionAuthorization,
) -> RiskDecision:
    """The central risk verdict for one candidate against this snapshot.

    The element is resolved for CONTEXT only — the policy reads its role, name and
    ``secretish`` flag. A candidate whose identity does not resolve here still gets
    a verdict (on its own semantic target), because "the element vanished" must not
    read as "the action is safe"; the loop's own identity re-resolution, further
    down, is what refuses to act on it.
    """

    element: SnapshotElement | None = None
    if candidate.identity is not None:
        _, element = resolve_identity(candidate.identity, elements)
    return _RISK_POLICY.classify(candidate=candidate, authorization=authorization, element=element)


def _autonomous_options(
    candidates: Sequence[ActionCandidate],
    elements: Sequence[SnapshotElement],
    authorization: ActionAuthorization,
) -> tuple[list[ActionCandidate], tuple[ActionCandidate, RiskDecision] | None]:
    """Split candidates into what may run autonomously and why the rest may not.

    Returns the allowed list plus the FIRST refusal with its verdict. The refusal
    is kept rather than counted because when nothing is allowed it is the only
    thing that can tell the operator what decision the page is asking for — a
    billing wall and an unreviewed "Generate key" button both leave this list
    empty, and they need different humans.
    """

    allowed: list[ActionCandidate] = []
    first_denied: tuple[ActionCandidate, RiskDecision] | None = None
    for candidate in candidates:
        verdict = _risk_of(candidate, elements, authorization)
        if verdict.autonomous_allowed:
            allowed.append(candidate)
        elif first_denied is None:
            first_denied = (candidate, verdict)
    return allowed, first_denied


def _gate(
    candidate: ActionCandidate | None,
    observation: BrowserObservation,
    *,
    actions: int,
    model_calls: int,
    denials: int,
    category: str = "",
) -> LoopResult:
    """A gate outcome that always names the human action, candidate unexecuted."""

    return _result(
        "gate",
        _gate_observation(observation, candidate, category=category),
        "candidate_risk_requires_human",
        actions=actions,
        model_calls=model_calls,
        denials=denials,
    )


def _gate_observation(
    observation: BrowserObservation,
    candidate: ActionCandidate | None,
    *,
    category: str = "",
) -> BrowserObservation:
    """Project an observation into one that names the human action required.

    The page's own typed human action wins when it has one; otherwise the action
    comes from the risk policy's verb family when a verdict supplied one, and
    failing that from the candidate's own irreversible category — so the driver
    never has to guess what to ask the operator for. The verdict is preferred
    because its vocabulary is the wider of the two: the candidate generator's
    category set omits the credential-creation and persistence families entirely.
    """

    if observation.human_action_type is not None:
        return observation
    if not category and candidate is not None:
        if candidate.expected_postcondition.startswith("human_decision:"):
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
