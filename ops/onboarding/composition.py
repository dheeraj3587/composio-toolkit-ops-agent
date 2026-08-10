"""The composition root: every onboarding port bound to an implementation.

This is the one module that is allowed to know both halves of design LL-2. Every
port is a ``typing.Protocol`` satisfied structurally, so the direction of every
dependency in the feature points *away* from the phase driver: a store, a mailbox,
a validator, or a research adapter never imports ``ops.onboarding.driver``, and
adding an adapter is implementing a protocol plus one line here.

Three things follow from that and are worth stating because they are the reason
this file exists rather than the wiring being spread across call sites.

**Absence is reported, never faked.** A port whose implementation needs
configuration the deployment does not have is bound to ``None`` and named in
:attr:`OnboardingPorts.unavailable`. The driver already treats an unwired mailbox,
validator, or login binder as a pause with an honest reason code, so a partially
configured deployment degrades to "this run cannot get past that phase" instead of
to a guess. The two failure modes stay distinct, per ``CLAUDE.md``: a flag that is
on with its credential missing is a deployment mistake and raises
:class:`~ops.providers.errors.ConfigurationRequiredError`; nothing configured at all
is an unavailability this root records.

**The browser is supplied, not constructed here.** ``sessions`` — the port the
action loop observes and acts through — is an argument to
:meth:`OnboardingPorts.deps_for` rather than a field of this root, because the
component that owns a bound browser session owns its lifecycle. This root binds
everything that is durable state, a model backend, a mailbox, or a policy.

**The one host constraint.** Every store below is SQLite-backed, so a deployment
that uses this root runs onboarding workers on exactly one host
(Requirement 21.7). Swapping the four stores and the queue for shared-transaction
implementations is a change to :func:`build_onboarding_ports` and nothing else,
which is what Requirement 21.6 asks the port boundary to make true.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ops.browser.login import LoginRouteHandler
from ops.browser.signup import (
    SignupCredentialVault,
    SignupMailboxBinder,
    SignupPhaseHandler,
    SignupRunBinding,
    SignupSubmitter,
    enter_signup,
)
from ops.core.config import Settings
from ops.core.effect_ledger import EffectStore, SQLiteEffectStore
from ops.core.inference import DecisionOutcome, JsonInference, build_json_inference
from ops.core.model_catalog import ModelSelection
from ops.core.redaction import install_redacting_filter
from ops.core.secret_store import SQLiteSecretStore
from ops.core.state import CredentialCreationPolicy
from ops.core.storage import OperationsStorage
from ops.email.verification_provider import VerificationProvider
from ops.gmail.verification_provider import default_verification_provider
from ops.onboarding.action_loop import (
    CandidateDecider,
    LoopBudget,
    LoopStage,
    LoopTelemetry,
    PhaseGoal,
    StepDeadlines,
    StepDecision,
)
from ops.onboarding.admission import CredentialReferenceProbe
from ops.onboarding.credentials import (
    CredentialBudgets,
    CredentialCaptureVault,
    CredentialLifecycleDeps,
    CredentialValidatorPort,
    ProfileBoundCredentialValidator,
    ProviderConfigurationPublisher,
    build_profile_bound_validator,
)
from ops.onboarding.driver import (
    AutonomyOutcomeStore,
    CaptchaBudget,
    CaptchaPauseStore,
    DeveloperAppBinding,
    DeveloperAppPhaseHandler,
    LedgerAutonomyOutcomes,
    LoginReferenceBinder,
    LoopSessionFactory,
    OnboardingDeps,
    PhaseGoalFactory,
    PhaseHandler,
    PhaseHistoryStore,
    RecoveryEffectReader,
    RunPlanner,
    RunPlanValidator,
    SQLitePhaseHistoryStore,
    VerificationBinding,
    VerificationBudget,
    VerificationSecretVault,
)
from ops.onboarding.handlers import (
    AdmissionDecisionStore,
    RunAccountBinding,
    RunProviderBinding,
    onboarding_phase_handlers,
)
from ops.onboarding.lease import LeaseStore, LeaseTimings, RunQueue
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.loop_telemetry import DenialFactStore, DurableLoopTelemetry
from ops.onboarding.phase import (
    ONBOARDING_REASON_CODES,
    OnboardingPhase,
    OnboardingReasonCode,
)
from ops.onboarding.publishers import (
    ComposioProviderConfigurationPublisher,
    LedgerDeveloperAppBinding,
    LedgerRunAccountBinding,
    LedgerRunProviderBinding,
    LedgerSignupMailboxBinder,
    LedgerSignupRunBinding,
    LedgerVerificationBinding,
    VaultLoginReferenceBinder,
)
from ops.onboarding.setup_refs import phase_value_refs, run_setup_values
from ops.onboarding.standing_authorization import SettingsStandingSignupAuthority
from ops.planner.adherence import RouteAdherenceMonitor
from ops.planner.decide import PlanOutcome, decide_run_plan
from ops.planner.store import RunPlanStore, SQLiteRunPlanStore
from ops.planner.validator import PlanRefusal, validate_plan
from ops.providers.composio_managed_auth import ComposioManagedAuthProvider
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.providers.profile import MAX_FLOW_STEPS, FlowSpec, ProviderProfile
from ops.providers.profile_builder import (
    DiscoveryAdapter,
    ProfileEvidenceFetcher,
    ProfileExtractor,
    research_adapters,
)
from ops.providers.profile_extractor import ProfileClaimExtractor
from ops.providers.profile_fetcher import DomainElectedEvidenceFetcher
from ops.providers.profile_store import ProviderProfileStore, SQLiteProviderProfileStore
from ops.recipes.app_recipes import AppRecipe

LOGGER = logging.getLogger("composio_ops.onboarding_composition")

# The profile store's own file, kept beside the run ledger the same way every
# other private database in this deployment is.
PROFILE_DATABASE_NAME = "provider_profiles.db"

# What an unbound port is reported as. Each is a closed onboarding reason code, so
# an unavailability can be projected onto the API or written onto a boundary
# without translation (Requirement 20.2). They are the SAME codes the phases
# themselves pause with when they find the port missing — the mailbox pauses with
# ``verification_unresolved`` and the credential lifecycle pauses with
# ``capture_spec_unavailable`` — so a reader does not have to learn a second
# vocabulary for "this deployment cannot do that".
MAILBOX_UNAVAILABLE: OnboardingReasonCode = "verification_unresolved"
VALIDATOR_UNAVAILABLE: OnboardingReasonCode = "capture_spec_unavailable"
# ``build_json_inference`` returned ``None``: no provider key is configured, which
# is the cause Requirement 4.4 names rather than a spent model-call budget.
DECIDER_UNAVAILABLE: OnboardingReasonCode = "decision_provider_unconfigured"
RESEARCH_UNAVAILABLE: OnboardingReasonCode = "research_adapters_unavailable"
# Composio has no key, or no public HTTPS callback origin is configured, so the
# terminal step of the credential lifecycle has nowhere to publish to. The
# lifecycle's own code for a port it needs and does not have, for the same reason
# the validator uses it: a run reaches it at the same place either way.
PUBLISHER_UNAVAILABLE: OnboardingReasonCode = "capture_spec_unavailable"
# No signup submitter is bound, so ``signup`` has no handler and the generic loop
# dispatch would drive it — which is exactly the store-before-submit ordering the
# handler exists to keep. Reported with the code the phase itself refuses with.
SIGNUP_UNAVAILABLE: OnboardingReasonCode = "signup_policy_absent"
# No login route worker/broker/gate seam is bound, so a run the vault probe routed
# to ``login`` has no handler for it.
LOGIN_ROUTE_UNAVAILABLE: OnboardingReasonCode = "credentials_missing"

assert {
    MAILBOX_UNAVAILABLE,
    VALIDATOR_UNAVAILABLE,
    DECIDER_UNAVAILABLE,
    RESEARCH_UNAVAILABLE,
    PUBLISHER_UNAVAILABLE,
    SIGNUP_UNAVAILABLE,
    LOGIN_ROUTE_UNAVAILABLE,
} <= set(ONBOARDING_REASON_CODES), (
    "an unavailable port must be reported with a closed onboarding reason code"
)


class RunDenialTelemetry:
    """Loop telemetry that attributes each denial to the run's committed phase.

    :class:`~ops.onboarding.loop_telemetry.DurableLoopTelemetry` is constructed per
    phase because a denial fact names the phase and the profile whose allow-list
    denied it, while :class:`~ops.onboarding.driver.OnboardingDeps` holds one
    telemetry for the whole walk. This adapter closes that gap by reading the phase
    and the digest from the phase history at the moment of the denial — which is
    exact, because the driver commits the boundary into a phase before driving it.

    A run with no committed boundary cannot have navigated anywhere, so a denial
    arriving then is logged rather than attributed to a phase that does not exist.
    """

    def __init__(
        self,
        *,
        store: DenialFactStore,
        phases: PhaseHistoryStore,
        run_id: str,
    ) -> None:
        self._store = store
        self._phases = phases
        self._run_id = run_id
        self.denials = 0
        self.rejects = 0
        self.dlp_refusals = 0
        self.actions_executed = 0
        self.model_calls = 0

    def denial(self, reason_code: OnboardingReasonCode) -> None:
        """Record one navigation denial against the run's current phase (5.15)."""

        self.denials += 1
        durable = self._durable()
        if durable is None:
            LOGGER.warning(
                "navigation denied before any phase boundary was committed",
                extra={"run_id": self._run_id, "reason_code": reason_code},
            )
            return
        durable.denial(reason_code)

    def reject(self, reason_code: OnboardingReasonCode) -> None:
        """Count one discarded model selection (Requirements 4.5, 4.7, 4.8)."""

        self.rejects += 1
        LOGGER.info(
            "model selection discarded",
            extra={"run_id": self._run_id, "reason_code": reason_code},
        )

    def dlp_refusal(self) -> None:
        """Count one refused page projection (`dlp_prompt_refused`, 4.19)."""

        self.dlp_refusals += 1
        LOGGER.warning(
            "page projection refused",
            extra={"run_id": self._run_id, "reason_code": "dlp_prompt_refused"},
        )

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        """Adopt the loop's running executed-action total."""

        self.actions_executed = actions_executed

    def model_call(self, *, model_calls: int) -> None:
        """Adopt the loop's running model-call total."""

        self.model_calls = model_calls

    def progress(self, *, step_index: int, stage: LoopStage, elapsed_ms: int) -> None:
        """Record one completed loop iteration against the run's phase (R4.1)."""

        durable = self._durable()
        if durable is None:
            return
        durable.progress(step_index=step_index, stage=stage, elapsed_ms=elapsed_ms)

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
        """Record one iteration's decision against the run's phase."""

        durable = self._durable()
        if durable is None:
            return
        durable.decision(
            step_index=step_index,
            decision=decision,
            reason_code=reason_code,
            candidate_label=candidate_label,
            action=action,
            target_host=target_host,
            reason=reason,
        )

    def record_attempt(self, *, provider: str, outcome: DecisionOutcome, latency_ms: int) -> None:
        """Record one inference attempt against the run's phase (R4.3)."""

        durable = self._durable()
        if durable is None:
            return
        durable.record_attempt(provider=provider, outcome=outcome, latency_ms=latency_ms)

    def _durable(self) -> DurableLoopTelemetry | None:
        """The per-phase durable telemetry for where the run stands right now."""

        history = self._phases.history(run_id=self._run_id)
        if not history:
            return None
        boundary = history[-1]
        return DurableLoopTelemetry(
            store=self._store,
            run_id=self._run_id,
            phase=boundary.to_phase,
            profile_digest=boundary.profile_digest,
            correlation_id=boundary.correlation_id,
        )


class ProfileGoals:
    """The phase goals, built from the run's committed profile and nothing else.

    Every goal's postcondition tuple comes from
    :data:`~ops.onboarding.action_loop.PHASE_POSTCONDITIONS` through
    :meth:`~ops.onboarding.action_loop.PhaseGoal.for_phase`, so this factory cannot
    lower the bar a phase is judged against. What it does supply is prose for the
    prompt and the reviewed URLs a ``goto`` candidate may use — and those URLs are
    the profile's own, so the model can only be offered a destination the profile
    already authorized.

    ``values`` is the run's approved non-secret value map — the same one its
    browser session is seeded with. It is a constructor argument rather than a
    ``goal_for`` parameter because it is a property of the RUN and this factory is
    already built per run by :meth:`OnboardingPorts.deps_for`; threading it through
    the port signature would have made every implementation of
    :class:`~ops.onboarding.driver.PhaseGoalFactory` carry a parameter only one of
    them can use. Empty is the safe default and the pre-existing behaviour: the
    goal then declares no fillable references and the loop emits no ``fill``
    candidates, which is where the driver stood before.

    ``credential_creation_policy`` is the RUN's own immutable column, read from the
    ledger row by :meth:`OnboardingPorts.deps_for` and carried here for the same
    reason ``values`` is: it is a property of the run, not of the phase. It is one
    HALF of the credential-creation gate — the other half is the reviewed control
    names the profile carries — and the two are ANDed by
    :meth:`~ops.browser.risk.ActionAuthorization.for_phase`, exactly as the worker's
    trace loop ANDs them. Deriving one half from the other would collapse the gate,
    so this factory only ever passes the run's answer through.
    """

    def __init__(
        self,
        values: Mapping[str, str] | None = None,
        *,
        credential_creation_policy: str | None = None,
    ) -> None:
        self._values: Mapping[str, str] = dict(values or {})
        self._creation_policy: CredentialCreationPolicy = _creation_policy(
            credential_creation_policy
        )

    # Phase -> (description, instruction, the code a satisfied postcondition
    # earns). The closed vocabulary has one code for "the run now holds an
    # authenticated session" — the same ``credentials_present`` that
    # ``ops.browser.login`` records for an accepted sign-in — so both
    # session-reaching phases carry it rather than inventing a synonym.
    _PROSE: Mapping[OnboardingPhase, tuple[str, str, OnboardingReasonCode]] = {
        "route_selected_login": (
            "Sign in to the provider with the credentials this run already stored.",
            "Complete the sign-in form and reach an authenticated console.",
            "credentials_present",
        ),
        "signup": (
            "Create this run's account with the provider.",
            "Complete and submit the provider's sign-up form once.",
            "signup_submitted",
        ),
        "email_verification": (
            "Complete the provider's email verification for this run.",
            "Confirm the provider accepted the verification the mailbox supplied.",
            "verification_email_found",
        ),
        "authenticated": (
            "Reach the provider's developer console for this account.",
            "Navigate to the developer area of the authenticated account.",
            "credentials_present",
        ),
        "developer_app": (
            "Create the developer application this run's credential comes from.",
            "Create one developer application with the requested name.",
            "developer_app_created",
        ),
        "credential_generation": (
            "Generate the credential this run was started for.",
            "Generate the credential and leave it visible for capture.",
            "credential_generated",
        ),
    }

    def goal_for(self, *, phase: OnboardingPhase, profile: ProviderProfile) -> PhaseGoal:
        """The goal for ``phase`` under ``profile``'s reviewed URLs."""

        prose = self._PROSE.get(phase)
        if prose is None:
            raise ValueError(f"no phase goal is declared for {phase!r}")
        description, instruction, success = prose
        creation_controls = _reviewed_controls(phase, profile)
        return PhaseGoal.for_phase(
            phase,
            provider_name=profile.provider_name,
            description=description,
            instruction=instruction,
            success_reason_code=success,
            # The flow prose that grounds candidate ranking. Passing nothing here
            # left the loop ranking on an empty needle set, which degenerates to
            # "the first eight named elements the page happened to yield" — on a
            # settings page that is a nav bar.
            signals=_reviewed_signals(phase, profile),
            reviewed_goto_urls=_reviewed_urls(phase, profile),
            # What this phase is allowed to TYPE. With nothing here
            # ``ops.browser.candidates`` emits no ``fill`` and no
            # ``select_option``, so the loop's whole live alphabet was
            # click/press/goto and no form on any app could be completed. The set
            # is the phase's declared references intersected with the values this
            # run actually carries, so a reference the session was never seeded
            # with never becomes a candidate.
            allow_value_refs=phase_value_refs(phase, self._values),
            # Half one of the gate: the accessible names a human reviewed as the
            # controls that may create a credential on THIS phase's pages. Only
            # the phases whose declared purpose IS to create something carry any,
            # so a "Generate key" button appearing on a login page gates to a
            # human rather than being clicked.
            credential_creation_controls=creation_controls,
            # Half two: what the RUN asked for, read from its own immutable
            # column. Synthesizing it from ``creation_controls`` — as this line
            # used to — collapsed the two halves into one, so any profile that
            # named a control authorized creation no matter what the run was
            # started with. The run's answer passes through untouched; the AND
            # lives in ``ActionAuthorization.for_phase``.
            credential_creation_policy=self._creation_policy,
        )


def _creation_policy(value: object) -> CredentialCreationPolicy:
    """``value`` read as a credential-creation policy, failing closed.

    PRE:  ``value`` is whatever the run's ledger row carried in its
          ``credential_creation_policy`` column — which for a row written before
          the column existed, or read back from a store that lost it, is ``None``.
    POST: ``"create_if_missing"`` only when the run said exactly that. Absent,
          unreadable, mistyped and unrecognised values all become ``"reuse_only"``,
          because the failure mode of guessing the other way is creating a
          credential no run authorized.
    """

    return "create_if_missing" if value == "create_if_missing" else "reuse_only"


def _reviewed_urls(phase: OnboardingPhase, profile: ProviderProfile) -> tuple[str, ...]:
    """The profile URLs a ``goto`` candidate may use in ``phase``.

    Narrow per phase rather than "every URL the profile carries": a signup phase has
    no business navigating to the credential surface, and the allow-list is a
    ceiling rather than a menu.
    """

    flows = {
        "developer_app": (
            profile.developer_app_flow.entry_url,
            profile.developer_portal_url,
        ),
        "credential_generation": (
            profile.api_key_flow.entry_url,
            profile.pat_flow.entry_url,
            profile.oauth_flow.entry_url,
        ),
        "authenticated": (profile.developer_portal_url,),
        "signup": (profile.signup_url,),
        "route_selected_login": (profile.login_url,),
        "email_verification": (),
    }
    return tuple(url for url in flows.get(phase, ()) if url)


def _phase_flows(phase: OnboardingPhase, profile: ProviderProfile) -> tuple[FlowSpec, ...]:
    """The profile flows whose reviewed description governs ``phase``.

    The same per-phase narrowing :func:`_reviewed_urls` applies to URLs, applied
    to prose and control names: the credential phase is described by the
    credential-producing flows, not by the developer-app flow that preceded it.
    """

    per_phase: dict[str, tuple[FlowSpec, ...]] = {
        "developer_app": (profile.developer_app_flow,),
        "credential_generation": (
            profile.api_key_flow,
            profile.pat_flow,
            profile.oauth_flow,
        ),
    }
    return tuple(flow for flow in per_phase.get(phase, ()) if flow.supported)


def _reviewed_signals(phase: OnboardingPhase, profile: ProviderProfile) -> tuple[str, ...]:
    """The declared, non-secret prose this phase's candidate ranking is grounded in."""

    signals: list[str] = []
    for flow in _phase_flows(phase, profile):
        signals.extend(flow.steps)
        signals.extend(flow.control_names)
    return tuple(dict.fromkeys(signals))[:MAX_FLOW_STEPS]


def _reviewed_controls(phase: OnboardingPhase, profile: ProviderProfile) -> tuple[str, ...]:
    """The controls a reviewer named as the ones that may create a credential here."""

    names: list[str] = []
    for flow in _phase_flows(phase, profile):
        names.extend(flow.control_names)
    return tuple(dict.fromkeys(names))


class InferenceCandidateDecider:
    """The loop's inference backend, bound to the deployment's provider chain.

    The loop owns prompt construction and validation, so this adapter is only the
    transport: it hands the already-sanitized prompt and the schema restricted to
    this iteration's candidate ids to :class:`~ops.core.inference.JsonInference` and
    returns the reply unvalidated, exactly as the port documents. The call is
    synchronous inside the inference stack (it manages its own per-provider
    timeouts and circuit breaker), so it runs in a worker thread rather than
    blocking the driver's event loop.
    """

    def __init__(self, inference: JsonInference) -> None:
        self._inference = inference

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        """Return the backend's JSON reply for ``prompt`` under ``schema``."""

        result = await asyncio.to_thread(self._inference.generate, prompt, schema=schema)
        return result.payload


class SettingsRunPlanner:
    """The planner bound to this deployment's settings and provider chain.

    The decision, the budget and the recipe-only fallback all live in
    ``ops.planner.decide``; this is the transport that supplies the settings the
    driver has no business holding.
    """

    def __init__(self, settings: Settings, *, inference: JsonInference | None = None) -> None:
        self._settings = settings
        self._inference = inference

    def plan_for(
        self, *, recipe: AppRecipe, revision: int, evidence: str = ""
    ) -> PlanOutcome | PlanRefusal:
        """Plan ``recipe``'s route, falling back to the reviewed route as decided.

        ``evidence`` is sanitized prose about this run -- on the one authorized
        re-plan, ``ops.planner.adherence.replan_evidence`` saying where the run
        actually landed. Passing nothing was the bug: ``plan_prompt`` varies only on
        evidence, so revision 2 came out byte-identical to revision 1, diverged at
        the same step, and the run blocked permanently on its second pass.
        """

        return decide_run_plan(
            recipe=recipe,
            settings=self._settings,
            revision=revision,
            evidence=evidence,
            inference=self._inference,
        )


@dataclass(frozen=True, slots=True)
class ProfileResearchPorts:
    """The three research ports, bound together because a build needs all three.

    ``discovery`` is opted into per adapter through ``Settings``, and the other two
    follow it: :func:`_research_ports` binds a ``fetcher``/``extractor`` only when
    at least one discovery adapter is enabled, so "no adapter configured" stays a
    port set that cannot run rather than a live fetcher waiting for a URL.

    The bootstrap problem these two used to be ``None`` for — every fetcher in the
    tree is built *from* a reviewed host list, and profile research exists to
    discover that host list — is resolved by
    :class:`~ops.providers.profile_fetcher.DomainElectedEvidenceFetcher`, which
    elects one registrable domain from the candidate URLs *before* dereferencing
    any of them and builds its host policy from the winner. So a bound fetcher is
    no longer one that would refuse every candidate URL.
    """

    discovery: tuple[DiscoveryAdapter, ...] = ()
    fetcher: ProfileEvidenceFetcher | None = None
    extractor: ProfileExtractor | None = None

    @property
    def is_complete(self) -> bool:
        """Whether :func:`~ops.providers.profile_builder.build_profile` can run."""

        return bool(self.discovery) and self.fetcher is not None and self.extractor is not None


@dataclass(frozen=True, slots=True)
class OnboardingPorts:
    """Every durable store, adapter, and policy this deployment binds.

    Held as one value so a worker, the API, and a test are handed the same graph
    instead of each opening its own connections to the same files. The stores are
    cheap handles over SQLite files; they are safe to share and none of them holds a
    connection open between calls.
    """

    settings: Settings
    ledger: OperationsStorage
    profiles: ProviderProfileStore
    phases: SQLitePhaseHistoryStore
    leases: LeaseStore
    queue: RunQueue
    outcomes: AutonomyOutcomeStore
    timings: LeaseTimings
    budget: LoopBudget
    captcha_budget: CaptchaBudget
    verification_budget: VerificationBudget
    research: ProfileResearchPorts
    deadlines: StepDeadlines = field(default_factory=StepDeadlines)
    # The chain behind ``decider``, kept so each run's decider can be bound to that
    # run's attempt sink (Requirement 4.3).
    inference: JsonInference | None = None
    # The pre-flight plan: where it is recorded, where it comes from, and the
    # monitor that compares an observed surface against it. All three are
    # optional, and an unwired plan store leaves both planning and adherence inert
    # rather than guessing a route.
    plans: RunPlanStore | None = None
    planner: RunPlanner | None = None
    plan_validator: RunPlanValidator = validate_plan
    adherence: RouteAdherenceMonitor | None = None
    verification: VerificationProvider | None = None
    vault: VerificationSecretVault | None = None
    validator: CredentialValidatorPort | None = None
    decider: CandidateDecider | None = None
    goals: PhaseGoalFactory = field(default_factory=ProfileGoals)
    # --- the run-scoped bindings the phase handlers read -------------------
    #
    # Each is one of the adapters in ``ops.onboarding.publishers``, bound here
    # because they are all reads of durable state this root already opened. They
    # are fields rather than locals of :meth:`phase_handlers` so a caller — a
    # worker, a test — can substitute one without rebuilding the whole root.
    providers: RunProviderBinding | None = None
    accounts: RunAccountBinding | None = None
    developer_app: DeveloperAppBinding | None = None
    logins: LoginReferenceBinder | None = None
    signup_binding: SignupRunBinding | None = None
    signup_mailbox: SignupMailboxBinder | None = None
    # The terminal step of the credential lifecycle. Absent when Composio has no
    # key or no callback origin: the lifecycle then has no publisher, and rather
    # than hand it a double this root leaves the three credential handlers
    # unregistered and names the reason.
    publisher: ProviderConfigurationPublisher | None = None
    # The effect ledger the credential lifecycle reserves against. Its own file,
    # shared with every other provider-visible effect in the deployment, because
    # "exactly once" is a property of the ledger and not of the caller.
    effect_store: EffectStore | None = None
    # The credential vault as the CONCRETE store, kept beside the narrow ``vault``
    # port above rather than instead of it. Five different phases need five
    # different slices of this one object — a staging pair of verbs, a
    # reference-only probe, a capture vault, a signup staging vault, a login
    # reference reader — and every one of those slices is a Protocol the store
    # satisfies structurally. Narrowing happens at each binding site (the
    # ``_*_conformance`` helpers below), so no caller can widen ``vault`` back
    # into a value-resolving handle by accident.
    secrets: SQLiteSecretStore | None = None
    # The two ports with no production implementation in this tree. Both phases
    # are driven by an adapter over the browser service that nobody has written
    # yet, so they are injectable here and reported unavailable when absent
    # rather than faked — see ``build_onboarding_ports``.
    signup_submitter: SignupSubmitter | None = None
    login_handler: PhaseHandler | None = None
    # The reason each absent port is absent, keyed by port name. Reported rather
    # than raised so a deployment can start, serve its API, and refuse the phases
    # it cannot drive with a code an operator can act on.
    unavailable: Mapping[str, OnboardingReasonCode] = field(default_factory=dict)
    # Owned only when this root created it, so a caller that supplied its own
    # client keeps its lifecycle.
    _owned_http_client: httpx.AsyncClient | None = None

    def __post_init__(self) -> None:
        """Keep adherence disabled unless its durable plan authority is wired.

        A monitor without the corresponding store could only infer an expectation
        from transient state.  Dropping it here makes the degraded composition
        explicit and inert instead of allowing a caller to guess a route.
        """

        if self.plans is None and self.adherence is not None:
            object.__setattr__(self, "adherence", None)

    def phase_handlers(self) -> dict[OnboardingPhase, PhaseHandler]:
        """Every phase this deployment can drive with a handler rather than a loop.

        Roadmap 4.5's six handlers plus the four that were already handler-shaped
        and had no registration. Without this the driver reached
        ``_drive_phase``'s last resort — the generic action loop — for phases the
        loop cannot express (research happens before a session exists; the
        credential lifecycle's ordering is not a page walk), which is why a run in
        this tree had never walked past the phase whose handler a test supplied.

        **A phase whose ports are absent gets no entry, deliberately.** A handler
        built over a ``None`` port would fail at the last inch of a phase the run
        has already spent effects reaching; leaving it unregistered means the run
        stops at the same place through the path the driver already has for it,
        with the absence named in :attr:`unavailable`. This is the same rule the
        rest of this root keeps: absence is reported, never faked.

        **…but the gate has to be per handler, not per call.** "Stops at the same
        place" holds only for a phase the action loop can express. ``research``
        cannot be: it runs before a session exists, so ``PHASE_SUCCESSORS`` names
        no goal for it and an unregistered ``research`` reaches
        ``_drive_phase``'s ``raise PhaseNotDrivable`` instead of a pause. Gating
        all six of roadmap 4.5's handlers on one condition therefore turned a
        missing *credential* port into "no onboarding run gets past phase one, and
        it fails by raising", which the worker retries every 60 s forever. Each
        group is now gated on the ports it actually uses.

        Rebuilt per call rather than cached because the three credential handlers
        share one :class:`~ops.onboarding.handlers.CredentialOutcomeMemo`, and a
        memo shared across runs would let one run's generation outcome be taken
        by the next run's ``vault_storage``.
        """

        handlers: dict[OnboardingPhase, PhaseHandler] = {}
        credentials = self._credential_lifecycle()
        secrets = self.secrets
        # The gate is exactly the ports the FIRST four handlers need — research,
        # the vault probe, admission, and vault storage. It deliberately does NOT
        # include the credential lifecycle: ``research`` is the first phase of
        # every run and the only phase with no action-loop fallback, so folding
        # the lifecycle's four ports into this condition meant a deployment with
        # no Composio key produced no research handler and every onboarding run
        # died at phase one with ``PhaseNotDrivable`` — which the worker retries
        # forever. The lifecycle now gates only its own two handlers, inside the
        # factory.
        if self.providers is not None and self.accounts is not None and secrets is not None:
            handlers.update(
                onboarding_phase_handlers(
                    research=self.research,
                    providers=self.providers,
                    accounts=self.accounts,
                    # ``OperationsStorage`` satisfies the decision store
                    # structurally; the login route's own decision is recorded
                    # through it by the vault probe (Requirement 3.2).
                    decisions=_admission_decisions(self.ledger),
                    prompts=self.phases,
                    # The reference-only vault probe. Bound to the same secret
                    # store the vault port is, and narrowed to the one verb that
                    # cannot resolve a value.
                    probe=_reference_probe(secrets),
                    credentials=credentials,
                    developer_app=self.developer_app,
                    owner_id=self.settings.browser_service_owner,
                    # The owner's standing per-app authorization to create
                    # accounts, or None when this deployment configures none.
                    # Built from settings, so granting or revoking it is a
                    # reviewed deploy rather than something the running system
                    # can do to itself.
                    standing=SettingsStandingSignupAuthority.from_settings(self.settings),
                )
            )
        # ``route_selected_signup`` is a pure policy read with no ports at all, so
        # it is always registrable: an app whose recipe declares no signup policy
        # never enters ``signup`` and therefore never stages a credential.
        handlers["route_selected_signup"] = enter_signup
        # The developer application is a provider-visible effect, so the handler
        # needs the effect ledger as much as it needs the binding: its whole reason
        # to exist over the generic loop dispatch is reserving the key that makes a
        # second application impossible. Registered only when BOTH are bound —
        # registering it with a binding and no ledger would put the run through the
        # one path that creates a real application with nothing making it once.
        if self.developer_app is not None and self.effect_store is not None:
            handlers["developer_app"] = DeveloperAppPhaseHandler(
                effects=self.effect_store, binding=self.developer_app
            )
        if (
            self.signup_submitter is not None
            and self.signup_binding is not None
            and secrets is not None
            and self.effect_store is not None
        ):
            handlers["signup"] = SignupPhaseHandler(
                vault=_signup_vault(secrets),
                effects=self.effect_store,
                binding=self.signup_binding,
                submitter=self.signup_submitter,
                mailbox=self.signup_mailbox,
            )
        if self.login_handler is not None:
            handlers["route_selected_login"] = self.login_handler
        return handlers

    def _credential_lifecycle(self) -> CredentialLifecycleDeps | None:
        """The credential lifecycle's dependencies, or ``None`` when incomplete.

        All-or-nothing on purpose. ``capture_store_validate_publish`` commits two
        boundaries itself (Requirement 10.7), so a partially bound lifecycle would
        be discovered after the capture rather than before it — the one place in
        this feature where "degrade and find out later" costs a real credential.
        """

        if self.secrets is None or self.validator is None or self.publisher is None:
            return None
        if self.effect_store is None:
            return None
        return CredentialLifecycleDeps(
            journal=self.phases,
            effects=self.effect_store,
            vault=_capture_vault(self.secrets),
            validator=self.validator,
            publisher=self.publisher,
            budgets=CredentialBudgets.from_settings(self.settings),
        )

    def deps_for(
        self,
        *,
        run_id: str,
        sessions: LoopSessionFactory,
        handlers: Mapping[OnboardingPhase, PhaseHandler] | None = None,
        logins: LoginReferenceBinder | None = None,
        verification_binding: VerificationBinding | None = None,
        telemetry: LoopTelemetry | None = None,
        selection: ModelSelection | None = None,
    ) -> OnboardingDeps:
        """Compose the driver's dependencies for one run.

        PRE:  ``sessions`` yields the run's own bound browser session; the
              caller that owns the browser owns that binding.
        POST: every port on the returned value is either this deployment's
              implementation or ``None`` with its absence recorded in
              :attr:`unavailable`. The phase store is bound three times — as the
              phase history, as the CAPTCHA pause store, and as the reservation
              reader — because those are three ports over the same durable rows,
              and binding them to one object is what keeps the counts, the pause,
              and the boundary in one transaction-consistent view.

        The decider is required: a run driven with no inference backend would reach
        the first loop phase and exhaust its model-call budget, which reports a
        bound as though it had been spent. Refusing here says the true thing.

        ``selection`` is the run's own pinned decision model. It is why the decider
        is built here rather than shared: this root is constructed once per
        deployment, but the chain order belongs to the run. With no selection the
        deployment's chain is used unchanged, which is the ordinary case.

        Three ports default from this root and are overridable per call rather
        than the other way round, because each is something a caller might
        legitimately own for one run: ``handlers`` MERGES over
        :meth:`phase_handlers` (a caller registering one phase keeps the other
        nine, which is what made every existing test's single-handler mapping a
        silent nine-phase regression waiting to happen), ``logins`` falls back to
        the vault-backed binder, and ``verification_binding`` is built here
        because it is the one binding that needs this run's own ``sessions``:
        verification continues on the session the signup was submitted on, so a
        factory-less binding could only open a second one (Requirement 7.30).
        """

        if self.decider is None:
            raise PhaseUnavailableError(
                phase=4,
                capability="onboarding action loop",
                reason_code=DECIDER_UNAVAILABLE,
            )
        sink = telemetry or RunDenialTelemetry(store=self.ledger, phases=self.phases, run_id=run_id)
        # Each attempt is recorded against the run it was made for, which is only
        # possible once the run's telemetry exists (Requirement 4.3). A decider
        # substituted by a caller is left exactly as it was given.
        decider = self.decider
        if (
            isinstance(decider, InferenceCandidateDecider)
            and isinstance(sink, RunDenialTelemetry)
            and self.inference is not None
        ):
            chain = self.inference
            if selection is not None:
                # A selection that no longer builds — a key rotated out since the
                # run was accepted — leaves the deployment chain in place rather
                # than failing the run over a preference.
                pinned = build_json_inference(self.settings, selection=selection)
                chain = pinned if pinned is not None else chain
            decider = InferenceCandidateDecider(chain.with_attempts(sink))
        registered = self.phase_handlers()
        registered.update(handlers or {})
        # The run's own approved non-secret values, bound onto its goals. This is
        # what turns ``allow_value_refs`` from the empty tuple every goal carried
        # into the phase's declared, run-available references — and so what lets
        # the loop emit a ``fill`` at all. A caller that supplied its own factory
        # is left exactly as it was given, on the same rule as ``decider`` above.
        # The run's own credential-creation policy rides along on the same read.
        # It is the RUN half of the creation gate and belongs to the immutable
        # ledger row, not to the profile: a factory the caller supplied keeps
        # whatever policy it was built with, on the same rule as ``decider``.
        record = self.ledger.get_run(run_id) or {}
        # One read, one normalization, two consumers: the goal factory below and
        # the deps bundle's own field. The bundle carries it unconditionally —
        # even when the caller supplied its own factory — because the phases that
        # build their goal outside the factory (``developer_app`` selects its
        # reviewed URLs from the credential kind, which a factory keyed by phase
        # and profile cannot know) read the RUN half from the bundle. A run whose
        # row is missing or predates the column reads ``reuse_only``.
        creation_policy = _creation_policy(record.get("credential_creation_policy"))
        goals = self.goals
        if isinstance(goals, ProfileGoals):
            goals = ProfileGoals(
                run_setup_values(record, app_slug=str(record.get("app_slug") or "")),
                credential_creation_policy=creation_policy,
            )
        bound_verification = verification_binding
        if bound_verification is None:
            bound_verification = _verification_binding(
                LedgerVerificationBinding(ledger=self.ledger, sessions=sessions)
            )
        return OnboardingDeps(
            leases=self.leases,
            phases=self.phases,
            profiles=self.profiles,
            queue=self.queue,
            goals=goals,
            sessions=sessions,
            decider=decider,
            telemetry=sink,
            logins=logins if logins is not None else self.logins,
            verification=self.verification,
            handlers=registered,
            outcomes=self.outcomes,
            pauses=_captcha_pause_store(self.phases),
            verification_binding=bound_verification,
            vault=self.vault,
            effects=_effect_reader(self.phases),
            # The run ledger doubles as the scratchpad store: the phase's working
            # memory is a row beside the run's own rows, so a restart reads back
            # exactly what the walk that crashed had written.
            scratchpads=self.ledger,
            plans=self.plans,
            planner=self.planner,
            plan_validator=self.plan_validator,
            budget=self.budget,
            deadlines=self.deadlines,
            captcha_budget=self.captcha_budget,
            verification_budget=self.verification_budget,
            timings=self.timings,
            credential_creation_policy=creation_policy,
        )

    async def aclose(self) -> None:
        """Release the HTTP client this root created, if it created one."""

        if self._owned_http_client is not None:
            await self._owned_http_client.aclose()


def build_onboarding_ports(
    settings: Settings,
    *,
    ledger_path: str | Path | None = None,
    secret_store: SQLiteSecretStore | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> OnboardingPorts:
    """Bind every onboarding port for this deployment (Requirement 21.6).

    PRE:  ``settings`` is the deployment's configuration. ``secret_store`` is the
          initialized vault when one exists; passing the caller's own instance is
          preferred so the run ledger and the vault agree on one handle.
    POST: the returned value binds every port that this deployment can serve, and
          names the reason for each one it cannot. Nothing here performs provider
          I/O: constructing an adapter is not calling it.

    ``install_redacting_filter`` is re-applied here as well as at the API and CLI
    startup boundaries (Requirement 19.4). It is idempotent, and a worker process
    that composes these ports without going through either startup path still must
    not emit an unfiltered record.
    """

    install_redacting_filter()
    path = Path(ledger_path) if ledger_path is not None else settings.ops_db_path
    ledger = OperationsStorage(path)
    ledger.initialize()
    unavailable: dict[str, OnboardingReasonCode] = {}

    store = secret_store
    if store is None and settings.secret_vault_key is not None:
        store = SQLiteSecretStore(
            settings.secret_vault_db_path,
            settings.secret_vault_key.get_secret_value(),
        )

    verification: VerificationProvider | None = None
    if store is not None:
        # Declared as the port: this call is the one place that knows the default
        # mailbox is Gmail, and nothing downstream of it does.
        verification = default_verification_provider(settings=settings, store=store)
    else:
        unavailable["verification"] = MAILBOX_UNAVAILABLE

    validator: ProfileBoundCredentialValidator | None = None
    owned_client: httpx.AsyncClient | None = None
    # Hoisted out of the branch below because profile research shares this one
    # client: two pools against the same provider hosts would double the sockets
    # a run holds and split the redirect/timeout settings across two objects.
    client: httpx.AsyncClient | None = http_client
    if store is not None:
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
            )
            owned_client = client
        validator = build_profile_bound_validator(secret_store=store, http_client=client)
    else:
        unavailable["validator"] = VALIDATOR_UNAVAILABLE

    inference = build_json_inference(settings)
    decider = InferenceCandidateDecider(inference) if inference is not None else None
    if decider is None:
        unavailable["decider"] = DECIDER_UNAVAILABLE

    # The evidence fetcher and the claim extractor are adapters over things this
    # root already owns — the shared HTTP client and the decision chain — so they
    # are handed in rather than constructed inside, keeping the client's lifetime
    # (``aclose`` below) in one place.
    research = _research_ports(settings, http_client=client, inference=inference)
    if not research.is_complete:
        unavailable["research"] = RESEARCH_UNAVAILABLE

    # The plan lives in the run ledger's own file, so the plan rows and the phase
    # boundaries are one durable view of the run.
    plans = SQLiteRunPlanStore(path)

    # Every provider-visible effect in this deployment reserves against one
    # ledger file, so the credential lifecycle's ``generate_credential`` key and
    # the managed-auth boundary's ``auth_configs.create`` cannot end up in two
    # different "exactly once" schemes.
    effect_store = SQLiteEffectStore(settings.provider_effects_db_path)

    publisher: ComposioProviderConfigurationPublisher | None = None
    if settings.composio_api_key is not None and settings.managed_auth_callback_base_url:
        # ``from_settings`` re-checks both and raises ``ConfigurationRequiredError``
        # for a callback origin that is present but unusable (a placeholder, a
        # loopback host). That is the "flag on, credential missing" case CLAUDE.md
        # says must fail loudly at composition rather than at the last step of a
        # run, so it is deliberately NOT caught here.
        publisher = ComposioProviderConfigurationPublisher(
            connections=ComposioManagedAuthProvider.from_settings(
                settings, effect_store=effect_store
            ),
            ledger=ledger,
            callback_base_url=settings.managed_auth_callback_base_url,
        )
    else:
        unavailable["publisher"] = PUBLISHER_UNAVAILABLE

    logins: VaultLoginReferenceBinder | None = None
    if store is not None:
        logins = VaultLoginReferenceBinder(vault=store, ledger=ledger)

    signup_binding: LedgerSignupRunBinding | None = None
    signup_address = settings.gmail_signup_address
    if signup_address is not None:
        signup_binding = LedgerSignupRunBinding(
            ledger=ledger, signup_address=signup_address.get_secret_value()
        )

    # Neither of these two has a production implementation anywhere in the tree:
    # ``SignupSubmitter`` and the login route's worker/broker/gate seam are
    # adapters over the browser service that nobody has written. Recorded as
    # unavailable so the absence is visible on the deployment rather than
    # discovered by a run that reached the phase.
    unavailable["signup_submitter"] = SIGNUP_UNAVAILABLE
    unavailable["login_route"] = LOGIN_ROUTE_UNAVAILABLE

    return OnboardingPorts(
        settings=settings,
        ledger=ledger,
        profiles=SQLiteProviderProfileStore(
            path.parent / PROFILE_DATABASE_NAME,
            owner=settings.browser_service_owner,
        ),
        phases=SQLitePhaseHistoryStore(path),
        leases=SQLiteLeaseStore(path),
        queue=SQLiteRunQueue(path),
        outcomes=LedgerAutonomyOutcomes(ledger),
        timings=LeaseTimings.from_settings(settings),
        budget=LoopBudget.from_settings(settings),
        deadlines=StepDeadlines.from_settings(settings),
        inference=inference,
        plans=plans,
        # The planner builds its own bounded decision chain so planning uses the
        # plan budget/provider order from ops.planner.decide rather than borrowing
        # the action loop's per-page chain.
        planner=SettingsRunPlanner(settings),
        plan_validator=validate_plan,
        adherence=RouteAdherenceMonitor(plans=plans, audit=ledger),
        captcha_budget=CaptchaBudget(max_pauses=settings.onboarding_captcha_pause_budget),
        verification_budget=VerificationBudget.from_settings(settings),
        research=research,
        verification=verification,
        # ``SQLiteSecretStore`` satisfies the two-verb staging port structurally;
        # it is bound as that port so nothing on the verification path can reach a
        # read verb through it.
        vault=store,
        secrets=store,
        validator=validator,
        decider=decider,
        # The run-scoped bindings. All three are reads of the run's own durable
        # row, so they need nothing but the ledger and are always bindable.
        providers=LedgerRunProviderBinding(ledger=ledger),
        accounts=LedgerRunAccountBinding(ledger=ledger),
        developer_app=LedgerDeveloperAppBinding(
            ledger=ledger, owner_id=settings.browser_service_owner
        ),
        logins=logins,
        signup_binding=signup_binding,
        signup_mailbox=LedgerSignupMailboxBinder(ledger=ledger),
        publisher=publisher,
        effect_store=effect_store,
        unavailable=dict(unavailable),
        _owned_http_client=owned_client,
    )


def _research_ports(
    settings: Settings,
    *,
    http_client: httpx.AsyncClient | None = None,
    inference: JsonInference | None = None,
) -> ProfileResearchPorts:
    """The discovery adapters this deployment opted into, and nothing invented.

    PRE:  ``http_client`` is the root's shared client when one exists, and
          ``inference`` the deployment's decision chain, or ``None`` for either.
    POST: ``discovery`` holds only adapters an explicit flag turned on;
          ``fetcher`` and ``extractor`` are bound ONLY when discovery is
          non-empty, so a deployment that opted into no research adapter gets a
          port set that is still incomplete and therefore still inert. Every
          unbindable port is ``None`` rather than an exception (Requirement 2.7's
          degrade-to-``research_adapters_unavailable``), because a missing key is
          an unavailability and not a reason to refuse to compose the root.

    A ``ConfigurationRequiredError`` from the adapter table propagates: a flag that
    is on with its credential missing is a deployment mistake, and degrading it to
    "no adapters" would turn it into a quieter failure later. "Nothing enabled" is
    the other case, and it is an unavailability rather than a mistake.

    WHY the discovery flags gate the fetcher too: the fetcher dereferences URLs
    over the network, and the only thing that produces those URLs is a discovery
    adapter. Binding it whenever an HTTP client happens to exist would make a
    network-fetching research pipeline default-on for every deployment, which is
    the opposite of the opt-in-per-adapter rule the table above enforces. With no
    adapter enabled there is nothing to fetch, so returning it would only widen
    what an accident could reach.
    """

    try:
        discovery: Sequence[DiscoveryAdapter] = research_adapters(settings)
    except ConfigurationRequiredError:
        raise
    except PhaseUnavailableError as exc:
        LOGGER.info("onboarding profile research is unconfigured (%s)", exc.reason_code)
        return ProfileResearchPorts()

    fetcher: ProfileEvidenceFetcher | None = None
    if http_client is not None:
        # No host allowlist is passed, and that is the point: this fetcher elects
        # ONE registrable domain from the candidates discovery returned and builds
        # its own ``OfficialURLPolicy`` from the winner. Every transport bound —
        # size cap, redirect confinement, SSRF resolution — still lives in
        # ``OfficialEvidenceFetcher`` underneath it, so nothing is relaxed here.
        #
        # One instance serves every run in this process. Its only mutable state is
        # ``elected_domain``, which it resets at the top of each ``fetch_many`` and
        # which nothing outside its own module reads (the documents it returns are
        # already confined to the elected domain), so sharing it cannot leak one
        # provider's domain into another provider's evidence.
        fetcher = DomainElectedEvidenceFetcher(http_client)
    else:
        LOGGER.info("onboarding profile research has no evidence fetcher: no http client")

    extractor: ProfileExtractor | None = None
    if inference is not None:
        try:
            extractor = ProfileClaimExtractor(inference)
        except ValueError as exc:
            # Raised when one decision budget is wider than the whole extraction
            # deadline. That is a budget configuration a run cannot satisfy, but it
            # is not a reason to fail composition of every other port, so research
            # degrades to incomplete and says why.
            LOGGER.info("onboarding profile research extractor is unusable (%s)", exc)
    else:
        LOGGER.info("onboarding profile research has no extractor: no inference chain")

    return ProfileResearchPorts(discovery=tuple(discovery), fetcher=fetcher, extractor=extractor)


def _captcha_pause_store(store: SQLitePhaseHistoryStore) -> CaptchaPauseStore:
    """Bind the phase store as the pause port; typed so a drift is a type error."""

    return store


def _effect_reader(store: SQLitePhaseHistoryStore) -> RecoveryEffectReader:
    """Bind the phase store as the read-only reservation reader."""

    return store


def _admission_decisions(ledger: OperationsStorage) -> AdmissionDecisionStore:
    """Bind the run ledger as the admission decision store and nothing wider.

    ``OperationsStorage`` is a very large handle and the admission path needs two
    verbs of it. Passing the whole store to the handler factory would typecheck
    against the protocol either way; going through this function is what makes the
    NARROWED type the one the call site has, so a future handler that reached for
    a third verb fails here rather than quietly acquiring the run ledger.
    """

    return ledger


def _reference_probe(store: SQLiteSecretStore) -> CredentialReferenceProbe:
    """Narrow the vault to its single reference-returning verb (Requirement 3.2).

    The admission path must be unable to resolve a secret VALUE, and the way that
    is guaranteed is the shape of the port rather than the restraint of the caller
    — ``CredentialReferenceProbe`` has one method and it returns ``vault://``
    references. Handing ``SQLiteSecretStore`` straight to ``VaultCheckPhaseHandler``
    would have given that handler every read verb the vault has.
    """

    return store


def _capture_vault(store: SQLiteSecretStore) -> CredentialCaptureVault:
    """Narrow the vault to reserve-grant plus the two retire verbs.

    Same rule as :func:`_reference_probe`, applied to the credential lifecycle:
    ``CredentialCaptureVault`` deliberately has no read verb, so no branch of
    ``capture_store_validate_publish`` can resolve the credential it just minted,
    and that stays true no matter what the concrete store grows later.
    """

    return store


def _signup_vault(store: SQLiteSecretStore) -> SignupCredentialVault:
    """Narrow the vault to the signup staging verbs — write, promote, never read.

    ``SignupPhaseHandler`` stages a generated pair, hands the browser a grant, and
    promotes the pair into the reusable account scope on success. It never needs
    the password back, so it is not given a port that could return one.
    """

    return store


def _verification_binding(binding: LedgerVerificationBinding) -> VerificationBinding:
    """Typecheck-only proof that the ledger binding satisfies the driver's port.

    Built per :meth:`OnboardingPorts.deps_for` call rather than once on this root
    because it closes over the run's own ``sessions`` factory: verification
    continues on the session the signup was submitted on (Requirement 7.30), and a
    binding built at deployment time could only have opened a second one.
    """

    return binding


def _login_route_conformance(handler: LoginRouteHandler) -> PhaseHandler:
    """Typecheck-only proof that the injected login route satisfies the port.

    ``login_handler`` is an injected port rather than a construction here because
    this tree has no worker/broker/gate seam to build one from — the absence is
    recorded as ``login_route`` in :attr:`OnboardingPorts.unavailable`. This
    function is what pins the type that injection is expected to carry.
    """

    return handler


def _credential_validator_conformance(
    validator: ProfileBoundCredentialValidator,
) -> CredentialValidatorPort:
    """Typecheck-only proof that the bound validator satisfies its port."""

    return validator


def _decider_conformance(decider: InferenceCandidateDecider) -> CandidateDecider:
    """Typecheck-only proof that the inference adapter satisfies the loop's port."""

    return decider


def _planner_conformance(planner: SettingsRunPlanner) -> RunPlanner:
    """Typecheck-only proof that the planner adapter satisfies the driver's port."""

    return planner


def _goals_conformance(goals: ProfileGoals) -> PhaseGoalFactory:
    """Typecheck-only proof that the goal factory satisfies the driver's port."""

    return goals


def _telemetry_conformance(telemetry: RunDenialTelemetry) -> LoopTelemetry:
    """Typecheck-only proof that the telemetry adapter satisfies the loop's port."""

    return telemetry


__all__ = [
    "DECIDER_UNAVAILABLE",
    "MAILBOX_UNAVAILABLE",
    "PROFILE_DATABASE_NAME",
    "RESEARCH_UNAVAILABLE",
    "VALIDATOR_UNAVAILABLE",
    "InferenceCandidateDecider",
    "OnboardingPorts",
    "ProfileGoals",
    "ProfileResearchPorts",
    "RunDenialTelemetry",
    "SettingsRunPlanner",
    "build_onboarding_ports",
]
