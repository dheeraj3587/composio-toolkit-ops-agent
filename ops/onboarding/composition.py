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

from ops.core.config import Settings
from ops.core.inference import DecisionOutcome, JsonInference, build_json_inference
from ops.core.redaction import install_redacting_filter
from ops.core.secret_store import SQLiteSecretStore
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
)
from ops.onboarding.credentials import (
    CredentialValidatorPort,
    ProfileBoundCredentialValidator,
    build_profile_bound_validator,
)
from ops.onboarding.driver import (
    AutonomyOutcomeStore,
    CaptchaBudget,
    CaptchaPauseStore,
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
from ops.onboarding.lease import LeaseStore, LeaseTimings, RunQueue
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.loop_telemetry import DenialFactStore, DurableLoopTelemetry
from ops.onboarding.phase import (
    ONBOARDING_REASON_CODES,
    OnboardingPhase,
    OnboardingReasonCode,
)
from ops.planner.adherence import RouteAdherenceMonitor
from ops.planner.decide import PlanOutcome, decide_run_plan
from ops.planner.store import RunPlanStore, SQLiteRunPlanStore
from ops.planner.validator import PlanRefusal, validate_plan
from ops.providers.errors import ConfigurationRequiredError, PhaseUnavailableError
from ops.providers.profile import ProviderProfile
from ops.providers.profile_builder import (
    DiscoveryAdapter,
    ProfileEvidenceFetcher,
    ProfileExtractor,
    research_adapters,
)
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

assert {
    MAILBOX_UNAVAILABLE,
    VALIDATOR_UNAVAILABLE,
    DECIDER_UNAVAILABLE,
    RESEARCH_UNAVAILABLE,
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
    """

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
        return PhaseGoal.for_phase(
            phase,
            provider_name=profile.provider_name,
            description=description,
            instruction=instruction,
            success_reason_code=success,
            reviewed_goto_urls=_reviewed_urls(phase, profile),
        )


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

    def plan_for(self, *, recipe: AppRecipe, revision: int) -> PlanOutcome | PlanRefusal:
        """Plan ``recipe``'s route, falling back to the reviewed route as decided."""

        return decide_run_plan(
            recipe=recipe,
            settings=self._settings,
            revision=revision,
            inference=self._inference,
        )


@dataclass(frozen=True, slots=True)
class ProfileResearchPorts:
    """The three research ports, bound together because a build needs all three.

    ``discovery`` is opted into per adapter through ``Settings``. ``fetcher`` and
    ``extractor`` are ``None`` in this deployment: profile research has to fetch and
    interpret documents from a domain it has not resolved yet, and every fetcher and
    extractor in the tree today is constructed *from* a reviewed host list. Binding
    one of them here would hand profile research a fetcher that refuses every
    candidate URL, which reads as "research found nothing" rather than as the
    unconfigured capability it is.
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

    def deps_for(
        self,
        *,
        run_id: str,
        sessions: LoopSessionFactory,
        handlers: Mapping[OnboardingPhase, PhaseHandler] | None = None,
        logins: LoginReferenceBinder | None = None,
        verification_binding: VerificationBinding | None = None,
        telemetry: LoopTelemetry | None = None,
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
            decider = InferenceCandidateDecider(self.inference.with_attempts(sink))
        return OnboardingDeps(
            leases=self.leases,
            phases=self.phases,
            profiles=self.profiles,
            queue=self.queue,
            goals=self.goals,
            sessions=sessions,
            decider=decider,
            telemetry=sink,
            logins=logins,
            verification=self.verification,
            handlers=dict(handlers or {}),
            outcomes=self.outcomes,
            pauses=_captcha_pause_store(self.phases),
            verification_binding=verification_binding,
            vault=self.vault,
            effects=_effect_reader(self.phases),
            plans=self.plans,
            planner=self.planner,
            plan_validator=self.plan_validator,
            budget=self.budget,
            deadlines=self.deadlines,
            captcha_budget=self.captcha_budget,
            verification_budget=self.verification_budget,
            timings=self.timings,
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
    if store is not None:
        client = http_client
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

    research = _research_ports(settings)
    if not research.is_complete:
        unavailable["research"] = RESEARCH_UNAVAILABLE

    # The plan lives in the run ledger's own file, so the plan rows and the phase
    # boundaries are one durable view of the run.
    plans = SQLiteRunPlanStore(path)

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
        validator=validator,
        decider=decider,
        unavailable=dict(unavailable),
        _owned_http_client=owned_client,
    )


def _research_ports(settings: Settings) -> ProfileResearchPorts:
    """The discovery adapters this deployment opted into, and nothing invented.

    A ``ConfigurationRequiredError`` from the adapter table propagates: a flag that
    is on with its credential missing is a deployment mistake, and degrading it to
    "no adapters" would turn it into a quieter failure later. "Nothing enabled" is
    the other case, and it is an unavailability rather than a mistake.
    """

    try:
        discovery: Sequence[DiscoveryAdapter] = research_adapters(settings)
    except ConfigurationRequiredError:
        raise
    except PhaseUnavailableError as exc:
        LOGGER.info("onboarding profile research is unconfigured (%s)", exc.reason_code)
        discovery = ()
    return ProfileResearchPorts(discovery=tuple(discovery))


def _captcha_pause_store(store: SQLitePhaseHistoryStore) -> CaptchaPauseStore:
    """Bind the phase store as the pause port; typed so a drift is a type error."""

    return store


def _effect_reader(store: SQLitePhaseHistoryStore) -> RecoveryEffectReader:
    """Bind the phase store as the read-only reservation reader."""

    return store


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
