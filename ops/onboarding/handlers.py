"""The phase handlers for the six phases no browser loop can drive.

The driver dispatches a phase to a registered :class:`~ops.onboarding.driver.PhaseHandler`
first, to the mailbox second, and to the bounded action loop last
(``driver._drive_phase``). Six phases reach none of those on their own: research
and the vault probe happen before a browser session exists, admission waits on a
person, and the three credential phases are a lifecycle whose ordering no page
walk can express. Without a handler each one raises ``PhaseNotDrivable`` and the
run stops dead, which is why a run in this tree has never walked further than the
phase whose handler a test supplied. This module is those handlers, in
production.

**Every handler here returns a** :class:`~ops.onboarding.driver.PhaseStep` **and
commits nothing** (Requirement 4.20). That is the load-bearing rule of the whole
feature: the driver is the only component that turns a requested transition into
a durable boundary, so a handler cannot leave the run at a phase the transition
table refuses or at one the driver does not know it is at. The one deliberate
exception is not ours — :func:`~ops.onboarding.credentials.capture_store_validate_publish`
commits ``vault_storage`` and ``credential_validation`` itself, because
Requirement 10.7 orders those two boundaries relative to a capture that only that
function witnessed. Handlers 4 to 6 below are shaped around that fact rather than
fighting it: the lifecycle runs once, inside ``credential_generation``, and the
next two phases are the driver catching up to boundaries that are already
durable.

**No pause that a human cannot clear.** The owner's standing instruction is that
a run stops for a person only where a person is genuinely required, and there is
exactly one such place in this file: creating an account with a provider has
legal and billing consequences, so ``awaiting_admission`` waits for a recorded
operator decision (Requirements 3.5 - 3.7). It *defers* rather than pauses, so
the run comes back on its own the moment the decision is recorded and no operator
has to resume it by hand — and the one prompt it emits is emitted through
:func:`~ops.onboarding.driver.emit_admission_prompt`, whose durable conditional
write is what keeps it to one per run no matter how many workers arrive
(Requirement 11.13). Everywhere else a handler either has what it needs and
proceeds, or names the deployment fact that is missing.

**Two phases cannot pause at all, and the code reflects that.** The transition
table (``ops.onboarding.phase._LEGAL_PHASE_TRANSITIONS``) declares
``research -> {vault_check, blocked, cancelled}`` and
``vault_check -> {route_selected_login, awaiting_admission, blocked}``: neither
admits ``paused``. A ``PhaseStep.pause`` from either would be refused by
``validate_phase_transition`` at the commit, and a vault probe with no profile to
probe under raises ``PhaseNotDrivable``, because that is a wiring fault rather
than a run outcome.

**And research cannot commit any boundary at all**, which is stronger than "it
cannot pause". Every transition ``drive_run`` commits is keyed on a profile
digest (``driver.drive_run`` Q2: a step with no digest and a run with no profile
raises ``PhaseNotDrivable`` *before* ``commit_phase``), and research is the phase
that mints the digest — so until it succeeds there is nothing to key a boundary
on. Asking for ``blocked`` from a failed research therefore never blocked
anything: it raised out of the driver, ``OnboardingWorker`` caught it as
``driver_raised``, and the run re-claimed into the identical crash forever with no
reason code an operator could read. A failed research consequently *defers* with
backoff — the one step kind a phase with no digest may legally emit — and its
reason code travels on the structured timeline event
(``onboarding.research_unavailable`` / ``onboarding.research_inconclusive``)
rather than through phase history.

The ports below are narrow on purpose. ``OnboardingDeps`` carries what the driver
itself needs; the run-scoped facts these six phases need — which provider this run
is for, which account binding it runs under, where its admission decisions are
recorded — are supplied here as one-method protocols, so the composition root
binds them and this module knows nothing about SQLite, a mailbox, or a browser.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Protocol, cast

from ops.browser.metrics import OnboardingCorrelation
from ops.core.inference import DecisionFailed
from ops.onboarding.action_loop import LoopSession, run_action_loop
from ops.onboarding.admission import AdmissionDecision, CredentialReferenceProbe, admit_from_vault
from ops.onboarding.credentials import (
    CredentialLifecycleDeps,
    CredentialStep,
    CredentialSurfaceSession,
    capture_store_validate_publish,
)
from ops.onboarding.driver import (
    DEVELOPER_APP_RECEIPT_KEY,
    OUTCOME_UNKNOWN,
    AdmissionPromptStore,
    DeveloperAppBinding,
    OnboardingDeps,
    PhaseHandler,
    PhaseNotDrivable,
    PhaseStep,
    developer_app_name,
    emit_admission_prompt,
    phase_correlation_id,
    step_for_decision_failure,
    step_for_loop_outcome,
)
from ops.onboarding.effects import create_dev_app_key, plan_effect
from ops.onboarding.lease import Lease, deadline_after
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import ProviderProfile
from ops.providers.profile_builder import (
    DiscoveryAdapter,
    ProfileEvidenceFetcher,
    ProfileExtractor,
    ResearchFactRecorder,
    ResearchInconclusive,
    build_profile,
)

if TYPE_CHECKING:  # the catalog's own route vocabulary, imported for the type only
    from ops.recipes.app_recipes import RouteKind

LOGGER = logging.getLogger("composio_ops.onboarding_handlers")

# The six phases this module drives, named rather than spelled at each use so a
# handler asked to drive a phase it does not own says which one it does.
RESEARCH_PHASE: Final[OnboardingPhase] = "research"
VAULT_CHECK_PHASE: Final[OnboardingPhase] = "vault_check"
ADMISSION_PHASE: Final[OnboardingPhase] = "awaiting_admission"
CREDENTIAL_GENERATION_PHASE: Final[OnboardingPhase] = "credential_generation"
VAULT_STORAGE_PHASE: Final[OnboardingPhase] = "vault_storage"
CREDENTIAL_VALIDATION_PHASE: Final[OnboardingPhase] = "credential_validation"

# How long a run that could not research its provider waits before it tries
# again, and the ceiling its backoff climbs to. There is no "failed research"
# phase to end at: research is the phase that mints the profile digest every
# committed boundary is keyed on, so it may only defer (see the module docstring).
# The first delay is minutes because neither failure clears in seconds — an
# unbound port needs an operator to configure it, and a provider whose evidence
# did not corroborate needs the web to change — and the ceiling is an hour so a
# deployment whose ports get bound picks its stuck runs up within one.
RESEARCH_RETRY_SECONDS: Final = 300
RESEARCH_RETRY_CEILING_SECONDS: Final = 3600
# Where the doubling stops mattering: 300 s << 2**8 already exceeds the ceiling,
# so the exponent is clamped before it is computed rather than after.
_RESEARCH_RETRY_MAX_DOUBLINGS: Final = 8

# The three structured events a deferred research is visible on. Three rather
# than one because they are three jobs: an unbound port is a DEPLOYMENT defect an
# operator clears by configuring this deployment, an inconclusive build is a
# PROVIDER outcome nobody here can configure away, and a raised attempt is a
# DEFECT here or at an adapter that only a code or data fix clears. The reason
# code distinguishes them too, but only the event name is what an operator
# filters a timeline on.
RESEARCH_UNAVAILABLE_EVENT: Final = "onboarding.research_unavailable"
RESEARCH_INCONCLUSIVE_EVENT: Final = "onboarding.research_inconclusive"
RESEARCH_FAILED_EVENT: Final = "onboarding.research_failed"

PROFILE_CORROBORATED: Final[OnboardingReasonCode] = "profile_corroborated"
RESEARCH_ADAPTERS_UNAVAILABLE: Final[OnboardingReasonCode] = "research_adapters_unavailable"
RESEARCH_ATTEMPT_FAILED: Final[OnboardingReasonCode] = "research_attempt_failed"
SIGNUP_AUTHORIZATION_REQUIRED: Final[OnboardingReasonCode] = "signup_authorization_required"
CREDENTIAL_STORED: Final[OnboardingReasonCode] = "credential_stored"
PROFILE_UNAVAILABLE: Final[OnboardingReasonCode] = "capture_spec_unavailable"

# How long a run waits before it looks for its admission decision again. Short
# enough that an operator who answers sees the run move within the minute they
# are still watching it, long enough that a run left overnight costs 288 reads of
# one indexed row rather than a busy loop.
ADMISSION_POLL_SECONDS: Final = 300

# The effect whose completed reservation carries the developer application id the
# credential lifecycle mints against. Named here because two handlers below read
# the same receipt.
DEVELOPER_APP_EFFECT: Final = "create_dev_app"


# --- the run-scoped facts these phases need ----------------------------------


@dataclass(frozen=True, slots=True)
class ResearchTarget:
    """Which provider one run is for, as the catalog recorded it at creation.

    Deliberately not read off the profile: this is the input to research, and the
    profile is its output. ``hint_url`` is the reviewed URL the catalog already
    holds for the app when there is one — research treats it as one more candidate
    to corroborate, never as an admitted claim.

    ``route_kind`` is how this deployment reaches the provider, taken from the
    reviewed recipe the run was created against rather than guessed from the slug,
    and it selects which fields the built profile must carry
    (``profile_builder._REQUIRED_FIELDS_BY_ROUTE``). It matters because half the
    catalog is ``managed_auth`` or ``gated`` and has no self-serve signup page:
    researching those without their route applies the strictest, self-serve field
    set and they fail on a ``signup_url`` that does not exist. ``None`` is safe and
    means exactly that strictest set — a binding that cannot say which route a run
    takes gets the conservative answer rather than a relaxed one.
    """

    provider_name: str
    app_slug: str
    hint_url: str | None = None
    route_kind: RouteKind | None = None


class RunProviderBinding(Protocol):
    """Where the run's provider target comes from. One read, no verbs."""

    def research_target(self, *, run_id: str) -> ResearchTarget:
        """The provider this run was created to onboard."""


class RunAccountBinding(Protocol):
    """The run's opaque account binding, the same one signup stores under.

    The vault probe and the signup phase must agree on this value or the probe
    would ask about an account the run does not own — which reads as "no
    credentials" and routes a run that could have signed in straight to an
    operator prompt.
    """

    def account_ref(self, *, run_id: str) -> str:
        """The account binding this run's credentials are stored under."""


class AdmissionDecisionStore(Protocol):
    """The durable admission decision: read it, and record the system's own.

    Structurally satisfied by :class:`ops.core.storage.OperationsStorage`. The
    record verb is here because the *login* route is a decision this system makes
    (Requirement 3.2) and the login phase handler refuses to drive a run with no
    recorded decision; the signup route can only be written by the API acting on a
    person, which the table's own CHECK enforces rather than this port.
    """

    def read_admission_decision(self, run_id: str) -> AdmissionDecision | None:
        """The run's recorded decision, or ``None`` while it has none."""

    def record_admission_decision(
        self, decision: AdmissionDecision
    ) -> tuple[AdmissionDecision, bool]:
        """Record one decision, or report the replay of an earlier one."""


class ResearchPorts(Protocol):
    """The three profile-research ports, as one already-bound bundle.

    Structurally satisfied by
    :class:`ops.onboarding.composition.ProfileResearchPorts`, and declared as a
    protocol rather than imported from there so this module does not import the
    composition root that imports it.
    """

    @property
    def discovery(self) -> tuple[DiscoveryAdapter, ...]:
        """The discovery adapters this deployment opted into."""

    @property
    def fetcher(self) -> ProfileEvidenceFetcher | None:
        """Where evidence documents are fetched, or ``None`` if unconfigured."""

    @property
    def extractor(self) -> ProfileExtractor | None:
        """Where claims are extracted, or ``None`` if unconfigured."""


class CredentialLoopSession(Protocol):
    """The one session the credential phase is driven on, behind both its ports.

    ``credential_generation`` walks a page and then captures from it, so the
    session has to satisfy the loop's port and the capture port at once. It is one
    protocol rather than two arguments because it is one live session: capturing
    through a second handle would capture from a page the loop never drove.
    """

    @property
    def session_id(self) -> str:
        """The bound browser session this phase is driven on."""

    async def arm_credential_surface(self) -> bool:
        """Install the pixel mask and revoke outstanding live grants (10.1, 10.2)."""

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        """Store the rendered credential in the vault and return its reference."""


# --- research ----------------------------------------------------------------


def _research_retry_seconds(attempts: int) -> int:
    """The delay before a run that could not research its provider tries again.

    PRE:  ``attempts`` is how many times this run has already been driven, zero on
          its first turn.
    POST: a value in ``[RESEARCH_RETRY_SECONDS, RESEARCH_RETRY_CEILING_SECONDS]``,
          doubling per attempt. Bounded on both ends: a run that cannot research
          never spins, and one whose deployment is repaired never waits longer
          than the ceiling to notice.
    """

    if attempts < 0:
        raise ValueError("a research attempt count is not negative")
    doubling = 2 ** min(attempts, _RESEARCH_RETRY_MAX_DOUBLINGS)
    return min(RESEARCH_RETRY_SECONDS * doubling, RESEARCH_RETRY_CEILING_SECONDS)


def _research_retry(
    *,
    run_id: str,
    reason_code: OnboardingReasonCode,
    event: str,
    claims: int,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Defer ``research`` with backoff and put ``reason_code`` where an operator reads it.

    PRE:  ``claims`` is the run's fencing token — the durable, monotonic count of
          how many times this run has been claimed, at least 1 for a live lease.

    POST: nothing is committed and nothing is spent. The returned step is a
          ``yield``, so :func:`~ops.onboarding.driver.drive_run` re-queues the run
          at the named instant and leaves it standing at ``research``.

    The step kind is not a choice. ``advance`` and ``pause`` are both transitions,
    and every transition ``drive_run`` commits needs a profile digest that only a
    *successful* research produces — so either one raises ``PhaseNotDrivable``
    before ``commit_phase``, which is the crash loop this function exists to
    remove. A sentinel digest is not an option either: the ledger's
    ``profile_digest`` is a content address and "one profile per run" is what the
    whole phase history is keyed on.

    Because no boundary is written, the reason code cannot ride phase history, so
    it rides the same structured event every other onboarding record uses
    (Requirement 20.1's nine identifiers). That is the operator-visible artefact:
    the timeline shows ``research_adapters_unavailable`` /
    ``research_no_evidence`` / ``research_domain_disagreement`` and how long the
    run is waiting, rather than silence.
    """

    # The fencing token rather than the phase attempt: research commits no
    # boundary, so ``current_phase`` reports the same attempt forever and a
    # backoff scaled from it would never back off. The token increments on every
    # claim, and a run stuck at research is claimed once per research turn.
    seconds = _research_retry_seconds(max(claims - 1, 0))
    current = deps.phases.current_phase(run_id=run_id)
    # The driver's own attempt for this phase, so this event threads with the
    # boundary records of a run that is reset and re-researched.
    attempt = current[1] if current is not None else 0
    OnboardingCorrelation(
        run_id=run_id,
        phase=RESEARCH_PHASE,
        # Empty on purpose, and admitted as empty by the correlation: this run has
        # no committed profile yet, and that is precisely what is being reported.
        profile_digest="",
        reason_code=reason_code,
        attempt=attempt,
        correlation_id=phase_correlation_id(run_id=run_id, phase=RESEARCH_PHASE, attempt=attempt),
    ).emit(event, retry_in_seconds=seconds)
    return PhaseStep.defer(deadline_after(seconds), reason_code)


@dataclass(frozen=True, slots=True)
class ResearchPhaseHandler:
    """``research``: build this run's provider profile, or come back and try again.

    Research is the only phase that establishes a profile digest, so it is the only
    handler that sets ``PhaseStep.profile_digest``. Every later step leaves it
    ``None`` and the driver supplies the run's own.

    It is also the only handler that cannot report a failure as a transition, for
    the same reason: a boundary needs the digest this phase has not built yet. All
    three failure branches therefore defer through :func:`_research_retry`, and
    they are kept distinguishable because they are different jobs — an unbound port
    is a *deployment* defect an operator fixes by configuring one, an inconclusive
    build is a *provider* outcome nobody in this deployment can configure away, and
    a raised attempt is a *defect* here or at an adapter, which is why that branch
    logs its traceback as well as naming itself.

    Nothing leaves this handler by exception. Research is driven by a worker that
    treats a raise as an unexplained 60-second retry, so an escaping error would
    cost the run the very vocabulary this phase exists to publish.
    """

    research: ResearchPorts
    binding: RunProviderBinding
    # Where the exclusions research made become durable. Optional because a
    # deployment with no audit writer still researches; an unrecorded exclusion is
    # a thinner timeline, not a wrong profile.
    facts: ResearchFactRecorder | None = None

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Research the run's provider once and report the transition it earned.

        POST: a returned ``advance`` into ``vault_check`` implies the profile it
              names is durably committed for this run, because
              :func:`~ops.providers.profile_builder.build_profile` persists before
              it returns. Nothing else is written, no session exists, and no
              effect key is reserved.
        POST: the only other step this returns is a ``yield`` — research that did
              not conclude commits no boundary at all, because it has no digest to
              key one on (see :func:`_research_retry`).
        """

        if phase != RESEARCH_PHASE:
            raise ValueError("the research handler drives the research phase only")

        # A resumed run whose profile is already committed does not research
        # again. Re-running the build would re-fetch every document and re-derive
        # a digest that must come out identical to be usable at all, so the only
        # thing a second run of it can do is spend a research budget and fail.
        settled = profile or deps.profiles.get_for_run(run_id=run_id)
        if settled is not None:
            return PhaseStep.advance(
                VAULT_CHECK_PHASE, PROFILE_CORROBORATED, profile_digest=settled.profile_digest
            )

        fetcher = self.research.fetcher
        extractor = self.research.extractor
        if not self.research.discovery or fetcher is None or extractor is None:
            # The same code the composition root reports the unbound port under, so
            # an operator reads one vocabulary for "this deployment cannot do that"
            # whether they are looking at the run or at the deployment.
            LOGGER.warning(
                "onboarding run %s cannot research its provider: no discovery adapter, "
                "evidence fetcher, or claim extractor is bound — retrying, because this "
                "is a deployment fact an operator can configure without touching the run",
                run_id,
            )
            return _research_retry(
                run_id=run_id,
                reason_code=RESEARCH_ADAPTERS_UNAVAILABLE,
                event=RESEARCH_UNAVAILABLE_EVENT,
                claims=lease.fencing_token,
                deps=deps,
            )

        # Everything that reaches outside this handler runs inside the guard: the
        # binding raises on a ledger row that names no provider, and the builder
        # does not wrap its fetcher or extractor, so a timeout at either one
        # leaves the phase by exception. Uncontained, that exception reaches
        # ``OnboardingWorker._drive``, which logs ``driver_raised`` and defers 60 s
        # — a run retrying forever with no reason code anywhere on its timeline,
        # which is the one outcome this phase's whole failure design exists to
        # prevent. Contained, it becomes the same backing-off, named deferral the
        # other two branches produce.
        try:
            target = self.binding.research_target(run_id=run_id)
            built = await build_profile(
                run_id=run_id,
                provider_name=target.provider_name,
                app_slug=target.app_slug,
                hint_url=target.hint_url,
                # The reviewed route this run was created against, which selects the
                # field set the built profile must satisfy. Omitting it would apply the
                # strictest, self-serve set to every run and block managed_auth and
                # gated providers on a ``signup_url`` they do not have.
                route_kind=target.route_kind,
                adapters=self.research.discovery,
                fetcher=fetcher,
                extractor=extractor,
                store=deps.profiles,
                facts=self.facts,
            )
        except Exception:
            # ``Exception`` and not ``BaseException``: a cancelled worker must stay
            # cancelled, and ``asyncio.CancelledError`` is a ``BaseException``, so
            # it passes through here untouched. Logged at exception level with the
            # traceback because this branch cannot tell a provider's flaky timeout
            # from a programming error in this tree — the reason code makes the run
            # visible, the traceback is what makes the cause diagnosable, and a
            # deferral that hid one would trade a silent crash loop for a quiet one.
            LOGGER.exception(
                "onboarding run %s raised while researching its provider; retrying later",
                run_id,
            )
            return _research_retry(
                run_id=run_id,
                reason_code=RESEARCH_ATTEMPT_FAILED,
                event=RESEARCH_FAILED_EVENT,
                claims=lease.fencing_token,
                deps=deps,
            )
        if isinstance(built, ResearchInconclusive):
            # Research ran and could not corroborate a provider. The run comes back
            # carrying the builder's own reason code — no evidence, disagreeing
            # domains, or no adapter answered — because each names a different
            # thing to fix and a single "research_inconclusive" would name none.
            # Distinct from the branch above on purpose: nothing in this deployment
            # is misconfigured, so the thing that has to change is the web.
            LOGGER.info(
                "onboarding run %s ended research inconclusively (%s); retrying later",
                run_id,
                built.reason_code,
            )
            return _research_retry(
                run_id=run_id,
                reason_code=built.reason_code,
                event=RESEARCH_INCONCLUSIVE_EVENT,
                claims=lease.fencing_token,
                deps=deps,
            )
        return PhaseStep.advance(
            VAULT_CHECK_PHASE, PROFILE_CORROBORATED, profile_digest=built.profile_digest
        )


# --- the vault probe ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VaultCheckPhaseHandler:
    """``vault_check``: sign in on stored credentials, or go ask a person.

    The whole autonomy claim of Requirement 3.2 lives here: a run whose provider
    credentials are already in the vault routes to login and emits zero operator
    prompts. Only a run with nothing to sign in with reaches the one prompt this
    system has.
    """

    probe: CredentialReferenceProbe
    accounts: RunAccountBinding
    decisions: AdmissionDecisionStore
    # The tenant every profile and vault row in this deployment belongs to. A
    # decision is attributed to it, so it is deployment configuration rather than
    # something a run could choose.
    owner_id: str

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Probe the vault for a usable login and report the route it implies.

        POST: references present ⟹ a ``login`` decision is durably recorded and
              the step advances into ``route_selected_login``; references absent ⟹
              nothing is recorded and the step advances into ``awaiting_admission``.
              No credential value is read on either path — the port has no verb
              that could return one.
        """

        if phase != VAULT_CHECK_PHASE:
            raise ValueError("the vault probe handler drives the vault_check phase only")
        del lease, deps  # the probe is decided from the vault and the profile alone
        if profile is None:
            # ``vault_check`` is entered from ``research``, which commits the
            # digest, so an absent profile is a broken profile store rather than a
            # run outcome — and the transition table gives this phase no pause to
            # report it with.
            raise PhaseNotDrivable(phase, "the run has no committed provider profile")

        outcome = admit_from_vault(
            self.probe,
            run_id=run_id,
            profile_digest=profile.profile_digest,
            app_slug=profile.app_slug,
            app_name=profile.provider_name,
            account_ref=self.accounts.account_ref(run_id=run_id),
            owner_id=self.owner_id,
        )
        if outcome.decision is not None:
            # The login route is a decision this system made, and the login phase
            # handler refuses to drive a run with no recorded decision — so it is
            # recorded here, before the boundary that selects the route. Recording
            # is idempotent (``ON CONFLICT(run_id) DO NOTHING``), so a crash
            # between this write and the driver's commit re-probes, re-derives the
            # same decision, and reads back the first one.
            self.decisions.record_admission_decision(outcome.decision)
        # ``outcome.prompts`` is deliberately dropped: the admission prompt belongs
        # to the boundary into ``awaiting_admission``, and the durable counter that
        # authorizes it only moves while the run's committed phase IS
        # ``awaiting_admission`` (Requirement 11.13). Emitting it from here would
        # be a prompt no counter covers.
        return PhaseStep.advance(outcome.phase, outcome.reason_code)


# --- the one decision a person owns ------------------------------------------


@dataclass(frozen=True, slots=True)
class AdmissionPhaseHandler:
    """``awaiting_admission``: wait for the operator's account-creation decision.

    This is the only place in the onboarding walk where a run waits on a human,
    and it waits by *deferring* rather than pausing. The difference matters: a
    paused run needs a second human action to resume, so pausing here would turn
    one decision into two. A deferred run is re-queued and picks itself up the
    moment the decision row exists (Requirement 3.5).
    """

    decisions: AdmissionDecisionStore
    prompts: AdmissionPromptStore
    poll_seconds: int = ADMISSION_POLL_SECONDS

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Read the run's admission decision and act on it, or come back later.

        POST: at most one ``signup_authorization`` prompt exists for this run no
              matter how many times this handler runs, because the emission is
              gated on a conditional durable write rather than on this call.
        """

        if phase != ADMISSION_PHASE:
            raise ValueError("the admission handler drives the awaiting_admission phase only")
        del lease, deps  # admission is decided before any session exists
        if profile is None:
            raise PhaseNotDrivable(phase, "the run has no committed provider profile")

        decision = self.decisions.read_admission_decision(run_id)
        if decision is None:
            # Nobody has answered yet. The prompt is emitted through the durable
            # counter, so the first arrival asks and every later one — a re-queued
            # worker, a second worker, an operator refreshing the console — asks
            # nothing further and costs the run no prompt.
            emit_admission_prompt(
                run_id=run_id, app_name=profile.provider_name, prompts=self.prompts
            )
            return PhaseStep.defer(deadline_after(self.poll_seconds), SIGNUP_AUTHORIZATION_REQUIRED)

        if decision.profile_digest != profile.profile_digest:
            # An authorization is for the provider that was researched when it was
            # given. A reset re-researches and can land on a different digest, and
            # creating an account against an authorization nobody gave for THIS
            # provider is exactly the irreversible act this gate exists to hold.
            LOGGER.warning(
                "onboarding run %s holds an admission decision for another profile digest", run_id
            )
            return PhaseStep.pause(SIGNUP_AUTHORIZATION_REQUIRED)

        if decision.route == "signup":
            return PhaseStep.advance("route_selected_signup", decision.reason_code)
        if decision.route == "cancelled":
            return PhaseStep.advance("cancelled", decision.reason_code)
        # ``awaiting_admission`` has no edge to the login route: a run reaches this
        # phase only because the probe found nothing to sign in with, so a login
        # decision here means the decision and the probe disagree about the same
        # vault. Raising names that; committing would be refused by the table.
        raise PhaseNotDrivable(phase, "the recorded admission decision routes to login")


# --- the credential lifecycle ------------------------------------------------


@dataclass(slots=True)
class CredentialOutcomeMemo:
    """What the credential lifecycle earned, held between two phase boundaries.

    :func:`~ops.onboarding.credentials.capture_store_validate_publish` runs once,
    inside ``credential_generation``, and commits ``vault_storage`` and
    ``credential_validation`` itself (Requirement 10.7). The driver's own view of
    the phase therefore lags two boundaries behind the store, and the step the
    lifecycle actually earned — completed, superseded, retry, or pause — is the
    one that belongs at the *second* of them. This carries it across those two
    driver iterations, keyed by run because one worker may drive several.

    It is a cache and never an authority: an entry that is missing (a resumed run,
    a fresh worker, a restarted process) makes
    :class:`CredentialValidationPhaseHandler` re-run the lifecycle, which reserves
    no second mint — the completed ``generate_credential`` reservation makes it
    adopt the stored reference and re-probe it instead.
    """

    earned: dict[str, CredentialStep] = field(default_factory=dict)

    def remember(self, *, run_id: str, step: CredentialStep) -> None:
        """Hold the step the lifecycle earned for the phase that will report it."""

        self.earned[run_id] = step

    def take(self, *, run_id: str) -> CredentialStep | None:
        """Consume this run's remembered step, if this process is the one holding it."""

        return self.earned.pop(run_id, None)


def _phase_step(step: CredentialStep) -> PhaseStep:
    """Project a credential step onto the driver's own step type.

    The two are the same shape by design — the credential module documents its
    member names as matching — so this is a projection rather than a translation,
    and it exists only because the lifecycle must not import the driver.
    """

    if step.kind == "advance":
        assert step.next_phase is not None  # CredentialStep refuses an unnamed advance
        return PhaseStep.advance(step.next_phase, step.reason_code)
    if step.kind == "yield":
        assert step.not_before is not None  # …and a deferral with no deadline
        return PhaseStep.defer(step.not_before, step.reason_code)
    return PhaseStep.pause(step.reason_code)


@dataclass(frozen=True, slots=True)
class _CredentialLifecycle:
    """The inputs the lifecycle needs, resolved from the run's durable facts."""

    credentials: CredentialLifecycleDeps
    binding: DeveloperAppBinding
    memo: CredentialOutcomeMemo

    async def run(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile,
        session: CredentialSurfaceSession,
        deps: OnboardingDeps,
    ) -> CredentialStep | PhaseStep:
        """Mint, store, prove and publish one credential, or say why it stopped.

        Returns a :class:`PhaseStep` only for the refusals that happen before the
        lifecycle is entered — everything from the lifecycle itself comes back as
        the :class:`CredentialStep` the caller has to place at the right boundary.
        """

        request = self.binding.developer_app_request(run_id=run_id)
        # The developer application this credential is minted against, read from
        # the receipt the previous phase recorded (Requirement 9.6). The key is
        # re-derived rather than remembered, which is the point of deriving keys
        # from durable facts: any worker computes the same one.
        plan = plan_effect(
            self.credentials.effects,
            operation_key=create_dev_app_key(
                run_id, profile, developer_app_name(owner_id=request.owner_id, run_id=run_id)
            ),
            action=DEVELOPER_APP_EFFECT,
        )
        developer_app_id = (plan.receipt or {}).get(DEVELOPER_APP_RECEIPT_KEY)
        if plan.disposition != "skip" or not developer_app_id:
            # The run stands past ``developer_app`` with no completed application
            # under its own key. Minting a credential now would attach it to
            # whatever application the page happens to show, so this is ambiguous
            # rather than retryable.
            LOGGER.warning(
                "onboarding run %s has no completed developer application to mint against", run_id
            )
            return PhaseStep.pause(OUTCOME_UNKNOWN)

        # The attempt and correlation id are the driver's, read from the durable
        # phase rather than assumed, so the two boundaries the lifecycle commits
        # are attributable exactly like every boundary the driver commits
        # (Requirement 12.12).
        current = deps.phases.current_phase(run_id=run_id)
        attempt = current[1] if current is not None else 0
        return await capture_store_validate_publish(
            run_id=run_id,
            profile=profile,
            developer_app_id=developer_app_id,
            kind=request.credential_kind,
            session=session,
            deps=self.credentials,
            attempt=attempt,
            correlation_id=phase_correlation_id(run_id=run_id, phase=phase, attempt=attempt),
        )


@dataclass(frozen=True, slots=True)
class CredentialGenerationPhaseHandler:
    """``credential_generation``: walk to the credential, then capture it.

    This phase is loop-drivable and effect-bearing at once, which is why it needs
    a handler rather than the generic dispatch: the loop can reach a page where
    the credential is visible, but only the lifecycle may reserve the mint, arm
    the pixel mask, and take the value through the broker. So this handler does
    both, in that order and on one session — the same shape
    :func:`~ops.onboarding.driver.drive_developer_app` uses for the other
    effect-bearing phase a loop drives.

    Registering it does not cost the page walk: ``run_action_loop`` below is the
    same call the driver's own dispatch would have made, with the same goal from
    the same factory and the same allow-list.
    """

    credentials: CredentialLifecycleDeps
    binding: DeveloperAppBinding
    memo: CredentialOutcomeMemo

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Drive the credential surface and run the lifecycle once against it.

        PRE:  the ``credential_generation`` boundary is durably committed — the
              driver refuses to enter an effect-bearing phase otherwise — so the
              mint reserved inside the lifecycle is never the first durable fact
              about the phase that owns it (Requirement 12.4).
        POST: a returned ``advance`` into ``vault_storage`` implies the credential
              is stored and both storage boundaries are durable; the step the
              lifecycle actually earned is held for ``credential_validation``,
              which is the boundary it belongs at.
        """

        if phase != CREDENTIAL_GENERATION_PHASE:
            raise ValueError("the credential handler drives the credential_generation phase only")
        if profile is None:
            # Neither the allow-list the loop is confined to nor the capture and
            # validation contracts can be derived without the profile.
            return PhaseStep.pause(PROFILE_UNAVAILABLE)

        session = await deps.sessions.session_for(run_id=run_id, phase=phase, lease=lease)
        try:
            result = await run_action_loop(
                phase=phase,
                goal=deps.goals.goal_for(phase=phase, profile=profile),
                session=session,
                allowed=profile.allowed_hosts(),
                budget=deps.budget,
                decider=deps.decider,
                telemetry=deps.telemetry,
                deadlines=deps.deadlines,
                run_id=run_id,
                scratchpads=deps.scratchpads,
            )
        except DecisionFailed as failure:
            # Nothing was minted: the chain stopped before any action, so the
            # phase names which of the causes it was rather than looking slow.
            return step_for_decision_failure(failure)
        if result.outcome != "done":
            # The credential is not visible, so there is nothing to capture. A
            # CAPTCHA here takes the same pause path every loop-driven phase takes.
            return await step_for_loop_outcome(
                run_id=run_id, phase=phase, result=result, session=session, deps=deps
            )

        # ``done`` means the ``credential_visible`` postcondition held against a
        # fresh observation, so the surface the lifecycle is about to arm and
        # capture from is the page the loop just proved. The session satisfies both
        # ports; the cast is the seam, not a conversion.
        earned = await _CredentialLifecycle(
            credentials=self.credentials, binding=self.binding, memo=self.memo
        ).run(
            run_id=run_id,
            phase=phase,
            profile=profile,
            session=cast(CredentialSurfaceSession, session),
            deps=deps,
        )
        if isinstance(earned, PhaseStep):
            return earned
        if earned.kind != "advance":
            # A pause or a retry is reported here, at the phase the driver still
            # believes the run is at. The storage boundaries may already be durable
            # underneath — a resumed run reads them from the history and re-enters
            # at the further of the two, which is exactly where the work stopped.
            return _phase_step(earned)
        self.memo.remember(run_id=run_id, step=earned)
        # The lifecycle already committed this boundary, so the driver's commit is
        # a replay it counts and moves past (Requirement 20.5's replay counter).
        return PhaseStep.advance(VAULT_STORAGE_PHASE, CREDENTIAL_STORED)


@dataclass(frozen=True, slots=True)
class VaultStoragePhaseHandler:
    """``vault_storage``: the first boundary the lifecycle already committed.

    There is deliberately no work here. Arriving at this phase *is* the proof that
    the credential is durable, because the only path that commits the boundary
    into it is the one that stored the value first (Requirement 10.7). The handler
    exists so the driver can walk through a phase whose transition is already
    durable instead of raising ``PhaseNotDrivable`` on it.
    """

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Report the boundary into ``credential_validation`` the store already holds."""

        if phase != VAULT_STORAGE_PHASE:
            raise ValueError("the vault storage handler drives the vault_storage phase only")
        del run_id, profile, lease, deps
        return PhaseStep.advance(CREDENTIAL_VALIDATION_PHASE, CREDENTIAL_STORED)


@dataclass(frozen=True, slots=True)
class CredentialValidationPhaseHandler:
    """``credential_validation``: report what proving the credential earned.

    Two arrivals reach this phase and they are not the same. The ordinary one is
    the driver catching up two boundaries behind the lifecycle that ran in
    ``credential_generation``: the answer is already known and is taken from the
    memo. The other is a run that came back — a lease that expired between the two
    commits, a worker that restarted, a validation retry that deferred — and it has
    no memo to take. That one re-runs the lifecycle, which is safe *and* is the
    behaviour this phase is named for: the completed mint reservation makes it
    adopt the stored reference rather than mint a second credential, and it probes
    that reference again under the same durable attempt budget.
    """

    credentials: CredentialLifecycleDeps
    binding: DeveloperAppBinding
    memo: CredentialOutcomeMemo

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Report the credential's proven outcome, re-proving it if this worker must.

        POST: ``completed`` is requested only behind a recorded ``valid``, because
              the only thing that can produce it is the lifecycle's own publish
              branch (Requirements 10.12 - 10.14). Nothing here publishes, retires,
              or validates on its own.
        """

        if phase != CREDENTIAL_VALIDATION_PHASE:
            raise ValueError("the validation handler drives the credential_validation phase only")
        remembered = self.memo.take(run_id=run_id)
        if remembered is not None:
            return _phase_step(remembered)

        if profile is None:
            return PhaseStep.pause(PROFILE_UNAVAILABLE)
        LOGGER.info("onboarding run %s is re-proving its stored credential", run_id)
        session = await deps.sessions.session_for(run_id=run_id, phase=phase, lease=lease)
        earned = await _CredentialLifecycle(
            credentials=self.credentials, binding=self.binding, memo=self.memo
        ).run(
            run_id=run_id,
            phase=phase,
            profile=profile,
            session=cast(CredentialSurfaceSession, session),
            deps=deps,
        )
        return earned if isinstance(earned, PhaseStep) else _phase_step(earned)


# --- the registration --------------------------------------------------------


def onboarding_phase_handlers(
    *,
    research: ResearchPorts,
    providers: RunProviderBinding,
    accounts: RunAccountBinding,
    decisions: AdmissionDecisionStore,
    prompts: AdmissionPromptStore,
    probe: CredentialReferenceProbe,
    owner_id: str,
    credentials: CredentialLifecycleDeps | None = None,
    developer_app: DeveloperAppBinding | None = None,
    facts: ResearchFactRecorder | None = None,
) -> dict[OnboardingPhase, PhaseHandler]:
    """The six handlers, ready to merge into ``OnboardingDeps.handlers``.

    One factory rather than six constructor calls at the composition root, because
    the three credential handlers share a memo and handing them three different
    ones would silently turn every run's ordinary path into the recovery path.

    ``credentials`` and ``developer_app`` are optional and gate ONLY the two
    handlers that use them. They used to be required, and requiring them was a
    hard blocker: the credential lifecycle needs a publisher, a validator, a vault
    and an effect ledger, so a deployment missing any one of those got no handler
    for ``research`` either — and ``research`` is the first phase of every run and
    the one phase with no action-loop fallback (it happens before a session
    exists, so ``PHASE_SUCCESSORS`` declares no goal for it). The observed result
    was not an honest stop but ``PhaseNotDrivable`` raised out of ``_drive_phase``,
    which ``OnboardingWorker`` catches as ``driver_raised`` and defers 60 s — a run
    that re-claims into the same crash forever. Gating per handler means a
    partially configured deployment researches, probes the vault and takes the
    admission decision, then stops at ``credential_generation`` with the code the
    composition root already recorded for the port it does not have.
    """

    memo = CredentialOutcomeMemo()
    handlers: dict[OnboardingPhase, PhaseHandler] = {
        RESEARCH_PHASE: ResearchPhaseHandler(research=research, binding=providers, facts=facts),
        VAULT_CHECK_PHASE: VaultCheckPhaseHandler(
            probe=probe, accounts=accounts, decisions=decisions, owner_id=owner_id
        ),
        ADMISSION_PHASE: AdmissionPhaseHandler(decisions=decisions, prompts=prompts),
        # No ports at all: it reads the previous phase's committed outcome, so it
        # is registrable wherever the three above are.
        VAULT_STORAGE_PHASE: VaultStoragePhaseHandler(),
    }
    if credentials is not None and developer_app is not None:
        handlers[CREDENTIAL_GENERATION_PHASE] = CredentialGenerationPhaseHandler(
            credentials=credentials, binding=developer_app, memo=memo
        )
        handlers[CREDENTIAL_VALIDATION_PHASE] = CredentialValidationPhaseHandler(
            credentials=credentials, binding=developer_app, memo=memo
        )
    return handlers


# --- typecheck-only conformance ----------------------------------------------
#
# Each of the six is checked against the driver's port here rather than at the
# composition root, so a signature that drifts fails in the module that owns the
# handler instead of in the file that registers it.


def _handler_conformance(
    handlers: Sequence[
        ResearchPhaseHandler
        | VaultCheckPhaseHandler
        | AdmissionPhaseHandler
        | CredentialGenerationPhaseHandler
        | VaultStoragePhaseHandler
        | CredentialValidationPhaseHandler
    ],
) -> tuple[PhaseHandler, ...]:
    """Typecheck-only proof that every handler satisfies the driver's port."""

    return tuple(handlers)


def _session_conformance(session: CredentialLoopSession) -> tuple[LoopSession, object]:
    """Typecheck-only proof that one session serves the loop and the capture port."""

    return cast(LoopSession, session), cast(CredentialSurfaceSession, session)


def _registration_conformance(
    handlers: Mapping[OnboardingPhase, PhaseHandler],
) -> Mapping[OnboardingPhase, PhaseHandler]:
    """Typecheck-only proof that the factory's mapping is the one ``deps_for`` takes."""

    return handlers


__all__ = [
    "ADMISSION_PHASE",
    "ADMISSION_POLL_SECONDS",
    "CREDENTIAL_GENERATION_PHASE",
    "CREDENTIAL_VALIDATION_PHASE",
    "RESEARCH_INCONCLUSIVE_EVENT",
    "RESEARCH_PHASE",
    "RESEARCH_RETRY_CEILING_SECONDS",
    "RESEARCH_RETRY_SECONDS",
    "RESEARCH_UNAVAILABLE_EVENT",
    "VAULT_CHECK_PHASE",
    "VAULT_STORAGE_PHASE",
    "AdmissionDecisionStore",
    "AdmissionPhaseHandler",
    "CredentialGenerationPhaseHandler",
    "CredentialLoopSession",
    "CredentialOutcomeMemo",
    "CredentialValidationPhaseHandler",
    "ResearchPhaseHandler",
    "ResearchPorts",
    "ResearchTarget",
    "RunAccountBinding",
    "RunProviderBinding",
    "VaultCheckPhaseHandler",
    "VaultStoragePhaseHandler",
    "onboarding_phase_handlers",
]
