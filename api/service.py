"""Injectable API boundary over the canonical run ledger and legacy reader."""

from __future__ import annotations

import logging
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol, TypeVar, cast

import httpx
from fastapi.exceptions import RequestValidationError
from pydantic import SecretStr, ValidationError
from starlette.concurrency import run_in_threadpool

from api.browser_ui import project_browser_ui, session_lost_recorded
from api.models import (
    ActionReceipt,
    AdmissionDecisionRequest,
    AdmissionDecisionResponse,
    AppCatalogResponse,
    AppResearchResponse,
    AppSearchResponse,
    AppSummary,
    AutonomyOutcomeView,
    AuxiliaryHostView,
    BrowserLoginInput,
    BrowserServiceHealthView,
    BrowserUiState,
    BrowserVerificationInput,
    CreateRunRequest,
    CredentialSubmissionRequest,
    FieldEvidenceView,
    FlowSpecView,
    HealthCheck,
    HealthResponse,
    HitlRequestView,
    LiveViewResponse,
    ManagedConnectionResponse,
    ModelCatalogResponse,
    ModelOptionView,
    OnboardingControlsView,
    OnboardingStateView,
    PauseResponse,
    PhaseState,
    PrimaryAction,
    ProviderProfileView,
    ProviderState,
    ResetResponse,
    RetryableStep,
    RetryStepRequest,
    RetryStepResponse,
    RouteDecisionView,
    RunCitationView,
    RunDecisionView,
    RunDetailResponse,
    RunListResponse,
    RunOutputResponse,
    RunProgressEventView,
    RunSummary,
    SecurityState,
    SnapshotHealth,
    TimelineCorrelation,
    TimelineDetail,
    TimelineEvent,
    TimelineResponse,
)
from ops.browser.metrics import autonomy_outcome_view
from ops.browser.readiness import browser_configuration_state
from ops.browser.service_client import BrowserServiceClient, BrowserServiceHealth
from ops.core.config import Settings, load_settings
from ops.core.model_catalog import (
    ModelSelection,
    available_models,
    default_effort_for,
    resolve_selection,
)
from ops.core.models import AccountMode, CompanyProfile, OperationalResearch, OperationsRequest
from ops.core.state import RUN_STATUSES, BrowserProvider, RunStatus
from ops.deploy.acceptance import deployment_is_accepted
from ops.gmail.worker import GmailSignupPreflight
from ops.onboarding.admission import AdmissionDecision, decide_from_operator
from ops.onboarding.driver import (
    WAITING_PHASES,
    EffectReservationRecord,
    SQLitePhaseHistoryStore,
)
from ops.onboarding.phase import (
    TERMINAL_PHASES,
    OnboardingPhase,
    OnboardingReasonCode,
    is_legal_phase_transition,
    legal_phase_targets,
)
from ops.providers.composio_managed_auth import managed_auth_configuration_is_valid
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.recipes.app_recipes import (
    AppRecipe,
    get_app_recipe,
    get_app_recipe_for_name,
    load_app_recipe_catalog,
    recipe_to_operational_research,
)
from ops.recipes.signup_overlay import SignupOverlayRefused, install_signup_finding
from ops.research.operational_research import OfficialEvidenceFetcher
from ops.research.signup_agent import (
    PROGRESS_SUMMARIES as SIGNUP_RESEARCH_SUMMARIES,
)
from ops.research.signup_agent import (
    ProgressReporter,
    research_signup_route,
)
from ops.runs.projections import (
    ProjectedTimelineEvent,
    onboarding_timeline_event,
)
from ops.runs.reconciliation import OnboardingRunRecoveryService
from ops.runs.service import CredentialSubmissionError
from ops.runs.service import RunService as CoreRunService


class RunNotFoundError(LookupError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("run was not found")


class AppNotFoundError(LookupError):
    def __init__(self, app_slug: str) -> None:
        self.app_slug = app_slug
        super().__init__("app was not found")


class InvalidRequestError(ValueError):
    """A request field that only the deployment's own configuration can judge.

    Pydantic checks a field's shape; some fields are only valid against settings
    the model has no access to — a decision model id is real only if THIS
    deployment holds that provider's key. Raising this carries such a rejection
    back to the same 422 shape a shape failure produces, so a client sees one
    contract for "that field is not acceptable" rather than a 500 for the half
    of the check that happens later.
    """

    def __init__(self, *fields: str) -> None:
        self.fields = tuple(fields)
        super().__init__("request validation failed")


@dataclass(frozen=True, slots=True)
class _CachedGmailSignupPreflight:
    result: GmailSignupPreflight
    expires_monotonic: float
    checked_at: str
    expires_at: str


class PhaseUnavailableError(RuntimeError):
    def __init__(
        self,
        *,
        run_id: str,
        action: str,
        available_in: tuple[str, ...],
        error: str = "phase_unavailable",
        message: str = "Action is unavailable in the current runtime configuration.",
        reason_code: OnboardingReasonCode | None = None,
    ) -> None:
        self.run_id = run_id
        self.action = action
        self.available_in = available_in
        self.error = error
        self.safe_message = message
        # The onboarding refusals carry their reason code (design LL-6.4). It is
        # a member of the closed vocabulary or nothing at all, so a 409 body can
        # never carry provider text.
        self.reason_code = reason_code
        super().__init__(message)


class RunService(Protocol):
    """Stable orchestration boundary shared by API implementations."""

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    def deployment_mutations_allowed(self) -> bool: ...

    async def create_run(
        self,
        request: CreateRunRequest,
        *,
        idempotency_key: str | None = None,
    ) -> RunDetailResponse: ...

    async def submit_credentials(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse: ...

    async def list_runs(self, *, limit: int, offset: int) -> RunListResponse: ...

    async def get_model_catalog(self) -> ModelCatalogResponse: ...

    async def get_run(self, run_id: str) -> RunDetailResponse: ...

    async def get_timeline(self, run_id: str) -> TimelineResponse: ...

    async def resume(
        self,
        run_id: str,
        *,
        browser_login: BrowserLoginInput | None = None,
        browser_verification: BrowserVerificationInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt: ...

    async def get_live_view(self, run_id: str) -> LiveViewResponse: ...

    async def get_live_screenshot(self, run_id: str) -> tuple[bytes, str]: ...

    async def poll_email(self, run_id: str) -> ActionReceipt: ...

    async def connect_managed(self, run_id: str) -> ManagedConnectionResponse: ...

    async def poll_managed_connection(self, run_id: str) -> ManagedConnectionResponse: ...

    async def send_gated_outreach(self, run_id: str) -> ActionReceipt: ...

    async def get_output(self, run_id: str) -> RunOutputResponse: ...

    async def retry(self, run_id: str, capability: str) -> ActionReceipt: ...

    async def decide_admission(
        self,
        run_id: str,
        request: AdmissionDecisionRequest,
    ) -> AdmissionDecisionResponse: ...

    async def pause_onboarding(
        self, run_id: str, *, reason: str | None = None
    ) -> PauseResponse: ...

    async def reset_onboarding(self, run_id: str, *, confirm: bool) -> ResetResponse: ...

    async def retry_onboarding_step(
        self,
        run_id: str,
        request: RetryStepRequest,
    ) -> RetryStepResponse: ...

    async def get_provider_profile(self, run_id: str) -> ProviderProfileView: ...

    async def search_apps(self, query: str) -> AppSearchResponse: ...

    async def list_apps(self) -> AppCatalogResponse: ...

    async def get_app_research(self, app_slug: str) -> AppResearchResponse: ...

    async def signup_readiness(self) -> ProviderState: ...

    async def health(self) -> HealthResponse: ...


_LEGACY_EVENT_SUMMARIES: Final[dict[str, str]] = {
    "dry_run_created": "Local dry-run ledger entry created.",
    "run_created": "Executable run ledger entry created.",
    "operational_research_started": "Deterministic operational research started.",
    "p1_snapshot_loaded": "Verified P1 research loaded.",
    "p1_snapshot_not_found": "App was not found in the verified P1 snapshot.",
    "operational_research_built": "Provider-agnostic operational research built.",
    "reviewed_operational_baseline_applied": "Reviewed versioned provider baseline applied.",
    "route_pending": "Access route remains unknown; one bounded enrichment probe is available.",
    "route_selected": "Access route selected.",
    "composio_capability_evaluated": "Composio toolkit capability evaluated.",
    "browser_session_started": "Controlled browser session started.",
    "browser_navigation_completed": "Browser navigation to the official setup page completed.",
    "credential_page_ready": "Official credential/developer setup page reached.",
    "browser_hitl_required": "Human action required in the live browser.",
    "hitl_requested": "Human action requested.",
    "hitl_resumed": "Human action completed; run resumed.",
    "hitl_cancelled": "Human action cancelled; run blocked and browser released.",
    "outreach_sent": "Provider outreach sent.",
    "reply_received": "Provider reply received and sanitized.",
    "credential_stored": "Credential material stored behind a vault reference.",
    "credential_validated": "Credential validation completed.",
    "credential_capture_started": "Deterministic credential capture started.",
    "credentials_stored": "Captured credentials stored behind vault references.",
    "credential_validation_started": "Read-only credential validation started.",
    "credentials_validated": "Credential validation completed.",
    "integrator_bundle_generated": "Reference-only IntegratorBundle generated.",
    "credentials_ready": "Validated credential references are ready.",
    "run_completed": "Run completed.",
    "completed": "Run completed.",
}

# The 14 onboarding progress events of Requirement 17.2, with the LL-7 summaries.
# Every summary is a STATIC constant: it is looked up by event type and is never
# derived from a durable payload, so a run cannot author timeline text.
_ONBOARDING_PROGRESS_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_research_started": "Provider research started.",
    "onboarding_official_domain_found": "Official provider domain corroborated.",
    "onboarding_vault_checked": "Vault checked for existing credentials.",
    "onboarding_credentials_missing": "No credentials exist for this provider.",
    "onboarding_operator_approved_signup": "Operator approved account creation.",
    "onboarding_signup_started": "Account signup started.",
    "onboarding_verification_email_received": "Verification email received and authenticated.",
    "onboarding_verification_completed": "Provider accepted email verification.",
    "onboarding_authenticated": "Authenticated session established.",
    "onboarding_developer_app_created": "Developer application created.",
    "onboarding_credentials_generated": (
        "Credential generated and stored behind a vault reference."
    ),
    "onboarding_stored_in_vault": "Credential material stored behind a vault reference.",
    "onboarding_credentials_validated": "Credential validation passed.",
    "onboarding_completed": "Onboarding completed.",
}

# The 9 onboarding exception events of Requirement 17.3, with the LL-7 summaries.
_ONBOARDING_EXCEPTION_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_research_inconclusive": (
        "Provider research was inconclusive; nothing was executed."
    ),
    "onboarding_captcha_detected": "CAPTCHA detected; waiting for an operator.",
    "onboarding_captcha_resolved": "CAPTCHA resolved; run resumed.",
    "onboarding_verification_unresolved": (
        "Verification email was not received in the allowed window."
    ),
    "onboarding_validation_failed": "Credential validation failed.",
    "onboarding_run_paused": "Run paused.",
    "onboarding_run_cancelled": "Run cancelled.",
    "onboarding_run_reset": "Run reset; credentials preserved.",
    "onboarding_step_retried": "Current step retried.",
}

# The admission prompt is neither progress nor exception — it is the run asking
# for authorization — but LL-7 gives it a static summary, so it is allow-listed
# here rather than degrading to the generic one.
_ONBOARDING_ADMISSION_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_admission_requested": "Operator authorization requested for account creation.",
}

# The continuation of a paused run, written by
# ``OnboardingRunControlService.resume_from_pause``. A CAPTCHA pause continues
# under ``onboarding_captcha_resolved`` above; every other waiting phase continues
# under this type, and without a static summary here that continuation degraded to
# the generic run-updated projection — the one fact the production evidence of
# Requirement 10.2 has to be able to read (Requirements 1.13, 10.2).
_ONBOARDING_CONTINUATION_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_resumed": "Run continued from its pause.",
}

# The autonomous takeover of a run paused on a human-only gate, written by the
# Takeover_Watcher's sweep. The durable row carries the run id, the gate type, the
# phase re-entered and the reason code; none of it reaches the projection, which
# renders these fixed strings instead (Requirement 1.13).
_ONBOARDING_TAKEOVER_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_takeover_continued": "Gate cleared; the agent continued the run by itself.",
    "onboarding_takeover_withheld": "Takeover withheld; the run stays paused for an operator.",
}

# The live-view attachment fact that decides whether a paused session keeps its
# idle budget, written by the browser session boundary. The row carries the run id,
# the session id and the attachment outcome, and never a signed live-view URL
# (Requirement 2.7).
_ONBOARDING_ATTACHMENT_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_attachment_changed": "Live browser view attachment changed.",
}

# Loop liveness, written by the Run_Liveness sweep when a non-waiting run has
# reported no progress inside the Staleness_Window (Requirement 4.9).
_ONBOARDING_LIVENESS_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_progress_stale": "No loop progress within the staleness window.",
}

# The pre-flight route plan and its adherence, written by the plan store and the
# Route_Adherence_Monitor. A divergence row carries only the four bounded host and
# path fields, and a plan row only its revision, so the projection stays a fixed
# string and no observed URL can reach the timeline (Requirements 5.9, 6.1, 6.6).
_ONBOARDING_PLAN_SUMMARIES: Final[dict[str, str]] = {
    "onboarding_plan_recorded": "Pre-flight route plan recorded.",
    "onboarding_plan_superseded": "Route plan superseded by a replacement revision.",
    "onboarding_route_divergence": "The run left the surface its plan declared.",
}

# The signup research agent's own steps, so an operator watching a run sees what
# it is reading rather than a gap before signup starts. Static, like every other
# summary here: the researched page never authors the text an operator reads.
_ONBOARDING_SIGNUP_RESEARCH_SUMMARIES: Final[dict[str, str]] = {
    f"onboarding_{step}": summary for step, summary in SIGNUP_RESEARCH_SUMMARIES.items()
}

_EVENT_SUMMARIES: Final[dict[str, str]] = {
    **_LEGACY_EVENT_SUMMARIES,
    **_ONBOARDING_SIGNUP_RESEARCH_SUMMARIES,
    **_ONBOARDING_PROGRESS_SUMMARIES,
    **_ONBOARDING_EXCEPTION_SUMMARIES,
    **_ONBOARDING_ADMISSION_SUMMARIES,
    **_ONBOARDING_CONTINUATION_SUMMARIES,
    **_ONBOARDING_TAKEOVER_SUMMARIES,
    **_ONBOARDING_ATTACHMENT_SUMMARIES,
    **_ONBOARDING_LIVENESS_SUMMARIES,
    **_ONBOARDING_PLAN_SUMMARIES,
}

# What an event type absent from the allow-list projects. The durable row is left
# exactly as written; only its projection degrades (Requirement 17.5).
_GENERIC_EVENT_TYPE: Final = "run_updated"
_GENERIC_EVENT_SUMMARY: Final = "Run state updated."

_TimelineAttribution = TypeVar("_TimelineAttribution", TimelineCorrelation, TimelineDetail)


def _timeline_model(
    model: type[_TimelineAttribution],
    values: Mapping[str, object] | None,
) -> _TimelineAttribution | None:
    """Validate one projected attribution object, dropping an unprojectable one.

    The closed schemas are the last check on the durable columns. A column the
    schema refuses is omitted rather than failing the whole timeline response,
    which keeps the narrative readable and still lets nothing unvalidated out.
    """

    if not values:
        return None
    try:
        return model.model_validate(values)
    except ValidationError:
        return None


# --- Onboarding projections (design LL-6.1, LL-6.2, LL-6.3) ------------------
#
# Everything an onboarding response says about what the run is doing comes from
# one of two places: a durable column, or one of the STATIC tables below keyed by
# phase or by event type. Nothing is composed from a worker object, a page
# observation, a prompt, or a model response, which is what makes Requirement
# 19.13 a property of the projection rather than a rule a handler has to remember.

# Phase -> (goal, step). Static labels for the two narrative fields of
# ``OnboardingStateView``; the run cannot author either one.
_PHASE_NARRATIVE: Final[dict[OnboardingPhase, tuple[str, str]]] = {
    "research": ("Identify the provider's official domain", "Corroborating research evidence"),
    "vault_check": ("Decide how to authenticate", "Checking the vault for credentials"),
    "awaiting_admission": ("Decide how to authenticate", "Waiting for an admission decision"),
    "route_selected_login": ("Sign in to the provider", "Signing in with stored credentials"),
    "route_selected_signup": ("Create a provider account", "Opening the provider's signup page"),
    "signup": ("Create a provider account", "Completing the signup form"),
    "email_verification": ("Verify the account's email", "Waiting for the verification email"),
    "authenticated": ("Reach the developer portal", "Opening the developer portal"),
    "developer_app": ("Create a developer application", "Filling the application form"),
    "credential_generation": ("Generate API credentials", "Requesting a new credential"),
    "vault_storage": ("Store the credential safely", "Writing the credential to the vault"),
    "credential_validation": ("Prove the credential works", "Running a read-only validation call"),
    "captcha_paused": (
        "Clear the provider's challenge",
        "Waiting for an operator to solve a CAPTCHA",
    ),
    "completed": ("Onboarding complete", "Validated credential references are ready"),
    "paused": ("Paused by the operator", "Waiting for the operator to resume"),
    "blocked": ("Onboarding blocked", "No autonomous path remains"),
    "cancelled": ("Onboarding cancelled", "The run was cancelled"),
}

LOGGER: Final = logging.getLogger("composio_ops.api_service")

# What an unreadable ``runs.status`` is reported as. ``blocked`` is terminal and
# authorizes no action, so a row the vocabulary cannot name degrades into one the
# console will not act on rather than one it might drive.
_UNKNOWN_STATUS_FALLBACK: Final[RunStatus] = "blocked"
_KNOWN_RUN_STATUSES: Final[frozenset[str]] = frozenset(RUN_STATUSES)

# Phase -> the step an operator may retry in place. A phase absent here has no
# retryable step, so the controls view cannot offer a retry the backend refuses.
_RETRYABLE_STEP_FOR_PHASE: Final[dict[OnboardingPhase, RetryableStep]] = {
    "research": "research",
    "signup": "signup",
    "email_verification": "email_verification",
    "developer_app": "developer_app",
    "credential_generation": "credential_generation",
    "credential_validation": "credential_validation",
}

# Once a session has entered the secret capture boundary the live view is
# reported unavailable (Requirement 18.8). Both halves are durable: the phases in
# which credential material can render, and the recorded fact that a capture
# started.
_SECRET_CAPTURE_PHASES: Final[frozenset[str]] = frozenset(
    {"credential_generation", "vault_storage", "credential_validation"}
)
_SECRET_CAPTURE_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "credential_capture_started",
        "credentials_stored",
        "credential_stored",
        "onboarding_credentials_generated",
        "onboarding_stored_in_vault",
    }
)

# The three refusal codes the onboarding error mapping reports (design LL-6.4).
# Annotated with the closed vocabulary rather than ``str``, so a typo is a type
# error here instead of an unrecognized code on a 409 body.
_PHASE_REPLAY_NOOP: Final[OnboardingReasonCode] = "phase_replay_noop"
_OPERATOR_APPROVED_SIGNUP: Final[OnboardingReasonCode] = "operator_approved_signup"
_OUTCOME_UNKNOWN: Final[OnboardingReasonCode] = "outcome_unknown"


class _OnboardingEffectLedger:
    """The effect-ledger port the pause and retry controls read and settle through.

    Every verb is delegated verbatim to :class:`SQLitePhaseHistoryStore`, which owns
    all three: the reservation table it writes is the same table the enumeration
    reads, so a control decides from the standing disposition of each key rather
    than from anything reconstructed on this side.
    """

    def __init__(self, *, storage: object, phases: SQLitePhaseHistoryStore) -> None:
        self._storage = storage
        self._phases = phases

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        return self._phases.reservations(run_id=run_id)

    def complete_effect_reservation(
        self, *, run_id: str, operation_key: str, receipt: Mapping[str, str]
    ) -> EffectReservationRecord:
        return self._phases.complete_effect_reservation(
            run_id=run_id, operation_key=operation_key, receipt=receipt
        )

    def mark_effect_reservation_outcome_unknown(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord:
        return self._phases.mark_effect_reservation_outcome_unknown(
            run_id=run_id, operation_key=operation_key
        )


def _evidence_views(evidence: tuple[FieldEvidence, ...]) -> list[FieldEvidenceView]:
    """Project each citation, dropping one the closed schema will not admit.

    A dropped row is the right failure: the schemas refuse anything that is not a
    URL, a domain, or an enum member, and an unprojectable citation is more likely
    to be page-derived text than a fact the operator needs.
    """

    views: list[FieldEvidenceView] = []
    for item in evidence[:64]:
        try:
            views.append(
                FieldEvidenceView(
                    field=item.field,
                    value=item.value,
                    source_url=item.source_url,
                    source_digest=item.source_digest,
                    adapters=list(item.adapters[:8]),
                    corroborations=item.corroborations,
                    confidence=item.confidence,
                )
            )
        except ValidationError:
            continue
    return views


def _flow_views(flows: tuple[FlowSpec, ...]) -> list[FlowSpecView]:
    """Project the declared credential-producing flows, evidence excluded."""

    views: list[FlowSpecView] = []
    for flow in flows[:5]:
        try:
            views.append(
                FlowSpecView(
                    kind=flow.kind,
                    supported=flow.supported,
                    entry_url=flow.entry_url,
                    steps=list(flow.steps[:8]),
                    produces=list(flow.produces[:4]),
                    requires_approval=flow.requires_approval,
                    requires_billing=flow.requires_billing,
                )
            )
        except ValidationError:
            continue
    return views


def _project_provider_profile(
    profile: ProviderProfile,
    *,
    evidence: tuple[FieldEvidence, ...],
) -> ProviderProfileView:
    """The sanitized profile projection (design LL-6.1, Requirement 18.9).

    The allow-list patterns are projected in the shape the reviewed browser policy
    derives them in — one vendor wildcard over the primary registrable domain,
    plus each typed auxiliary host as an exact entry — so the console shows the
    same confinement the browser enforces rather than a second description of it.
    """

    patterns = [f"*.{profile.registrable_domain}", profile.registrable_domain]
    patterns.extend(auxiliary.host for auxiliary in profile.auxiliary_hosts)
    return ProviderProfileView(
        run_id=profile.run_id,
        profile_digest=profile.profile_digest,
        provider_name=profile.provider_name,
        app_slug=profile.app_slug,
        registrable_domain=profile.registrable_domain,
        allowed_host_patterns=list(dict.fromkeys(patterns))[:32],
        auxiliary_hosts=[
            AuxiliaryHostView(host=auxiliary.host, kind=auxiliary.kind)
            for auxiliary in profile.auxiliary_hosts[:16]
        ],
        developer_portal_url=profile.developer_portal_url,
        signup_url=profile.signup_url,
        login_url=profile.login_url,
        developer_docs_url=profile.developer_docs_url,
        flows=_flow_views(profile.flows()),
        approval_requirement=profile.approval_requirement,
        billing_requirement=profile.billing_requirement,
        evidence=_evidence_views(evidence),
        confidence=profile.confidence,
        built_at=profile.built_at,
    )


def _work_email_ref_for_app(app_name: str, *, app_slug: str | None = None) -> str:
    """Return a non-secret, deterministic work-email vault reference.

    Catalog slugs are preferred so punctuation-heavy display names such as
    ``Monday.com`` resolve to the exact same reference everywhere. The fallback
    is only for the conservative research-only path and remains inside the
    strict vault-reference alphabet.
    """

    resolved_slug = app_slug
    if resolved_slug is None:
        recipe = get_app_recipe_for_name(app_name) or get_app_recipe(app_name)
        resolved_slug = recipe.app_slug if recipe is not None else None
    if resolved_slug is None:
        resolved_slug = re.sub(r"[^a-z0-9]+", "-", app_name.strip().casefold()).strip("-")
    return f"vault://company/work_email/{resolved_slug or 'app'}"


class LocalRunService:
    """Leak-resistant HTTP adapter over the canonical application service."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        core_service: CoreRunService | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or load_settings()
        resolved_path = Path(db_path) if db_path is not None else self._settings.ops_db_path
        self._service = core_service or CoreRunService.from_paths(
            db_path=resolved_path,
            settings=self._settings,
        )
        self._started = False
        self._gmail_preflight_lock = threading.Lock()
        self._gmail_preflight_cache: _CachedGmailSignupPreflight | None = None
        # The two onboarding stores are opened on first use and reused: each one
        # runs its idempotent DDL in its constructor, and a legacy run pays for
        # neither until something asks for an onboarding projection.
        self._onboarding_lock = threading.Lock()
        self._onboarding_phases: SQLitePhaseHistoryStore | None = None
        self._onboarding_profiles: SQLiteProviderProfileStore | None = None

    async def startup(self) -> None:
        await run_in_threadpool(self._service.startup)
        self._started = True

    async def shutdown(self) -> None:
        self._started = False
        await run_in_threadpool(self._service.shutdown)

    def deployment_mutations_allowed(self) -> bool:
        """Keep production writes inert until this exact release is accepted.

        Local and test runtimes do not enable startup automation and therefore
        need no deploy marker. Production enables it in Compose; the same exact
        revision+nonce marker that unlocks background maintenance also unlocks
        operator and browser-broker mutations. Reading the small owner-only
        marker for every write avoids a stale in-memory acceptance decision
        during rollback.
        """

        if not self._settings.ops_startup_automation_enabled:
            return True
        return deployment_is_accepted(self._settings)

    def _require_started(self) -> None:
        if not self._started:
            raise RuntimeError("API service lifespan has not started")

    @staticmethod
    def _run_status(record: Mapping[str, object]) -> RunStatus:
        """The row's status, or a terminal placeholder if the vocabulary lost it.

        A ledger predates its vocabulary: a status written by a since-removed code
        path still sits in deployed rows, and a strict model would reject it. One
        such row must not take the whole list with it, so the value is coerced and
        the loss is logged with the run it happened to rather than swallowed.
        """

        status = record.get("status")
        if isinstance(status, str) and status in _KNOWN_RUN_STATUSES:
            return cast(RunStatus, status)
        LOGGER.warning(
            "run %s carries unknown status %r; reporting it as %r",
            record.get("run_id"),
            status,
            _UNKNOWN_STATUS_FALLBACK,
        )
        return _UNKNOWN_STATUS_FALLBACK

    @staticmethod
    def _summary(record: dict[str, object]) -> RunSummary:
        raw_attempt = record.get("attempt", 0)
        attempt = int(raw_attempt) if isinstance(raw_attempt, int | str) else 0
        stored_request = record.get("request")
        raw_account_mode = record.get("account_mode")
        if raw_account_mode is None and isinstance(stored_request, Mapping):
            raw_account_mode = stored_request.get("account_mode")
        account_mode = (
            cast(AccountMode, raw_account_mode)
            if raw_account_mode in {"existing_account", "create_account"}
            else None
        )
        return RunSummary(
            run_id=str(record["run_id"]),
            thread_id=str(record["thread_id"]),
            app_name=str(record["app_name"]),
            app_slug=str(record["app_slug"]),
            account_mode=account_mode,
            status=LocalRunService._run_status(record),
            access_route=record.get("access_route"),  # type: ignore[arg-type]
            created_at=str(record["created_at"]),
            updated_at=str(record["updated_at"]),
            execution_mode=record.get("execution_mode", "plan_only"),  # type: ignore[arg-type]
            browser_provider=record.get("browser_provider", "browser_use"),  # type: ignore[arg-type]
            credential_creation_policy=record.get("credential_creation_policy", "reuse_only"),  # type: ignore[arg-type]
            recipe_version=(
                str(record["recipe_version"]) if record.get("recipe_version") else None
            ),
            route_kind=record.get("route_kind"),  # type: ignore[arg-type]
            readiness_tier=record.get("readiness_tier"),  # type: ignore[arg-type]
            attempt=attempt,
            phase=str(record.get("phase") or "legacy"),
            reason_code=(str(record["reason_code"]) if record.get("reason_code") else None),
            state_engine=record.get("state_engine", "legacy"),  # type: ignore[arg-type]
            external_actions=bool(record.get("external_actions", False)),
        )

    def _primary_action(self, record: Mapping[str, object], summary: RunSummary) -> PrimaryAction:
        if summary.status == "completed":
            return PrimaryAction(kind="none", enabled=False, reason_code="run_completed")
        if summary.execution_mode == "plan_only":
            return PrimaryAction(kind="none", enabled=False, reason_code="plan_only_run_read_only")
        if summary.status == "credentials_ready":
            return PrimaryAction(
                kind="none",
                enabled=False,
                reason_code="credential_stored_validation_not_reviewed",
            )
        if summary.route_kind == "managed_auth":
            managed_enabled = managed_auth_configuration_is_valid(self._settings)
            if record.get("connection_request_id"):
                return PrimaryAction(
                    kind="poll_connection",
                    enabled=managed_enabled,
                    reason_code=(
                        "managed_connection_pending"
                        if managed_enabled
                        else "composio_managed_auth_not_configured"
                    ),
                )
            return PrimaryAction(
                kind="connect_account",
                enabled=managed_enabled,
                reason_code=(
                    "managed_connection_required"
                    if managed_enabled
                    else "composio_managed_auth_not_configured"
                ),
            )
        if summary.route_kind == "playwright":
            if summary.phase in {"credential_ready", "entry_reached"}:
                owner_actions_enabled = self._settings.allow_local_credential_submission
                return PrimaryAction(
                    kind="submit_credentials",
                    enabled=owner_actions_enabled,
                    reason_code=(
                        "owner_credential_submission_disabled"
                        if not owner_actions_enabled
                        else "owner_credential_submission_required"
                        if summary.phase == "credential_ready"
                        else "owner_credential_submission_available"
                    ),
                )
            return PrimaryAction(
                kind="open_browser",
                enabled=summary.status in {"browser_running", "waiting_for_hitl"},
                reason_code=(
                    "playwright_session_live"
                    if summary.status in {"browser_running", "waiting_for_hitl"}
                    else "playwright_session_not_live"
                ),
            )
        if summary.route_kind == "gated":
            if summary.status in {"outreach_sent", "waiting_for_reply"}:
                return PrimaryAction(
                    kind="poll_reply",
                    enabled=True,
                    reason_code="outreach_reply_pending",
                )
            controlled_outreach_enabled = bool(
                self._settings.composio_gmail_api_key is not None
                and self._settings.composio_gmail_connected_account_id
                and self._settings.outreach_recipient_override
            )
            outreach_ready = summary.readiness_tier == "outreach_ready"
            return PrimaryAction(
                kind="review_outreach",
                enabled=outreach_ready and controlled_outreach_enabled,
                reason_code=(
                    "outreach_contact_review_required"
                    if not outreach_ready
                    else "controlled_outreach_not_configured"
                    if not controlled_outreach_enabled
                    else "controlled_outreach_ready"
                ),
            )
        return PrimaryAction(kind="none", enabled=False, reason_code="legacy_run_read_only")

    def _cached_gmail_preflight(
        self,
        *,
        refresh: bool,
        force: bool = False,
    ) -> _CachedGmailSignupPreflight | None:
        """Return one bounded, value-free Gmail readiness result.

        Success is cached for one minute and failure for ten seconds. The lock is
        also the single-flight boundary: concurrent health requests cannot fan
        out into multiple provider reads.
        """

        settings = self._settings
        configured = bool(
            settings.composio_gmail_api_key is not None
            and settings.composio_gmail_connected_account_id
            and settings.gmail_signup_address is not None
        )
        if not configured:
            return None
        with self._gmail_preflight_lock:
            now_monotonic = time.monotonic()
            cached = self._gmail_preflight_cache
            if not force and cached is not None and cached.expires_monotonic > now_monotonic:
                return cached
            if not refresh:
                return None
            try:
                result = self._service.gmail_signup_preflight(
                    timeout_seconds=settings.gmail_signup_preflight_timeout_seconds
                )
            except Exception:
                result = GmailSignupPreflight(
                    status="unavailable",
                    reason_code="gmail_signup_preflight_failed",
                    provider_read_attempted=False,
                )
            ttl_seconds = 60 if result.ready else 10
            checked = datetime.now(UTC)
            entry = _CachedGmailSignupPreflight(
                result=result,
                expires_monotonic=time.monotonic() + ttl_seconds,
                checked_at=checked.isoformat(),
                expires_at=(checked + timedelta(seconds=ttl_seconds)).isoformat(),
            )
            self._gmail_preflight_cache = entry
            return entry

    def _provider_states(
        self,
        *,
        gmail_preflight: _CachedGmailSignupPreflight | None = None,
        browser_health: BrowserServiceHealth | None = None,
    ) -> list[ProviderState]:
        settings = self._settings

        def state(
            provider: str,
            *,
            configured: bool,
            enabled: bool = True,
            ready: bool = False,
            detail: str,
            reason_code: str | None = None,
            checked_at: str | None = None,
            expires_at: str | None = None,
        ) -> ProviderState:
            if not enabled:
                status = "disabled"
            elif ready:
                status = "ready"
            elif configured:
                status = "configured_not_verified"
            else:
                status = "not_configured"
            return ProviderState.model_validate(
                {
                    "provider": provider,
                    "status": status,
                    "detail": detail,
                    "reason_code": reason_code,
                    "checked_at": checked_at,
                    "expires_at": expires_at,
                }
            )

        live_browser_enabled = bool(getattr(settings, "allow_live_browser", False))
        gmail_inbox_configured = bool(
            settings.composio_gmail_api_key is not None
            and settings.composio_gmail_connected_account_id
        )
        gmail_outreach_configured = bool(
            gmail_inbox_configured and settings.outreach_recipient_override
        )
        if gmail_preflight is None:
            gmail_preflight = self._cached_gmail_preflight(refresh=False)
        gmail_signup_ready = bool(
            gmail_preflight is not None
            and gmail_preflight.result.ready
            and settings.gmail_signup_address is not None
        )
        managed_configured = managed_auth_configuration_is_valid(settings)
        browser_use_enabled = bool(
            live_browser_enabled and settings.browser_use_compatibility_enabled
        )
        playwright_configured = browser_configuration_state(settings, "playwright")
        if browser_health is None:
            playwright_state = state(
                "playwright",
                configured=playwright_configured,
                enabled=live_browser_enabled,
                detail=self._browser_provider_detail(
                    provider="playwright",
                    settings=settings,
                    live_enabled=live_browser_enabled,
                ),
            )
        else:
            browser_ready = bool(
                browser_health.state in {"ready", "capacity_exhausted"}
                and browser_health.chromium_installed
                and browser_health.context_launch_ok
                and browser_health.janitor_running
            )
            playwright_state = ProviderState.model_validate(
                {
                    "provider": "playwright",
                    "status": "ready" if browser_ready else "configured_not_verified",
                    "detail": (
                        f"Cached browser service state={browser_health.state}; "
                        f"version={browser_health.version}; "
                        f"chromium_installed={str(browser_health.chromium_installed).lower()}; "
                        f"context_launch_ok={str(browser_health.context_launch_ok).lower()}; "
                        f"janitor_running={str(browser_health.janitor_running).lower()}; "
                        f"capacity={browser_health.capacity_in_use}/"
                        f"{browser_health.capacity_total}."
                    ),
                    "reason_code": browser_health.reason_code,
                }
            )
        return [
            state(
                "recipes",
                configured=True,
                ready=len(load_app_recipe_catalog().apps) == 50,
                detail="The reviewed 50-app recipe catalog passed startup validation.",
            ),
            state(
                "vault",
                configured=settings.secret_vault_key is not None,
                detail="The credential vault requires a separate Fernet key.",
            ),
            state(
                "composio_managed_auth",
                configured=managed_configured,
                detail=(
                    "Managed connection links are configured; live status is checked only on an owner action."
                    if managed_configured
                    else "Managed auth requires COMPOSIO_API_KEY and a valid public HTTPS "
                    "MANAGED_AUTH_CALLBACK_BASE_URL origin."
                ),
            ),
            state(
                "gmail",
                configured=gmail_inbox_configured,
                enabled=gmail_inbox_configured,
                ready=gmail_signup_ready,
                detail=(
                    "A bounded inbox read succeeded; Gmail signup verification is ready."
                    if gmail_signup_ready
                    else "Gmail signup inbox verification failed its latest bounded read."
                    if gmail_preflight is not None
                    else "Gmail inbox verification and controlled outreach are configured but not yet verified."
                    if gmail_outreach_configured and settings.gmail_signup_address
                    else "Gmail inbox verification is configured; new-account signup still needs GMAIL_SIGNUP_ADDRESS."
                    if gmail_inbox_configured and not settings.gmail_signup_address
                    else "Gmail inbox verification is configured; outreach remains disabled."
                    if gmail_inbox_configured
                    else "Gmail verification requires Composio and a connected Gmail account."
                ),
                reason_code=(
                    gmail_preflight.result.reason_code
                    if gmail_preflight is not None
                    else "gmail_signup_address_missing"
                    if gmail_inbox_configured and settings.gmail_signup_address is None
                    else "gmail_signup_preflight_not_run"
                    if gmail_inbox_configured
                    else "gmail_signup_not_configured"
                ),
                checked_at=(gmail_preflight.checked_at if gmail_preflight is not None else None),
                expires_at=(gmail_preflight.expires_at if gmail_preflight is not None else None),
            ),
            playwright_state,
            state(
                "browser_use",
                configured=(
                    browser_use_enabled and browser_configuration_state(settings, "browser_use")
                ),
                enabled=browser_use_enabled,
                detail=self._browser_provider_detail(
                    provider="browser_use",
                    settings=settings,
                    live_enabled=browser_use_enabled,
                ),
            ),
        ]

    @staticmethod
    def _browser_provider_detail(*, provider: str, settings: Settings, live_enabled: bool) -> str:
        """Provider health detail. Never launches a browser from the API path."""

        if not live_enabled:
            if provider == "browser_use" and not settings.browser_use_compatibility_enabled:
                return "Browser Use compatibility execution is disabled for this rollout."
            return "Live browser execution is policy-disabled."
        if provider != "playwright":
            if settings.browser_use_api_key is None:
                return "Browser Use requires BROWSER_USE_API_KEY."
            return "Browser configuration is present but has not been verified."
        if getattr(settings, "playwright_in_process_sandbox", False):
            return (
                "In-process Playwright sandbox is enabled (tests and local debugging "
                "only); Chromium runs inside this process rather than the browser service."
            )
        if not settings.browser_service_url or settings.browser_service_token is None:
            return (
                "The Playwright provider requires BROWSER_SERVICE_URL and "
                "BROWSER_SERVICE_TOKEN, or the explicit in-process sandbox flag."
            )
        return (
            "Chromium runs in the isolated browser service; its readiness is reported "
            "by that service's own cached probe rather than by this image."
        )

    @staticmethod
    def _browser_phase_detail(*, provider: str, configured: bool) -> str:
        """Describe the SELECTED browser provider's state in its own terms."""

        if provider == "playwright":
            if not configured:
                return (
                    "The self-hosted browser harness requires the ALLOW_LIVE_BROWSER policy "
                    "opt-in. No Browser Use key is needed for this provider."
                )
            return (
                "The self-hosted harness enforces the host allowlist in-process via request "
                "interception, and Chromium runs in the separate browser service so an API "
                "restart does not end a live session. Readiness is proven by that service's "
                "own health probe rather than by this image."
            )
        if not configured:
            return "A Browser Use key and ALLOW_LIVE_BROWSER policy opt-in are required."
        return (
            "Browser Use v3 agent navigation fails closed because the installed SDK cannot "
            "prove the mandatory domain allowlist. Trusted adapter-owned Playwright capture "
            "remains a separate deterministic boundary."
        )

    def _phases(
        self,
        research: OperationalResearch | None,
        record: dict[str, object],
    ) -> list[PhaseState]:
        research_phase = (
            PhaseState(
                key="research",
                name="Research",
                phase="2",
                status="ready",
                detail="Verified P1 research and deterministic access routing are available.",
                available=True,
            )
            if research is not None
            else PhaseState(
                key="research",
                name="Research",
                phase="2",
                status="waiting",
                detail=(
                    "The app is absent from the verified P1 snapshot. One bounded enrichment "
                    "probe remains pending and requires configured discovery plus structured extraction."
                ),
                available=False,
            )
        )
        route_kind = str(record.get("route_kind") or "")
        run_status = str(record.get("status") or "")
        run_phase = str(record.get("phase") or "")
        browser_provider: BrowserProvider = (
            "playwright" if record.get("browser_provider") == "playwright" else "browser_use"
        )
        has_browser_configuration = browser_configuration_state(
            self._settings,
            browser_provider,
        )
        browser_detail = self._browser_phase_detail(
            provider=browser_provider, configured=has_browser_configuration
        )
        has_email_inbox_configuration = bool(
            self._settings.composio_gmail_api_key is not None
            and self._settings.composio_gmail_connected_account_id
        )
        has_outreach_configuration = bool(
            has_email_inbox_configuration and self._settings.outreach_recipient_override
        )
        bundle_ready = record.get("integrator_bundle") is not None

        if route_kind != "playwright":
            browser_phase = PhaseState(
                key="browser",
                name="Browser",
                phase="browser",
                status="unavailable",
                detail="This recipe does not use browser automation.",
                available=False,
            )
            hitl_phase = PhaseState(
                key="hitl",
                name="HITL",
                phase="hitl",
                status="unavailable",
                detail="No browser handoff is part of this route.",
                available=False,
            )
        else:
            if run_status == "waiting_for_hitl":
                browser_status = "waiting"
            elif run_status == "browser_running" and run_phase in {
                "credential_ready",
                "entry_reached",
            }:
                browser_status = "ready"
            elif run_status == "browser_running":
                browser_status = "running"
            elif run_status in {"failed", "blocked", "configuration_required"}:
                browser_status = run_status
            else:
                browser_status = "ready" if has_browser_configuration else "configuration_required"
            browser_phase = PhaseState(
                key="browser",
                name="Browser",
                phase="browser",
                status=browser_status,  # type: ignore[arg-type]
                detail=browser_detail,
                available=has_browser_configuration,
            )
            hitl_phase = PhaseState(
                key="hitl",
                name="HITL",
                phase="hitl",
                status=(
                    "waiting"
                    if run_status == "waiting_for_hitl"
                    else "ready"
                    if has_browser_configuration
                    else "configuration_required"
                ),
                detail=(
                    "The same Playwright session is paused for owner control."
                    if run_status == "waiting_for_hitl"
                    else "HITL state is persisted in the canonical SQLite run record."
                ),
                available=has_browser_configuration,
            )

        hitl_request = record.get("hitl_request")
        waiting_for_email_verification = bool(
            run_status == "waiting_for_hitl"
            and isinstance(hitl_request, dict)
            and (
                hitl_request.get("type") == "email_otp"
                or hitl_request.get("action_type") == "email_otp"
            )
        )
        if route_kind == "playwright":
            email_phase = PhaseState(
                key="email",
                name="Email verification",
                phase="verification",
                status=(
                    "waiting"
                    if waiting_for_email_verification
                    else "ready"
                    if has_email_inbox_configuration
                    else "configuration_required"
                ),
                detail=(
                    "Waiting for a fresh, correctly addressed code or verification link."
                    if waiting_for_email_verification
                    else "The connected Gmail inbox can resolve signup and login verification."
                    if has_email_inbox_configuration
                    else "Connect Gmail to enable automatic signup and login verification."
                ),
                available=has_email_inbox_configuration,
            )
        elif route_kind != "gated":
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status="unavailable",
                detail="This recipe does not use controlled outreach.",
                available=False,
            )
        elif record.get("readiness_tier") == "outreach_review_required":
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status="unavailable",
                detail="A reviewed vendor contact is required before outreach can be enabled.",
                available=False,
            )
        else:
            email_phase = PhaseState(
                key="email",
                name="Email",
                phase="outreach",
                status=(
                    "waiting"
                    if run_status in {"outreach_sent", "waiting_for_reply"}
                    else "ready"
                    if has_outreach_configuration
                    else "configuration_required"
                ),
                detail="Outreach is bounded to the configured controlled sink.",
                available=has_outreach_configuration,
            )
        return [
            research_phase,
            browser_phase,
            hitl_phase,
            email_phase,
            PhaseState(
                key="output",
                name="Output",
                phase="3+",
                status="complete" if bundle_ready else "waiting",
                detail=(
                    "A sanitized IntegratorBundle is available."
                    if bundle_ready
                    else "No IntegratorBundle exists until credential validation reaches a terminal state."
                ),
                available=bundle_ready,
            ),
        ]

    @staticmethod
    def _hitl_view(record: dict[str, object]) -> HitlRequestView | None:
        if record.get("status") != "waiting_for_hitl":
            return None
        hitl = record.get("hitl_request")
        if not isinstance(hitl, dict):
            return None
        action_type = str(hitl.get("type") or hitl.get("action_type") or "provider_verification")
        message = str(hitl.get("message") or "A human action is required in the live browser.")
        signal = str(
            hitl.get("expected_completion_signal") or "The required action has been completed."
        )
        return HitlRequestView(
            action_type=action_type,
            message=message,
            expected_completion_signal=signal,
            resumable=True,
        )

    def _browser_ui(
        self, record: dict[str, object], hitl: HitlRequestView | None
    ) -> BrowserUiState:
        """Project explicit browser permissions from backend-owned facts only."""

        run_id = str(record.get("run_id") or "")
        try:
            events = self._service.get_timeline(run_id)
        except Exception:
            # A timeline read failure must not fabricate progress: with no trusted
            # events, nothing is verified and every mutation stays disabled.
            events = []
        event_types = {str(event.get("event_type")) for event in events}
        run_status = str(record.get("status") or "")
        session_id = record.get("browser_session_id")
        session_id = session_id if isinstance(session_id, str) and session_id else None
        # Rule 8: ask the worker whether a real frame exists, and only when a live
        # session could plausibly have one.
        screenshot_present = False
        if session_id is not None and run_status in {"browser_running", "waiting_for_hitl"}:
            try:
                screenshot_present = self._service.get_browser_screenshot(run_id) is not None
            except Exception:
                screenshot_present = False
        return project_browser_ui(
            settings=self._settings,
            browser_provider=record.get("browser_provider", "browser_use"),  # type: ignore[arg-type]
            run_status=run_status,
            event_types=event_types,
            browser_session_id=session_id,
            hitl=hitl,
            screenshot_present=screenshot_present,
            session_lost=session_lost_recorded(events),
            plan_only=str(record.get("execution_mode") or "") == "local_dry_run",
            owner_submission_ready=(
                record.get("readiness_tier") == "owner_submit_ready"
                and record.get("phase") == "entry_reached"
            ),
        )

    # --- The onboarding surface (design LL-6.3) -----------------------------
    #
    # Every method below reads durable state and returns a response model. None of
    # them drives a provider, and none of them can resolve a credential value: the
    # only vault-facing dependency is the reference-only probe reset uses to count
    # what it preserved.

    def _phase_store(self) -> SQLitePhaseHistoryStore:
        """The run ledger's phase history, opened once per service instance."""

        with self._onboarding_lock:
            if self._onboarding_phases is None:
                self._onboarding_phases = SQLitePhaseHistoryStore(self._service.storage.db_path)
            return self._onboarding_phases

    def _profile_store(self) -> SQLiteProviderProfileStore:
        """The content-addressed profile store, scoped to this deployment's owner."""

        with self._onboarding_lock:
            if self._onboarding_profiles is None:
                self._onboarding_profiles = SQLiteProviderProfileStore(
                    Path(self._service.storage.db_path).parent / "provider_profiles.db",
                    owner=self._settings.browser_service_owner,
                )
            return self._onboarding_profiles

    def _release_onboarding_session(self, *, run_id: str, reason: str) -> bool:
        """Hand the run's bound browser session back, synchronously.

        Cancel and reset must not answer before the session is gone
        (Requirements 14.5, 14.7), so the release happens on this call rather than
        in a sweep. The core service owns the worker and the release is idempotent
        there, so a run with no bound session reports ``False`` instead of raising.
        """

        record = self._service.storage.get_run(run_id)
        context = self._service._session_context_for(run_id)
        if record is None or context is None:
            return False
        provider = cast(BrowserProvider, record.get("browser_provider", "browser_use"))
        self._service._release_browser_session(context, provider, reason=reason)
        return True

    def _run_controls(self) -> OnboardingRunRecoveryService:
        """The five operator controls over one run's durable phase machine.

        The vault probe is the run service's own store, so the count reset reports
        is read from the same references the run itself uses. Its port exposes a
        reference lookup and nothing else, so this wiring cannot resolve a value.
        """

        phases = self._phase_store()
        return OnboardingRunRecoveryService(
            storage=self._service.storage,
            phases=phases,
            effects=_OnboardingEffectLedger(storage=self._service.storage, phases=phases),
            # No component clears LangGraph checkpoints yet, so a reset reports
            # ``workflow_state_cleared=False`` honestly rather than claiming it.
            workflow=None,
            credentials=getattr(self._service, "_secret_store", None),
            release_session=self._release_onboarding_session,
        )

    def _latest_decision(self, run_id: str) -> str:
        """The newest allow-listed event summary, or empty for a run with none.

        Deliberately the SAME static allow-list the timeline projects through: the
        console's "latest decision" line is therefore one of a fixed set of
        strings and can never be authored by a run (Requirement 19.13).
        """

        summary = ""
        try:
            events = self._service.storage.list_audit_events(run_id)
        except Exception:  # pragma: no cover - a read failure carries no decision
            return ""
        for event in events:
            known = _EVENT_SUMMARIES.get(str(event.get("event_type") or ""))
            if known is not None:
                summary = known
        return summary[:300]

    def _onboarding_state(self, run_id: str) -> OnboardingStateView | None:
        """Project the run's onboarding sub-state, or ``None`` for a legacy run.

        A run is an onboarding run exactly when it has a committed phase boundary,
        which is durable and survives an API restart. Every field comes from that
        boundary, from a durable counter, or from a static table.
        """

        phases = self._phase_store()
        history = phases.history(run_id=run_id)
        if not history:
            return None
        boundary = history[-1]
        try:
            pause = phases.captcha_pause(run_id=run_id)
        except KeyError:  # pragma: no cover - written by the first boundary
            phase_at_pause: OnboardingPhase | None = None
            captcha_prompts = 0
        else:
            phase_at_pause = pause.phase_at_pause
            captcha_prompts = pause.prompts
        goal, step = _PHASE_NARRATIVE[boundary.to_phase]
        return OnboardingStateView(
            phase=boundary.to_phase,
            phase_at_pause=phase_at_pause,
            profile_digest=boundary.profile_digest,
            reason_code=boundary.reason_code,
            goal=goal,
            step=step,
            latest_decision=self._latest_decision(run_id),
            attempt=boundary.attempt,
            admission_prompts=min(phases.admission_prompts(run_id=run_id), 1),
            captcha_prompts=captcha_prompts,
            correlation_id=boundary.correlation_id,
        )

    def _autonomy_view(self, run_id: str) -> AutonomyOutcomeView | None:
        """Project the run's autonomy outcome once it has one (Requirement 20.8).

        The driver writes the record at a terminal phase and nowhere else, so the
        PRESENCE of a row is the terminal condition — there is no second status
        check here that could disagree with it. ``None`` means the run has not
        finished, and the field is simply absent from the response.

        A row that the projection refuses (a verdict, phase, or count the closed
        view will not admit) is dropped rather than raised: a corrupted metrics row
        must not make a run undisplayable.
        """

        try:
            row = self._service.storage.read_autonomy_outcome(run_id)
        except Exception:  # pragma: no cover - a read failure carries no outcome
            return None
        if row is None:
            return None
        try:
            # ``model_validate`` rather than a keyword splat: the six projected
            # values arrive as ``object`` from the stored row, and the view's own
            # closed vocabularies are what narrow them.
            return AutonomyOutcomeView.model_validate(autonomy_outcome_view(row))
        except (ValidationError, ValueError):
            return None

    def _onboarding_controls(
        self,
        run_id: str,
        state: OnboardingStateView,
    ) -> OnboardingControlsView:
        """Decide each control from the phase table and the durable decision row.

        Read the flags as decisions, not hints: the console renders exactly what
        the backend says is legal, and a control whose boundary the phase table
        refuses is false here rather than a 409 later (Requirement 18.4).
        """

        phase = state.phase
        terminal = phase in TERMINAL_PHASES
        waiting = phase in WAITING_PHASES
        targets = legal_phase_targets(phase)
        retryable = None if terminal or waiting else _RETRYABLE_STEP_FOR_PHASE.get(phase)
        reset_available = not terminal and (
            phase == "research"
            or "research" in targets
            or ("paused" in targets and is_legal_phase_transition("paused", "research"))
        )
        can_resume = waiting
        withheld = (
            self._withheld_resume_reason(run_id, state) if phase == "captcha_paused" else None
        )
        if withheld is not None:
            can_resume = False
        return OnboardingControlsView(
            can_decide_admission=(
                phase == "awaiting_admission"
                and self._service.storage.read_admission_decision(run_id) is None
            ),
            can_pause=not terminal and not waiting,
            can_resume=can_resume,
            can_cancel=not terminal and "cancelled" in targets,
            can_reset=reset_available,
            can_retry_step=retryable is not None,
            retryable_step=retryable,
            reason_code=state.reason_code,
            resume_withheld_reason=withheld,
        )

    def _withheld_resume_reason(
        self,
        run_id: str,
        state: OnboardingStateView,
    ) -> OnboardingReasonCode | None:
        """Why a CAPTCHA-paused run cannot be resumed, or ``None`` when it can.

        Total by construction: the three provable causes in order, then
        ``control_withheld`` for a re-entry the phase table refuses.
        """

        if state.phase_at_pause is None:
            return "takeover_step_unavailable"
        record = self._service.storage.get_run(run_id)
        if record is None or not record.get("browser_session_id"):
            return "session_unreattachable"
        if state.captcha_prompts >= self._settings.onboarding_captcha_pause_budget:
            return "captcha_attempt_budget_exhausted"
        if not is_legal_phase_transition(state.phase, state.phase_at_pause):
            return "control_withheld"
        return None

    def _secret_capture_boundary_entered(self, record: Mapping[str, object]) -> bool:
        """Whether a capture surface has been reached for this run (Requirement 18.8).

        Two durable readings: the phases in which credential material can render,
        and the recorded fact that a capture started. Either one closes the live
        view, and neither can be re-opened by a later observation.

        A core service that offers no audit trail at all is a different case from
        a trail that cannot be read: an absent reader is no evidence that a
        capture happened, so the phase reading above is then the only signal. The
        probe mirrors the optional-verb convention used for the interactive grant
        below, and a reader that exists but raises still fails closed.
        """

        if str(record.get("phase") or "") in _SECRET_CAPTURE_PHASES:
            return True
        run_id = str(record.get("run_id") or "")
        reader = getattr(getattr(self._service, "storage", None), "list_audit_events", None)
        if not callable(reader):
            return False
        try:
            events = reader(run_id)
        except Exception:  # pragma: no cover - fail closed on an unreadable trail
            return True
        return any(str(event.get("event_type") or "") in _SECRET_CAPTURE_EVENTS for event in events)

    def _require_onboarding_state(self, run_id: str, *, action: str) -> OnboardingStateView:
        """The run's onboarding state, or a typed 409 for a run that has none."""

        if self._service.get_run(run_id) is None:
            raise RunNotFoundError(run_id)
        state = self._onboarding_state(run_id)
        if state is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action=action,
                available_in=("onboarding",),
                error="phase_unavailable",
                message="This control is available only for a run on the onboarding driver.",
            )
        return state

    @staticmethod
    def _decision_response(
        decision: AdmissionDecision,
        *,
        state: OnboardingStateView,
        replayed: bool,
    ) -> AdmissionDecisionResponse:
        """Project a recorded decision. The credential references are NOT projected."""

        return AdmissionDecisionResponse(
            run_id=decision.run_id,
            route=decision.route,
            reason_code=decision.reason_code,
            decided_by=decision.decided_by,
            decided_at=decision.decided_at,
            replayed=replayed,
            onboarding=state,
        )

    def _decision_sync(
        self,
        run_id: str,
        request: AdmissionDecisionRequest,
    ) -> AdmissionDecisionResponse:
        """Record the operator's admission decision, then answer from the record.

        The response is built from what was READ BACK out of the admission table,
        never from the request, so a body that says ``signup`` is a body whose row
        exists (Requirements 3.8, 3.9).

        The refusals are ordered, and the order is the design (LL-6.4). The digest
        check runs first because a request about the wrong profile is wrong
        whatever the run's phase is (Requirement 3.10). The replay branch runs
        before the phase check, because a run that has already decided has left
        ``awaiting_admission`` and a second ``create_account`` must still get the
        original record back rather than a 409 (Requirement 3.11) — with the one
        exception the vocabulary names: a ``cancel`` against an approved signup is
        refused (Requirement 3.12). Only then does a decision on a run that never
        reached the admission gate get the run's current reason code
        (Requirement 3.15).
        """

        state = self._require_onboarding_state(run_id, action="decision")
        storage = self._service.storage
        if request.profile_digest != state.profile_digest:
            # The operator decided about a profile that is not the committed one.
            # Nothing is read back and nothing is written, so the recorded
            # decision and the committed phase are untouched.
            raise PhaseUnavailableError(
                run_id=run_id,
                action="decision",
                available_in=("awaiting_admission",),
                error="phase_unavailable",
                message="The decision names a provider profile the run has not committed.",
                reason_code=_PHASE_REPLAY_NOOP,
            )
        recorded = storage.read_admission_decision(run_id)
        if recorded is not None:
            if request.decision == "cancel" and recorded.route == "signup":
                # Account creation is already authorized and may already have run;
                # withdrawing it here would claim a rollback the API cannot make.
                # Cancelling the run itself remains available as its own control.
                raise PhaseUnavailableError(
                    run_id=run_id,
                    action="decision",
                    available_in=("awaiting_admission",),
                    error="phase_unavailable",
                    message="Account creation was already approved for this run.",
                    reason_code=_OPERATOR_APPROVED_SIGNUP,
                )
            # Idempotent per run: the ORIGINAL answer comes back with the replay
            # indicator set and nothing is rewritten (Requirement 3.11).
            return self._decision_response(recorded, state=state, replayed=True)
        if state.phase != "awaiting_admission":
            # No decision on record and the run is not at the gate: the refusal
            # carries the phase's own reason code so the console can say why.
            raise PhaseUnavailableError(
                run_id=run_id,
                action="decision",
                available_in=("awaiting_admission",),
                error="phase_unavailable",
                message="This run is not waiting for an admission decision.",
                reason_code=state.reason_code,
            )
        decision = decide_from_operator(
            request.decision,
            run_id=run_id,
            profile_digest=state.profile_digest,
            actor_owner_id=self._settings.browser_service_owner,
        )
        stored, replayed = storage.record_admission_decision(decision)
        if stored.route == "cancelled":
            # A cancellation is released, persisted, and committed before the API
            # answers (Requirements 3.13, 14.5, 14.6).
            self._run_controls().cancel_run(run_id)
        return self._decision_response(
            stored,
            state=self._onboarding_state(run_id) or state,
            replayed=replayed,
        )

    def _pause_sync(self, run_id: str, reason: str | None) -> PauseResponse:
        """Stop the run at its next safe boundary, keeping the session alive.

        ``reason`` is accepted and dropped on purpose: the durable record carries
        the closed reason code, and an operator-supplied string on an audit row is
        the one field that could carry anything at all.
        """

        state = self._require_onboarding_state(run_id, action="pause")
        del reason
        outcome = self._run_controls().request_pause(run_id)
        return PauseResponse(
            run_id=run_id,
            accepted=outcome.accepted,
            pausing_after_phase=outcome.pausing_after_phase,
            reason_code=outcome.reason_code,
            onboarding=self._onboarding_state(run_id) or state,
        )

    def _reset_sync(self, run_id: str, confirm: bool) -> ResetResponse:
        """Restart the walk at research, preserving every vault reference.

        An unconfirmed reset is a validation error (Requirement 14.12). The
        request model already refuses it — ``confirm`` admits only ``True`` and has
        no default — and the same refusal is restated here, ahead of every read
        and every port, so the guarantee holds for any caller of this service and
        not only for one that arrived through the route: no session is released,
        no workflow state is cleared, and no vault reference is touched.
        """

        if confirm is not True:
            raise RequestValidationError(
                [
                    {
                        "type": "literal_error",
                        "loc": ("body", "confirm"),
                        "msg": "reset requires explicit confirmation",
                        "input": confirm,
                    }
                ]
            )
        self._require_onboarding_state(run_id, action="reset")
        outcome = self._run_controls().reset_run(run_id, confirm=confirm)
        if not outcome.accepted:
            # The phase table gives this run no route back to research, so nothing
            # was released, cleared, or committed. Refused rather than reported as
            # a reset: the response shape has no way to say "did nothing".
            raise PhaseUnavailableError(
                run_id=run_id,
                action="reset",
                available_in=("research", "paused"),
                error="phase_unavailable",
                message="This run cannot be reset from its current phase.",
                reason_code=outcome.reason_code,
            )
        return ResetResponse(
            run_id=run_id,
            reason_code=outcome.reason_code,
            phase=outcome.phase,
            browser_session_released=outcome.browser_session_released,
            workflow_state_cleared=outcome.workflow_state_cleared,
            vault_references_preserved=min(outcome.vault_references_preserved, 64),
            expected_route_on_restart=outcome.expected_route_on_restart,
        )

    def _retry_step_sync(self, run_id: str, request: RetryStepRequest) -> RetryStepResponse:
        """Re-attempt the current step, naming every effect the ledger will skip.

        Two refusals, both 409 and both carrying the control service's own reason
        code: an ``expected_phase`` that is not the run's current phase reports
        ``phase_replay_noop`` and leaves the phase and every ledger row untouched
        (Requirement 14.16), and a run holding a reservation marked
        ``outcome_unknown`` reports that code with no provider submission
        performed (Requirement 14.17). Neither refusal is reachable after a write:
        the control service decides both before it commits anything.
        """

        self._require_onboarding_state(run_id, action="retry_step")
        outcome = self._run_controls().retry_current_step(
            run_id, expected_phase=request.expected_phase
        )
        if not outcome.accepted:
            unknown = outcome.reason_code == _OUTCOME_UNKNOWN
            raise PhaseUnavailableError(
                run_id=run_id,
                action="retry_step",
                available_in=(outcome.phase,),
                error="phase_unavailable",
                message=(
                    "An effect for this run has an unknown outcome and must be "
                    "reconciled before a retry."
                    if unknown
                    else "The retry names a step the run is not standing in."
                ),
                reason_code=outcome.reason_code,
            )
        return RetryStepResponse(
            run_id=run_id,
            accepted=outcome.accepted,
            phase=outcome.phase,
            attempt=outcome.attempt,
            reason_code=outcome.reason_code,
            skipped_effects=list(outcome.skipped_effects),
        )

    def _profile_sync(self, run_id: str) -> ProviderProfileView:
        """Serve the sanitized profile projection (Requirement 18.9)."""

        if self._service.get_run(run_id) is None:
            raise RunNotFoundError(run_id)
        store = self._profile_store()
        profile = store.get_for_run(run_id=run_id)
        if profile is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="profile",
                available_in=("research",),
                error="phase_unavailable",
                message="No provider profile is committed for this run yet.",
            )
        return _project_provider_profile(
            profile,
            evidence=store.evidence_for(profile_digest=profile.profile_digest),
        )

    async def decide_admission(
        self,
        run_id: str,
        request: AdmissionDecisionRequest,
    ) -> AdmissionDecisionResponse:
        self._require_started()
        return await run_in_threadpool(self._decision_sync, run_id, request)

    async def pause_onboarding(self, run_id: str, *, reason: str | None = None) -> PauseResponse:
        self._require_started()
        return await run_in_threadpool(self._pause_sync, run_id, reason)

    async def reset_onboarding(self, run_id: str, *, confirm: bool) -> ResetResponse:
        self._require_started()
        return await run_in_threadpool(self._reset_sync, run_id, confirm)

    async def retry_onboarding_step(
        self,
        run_id: str,
        request: RetryStepRequest,
    ) -> RetryStepResponse:
        self._require_started()
        return await run_in_threadpool(self._retry_step_sync, run_id, request)

    async def get_provider_profile(self, run_id: str) -> ProviderProfileView:
        self._require_started()
        return await run_in_threadpool(self._profile_sync, run_id)

    def _detail(self, summary: RunSummary) -> RunDetailResponse:
        research = self._service.get_research(summary.run_id)
        record = self._service.storage.get_run(summary.run_id)
        if record is None:  # pragma: no cover - summary came from the same record
            raise RunNotFoundError(summary.run_id)
        owner_only = self._storage_permissions_are_owner_only()
        route_reason_code = record.get("route_reason_code")
        route_explanation = record.get("route_explanation")
        hitl_view = self._hitl_view(record)
        onboarding = self._onboarding_state(summary.run_id)
        return RunDetailResponse(
            run=summary,
            research=research,
            phases=self._phases(research, record),
            security=SecurityState(
                secret_vault=(
                    "configured_not_verified"
                    if self._settings.secret_vault_key is not None
                    else "not_configured"
                ),
                owner_only_storage=("verified_owner_only" if owner_only else "verification_failed"),
                operational_state_storage="sqlite_not_app_encrypted",
                live_vendor_email=(
                    "enabled" if self._settings.allow_live_vendor_email else "disabled"
                ),
                live_browser=(
                    "enabled"
                    if getattr(self._settings, "allow_live_browser", False)
                    else "disabled"
                ),
                external_actions=bool(record.get("external_actions", False)),
                notes=[
                    "API responses exclude provider sessions and raw audit payloads.",
                    "Vault values and provider capability URLs are never exposed by this API.",
                    (
                        "Canonical run state and effect receipts use ordinary SQLite; they are "
                        "not application-layer encrypted. Owner-only permissions are reported "
                        "separately."
                    ),
                    "Reusable credential payloads are separately Fernet-encrypted in the vault.",
                ],
            ),
            route_decision=(
                RouteDecisionView(
                    route=summary.access_route or "unknown",
                    reason_code=str(route_reason_code),
                    explanation=str(route_explanation),
                    is_final=summary.status != "researching",
                )
                if route_reason_code is not None and route_explanation is not None
                else None
            ),
            missing_fields=[str(item) for item in record.get("missing_fields", [])],
            provider_states=self._provider_states(),
            hitl_request=hitl_view,
            browser=self._browser_ui(record, hitl_view),
            primary_action=self._primary_action(record, summary),
            # Additive: absent for a legacy run, populated for a run the
            # onboarding phase machine has committed a boundary for.
            onboarding=onboarding,
            autonomy=self._autonomy_view(summary.run_id),
            controls=(
                None
                if onboarding is None
                else self._onboarding_controls(summary.run_id, onboarding)
            ),
        )

    def _create_sync(
        self,
        operation: OperationsRequest,
        idempotency_key: str | None,
        execution_mode: Literal["plan_only", "execute_when_configured"],
        browser_login: Mapping[str, SecretStr] | None = None,
        selection: ModelSelection | None = None,
    ) -> RunDetailResponse:
        record = self._service.create_run(
            operation,
            idempotency_key=idempotency_key,
            execution_mode=execution_mode,
            browser_login=browser_login,
            selection=selection,
        )
        return self._detail(self._summary(record))

    def _list_sync(self, *, limit: int, offset: int) -> RunListResponse:
        records, total = self._service.list_runs(limit=limit, offset=offset)
        items = [self._summary(record) for record in records]
        return RunListResponse(items=items, total=total, limit=limit, offset=offset)

    def _get_sync(self, run_id: str) -> RunDetailResponse:
        record = self._service.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        return self._detail(self._summary(record))

    def _timeline_sync(self, run_id: str) -> TimelineResponse:
        record = self._service.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        raw_events = self._service.get_timeline(run_id)
        items = [
            self._timeline_event(onboarding_timeline_event(event, durable=record))
            for event in raw_events
        ]
        window = self._settings.onboarding_progress_window
        progress = [
            RunProgressEventView(
                step_index=event["step_index"],
                stage=event["stage"],
                elapsed_ms=event["elapsed_ms"],
                onboarding_phase=event["phase"],
                recorded_at=event["recorded_at"],
            )
            for event in self._service.get_progress_events(run_id, limit=window)
        ]
        decisions = [
            RunDecisionView(
                step_index=decision["step_index"],
                onboarding_phase=decision["phase"],
                decision=decision["decision"],
                reason_code=decision["reason_code"],
                candidate_label=decision["candidate_label"],
                action=decision["action"],
                target_host=decision["target_host"],
                reason=decision["reason_text"],
                reason_withheld=bool(decision["reason_withheld"]),
                recorded_at=decision["recorded_at"],
            )
            for decision in self._service.get_step_decisions(run_id, limit=window)
        ]
        return TimelineResponse(
            run_id=run_id,
            items=items,
            progress=progress,
            decisions=decisions,
            citations=self._citations(run_id, record, raw_events),
            decision_model=record.get("decision_model") or None,
            decision_effort=record.get("decision_effort") or None,
        )

    def _citations(
        self,
        run_id: str,
        record: Mapping[str, Any],
        raw_events: Sequence[Mapping[str, Any]],
    ) -> list[RunCitationView]:
        """Every source this run already earned, deduplicated, in a stable order.

        Three origins, all of them already fetched and host-policy validated:
        the research's operational URL claims (each of which names the page it
        was read on), the evidence pages the research read, and the signup
        agent's own audit events whose payload detail is a URL.

        Nothing is fetched here and no URL is constructed. A value that does not
        survive :class:`RunCitationView`'s own HTTPS validator is dropped rather
        than repaired: a citation that needed fixing is not a citation.
        """

        del run_id
        seen: set[tuple[str, str]] = set()
        citations: list[RunCitationView] = []

        def add(kind: str, url: object, source_url: object = None) -> None:
            if not isinstance(url, str) or not url:
                return
            key = (kind, url)
            if key in seen:
                return
            try:
                citation = RunCitationView(
                    kind=kind,
                    url=url,
                    source_url=source_url if isinstance(source_url, str) and source_url else None,
                )
            except ValidationError:
                return
            seen.add(key)
            citations.append(citation)

        research = record.get("operational_research")
        if isinstance(research, Mapping):
            for claim in research.get("operational_url_claims") or ():
                if isinstance(claim, Mapping):
                    add(
                        str(claim.get("field") or "claim"),
                        claim.get("url"),
                        claim.get("source_url"),
                    )
            for url in research.get("evidence_urls") or ():
                add("evidence", url)
        for event in raw_events:
            event_type = str(event.get("event_type") or "")
            if not event_type.startswith("onboarding_signup_"):
                continue
            payload = event.get("payload")
            if isinstance(payload, Mapping):
                add(event_type.removeprefix("onboarding_"), payload.get("detail"))
        return citations

    @staticmethod
    def _timeline_event(projected: ProjectedTimelineEvent) -> TimelineEvent:
        """Compose one timeline event: durable attribution plus a static summary.

        The projector supplies the correlation and detail objects from durable
        columns; the summary comes from the static allow-list keyed by event type.
        An event type the allow-list does not know degrades to the generic
        run-updated projection instead of carrying anything from its row.
        """

        known = projected.event_type in _EVENT_SUMMARIES
        return TimelineEvent(
            event_id=projected.event_id,
            event_type=projected.event_type if known else _GENERIC_EVENT_TYPE,
            summary=_EVENT_SUMMARIES.get(projected.event_type, _GENERIC_EVENT_SUMMARY),
            status=projected.status,
            created_at=projected.created_at,
            correlation=_timeline_model(TimelineCorrelation, projected.correlation),
            detail=_timeline_model(TimelineDetail, projected.detail),
        )

    def _storage_permissions_are_owner_only(self) -> bool:
        database_path = self._service.storage.db_path
        try:
            parent_info = database_path.parent.lstat()
            file_info = database_path.lstat()
        except OSError:
            return False
        current_user = os.getuid()
        return bool(
            stat.S_ISDIR(parent_info.st_mode)
            and not stat.S_ISLNK(parent_info.st_mode)
            and parent_info.st_uid == current_user
            and stat.S_IMODE(parent_info.st_mode) & 0o077 == 0
            and stat.S_ISREG(file_info.st_mode)
            and not stat.S_ISLNK(file_info.st_mode)
            and file_info.st_uid == current_user
            and stat.S_IMODE(file_info.st_mode) & 0o077 == 0
        )

    def _storage_is_readable(self) -> bool:
        try:
            count = self._service.storage.count_runs()
            sample = self._service.storage.list_runs(limit=1, offset=0)
        except Exception:
            return False
        return count >= len(sample)

    def _health_sync(
        self,
        *,
        browser_health: BrowserServiceHealth | None = None,
        browser_service_expected: bool = False,
    ) -> HealthResponse:
        storage_readable = self._storage_is_readable()
        storage_owner_only = self._storage_permissions_are_owner_only()
        try:
            provenance = self._service.snapshot_provenance()
        except Exception:
            snapshot = SnapshotHealth(verified=False)
            snapshot_verified = False
        else:
            snapshot = SnapshotHealth(
                verified=True,
                source_repository=provenance.source_repository,
                source_commit=provenance.source_commit,
                copied_at=provenance.copied_at,
                results_sha256=provenance.results_sha256,
                coverage_sha256=provenance.coverage_sha256,
            )
            snapshot_verified = True
        checks = [
            HealthCheck(
                name="operations_storage_read",
                status="pass" if storage_readable else "fail",
            ),
            HealthCheck(
                name="operations_storage_owner_only",
                status="pass" if storage_owner_only else "fail",
            ),
            HealthCheck(
                name="p1_snapshot_integrity",
                status="pass" if snapshot_verified else "fail",
            ),
        ]
        browser_service_healthy = bool(
            browser_health is not None
            and browser_health.state in {"ready", "capacity_exhausted"}
            and browser_health.chromium_installed
            and browser_health.context_launch_ok
            and browser_health.janitor_running
            and browser_health.capacity_total >= 1
        )
        if browser_service_expected:
            checks.append(
                HealthCheck(
                    name="browser_service_cached_readiness",
                    status="pass" if browser_service_healthy else "fail",
                )
            )
        browser_view = (
            BrowserServiceHealthView(
                state=browser_health.state,
                reason_code=browser_health.reason_code,
                version=browser_health.version,
                chromium_installed=browser_health.chromium_installed,
                context_launch_ok=browser_health.context_launch_ok,
                capacity_total=browser_health.capacity_total,
                capacity_in_use=browser_health.capacity_in_use,
                janitor_running=browser_health.janitor_running,
            )
            if browser_health is not None
            else None
        )
        return HealthResponse(
            status="healthy" if all(check.status == "pass" for check in checks) else "degraded",
            snapshot=snapshot,
            checks=checks,
            # Liveness is intentionally provider-I/O-free. A cached readiness
            # result may be projected, but only the dedicated owner-facing
            # endpoint refreshes Gmail.
            providers=self._provider_states(browser_health=browser_health),
            browser_service=browser_view,
        )

    def _search_apps_sync(self, query: str) -> AppSearchResponse:
        items = [AppSummary.model_validate(item) for item in self._service.search_apps(query)]
        return AppSearchResponse(query=query, items=items, total=len(items))

    def _list_apps_sync(self) -> AppCatalogResponse:
        items = [AppSummary.model_validate(item) for item in self._service.list_apps()]
        return AppCatalogResponse(items=items, total=len(items))

    def _get_app_research_sync(self, app_slug: str) -> AppResearchResponse:
        recipe = get_app_recipe(app_slug)
        if recipe is None:
            raise AppNotFoundError(app_slug)
        result = self._service.get_app_research(app_slug)
        if result is None:
            raise AppNotFoundError(app_slug)
        summary, _snapshot_research = result
        # Runtime capabilities must come from the reviewed recipe, not from a
        # broader evidence snapshot.
        research = recipe_to_operational_research(recipe)
        # This stays an offline read. A recipe-owned signup URL is "reviewed";
        # otherwise the route is resolved by the signup research agent when the
        # run starts, so nothing here makes a network call.
        signup_source: Literal["reviewed", "runtime_research", "unavailable"] = "unavailable"
        if research.signup_url is not None:
            signup_source = "reviewed"
        elif recipe.browser is not None:
            # No route is known YET, and that is not a reason to refuse. The run
            # researches the route from the app's own site when it starts, so the
            # honest answer here is "this app can be signed up for, and where is
            # decided at run time" rather than a disabled control.
            signup_source = "runtime_research"
        provenance = self._service.snapshot_provenance()
        return AppResearchResponse(
            app=AppSummary.model_validate(summary),
            research=research,
            signup_source=signup_source,
            signup_evidence_url=None,
            provenance=SnapshotHealth(
                verified=True,
                source_repository=provenance.source_repository,
                source_commit=provenance.source_commit,
                copied_at=provenance.copied_at,
                results_sha256=provenance.results_sha256,
                coverage_sha256=provenance.coverage_sha256,
            ),
        )

    async def get_model_catalog(self) -> ModelCatalogResponse:
        """What this deployment can be asked to think with.

        Derived from settings on every call rather than cached: a key added to
        the environment and a restart is how a provider appears, and a cached
        catalog would keep denying a model the chain would now happily build.
        Reads no database and performs no provider I/O.
        """

        options = available_models(self._settings)
        default = next((option for option in options if option.is_default), None)
        return ModelCatalogResponse(
            models=[
                ModelOptionView(
                    id=option.id,
                    provider=option.provider,
                    model=option.model,
                    label=option.label,
                    description=option.description,
                    supports_effort=option.supports_effort,
                    effort_values=list(option.effort_values),
                    is_default=option.is_default,
                )
                for option in options
            ],
            default_model_id=None if default is None else default.id,
            default_effort=(
                None if default is None else (default_effort_for(self._settings, default.provider))
            )
            or None,
        )

    async def create_run(
        self,
        request: CreateRunRequest,
        *,
        idempotency_key: str | None = None,
    ) -> RunDetailResponse:
        self._require_started()
        recipe = get_app_recipe_for_name(request.app_name) or get_app_recipe(
            request.app_name.strip().casefold()
        )
        if recipe is None:
            # Canonical runs are bound to the reviewed recipe matrix. Reject an
            # unknown display name at the API boundary instead of letting a
            # KeyError escape as a misleading 500 after the operator submits.
            raise AppNotFoundError("unknown")
        # Resolve the pinned decision model BEFORE anything durable happens. An id
        # this deployment cannot serve is refused rather than quietly replaced:
        # a run record naming a model that never ran would be a lie told to the
        # operator on every subsequent page load.
        try:
            selection = resolve_selection(
                self._settings,
                model_id=request.decision_model,
                effort=request.decision_effort,
            )
        except ValueError:
            raise InvalidRequestError("body.decision_model") from None
        work_email_ref = request.company.work_email_ref or _work_email_ref_for_app(request.app_name)
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=work_email_ref,
            use_case=request.company.use_case,
            expected_volume=request.company.expected_volume,
            callback_urls=request.company.callback_urls,
        )
        operation = OperationsRequest(
            app_name=request.app_name,
            company=company,
            account_mode=request.account_mode,
            requested_scope_policy=request.requested_scope_policy,
            browser_provider=request.browser_provider,
            credential_creation_policy=request.credential_creation_policy,
            provider_setup=request.provider_setup,
            dry_run=True,
            account_creation_requested=request.account_mode == "create_account",
        )
        # Autonomous sign-in credentials (if provided) are mapped to the Browser
        # Use secure-placeholder key names and injected at session creation. The
        # raw values never enter run state, checkpoints, or logs. Reusable pairs
        # may be retained only in the encrypted account-scoped vault.
        browser_login: dict[str, SecretStr] | None = None
        if request.browser_login is not None:
            browser_login = {
                "login_email": request.browser_login.email,
                "login_password": request.browser_login.password,
            }
        # Research the signup route BEFORE the run is created, because the
        # recipe the run binds to is read during creation: an overlay installed
        # afterwards would arrive too late for this run's plan. The steps it
        # reports are buffered and written onto the run's timeline as soon as
        # the run has an id, so the operator can see what was read and where the
        # route came from.
        research_steps: list[tuple[str, str | None]] = []
        if operation.account_creation_requested:
            await self._research_signup_route(recipe, research_steps.append)
        detail = await run_in_threadpool(
            self._create_sync,
            operation,
            idempotency_key,
            request.execution_mode,
            browser_login,
            selection,
        )
        for step, step_detail in research_steps:
            self._service.storage.append_audit_event(
                run_id=detail.run.run_id,
                event_type=f"onboarding_{step}",
                # Only a URL or the app's own slug. The agent never passes page
                # text through here, so the payload stays projectable.
                payload={"detail": step_detail} if step_detail else {},
            )
        return detail

    @staticmethod
    def _buffer_step(
        on_step: Callable[[tuple[str, str | None]], object],
    ) -> ProgressReporter:
        """Adapt the agent's keyword-only reporter onto a plain list append."""

        def report(step: str, *, detail: str | None = None) -> None:
            on_step((step, detail))

        return report

    async def _research_signup_route(
        self,
        recipe: AppRecipe,
        on_step: Callable[[tuple[str, str | None]], object],
    ) -> None:
        """Fill in a missing signup route from the app's own site, best-effort.

        A reviewed signup policy always wins and skips this entirely. Failure is
        silent by design: the run proceeds exactly as it did before research
        existed, which is to pause at ``signup_policy_absent`` rather than to
        surface a research error the operator cannot act on.
        """

        browser = recipe.browser
        if browser is None or browser.signup is not None:
            return
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=5.0), follow_redirects=False
            ) as client:
                finding = await research_signup_route(
                    recipe=recipe,
                    fetcher_factory=lambda policy: OfficialEvidenceFetcher(client, policy),
                    on_progress=self._buffer_step(on_step),
                )
            if finding is not None:
                install_signup_finding(recipe, finding)
        except (SignupOverlayRefused, httpx.HTTPError, ValueError, OSError) as error:
            LOGGER.info(
                "signup research for %s produced no usable route: %r", recipe.app_slug, error
            )

    def _submit_credentials_sync(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse:
        record = self._service.storage.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        work_email_ref = request.company.work_email_ref
        if work_email_ref is None:
            stored_request = record.get("request")
            stored_company = (
                stored_request.get("company") if isinstance(stored_request, Mapping) else None
            )
            stored_ref = (
                stored_company.get("work_email_ref")
                if isinstance(stored_company, Mapping)
                else None
            )
            if isinstance(stored_ref, str):
                work_email_ref = stored_ref
            else:
                work_email_ref = _work_email_ref_for_app(
                    str(record.get("app_name") or "app"),
                    app_slug=(str(record["app_slug"]) if record.get("app_slug") else None),
                )
        company = CompanyProfile(
            legal_name=request.company.legal_name,
            website=request.company.website,
            work_email_ref=work_email_ref,
            use_case=request.company.use_case,
            expected_volume=request.company.expected_volume,
            callback_urls=request.company.callback_urls,
        )
        try:
            record = self._service.submit_owner_credentials(
                run_id,
                company=company,
                fields=dict(request.credentials),
            )
        except KeyError:
            raise RunNotFoundError(run_id) from None
        return self._detail(self._summary(record))

    async def submit_credentials(
        self,
        run_id: str,
        request: CredentialSubmissionRequest,
    ) -> RunDetailResponse:
        self._require_started()
        return await run_in_threadpool(self._submit_credentials_sync, run_id, request)

    async def list_runs(self, *, limit: int, offset: int) -> RunListResponse:
        self._require_started()
        return await run_in_threadpool(self._list_sync, limit=limit, offset=offset)

    async def get_run(self, run_id: str) -> RunDetailResponse:
        self._require_started()
        return await run_in_threadpool(self._get_sync, run_id)

    async def get_timeline(self, run_id: str) -> TimelineResponse:
        self._require_started()
        return await run_in_threadpool(self._timeline_sync, run_id)

    def _resume_onboarding_phase(self, run_id: str) -> ActionReceipt | None:
        """Continue a paused onboarding run through its phase machine.

        ``None`` means this run is not an onboarding run standing at a waiting
        phase, and the caller keeps the LangGraph resume it has always used. That
        is the whole of the routing decision: the phase the console reads
        ``can_resume`` from (:data:`WAITING_PHASES`) is the phase this path serves,
        so the control the operator sees and the committer that answers it can
        never disagree.

        The commit is :meth:`OnboardingRunControlService.resume_from_pause`, reached
        through the run-service boundary — the same method the autonomous takeover
        commits through, which is what makes an owner signal and a takeover one
        mechanism rather than two (Requirements 1.5, 1.9, 9.3, 9.5).

        Two refusals, both decided before anything is written. A phase the table
        gives no re-entry (``paused`` fans out only to ``research`` and
        ``cancelled``, and a run with no recorded phase at pause has nowhere to go)
        is the existing 409 carrying the control service's own reason code. A
        boundary that is already committed is a replay: nothing is written a second
        time and the receipt says so (Requirement 1.10).
        """

        state = self._onboarding_state(run_id)
        if state is None or state.phase not in WAITING_PHASES:
            return None
        outcome = self._service.resume_onboarding_from_pause(run_id)
        if not outcome.accepted:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=tuple(sorted(WAITING_PHASES)),
                error="phase_unavailable",
                message="This run cannot re-enter the phase it recorded when it paused.",
                reason_code=outcome.reason_code,
            )
        projected = self._onboarding_state(run_id) or state
        if not outcome.committed:
            return ActionReceipt(
                run_id=run_id,
                action="resume",
                status="no_change",
                detail=(
                    "This run was already continued from its pause "
                    f"({_PHASE_REPLAY_NOOP}); nothing was committed twice."
                ),
                onboarding=projected,
            )
        return ActionReceipt(
            run_id=run_id,
            action="resume",
            status="accepted",
            detail=(
                f"Re-entered {outcome.resumed_phase} on the same browser session "
                f"({outcome.reason_code}); the run continues from there."
            ),
            onboarding=projected,
        )

    def _resume_sync(
        self,
        run_id: str,
        *,
        browser_login: Mapping[str, SecretStr] | None = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        if signal == "completed" and not browser_login:
            # The owner's continuation of a paused onboarding run is committed by
            # the phase machine, not by the LangGraph resume. Both conjuncts are
            # load-bearing: ``cancelled`` ends a run rather than continuing it, and
            # a credential-bearing resume is a gate this waiting phase does not
            # represent — routing either one here would drop what the caller asked
            # for. Every other run, onboarding or not, keeps the path it had.
            onboarding_receipt = self._resume_onboarding_phase(run_id)
            if onboarding_receipt is not None:
                return onboarding_receipt
        try:
            record = self._service.resume_run(run_id, signal=signal, browser_login=browser_login)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        except CredentialSubmissionError:
            # Run is not waiting for human action, or the workflow is unconfigured.
            return ActionReceipt(
                run_id=run_id,
                action="resume",
                status="no_change",
                detail="Run is not waiting for a human action.",
            )
        status = str(record.get("status"))
        injected_fields = frozenset(browser_login or {})
        logged_in = bool({"login_email", "login_password"} & injected_fields)
        verification_submitted = bool({"login_otp", "login_verification_url"} & injected_fields)
        detail = (
            (
                "Logged in autonomously with the submitted credentials; the credential page "
                "is ready."
                if logged_in
                else "Submitted the one-time email verification; the credential page is ready."
                if verification_submitted
                else "Resumed on the same browser session; the credential page is ready."
            )
            if status == "browser_running"
            else "Resumed on the same browser session; another human action is required."
            if status == "waiting_for_hitl"
            else f"Run resumed (status: {status})."
        )
        return ActionReceipt(run_id=run_id, action="resume", status="accepted", detail=detail)

    async def resume(
        self,
        run_id: str,
        *,
        browser_login: BrowserLoginInput | None = None,
        browser_verification: BrowserVerificationInput | None = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        detail = await self.get_run(run_id)
        if detail.run.state_engine != "canonical_v1":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("canonical_v1",),
                error="phase_unavailable",
            )
        if detail.run.execution_mode == "plan_only" or detail.run.status != "waiting_for_hitl":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("waiting_for_hitl",),
                error="phase_unavailable",
                message="Resume is available only while a canonical run is waiting for HITL.",
            )
        if browser_verification is not None and (
            detail.hitl_request is None or detail.hitl_request.action_type != "email_otp"
        ):
            raise PhaseUnavailableError(
                run_id=run_id,
                action="resume",
                available_in=("email_otp",),
                error="phase_unavailable",
                message="Email verification can be submitted only at its matching gate.",
            )
        # Map owner input onto the provider-neutral secret boundary names.
        # SecretStr keeps values wrapped until the core service resolves them in
        # memory for the single resume call.
        login_map: dict[str, SecretStr] | None = None
        if browser_login is not None:
            login_map = {
                "login_email": browser_login.email,
                "login_password": browser_login.password,
            }
        elif browser_verification is not None:
            if browser_verification.code is not None:
                login_map = {"login_otp": browser_verification.code}
            elif browser_verification.url is not None:
                login_map = {
                    "login_verification_url": browser_verification.url,
                }
        return await run_in_threadpool(
            self._resume_sync, run_id, browser_login=login_map, signal=signal
        )

    def _live_view_sync(self, run_id: str) -> LiveViewResponse:
        record = self._service.get_run(run_id)
        if record is None:
            raise RunNotFoundError(run_id)
        provider = record.get("browser_provider", "browser_use")
        if self._secret_capture_boundary_entered(record):
            # Requirement 18.8: once a capture surface has been reached the live
            # view is closed rather than masked, so no signed URL and no frame of
            # a credential page can cross this boundary.
            return LiveViewResponse(
                run_id=run_id,
                provider=provider,
                available=False,
                mode="unavailable",
                interaction_available=False,
                reason_code="secret_capture_boundary_entered",
            )
        # Browser Use keeps its exact existing behavior: a signed hosted URL the
        # owner can interact with directly.
        live_url = self._service.get_browser_live_url(run_id)
        if live_url is not None:
            return LiveViewResponse(
                run_id=run_id,
                provider="browser_use",
                available=True,
                mode="hosted_url",
                live_url=live_url,
                interaction_available=True,
                reason_code="hosted_session_live",
            )
        # Playwright grants are minted for both autonomous viewing and HITL. The
        # browser service signs the capability: autonomous grants are view-only;
        # a live HITL pause may receive control. The private URL remains transient.
        grant_getter = getattr(self._service, "get_browser_interactive_grant", None)
        grant = grant_getter(run_id) if callable(grant_getter) else None
        if provider == "playwright" and grant is not None:
            _, interactive_url, _expires_at, control_allowed = grant
            return LiveViewResponse(
                run_id=run_id,
                provider="playwright",
                available=True,
                mode="interactive_remote",
                interactive_url=interactive_url,
                interaction_available=control_allowed,
                reason_code=(
                    "interactive_control_live" if control_allowed else "interactive_view_only_live"
                ),
            )
        # Self-hosted Playwright has no hosted URL; the client polls masked frames.
        # Frames are viewable but not drivable, so interaction is not advertised.
        shot = self._service.get_browser_screenshot(run_id)
        if shot is not None:
            _, captured_at = shot
            return LiveViewResponse(
                run_id=run_id,
                provider="playwright",
                available=True,
                mode="screenshot",
                screenshot_url=f"/api/runs/{run_id}/live-view/screenshot",
                captured_at=captured_at,
                interaction_available=False,
                reason_code="screenshot_frames_available",
            )
        return LiveViewResponse(
            run_id=run_id,
            # Report the configured backend truthfully even with no live session.
            provider=provider,
            available=False,
            mode="unavailable",
            interaction_available=False,
            reason_code="no_active_browser_session",
        )

    async def get_live_view(self, run_id: str) -> LiveViewResponse:
        self._require_started()
        return await run_in_threadpool(self._live_view_sync, run_id)

    def _live_screenshot_sync(self, run_id: str) -> tuple[bytes, str]:
        if self._service.get_run(run_id) is None:
            raise RunNotFoundError(run_id)
        shot = self._service.get_browser_screenshot(run_id)
        if shot is None:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="live_view_screenshot",
                available_in=("phase_5",),
                error="configuration_required",
            )
        return shot

    async def get_live_screenshot(self, run_id: str) -> tuple[bytes, str]:
        """Return the newest masked PNG frame for this run's browser session."""

        self._require_started()
        return await run_in_threadpool(self._live_screenshot_sync, run_id)

    async def poll_email(self, run_id: str) -> ActionReceipt:
        detail = await self.get_run(run_id)
        verification_wait = bool(
            detail.run.status == "waiting_for_hitl"
            and detail.hitl_request is not None
            and detail.hitl_request.action_type == "email_otp"
        )
        outreach_wait = bool(
            detail.run.route_kind == "gated"
            and detail.run.status
            in {
                "outreach_sent",
                "waiting_for_reply",
            }
        )
        if not verification_wait and not outreach_wait:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("waiting_for_hitl", "outreach_sent", "waiting_for_reply"),
                error="phase_unavailable",
                message="Email checking is available for a pending verification or outreach reply.",
            )
        if verification_wait:
            if not (
                self._settings.composio_gmail_api_key
                and self._settings.composio_gmail_connected_account_id
            ):
                raise PhaseUnavailableError(
                    run_id=run_id,
                    action="poll_email",
                    available_in=("waiting_for_hitl",),
                    error="configuration_required",
                    message="Gmail verification is not configured.",
                )
            return await run_in_threadpool(self._poll_verification_sync, run_id)
        if detail.run.route_kind != "gated" or detail.run.status not in {
            "outreach_sent",
            "waiting_for_reply",
        }:
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("outreach_sent", "waiting_for_reply"),
                error="phase_unavailable",
                message="Email polling is available only after controlled outreach.",
            )
        if not (
            self._settings.composio_gmail_api_key
            and self._settings.composio_gmail_connected_account_id
            and self._settings.outreach_recipient_override
        ):
            raise PhaseUnavailableError(
                run_id=run_id,
                action="poll_email",
                available_in=("phase_4",),
                error="configuration_required",
            )
        return await run_in_threadpool(self._poll_email_sync, run_id)

    def _poll_verification_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.resolve_email_otp(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        if record is None:
            return ActionReceipt(
                run_id=run_id,
                action="poll_email",
                status="no_change",
                detail="No fresh, correctly addressed verification email was found yet.",
            )
        return ActionReceipt(
            run_id=run_id,
            action="poll_email",
            status="accepted",
            detail="Verification email accepted and the same browser session resumed.",
        )

    def _poll_email_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.poll_email(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        except CredentialSubmissionError as exc:
            return ActionReceipt(
                run_id=run_id,
                action="poll_email",
                status="no_change",
                detail=f"No reply action taken ({exc.reason_code.replace('_', ' ')}).",
            )
        status = str(record.get("status"))
        reply_class = str(record.get("latest_reply_class") or "no_reply")
        detail = (
            "Provider reply received and classified as "
            f"{reply_class.replace('_', ' ')}; run status: {status.replace('_', ' ')}."
        )
        return ActionReceipt(
            run_id=run_id,
            action="poll_email",
            status="no_change" if reply_class == "no_reply" else "accepted",
            detail=detail,
        )

    @staticmethod
    def _managed_response(payload: Mapping[str, object]) -> ManagedConnectionResponse:
        run = payload.get("run")
        if not isinstance(run, dict):
            raise RuntimeError("managed connection response is missing its run")
        return ManagedConnectionResponse(
            run=LocalRunService._summary(run),
            connection_request_id=str(payload.get("connection_request_id") or ""),
            state=payload.get("state", "pending"),  # type: ignore[arg-type]
            redirect_url=(
                str(payload["redirect_url"]) if payload.get("redirect_url") is not None else None
            ),
            replayed=bool(payload.get("replayed", False)),
        )

    def _connect_managed_sync(self, run_id: str) -> ManagedConnectionResponse:
        try:
            return self._managed_response(self._service.connect_managed_run(run_id))
        except KeyError:
            raise RunNotFoundError(run_id) from None

    async def connect_managed(self, run_id: str) -> ManagedConnectionResponse:
        self._require_started()
        return await run_in_threadpool(self._connect_managed_sync, run_id)

    def _poll_managed_sync(self, run_id: str) -> ManagedConnectionResponse:
        try:
            return self._managed_response(self._service.poll_managed_connection(run_id))
        except KeyError:
            raise RunNotFoundError(run_id) from None

    async def poll_managed_connection(self, run_id: str) -> ManagedConnectionResponse:
        self._require_started()
        return await run_in_threadpool(self._poll_managed_sync, run_id)

    def _send_gated_outreach_sync(self, run_id: str) -> ActionReceipt:
        try:
            record = self._service.send_gated_outreach(run_id)
        except KeyError:
            raise RunNotFoundError(run_id) from None
        return ActionReceipt(
            run_id=run_id,
            action="send_outreach",
            status="accepted",
            detail=(
                "Controlled-sink outreach was recorded; run status: "
                f"{str(record.get('status') or 'unknown').replace('_', ' ')}."
            ),
        )

    async def send_gated_outreach(self, run_id: str) -> ActionReceipt:
        self._require_started()
        return await run_in_threadpool(self._send_gated_outreach_sync, run_id)

    async def retry(self, run_id: str, capability: str) -> ActionReceipt:
        detail = await self.get_run(run_id)
        if detail.run.execution_mode == "plan_only":
            raise PhaseUnavailableError(
                run_id=run_id,
                action="retry",
                available_in=("execute_when_configured",),
                error="phase_unavailable",
                message="Plan-only runs are immutable.",
            )
        if capability == "browser":
            if detail.run.route_kind != "playwright" or detail.run.browser_provider != "playwright":
                raise PhaseUnavailableError(
                    run_id=run_id,
                    action="retry",
                    available_in=("failed_playwright_run",),
                    error="phase_unavailable",
                )
            if not browser_configuration_state(self._settings, "playwright"):
                return ActionReceipt(
                    run_id=run_id,
                    action="retry",
                    status="configuration_required",
                    detail="Required provider configuration or policy opt-in is missing.",
                )
            try:
                retried = await run_in_threadpool(self._service.retry_browser_run, run_id)
            except KeyError:
                raise RunNotFoundError(run_id) from None
            return ActionReceipt(
                run_id=run_id,
                action="retry",
                status="accepted",
                detail=(
                    "A new Playwright attempt started with the run's approved account policy "
                    f"(attempt {int(retried.get('attempt', 0) or 0)})."
                ),
            )
        requirements = {
            "research": bool(
                self._settings.perplexity_api_key and self._settings.google_genai_api_key
            ),
            # Provider-aware retry eligibility (no Browser Use key for Playwright).
            "browser": browser_configuration_state(
                self._settings,
                detail.run.browser_provider,
            ),
            "email": bool(
                self._settings.composio_gmail_api_key
                and self._settings.composio_gmail_connected_account_id
                and self._settings.allow_live_vendor_email
            ),
            "validation": self._settings.secret_vault_key is not None,
        }
        if not requirements.get(capability, False):
            return ActionReceipt(
                run_id=run_id,
                action="retry",
                status="configuration_required",
                detail="Required provider configuration or policy opt-in is missing.",
            )
        return ActionReceipt(
            run_id=run_id,
            action="retry",
            status="no_change",
            detail="No retryable failed operation is recorded for this run.",
        )

    async def search_apps(self, query: str) -> AppSearchResponse:
        self._require_started()
        return await run_in_threadpool(self._search_apps_sync, query)

    async def list_apps(self) -> AppCatalogResponse:
        self._require_started()
        return await run_in_threadpool(self._list_apps_sync)

    async def get_app_research(self, app_slug: str) -> AppResearchResponse:
        self._require_started()
        return await run_in_threadpool(self._get_app_research_sync, app_slug)

    def _signup_readiness_sync(self) -> ProviderState:
        gmail_preflight = self._cached_gmail_preflight(refresh=True)
        return next(
            state
            for state in self._provider_states(gmail_preflight=gmail_preflight)
            if state.provider == "gmail"
        )

    async def signup_readiness(self) -> ProviderState:
        self._require_started()
        return await run_in_threadpool(self._signup_readiness_sync)

    async def get_output(self, run_id: str) -> RunOutputResponse:
        await self.get_run(run_id)
        output = await run_in_threadpool(self._service.get_output, run_id)
        if output:
            return RunOutputResponse(run_id=run_id, integrator_bundle=output)  # type: ignore[arg-type]
        raise PhaseUnavailableError(
            run_id=run_id,
            action="output",
            available_in=("output",),
        )

    def _expects_browser_service_health(self) -> bool:
        settings = self._settings
        return bool(
            settings.allow_live_browser
            and not settings.playwright_in_process_sandbox
            and browser_configuration_state(settings, "playwright")
        )

    async def _cached_browser_service_health(self) -> BrowserServiceHealth | None:
        """Fetch the worker's cache-only endpoint within the API health budget."""

        if not self._expects_browser_service_health():
            return None
        settings = self._settings
        if (
            not settings.browser_service_url
            or settings.browser_service_token is None
            or settings.browser_session_capability_key is None
        ):
            return BrowserServiceHealth(
                state="not_configured",
                reason_code="browser_service_configuration_required",
            )
        client = BrowserServiceClient(
            base_url=settings.browser_service_url,
            token=settings.browser_service_token,
            owner=settings.browser_service_owner,
            capability_key=settings.browser_session_capability_key,
            # Operations may run for minutes; health must never inherit that
            # budget. BrowserServiceClient.health applies its own <=5s cap.
            timeout_seconds=2.0,
        )
        return await client.health(timeout_seconds=2.0)

    async def health(self) -> HealthResponse:
        self._require_started()
        browser_service_expected = self._expects_browser_service_health()
        browser_health = await self._cached_browser_service_health()
        return await run_in_threadpool(
            self._health_sync,
            browser_health=browser_health,
            browser_service_expected=browser_service_expected,
        )
