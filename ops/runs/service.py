"""Application service for durable, sanitized operations-ledger runs.

This module is the single application boundary shared by HTTP, CLI, LangGraph,
and internal debugging surfaces. Creating a run is intentionally side-effect
free: it verifies the immutable P1 snapshot, builds a conservative research
baseline, records the deterministic route, and leaves provider execution to
explicit retry/resume actions guarded by runtime policy.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import httpx
from pydantic import SecretStr

# The backend contract, not a concrete backend: with Browser Use removed the
# only implementation is the Playwright harness, and these call sites only ever
# needed the protocol. Aliased so the annotations below read unchanged.
from ops.browser.provider import BrowserProvider as BrowserWorker
from ops.core.config import Settings
from ops.core.effect_ledger import SQLiteEffectStore
from ops.core.inference import DecisionBudget, build_json_inference
from ops.core.model_catalog import ModelSelection
from ops.core.models import (
    CapabilityAvailability,
    CompanyProfile,
    OperationalResearch,
    OperationsRequest,
)
from ops.core.secret_store import SQLiteSecretStore
from ops.core.state import (
    BrowserProvider,
    RunStatus,
)
from ops.core.storage import OperationsStorage, OperationsUnitOfWork
from ops.credentials.validator import (
    CredentialValidationResult,
    CredentialValidator,
    PolicyBoundCredentialValidator,
)
from ops.email.verification import (
    VerificationDecision,
    VerificationPurpose,
)
from ops.gmail.worker import GmailSignupPreflight, GmailWorker
from ops.onboarding.composition import SettingsRunPlanner
from ops.onboarding.driver import (
    RunPlanner,
    RunPlanValidator,
    SQLitePhaseHistoryStore,
)
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.planner.adherence import AdherenceOutcome, RouteAdherenceMonitor
from ops.planner.decide import PlanOutcome
from ops.planner.plan import RunPlan
from ops.planner.store import SQLiteRunPlanStore, plan_from_row
from ops.planner.validator import (
    CREDENTIAL_SURFACE_ORDINAL,
    PLAN_REFUSAL_REASON_CODE,
    PlanRefusal,
    validate_plan,
)
from ops.providers.composio_capability import ComposioCapabilityPreflight, ComposioCapabilityReport
from ops.providers.composio_managed_auth import (
    ComposioManagedAuthProvider,
    managed_auth_configuration_is_valid,
)
from ops.providers.errors import (
    ConfigurationRequiredError,
)
from ops.recipes.app_recipes import (
    AppRecipe,
    get_app_recipe,
    get_app_validation_policy,
    load_app_recipe_catalog,
)
from ops.research.cache import SqliteResearchCache
from ops.research.operational_research import (
    OfficialEvidenceFetcher,
    OperationalResearchEnricher,
    PerplexitySearchDiscovery,
    ResearchEnricher,
    ResearchEnrichmentOutcome,
    StructuredExtractor,
)
from ops.research.p1_adapter import (
    DEFAULT_P1_ROOT,
    P1AppRecord,
    P1LookupFound,
    P1OperationalAdapter,
    P1SnapshotProvenance,
    load_verified_snapshot,
)

# Explicitly re-exported (the ``X as X`` form): ``api.app`` and ``api.service``
# import these from ``ops.runs.service``, which remains their public home, and the
# type checker forbids implicit re-export.
from ops.runs.advance import _AUTO_ADVANCEABLE_GATES, RunAdvanceService  # noqa: F401
from ops.runs.browser_execution import RunBrowserExecutionService

# Imported for use below AND deliberately re-exported: tests and debugging
# surfaces import these internals from ``ops.runs.service``, which stays their
# stable home even though the implementations now live in a leaf module. The
# noqa markers are uniform so this block does not need editing every time
# another cluster moves out.
from ops.runs.creation import RunCreationService
from ops.runs.credentials import (  # noqa: F401
    RunCredentialService,
    _CredentialOutcome,
)
from ops.runs.email import RunEmailService
from ops.runs.errors import CredentialSubmissionError as CredentialSubmissionError
from ops.runs.errors import IdempotencyConflictError as IdempotencyConflictError
from ops.runs.errors import InvalidIdempotencyKeyError as InvalidIdempotencyKeyError
from ops.runs.errors import RunConflictError as RunConflictError
from ops.runs.idempotency import (  # noqa: F401
    IDEMPOTENCY_KEY_PATTERN,
    _legacy_request_fingerprint,
    _legacy_request_fingerprints,
    _request_fingerprint,
)
from ops.runs.idempotency import validate_idempotency_key as validate_idempotency_key
from ops.runs.live_view import RunLiveViewService
from ops.runs.liveness import RunLivenessService
from ops.runs.login_secrets import RunLoginSecretService
from ops.runs.projections import (  # noqa: F401
    _LOGICAL_EXECUTION_MODE,
    _PERSISTED_EXECUTION_MODE,
    _PUBLIC_RUN_FIELDS,
    _TERMINAL_BROWSER_STATUSES,
    _app_projection,
    _browser_result_reason,
    _capability_reason_code,
    _clean_credential_value,
    _missing_operational_fields,
    _parse_timestamp,
    _public_run,
    _sanitized_app_list,
    _slugify,
    _strip_quoted_reply,
    decode_stored_payload,
)
from ops.runs.queries import RunQueryService
from ops.runs.reconciliation import RunReconciliationService
from ops.runs.resume import OnboardingRunControlService, ResumeOutcome, RunResumeService
from ops.runs.state_projection import (  # noqa: F401
    _CREATE_PROJECTION_CHAINS,
    RunProjectionService,
    _validate_created_projection,
)
from ops.runs.takeover import ClearanceProbe, RunTakeoverService
from ops.runs.verification import (  # noqa: F401
    RunVerificationService,
    _verification_backoff,
    _VerificationBinding,
)
from ops.workflow.canonical_runtime import CanonicalRuntime
from ops.workflow.graph import (
    DurableOperationsWorkflow,
    WorkflowDependencies,
)
from ops.you.research import (
    CompositeEvidenceDiscovery,
    FallbackEvidenceContentFetcher,
    GuardedHTTPEvidenceFetcher,
    LegacyDiscoveryAdapter,
    ResearchHostPolicy,
    YouContentsFetcher,
    YouResearchFallback,
    YouSearchDiscovery,
)

LOGGER = logging.getLogger("composio_ops.run_service")

_GATED_OUTREACH_ROUTES = frozenset({"approval_required", "partner_gated"})


class _YouComWiringMarker:
    """Display-only marker so the wiring audit can show "You.com is
    configured" without fabricating a reference to internal pipeline
    objects that only exist inside ``_build_research_enricher``'s closures."""


class CredentialCapturePort(Protocol):
    """Injectable deterministic credential capture returning vault references only."""

    async def capture(self, *, app_slug: str, app_name: str) -> dict[str, str]: ...


class CredentialValidationPort(Protocol):
    """Injectable read-only credential validation over stored vault references."""

    async def validate(
        self, *, app_slug: str, credential_refs: dict[str, str]
    ) -> CredentialValidationResult: ...


@dataclass(frozen=True, slots=True)
class _RunPlanningBinding:
    """One memoized plan store, planner, validator, and adherence monitor."""

    plans: SQLiteRunPlanStore
    planner: RunPlanner
    plan_validator: RunPlanValidator
    adherence: RouteAdherenceMonitor


class RunService:
    """Coordinate verified P1 lookup, routing, and sanitized persistence."""

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        p1_adapter: P1OperationalAdapter | None = None,
        settings: Settings | None = None,
        workflow: DurableOperationsWorkflow | None = None,
        research_enricher: ResearchEnricher | None = None,
        capability_preflight: ComposioCapabilityPreflight | None = None,
        credential_capturer: CredentialCapturePort | None = None,
        credential_validator: CredentialValidationPort | None = None,
        managed_auth_provider: ComposioManagedAuthProvider | None = None,
    ) -> None:
        self.storage = storage
        self.p1_adapter = p1_adapter or P1OperationalAdapter()
        self._settings = settings
        self._workflow = workflow
        # Optional, injected one-probe enrichment boundary. When absent (the
        # default), run creation performs no enrichment and stays byte-identical
        # to the plan-only baseline; the enricher never performs a browser,
        # Gmail, or credential side effect.
        self._enricher = research_enricher
        # Optional Composio capability preflight. It gates gated outreach and is
        # read-only. When absent, a gated execute_when_configured run fails closed
        # (configuration_required) rather than sending blindly.
        self._capability_preflight = capability_preflight
        # Optional credential capture + read-only validation adapters. When both
        # are present, a self-serve run that reaches the credential page captures
        # test credentials into the encrypted vault (references only), validates
        # read-only, and builds the sanitized IntegratorBundle. When absent, the
        # run truthfully stops at browser_running (M5 behavior).
        self._credential_capturer = credential_capturer
        self._credential_validator = credential_validator
        self._managed_auth_provider = managed_auth_provider
        self._run_locks: dict[str, threading.RLock] = {}
        self._run_locks_guard = threading.Lock()
        # Resources owned and closed by this service when built at startup.
        self._http_client: httpx.AsyncClient | None = None
        self._validation_http_client: httpx.AsyncClient | None = None
        # Persistent research cache shared by the You.com adapters (Search /
        # Contents / Research). The adapters manage their own SDK client
        # lifecycle per call via ``async with``; no You.com async client is
        # stored on the service (that would be unsafe across the per-enrichment
        # ``asyncio.run`` event loops). Only built when YDC_API_KEY is present.
        self._research_cache: SqliteResearchCache | None = None
        self._browser_workers: dict[BrowserProvider, BrowserWorker] = {}
        # Compatibility alias for older tests and assignment patches. Runtime
        # operations always resolve from _browser_workers using the persisted run.
        self._browser_worker: BrowserWorker | None = None
        self._gmail_worker: GmailWorker | None = None
        # Bounded per-run count of autonomous email-OTP resume attempts.
        self._otp_attempts: dict[str, int] = {}
        # Background email poller (autonomous "listen for replies").
        self._email_poller_thread: threading.Thread | None = None
        self._email_poller_stop = threading.Event()
        # Autonomous advancement: bounded per-run count of machine-resolved human
        # gates (e.g. a login form we already hold credentials for), plus its own
        # sweep thread. Kept separate from the email poller because it must run
        # even when Gmail is not configured.
        self._autonomous_advances: dict[str, int] = {}
        self._advance_thread: threading.Thread | None = None
        self._advance_stop = threading.Event()
        # The takeover sweep owns its own thread, so the service holds the instance
        # rather than a handle to it.
        self._takeover_service: RunTakeoverService | None = None
        # Asynchronous browser execution: when enabled (production live mode), a
        # self-serve browser run commits at browser_running with the live view
        # available immediately, and the bounded onboarding task runs in a
        # background thread that applies the terminal observation to the run.
        # This keeps the run creation request fast and the embedded live view /
        # HITL available for the entire duration of the autonomous task, instead
        # of blocking the request until the multi-minute task finishes.
        self._async_browser_enabled = False
        self._browser_threads: list[threading.Thread] = []
        self._secret_store: SQLiteSecretStore | None = None
        self._effect_store: SQLiteEffectStore | None = None
        self._run_planning_binding: _RunPlanningBinding | None = None
        self._route_adherence_monitor: RouteAdherenceMonitor | None = None
        # Sanitized startup wiring audit rows; never contains secrets.
        self._wiring: list[dict[str, object]] = []

    # --- extracted collaborators -------------------------------------------
    #
    # Resolved lazily on access rather than assigned in __init__ for two
    # reasons. First, each one is stateless: it holds only a reference back to
    # this service and reads storage, settings and adapters through it on every
    # call, so constructing one is free and late-assigned adapters are always
    # honored. Second, several tests build a service with
    # ``RunService.__new__`` and hand-assign only the attributes they need,
    # which never runs __init__; a collaborator assigned there would be missing.

    @property
    def _queries(self) -> RunQueryService:
        """Read-only run and catalog queries."""

        return RunQueryService(self)

    @property
    def _live_view(self) -> RunLiveViewService:
        """Ephemeral screenshot, live-URL and interactive-grant resolution."""

        return RunLiveViewService(self)

    @property
    def _reconciliation(self) -> RunReconciliationService:
        """Startup and periodic recovery of runs holding a dead browser."""

        return RunReconciliationService(self)

    @property
    def _creation(self) -> RunCreationService:
        """Run creation: verify, research, route, persist and dispatch."""

        return RunCreationService(self)

    @property
    def _canonical(self) -> CanonicalRuntime:
        """The single SQLite-backed state machine for every reviewed recipe."""

        return CanonicalRuntime(self, planning=self._planning)

    @property
    def _resume(self) -> RunResumeService:
        """HITL resume on the run's existing session and thread."""

        return RunResumeService(self)

    @property
    def _control(self) -> OnboardingRunControlService:
        """Run controls over the durable onboarding phase machine.

        The phase history is both ports it needs: the store owns the boundary
        table and the reservation table in the same file, so a control decides
        from the standing disposition of each key rather than from anything
        reconstructed on this side.

        No release port is wired here on purpose. The verbs reached through this
        boundary — resume from a waiting phase, and the pause the takeover sweep
        commits — never hand a session back (Requirement 14.2), so a release port
        would be an unused capability. Cancel and reset, which must release
        synchronously, keep their own wiring on the surface that owns that
        guarantee.
        """

        phases = SQLitePhaseHistoryStore(self.storage.db_path)
        return OnboardingRunControlService(
            storage=self.storage,
            phases=phases,
            effects=phases,
        )

    @property
    def _credentials(self) -> RunCredentialService:
        """Credential capture, read-only validation and reference-only handoff."""

        return RunCredentialService(self)

    @property
    def _browser_execution(self) -> RunBrowserExecutionService:
        """Background browser navigation, terminal application and teardown."""

        return RunBrowserExecutionService(self)

    @property
    def _login_secrets(self) -> RunLoginSecretService:
        """Browser sign-in secret transport, reuse and transient vaulting."""

        return RunLoginSecretService(self)

    @property
    def _projection(self) -> RunProjectionService:
        """Idempotent state projection and serialized status updates."""

        return RunProjectionService(self)

    @property
    def _email(self) -> RunEmailService:
        """Provider-reply polling and intake."""

        return RunEmailService(self)

    @property
    def _verification(self) -> RunVerificationService:
        """Emailed verification (code or magic link) resolution."""

        return RunVerificationService(self)

    @property
    def _advance(self) -> RunAdvanceService:
        """Autonomous continuation of machine-resolvable human gates."""

        return RunAdvanceService(self)

    @property
    def _liveness(self) -> RunLivenessService:
        """The sweep that marks a run whose loop has stopped reporting progress."""

        return RunLivenessService(
            storage=self.storage,
            phases=SQLitePhaseHistoryStore(self.storage.db_path),
            control=self._control,
            leases=SQLiteLeaseStore(self.storage.db_path),
            settings=self._settings or Settings.from_env(),
            canonical=self._canonical,
        )

    @property
    def _planning(self) -> _RunPlanningBinding:
        """The memoized pre-flight dependencies shared with canonical execution."""

        existing = cast(
            "_RunPlanningBinding | None",
            getattr(self, "_run_planning_binding", None),
        )
        if existing is None:
            settings = cast("Settings | None", getattr(self, "_settings", None))
            plans = SQLiteRunPlanStore(self.storage.db_path)
            existing = _RunPlanningBinding(
                plans=plans,
                planner=SettingsRunPlanner(settings or Settings.from_env()),
                plan_validator=validate_plan,
                adherence=RouteAdherenceMonitor(plans=plans, audit=self.storage),
            )
            self._run_planning_binding = existing
        return existing

    @property
    def plan_validator(self) -> RunPlanValidator:
        """Expose the catalog Plan_Validator through the run-service boundary."""

        return self._planning.plan_validator

    @property
    def route_adherence_monitor(self) -> RouteAdherenceMonitor:
        """Expose the plan-backed Route_Adherence_Monitor through this boundary."""

        return self._planning.adherence

    @property
    def _plan_validator(self) -> RunPlanValidator:
        """Compatibility alias for the public Plan_Validator boundary."""

        return self.plan_validator

    @property
    def _route_adherence(self) -> RouteAdherenceMonitor:
        """Compatibility alias for the public adherence-monitor boundary."""

        return self.route_adherence_monitor

    def validate_run_plan(self, *, plan: RunPlan, app_slug: str) -> PlanRefusal | None:
        """The Plan_Validator, against the catalog recipe for ``app_slug`` (R9.3).

        An app the catalog does not carry is refused rather than admitted: there is
        no reviewed recipe to validate its surfaces against.
        """

        recipe = get_app_recipe(app_slug)
        if recipe is None:
            return PlanRefusal(
                reason_code=PLAN_REFUSAL_REASON_CODE,
                detail="recipe_route_not_browser",
                ordinal=CREDENTIAL_SURFACE_ORDINAL,
            )
        return self.plan_validator(plan, recipe=recipe)

    def observe_run_surface(
        self, *, run_id: str, step_index: int, observed_url: str
    ) -> AdherenceOutcome:
        """What one observed surface authorizes for ``run_id`` (R6.1, R9.3)."""

        return self.route_adherence_monitor.observe(
            run_id=run_id, step_index=step_index, observed_url=observed_url
        )

    def replan_run_route(
        self,
        *,
        run_id: str,
        recipe: AppRecipe,
        expected_state_revision: int,
        expected_effect_identity: str | None,
    ) -> bool | None:
        """Atomically commit the run's one catalog-confined replacement plan.

        ``None`` means the observed browser operation no longer owns the run,
        ``False`` means no valid replacement can be committed, and ``True`` means
        revision 2 is already valid or was committed with the run projection.
        """

        planning = self._planning
        planned = planning.planner.plan_for(recipe=recipe, revision=2)
        outcome = (
            planned
            if isinstance(planned, PlanOutcome)
            and planned.plan.revision == 2
            and planning.plan_validator(planned.plan, recipe=recipe) is None
            else None
        )

        lock = self._run_lock(run_id)
        with lock, self.storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None:
                return None
            if (
                current.get("state_engine") != "canonical_v1"
                or current.get("browser_provider") != "playwright"
                or current.get("status") != "browser_running"
                or int(current.get("state_revision", 0) or 0) != expected_state_revision
                or current.get("effect_identity") != expected_effect_identity
            ):
                return None
            if outcome is None:
                return False
            replacement = outcome.plan

            plan_count = transaction.count_run_plans(run_id)
            active_row = transaction.read_active_run_plan(run_id)
            if plan_count == 2:
                if active_row is None:
                    return False
                try:
                    active_plan = plan_from_row(active_row)
                except (KeyError, TypeError, ValueError):
                    return False
                return active_plan == replacement
            if plan_count != 1 or active_row is None:
                return False
            try:
                active_plan = plan_from_row(active_row)
            except (KeyError, TypeError, ValueError):
                return False
            if active_plan.revision != 1:
                return False

            recorded = transaction.record_run_plan(
                run_id=run_id,
                source=replacement.source,
                app_slug=replacement.app_slug,
                catalog_id=replacement.catalog_id,
                recipe_version=replacement.recipe_version,
                surfaces=replacement.as_surface_rows(),
                credential_host=replacement.credential_host,
                credential_path=replacement.credential_path,
                success_digest=replacement.success_digest,
                reason_code=outcome.reason_code,
            )
            recorded_revision = int(recorded["revision"])
            if recorded_revision != 2:  # pragma: no cover - transaction invariant
                raise RuntimeError("replacement plan revision was not 2")
            projection_revision = int(current.get("state_revision", 0) or 0) + 1
            transaction.update_run(
                run_id,
                attempt=int(current.get("attempt", 0) or 0) + 1,
                reason_code="route_replanned",
                route_reason_code="route_replanned",
                state_revision=projection_revision,
                last_projected_revision=projection_revision,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="onboarding_plan_superseded",
                payload={
                    "revision": recorded_revision,
                    "reason_code": "route_replanned",
                    "external_actions": False,
                },
            )
        return True

    @property
    def _takeover(self) -> RunTakeoverService | None:
        """The takeover sweep, or ``None`` when no worker can serve a clearance read.

        Built once and remembered, unlike the stateless collaborators above: it owns
        a thread that shutdown has to join.
        """

        existing = cast("RunTakeoverService | None", getattr(self, "_takeover_service", None))
        if existing is not None:
            return existing
        worker = self._browser_worker_for("playwright")
        probe = getattr(worker, "probe_gate_clearance", None)
        if probe is None:
            return None
        service = RunTakeoverService(
            storage=self.storage,
            phases=SQLitePhaseHistoryStore(self.storage.db_path),
            control=self._control,
            clearance=cast("ClearanceProbe", worker),
            queue=SQLiteRunQueue(self.storage.db_path),
            settings=self._settings or Settings.from_env(),
            canonical=self._canonical,
        )
        self._takeover_service = service
        return service

    @classmethod
    def from_paths(
        cls,
        *,
        db_path: str | Path,
        snapshot_root: str | Path = DEFAULT_P1_ROOT,
        settings: Settings | None = None,
        workflow: DurableOperationsWorkflow | None = None,
        research_enricher: ResearchEnricher | None = None,
        capability_preflight: ComposioCapabilityPreflight | None = None,
        credential_capturer: CredentialCapturePort | None = None,
        credential_validator: CredentialValidationPort | None = None,
        managed_auth_provider: ComposioManagedAuthProvider | None = None,
    ) -> RunService:
        return cls(
            storage=OperationsStorage(db_path),
            p1_adapter=P1OperationalAdapter(snapshot_root),
            settings=settings,
            workflow=workflow,
            research_enricher=research_enricher,
            capability_preflight=capability_preflight,
            credential_capturer=credential_capturer,
            credential_validator=credential_validator,
            managed_auth_provider=managed_auth_provider,
        )

    def initialize(self) -> None:
        """Validate application-owned storage and the pinned snapshot."""

        self.storage.initialize()
        load_verified_snapshot(self.p1_adapter.snapshot_root)
        # The approved matrix is process policy. A malformed/incomplete recipe
        # catalog is a startup error, never a per-run fallback.
        load_app_recipe_catalog()

    def startup(self) -> None:
        """Initialize storage and construct real dependencies only when configured.

        Explicit constructor injection (used by unit tests) always takes
        priority: startup fills only the dependencies left as ``None``. Missing
        provider keys leave the corresponding adapter unbuilt so the run reports
        ``configuration_required`` truthfully. No secret value is ever logged or
        recorded in the wiring audit.
        """

        self.initialize()
        settings = self._settings or Settings.from_env()
        self._settings = settings
        self._wiring = []

        # Read-only Composio capability preflight; fails closed when unconfigured.
        # This is a normal constructor dependency, not a production-only import-time
        # override, so tests and the deployed application use the same graph.
        if self._capability_preflight is None:
            self._capability_preflight = ComposioCapabilityPreflight(settings=settings)
        self._record_wiring("composio_preflight", self._capability_preflight, configured=True)

        # Runtime research is deliberately disabled. You.com and model-backed URL
        # discovery are recipe-authoring tools only; a live run consumes a reviewed,
        # versioned AppRecipe and can never spend research credits or expand policy.
        self._record_wiring(
            "runtime_research",
            None,
            configured=False,
        )
        # You.com is a sanitized wiring-audit ENTRY, never a live probe: a
        # normal health/startup check must never spend a You.com credit. See
        # `python -m ops.cli probe-you` for the explicit, opt-in live check.
        # A key that is present but unused is NOT an active integration, so the
        # audit reports You.com only when a capability flag actually enables it.
        you_enabled = settings.any_you_feature_configured
        self._record_wiring(
            "you_com",
            _YouComWiringMarker() if you_enabled else None,
            configured=you_enabled,
        )

        # Build the vault before any dependency that consumes it. A malformed
        # Fernet key must disable the entire vault boundary atomically; letting
        # the credential validator construct the store first would raise before
        # this fail-closed handling could run.
        if self._secret_store is None and settings.secret_vault_key is not None:
            try:
                self._secret_store = SQLiteSecretStore(
                    settings.secret_vault_db_path,
                    settings.secret_vault_key.get_secret_value(),
                )
            except (ValueError, TypeError) as exc:
                # Keep the diagnostic value-free. Production deployment performs
                # a stricter key preflight, while non-production startup remains
                # available for plan-only and configuration-repair workflows.
                LOGGER.error(
                    "SECRET_VAULT_KEY is invalid (%s); the credential vault is "
                    "disabled. Expected a url-safe base64 Fernet key.",
                    type(exc).__name__,
                )
                self._secret_store = None
        self._record_wiring(
            "secret_store",
            self._secret_store,
            configured=settings.secret_vault_key is not None,
        )

        # Read-only credential validator (HubSpot bearer, current endpoint).
        if self._credential_validator is None:
            self._credential_validator = self._build_credential_validator(settings)
        self._record_wiring(
            "credential_validator",
            self._credential_validator,
            configured=self._credential_validator is not None,
        )

        # Credential capture is intentionally NOT auto-injected at startup: raw
        # credentials are submitted explicitly by the owner, never scraped from
        # the browser.
        self._record_wiring(
            "credential_capturer",
            self._credential_capturer,
            configured=self._credential_capturer is not None,
        )

        # Provider construction is independent of LangGraph. New runs are driven
        # by the canonical SQLite state machine; a constructor-injected workflow is
        # retained only so pre-migration runs can still be inspected by a temporary
        # legacy adapter.
        self._build_workflow_dependencies(settings)
        managed_auth_configured = managed_auth_configuration_is_valid(settings)
        if self._managed_auth_provider is None and managed_auth_configured:
            try:
                self._managed_auth_provider = ComposioManagedAuthProvider.from_settings(
                    settings,
                    effect_store=self._effect_store,
                )
            except (ConfigurationRequiredError, ImportError, AttributeError, TypeError):
                self._managed_auth_provider = None
        self._record_wiring(
            "composio_managed_auth",
            self._managed_auth_provider,
            configured=managed_auth_configured,
            wired=managed_auth_configured and self._managed_auth_provider is not None,
        )
        self._record_wiring(
            "legacy_workflow",
            self._workflow,
            configured=self._workflow is not None,
            wired=self._workflow is not None,
        )
        # Startup remains provider-I/O-free. When automation is enabled, these
        # methods only create threads whose first sweep waits for the configured
        # grace period. That preserves observational process startup while still
        # giving an accepted production revision autonomous OTP/reply polling and
        # restart reconciliation.
        self._record_wiring(
            "startup_automation",
            self if settings.ops_startup_automation_enabled else None,
            configured=settings.ops_startup_automation_enabled,
            wired=settings.ops_startup_automation_enabled,
        )
        if settings.ops_startup_automation_enabled:
            # Independent maintenance handles reconciliation even when Gmail is
            # unavailable; the email worker handles only bounded inbox work.
            self._start_autonomous_advancer()
            self._start_onboarding_takeover()
            self._start_email_poller()

    def _reconcile_stranded_runs(self) -> None:
        """Recover runs stranded by the previous shutdown."""

        self._reconciliation.reconcile_stranded_runs()

    def _continue_pristine_playwright_run(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Resume one committed attempt-zero browser run after the startup grace."""

        return self._canonical._continue_pristine_playwright_run(
            record,
            browser_login=None,
        )

    def _browser_session_is_live(self, record: Mapping[str, Any]) -> bool | None:
        """Ask the browser service whether a persisted session id still exists."""

        return self._reconciliation.browser_session_is_live(record)

    def _reconcile_one_stranded(
        self,
        run_id: str,
        *,
        stranded_statuses: tuple[str, ...] = ("browser_running",),
        reason: str = "api_restart_stranded_browser_run",
    ) -> None:
        self._reconciliation.reconcile_one_stranded(
            run_id,
            stranded_statuses=stranded_statuses,
            reason=reason,
        )

    def _start_email_poller(self) -> None:
        """Start the background thread that polls waiting runs for new replies."""

        self._email.start_poller()

    def _hitl_action_type(self, record: Mapping[str, object]) -> str | None:
        """Return the pending HITL action type from the record or checkpoint."""

        hitl = record.get("hitl_request")
        if isinstance(hitl, Mapping) and hitl.get("type"):
            return str(hitl.get("type"))
        if self._workflow is None:
            return None
        thread_id = str(record.get("thread_id") or "")
        if not thread_id:
            return None
        try:
            state = self._workflow.get_state(thread_id)
        except Exception:
            return None
        observation = state.get("browser_observation")
        if isinstance(observation, Mapping):
            action = observation.get("human_action_type")
            return str(action) if action else None
        return None

    def _start_autonomous_advancer(self) -> None:
        """Start the sweep that auto-resumes machine-resolvable human gates."""

        self._advance.start()

    def _start_onboarding_takeover(self) -> None:
        """Start the sweep that continues a run once a human clears its gate."""

        takeover = self._takeover
        if takeover is not None:
            takeover.start()

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int:
        """Recover runs stuck at ``browser_running`` with nothing driving them."""

        return self._reconciliation.reconcile_idle_browser_runs(limit=limit)

    def sweep_onboarding_takeover(self, limit: int = 100) -> int:
        """Continue every paused run whose human gate a person has now cleared."""

        takeover = self._takeover
        return 0 if takeover is None else takeover.sweep(limit=limit)

    def mark_stale_runs(self, *, limit: int = 100) -> int:
        """Mark every run whose loop stopped stepping inside the staleness window."""

        return self._liveness.mark_stale_runs(limit=limit)

    def advance_autonomous_runs(self, *, limit: int = 100) -> int:
        """Resume every waiting run whose human gate the agent can resolve itself."""

        return self._advance.advance_autonomous_runs(limit=limit)

    def resolve_pending_otps(
        self,
        *,
        limit: int = 1_000,
        max_attempts_per_run: int | None = None,
    ) -> int:
        """Autonomously resolve every run waiting on an emailed login code."""

        return self._verification.resolve_pending_otps(
            limit=limit,
            max_attempts_per_run=max_attempts_per_run,
        )

    def resolve_email_otp(
        self,
        run_id: str,
        *,
        max_attempts: int | None = None,
    ) -> dict[str, Any] | None:
        """Resolve an emailed LOGIN verification and resume the browser with it."""

        return self._verification.resolve_email_otp(
            run_id,
            max_attempts=max_attempts,
        )

    def resolve_email_verification(
        self,
        run_id: str,
        *,
        purpose: VerificationPurpose = "login_verification",
        expected_recipient: str | None = None,
        max_attempts: int | None = None,
    ) -> dict[str, Any] | None:
        """Read the verification email for a waiting run and resume the browser."""

        return self._verification.resolve_email_verification(
            run_id,
            purpose=purpose,
            expected_recipient=expected_recipient,
            max_attempts=max_attempts,
        )

    def gmail_signup_preflight(
        self,
        *,
        timeout_seconds: float = 10.0,
    ) -> GmailSignupPreflight:
        """Run the real, read-only Gmail capability probe used before signup."""

        worker = self._gmail_worker
        if worker is None:
            return GmailSignupPreflight(
                status="configuration_required",
                reason_code="gmail_signup_worker_not_configured",
                provider_read_attempted=False,
            )
        return asyncio.run(worker.preflight_signup_inbox(timeout_seconds=timeout_seconds))

    def _verification_binding(
        self,
        app_slug: str,
        *,
        expected_recipient: str | None = None,
        account_ref: str | None = None,
    ) -> _VerificationBinding | None:
        """Resolve the bindings available for an emailed verification."""

        return self._verification.verification_binding(
            app_slug,
            expected_recipient=expected_recipient,
            account_ref=account_ref,
        )

    def _fetch_bound_verification(
        self,
        *,
        run_id: str,
        purpose: str,
        binding: _VerificationBinding | None,
        verification_requested_at_ms: int,
    ) -> VerificationDecision | None:
        """Read one verification message, preferring the fully bound path."""

        return self._verification.fetch_bound_verification(
            run_id=run_id,
            purpose=purpose,
            binding=binding,
            verification_requested_at_ms=verification_requested_at_ms,
        )

    def _legacy_verification_read(
        self,
        worker: Any,
        *,
        run_id: str,
        purpose: str,
        verification_requested_at_ms: int,
        allowed_link_host_patterns: tuple[str, ...] = (),
        max_age_seconds: int = 900,
    ) -> VerificationDecision | None:
        """Preference-only inbox read for runs without an exact recipient binding."""

        return self._verification.legacy_verification_read(
            worker,
            run_id=run_id,
            purpose=purpose,
            verification_requested_at_ms=verification_requested_at_ms,
            allowed_link_host_patterns=allowed_link_host_patterns,
            max_age_seconds=max_age_seconds,
        )

    def poll_waiting_runs(self, *, limit: int = 100) -> int:
        """Poll every run awaiting a provider reply; returns how many were polled."""

        return self._email.poll_waiting_runs(limit=limit)

    def _build_research_enricher(self, settings: Settings) -> ResearchEnricher | None:
        """Build the enricher when any extraction model is configured; own its HTTP client(s).

        Discovery order: You.com Search (primary, when ``you_search_configured``)
        then Perplexity (fallback, when configured) via
        ``CompositeEvidenceDiscovery``. Content-fetch order: You.com Contents
        (primary, when ``you_contents_configured``) then the pre-existing
        guarded HTTP fetcher (fallback, always available). You.com Research is
        optional, disabled by default, and only ever supplies MORE candidate
        pages for the SAME canonical extraction below.

        The extraction model is the deployment's own chain. ``build_json_inference``
        — the Mercury-first chain the browser decider runs on — is what the
        extractor asks first, and the Gemini key it also takes is the fallback
        behind it. Research was the last model-answered task in this system still
        answered by a different provider than every other one, and it was answered
        that way in every deployment with a Gemini key regardless of what the
        deployment's primary model was. The gate is correspondingly no longer
        "Gemini or nothing": a Mercury key alone builds an enricher.

        Still backward-compatible in wiring: with ``YDC_API_KEY`` absent this
        builds the EXACT pre-existing Perplexity + guarded-HTTP pipeline and
        ``OperationalResearchEnricher`` runs its original code path unchanged.
        """

        # Same chain, same order, as the browser decision loop: Mercury, Groq,
        # Cerebras, OpenRouter, Gemini. ``None`` when no provider key is set.
        #
        # Sized for extraction, not for a page decision. The defaults exist to
        # stop ONE browser-loop decision eating the loop's budget: 1,024 output
        # tokens and 15 seconds across at most 3 providers. An
        # ``OperationalResearch`` record is a different shape of answer — a
        # multi-scope OAuth app with the per-URL claims the enricher requires
        # measures well past 1,024 tokens once the model pretty-prints it. On
        # the old caps Mercury answered first and correctly and was then cut
        # mid-JSON, Groq and Cerebras truncated identically, ``max_providers=3``
        # ended the chain before the in-chain Gemini, and the extractor fell
        # through to its own uncapped direct Gemini call — handing research back
        # to Gemini, which is precisely what putting the chain first was meant
        # to stop. Gemini's own extraction path already runs uncapped with a 45s
        # timeout, so this only gives the chain the same room it has.
        inference = build_json_inference(
            settings,
            budget=DecisionBudget(total_seconds=90.0, provider_seconds=45.0, max_providers=3),
            max_completion_tokens=8192,
        )
        if settings.google_genai_api_key is None and inference is None:
            return None

        extractor = StructuredExtractor(
            settings.google_genai_api_key,
            model=settings.gemini_model_chain,
            inference=inference,
        )
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
        )

        # A key alone must not change runtime wiring: with every You.com flag off
        # this builds the EXACT pre-existing Perplexity + guarded-HTTP pipeline and
        # never opens the research cache.
        if not settings.any_you_feature_configured:
            discovery = (
                PerplexitySearchDiscovery(settings.perplexity_api_key)
                if settings.perplexity_api_key is not None
                else None
            )
            return OperationalResearchEnricher(
                discovery=discovery,
                extractor=extractor,
                http_client=self._http_client,
            )

        you_api_key = settings.you_api_key
        if you_api_key is None:  # pragma: no cover - every *_configured requires the key
            raise ConfigurationRequiredError(
                phase=2,
                capability="You.com research",
                reason_code="you_api_key_required",
            )
        # One persistent research cache shared by all three You.com adapters, so
        # identical app research does not re-spend credits across enrichments.
        # The You.com adapters themselves manage their SDK client lifecycle via
        # ``async with`` per call — no persistent async client is stored here
        # (that would be unsafe across the per-enrichment asyncio.run loops).
        if self._research_cache is None:
            self._research_cache = SqliteResearchCache(settings.research_cache_db_path)
        research_cache = self._research_cache

        discovery_providers: list[object] = []
        if settings.you_search_configured:
            discovery_providers.append(
                YouSearchDiscovery(
                    you_api_key,
                    count=settings.you_search_count,
                    timeout_seconds=settings.you_search_timeout_seconds,
                    max_calls=settings.you_max_search_calls_per_enrichment,
                    cache=research_cache,
                )
            )
        if settings.perplexity_api_key is not None:
            discovery_providers.append(
                LegacyDiscoveryAdapter(PerplexitySearchDiscovery(settings.perplexity_api_key))
            )
        rich_discovery = (
            CompositeEvidenceDiscovery(discovery_providers)  # type: ignore[arg-type]
            if discovery_providers
            else None
        )

        content_fetcher_factory = None
        if settings.you_contents_configured:
            contents_timeout = settings.you_contents_timeout_seconds
            contents_max_age = settings.you_contents_max_age_seconds
            contents_max_pages = settings.you_max_contents_pages_per_enrichment
            guarded_http_client = self._http_client

            def _build_content_fetcher(host_policy: ResearchHostPolicy) -> object:
                primary = YouContentsFetcher(
                    you_api_key,
                    policy=host_policy,
                    max_age=contents_max_age,
                    request_timeout=contents_timeout,
                    max_pages=contents_max_pages,
                    cache=research_cache,
                )
                fallback_policy = host_policy.official_url_policy
                if fallback_policy is None:
                    return primary
                fallback = GuardedHTTPEvidenceFetcher(
                    OfficialEvidenceFetcher(guarded_http_client, fallback_policy)
                )
                return FallbackEvidenceContentFetcher(primary=primary, fallback=fallback)

            content_fetcher_factory = _build_content_fetcher

        research_fallback = None
        if settings.you_research_configured:
            research_fallback = YouResearchFallback(
                you_api_key,
                timeout_seconds=settings.you_research_timeout_seconds,
                cache=research_cache,
            )

        return OperationalResearchEnricher(
            discovery=None,
            extractor=extractor,
            http_client=self._http_client,
            rich_discovery=rich_discovery,
            # ops.research.operational_research declares these as small structural
            # Protocols typed with `policy: object` (it cannot import the
            # concrete ResearchHostPolicy without a circular import). The
            # concrete you_research classes correctly narrow that parameter
            # to ResearchHostPolicy, which mypy's Protocol contravariance
            # check flags even though it is safe here: _enrich_rich always
            # calls both with the exact ResearchHostPolicy it just built.
            content_fetcher_factory=content_fetcher_factory,  # type: ignore[arg-type]
            research_fallback=research_fallback,  # type: ignore[arg-type]
            # Cache the fully validated projection in the same SQLite cache as
            # Search/Contents so a warm run can be resumed without a fresh Gemini
            # extraction. Cached documents and claims are revalidated on every hit.
            outcome_cache=research_cache,
            outcome_cache_ttl=timedelta(
                seconds=max(1, settings.you_contents_max_age_seconds or 86_400)
            ),
        )

    def _build_credential_validator(
        self, settings: Settings
    ) -> PolicyBoundCredentialValidator | None:
        """Build the read-only validator only from an initialized vault."""

        if settings.secret_vault_key is None or self._secret_store is None:
            return None
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
        )
        self._validation_http_client = client
        policies = tuple(
            policy
            for recipe in load_app_recipe_catalog().apps
            if (policy := get_app_validation_policy(recipe.app_slug)) is not None
        )
        validator = CredentialValidator(
            secret_store=self._secret_store,
            http_client=client,
            policies=policies,
        )
        endpoints = {policy.app_slug: policy.allowed_endpoints[0] for policy in policies}
        return PolicyBoundCredentialValidator(validator=validator, endpoints=endpoints)

    def _build_workflow_dependencies(self, settings: Settings) -> WorkflowDependencies:
        """Inject controlled Gmail and every configured browser adapter.

        Gmail inbox reads require only the Composio Gmail connection. Outreach is
        a separate capability and still requires a controlled recipient override
        (or the explicit live-send policy inside GmailWorker). Keeping these facts
        separate lets signup/login verification work without enabling email sends.
        Browser adapters are evaluated independently and registered under their
        canonical identities.
        """

        # Build the effect ledger up front so the Gmail worker can share it for
        # effectively-once sends.
        if self._effect_store is None:
            self._effect_store = SQLiteEffectStore(settings.provider_effects_db_path)

        gmail: GmailWorker | None = None
        if (
            settings.composio_gmail_api_key is not None
            and settings.composio_gmail_connected_account_id is not None
        ):
            # Wire the encrypted vault + effect ledger: a reply that carries a
            # credential is then stored as a vault:// reference instead of raising
            # secret_store_missing (which previously wedged the email path), and
            # sends stay idempotent.
            gmail = GmailWorker(
                settings=settings,
                secret_store=self._secret_store,
                effect_store=self._effect_store,
            )
            # Retain the Gmail worker so the poll-email action can fetch and
            # classify replies and resolve signup/login verification on the same
            # scoped account. Sending remains independently policy-gated.
            self._gmail_worker = gmail
        self._record_wiring("gmail:inbox", gmail, configured=gmail is not None)
        self._record_wiring(
            "gmail:outreach",
            gmail if settings.outreach_recipient_override is not None else None,
            configured=bool(gmail is not None and settings.outreach_recipient_override),
        )

        browsers: dict[BrowserProvider, BrowserWorker] = {}
        for provider_name in ("playwright",):
            if not self._browser_provider_enabled(settings, provider_name):
                self._record_wiring(
                    f"browser:{provider_name}",
                    None,
                    configured=False,
                )
                continue
            provider_settings = settings.model_copy(update={"browser_provider": provider_name})
            worker = self._build_browser_worker(provider_settings, provider=provider_name)
            browsers[provider_name] = worker
            self._record_wiring(
                f"browser:{provider_name}",
                worker,
                configured=True,
            )
        self._browser_workers = browsers
        browser = browsers.get(settings.browser_provider)
        self._browser_worker = browser
        self._record_wiring("browser", browser, configured=browser is not None)

        self._record_wiring("effect_store", self._effect_store, configured=True)

        return WorkflowDependencies(
            browser=browser,
            browsers=browsers,
            gmail=gmail,
            effect_store=self._effect_store,
            outreach_recipient=settings.outreach_recipient_override,
        )

    def _browser_provider_enabled(
        self,
        settings: Settings,
        provider: BrowserProvider | None = None,
    ) -> bool:
        """Whether a browser worker should be wired for the selected provider.

        ``playwright`` needs the live opt-in AND an execution location: the browser
        service (URL + token) or the explicit in-process sandbox.
        """

        from ops.browser.readiness import browser_configuration_state

        return browser_configuration_state(settings, provider or settings.browser_provider)

    def _browser_worker_for(
        self,
        source: Mapping[str, object] | BrowserProvider,
    ) -> BrowserWorker | None:
        provider = (
            source
            if isinstance(source, str)
            else cast(BrowserProvider, source.get("browser_provider", "playwright"))
        )
        workers = cast(
            dict[BrowserProvider, BrowserWorker],
            getattr(self, "_browser_workers", {}),
        )
        worker = workers.get(provider)
        if worker is not None:
            return worker
        # Compatibility for narrow tests and older embedders that injected the
        # former single-worker attribute directly. Never cross-route a worker
        # whose provider identity is known to differ from the run.
        legacy_worker = cast(BrowserWorker | None, getattr(self, "_browser_worker", None))
        legacy_provider = getattr(legacy_worker, "provider_name", provider)
        return legacy_worker if legacy_provider == provider else None

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]:
        """Build the credential payload for the ACTIVE browser provider."""

        return self._login_secrets.browser_login_payload(
            provider=provider,
            app_slug=app_slug,
            scope_id=scope_id,
            values=values,
        )

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]:
        """Persist reusable sign-in credentials for one opaque account binding."""

        return self._login_secrets.remember_reusable_login(
            app_slug=app_slug,
            account_ref=account_ref,
            values=values,
        )

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]:
        """Load remembered sign-in credentials for one bound account."""

        return self._login_secrets.reusable_login_values(app_slug, account_ref)

    def _stage_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, SecretStr]:
        """Stage one generated signup pair without changing reusable login."""

        return self._login_secrets.stage_signup_login(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
            values=values,
        )

    def _staged_signup_login_values(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, SecretStr]:
        """Load only this run's staged signup credentials."""

        return self._login_secrets.staged_signup_login_values(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
        )

    def _promote_staged_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> tuple[str, ...]:
        """Promote a staged pair after the browser proves authentication."""

        return self._login_secrets.promote_staged_signup_login(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
        )

    def _store_transient_browser_secrets(
        self, *, app_slug: str, scope_id: str, values: Mapping[str, str]
    ) -> dict[str, str]:
        """Vault each permitted secret as a one-time, run-scoped reference."""

        return self._login_secrets.store_transient_browser_secrets(
            app_slug=app_slug, scope_id=scope_id, values=values
        )

    def _build_browser_worker(
        self,
        settings: Settings,
        *,
        provider: BrowserProvider | None = None,
    ) -> BrowserWorker:
        """Build the browser backend.

        Playwright is the only backend. For it the NORMAL path is the isolated browser service over
        authenticated RPC. Previously this always returned the in-process worker, so
        the service, its RPC auth, restart reattachment, health and lifecycle manager
        were never used by the real application. Running Chromium inside the API is
        still possible but must be requested explicitly via
        ``playwright_in_process_sandbox`` — it is for isolated tests and local
        debugging, not a silent fallback when the service is unconfigured.
        """

        del provider  # only one backend exists; kept for the call-site signature
        if getattr(settings, "playwright_in_process_sandbox", False):
            try:
                from ops.playwright.worker import PlaywrightBrowserWorker
            except ImportError:
                raise ConfigurationRequiredError(
                    phase=5,
                    capability="Playwright browser provider",
                    reason_code="playwright_provider_unavailable",
                ) from None
            return cast("BrowserWorker", PlaywrightBrowserWorker(settings=settings))

        if (
            not settings.browser_service_url
            or settings.browser_service_token is None
            or settings.browser_session_capability_key is None
        ):
            # Fail closed with an actionable reason rather than quietly starting
            # a browser in the control plane.
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser service",
                reason_code="browser_service_configuration_required",
            )
        from ops.browser.service_client import BrowserServiceClient

        return cast(
            "BrowserWorker",
            BrowserServiceClient(
                base_url=settings.browser_service_url,
                token=settings.browser_service_token,
                owner=settings.browser_service_owner,
                capability_key=settings.browser_session_capability_key,
                timeout_seconds=settings.browser_service_client_timeout_seconds,
                # The clearance probe is bounded on its own, well inside the
                # takeover interval, rather than inheriting the operation
                # budget above: a slow read is reported unread and the run
                # keeps waiting.
                takeover_probe_timeout_seconds=(settings.onboarding_takeover_probe_timeout_seconds),
            ),
        )

    def _record_wiring(
        self,
        dependency: str,
        instance: object | None,
        *,
        configured: bool,
        wired: bool | None = None,
    ) -> None:
        """Append a sanitized wiring-audit row (class name only, never secrets)."""

        self._wiring = [row for row in self._wiring if row.get("dependency") != dependency]
        self._wiring.append(
            {
                "dependency": dependency,
                "class": type(instance).__name__ if instance is not None else None,
                "configured": configured,
                "runtime_wired": (instance is not None) if wired is None else wired,
                "live_verified": False,
            }
        )

    def wiring_audit(self) -> list[dict[str, object]]:
        """Return the sanitized startup wiring audit (dependency/class/state)."""

        return [dict(row) for row in self._wiring]

    def shutdown(self) -> None:
        """Close the durable workflow, owned provider clients, and connections."""

        self._email_poller_stop.set()
        if self._email_poller_thread is not None:
            self._email_poller_thread.join(timeout=5)
            self._email_poller_thread = None
        self._advance_stop.set()
        if self._advance_thread is not None:
            self._advance_thread.join(timeout=5)
            self._advance_thread = None
        takeover = cast("RunTakeoverService | None", getattr(self, "_takeover_service", None))
        if takeover is not None:
            takeover.stop()
            self._takeover_service = None
        workflow = self._workflow
        self._workflow = None
        if workflow is not None:
            workflow.close()
        for client_attr in ("_http_client", "_validation_http_client"):
            client = getattr(self, client_attr, None)
            if isinstance(client, httpx.AsyncClient):
                try:
                    asyncio.run(client.aclose())
                except RuntimeError:  # pragma: no cover - already within a loop
                    pass
                setattr(self, client_attr, None)
        if self._research_cache is not None:
            try:
                self._research_cache.close()
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
            self._research_cache = None
        if self._gmail_worker is not None:
            try:
                asyncio.run(self._gmail_worker.close())
            except Exception:  # pragma: no cover - best-effort provider cleanup
                pass
            self._gmail_worker = None
        for worker in dict.fromkeys(self._browser_workers.values()):
            try:
                asyncio.run(worker.close())
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
        self._browser_workers = {}
        self._browser_worker = None

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None = None,
        execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only",
        browser_login: Mapping[str, SecretStr] | None = None,
        selection: ModelSelection | None = None,
    ) -> dict[str, Any]:
        """Create and route one run without invoking an external provider.

        ``execution_mode`` is the single canonical control. ``plan_only`` runs the
        verified P1 lookup, deterministic routing, and sanitized persistence with
        no provider or network action. ``execute_when_configured`` may perform a
        bounded, policy-gated provider operation when the relevant dependency is
        configured; provider failures retain the verified baseline and are
        recorded as sanitized capability state. The deprecated ``request.dry_run``
        flag is no longer consulted as a runtime control.
        """

        if self._canonical.recipe_for_request(request) is not None:
            return self._canonical.create_run(
                request,
                idempotency_key=idempotency_key,
                execution_mode=execution_mode,
                browser_login=browser_login,
                selection=selection,
            )
        if execution_mode == "execute_when_configured":
            raise CredentialSubmissionError("reviewed_recipe_required")
        # The remaining P1 apps stay research-only. They retain the conservative
        # local projection but cannot enter any provider path.
        return self._creation.create_run(
            request,
            idempotency_key=idempotency_key,
            execution_mode="plan_only",
            browser_login=None,
            selection=selection,
        )

    def _spawn_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Run the durable browser navigate for a run in a background thread."""

        self._browser_execution.spawn_async_browser(
            run_id, thread_id, request, research, context, sensitive_data
        )

    def _run_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Background worker: drive the durable navigate on the pre-created session."""

        self._browser_execution.run_async_browser(
            run_id, thread_id, request, research, context, sensitive_data
        )

    def _apply_async_browser_result(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        workflow_state: Mapping[str, object],
        context: Any = None,
    ) -> None:
        """Transition a browser_running run based on the completed navigate."""

        self._browser_execution.apply_async_browser_result(
            run_id, thread_id, request, workflow_state, context
        )

    def _stop_terminal_playwright_session(
        self,
        context: Any,
        next_status: RunStatus,
        provider: BrowserProvider,
    ) -> None:
        """Close a self-hosted browser session once the run reaches a terminal state."""

        self._browser_execution.stop_terminal_playwright_session(context, next_status, provider)

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None:
        """Release a self-hosted browser session for a run that is finished."""

        self._browser_execution.release_browser_session(context, provider, reason=reason)

    def _session_context_for(self, run_id: str) -> Any:
        """A minimal session handle for a persisted run, or None."""

        return self._browser_execution.session_context_for(run_id)

    def _mark_async_browser_failed(self, run_id: str) -> None:
        """Best-effort transition of a stuck browser_running run to failed."""

        self._browser_execution.mark_async_browser_failed(run_id)

    def _run_enrichment_probe(
        self,
        record: P1AppRecord,
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome:
        """Run the single bounded enrichment probe synchronously.

        ``create_run`` is synchronous and, at the API boundary, is dispatched in
        a worker thread with no running event loop, so ``asyncio.run`` is safe
        and mirrors the durable workflow's async-invocation pattern.
        """

        if self._enricher is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no research enricher is configured")
        try:
            return asyncio.run(
                self._enricher.enrich(
                    app_name=baseline.app_name,
                    p1_record=record.model_dump(mode="json"),
                    baseline=baseline,
                )
            )
        except (TypeError, AttributeError, ImportError, ModuleNotFoundError, NameError):
            # A broken integration (wrong kwarg, renamed SDK attribute, missing
            # module) must reach monitoring/tests, not be silently degraded to a
            # provider outage. It may surface as a sanitized HTTP 500 upstream.
            raise
        except Exception:
            # An EXPECTED provider/transport/extraction/validation failure must
            # never turn an otherwise valid run request into an untyped HTTP 500.
            # Preserve the verified P1 baseline and expose only a stable reason.
            return ResearchEnrichmentOutcome(
                research=baseline,
                capability=CapabilityAvailability(
                    capability="operational_research",
                    status="failed",
                    reason_code="official_evidence_provider_failed",
                    detail=(
                        "Official-evidence enrichment did not complete; the verified "
                        "P1 baseline was retained."
                    ),
                ),
                missing_fields=_missing_operational_fields(baseline.model_dump(mode="json")),
                documents_fetched=0,
            )

    def _run_capability_preflight(self, app_slug: str, app_name: str) -> ComposioCapabilityReport:
        """Evaluate Composio capability once, synchronously, with no side effect."""

        if self._capability_preflight is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no capability preflight is configured")
        return asyncio.run(
            self._capability_preflight.evaluate(app_name=app_name, app_slug=app_slug)
        )

    def _run_m6_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
    ) -> _CredentialOutcome:
        """Capture -> store -> validate -> bundle, returning only sanitized metadata."""

        return self._credentials.run_m6_credentials(research, request)

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        captured: Mapping[str, str],
        *,
        recipe: AppRecipe | None = None,
    ) -> _CredentialOutcome:
        """Validate deterministically-captured vault refs and build the bundle."""

        return self._credentials.finalize_captured_credentials(
            research,
            request,
            captured,
            recipe=recipe,
        )

    def _record_verified_research(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        lookup: P1LookupFound,
        research: Mapping[str, object],
    ) -> None:
        record = lookup.record
        transaction.append_audit_event(
            run_id=run_id,
            event_type="p1_snapshot_loaded",
            payload={
                "status": "found",
                "source": "verified_p1_snapshot",
                "matched_by": lookup.matched_by,
                "api_type": record.api_type,
                "auth_methods": record.auth_methods,
                "access_model": record.access_model.kind,
                "buildability": record.buildability,
                "verification_status": record.verification_status,
                "confidence": record.confidence,
                "evidence_count": len(record.evidence_urls),
                "primary_docs_url": record.primary_docs_url,
                "external_actions": False,
            },
        )
        transaction.append_audit_event(
            run_id=run_id,
            event_type="operational_research_built",
            payload={
                "status": "baseline_complete",
                "source": "verified_p1_snapshot",
                "missing_fields": _missing_operational_fields(research),
                "evidence_count": len(cast(list[object], research.get("evidence_urls", []))),
                "external_actions": False,
            },
        )

    def list_runs(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        return self._queries.list_runs(limit=limit, offset=offset)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._queries.get_run(run_id)

    def get_timeline(self, run_id: str) -> list[dict[str, Any]]:
        return self._queries.get_timeline(run_id)

    def get_progress_events(self, run_id: str, *, limit: int) -> list[dict[str, Any]]:
        return self._queries.get_progress_events(run_id, limit=limit)

    def get_step_decisions(self, run_id: str, *, limit: int) -> list[dict[str, Any]]:
        return self._queries.get_step_decisions(run_id, limit=limit)

    def get_research(self, run_id: str) -> OperationalResearch | None:
        """Return the persisted sanitized research projection for a run."""

        return self._queries.get_research(run_id)

    def search_apps(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Search the verified P1 catalog and return a minimal safe projection."""

        return self._queries.search_apps(query, limit=limit)

    def list_apps(self) -> list[dict[str, Any]]:
        """Return EVERY verified app, so the interface can offer a real choice."""

        return self._queries.list_apps()

    def get_app_research(self, app_slug: str) -> tuple[dict[str, Any], OperationalResearch] | None:
        """Return a verified app summary and its reviewed operational baseline."""

        return self._queries.get_app_research(app_slug)

    def get_output(self, run_id: str) -> dict[str, Any] | None:
        return self._queries.get_output(run_id)

    def project(
        self,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        *,
        command: str = "workflow",
    ) -> dict[str, Any]:
        """Idempotently project durable graph state into the sanitized ledger."""

        return self._projection.project(run_id, state, revision, command=command)

    def _apply_projection(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        command: str,
    ) -> dict[str, Any]:
        return self._projection.apply_projection(transaction, run_id, state, revision, command)

    def _run_lock(self, run_id: str) -> threading.RLock:
        with self._run_locks_guard:
            return self._run_locks.setdefault(run_id, threading.RLock())

    def guarded_status_update(
        self,
        run_id: str,
        *,
        expected_revision: int,
        next_status: RunStatus,
        command: str,
        **changes: object,
    ) -> dict[str, Any]:
        """Apply one mutating command under per-run serialization."""

        return self._projection.guarded_status_update(
            run_id,
            expected_revision=expected_revision,
            next_status=next_status,
            command=command,
            **changes,
        )

    def get_browser_screenshot(self, run_id: str) -> tuple[bytes, str] | None:
        """Return the newest masked screenshot for a run's browser session."""

        return self._live_view.get_browser_screenshot(run_id)

    def get_browser_interactive_grant(self, run_id: str) -> tuple[str, str, str, bool] | None:
        """Mint an ephemeral Playwright grant only for an active human handoff."""

        return self._live_view.get_browser_interactive_grant(run_id)

    def _public_no_reply(self, record: Mapping[str, object]) -> dict[str, Any]:
        """Return the current run projection with a no-op reply marker."""

        return self._email.public_no_reply(record)

    def _company_from_checkpoint(self, thread_id: str) -> CompanyProfile | None:
        """Read the run's company profile from the durable workflow checkpoint."""

        return self._email.company_from_checkpoint(thread_id)

    def _email_credentials_bundle_change(
        self,
        record: Mapping[str, object],
        company: CompanyProfile | None,
        credential_refs: dict[str, str],
    ) -> dict[str, object]:
        """Merge emailed credential references into the run's reference-only bundle."""

        return self._email.email_credentials_bundle_change(record, company, credential_refs)

    def poll_email(self, run_id: str) -> dict[str, Any]:
        """Fetch the outreach thread, classify the latest reply, and advance."""

        return self._email.poll_email(run_id)

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str = "completed",
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> dict[str, Any]:
        """Resume a waiting_for_hitl run on the SAME browser session/thread."""

        record = self.storage.get_run(run_id)
        if record is None:
            raise KeyError("run was not found")
        if record.get("state_engine") == "canonical_v1":
            return self._canonical.resume_run(
                run_id,
                signal=signal,
                browser_login=browser_login,
            )
        raise CredentialSubmissionError("legacy_run_is_read_only")

    def resume_onboarding_from_pause(self, run_id: str) -> ResumeOutcome:
        """Re-enter the phase an onboarding run recorded when it parked.

        The one continuation an onboarding run has: the phase machine commits
        ``captcha_paused -> phase_at_pause`` with ``captcha_resolved`` at the next
        attempt, projects the coarse status, and writes the audit row. A replayed
        signal reports ``committed=False`` and writes nothing, so the owner's
        resume and an autonomous takeover are the same mechanism rather than two
        (Requirements 1.5, 1.9, 1.10).
        """

        return self._control.resume_from_pause(run_id)

    def connect_managed_run(self, run_id: str) -> dict[str, Any]:
        """Create or replay one managed Composio connection link."""

        return self._canonical.connect_managed_run(run_id)

    def retry_browser_run(self, run_id: str) -> dict[str, Any]:
        """Retry one recoverable canonical Playwright attempt without login reuse."""

        return self._canonical.retry_browser_run(run_id)

    def poll_managed_connection(self, run_id: str) -> dict[str, Any]:
        """Advance a managed run only after Composio reports ACTIVE."""

        return self._canonical.poll_managed_connection(run_id)

    def send_gated_outreach(self, run_id: str) -> dict[str, Any]:
        """Execute reviewed outreach only through the controlled Gmail boundary."""

        return self._canonical.send_gated_outreach(run_id)

    def submit_owner_credentials(
        self,
        run_id: str,
        *,
        company: CompanyProfile,
        fields: Mapping[str, SecretStr],
    ) -> dict[str, Any]:
        """Owner-only credential submission: vault-write, validate, and bundle."""

        return self._credentials.submit_owner_credentials(run_id, company=company, fields=fields)

    def snapshot_provenance(self) -> P1SnapshotProvenance:
        return self._queries.snapshot_provenance()
