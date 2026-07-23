"""Application service for durable, sanitized operations-ledger runs.

This module is the single application boundary shared by HTTP, CLI, LangGraph,
and internal debugging surfaces. Creating a run is intentionally side-effect
free: it verifies the immutable P1 snapshot, builds a conservative research
baseline, records the deterministic route, and leaves provider execution to
explicit retry/resume actions guarded by runtime policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

import httpx
from pydantic import SecretStr

from ops.browser_worker import BrowserWorker
from ops.composio_capability import ComposioCapabilityPreflight, ComposioCapabilityReport
from ops.config import Settings
from ops.credential_validator import (
    CredentialValidationResult,
    CredentialValidator,
    PolicyBoundCredentialValidator,
    hubspot_validation_policy,
    pipedrive_validation_policy,
)
from ops.network_endpoint_policy import validation_endpoint as network_validation_endpoint
from ops.effect_ledger import SQLiteEffectStore
from ops.gmail_worker import GmailWorker
from ops.graph import DurableOperationsWorkflow, WorkflowDependencies, build_graph
from ops.operational_research import (
    GeminiStructuredExtractor,
    OperationalResearchEnricher,
    PerplexitySearchDiscovery,
)
from ops.secret_store import SQLiteSecretStore
from ops.integrator import build_integrator_bundle
from ops.models import (
    CapabilityAvailability,
    CompanyProfile,
    IntegratorBundle,
    OperationalResearch,
    OperationsRequest,
    validate_vault_reference,
)
from ops.operational_research import ResearchEnricher, ResearchEnrichmentOutcome
from ops.p1_adapter import (
    DEFAULT_P1_ROOT,
    P1AppRecord,
    P1LookupFound,
    P1OperationalAdapter,
    P1SnapshotProvenance,
    load_verified_snapshot,
    to_operational_research,
)
from ops.provider_errors import ConfigurationRequiredError
from ops.redaction import redact_data, redact_text
from ops.routing import RoutingDecision, decide_access
from ops.state import AccessRoute, RunStatus, validate_status_transition
from ops.storage import OperationsStorage, OperationsUnitOfWork

IDEMPOTENCY_KEY_PATTERN = re.compile(r"^idem_[0-9a-f]{32}$")

# Gated routes that may proceed to a single controlled outreach in
# execute_when_configured. self_serve/hybrid use the browser path (later
# milestones) and unknown/blocked never contact a provider.
_GATED_OUTREACH_ROUTES = frozenset({"approval_required", "partner_gated"})

# Persisted reason codes for a gated run whose outreach the Composio capability
# preflight suppressed (or could not evaluate).
_CAPABILITY_SUPPRESSION_REASONS = {
    "composio_ready": "composio_ready",
    "connection_required": "composio_connection_required",
}


def _capability_reason_code(report: ComposioCapabilityReport | None) -> str:
    if report is None:
        return "composio_preflight_unavailable"
    return _CAPABILITY_SUPPRESSION_REASONS.get(report.capability_state, report.reason_code)


# The public RunService boundary exposes logical execution modes, while storage
# keeps its existing persisted tokens (no migration of existing rows).
_PERSISTED_EXECUTION_MODE = {
    "plan_only": "local_dry_run",
    "execute_when_configured": "operations",
}
_LOGICAL_EXECUTION_MODE = {value: key for key, value in _PERSISTED_EXECUTION_MODE.items()}

_PUBLIC_RUN_FIELDS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "created_at",
    "updated_at",
)


class InvalidIdempotencyKeyError(ValueError):
    """Raised without echoing a malformed or credential-shaped key."""


class IdempotencyConflictError(ValueError):
    """Raised when a key is reused for a different canonical request."""


class RunConflictError(RuntimeError):
    """Raised when a competing command mutates the same run concurrently."""

    def __init__(self, run_id: str, action: str) -> None:
        self.run_id = run_id
        self.action = action
        super().__init__("a competing command is already modifying this run")


class CredentialSubmissionError(RuntimeError):
    """Owner credential submission rejected; no partial vault write is kept."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("owner credential submission was rejected")


def validate_idempotency_key(value: str | None) -> str | None:
    """Validate a short opaque replay key without accepting secret material."""

    if value is None:
        return None
    if IDEMPOTENCY_KEY_PATTERN.fullmatch(value) is None or redact_text(value) != value:
        raise InvalidIdempotencyKeyError("idempotency key is invalid")
    return value


# create_run collapses several legal graph transitions into one initial
# projection (for example a gated run that reaches waiting_for_reply). The chain
# is validated hop-by-hop through the single transition authority so no illegal
# jump is ever written to the ledger.
_CREATE_PROJECTION_CHAINS: dict[str, tuple[RunStatus, ...]] = {
    "waiting_for_reply": ("route_selected", "outreach_sent", "waiting_for_reply"),
    "outreach_sent": ("route_selected", "outreach_sent"),
    "browser_running": ("route_selected", "browser_running"),
    "waiting_for_hitl": ("route_selected", "browser_running", "waiting_for_hitl"),
    "credentials_ready": ("route_selected", "browser_running", "credentials_ready"),
    "completed": ("route_selected", "browser_running", "credentials_ready", "completed"),
}


class CredentialCapturePort(Protocol):
    """Injectable deterministic credential capture returning vault references only."""

    async def capture(self, *, app_slug: str, app_name: str) -> dict[str, str]: ...


class CredentialValidationPort(Protocol):
    """Injectable read-only credential validation over stored vault references."""

    async def validate(
        self, *, app_slug: str, credential_refs: dict[str, str]
    ) -> CredentialValidationResult: ...


@dataclass(frozen=True, slots=True)
class _CredentialOutcome:
    """Internal result of the M6 capture -> store -> validate -> bundle flow."""

    status: str
    reason_code: str
    validation_status: str | None
    bundle: dict[str, Any] | None
    external_actions: bool
    events: list[tuple[str, dict[str, object]]] = field(default_factory=list)


def _validate_created_projection(final_status: str) -> None:
    chain = _CREATE_PROJECTION_CHAINS.get(final_status)
    if chain is None:
        validate_status_transition("created", cast(RunStatus, final_status), "create")
        return
    previous: RunStatus = "created"
    for nxt in chain:
        validate_status_transition(previous, nxt, "create")
        previous = nxt


def _request_fingerprint(request: OperationsRequest, execution_mode: str) -> str:
    canonical = json.dumps(
        {"execution_mode": execution_mode, "request": request.model_dump(mode="json")},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _slugify(app_name: str) -> str:
    # Sanitize before transforming. Lower-casing or replacing separators first
    # can otherwise make a provider credential stop matching its redaction
    # signature while leaving a recognizable fragment in the public slug.
    safe_name = redact_text(app_name)
    slug = re.sub(r"[^a-z0-9]+", "-", safe_name.strip().lower()).strip("-")
    return slug or "app"


def _public_run(record: Mapping[str, object]) -> dict[str, Any]:
    public = {
        field: record.get(field) for field in _PUBLIC_RUN_FIELDS if record.get(field) is not None
    }
    persisted_execution_mode = str(record.get("execution_mode") or "local_dry_run")
    public["execution_mode"] = _LOGICAL_EXECUTION_MODE.get(persisted_execution_mode, "plan_only")
    public["external_actions"] = bool(record.get("external_actions", False))
    sanitized = redact_data(public)
    if not isinstance(sanitized, dict):  # pragma: no cover - fixed mapping invariant
        raise RuntimeError("run response could not be sanitized")
    return cast(dict[str, Any], sanitized)


def _missing_operational_fields(research: Mapping[str, object]) -> list[str]:
    candidates = (
        "api_base_url",
        "authorization_url",
        "token_url",
        "credential_fields",
        "scopes",
        "developer_portal_url",
        "signup_url",
        "production_approval_required",
        "contact_email",
        "contact_url",
    )
    missing: list[str] = []
    for name in candidates:
        value = research.get(name)
        if value is None or value == "" or value == []:
            missing.append(name)
    return missing


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
        self._run_locks: dict[str, threading.RLock] = {}
        self._run_locks_guard = threading.Lock()
        # Resources owned and closed by this service when built at startup.
        self._http_client: httpx.AsyncClient | None = None
        self._validation_http_client: httpx.AsyncClient | None = None
        self._browser_worker: BrowserWorker | None = None
        self._secret_store: SQLiteSecretStore | None = None
        self._effect_store: SQLiteEffectStore | None = None
        # Sanitized startup wiring audit rows; never contains secrets.
        self._wiring: list[dict[str, object]] = []

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
        )

    def initialize(self) -> None:
        """Validate application-owned storage and the pinned snapshot."""

        self.storage.initialize()
        load_verified_snapshot(self.p1_adapter.snapshot_root)

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
        self._wiring = []

        # Read-only Composio capability preflight; fails closed when unconfigured.
        if self._capability_preflight is None:
            self._capability_preflight = ComposioCapabilityPreflight(settings=settings)
        self._record_wiring("composio_preflight", self._capability_preflight, configured=True)

        # One-probe research enricher (Perplexity discovery optional, Gemini
        # extraction mandatory). Only built when Gemini is configured; the owned
        # httpx client performs bounded official-evidence fetches.
        if self._enricher is None:
            self._enricher = self._build_research_enricher(settings)
        self._record_wiring(
            "research_enricher",
            self._enricher,
            configured=settings.google_genai_api_key is not None,
        )

        # Read-only credential validator (HubSpot bearer, current endpoint).
        if self._credential_validator is None:
            self._credential_validator = self._build_credential_validator(settings)
        self._record_wiring(
            "credential_validator",
            self._credential_validator,
            configured=self._credential_validator is not None,
        )

        # Owner-only vault. Credential capture is intentionally NOT auto-injected
        # at startup: raw credentials are submitted explicitly by the owner, never
        # scraped from the browser.
        if self._secret_store is None and settings.secret_vault_key is not None:
            self._secret_store = SQLiteSecretStore(
                settings.secret_vault_db_path,
                settings.secret_vault_key.get_secret_value(),
            )
        self._record_wiring(
            "secret_store", self._secret_store, configured=settings.secret_vault_key is not None
        )
        self._record_wiring(
            "credential_capturer",
            self._credential_capturer,
            configured=self._credential_capturer is not None,
        )

        if self._workflow is not None:
            self._record_wiring("workflow", self._workflow, configured=True, wired=True)
            return
        if settings.langgraph_aes_key is None:
            self._record_wiring("workflow", None, configured=False)
            return
        try:
            self._workflow = build_graph(
                checkpoint_path=settings.checkpoint_db_path,
                encryption_key=settings.langgraph_aes_key,
                dependencies=self._build_workflow_dependencies(settings),
            )
        except ConfigurationRequiredError:
            self._workflow = None
        self._record_wiring("workflow", self._workflow, configured=True)

    def _build_research_enricher(self, settings: Settings) -> ResearchEnricher | None:
        """Build the enricher only when Gemini is configured; own its HTTP client."""

        if settings.google_genai_api_key is None:
            return None
        discovery = (
            PerplexitySearchDiscovery(settings.perplexity_api_key)
            if settings.perplexity_api_key is not None
            else None
        )
        extractor = GeminiStructuredExtractor(
            settings.google_genai_api_key,
            model=settings.gemini_model_chain,
        )
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
        )
        return OperationalResearchEnricher(
            discovery=discovery,
            extractor=extractor,
            http_client=self._http_client,
        )

    def _build_credential_validator(
        self, settings: Settings
    ) -> PolicyBoundCredentialValidator | None:
        """Build the read-only HubSpot validator when the vault key is present."""

        if settings.secret_vault_key is None:
            return None
        if self._secret_store is None:
            self._secret_store = SQLiteSecretStore(
                settings.secret_vault_db_path,
                settings.secret_vault_key.get_secret_value(),
            )
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
        )
        self._validation_http_client = client
        validator = CredentialValidator(
            secret_store=self._secret_store,
            http_client=client,
            policies=(hubspot_validation_policy(), pipedrive_validation_policy()),
        )
        # Read-only validation endpoints come from the reviewed NetworkEndpointPolicy
        # (the single source of truth for exact backend endpoints).
        endpoints: dict[str, str] = {}
        for slug in ("hubspot", "pipedrive"):
            endpoint = network_validation_endpoint(slug)
            if endpoint is not None:
                endpoints[slug] = endpoint
        return PolicyBoundCredentialValidator(validator=validator, endpoints=endpoints)

    def _build_workflow_dependencies(self, settings: Settings) -> WorkflowDependencies:
        """Inject controlled Gmail and Browser Use adapters only when configured.

        Gmail outreach requires Composio configuration AND a configured
        OUTREACH_RECIPIENT_OVERRIDE so every send is delivered to the controlled
        recipient, never the discovered vendor address. The Browser Use adapter is
        injected only when live browsing is explicitly enabled with a key.
        """

        gmail: GmailWorker | None = None
        if (
            settings.composio_api_key is not None
            and settings.composio_gmail_connected_account_id is not None
            and settings.outreach_recipient_override is not None
        ):
            gmail = GmailWorker(settings=settings)
        self._record_wiring("gmail", gmail, configured=gmail is not None)

        browser: BrowserWorker | None = None
        if settings.allow_live_browser and settings.browser_use_api_key is not None:
            browser = BrowserWorker(settings=settings)
            self._browser_worker = browser
        self._record_wiring("browser", browser, configured=browser is not None)

        if self._effect_store is None:
            self._effect_store = SQLiteEffectStore(settings.provider_effects_db_path)
        self._record_wiring("effect_store", self._effect_store, configured=True)

        return WorkflowDependencies(
            browser=browser,
            gmail=gmail,
            effect_store=self._effect_store,
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
        if self._browser_worker is not None:
            try:
                asyncio.run(self._browser_worker.close())
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
            self._browser_worker = None

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None = None,
        execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only",
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

        persisted_execution_mode = _PERSISTED_EXECUTION_MODE[execution_mode]
        created_event_type = "dry_run_created" if execution_mode == "plan_only" else "run_created"
        validated_idempotency_key = validate_idempotency_key(idempotency_key)
        request_fingerprint = (
            _request_fingerprint(request, execution_mode)
            if validated_idempotency_key is not None
            else None
        )

        # Verify all immutable inputs before writing any run state.
        lookup = self.p1_adapter.lookup(request.app_name)
        research_payload: Mapping[str, object] | None = None
        research_source = "verified_p1_snapshot"
        enrichment_attempts = 0
        enrichment_documents = 0
        enrichment_capability: CapabilityAvailability | None = None
        if isinstance(lookup, P1LookupFound):
            research = to_operational_research(lookup.record)
            # Plan-only runs are strictly local: no provider or network action is
            # permitted. An explicit execute request may use one bounded,
            # allowlisted official-evidence probe when the baseline is incomplete.
            # Browser, Gmail, and credential side effects remain separately gated.
            if (
                execution_mode == "execute_when_configured"
                and self._enricher is not None
                and _missing_operational_fields(research.model_dump(mode="json"))
            ):
                outcome = self._run_enrichment_probe(lookup.record, research)
                research = outcome.research
                enrichment_capability = outcome.capability
                enrichment_documents = outcome.documents_fetched
                if outcome.capability.status == "ready":
                    enrichment_attempts = 1
                    research_source = "official_evidence_combined"
                decision = decide_access(research, unknown_probe_attempts=enrichment_attempts)
            else:
                decision = decide_access(research)
            research_payload = research.model_dump(mode="json")
        else:
            decision = RoutingDecision(
                route="unknown",
                reason_code="insufficient_evidence_probe_available",
                explanation=(
                    "The app is not present in the verified P1 snapshot. One bounded enrichment "
                    "probe remains available, but no external provider was invoked."
                ),
                is_final=False,
                unknown_probe_attempts=0,
                unknown_probe_remaining=1,
            )

        run_id = f"run_{uuid4().hex}"
        thread_id = f"local_{uuid4().hex}"
        with self.storage.unit_of_work() as transaction:
            if validated_idempotency_key is not None:
                existing = transaction.get_idempotent_run(validated_idempotency_key)
                if existing is not None:
                    record, stored_fingerprint = existing
                    if stored_fingerprint != request_fingerprint:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for another request"
                        )
                    return _public_run(record)

            transaction.create_run(
                run_id=run_id,
                thread_id=thread_id,
                app_name=request.app_name,
                app_slug=_slugify(request.app_name),
                status="created",
                p1_summary=(
                    {
                        "category": lookup.record.category,
                        "one_liner": lookup.record.one_liner,
                        "auth_methods": lookup.record.auth_methods,
                        "access_model": lookup.record.access_model.kind,
                        "api_type": lookup.record.api_type,
                        "buildability": lookup.record.buildability,
                        "recommended_next_action": lookup.record.recommended_next_action,
                        "verification_status": lookup.record.verification_status,
                        "confidence": lookup.record.confidence,
                        "last_verified": lookup.record.last_verified,
                    }
                    if isinstance(lookup, P1LookupFound)
                    else None
                ),
                operational_research=research_payload,
                route_reason_code=decision.reason_code,
                route_explanation=decision.explanation,
                missing_fields=(
                    _missing_operational_fields(research_payload)
                    if research_payload is not None
                    else ["p1_record", "operational_research"]
                ),
                provider_status={
                    "research": (
                        enrichment_capability.status
                        if enrichment_capability is not None
                        else ("baseline_ready" if research_payload is not None else "not_started")
                    ),
                    "browser": "not_started",
                    "email": "not_started",
                    "validation": "not_started",
                },
                scope_policy=request.requested_scope_policy,
                execution_mode=persisted_execution_mode,
                external_actions=False,
                idempotency_key=validated_idempotency_key,
                request_fingerprint=request_fingerprint,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type=created_event_type,
                payload={
                    "status": "created",
                    "scope_policy": request.requested_scope_policy,
                    "execution_mode": persisted_execution_mode,
                    "external_actions": False,
                },
            )

            if isinstance(lookup, P1LookupFound):
                if research_payload is None:  # pragma: no cover - narrowing invariant
                    raise RuntimeError("verified research payload was not built")
                self._record_verified_research(
                    transaction,
                    run_id,
                    lookup,
                    research_payload,
                )
                if enrichment_capability is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="operational_research_enriched",
                        payload={
                            "status": enrichment_capability.status,
                            "source": research_source,
                            "reason_code": enrichment_capability.reason_code,
                            "detail": enrichment_capability.detail,
                            "enrichment_attempts": enrichment_attempts,
                            "documents_fetched": enrichment_documents,
                            "missing_fields": _missing_operational_fields(research_payload),
                            "confidence": research_payload.get("confidence"),
                            "external_actions": False,
                        },
                    )
            else:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="p1_snapshot_not_found",
                    payload={
                        "status": "not_found",
                        "source": "verified_p1_snapshot",
                        "external_actions": False,
                    },
                )

            routed_status: str = "route_selected" if decision.is_final else "researching"
            decision_event = "route_selected" if decision.is_final else "route_pending"
            persisted_route: AccessRoute = decision.route
            persisted_reason: str = decision.reason_code
            persisted_explanation: str = decision.explanation
            outreach_updates: dict[str, object] = {}
            outreach_event: dict[str, object] | None = None
            persisted_status = routed_status

            capability_report: ComposioCapabilityReport | None = None
            capability_event: dict[str, object] | None = None
            browser_events: list[tuple[str, dict[str, object]]] = []

            if (
                execution_mode == "execute_when_configured"
                and self._workflow is not None
                and isinstance(lookup, P1LookupFound)
            ):
                is_gated = decision.route in _GATED_OUTREACH_ROUTES
                is_self_serve = decision.route == "self_serve"
                needs_capability = is_gated or is_self_serve
                if needs_capability and self._capability_preflight is not None:
                    # Evaluate Composio capability exactly once before any verified
                    # P1 fallback (gated outreach or self-serve browser onboarding).
                    capability_report = self._run_capability_preflight(
                        lookup.record.slug, request.app_name
                    )
                    capability_event = {
                        "capability_state": capability_report.capability_state,
                        "reason_code": capability_report.reason_code,
                        "toolkit_available": capability_report.toolkit_available,
                        "toolkit_slug": capability_report.toolkit_slug,
                        "active_connected_account": capability_report.active_connected_account,
                        "managed_auth_available": capability_report.managed_auth_available,
                        "required_tools_present": capability_report.required_tools_present,
                        "external_actions": False,
                    }

                # The verified P1 fallback (gated outreach or self-serve browser)
                # runs only when Composio cannot already integrate the app.
                fallback_allowed = (
                    capability_report is not None and capability_report.p1_fallback_allowed
                )
                run_provider_action = fallback_allowed
                # Gated outreach fails closed: any non-fallback capability, or an
                # unconfigured/absent preflight, suppresses the send. A self-serve
                # run is suppressed only by a definitive Composio capability
                # (composio_ready/connection_required); an unconfigured or absent
                # preflight preserves plan-only routing with no external action.
                suppress_fallback = (is_gated and not fallback_allowed) or (
                    is_self_serve
                    and capability_report is not None
                    and capability_report.capability_state
                    in {"composio_ready", "connection_required"}
                )

                if suppress_fallback:
                    persisted_status = "configuration_required"
                    decision_event = "configuration_required"
                    persisted_reason = _capability_reason_code(capability_report)
                    outreach_updates = {
                        "provider_status": {
                            "research": "baseline_ready",
                            "browser": "not_started",
                            "email": "not_started",
                            "composio": (
                                capability_report.capability_state
                                if capability_report is not None
                                else "configuration_required"
                            ),
                            "validation": "not_started",
                        },
                    }
                else:
                    # A provider action (gated outreach or self-serve browser) runs
                    # only when the fallback is allowed; unknown/blocked/hybrid
                    # routes run the workflow plan-only (routing only). The workflow
                    # performs the legal internal transitions and this projection
                    # records its truthful result.
                    workflow_state = self._workflow.start(
                        request.model_copy(update={"dry_run": not run_provider_action}),
                        thread_id=thread_id,
                    )
                    persisted_status = str(workflow_state.get("status") or routed_status)
                    persisted_route = workflow_state.get("access_route") or decision.route
                    persisted_reason = str(
                        workflow_state.get("route_reason_code") or decision.reason_code
                    )
                    persisted_explanation = str(
                        workflow_state.get("route_reason") or decision.explanation
                    )
                    thread = workflow_state.get("gmail_thread_id")
                    browser_session = workflow_state.get("browser_session_id")
                    observation = workflow_state.get("browser_observation")
                    observation_status = (
                        str(observation.get("status")) if isinstance(observation, Mapping) else None
                    )
                    if isinstance(thread, str) and thread:
                        outreach_updates = {
                            "gmail_session_id": workflow_state.get("gmail_session_id"),
                            "gmail_thread_id": thread,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "not_started",
                                "email": "sent",
                                "validation": "not_started",
                            },
                        }
                        # The effect/idempotency key is deterministically
                        # "<run_id>:initial-outreach"; it is not duplicated into the
                        # sanitized payload where the redactor would mask it as noise.
                        outreach_event = {
                            "status": persisted_status,
                            "route": persisted_route,
                            "reason_code": persisted_reason,
                            "intended_recipient": workflow_state.get("intended_recipient"),
                            "actual_recipient": workflow_state.get("actual_recipient"),
                            "outreach_round": workflow_state.get("outreach_round", 0),
                            "gmail_session_id": workflow_state.get("gmail_session_id"),
                            "gmail_thread_id": thread,
                            "provider_outcome": "sent",
                            "external_actions": True,
                        }
                        decision_event = "route_selected"
                    elif isinstance(browser_session, str) and browser_session:
                        # A controlled browser session was started. The effect key
                        # is deterministically "<run_id>:browser-start".
                        decision_event = "route_selected"
                        current_url = workflow_state.get("current_url")
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": observation_status or "running",
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
                        if (
                            observation_status == "human_action_required"
                            or persisted_status == "waiting_for_hitl"
                        ):
                            persisted_status = "waiting_for_hitl"
                            hitl = workflow_state.get("hitl_request")
                            required_action: object = None
                            if isinstance(hitl, Mapping):
                                required_action = hitl.get("type") or hitl.get("message")
                            browser_events = [
                                (
                                    "browser_session_started",
                                    {
                                        "session_id": browser_session,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "browser_hitl_required",
                                    {
                                        "status": "waiting_for_hitl",
                                        "current_url": current_url,
                                        "required_human_action": required_action,
                                        "external_actions": True,
                                    },
                                ),
                            ]
                        else:
                            base_browser_events: list[tuple[str, dict[str, object]]] = [
                                (
                                    "browser_session_started",
                                    {
                                        "session_id": browser_session,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "browser_navigation_completed",
                                    {
                                        "current_url": current_url,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                                (
                                    "credential_page_ready",
                                    {
                                        "current_url": current_url,
                                        "status": "browser_running",
                                        "external_actions": True,
                                    },
                                ),
                            ]
                            if (
                                self._credential_capturer is not None
                                and self._credential_validator is not None
                            ):
                                # M6: capture -> store -> validate -> bundle. Raw
                                # credentials never leave the adapters/vault; only
                                # vault references and sanitized metadata are stored.
                                credential_outcome = self._run_m6_credentials(research, request)
                                persisted_status = credential_outcome.status
                                persisted_reason = credential_outcome.reason_code
                                decision_event = (
                                    "configuration_required"
                                    if credential_outcome.status == "configuration_required"
                                    else "route_selected"
                                )
                                outreach_updates = {
                                    "browser_session_id": browser_session,
                                    "external_actions": credential_outcome.external_actions,
                                    "provider_status": {
                                        "research": "baseline_ready",
                                        "browser": "credential_page_ready",
                                        "email": "not_started",
                                        "validation": credential_outcome.validation_status
                                        or "configuration_required",
                                    },
                                }
                                if credential_outcome.bundle is not None:
                                    outreach_updates["integrator_bundle"] = (
                                        credential_outcome.bundle
                                    )
                                browser_events = [*base_browser_events, *credential_outcome.events]
                            else:
                                persisted_status = "browser_running"
                                browser_events = base_browser_events
                    elif persisted_status == "configuration_required":
                        decision_event = "configuration_required"
                        # Surface the truthful capability reason (for example a
                        # missing Gmail/browser adapter, verified recipient, or an
                        # ambiguous outcome) rather than the routing reason.
                        capabilities = workflow_state.get("capability_statuses")
                        if (
                            isinstance(capabilities, list)
                            and capabilities
                            and isinstance(capabilities[-1], Mapping)
                        ):
                            persisted_reason = str(
                                capabilities[-1].get("reason_code") or persisted_reason
                            )
                        outreach_updates = {
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "not_started",
                                "email": "configuration_required",
                                "validation": "not_started",
                            },
                        }
                    elif persisted_status == "route_selected":
                        decision_event = "route_selected"
                    else:
                        decision_event = "route_pending"
            elif execution_mode == "execute_when_configured" and self._workflow is None:
                # The durable engine is not configured (no encryption key); report
                # the truthful state without performing any provider action.
                persisted_status = "configuration_required"
                decision_event = "configuration_required"

            _validate_created_projection(persisted_status)
            transaction.update_run(
                run_id,
                status=persisted_status,
                access_route=persisted_route,
                route_reason_code=persisted_reason,
                route_explanation=persisted_explanation,
                state_revision=1,
                last_projected_revision=1,
                **outreach_updates,
            )
            if capability_event is not None:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="composio_capability_evaluated",
                    payload=capability_event,
                )
            transaction.append_audit_event(
                run_id=run_id,
                event_type=decision_event,
                payload={
                    "status": persisted_status,
                    "route": persisted_route,
                    "reason_code": persisted_reason,
                    "explanation": persisted_explanation,
                    "is_final": decision.is_final,
                    "unknown_probe_attempts": decision.unknown_probe_attempts,
                    "unknown_probe_remaining": decision.unknown_probe_remaining,
                    "external_actions": False,
                },
            )
            if outreach_event is not None:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_sent",
                    payload=outreach_event,
                )
            for browser_event_type, browser_payload in browser_events:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type=browser_event_type,
                    payload=browser_payload,
                )
            created = transaction.get_run(run_id)
            if created is None:  # pragma: no cover - persistence invariant
                raise RuntimeError("created run could not be read")
            return _public_run(created)

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
        except Exception:
            # A provider/transport/extraction failure must never turn an
            # otherwise valid run request into an untyped HTTP 500. Preserve the
            # verified P1 baseline and expose only a stable, sanitized reason.
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
        """Capture -> store -> validate -> bundle, returning only sanitized metadata.

        Raw credentials exist only inside the injected capture/validation adapters
        and the encrypted vault; this method handles vault references and
        sanitized validation metadata only.
        """

        capturer = self._credential_capturer
        validator = self._credential_validator
        if capturer is None or validator is None:  # pragma: no cover - guarded by caller
            raise RuntimeError("credential adapters are not configured")

        events: list[tuple[str, dict[str, object]]] = [
            (
                "credential_capture_started",
                {"app_slug": research.app_slug, "external_actions": True},
            )
        ]
        try:
            captured = asyncio.run(
                capturer.capture(app_slug=research.app_slug, app_name=research.app_name)
            )
        except ConfigurationRequiredError as exc:
            return _CredentialOutcome(
                status="configuration_required",
                reason_code=exc.reason_code,
                validation_status=None,
                bundle=None,
                external_actions=False,
                events=events,
            )
        references = {kind: validate_vault_reference(ref) for kind, ref in captured.items()}
        events.append(
            (
                "credentials_stored",
                {
                    "kinds": sorted(references),
                    "references": dict(sorted(references.items())),
                    "external_actions": True,
                },
            )
        )
        events.append(
            (
                "credential_validation_started",
                {"app_slug": research.app_slug, "external_actions": True},
            )
        )
        try:
            result = asyncio.run(
                validator.validate(app_slug=research.app_slug, credential_refs=references)
            )
        except ConfigurationRequiredError as exc:
            return _CredentialOutcome(
                status="configuration_required",
                reason_code=exc.reason_code,
                validation_status=None,
                bundle=None,
                external_actions=True,
                events=events,
            )
        events.append(
            (
                "credentials_validated",
                {
                    "validation_status": result.status,
                    "reason_code": result.reason_code,
                    "http_status": result.http_status,
                    "endpoint": result.endpoint,
                    "external_actions": True,
                },
            )
        )
        bundle = build_integrator_bundle(
            research=research,
            company=request.company,
            credential_refs=references,
            validation=result,
            stage="normal",
        )
        events.append(
            (
                "integrator_bundle_generated",
                {
                    "readiness": bundle.readiness,
                    "auth_scheme": bundle.auth_scheme,
                    "scopes": list(bundle.scopes),
                    "credential_ref_count": len(bundle.credential_refs),
                    "external_actions": True,
                },
            )
        )
        if result.status == "valid":
            status = "completed"
            reason_code = result.reason_code
        elif result.status == "invalid":
            status = "configuration_required"
            reason_code = result.reason_code
        else:
            # unavailable / failed: the true credential state is ambiguous. There is
            # no outcome_unknown RunStatus, so the run rests at configuration_required
            # with a truthful reason while the ambiguous validation status is recorded.
            status = "configuration_required"
            reason_code = "validation_outcome_unknown"
        return _CredentialOutcome(
            status=status,
            reason_code=reason_code,
            validation_status=result.status,
            bundle=bundle.model_dump(mode="json"),
            external_actions=True,
            events=events,
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
        records = self.storage.list_runs(limit=limit, offset=offset)
        return ([_public_run(record) for record in records], self.storage.count_runs())

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        record = self.storage.get_run(run_id)
        return _public_run(record) if record is not None else None

    def get_timeline(self, run_id: str) -> list[dict[str, Any]]:
        if self.storage.get_run(run_id) is None:
            return []
        return self.storage.list_audit_events(run_id)

    def get_research(self, run_id: str) -> OperationalResearch | None:
        """Return the persisted sanitized research projection for a run."""

        record = self.storage.get_run(run_id)
        if record is None:
            return None
        persisted = record.get("operational_research")
        if isinstance(persisted, Mapping):
            return OperationalResearch.model_validate(persisted)
        return None

    def search_apps(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Search the verified P1 catalog and return a minimal safe projection."""

        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        normalized = " ".join(query.casefold().split())
        snapshot = load_verified_snapshot(self.p1_adapter.snapshot_root)
        matches: list[dict[str, Any]] = []
        for record in snapshot.records:
            haystack = " ".join((record.app, record.slug, record.category)).casefold()
            if normalized and normalized not in haystack:
                continue
            matches.append(
                {
                    "app_name": record.app,
                    "app_slug": record.slug,
                    "category": record.category,
                    "api_type": record.api_type,
                    "auth_methods": list(record.auth_methods),
                    "access_route": to_operational_research(record).access_route,
                    "buildability": record.buildability,
                    "verification_status": record.verification_status,
                    "confidence": record.confidence,
                }
            )
            if len(matches) >= limit:
                break
        sanitized = redact_data(matches)
        if not isinstance(sanitized, list):  # pragma: no cover - fixed list invariant
            raise RuntimeError("app search response could not be sanitized")
        return cast(list[dict[str, Any]], sanitized)

    def get_app_research(self, app_slug: str) -> tuple[dict[str, Any], OperationalResearch] | None:
        """Return a verified app summary and its conservative operational baseline."""

        lookup = self.p1_adapter.lookup(app_slug)
        if not isinstance(lookup, P1LookupFound):
            return None
        record = lookup.record
        summary = {
            "app_name": record.app,
            "app_slug": record.slug,
            "category": record.category,
            "api_type": record.api_type,
            "auth_methods": list(record.auth_methods),
            "access_route": to_operational_research(record).access_route,
            "buildability": record.buildability,
            "verification_status": record.verification_status,
            "confidence": record.confidence,
        }
        return summary, to_operational_research(record)

    def get_output(self, run_id: str) -> dict[str, Any] | None:
        record = self.storage.get_run(run_id)
        if record is None:
            return None
        bundle = record.get("integrator_bundle")
        if bundle is None:
            return {}
        validated = IntegratorBundle.model_validate(bundle)
        sanitized = redact_data(validated.model_dump(mode="json"))
        if not isinstance(sanitized, dict):  # pragma: no cover - model invariant
            raise RuntimeError("output response could not be sanitized")
        return cast(dict[str, Any], sanitized)

    def project(
        self,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        *,
        command: str = "workflow",
    ) -> dict[str, Any]:
        """Idempotently project durable graph state into the sanitized ledger.

        A revision equal to or lower than the last projected revision is a
        no-op: no status is rewritten and no audit event is appended. Every
        status write first passes the single ``validate_status_transition``
        authority. The operations ledger remains a derived projection and never
        overrides the checkpoint.
        """

        with self.storage.unit_of_work() as transaction:
            result = self._apply_projection(transaction, run_id, state, revision, command)
            return _public_run(result)

    def _apply_projection(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        command: str,
    ) -> dict[str, Any]:
        current = transaction.get_run(run_id)
        if current is None:
            raise KeyError("run was not found")
        last_projected = int(current.get("last_projected_revision", 0) or 0)
        if revision <= last_projected:
            return current
        previous_status = cast(RunStatus, current["status"])
        next_status = cast(RunStatus, state.get("status") or previous_status)
        validate_status_transition(previous_status, next_status, command)
        changes: dict[str, object] = {
            "status": next_status,
            "state_revision": revision,
            "last_projected_revision": revision,
        }
        access_route = state.get("access_route")
        if access_route is not None:
            changes["access_route"] = access_route
        route_reason_code = state.get("route_reason_code")
        if route_reason_code is not None:
            changes["route_reason_code"] = route_reason_code
        route_reason = state.get("route_reason")
        if route_reason is not None:
            changes["route_explanation"] = route_reason
        research = state.get("operational_research")
        if isinstance(research, Mapping):
            changes["operational_research"] = dict(research)
        missing = state.get("missing_fields")
        if isinstance(missing, list):
            changes["missing_fields"] = list(missing)
        updated = transaction.update_run(run_id, **changes)
        transaction.append_audit_event(
            run_id=run_id,
            event_type="state_projected",
            payload={
                "status": next_status,
                "revision": revision,
                "external_actions": False,
            },
        )
        return updated

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
        """Apply one mutating command under per-run serialization.

        Competing commands are rejected with ``RunConflictError`` (surfaced as
        HTTP 409) without any partial write or external action. Concurrency is
        guarded by a per-run lock plus an optimistic ``state_revision`` check.
        """

        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, command)
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                if int(current.get("state_revision", 0) or 0) != expected_revision:
                    raise RunConflictError(run_id, command)
                previous_status = cast(RunStatus, current["status"])
                validate_status_transition(previous_status, next_status, command)
                new_revision = expected_revision + 1
                updated = transaction.update_run(
                    run_id,
                    status=next_status,
                    state_revision=new_revision,
                    last_projected_revision=new_revision,
                    **changes,
                )
                return _public_run(updated)
        finally:
            lock.release()

    def get_browser_live_url(self, run_id: str) -> str | None:
        """Return the ephemeral signed live-view URL for a run, if one is active.

        The URL is read from the in-memory BrowserWorker at request time and is
        never persisted to run state, checkpoints, the ledger, logs, or Git. It
        exists only while the worker holds the session, for owner interaction.
        """

        worker = self._browser_worker
        if worker is None:
            return None
        record = self.storage.get_run(run_id)
        if record is None:
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        return worker.live_url(session_id)

    def resume_run(self, run_id: str, *, signal: str = "completed") -> dict[str, Any]:
        """Resume a waiting_for_hitl run on the SAME browser session/thread.

        Continues the durable workflow through the existing thread id (no new
        session is created), then projects the resumed state. A repeated
        interrupt keeps the run at waiting_for_hitl with a refreshed instruction;
        a cleared path advances toward the credential page.
        """

        if self._workflow is None:
            raise CredentialSubmissionError("workflow_not_configured")
        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        try:
            current = self.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current["status"] != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            thread_id = str(current.get("thread_id") or run_id)
            state = self._workflow.resume(thread_id, signal)
            interrupts = self._workflow.get_interrupts(thread_id)

            observation = state.get("browser_observation")
            observation_status = (
                str(observation.get("status")) if isinstance(observation, Mapping) else None
            )
            current_url = state.get("current_url")
            still_blocked = bool(interrupts) or observation_status == "human_action_required"
            next_status: RunStatus = "waiting_for_hitl" if still_blocked else "browser_running"
            if signal == "cancelled":
                next_status = "blocked"

            with self.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:  # pragma: no cover - re-checked under lock
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                validate_status_transition("waiting_for_hitl", next_status, "resume")
                hitl_payload: dict[str, object] | None = None
                if next_status == "waiting_for_hitl":
                    source = interrupts[0] if interrupts else state.get("hitl_request")
                    if isinstance(source, Mapping):
                        hitl_payload = {str(k): v for k, v in source.items()}
                changes: dict[str, object] = {
                    "status": next_status,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    "external_actions": True,
                    "hitl_request": hitl_payload,
                }
                if isinstance(current_url, str) and current_url:
                    changes["browser_live_url"] = None  # never persist the signed URL
                updated = transaction.update_run(run_id, **changes)
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="hitl_resumed",
                    payload={"signal": signal, "external_actions": True},
                )
                if next_status == "waiting_for_hitl":
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="browser_hitl_required",
                        payload={
                            "status": "waiting_for_hitl",
                            "current_url": current_url,
                            "required_human_action": (
                                hitl_payload.get("type") if hitl_payload else None
                            ),
                            "external_actions": True,
                        },
                    )
                elif next_status == "browser_running":
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="credential_page_ready",
                        payload={
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                return _public_run(updated)
        finally:
            lock.release()

    def submit_owner_credentials(
        self,
        run_id: str,
        *,
        company: CompanyProfile,
        fields: Mapping[str, SecretStr],
    ) -> dict[str, Any]:
        """Owner-only credential submission: vault-write, validate, and bundle.

        Raw values are written straight to the encrypted vault and never enter
        run state, checkpoints, audit events, API output, or logs. Only exact
        ``vault://`` references, sanitized validation metadata, and the reference
        -only IntegratorBundle are persisted. Credentials are supplied explicitly
        by the owner here; they are never scraped from the browser.
        """

        if not fields:
            raise CredentialSubmissionError("no_credential_fields")
        for kind in fields:
            if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is None:
                raise CredentialSubmissionError("invalid_credential_field")
        store = self._secret_store
        validator = self._credential_validator
        if store is None or validator is None:
            raise CredentialSubmissionError("credential_boundary_not_configured")

        lock = self._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "submit_credentials")
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                if current["status"] != "browser_running":
                    raise CredentialSubmissionError("run_not_awaiting_credentials")
                research_payload = current.get("operational_research")
                if not isinstance(research_payload, Mapping):
                    raise CredentialSubmissionError("verified_research_unavailable")
                research = OperationalResearch.model_validate(dict(research_payload))
                app_slug = research.app_slug

                references: dict[str, str] = {}
                try:
                    for kind, secret in fields.items():
                        reference = store.put(
                            app_slug=app_slug,
                            kind=kind,
                            value=secret.get_secret_value(),
                        )
                        references[kind] = validate_vault_reference(reference)
                except Exception:
                    for reference in references.values():
                        try:
                            store.delete(reference)
                        except Exception:  # pragma: no cover - best-effort rollback
                            pass
                    raise CredentialSubmissionError("vault_write_failed") from None

                result = asyncio.run(
                    validator.validate(app_slug=app_slug, credential_refs=references)
                )
                bundle = build_integrator_bundle(
                    research=research,
                    company=company,
                    credential_refs=references,
                    validation=result,
                    stage="normal",
                )

                revision = int(current.get("state_revision", 0) or 0) + 1
                if result.status == "valid":
                    validate_status_transition("browser_running", "credentials_ready", "submit")
                    validate_status_transition("credentials_ready", "completed", "submit")
                    final_status: RunStatus = "completed"
                else:
                    validate_status_transition(
                        "browser_running", "configuration_required", "submit"
                    )
                    final_status = "configuration_required"

                updated = transaction.update_run(
                    run_id,
                    status=final_status,
                    state_revision=revision,
                    last_projected_revision=revision,
                    external_actions=True,
                    integrator_bundle=bundle.model_dump(mode="json"),
                    validation={
                        "status": result.status,
                        "reason_code": result.reason_code,
                        "http_status": result.http_status,
                        "endpoint": result.endpoint,
                        "checked_at": result.checked_at,
                        "account_identifier": result.account_identifier,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credentials_stored",
                    payload={
                        "kinds": sorted(references),
                        "references": dict(sorted(references.items())),
                        "external_actions": True,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credentials_validated",
                    payload={
                        "validation_status": result.status,
                        "reason_code": result.reason_code,
                        "http_status": result.http_status,
                        "endpoint": result.endpoint,
                        "account_identifier": result.account_identifier,
                        "external_actions": True,
                    },
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="integrator_bundle_generated",
                    payload={
                        "readiness": bundle.readiness,
                        "auth_scheme": bundle.auth_scheme,
                        "credential_ref_count": len(bundle.credential_refs),
                        "external_actions": True,
                    },
                )
                return _public_run(updated)
        finally:
            lock.release()

    def snapshot_provenance(self) -> P1SnapshotProvenance:
        return load_verified_snapshot(self.p1_adapter.snapshot_root).provenance


def decode_stored_payload(value: object) -> dict[str, Any]:
    """Decode only sanitized audit payloads returned by ``OperationsStorage``."""

    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        decoded = json.loads(value)
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}
