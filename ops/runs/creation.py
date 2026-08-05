"""Run creation: verify, research, route, persist, and dispatch execution.

Creation is deliberately front-loaded. Every immutable input is verified BEFORE any
run state is written, so a request for an unknown app or with a conflicting replay
key fails without leaving a partial run behind.

``execution_mode`` is the single canonical control. ``plan_only`` is strictly local:
verified P1 lookup, deterministic routing and sanitized persistence, with no
provider or network action. ``execute_when_configured`` may perform one bounded,
policy-gated provider operation per configured dependency; a provider failure
retains the verified baseline and is recorded as sanitized capability state rather
than failing the run.

A live browser run commits at ``browser_running`` with the session already created
and the live view available, then hands the bounded task to a background thread.
That is what keeps the create request fast while the embedded live view and HITL
stay usable for the whole task.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Mapping
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import SecretStr

from ops.access.routing import RoutingDecision, decide_access
from ops.browser.api_trace_catalog import get_browser_api_trace
from ops.browser.link_log import log_event
from ops.browser.worker import BrowserWorker
from ops.core.config import Settings
from ops.core.model_catalog import ModelSelection
from ops.core.models import CapabilityAvailability, OperationsRequest
from ops.core.state import AccessRoute, BrowserProvider, OperationsState
from ops.core.storage import OperationsStorage
from ops.providers.composio_capability import ComposioCapabilityReport
from ops.research.operational_baselines import apply_reviewed_operational_baseline
from ops.research.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research
from ops.runs.errors import IdempotencyConflictError
from ops.runs.idempotency import (
    _legacy_request_fingerprints,
    _request_fingerprint,
    validate_idempotency_key,
)
from ops.runs.projections import (
    _PERSISTED_EXECUTION_MODE,
    _TERMINAL_BROWSER_STATUSES,
    _browser_result_reason,
    _capability_reason_code,
    _missing_operational_fields,
    _public_run,
    _slugify,
)
from ops.runs.state_projection import _validate_created_projection
from ops.workflow.graph import browser_account_ref

# Gated routes that may proceed to a single controlled outreach in
# execute_when_configured. self_serve/hybrid use the browser path and
# unknown/blocked never contact a provider.
_GATED_OUTREACH_ROUTES = frozenset({"approval_required", "partner_gated"})


class RunCreationContext(Protocol):
    """Run-service state and collaborators run creation drives."""

    storage: OperationsStorage
    p1_adapter: P1OperationalAdapter
    _settings: Settings | None
    _workflow: Any
    _enricher: Any
    _capability_preflight: Any
    _credential_capturer: Any
    _credential_validator: Any
    _async_browser_enabled: bool

    def _browser_worker_for(self, record: Any) -> BrowserWorker | None: ...

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]: ...

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]: ...

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def _record_verified_research(self, *args: Any, **kwargs: Any) -> Any: ...

    def _run_capability_preflight(
        self, app_slug: str, app_name: str
    ) -> ComposioCapabilityReport: ...

    def _run_enrichment_probe(self, *args: Any, **kwargs: Any) -> Any: ...

    def _run_m6_credentials(self, *args: Any, **kwargs: Any) -> Any: ...

    def _spawn_async_browser(self, *args: Any, **kwargs: Any) -> None: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunCreationService:
    """Create, route and dispatch one run."""

    def __init__(self, context: RunCreationContext) -> None:
        self._context = context

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

        service = self._context

        persisted_execution_mode = _PERSISTED_EXECUTION_MODE[execution_mode]
        created_event_type = "dry_run_created" if execution_mode == "plan_only" else "run_created"
        validated_idempotency_key = validate_idempotency_key(idempotency_key)
        request_fingerprint = (
            _request_fingerprint(request, execution_mode)
            if validated_idempotency_key is not None
            else None
        )

        # Verify all immutable inputs before writing any run state.
        lookup = service.p1_adapter.lookup(request.app_name)
        research_payload: Mapping[str, object] | None = None
        research_source = "verified_p1_snapshot"
        enrichment_attempts = 0
        enrichment_documents = 0
        enrichment_metrics: dict[str, object] = {}
        enrichment_capability: CapabilityAvailability | None = None
        reviewed_baseline_version: str | None = None
        if isinstance(lookup, P1LookupFound):
            research = to_operational_research(lookup.record)
            research, reviewed_baseline_version = apply_reviewed_operational_baseline(research)
            # Plan-only runs are strictly local: no provider or network action is
            # permitted. An explicit execute request may use one bounded,
            # allowlisted official-evidence probe when the baseline is incomplete.
            # Browser, Gmail, and credential side effects remain separately gated.
            if (
                execution_mode == "execute_when_configured"
                and service._enricher is not None
                and _missing_operational_fields(research.model_dump(mode="json"))
            ):
                outcome = service._run_enrichment_probe(lookup.record, research)
                research = outcome.research
                enrichment_capability = outcome.capability
                enrichment_documents = outcome.documents_fetched
                enrichment_metrics = dict(outcome.provider_metrics)
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
        with service.storage.unit_of_work() as transaction:
            if validated_idempotency_key is not None:
                existing = transaction.get_idempotent_run(validated_idempotency_key)
                if existing is not None:
                    record, stored_fingerprint = existing
                    legacy_match = stored_fingerprint in _legacy_request_fingerprints(
                        request, execution_mode
                    )
                    if stored_fingerprint != request_fingerprint and not legacy_match:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for another request"
                        )
                    return _public_run(record)

            transaction.create_run(
                decision_model=None
                if selection is None
                else f"{selection.provider}:{selection.model}",
                decision_effort=None if selection is None else (selection.effort or None),
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
                browser_provider=request.browser_provider,
                credential_creation_policy=request.credential_creation_policy,
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
                    "browser_provider": request.browser_provider,
                    "credential_creation_policy": request.credential_creation_policy,
                    "external_actions": False,
                },
            )
            if execution_mode == "execute_when_configured":
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="operational_research_started",
                    payload={"status": "researching", "external_actions": False},
                )

            if isinstance(lookup, P1LookupFound):
                if research_payload is None:  # pragma: no cover - narrowing invariant
                    raise RuntimeError("verified research payload was not built")
                service._record_verified_research(
                    transaction,
                    run_id,
                    lookup,
                    research_payload,
                )
                if reviewed_baseline_version is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="reviewed_operational_baseline_applied",
                        payload={
                            "status": "baseline_complete",
                            "app_slug": lookup.record.slug,
                            "version": reviewed_baseline_version,
                            "missing_fields": _missing_operational_fields(research_payload),
                            "external_actions": False,
                        },
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
                            # Sanitized provider metrics (counts/latency/provider
                            # name); never query text, page content, or the key.
                            "provider_metrics": enrichment_metrics,
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
            observation_status: str | None = None
            # Set when the self-serve browser run is dispatched asynchronously
            # (Option A). Carries the pre-created live session so the background
            # navigate can be started once the creation transaction commits.
            pending_async_navigate: tuple[Any, dict[str, str] | None] | None = None
            # Sanitized autonomous-login bookkeeping: field NAMES and the source
            # only. A credential value never reaches these variables.
            login_remembered_fields: tuple[str, ...] = ()
            injected_login_source: str | None = None
            injected_login_fields: tuple[str, ...] = ()

            if (
                execution_mode == "execute_when_configured"
                and service._workflow is not None
                and isinstance(lookup, P1LookupFound)
            ):
                is_gated = decision.route in _GATED_OUTREACH_ROUTES
                is_self_serve = decision.route == "self_serve"
                needs_capability = is_gated or is_self_serve
                if needs_capability and service._capability_preflight is not None:
                    # Evaluate Composio capability exactly once before any verified
                    # P1 fallback (gated outreach or self-serve browser onboarding).
                    capability_report = service._run_capability_preflight(
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
                    # Autonomous sign-in credentials (if any) are injected into
                    # Browser Use as secure ``sensitive_data`` placeholders at
                    # session creation, so the agent signs in on its own. The raw
                    # values are passed to the workflow only as a call argument and
                    # never persisted to state, checkpoints, the ledger, or logs.
                    start_sensitive_data: dict[str, str] | None = None
                    # Autonomy: when the owner did not supply credentials for THIS
                    # run, reuse the ones they already authorized for this app.
                    # Without this a second run always stopped at the login form
                    # even though the credentials were known.
                    login_account_ref = (
                        f"acct_{browser_account_ref(request.company.work_email_ref)}"
                    )
                    login_values: Mapping[str, SecretStr] | None = browser_login
                    login_source = "owner_supplied"
                    if not login_values and run_provider_action:
                        remembered = service._reusable_login_values(
                            research.app_slug, login_account_ref
                        )
                        if remembered:
                            login_values = remembered
                            login_source = "vault_reuse"
                    if browser_login:
                        remembered_fields = service._remember_reusable_login(
                            app_slug=research.app_slug,
                            account_ref=login_account_ref,
                            values=browser_login,
                        )
                        if remembered_fields:
                            login_remembered_fields = remembered_fields
                    if login_values and run_provider_action:
                        injected_login_source = login_source
                        injected_login_fields = tuple(sorted(login_values))
                        start_sensitive_data = service._browser_login_payload(
                            provider=request.browser_provider,
                            # The verified slug and the newly created run id are
                            # already in scope here; the run row is not readable
                            # yet from inside its own creating transaction.
                            app_slug=research.app_slug,
                            # Scope the transient references to THIS run, so the
                            # service will only consume them for the matching run.
                            scope_id=run_id,
                            # The resolved set, which may be the remembered
                            # credentials rather than an owner submission.
                            values=login_values,
                        )
                    selected_worker = service._browser_worker_for(request.browser_provider)
                    trace_available = get_browser_api_trace(research.app_slug) is not None
                    # Trace-only readiness is scoped to the assignment's async
                    # runtime. Conservative/synchronous workflows still load their
                    # own reviewed operational URLs instead of receiving an
                    # incomplete baseline from RunService.
                    browser_research_ready = bool(
                        trace_available
                        and (
                            service._async_browser_enabled
                            or (research.login_url and research.credential_management_url)
                        )
                    )
                    # The pre-created session is attempted first, but a provider
                    # failure must NOT abort run creation. It previously raised
                    # straight out of create_run, which returned an unhandled 500
                    # and persisted NOTHING: the operator saw "the operations API is
                    # unavailable" with no run in the ledger and no way to see why.
                    # A failed start now falls through to the durable workflow, which
                    # records a truthful failure state for a run that really exists.
                    context = None
                    if (
                        service._async_browser_enabled
                        and is_self_serve
                        and run_provider_action
                        and selected_worker is not None
                        and browser_research_ready
                    ):
                        # OPTION A: pre-create the live provider session so the
                        # embedded live view is available immediately, commit the
                        # run at browser_running now, and run the durable navigate
                        # in a background thread. Run creation stays fast (no 504)
                        # and the live stream is available for the entire task.
                        #
                        # The same session metadata the LangGraph browser node
                        # supplies is passed here: without app_slug the service
                        # cannot resolve its host policy, and without secret_scope
                        # it cannot consume this run's one-time login references.
                        worker = selected_worker
                        is_playwright = getattr(worker, "provider_name", "") == "playwright"
                        account_ref: str | None = None
                        if is_playwright:
                            with contextlib.suppress(Exception):
                                account_ref = login_account_ref
                        try:
                            context = asyncio.run(
                                worker.start(
                                    None,
                                    app_slug=research.app_slug,
                                    account_ref=account_ref,
                                    secret_scope=run_id,
                                    # The model this run asked for, carried to
                                    # whichever process decides. Ignored by a
                                    # provider that runs its own agent model.
                                    decision_model=(
                                        None
                                        if selection is None
                                        else f"{selection.provider}:{selection.model}"
                                    ),
                                    decision_effort=(
                                        None if selection is None else (selection.effort or None)
                                    ),
                                    use_storage_state=is_playwright,
                                    live_view_mode=(
                                        "interactive_remote"
                                        if is_playwright
                                        and bool(
                                            getattr(
                                                service._settings,
                                                "browser_interactive_hitl_enabled",
                                                False,
                                            )
                                        )
                                        else "screenshot"
                                    ),
                                )
                            )
                        except (TypeError, AttributeError, AssertionError, NameError):
                            raise  # a programming error must surface, never degrade
                        except Exception as exc:
                            # Sanitized reason only; the durable workflow below now
                            # records the outcome against a persisted run.
                            log_event(
                                "run.dispatch.session_error",
                                level=40,
                                run_id=run_id,
                                thread_id=thread_id,
                                error=type(exc).__name__,
                                reason_code=str(getattr(exc, "reason_code", "") or "unknown"),
                            )
                            context = None
                    if context is not None:
                        pending_async_navigate = (context, start_sensitive_data)
                        workflow_state: OperationsState = {
                            "status": "browser_running",
                            "access_route": "self_serve",
                            "route_reason_code": decision.reason_code,
                            "route_reason": decision.explanation,
                            "browser_session_id": context.session_id,
                        }
                        log_event(
                            "run.dispatch.async_begin",
                            run_id=run_id,
                            thread_id=thread_id,
                            handle=context.session_id,
                            live_view_available=context.live_view_available,
                        )
                    else:
                        # Reached either because Option A does not apply to this run
                        # or because the pre-created session failed above.
                        log_event(
                            "run.dispatch.begin",
                            run_id=run_id,
                            thread_id=thread_id,
                            app_slug=_slugify(request.app_name),
                            route=decision.route,
                            run_provider_action=run_provider_action,
                            has_login=bool(browser_login),
                        )
                        try:
                            workflow_state = service._workflow.start(
                                request.model_copy(update={"dry_run": not run_provider_action}),
                                thread_id=thread_id,
                                sensitive_data=start_sensitive_data,
                                research=research if browser_research_ready else None,
                            )
                        except Exception as exc:
                            log_event(
                                "run.dispatch.error",
                                level=40,
                                run_id=run_id,
                                thread_id=thread_id,
                                error=type(exc).__name__,
                            )
                            raise
                    log_event(
                        "run.dispatch.result",
                        run_id=run_id,
                        thread_id=thread_id,
                        status=str(workflow_state.get("status") or routed_status),
                        access_route=workflow_state.get("access_route"),
                        has_browser_session=bool(workflow_state.get("browser_session_id")),
                        observation_status=(
                            str(workflow_state.get("browser_observation", {}).get("status"))
                            if isinstance(workflow_state.get("browser_observation"), Mapping)
                            else None
                        ),
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
                    if pending_async_navigate is not None:
                        # Async browser dispatch: commit browser_running with the
                        # live session; the background navigate advances the run.
                        decision_event = "route_selected"
                        persisted_status = "browser_running"
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": "running",
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
                        browser_events = [
                            (
                                "browser_session_started",
                                {
                                    "session_id": browser_session,
                                    "status": "browser_running",
                                    "external_actions": True,
                                },
                            ),
                        ]
                    elif (
                        (
                            persisted_status in {"failed", "blocked"}
                            or (
                                persisted_status == "configuration_required"
                                and observation_status
                                not in {"credential_page_ready", "developer_console_ready"}
                            )
                        )
                        and isinstance(browser_session, str)
                        and browser_session
                    ):
                        # A workflow can retain the session id after navigation
                        # fails. The old projection treated any non-empty id as
                        # success, invented credential_page_ready events, and left
                        # the UI polling a blank/dead browser forever.
                        fallback_reason = {
                            "blocked": "browser_navigation_blocked",
                            "configuration_required": "browser_configuration_required",
                            "failed": "browser_operation_failed",
                        }.get(persisted_status, "browser_operation_failed")
                        persisted_reason = _browser_result_reason(workflow_state, fallback_reason)
                        if persisted_status == "configuration_required":
                            decision_event = "configuration_required"
                        outreach_updates = {
                            "browser_session_id": browser_session,
                            "external_actions": True,
                            "provider_status": {
                                "research": "baseline_ready",
                                "browser": persisted_status,
                                "email": "not_started",
                                "validation": "not_started",
                            },
                        }
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
                                (
                                    "browser_navigation_blocked"
                                    if persisted_status == "blocked"
                                    else "browser_navigation_failed"
                                ),
                                {
                                    "status": persisted_status,
                                    "reason_code": persisted_reason,
                                    "external_actions": True,
                                },
                            ),
                        ]
                    elif isinstance(thread, str) and thread:
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
                                service._credential_capturer is not None
                                and service._credential_validator is not None
                            ):
                                # M6: capture -> store -> validate -> bundle. Raw
                                # credentials never leave the adapters/vault; only
                                # vault references and sanitized metadata are stored.
                                credential_outcome = service._run_m6_credentials(research, request)
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
            elif execution_mode == "execute_when_configured" and service._workflow is None:
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
                    # Route selection is a real completed phase even when this same
                    # transaction immediately dispatches the browser. Recording the
                    # later browser status here erased the route_selected hop from
                    # the evaluator timeline.
                    "status": (
                        "route_selected" if decision_event == "route_selected" else persisted_status
                    ),
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
            if injected_login_source is not None:
                # Field NAMES and the source only, so the timeline proves the
                # agent signed itself in without recording any credential value.
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="login_credentials_injected",
                    payload={
                        "fields": list(injected_login_fields),
                        "source": injected_login_source,
                        "external_actions": True,
                    },
                )
            if login_remembered_fields:
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="login_credentials_remembered",
                    payload={
                        "fields": list(login_remembered_fields),
                        "external_actions": False,
                    },
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
        # The creation transaction has committed here. Only now start the
        # background browser task, so its own transaction never races the
        # creation write and the run row is already queryable + streamable.
        if pending_async_navigate is not None:
            context, async_sensitive = pending_async_navigate
            service._spawn_async_browser(
                run_id,
                thread_id,
                request,
                research,
                context,
                async_sensitive,
            )
        elif persisted_status in _TERMINAL_BROWSER_STATUSES and not (
            persisted_status == "configuration_required"
            and observation_status in {"credential_page_ready", "developer_console_ready"}
        ):
            # A synchronous workflow may have created a Playwright session and
            # then failed before returning an observation. Release that terminal
            # session now instead of serving its blank frame until the janitor TTL.
            # A verified credential page remains attached for the existing owner
            # handoff even when capture/validation needs configuration.
            service._release_browser_session(
                service._session_context_for(run_id),
                request.browser_provider,
                reason=f"sync_terminal_{persisted_status}",
            )
        return _public_run(created)


__all__ = [
    "RunCreationContext",
    "RunCreationService",
]
