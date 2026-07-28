"""Canonical SQLite-backed execution for reviewed app recipes.

New runs use this service directly.  The database transaction boundary is kept
deliberately small: intent/state is committed first, provider I/O happens with no
SQLite transaction open, and the sanitized outcome is appended afterward.  Raw
credentials cross only the existing one-shot Playwright/vault boundaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from pydantic import SecretStr

from ops.app_recipes import (
    AppRecipe,
    get_app_recipe,
    get_app_recipe_for_name,
    load_app_recipe_catalog,
    recipe_to_operational_research,
)
from ops.browser_account_binding import (
    derive_browser_account_ref,
    validate_browser_account_ref,
)
from ops.browser_link_log import log_event
from ops.browser_worker import BrowserObservation, BrowserSessionContext, BrowserWorker
from ops.composio_managed_auth import ComposioManagedAuthProvider
from ops.gated_route import GatedRoute, GatedRoutePolicyError
from ops.integrator import build_integrator_bundle
from ops.models import OperationalResearch, OperationsRequest
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter
from ops.provider_errors import ConfigurationRequiredError
from ops.run_errors import CredentialSubmissionError, IdempotencyConflictError, RunConflictError
from ops.run_idempotency import (
    _legacy_request_fingerprints,
    _request_fingerprint,
    validate_idempotency_key,
)
from ops.run_projections import _PERSISTED_EXECUTION_MODE, _public_run, _slugify
from ops.run_recipe_snapshot import (
    RecipeSnapshotError,
    build_recipe_snapshot,
    recipe_from_run,
)
from ops.secret_store import SQLiteSecretStore
from ops.state import BrowserProvider, RunStatus
from ops.storage import OperationsStorage

ExecutionMode = Literal["plan_only", "execute_when_configured"]


class CanonicalRuntimeContext(Protocol):
    storage: OperationsStorage
    p1_adapter: P1OperationalAdapter
    _settings: Any
    _browser_threads: list[threading.Thread]
    _secret_store: SQLiteSecretStore | None
    _credential_validator: Any
    _managed_auth_provider: ComposioManagedAuthProvider | None
    _gmail_worker: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _browser_worker_for(
        self, source: Mapping[str, object] | BrowserProvider
    ) -> BrowserWorker | None: ...

    def _browser_login_payload(
        self,
        *,
        provider: BrowserProvider,
        app_slug: str,
        scope_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, str]: ...

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        credential_refs: Mapping[str, str],
        *,
        recipe: AppRecipe,
    ) -> Any: ...

    def _session_context_for(self, run_id: str) -> BrowserSessionContext | None: ...

    def _release_browser_session(
        self,
        context: BrowserSessionContext | None,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _AppliedBrowserOutcome:
    status: RunStatus
    phase: str
    reason_code: str
    provider_browser: str
    hitl: dict[str, object] | None = None
    changes: Mapping[str, object] | None = None
    events: tuple[tuple[str, Mapping[str, object]], ...] = ()


def _recipe_version() -> str:
    catalog = load_app_recipe_catalog()
    return f"{catalog.catalog_id}@{catalog.schema_version}"


def _access_route(recipe: AppRecipe) -> str:
    if recipe.route_kind == "gated":
        return "approval_required"
    return "self_serve"


def _initial_reason(recipe: AppRecipe) -> str:
    if recipe.route_kind == "managed_auth":
        return "managed_connection_required"
    if recipe.route_kind == "gated":
        return (
            "controlled_outreach_ready"
            if recipe.readiness_tier == "outreach_ready"
            else "outreach_contact_review_required"
        )
    return (
        "reviewed_browser_route_ready"
        if recipe.readiness_tier == "browser_ready"
        else "owner_submission_route_ready"
    )


def _safe_reason(exc: BaseException, fallback: str) -> str:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and reason and len(reason) <= 100:
        return reason
    return fallback


class CanonicalRuntime:
    """Execute managed, Playwright and gated recipes without LangGraph."""

    def __init__(self, context: CanonicalRuntimeContext) -> None:
        self._context = context

    def recipe_for_request(self, request: OperationsRequest) -> AppRecipe | None:
        return get_app_recipe_for_name(request.app_name) or get_app_recipe(
            _slugify(request.app_name)
        )

    @staticmethod
    def _recipe_for_run(record: Mapping[str, Any]) -> AppRecipe:
        try:
            return recipe_from_run(record)
        except RecipeSnapshotError as exc:
            raise CredentialSubmissionError(exc.reason_code) from None

    def create_run(
        self,
        request: OperationsRequest,
        *,
        idempotency_key: str | None,
        execution_mode: ExecutionMode,
        browser_login: Mapping[str, SecretStr] | None,
    ) -> dict[str, Any]:
        recipe = self.recipe_for_request(request)
        if recipe is None:
            raise KeyError("reviewed app recipe was not found")
        validated_key = validate_idempotency_key(idempotency_key)
        fingerprint = (
            _request_fingerprint(request, execution_mode) if validated_key is not None else None
        )
        run_id = f"run_{uuid4().hex}"
        thread_id = f"sqlite_{uuid4().hex}"
        browser_account_ref = (
            derive_browser_account_ref(
                run_id=run_id,
                app_slug=recipe.app_slug,
                work_email_ref=request.company.work_email_ref,
                browser_login=browser_login,
                binding_secret=getattr(self._context._settings, "secret_vault_key", None),
            )
            if recipe.route_kind == "playwright"
            else None
        )
        research = recipe_to_operational_research(recipe)
        recipe_version = _recipe_version()
        recipe_snapshot = build_recipe_snapshot(recipe, recipe_version)
        plan_only = execution_mode == "plan_only"
        status: RunStatus = (
            "route_selected"
            if plan_only or recipe.route_kind != "managed_auth"
            else "connection_required"
        )
        phase = (
            "route_selected"
            if plan_only
            else "connection_required"
            if recipe.route_kind == "managed_auth"
            else "browser_pending"
            if recipe.route_kind == "playwright"
            else "outreach_review"
        )
        reason = _initial_reason(recipe)
        provider_status = {
            "recipe": recipe.readiness_tier,
            "composio": "connection_required"
            if recipe.route_kind == "managed_auth"
            else "not_started",
            "browser": "not_started",
            "email": "not_started",
            "validation": "not_started",
        }

        with self._context.storage.unit_of_work() as transaction:
            if validated_key is not None:
                existing = transaction.get_idempotent_run(validated_key)
                if existing is not None:
                    record, stored_fingerprint = existing
                    legacy_match = stored_fingerprint in _legacy_request_fingerprints(
                        request, execution_mode
                    )
                    if stored_fingerprint != fingerprint and not legacy_match:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for another request"
                        )
                    return _public_run(record)

            lookup = self._context.p1_adapter.lookup(recipe.app_name)
            p1_summary: dict[str, object] | None = None
            if isinstance(lookup, P1LookupFound):
                p1_summary = {
                    "category": lookup.record.category,
                    "one_liner": lookup.record.one_liner,
                    "auth_methods": list(lookup.record.auth_methods),
                    "buildability": lookup.record.buildability,
                    "verification_status": lookup.record.verification_status,
                    "confidence": lookup.record.confidence,
                    "last_verified": lookup.record.last_verified,
                }
            transaction.create_run(
                run_id=run_id,
                thread_id=thread_id,
                app_name=recipe.app_name,
                app_slug=recipe.app_slug,
                status=status,
                access_route=cast(Any, _access_route(recipe)),
                p1_summary=p1_summary,
                operational_research=research.model_dump(mode="json"),
                request=request.model_dump(mode="json"),
                route_reason_code=reason,
                route_explanation=(
                    "This run is bound to a reviewed, versioned application recipe."
                ),
                missing_fields=[],
                provider_status=provider_status,
                scope_policy=request.requested_scope_policy,
                execution_mode=_PERSISTED_EXECUTION_MODE[execution_mode],
                browser_provider=request.browser_provider,
                credential_creation_policy=request.credential_creation_policy,
                recipe_version=recipe_version,
                recipe_snapshot=recipe_snapshot,
                route_kind=recipe.route_kind,
                readiness_tier=recipe.readiness_tier,
                browser_account_ref=browser_account_ref,
                attempt=0,
                phase=phase,
                reason_code=reason,
                state_engine="canonical_v1",
                external_actions=False,
                idempotency_key=validated_key,
                request_fingerprint=fingerprint,
            )
            transaction.update_run(
                run_id,
                state_revision=1,
                last_projected_revision=1,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="run_created",
                payload={
                    "status": "created",
                    "state_engine": "canonical_v1",
                    "recipe_version": recipe_version,
                    "route_kind": recipe.route_kind,
                    "readiness_tier": recipe.readiness_tier,
                    "browser_provider": request.browser_provider,
                    "browser_account_scope": (
                        "account_scoped"
                        if isinstance(browser_account_ref, str)
                        and browser_account_ref.startswith("acct_")
                        else "run_scoped"
                        if browser_account_ref is not None
                        else "not_applicable"
                    ),
                    "external_actions": False,
                },
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="route_selected",
                payload={
                    "status": "route_selected",
                    "route_kind": recipe.route_kind,
                    "phase": phase,
                    "reason_code": reason,
                    "external_actions": False,
                },
            )
            created = transaction.get_run(run_id)
            if created is None:  # pragma: no cover - SQLite invariant
                raise RuntimeError("created run could not be read")

        persisted_recipe = self._recipe_for_run(created)
        if not plan_only and persisted_recipe.route_kind == "playwright":
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=persisted_recipe,
                browser_login=browser_login,
            )
        return _public_run(created)

    def _start_playwright(
        self,
        run_id: str,
        *,
        request: OperationsRequest,
        research: OperationalResearch,
        recipe: AppRecipe,
        browser_login: Mapping[str, SecretStr] | None,
        attempt: int | None = None,
    ) -> dict[str, Any]:
        if request.browser_provider != "playwright":
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="playwright_required_for_recipe",
            )
        if recipe.browser is None:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="reviewed_browser_entry_required",
            )
        worker = self._context._browser_worker_for("playwright")
        if worker is None:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="playwright_not_configured",
            )

        persisted = self._context.storage.get_run(run_id)
        if persisted is None:
            raise KeyError("run was not found")
        try:
            browser_account_ref = validate_browser_account_ref(
                persisted.get("browser_account_ref")
            )
        except ValueError:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="browser_account_binding_missing",
            )

        sensitive: dict[str, str] | None = None
        if browser_login:
            sensitive = self._context._browser_login_payload(
                provider="playwright",
                app_slug=recipe.app_slug,
                scope_id=run_id,
                values=browser_login,
            )

        with self._context.storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            next_attempt = attempt or int(current.get("attempt", 0) or 0) + 1
            if next_attempt < 1:
                raise ValueError("browser attempt must be positive")
            effect_identity = f"{run_id}:browser-start:v{next_attempt}"
            _intent, reserved = transaction.reserve_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                provider="playwright",
            )
            transaction.update_run(
                run_id,
                phase="authentication_submitted" if sensitive else "browser_starting",
                reason_code="browser_start_reserved",
                effect_identity=effect_identity,
                attempt=next_attempt,
                state_revision=int(current.get("state_revision", 0) or 0) + 1,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="browser_start_reserved",
                payload={
                    "provider": "playwright",
                    "attempt": next_attempt,
                    "authentication_substate": "submitted" if sensitive else "not_submitted",
                    "external_actions": False,
                },
            )
        if not reserved:
            if sensitive is not None:
                sensitive.clear()
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_start_reconciliation_required",
            )

        try:
            context = asyncio.run(
                worker.start(
                    None,
                    recipe=recipe,
                    app_slug=recipe.app_slug,
                    account_ref=browser_account_ref,
                    secret_scope=run_id,
                    use_storage_state=True,
                    live_view_mode="interactive_remote",
                )
            )
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id=context.session_id,
            )
        except Exception as exc:
            with contextlib.suppress(Exception):
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status="failed",
                )
            if sensitive is not None:
                sensitive.clear()
            return self._record_provider_failure(
                run_id,
                status=(
                    "configuration_required"
                    if isinstance(exc, ConfigurationRequiredError)
                    else "failed"
                ),
                phase="browser_start_failed",
                reason_code=_safe_reason(exc, "browser_start_failed"),
                external_actions=True,
            )

        provider_session = context.session_id
        session_getter = getattr(worker, "provider_session_id", None)
        if callable(session_getter):
            with contextlib.suppress(Exception):
                provider_session = str(session_getter(context.session_id) or context.session_id)
        with self._context.storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            transaction.update_run(
                run_id,
                status="browser_running",
                browser_session_id=context.session_id,
                provider_session_id=provider_session,
                phase="authentication_submitted" if sensitive else "browser_running",
                reason_code="browser_session_started",
                provider_status={
                    "recipe": recipe.readiness_tier,
                    "composio": "not_started",
                    "browser": "running",
                    "email": "not_started",
                    "validation": "not_started",
                },
                external_actions=True,
                state_revision=int(current.get("state_revision", 0) or 0) + 1,
                last_projected_revision=int(current.get("state_revision", 0) or 0) + 1,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="browser_session_started",
                payload={
                    "provider": "playwright",
                    "status": "browser_running",
                    "live_view_available": context.live_view_available,
                    "external_actions": True,
                },
            )
            updated = transaction.get_run(run_id)
            if updated is None:  # pragma: no cover
                raise RuntimeError("browser run disappeared")

        thread = threading.Thread(
            target=self._drive_browser,
            kwargs={
                "run_id": run_id,
                "context": context,
                "request": request,
                "research": research,
                "recipe": recipe,
                "sensitive": sensitive,
            },
            name=f"canonical-browser-{run_id[:16]}",
            daemon=True,
        )
        self._context._browser_threads = [
            item for item in self._context._browser_threads if item.is_alive()
        ]
        self._context._browser_threads.append(thread)
        thread.start()
        return _public_run(updated)

    def retry_browser_run(self, run_id: str) -> dict[str, Any]:
        """Start a fresh Playwright attempt after a recoverable browser failure.

        Login values are intentionally not reused. Each attempt receives a new
        effect identity, while capture reconciliation remains bound to the run so
        a retry cannot duplicate a credential-generation side effect.
        """

        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "retry_browser")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("route_kind") != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")
            if current.get("browser_provider") != "playwright":
                raise CredentialSubmissionError("playwright_required_for_recipe")
            if current.get("status") not in {"failed", "configuration_required"}:
                raise CredentialSubmissionError("browser_retry_not_available")
            if current.get("phase") not in {
                "browser_unavailable",
                "browser_start_failed",
                "failed",
                "session_lost",
            }:
                raise CredentialSubmissionError("browser_retry_requires_reconciliation")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")
            request_payload = current.get("request")
            research_payload = current.get("operational_research")
            if not isinstance(request_payload, Mapping) or not isinstance(
                research_payload, Mapping
            ):
                raise CredentialSubmissionError("run_state_incomplete")
            request = OperationsRequest.model_validate(dict(request_payload))
            research = OperationalResearch.model_validate(dict(research_payload))
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=recipe,
                browser_login=None,
                attempt=int(current.get("attempt", 0) or 0) + 1,
            )
        finally:
            lock.release()

    def _drive_browser(
        self,
        *,
        run_id: str,
        context: BrowserSessionContext,
        request: OperationsRequest,
        research: OperationalResearch,
        recipe: AppRecipe,
        sensitive: dict[str, str] | None,
    ) -> None:
        worker = self._context._browser_worker_for("playwright")
        if worker is None:
            self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="playwright_not_configured",
            )
            return
        try:
            observation = asyncio.run(
                worker.navigate_onboarding(
                    context,
                    research,
                    recipe=recipe,
                    sensitive_data=sensitive,
                    account_creation_requested=request.account_creation_requested,
                    credential_creation_policy=request.credential_creation_policy,
                )
            )
        except Exception as exc:
            observation = BrowserObservation(
                status="failed",
                current_url="https://unknown.invalid/",
                page_title="Browser step",
                reason_code=_safe_reason(exc, "browser_navigation_failed"),
            )
        finally:
            if sensitive is not None:
                sensitive.clear()
        self._apply_browser_observation(
            run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
        )

    def _resolve_browser_outcome(
        self,
        *,
        run_id: str,
        observation: BrowserObservation,
        research: OperationalResearch,
        request: OperationsRequest,
        recipe: AppRecipe,
        context: BrowserSessionContext,
    ) -> _AppliedBrowserOutcome:
        if observation.status == "human_action_required":
            hitl = {
                "type": observation.human_action_type or "login_required",
                "message": observation.human_instruction or "Complete the browser step.",
                "expected_completion_signal": "human_completed",
                "live_view_available": True,
            }
            return _AppliedBrowserOutcome(
                status="waiting_for_hitl",
                phase="challenge_pending",
                reason_code=observation.reason_code or "human_action_required",
                provider_browser="waiting_for_hitl",
                hitl=hitl,
                events=(("browser_hitl_required", hitl),),
            )
        if observation.status == "blocked":
            return _AppliedBrowserOutcome(
                status="blocked",
                phase="blocked",
                reason_code=observation.reason_code or "browser_policy_blocked",
                provider_browser="blocked",
            )
        if observation.status == "failed":
            return _AppliedBrowserOutcome(
                status="failed",
                phase="failed",
                reason_code=observation.reason_code or "browser_navigation_failed",
                provider_browser="failed",
            )
        if observation.status not in {"credential_page_ready", "developer_console_ready"}:
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="target_probe_pending",
                reason_code=observation.reason_code or "browser_navigation_in_progress",
                provider_browser="running",
            )

        if (
            recipe.browser is not None
            and recipe.browser.scope == "entry_only"
            and observation.status == "developer_console_ready"
        ):
            entry_event = (
                "browser_entry_reached",
                {
                    "status": "browser_running",
                    "reason_code": "reviewed_public_entry_reached",
                    "external_actions": True,
                },
            )
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="entry_reached",
                reason_code="owner_credential_submission_available",
                provider_browser="entry_reached",
                events=(entry_event,),
            )

        ready_event = (
            "credential_page_ready",
            {
                "status": "browser_running",
                "reason_code": "reviewed_success_predicate_satisfied",
                "external_actions": True,
            },
        )
        if recipe.capture.mode != "automatic":
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="owner_credential_submission_required",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )

        worker = self._context._browser_worker_for("playwright")
        capture = getattr(worker, "auto_capture_credentials", None)
        if not callable(capture):
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="automatic_capture_unavailable",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )

        effect_identity = f"{run_id}:credential-capture:v1"
        with self._context.storage.unit_of_work() as transaction:
            _intent, reserved = transaction.reserve_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                provider="playwright_vault",
            )
            current = transaction.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            transaction.update_run(
                run_id,
                phase="credential_capture_reserved",
                reason_code="credential_capture_reserved",
                effect_identity=effect_identity,
                state_revision=int(current.get("state_revision", 0) or 0) + 1,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="credential_capture_reserved",
                payload={"provider": "playwright", "external_actions": False},
            )
        if not reserved:
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="credential_capture_reconciliation_required",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )
        try:
            refs = asyncio.run(
                capture(
                    context.session_id,
                    recipe.app_slug,
                    self._context._secret_store,
                    recipe=recipe,
                )
            )
        except Exception:
            # The service may have vaulted the value before its response was lost.
            # Retrying then could create an orphaned duplicate, so fail closed.
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="outcome_unknown",
            )
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="credential_capture_outcome_unknown",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )
        if not refs:
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id="no_credential_found",
            )
            return _AppliedBrowserOutcome(
                status="browser_running",
                phase="credential_ready",
                reason_code="automatic_capture_failed_owner_submission_available",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )
        try:
            final = self._context._finalize_captured_credentials(
                research,
                request,
                refs,
                recipe=recipe,
            )
        except Exception:
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id="credential_vaulted",
            )
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="credential_validation_failed",
                reason_code="credential_finalization_failed",
                provider_browser="credential_page_ready",
                events=(ready_event,),
            )
        self._context.storage.update_side_effect(
            run_id=run_id,
            operation_key=effect_identity,
            status="completed",
            external_id="credential_vaulted",
        )
        changes: dict[str, object] = {}
        if final.bundle is not None:
            changes["integrator_bundle"] = final.bundle
        return _AppliedBrowserOutcome(
            status=cast(RunStatus, final.status),
            phase="completed" if final.status == "completed" else "credential_ready",
            reason_code=final.reason_code,
            provider_browser="credential_page_ready",
            changes=changes,
            events=(ready_event, *tuple(final.events)),
        )

    def _apply_browser_observation(
        self,
        run_id: str,
        *,
        observation: BrowserObservation,
        research: OperationalResearch,
        request: OperationsRequest,
        recipe: AppRecipe,
        context: BrowserSessionContext,
    ) -> dict[str, Any] | None:
        # Capture/validation are provider operations and therefore finish before
        # the transaction below is opened.
        outcome = self._resolve_browser_outcome(
            run_id=run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
        )
        lock = self._context._run_lock(run_id)
        with lock:
            current = self._context.storage.get_run(run_id)
            if current is None or current.get("status") not in {
                "browser_running",
                "waiting_for_hitl",
            }:
                return None
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    return None
                revision = int(record.get("state_revision", 0) or 0) + 1
                changes: dict[str, object] = {
                    "status": outcome.status,
                    "phase": outcome.phase,
                    "reason_code": outcome.reason_code,
                    "route_reason_code": outcome.reason_code,
                    "hitl_request": outcome.hitl,
                    "provider_status": {
                        "recipe": recipe.readiness_tier,
                        "composio": "not_started",
                        "browser": outcome.provider_browser,
                        "email": "not_started",
                        "validation": ("ready" if outcome.status == "completed" else "not_started"),
                    },
                    "external_actions": True,
                    "state_revision": revision,
                    "last_projected_revision": revision,
                    **dict(outcome.changes or {}),
                }
                updated = transaction.update_run(run_id, **changes)
                for event_type, payload in outcome.events:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type=event_type,
                        payload={**dict(payload), "external_actions": True},
                    )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="browser_outcome_recorded",
                    payload={
                        "status": outcome.status,
                        "phase": outcome.phase,
                        "reason_code": outcome.reason_code,
                        "external_actions": True,
                    },
                )
        if outcome.status in {"completed", "failed", "blocked", "configuration_required"}:
            self._context._release_browser_session(
                context,
                "playwright",
                reason=f"canonical_{outcome.status}",
            )
        log_event("canonical.browser.applied", run_id=run_id, status=outcome.status)
        return _public_run(updated)

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str,
        browser_login: Mapping[str, SecretStr] | None,
    ) -> dict[str, Any]:
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("status") != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            if current.get("browser_provider") != "playwright":
                raise CredentialSubmissionError("playwright_required_for_recipe")
            try:
                validate_browser_account_ref(current.get("browser_account_ref"))
            except ValueError:
                raise CredentialSubmissionError("browser_account_binding_missing") from None
            worker = self._context._browser_worker_for("playwright")
            context = self._context._session_context_for(run_id)
            if worker is None or context is None:
                return self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="session_lost",
                    reason_code="session_lost",
                )
            research = OperationalResearch.model_validate(current.get("operational_research"))
            request = OperationsRequest.model_validate(current.get("request"))
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")

            sensitive: dict[str, str] | None = None
            # Resume never reuses credentials implicitly. Only an explicit owner
            # submission may inject a new value into the existing session.
            if browser_login:
                sensitive = self._context._browser_login_payload(
                    provider="playwright",
                    app_slug=recipe.app_slug,
                    scope_id=run_id,
                    values=browser_login,
                )
            attempt = int(current.get("attempt", 0) or 0) + 1
            effect_identity = f"{run_id}:browser-resume:{attempt}"
            with self._context.storage.unit_of_work() as transaction:
                _intent, reserved = transaction.reserve_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    provider="playwright",
                )
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="authentication_submitted" if sensitive else "target_probe_pending",
                    reason_code="resume_reserved",
                    effect_identity=effect_identity,
                    attempt=attempt,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
            if not reserved:
                raise CredentialSubmissionError("resume_reconciliation_required")
            try:
                observation = asyncio.run(
                    worker.resume_after_hitl(
                        context,
                        signal,
                        research,
                        recipe=recipe,
                        sensitive_data=sensitive,
                        credential_creation_policy=request.credential_creation_policy,
                        provider_session_id=str(current.get("provider_session_id") or "") or None,
                    )
                )
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status="completed",
                )
            except Exception as exc:
                with contextlib.suppress(Exception):
                    self._context.storage.update_side_effect(
                        run_id=run_id,
                        operation_key=effect_identity,
                        status="failed",
                    )
                observation = BrowserObservation(
                    status="failed",
                    current_url="https://unknown.invalid/",
                    page_title="Browser resume",
                    reason_code=_safe_reason(exc, "browser_resume_failed"),
                )
            finally:
                if sensitive is not None:
                    sensitive.clear()
            result = self._apply_browser_observation(
                run_id,
                observation=observation,
                research=research,
                request=request,
                recipe=recipe,
                context=context,
            )
            if result is None:
                raise RunConflictError(run_id, "resume")
            return result
        finally:
            lock.release()

    def connect_managed_run(self, run_id: str) -> dict[str, Any]:
        provider = self._context._managed_auth_provider
        settings = self._context._settings
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "connect")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "connection_required":
                raise CredentialSubmissionError("run_not_awaiting_connection")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "managed_auth":
                raise CredentialSubmissionError("run_is_not_managed_auth")
            if provider is None:
                raise CredentialSubmissionError("composio_managed_auth_not_configured")
            callback_base = getattr(settings, "managed_auth_callback_base_url", None)
            if not isinstance(callback_base, str) or not callback_base:
                raise CredentialSubmissionError("managed_auth_callback_not_configured")
            effect_identity = f"{run_id}:managed-connect:v1"
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="connection_starting",
                    reason_code="connection_start_reserved",
                    effect_identity=effect_identity,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_reserved",
                    payload={"status": "connection_required", "external_actions": False},
                )
            # Provider I/O occurs only after the intent transaction has committed.
            try:
                started = asyncio.run(
                    provider.start_connection(
                        toolkit_slug=recipe.toolkit_slug,
                        callback_url=f"{callback_base.rstrip('/')}/runs/{run_id}",
                        effect_identity=effect_identity,
                    )
                )
            except Exception as exc:
                reason = _safe_reason(exc, "managed_connection_start_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="connection_required",
                        phase="connection_start_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="managed_connection_failed",
                        payload={
                            "status": "connection_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                transaction.update_run(
                    run_id,
                    status="connection_required",
                    connection_request_id=started.connection_request_id,
                    phase="waiting_for_connection",
                    reason_code="managed_connection_pending",
                    provider_status={
                        "recipe": recipe.readiness_tier,
                        "composio": "pending",
                        "browser": "not_started",
                        "email": "not_started",
                        "validation": "not_started",
                    },
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_started",
                    payload={
                        "status": "connection_required",
                        "replayed": started.replayed,
                        "external_actions": True,
                    },
                )
                updated = transaction.get_run(run_id)
                if updated is None:  # pragma: no cover
                    raise RuntimeError("managed run disappeared")
            return {
                "run": _public_run(updated),
                "connection_request_id": started.connection_request_id,
                "redirect_url": started.redirect_url,
                "replayed": started.replayed,
                "state": "pending",
            }
        finally:
            lock.release()

    def poll_managed_connection(self, run_id: str) -> dict[str, Any]:
        provider = self._context._managed_auth_provider
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "poll_connection")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "connection_required":
                raise CredentialSubmissionError("run_not_awaiting_connection")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "managed_auth":
                raise CredentialSubmissionError("run_is_not_managed_auth")
            if provider is None:
                raise CredentialSubmissionError("composio_managed_auth_not_configured")
            request_id = current.get("connection_request_id")
            if not isinstance(request_id, str) or not request_id:
                raise CredentialSubmissionError("connection_request_missing")
            # Read provider state outside a database transaction.
            try:
                polled = asyncio.run(provider.poll_connection(request_id))
            except Exception as exc:
                reason = _safe_reason(exc, "connection_poll_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="connection_required",
                        phase="connection_poll_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="managed_connection_poll_failed",
                        payload={
                            "status": "connection_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None
            status: RunStatus = (
                "completed"
                if polled.state == "active"
                else "failed"
                if polled.state == "terminal"
                else "connection_required"
            )
            phase = (
                "completed"
                if polled.state == "active"
                else "connection_failed"
                if polled.state == "terminal"
                else "waiting_for_connection"
            )
            bundle: dict[str, object] | None = None
            if polled.state == "active":
                research = OperationalResearch.model_validate(current.get("operational_research"))
                request = OperationsRequest.model_validate(current.get("request"))
                bundle = build_integrator_bundle(
                    research=research,
                    company=request.company,
                    credential_refs={},
                    validation=None,
                    stage="managed_connection_ready",
                    provider_account_id=request_id,
                    operational_notes=("Composio reported the managed connected account ACTIVE.",),
                ).model_dump(mode="json")
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                updated = transaction.update_run(
                    run_id,
                    status=status,
                    phase=phase,
                    reason_code=polled.reason_code,
                    provider_status={
                        "recipe": record.get("readiness_tier"),
                        "composio": polled.state,
                        "browser": "not_started",
                        "email": "not_started",
                        "validation": "ready" if polled.state == "active" else "not_started",
                    },
                    integrator_bundle=bundle,
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="managed_connection_polled",
                    payload={
                        "status": status,
                        "connection_state": polled.state,
                        "reason_code": polled.reason_code,
                        "external_actions": True,
                    },
                )
                if bundle is not None:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="integrator_bundle_generated",
                        payload={
                            "readiness": "credentials_ready",
                            "auth_scheme": "oauth2",
                            "credential_ref_count": 0,
                            "external_actions": True,
                        },
                    )
            return {
                "run": _public_run(updated),
                "connection_request_id": request_id,
                "redirect_url": None,
                "replayed": False,
                "state": polled.state,
            }
        finally:
            lock.release()

    def send_gated_outreach(self, run_id: str) -> dict[str, Any]:
        """Send one explicitly requested, controlled-sink outreach operation."""

        gmail = self._context._gmail_worker
        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "send_outreach")
        try:
            current = self._context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("execution_mode") != "operations":
                raise CredentialSubmissionError("plan_only_run_is_read_only")
            if current.get("status") != "route_selected":
                raise CredentialSubmissionError("run_not_awaiting_outreach")
            recipe = self._recipe_for_run(current)
            if recipe.route_kind != "gated":
                raise CredentialSubmissionError("run_is_not_gated")
            if gmail is None:
                raise CredentialSubmissionError("gmail_not_configured")
            request_payload = current.get("request")
            if not isinstance(request_payload, Mapping):
                raise CredentialSubmissionError("run_request_missing")
            request = OperationsRequest.model_validate(dict(request_payload))
            try:
                route = GatedRoute(recipe=recipe, request=request, gmail=gmail)
            except GatedRoutePolicyError as exc:
                raise CredentialSubmissionError(exc.reason_code) from None

            effect_identity = f"{run_id}:gated-outreach:v1"
            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="outreach_sending",
                    reason_code="outreach_send_reserved",
                    effect_identity=effect_identity,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_send_reserved",
                    payload={"status": "route_selected", "external_actions": False},
                )

            try:
                receipt = asyncio.run(route.send_outreach(effect_identity=effect_identity))
            except Exception as exc:
                reason = _safe_reason(exc, "outreach_send_failed")
                with self._context.storage.unit_of_work() as transaction:
                    record = transaction.get_run(run_id)
                    if record is None:
                        raise KeyError("run was not found") from None
                    revision = int(record.get("state_revision", 0) or 0) + 1
                    transaction.update_run(
                        run_id,
                        status="configuration_required",
                        phase="outreach_send_failed",
                        reason_code=reason,
                        external_actions=True,
                        state_revision=revision,
                        last_projected_revision=revision,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="outreach_send_failed",
                        payload={
                            "status": "configuration_required",
                            "reason_code": reason,
                            "external_actions": True,
                        },
                    )
                raise CredentialSubmissionError(reason) from None

            with self._context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                updated = transaction.update_run(
                    run_id,
                    status="waiting_for_reply",
                    phase="waiting_for_reply",
                    reason_code="controlled_outreach_sent",
                    gmail_session_id=receipt.session_id,
                    gmail_thread_id=receipt.thread_id,
                    provider_status={
                        "recipe": recipe.readiness_tier,
                        "composio": "not_started",
                        "browser": "not_started",
                        "email": "waiting_for_reply",
                        "validation": "not_started",
                    },
                    external_actions=True,
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="outreach_sent",
                    payload={
                        "status": "waiting_for_reply",
                        "template_id": route.target.template_id,
                        "recipient_overridden": (
                            receipt.actual_recipient != receipt.intended_recipient
                        ),
                        "external_actions": True,
                    },
                )
            return _public_run(updated)
        finally:
            lock.release()

    def _record_provider_failure(
        self,
        run_id: str,
        *,
        status: RunStatus,
        phase: str,
        reason_code: str,
        external_actions: bool = False,
    ) -> dict[str, Any]:
        with self._context.storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            revision = int(current.get("state_revision", 0) or 0) + 1
            updated = transaction.update_run(
                run_id,
                status=status,
                phase=phase,
                reason_code=reason_code,
                route_reason_code=reason_code,
                provider_status={
                    "recipe": current.get("readiness_tier"),
                    "composio": "not_started",
                    "browser": "failed" if status == "failed" else "configuration_required",
                    "email": "not_started",
                    "validation": "not_started",
                },
                external_actions=bool(current.get("external_actions")) or external_actions,
                state_revision=revision,
                last_projected_revision=revision,
            )
            transaction.append_audit_event(
                run_id=run_id,
                event_type="provider_operation_failed",
                payload={
                    "status": status,
                    "phase": phase,
                    "reason_code": reason_code,
                    "external_actions": external_actions,
                },
            )
        return _public_run(updated)


__all__ = ["CanonicalRuntime", "CanonicalRuntimeContext", "recipe_to_operational_research"]
