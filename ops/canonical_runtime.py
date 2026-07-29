"""Canonical SQLite-backed execution for reviewed app recipes.

New runs use this service directly.  The database transaction boundary is kept
deliberately small: intent/state is committed first, provider I/O happens with no
SQLite transaction open, and the sanitized outcome is appended afterward.  Raw
credentials cross only the existing one-shot Playwright/vault boundaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
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
from ops.browser_readiness import browser_configuration_state
from ops.browser_signup import normalize_signup_fields
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    BrowserWorker,
    HumanActionType,
)
from ops.composio_managed_auth import (
    ComposioManagedAuthProvider,
    validate_managed_auth_callback_base_url,
)
from ops.gated_route import GatedRoute, GatedRoutePolicyError
from ops.integrator import build_integrator_bundle
from ops.models import OperationalResearch, OperationsRequest
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter
from ops.provider_errors import ConfigurationRequiredError
from ops.run_errors import (
    CredentialSubmissionError,
    IdempotencyConflictError,
    ProviderReadinessError,
    RunConflictError,
)
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
from ops.secret_store import AccountLoginStateError, SQLiteSecretStore, parse_vault_reference
from ops.state import BrowserProvider, RunStatus
from ops.storage import OperationsStorage

ExecutionMode = Literal["plan_only", "execute_when_configured"]
_HUMAN_ACTION_TYPES = frozenset(
    {
        "login_required",
        "captcha",
        "email_otp",
        "phone_otp",
        "passkey",
        "security_key",
        "device_approval",
        "provider_verification",
        "legal_acceptance",
        "billing",
        "account_selection",
    }
)


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

    def _remember_reusable_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        values: Mapping[str, SecretStr],
    ) -> tuple[str, ...]: ...

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def _stage_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
        values: Mapping[str, SecretStr],
    ) -> dict[str, SecretStr]: ...

    def _staged_signup_login_values(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, SecretStr]: ...

    def _promote_staged_signup_login(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> tuple[str, ...]: ...

    def gmail_signup_preflight(self, *, timeout_seconds: float = 10.0) -> Any: ...

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
    # The exact durable operation whose result may still be projected. A worker
    # response arriving after another operation took ownership of the run is
    # discarded instead of overwriting newer state.
    effect_identity: str | None = None
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


def _signup_fields_for(request: OperationsRequest) -> dict[str, str]:
    """Project the approved non-secret company fields into the browser contract."""

    if not request.account_creation_requested:
        return {}
    values: dict[str, object] = {
        "company_name": request.company.legal_name,
        "company_website": request.company.website,
        "use_case": request.company.use_case,
    }
    if request.company.expected_volume:
        values["expected_volume"] = request.company.expected_volume
    return normalize_signup_fields(values)


class CanonicalRuntime:
    """Execute managed, Playwright and gated recipes without LangGraph."""

    def __init__(self, context: CanonicalRuntimeContext) -> None:
        self._context = context

    @staticmethod
    def _requires_broker_grants(worker: object) -> bool:
        return bool(getattr(worker, "requires_secret_broker_grants", False))

    def _discard_pre_dispatch_browser_secrets(
        self,
        *,
        sensitive: dict[str, str] | None,
        app_slug: str,
        run_id: str,
        transient: bool,
    ) -> None:
        """Best-effort rollback for a payload that never reached the worker.

        The scoped store operation can only delete an unconsumed one-time row
        matching this exact run, app, and browser-login field. Durable/reusable
        credentials are therefore outside the deletion surface. Callers must
        transfer ownership to the worker immediately before invoking navigation
        or resume and must never use this rollback after that point.
        """

        if sensitive is None:
            return
        try:
            store = self._context._secret_store
            if transient and store is not None:
                for field_name, reference in tuple(sensitive.items()):
                    with contextlib.suppress(Exception):
                        store.delete_transient(
                            reference,
                            expected_app_slug=app_slug,
                            expected_kind=f"browser_login_{field_name}",
                            expected_scope_id=run_id,
                        )
        finally:
            sensitive.clear()

    def _reserve_consume_grants_locked(
        self,
        *,
        worker: object,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        references: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Reserve exact one-time-secret grants while the caller owns the run lock."""

        if not self._requires_broker_grants(worker):
            return {}
        if not references:
            return {}
        store = self._context._secret_store
        if store is None:
            raise CredentialSubmissionError("secret_vault_required_for_browser_service")
        grants: dict[str, str] = {}
        for field_name, reference in references.items():
            expected_kind = f"browser_login_{field_name}"
            try:
                parts = parse_vault_reference(reference)
            except ValueError:
                raise CredentialSubmissionError("malformed_vault_reference") from None
            if parts.app_slug != app_slug or parts.kind != expected_kind:
                raise CredentialSubmissionError("browser_secret_reference_binding_mismatch")
            grants[field_name] = store.reserve_browser_secret_grant(
                operation_key=f"{operation_key}:consume:{field_name}",
                run_id=run_id,
                session_id=session_id,
                app_slug=app_slug,
                kind=expected_kind,
                action="consume",
                reference=reference,
            )
        return grants

    def _reserve_capture_grant_locked(
        self,
        *,
        worker: object,
        operation_key: str,
        run_id: str,
        session_id: str,
        recipe: AppRecipe,
    ) -> str | None:
        """Reserve one idempotent automatic-capture grant under the run lock."""

        if not self._requires_broker_grants(worker):
            return None
        store = self._context._secret_store
        field_kind = recipe.capture.field_name
        if store is None or not field_kind:
            raise CredentialSubmissionError("automatic_capture_grant_unavailable")
        return store.reserve_browser_secret_grant(
            operation_key=f"{operation_key}:capture:{field_kind}",
            run_id=run_id,
            session_id=session_id,
            app_slug=recipe.app_slug,
            kind=field_kind,
            action="capture",
        )

    def _bound_browser_record_locked(
        self,
        *,
        run_id: str,
        session_id: str,
        statuses: frozenset[str],
        phases: frozenset[str] | None = None,
        effect_identity: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the authoritative row only while the exact browser op owns it.

        The caller must hold the per-run lock. This small predicate is shared by
        reservation and projection so a delayed worker response cannot be applied
        to a replacement session or a later operation that happens to use the same
        broad phase name.
        """

        record = self._context.storage.get_run(run_id)
        if record is None:
            return None
        if (
            record.get("state_engine") != "canonical_v1"
            or record.get("browser_provider") != "playwright"
            or record.get("browser_session_id") != session_id
            or str(record.get("status") or "") not in statuses
            or (phases is not None and str(record.get("phase") or "") not in phases)
            or (effect_identity is not None and record.get("effect_identity") != effect_identity)
        ):
            return None
        return record

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

    def _continue_pristine_playwright_run(
        self,
        record: Mapping[str, Any],
        *,
        browser_login: Mapping[str, SecretStr] | None,
    ) -> dict[str, Any] | None:
        """Dispatch a committed Playwright run whose first effect never started.

        A durable run can exist before login staging/browser dispatch because
        provider I/O intentionally happens after the creation transaction. Only
        the pristine ``attempt=0`` state with no reserved effect is safe to
        continue automatically. Any evidence that an effect was reserved is an
        unknown-outcome boundary and is moved to explicit reconciliation.
        """

        if (
            record.get("state_engine") != "canonical_v1"
            or record.get("execution_mode") != "operations"
            or record.get("route_kind") != "playwright"
            or record.get("browser_provider") != "playwright"
            or record.get("status") != "route_selected"
        ):
            return None
        run_id = str(record.get("run_id") or "")
        if not run_id:
            return None
        attempt = int(record.get("attempt", 0) or 0)
        first_effect = self._context.storage.get_side_effect(
            run_id,
            f"{run_id}:browser-start:v1",
        )
        phase = str(record.get("phase") or "")
        if (
            attempt != 0
            or first_effect is not None
            or bool(record.get("effect_identity"))
            or phase != "browser_pending"
        ):
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_start_reconciliation_required",
                external_actions=first_effect is not None,
            )

        recipe = self._recipe_for_run(record)
        request_payload = record.get("request")
        research_payload = record.get("operational_research")
        if not isinstance(request_payload, Mapping) or not isinstance(research_payload, Mapping):
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="run_state_incomplete",
            )
        request = OperationsRequest.model_validate(dict(request_payload))
        research = OperationalResearch.model_validate(dict(research_payload))
        try:
            account_ref = validate_browser_account_ref(record.get("browser_account_ref"))
        except ValueError:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="browser_account_binding_missing",
            )

        retry_login: Mapping[str, SecretStr] | None = None
        staged_existing = False
        if request.account_creation_requested:
            retry_login = self._context._staged_signup_login_values(
                app_slug=recipe.app_slug,
                account_ref=account_ref,
                run_id=run_id,
            )
            if not retry_login:
                signup_address = getattr(self._context._settings, "gmail_signup_address", None)
                if signup_address is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code="gmail_signup_address_not_configured",
                    )
                try:
                    retry_login = self._context._stage_signup_login(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                        values={
                            "login_email": SecretStr(signup_address.get_secret_value()),
                            "login_password": SecretStr(f"Rr7!{secrets.token_urlsafe(24)}"),
                        },
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code=_safe_reason(exc, "signup_login_vault_required"),
                    )
        else:
            store = self._context._secret_store
            staged_values = (
                store.get_staged_existing_login_pair(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if store is not None
                else {}
            )
            if set(staged_values) == {"login_email", "login_password"}:
                staged_existing = True
                retry_login = {
                    field: SecretStr(staged_values[field])
                    for field in ("login_email", "login_password")
                }
            elif browser_login:
                if store is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_vault_required",
                    )
                try:
                    staged_values = store.stage_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                        email=browser_login["login_email"].get_secret_value(),
                        password=browser_login["login_password"].get_secret_value(),
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code=_safe_reason(exc, "existing_login_stage_failed"),
                    )
                staged_existing = True
                retry_login = {
                    field: SecretStr(staged_values[field])
                    for field in ("login_email", "login_password")
                }
            else:
                retry_login = self._context._reusable_login_values(
                    recipe.app_slug,
                    account_ref,
                )
                if (
                    not retry_login
                    and store is not None
                    and bool(
                        getattr(
                            self._context._settings,
                            "browser_login_credential_reuse",
                            True,
                        )
                    )
                ):
                    try:
                        selected = store.get_unique_account_login_pair(app_slug=recipe.app_slug)
                    except AccountLoginStateError as exc:
                        return self._record_provider_failure(
                            run_id,
                            status="configuration_required",
                            phase="login_account_selection",
                            reason_code=exc.reason_code,
                        )
                    except Exception:
                        return self._record_provider_failure(
                            run_id,
                            status="configuration_required",
                            phase="login_account_selection",
                            reason_code="stored_login_lookup_failed",
                        )
                    if selected is not None:
                        selected_account_ref, selected_values = selected
                        if selected_account_ref != account_ref:
                            # The account binding is immutable once the run is
                            # committed. Guessing a different profile during crash
                            # recovery could cross account state, so require a new
                            # explicit run instead.
                            return self._record_provider_failure(
                                run_id,
                                status="configuration_required",
                                phase="login_account_selection",
                                reason_code="stored_login_account_binding_mismatch",
                            )
                        retry_login = {
                            field: SecretStr(selected_values[field])
                            for field in ("login_email", "login_password")
                        }

        return self._start_playwright(
            run_id,
            request=request,
            research=research,
            recipe=recipe,
            browser_login=retry_login,
            attempt=1,
            use_storage_state=not staged_existing,
        )

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

        def replay(
            existing: tuple[dict[str, Any], str] | None,
        ) -> dict[str, Any] | None:
            if existing is None:
                return None
            record, stored_fingerprint = existing
            legacy_match = stored_fingerprint in _legacy_request_fingerprints(
                request, execution_mode
            )
            if stored_fingerprint != fingerprint and not legacy_match:
                raise IdempotencyConflictError(
                    "idempotency key was already used for another request"
                )
            return _public_run(record)

        # A retry of an already-committed request must remain available even if a
        # provider is temporarily down. This read is repeated under the write
        # transaction below to close the concurrent-create race.
        if validated_key is not None:
            existing = self._context.storage.get_idempotent_run(validated_key)
            existing_replay = replay(existing)
            if existing_replay is not None:
                assert existing is not None
                replayed_record = existing[0]
                run_id = str(replayed_record.get("run_id") or "")
                lock = self._context._run_lock(run_id)
                if not lock.acquire(blocking=False):
                    return existing_replay
                try:
                    current = self._context.storage.get_run(run_id)
                    if current is None:
                        raise KeyError("run was not found")
                    continued = self._continue_pristine_playwright_run(
                        current,
                        browser_login=browser_login,
                    )
                    return continued if continued is not None else _public_run(current)
                finally:
                    lock.release()

        executable_signup = (
            execution_mode != "plan_only" and request.account_mode == "create_account"
        )
        if executable_signup:
            if recipe.route_kind != "playwright" or recipe.urls.signup is None:
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="reviewed_signup_recipe_not_available",
                )
            if request.browser_provider != "playwright":
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="playwright_required_for_reviewed_signup",
                )
            if not browser_configuration_state(self._context._settings, "playwright"):
                raise ProviderReadinessError(
                    provider="playwright",
                    reason_code="playwright_configuration_required",
                )
            signup_address = getattr(self._context._settings, "gmail_signup_address", None)
            if signup_address is None:
                raise ProviderReadinessError(
                    provider="gmail",
                    reason_code="gmail_signup_address_not_configured",
                )
            preflight = self._context.gmail_signup_preflight(
                timeout_seconds=float(
                    getattr(
                        self._context._settings,
                        "gmail_signup_preflight_timeout_seconds",
                        10.0,
                    )
                )
            )
            if not bool(getattr(preflight, "ready", False)):
                raise ProviderReadinessError(
                    provider="gmail",
                    reason_code=str(
                        getattr(
                            preflight,
                            "reason_code",
                            "gmail_signup_preflight_failed",
                        )
                    ),
                )

        run_id = f"run_{uuid4().hex}"
        thread_id = f"sqlite_{uuid4().hex}"
        submitted_existing_login = (
            browser_login if request.account_mode == "existing_account" and browser_login else None
        )
        stored_login_selection_error: str | None = None
        binding_login = browser_login
        if request.account_creation_requested:
            signup_address = getattr(self._context._settings, "gmail_signup_address", None)
            if signup_address is not None:
                # Bind every retry and later run for this generated vendor identity
                # to the same opaque account scope without persisting the address.
                binding_login = {"login_email": signup_address}
        browser_account_ref = (
            derive_browser_account_ref(
                run_id=run_id,
                app_slug=recipe.app_slug,
                work_email_ref=request.company.work_email_ref,
                browser_login=binding_login,
                binding_secret=getattr(self._context._settings, "secret_vault_key", None),
            )
            if recipe.route_kind == "playwright"
            else None
        )
        if (
            execution_mode != "plan_only"
            and recipe.route_kind == "playwright"
            and request.account_mode == "existing_account"
            and browser_login is None
            and bool(
                getattr(
                    self._context._settings,
                    "browser_login_credential_reuse",
                    True,
                )
            )
            and self._context._secret_store is not None
        ):
            try:
                selected = self._context._secret_store.get_unique_account_login_pair(
                    app_slug=recipe.app_slug
                )
            except AccountLoginStateError as exc:
                stored_login_selection_error = exc.reason_code
            except Exception:
                stored_login_selection_error = "stored_login_lookup_failed"
            else:
                if selected is not None:
                    selected_account_ref, selected_values = selected
                    try:
                        browser_account_ref = validate_browser_account_ref(selected_account_ref)
                    except ValueError:
                        stored_login_selection_error = "stored_login_account_binding_invalid"
                    else:
                        if set(selected_values) != {"login_email", "login_password"}:
                            stored_login_selection_error = "stored_login_pair_incomplete"
                        else:
                            browser_login = {
                                field: SecretStr(selected_values[field])
                                for field in ("login_email", "login_password")
                            }
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
                existing_replay = replay(transaction.get_idempotent_run(validated_key))
                if existing_replay is not None:
                    return existing_replay

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
            if stored_login_selection_error is not None:
                return self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="login_account_selection",
                    reason_code=stored_login_selection_error,
                )
            if submitted_existing_login is not None:
                store = self._context._secret_store
                if store is None:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_vault_required",
                    )
                try:
                    staged_existing = store.stage_existing_login_pair(
                        app_slug=persisted_recipe.app_slug,
                        account_ref=validate_browser_account_ref(browser_account_ref),
                        run_id=run_id,
                        email=submitted_existing_login["login_email"].get_secret_value(),
                        password=submitted_existing_login["login_password"].get_secret_value(),
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code=_safe_reason(exc, "existing_login_stage_failed"),
                    )
                if set(staged_existing) != {"login_email", "login_password"}:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="login_credential_staging",
                        reason_code="existing_login_pair_incomplete",
                    )
                browser_login = {
                    field: SecretStr(staged_existing[field])
                    for field in ("login_email", "login_password")
                }
            if request.account_mode == "create_account":
                signup_address = getattr(self._context._settings, "gmail_signup_address", None)
                if signup_address is None:  # pragma: no cover - pre-persistence invariant
                    raise RuntimeError("validated signup address disappeared")
                # Generate the vendor password inside the trusted backend and
                # retain it only in the encrypted run-scoped signup stage. The
                # raw value is passed to the current browser attempt in memory
                # and never enters the request snapshot, run state, or audit.
                generated_login: dict[str, SecretStr] = {
                    "login_email": SecretStr(signup_address.get_secret_value()),
                    "login_password": SecretStr(f"Rr7!{secrets.token_urlsafe(24)}"),
                }
                try:
                    staged_login = self._context._stage_signup_login(
                        app_slug=persisted_recipe.app_slug,
                        account_ref=validate_browser_account_ref(browser_account_ref),
                        run_id=run_id,
                        values=generated_login,
                    )
                except Exception as exc:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code=_safe_reason(exc, "signup_login_vault_required"),
                    )
                if set(staged_login) != {"login_email", "login_password"}:
                    return self._record_provider_failure(
                        run_id,
                        status="configuration_required",
                        phase="signup_identity_required",
                        reason_code="signup_login_pair_incomplete",
                    )
                browser_login = staged_login
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=persisted_recipe,
                browser_login=browser_login,
                use_storage_state=submitted_existing_login is None,
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
        use_storage_state: bool = True,
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
            browser_account_ref = validate_browser_account_ref(persisted.get("browser_account_ref"))
        except ValueError:
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="browser_unavailable",
                reason_code="browser_account_binding_missing",
            )

        sensitive: dict[str, str] | None = None
        transient_secrets = self._requires_broker_grants(worker)
        if browser_login:
            sensitive = self._context._browser_login_payload(
                provider="playwright",
                app_slug=recipe.app_slug,
                scope_id=run_id,
                values=browser_login,
            )

        try:
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
                        "authentication_substate": ("submitted" if sensitive else "not_submitted"),
                        "external_actions": False,
                    },
                )
        except BaseException:
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise
        if not reserved:
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            return self._record_provider_failure(
                run_id,
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_start_reconciliation_required",
            )

        context: BrowserSessionContext | None = None
        try:
            context = asyncio.run(
                worker.start(
                    None,
                    recipe=recipe,
                    app_slug=recipe.app_slug,
                    account_ref=browser_account_ref,
                    secret_scope=run_id,
                    use_storage_state=use_storage_state,
                    live_view_mode="interactive_remote",
                )
            )
            if context is None:
                raise RuntimeError("browser worker returned no session context")
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
                external_id=context.session_id,
            )
        except Exception as exc:
            if context is not None:
                with contextlib.suppress(Exception):
                    self._context._release_browser_session(
                        context,
                        "playwright",
                        reason="canonical_start_pre_dispatch_failed",
                    )
            with contextlib.suppress(Exception):
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status="failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
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
        except BaseException:
            if context is not None:
                with contextlib.suppress(Exception):
                    self._context._release_browser_session(
                        context,
                        "playwright",
                        reason="canonical_start_pre_dispatch_interrupted",
                    )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise

        provider_session = context.session_id
        session_getter = getattr(worker, "provider_session_id", None)
        if callable(session_getter):
            with contextlib.suppress(Exception):
                provider_session = str(session_getter(context.session_id) or context.session_id)
        try:
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
        except BaseException:
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_start_state_persistence_failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise

        thread: threading.Thread | None = None
        try:
            thread = threading.Thread(
                target=self._drive_browser,
                kwargs={
                    "run_id": run_id,
                    "context": context,
                    "request": request,
                    "research": research,
                    "recipe": recipe,
                    "sensitive": sensitive,
                    "transient_secrets": transient_secrets,
                },
                name=f"canonical-browser-{run_id[:16]}",
                daemon=True,
            )
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item.is_alive()
            ]
            self._context._browser_threads.append(thread)
            thread.start()
        except Exception as exc:
            # If a non-standard Thread implementation started and then raised,
            # ownership may already have crossed into ``_drive_browser``. Leave
            # its session and payload alone in that outcome-unknown case.
            if thread is not None and thread.ident is not None:
                raise
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item is not thread
            ]
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_browser_thread_start_failed",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            return self._record_provider_failure(
                run_id,
                status="failed",
                phase="browser_start_failed",
                reason_code=_safe_reason(exc, "browser_dispatch_failed"),
                external_actions=True,
            )
        except BaseException:
            if thread is not None and thread.ident is not None:
                raise
            self._context._browser_threads = [
                item for item in self._context._browser_threads if item is not thread
            ]
            with contextlib.suppress(Exception):
                self._context._release_browser_session(
                    context,
                    "playwright",
                    reason="canonical_browser_thread_start_interrupted",
                )
            self._discard_pre_dispatch_browser_secrets(
                sensitive=sensitive,
                app_slug=recipe.app_slug,
                run_id=run_id,
                transient=transient_secrets,
            )
            raise
        return _public_run(updated)

    def retry_browser_run(self, run_id: str) -> dict[str, Any]:
        """Start a fresh Playwright attempt after a recoverable browser failure.

        Signup and newly submitted existing-account pairs are loaded only from
        this exact run's encrypted stage. Already verified existing-account pairs
        may be loaded from the exact persisted account binding. Each attempt
        receives a new effect identity, while capture reconciliation remains bound
        to the run so a retry cannot duplicate a credential-generation side effect.
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
            if current.get("status") == "route_selected":
                continued = self._continue_pristine_playwright_run(
                    current,
                    browser_login=None,
                )
                if continued is not None:
                    return continued
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
            account_ref = validate_browser_account_ref(current.get("browser_account_ref"))
            staged_existing = False
            if request.account_creation_requested:
                retry_login = self._context._staged_signup_login_values(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if not retry_login:
                    raise CredentialSubmissionError("signup_login_vault_required")
            else:
                store = self._context._secret_store
                staged_values = (
                    store.get_staged_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                    )
                    if store is not None
                    else {}
                )
                staged_existing = set(staged_values) == {
                    "login_email",
                    "login_password",
                }
                retry_login = (
                    {
                        field: SecretStr(staged_values[field])
                        for field in ("login_email", "login_password")
                    }
                    if staged_existing
                    else self._context._reusable_login_values(recipe.app_slug, account_ref)
                )
            return self._start_playwright(
                run_id,
                request=request,
                research=research,
                recipe=recipe,
                browser_login=retry_login,
                attempt=int(current.get("attempt", 0) or 0) + 1,
                use_storage_state=not staged_existing,
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
        transient_secrets: bool,
    ) -> None:
        expected_effect_identity: str | None = None
        navigation_dispatched = False
        try:
            worker = self._context._browser_worker_for("playwright")
            if worker is None:
                self._record_provider_failure(
                    run_id,
                    status="configuration_required",
                    phase="browser_unavailable",
                    reason_code="playwright_not_configured",
                )
                return
            secret_grants: dict[str, str] = {}
            lock = self._context._run_lock(run_id)
            with lock:
                current = self._bound_browser_record_locked(
                    run_id=run_id,
                    session_id=context.session_id,
                    statuses=frozenset({"browser_running"}),
                    phases=(
                        frozenset({"authentication_submitted"})
                        if sensitive
                        else frozenset({"browser_running"})
                    ),
                )
                if current is None:
                    return
                raw_effect_identity = current.get("effect_identity")
                if not isinstance(raw_effect_identity, str) or not raw_effect_identity:
                    return
                expected_effect_identity = raw_effect_identity
                secret_grants = self._reserve_consume_grants_locked(
                    worker=worker,
                    operation_key=expected_effect_identity,
                    run_id=run_id,
                    session_id=context.session_id,
                    app_slug=recipe.app_slug,
                    references=sensitive,
                )
            navigate_kwargs: dict[str, object] = {
                "recipe": recipe,
                "sensitive_data": sensitive,
                "account_creation_requested": request.account_creation_requested,
                "signup_fields": _signup_fields_for(request),
                "credential_creation_policy": request.credential_creation_policy,
            }
            if self._requires_broker_grants(worker):
                navigate_kwargs["secret_grants"] = secret_grants
            navigate = cast(Any, worker.navigate_onboarding)
            navigation_call = navigate(
                context,
                research,
                **navigate_kwargs,
            )
            navigation_dispatched = True
            observation = asyncio.run(navigation_call)
        except Exception as exc:
            observation = BrowserObservation(
                status="failed",
                current_url="https://unknown.invalid/",
                page_title="Browser step",
                reason_code=_safe_reason(exc, "browser_navigation_failed"),
            )
        finally:
            if navigation_dispatched:
                if sensitive is not None:
                    sensitive.clear()
            else:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=recipe.app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
        self._apply_browser_observation(
            run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=expected_effect_identity,
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
        expected_effect_identity: str | None = None,
    ) -> _AppliedBrowserOutcome:
        if observation.status == "human_action_required":
            action_type = observation.human_action_type or "login_required"
            hitl = {
                "type": action_type,
                "message": observation.human_instruction or "Complete the browser step.",
                "expected_completion_signal": "human_completed",
                "live_view_available": True,
            }
            if action_type == "email_otp":
                hitl["verification_requested_at"] = (
                    datetime.now(UTC).isoformat().replace("+00:00", "Z")
                )
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
        if (
            observation.status == "failed"
            and observation.reason_code == "browser_resume_outcome_unknown"
        ):
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="browser_resume_outcome_unknown",
                provider_browser="outcome_unknown",
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
        broker_grant: str | None = None
        lock = self._context._run_lock(run_id)
        with lock:
            current = self._bound_browser_record_locked(
                run_id=run_id,
                session_id=context.session_id,
                statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                effect_identity=expected_effect_identity,
            )
            if current is None:
                return _AppliedBrowserOutcome(
                    status="configuration_required",
                    phase="effect_reconciliation",
                    reason_code="browser_observation_no_longer_current",
                    provider_browser="outcome_unknown",
                    effect_identity=expected_effect_identity,
                    events=(ready_event,),
                )
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
                    status="browser_running",
                    phase="credential_capture_reserved",
                    reason_code="credential_capture_reserved",
                    effect_identity=effect_identity,
                    hitl_request=None,
                    state_revision=int(current.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credential_capture_reserved",
                    payload={"provider": "playwright", "external_actions": False},
                )
            if reserved:
                try:
                    broker_grant = self._reserve_capture_grant_locked(
                        worker=worker,
                        operation_key=effect_identity,
                        run_id=run_id,
                        session_id=context.session_id,
                        recipe=recipe,
                    )
                except Exception as exc:
                    with contextlib.suppress(Exception):
                        self._context.storage.update_side_effect(
                            run_id=run_id,
                            operation_key=effect_identity,
                            status="failed",
                        )
                    return _AppliedBrowserOutcome(
                        status="configuration_required",
                        phase="effect_reconciliation",
                        reason_code=_safe_reason(
                            exc,
                            "automatic_capture_grant_unavailable",
                        ),
                        provider_browser="credential_page_ready",
                        effect_identity=effect_identity,
                        events=(ready_event,),
                    )
        if not reserved:
            return _AppliedBrowserOutcome(
                status="configuration_required",
                phase="effect_reconciliation",
                reason_code="credential_capture_reconciliation_required",
                provider_browser="credential_page_ready",
                effect_identity=effect_identity,
                events=(ready_event,),
            )
        try:
            capture_scope_kwargs: dict[str, object] = {}
            if bool(getattr(worker, "requires_session_capability_scope", False)):
                capture_scope_kwargs["capability_scope"] = run_id
            if self._requires_broker_grants(worker):
                if broker_grant is None:  # pragma: no cover - reservation invariant
                    raise CredentialSubmissionError("automatic_capture_grant_unavailable")
                capture_scope_kwargs["broker_grant"] = broker_grant
            refs = asyncio.run(
                capture(
                    context.session_id,
                    recipe.app_slug,
                    self._context._secret_store,
                    recipe=recipe,
                    **capture_scope_kwargs,
                )
            )
        except Exception:
            # The broker grant makes an exact capture retry idempotent, but loss of
            # the outer worker RPC can still hide whether the reviewed page state
            # changed. Keep the run at explicit reconciliation rather than infer
            # an outcome from transport failure.
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
                effect_identity=effect_identity,
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
                effect_identity=effect_identity,
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
                effect_identity=effect_identity,
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
            effect_identity=effect_identity,
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
        expected_effect_identity: str | None = None,
    ) -> dict[str, Any] | None:
        # Prove that this exact session/effect still owns the run before doing any
        # follow-up provider work. The lock is deliberately released before
        # capture/validation so a broker callback can acquire it.
        lock = self._context._run_lock(run_id)
        with lock:
            if (
                self._bound_browser_record_locked(
                    run_id=run_id,
                    session_id=context.session_id,
                    statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                    effect_identity=expected_effect_identity,
                )
                is None
            ):
                return None
        outcome = self._resolve_browser_outcome(
            run_id=run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=expected_effect_identity,
        )
        projection_effect_identity = outcome.effect_identity or expected_effect_identity
        with lock:
            current = self._bound_browser_record_locked(
                run_id=run_id,
                session_id=context.session_id,
                statuses=frozenset({"browser_running", "waiting_for_hitl"}),
                effect_identity=projection_effect_identity,
            )
            if current is None:
                return None
            persisted_hitl = dict(outcome.hitl) if outcome.hitl is not None else None
            if (
                persisted_hitl is not None
                and persisted_hitl.get("type") == "email_otp"
                and isinstance(current.get("hitl_request"), Mapping)
                and current["hitl_request"].get("type") == "email_otp"
            ):
                previous_requested_at = current["hitl_request"].get("verification_requested_at")
                if isinstance(previous_requested_at, str) and previous_requested_at:
                    persisted_hitl["verification_requested_at"] = previous_requested_at
            if request.account_creation_requested and observation.status in {
                "credential_page_ready",
                "developer_console_ready",
            }:
                try:
                    promoted = self._context._promote_staged_signup_login(
                        app_slug=recipe.app_slug,
                        account_ref=validate_browser_account_ref(
                            current.get("browser_account_ref")
                        ),
                        run_id=run_id,
                    )
                except Exception as exc:
                    outcome = replace(
                        outcome,
                        status="configuration_required",
                        phase="signup_login_promotion",
                        reason_code=_safe_reason(exc, "signup_login_promotion_failed"),
                        events=(
                            *(event for event in outcome.events if event[0] != "run_completed"),
                            (
                                "signup_login_promotion_failed",
                                {
                                    "reason_code": _safe_reason(
                                        exc, "signup_login_promotion_failed"
                                    ),
                                    "external_actions": False,
                                },
                            ),
                        ),
                    )
                else:
                    if set(promoted) != {"login_email", "login_password"}:
                        outcome = replace(
                            outcome,
                            status="configuration_required",
                            phase="signup_login_promotion",
                            reason_code="signup_login_promotion_incomplete",
                        )
                    else:
                        outcome = replace(
                            outcome,
                            events=(
                                (
                                    "signup_login_promoted",
                                    {
                                        "fields": list(promoted),
                                        "external_actions": False,
                                    },
                                ),
                                *outcome.events,
                            ),
                        )
            elif (
                request.account_mode == "existing_account"
                and observation.status == "credential_page_ready"
                and bool(
                    getattr(
                        self._context._settings,
                        "browser_login_credential_reuse",
                        True,
                    )
                )
                and self._context._secret_store is not None
            ):
                # ``credential_page_ready`` is emitted only after the reviewed
                # protected-page predicate is freshly satisfied. Form submission,
                # navigation, and entry-only public pages never reach this branch.
                # The staged pair is therefore promoted only after positive
                # authentication evidence, never when a typo merely gets typed.
                try:
                    promoted = self._context._secret_store.promote_staged_existing_login_pair(
                        app_slug=recipe.app_slug,
                        account_ref=validate_browser_account_ref(
                            current.get("browser_account_ref")
                        ),
                        run_id=run_id,
                    )
                except Exception as exc:
                    outcome = replace(
                        outcome,
                        status="configuration_required",
                        phase="login_credential_promotion",
                        reason_code=_safe_reason(exc, "existing_login_promotion_failed"),
                        events=(
                            *(event for event in outcome.events if event[0] != "run_completed"),
                            (
                                "existing_login_promotion_failed",
                                {
                                    "reason_code": _safe_reason(
                                        exc, "existing_login_promotion_failed"
                                    ),
                                    "external_actions": False,
                                },
                            ),
                        ),
                    )
                else:
                    if promoted and set(promoted) != {"login_email", "login_password"}:
                        outcome = replace(
                            outcome,
                            status="configuration_required",
                            phase="login_credential_promotion",
                            reason_code="existing_login_promotion_incomplete",
                        )
                    elif promoted:
                        outcome = replace(
                            outcome,
                            events=(
                                (
                                    "existing_login_promoted",
                                    {
                                        "fields": list(promoted),
                                        "external_actions": False,
                                    },
                                ),
                                *outcome.events,
                            ),
                        )
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
                    "hitl_request": persisted_hitl,
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
        sensitive: dict[str, str] | None = None
        sensitive_app_slug: str | None = None
        transient_secrets = False
        secret_grants: dict[str, str] = {}
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
                account_ref = validate_browser_account_ref(current.get("browser_account_ref"))
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
            sensitive_app_slug = recipe.app_slug
            transient_secrets = self._requires_broker_grants(worker)
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")

            if browser_login:
                login_values = browser_login
                if request.account_mode == "existing_account":
                    store = self._context._secret_store
                    if store is None:
                        raise CredentialSubmissionError("existing_login_vault_required")
                    try:
                        staged = store.stage_existing_login_pair(
                            app_slug=recipe.app_slug,
                            account_ref=account_ref,
                            run_id=run_id,
                            email=browser_login["login_email"].get_secret_value(),
                            password=browser_login["login_password"].get_secret_value(),
                        )
                    except Exception as exc:
                        raise CredentialSubmissionError(
                            _safe_reason(exc, "existing_login_stage_failed")
                        ) from None
                    login_values = {
                        field: SecretStr(staged[field])
                        for field in ("login_email", "login_password")
                    }
                elif request.account_creation_requested and set(browser_login).issubset(
                    {"login_otp", "login_verification_url"}
                ):
                    # A verification challenge can occur between the reviewed
                    # email-first entry and the password/details continuation.
                    # Preserve the one-time verification value while re-issuing
                    # this exact run's generated signup pair; otherwise the worker
                    # consumes the OTP/link successfully and then has no password
                    # with which to finish the same signup session.
                    staged_signup = self._context._staged_signup_login_values(
                        app_slug=recipe.app_slug,
                        account_ref=account_ref,
                        run_id=run_id,
                    )
                    if set(staged_signup) != {"login_email", "login_password"}:
                        raise CredentialSubmissionError("signup_login_vault_required")
                    login_values = {**staged_signup, **browser_login}
                sensitive = self._context._browser_login_payload(
                    provider="playwright",
                    app_slug=recipe.app_slug,
                    scope_id=run_id,
                    values=login_values,
                )
            elif request.account_creation_requested:
                # Generated signup credentials are part of this authorized account
                # creation attempt. A CAPTCHA/legal gate may occur before they were
                # filled, while the service-local transient references have already
                # been consumed. Re-issue fresh one-time references from the
                # encrypted reusable-login vault so the SAME session can continue.
                # Existing-account runs retain the explicit-submission-only rule.
                staged_signup = self._context._staged_signup_login_values(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                if staged_signup:
                    sensitive = self._context._browser_login_payload(
                        provider="playwright",
                        app_slug=recipe.app_slug,
                        scope_id=run_id,
                        values=staged_signup,
                    )
            elif self._context._secret_store is not None:
                # Re-issue only this run's staged submission first (for a CAPTCHA
                # or another same-session retry). If none exists, an already
                # verified account-scoped pair may be reused. Neither path mutates
                # durable credentials.
                staged_existing = self._context._secret_store.get_staged_existing_login_pair(
                    app_slug=recipe.app_slug,
                    account_ref=account_ref,
                    run_id=run_id,
                )
                reusable = (
                    {
                        field: SecretStr(staged_existing[field])
                        for field in ("login_email", "login_password")
                    }
                    if set(staged_existing) == {"login_email", "login_password"}
                    else self._context._reusable_login_values(recipe.app_slug, account_ref)
                )
                if reusable:
                    sensitive = self._context._browser_login_payload(
                        provider="playwright",
                        app_slug=recipe.app_slug,
                        scope_id=run_id,
                        values=reusable,
                    )
            attempt = int(current.get("attempt", 0) or 0) + 1
            effect_identity = f"{run_id}:browser-resume:{attempt}"
            # Reserve the exact vault grants while the old HITL state is still
            # authoritative. They are unusable until the transaction below moves
            # this exact effect into ``authentication_submitted``; an abandoned
            # reservation therefore cannot authorize a callback.
            secret_grants = self._reserve_consume_grants_locked(
                worker=worker,
                operation_key=effect_identity,
                run_id=run_id,
                session_id=context.session_id,
                app_slug=recipe.app_slug,
                references=sensitive,
            )
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
                    status="browser_running",
                    phase="authentication_submitted" if sensitive else "target_probe_pending",
                    reason_code="resume_reserved",
                    effect_identity=effect_identity,
                    attempt=attempt,
                    hitl_request=None,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
            if not reserved:
                raise CredentialSubmissionError("resume_reconciliation_required")
        except BaseException:
            if sensitive_app_slug is not None:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=sensitive_app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
            elif sensitive is not None:  # pragma: no cover - defensive invariant
                sensitive.clear()
            raise
        finally:
            lock.release()

        # Never retain the per-run lock across the worker RPC: the isolated worker
        # calls back into the broker, which must take that same lock to linearize
        # one-time consume/capture against the current run phase.
        resume_dispatched = False
        try:
            resume_kwargs: dict[str, object] = {
                "recipe": recipe,
                "sensitive_data": sensitive,
                "account_creation_requested": request.account_creation_requested,
                "signup_fields": _signup_fields_for(request),
                "credential_creation_policy": request.credential_creation_policy,
                "provider_session_id": str(current.get("provider_session_id") or "") or None,
            }
            if self._requires_broker_grants(worker):
                resume_kwargs["secret_grants"] = secret_grants
            resume = cast(Any, worker.resume_after_hitl)
            resume_call = resume(
                context,
                signal,
                research,
                **resume_kwargs,
            )
            resume_dispatched = True
            observation = asyncio.run(resume_call)
            self._context.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
            )
        except Exception as exc:
            reason_code = _safe_reason(exc, "browser_resume_failed")
            retryable_pre_action = reason_code.startswith("browser_secret_")
            with contextlib.suppress(Exception):
                self._context.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status=(
                        "outcome_unknown"
                        if reason_code == "browser_resume_outcome_unknown"
                        else "failed"
                    ),
                )
            if retryable_pre_action:
                hitl = current.get("hitl_request")
                raw_action_type = (
                    str(hitl.get("type") or "provider_verification")
                    if isinstance(hitl, Mapping)
                    else "provider_verification"
                )
                action_type = cast(
                    HumanActionType,
                    raw_action_type
                    if raw_action_type in _HUMAN_ACTION_TYPES
                    else "provider_verification",
                )
                observation = BrowserObservation(
                    status="human_action_required",
                    current_url="https://unknown.invalid/",
                    page_title="Browser resume",
                    human_action_type=action_type,
                    human_instruction="The secure browser handoff did not run. Retry this same step.",
                    reason_code=reason_code,
                )
            else:
                observation = BrowserObservation(
                    status="failed",
                    current_url="https://unknown.invalid/",
                    page_title="Browser resume",
                    reason_code=reason_code,
                )
        finally:
            if resume_dispatched:
                if sensitive is not None:
                    sensitive.clear()
            else:
                self._discard_pre_dispatch_browser_secrets(
                    sensitive=sensitive,
                    app_slug=recipe.app_slug,
                    run_id=run_id,
                    transient=transient_secrets,
                )
        result = self._apply_browser_observation(
            run_id,
            observation=observation,
            research=research,
            request=request,
            recipe=recipe,
            context=context,
            expected_effect_identity=effect_identity,
        )
        if result is None:
            raise RunConflictError(run_id, "resume")
        return result

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
            try:
                callback_base = validate_managed_auth_callback_base_url(callback_base)
            except (TypeError, ValueError):
                raise CredentialSubmissionError("managed_auth_callback_not_configured") from None
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
            try:
                validate_managed_auth_callback_base_url(
                    getattr(self._context._settings, "managed_auth_callback_base_url", None)
                )
            except (TypeError, ValueError):
                raise CredentialSubmissionError("managed_auth_callback_not_configured") from None
            request_id = current.get("connection_request_id")
            if not isinstance(request_id, str) or not request_id:
                raise CredentialSubmissionError("connection_request_missing")
            # Read provider state outside a database transaction.
            try:
                polled = asyncio.run(
                    provider.poll_connection(
                        request_id,
                        toolkit_slug=recipe.toolkit_slug,
                    )
                )
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
