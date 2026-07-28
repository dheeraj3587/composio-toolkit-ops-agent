"""Credential capture, read-only validation, and reference-only handoff.

Three paths reach a credential here and they differ only in where the raw value
came from: an injected capturer, a deterministic browser read already vaulted by
the worker, or an explicit owner submission. After that point they are identical,
and that is the property this module exists to hold: raw values live ONLY inside
the injected adapters and the encrypted vault, and everything that leaves is a
``vault://`` reference, sanitized validation metadata, or the reference-only
IntegratorBundle. Nothing raw reaches run state, checkpoints, audit events, API
output, or logs.

The other shared rule is how an ambiguous validation result is reported. There is
no ``outcome_unknown`` run status, so an unavailable or failed check rests the run
at ``configuration_required`` with a truthful reason while the ambiguous validation
status is recorded, rather than claiming success or hard failure.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.app_recipes import AppRecipe, recipe_to_validation_policy
from ops.integrator import build_integrator_bundle
from ops.models import (
    CompanyProfile,
    OperationalResearch,
    OperationsRequest,
    validate_vault_reference,
)
from ops.provider_errors import ConfigurationRequiredError
from ops.run_errors import CredentialSubmissionError, RunConflictError
from ops.run_projections import _clean_credential_value, _public_run
from ops.run_recipe_snapshot import RecipeSnapshotError, recipe_from_run
from ops.secret_store import SQLiteSecretStore
from ops.state import BrowserProvider, RunStatus
from ops.storage import OperationsStorage


@dataclass(frozen=True, slots=True)
class _CredentialOutcome:
    """Internal result of the M6 capture -> store -> validate -> bundle flow."""

    status: str
    reason_code: str
    validation_status: str | None
    bundle: dict[str, Any] | None
    external_actions: bool
    events: list[tuple[str, dict[str, object]]] = field(default_factory=list)


class RunCredentialContext(Protocol):
    """Run-service state and browser teardown hooks the credential flows need."""

    storage: OperationsStorage
    _secret_store: SQLiteSecretStore | None
    _credential_capturer: Any
    _credential_validator: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunCredentialService:
    """Capture, validate and hand off credentials without exposing a raw value."""

    def __init__(self, context: RunCredentialContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def run_m6_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
    ) -> _CredentialOutcome:
        """Capture -> store -> validate -> bundle, returning only sanitized metadata.

        Raw credentials exist only inside the injected capture/validation adapters
        and the encrypted vault; this method handles vault references and
        sanitized validation metadata only.
        """

        capturer = self._context._credential_capturer
        validator = self._context._credential_validator
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
        if status == "completed":
            events.extend(
                [
                    (
                        "credentials_ready",
                        {"status": "credentials_ready", "external_actions": True},
                    ),
                    (
                        "run_completed",
                        {"status": "completed", "external_actions": True},
                    ),
                ]
            )
        return _CredentialOutcome(
            status=status,
            reason_code=reason_code,
            validation_status=result.status,
            bundle=bundle.model_dump(mode="json"),
            external_actions=True,
            events=events,
        )

    def finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        captured: Mapping[str, str],
        *,
        recipe: AppRecipe | None = None,
    ) -> _CredentialOutcome:
        """Validate deterministically-captured vault refs and build the bundle.

        The raw credential was read over CDP and vaulted by the browser worker;
        here only the ``vault://`` references, read-only validation metadata, and
        the reference-only bundle are handled — never a raw value.
        """

        validator = self._context._credential_validator
        if validator is None:  # pragma: no cover - guarded by caller
            raise RuntimeError("credential validator is not configured")
        references = {kind: validate_vault_reference(ref) for kind, ref in captured.items()}
        events: list[tuple[str, dict[str, object]]] = [
            (
                "credentials_stored",
                {
                    "kinds": sorted(references),
                    "references": dict(sorted(references.items())),
                    "external_actions": True,
                },
            ),
            (
                "credential_validation_started",
                {"app_slug": research.app_slug, "external_actions": True},
            ),
        ]
        try:
            validation_policy = (
                recipe_to_validation_policy(recipe) if recipe is not None else None
            )
            if recipe is not None and validation_policy is None:
                raise CredentialSubmissionError("immutable_validation_policy_missing")
            result = asyncio.run(
                validator.validate(
                    app_slug=research.app_slug,
                    credential_refs=references,
                    **(
                        {"policy": validation_policy}
                        if validation_policy is not None
                        else {}
                    ),
                )
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
            status: RunStatus = "completed"
            reason_code = result.reason_code
        elif result.status == "invalid":
            status = "configuration_required"
            reason_code = result.reason_code
        else:
            status = "configuration_required"
            reason_code = "validation_outcome_unknown"
        if status == "completed":
            events.extend(
                [
                    (
                        "credentials_ready",
                        {"status": "credentials_ready", "external_actions": True},
                    ),
                    (
                        "run_completed",
                        {"status": "completed", "external_actions": True},
                    ),
                ]
            )
        return _CredentialOutcome(
            status=status,
            reason_code=reason_code,
            validation_status=result.status,
            bundle=bundle.model_dump(mode="json"),
            external_actions=True,
            events=events,
        )

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
        store = self._context._secret_store
        if store is None:
            raise CredentialSubmissionError("credential_boundary_not_configured")

        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "submit_credentials")
        references: dict[str, str] = {}
        try:
            current = self.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current.get("state_engine") != "canonical_v1":
                raise CredentialSubmissionError("legacy_run_is_read_only")
            if current.get("status") != "browser_running" or current.get("phase") not in {
                "credential_ready",
                "entry_reached",
            }:
                raise CredentialSubmissionError("run_not_awaiting_credentials")
            try:
                recipe = recipe_from_run(current)
            except RecipeSnapshotError as exc:
                raise CredentialSubmissionError(exc.reason_code) from None
            if recipe.route_kind != "playwright":
                raise CredentialSubmissionError("run_is_not_playwright")
            expected_fields = {field.name for field in recipe.credential_fields}
            if set(fields) != expected_fields:
                raise CredentialSubmissionError("credential_fields_do_not_match_recipe")
            validator = self._context._credential_validator
            if recipe.validation is not None and validator is None:
                raise CredentialSubmissionError("credential_validation_not_configured")
            research_payload = current.get("operational_research")
            if not isinstance(research_payload, Mapping):
                raise CredentialSubmissionError("verified_research_unavailable")
            research = OperationalResearch.model_validate(dict(research_payload))
            app_slug = research.app_slug
            effect_identity = f"{run_id}:owner-credential-submit:v1"

            # Commit the intent before touching the vault or validation endpoint.
            with self.storage.unit_of_work() as transaction:
                _effect, reserved = transaction.reserve_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    provider="owner_vault",
                )
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                transaction.update_run(
                    run_id,
                    phase="credential_submission_reserved",
                    reason_code="credential_submission_reserved",
                    effect_identity=effect_identity,
                    state_revision=int(record.get("state_revision", 0) or 0) + 1,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="credential_submission_reserved",
                    payload={
                        "kinds": sorted(fields),
                        "external_actions": False,
                    },
                )
            if not reserved:
                raise CredentialSubmissionError("credential_submission_reconciliation_required")

            # Vault and provider validation are deliberately outside every run DB
            # transaction. Raw values are cleared as each field crosses the vault.
            try:
                for kind, secret in fields.items():
                    cleaned = _clean_credential_value(secret.get_secret_value())
                    if not cleaned:
                        raise CredentialSubmissionError("empty_credential_value")
                    reference = store.put(app_slug=app_slug, kind=kind, value=cleaned)
                    references[kind] = validate_vault_reference(reference)
                    del cleaned
            except Exception:
                for reference in references.values():
                    try:
                        store.delete(reference)
                    except Exception:  # pragma: no cover - best-effort rollback
                        pass
                self.storage.update_side_effect(
                    run_id=run_id,
                    operation_key=effect_identity,
                    status="failed",
                )
                raise CredentialSubmissionError("vault_write_failed") from None

            result = None
            if recipe.validation is not None:
                try:
                    validation_policy = recipe_to_validation_policy(recipe)
                    if validation_policy is None:  # pragma: no cover - model invariant
                        raise CredentialSubmissionError("immutable_validation_policy_missing")
                    result = asyncio.run(
                        validator.validate(
                            app_slug=app_slug,
                            credential_refs=references,
                            policy=validation_policy,
                        )
                    )
                except ConfigurationRequiredError as exc:
                    for reference in references.values():
                        try:
                            store.delete(reference)
                        except Exception:  # pragma: no cover - best-effort cleanup
                            pass
                    references.clear()
                    self.storage.update_side_effect(
                        run_id=run_id,
                        operation_key=effect_identity,
                        status="failed",
                    )
                    with self.storage.unit_of_work() as transaction:
                        record = transaction.get_run(run_id)
                        if record is None:
                            raise KeyError("run was not found") from None
                        revision = int(record.get("state_revision", 0) or 0) + 1
                        transaction.update_run(
                            run_id,
                            phase=str(current.get("phase") or "credential_ready"),
                            reason_code=exc.reason_code,
                            state_revision=revision,
                            last_projected_revision=revision,
                        )
                    raise CredentialSubmissionError(exc.reason_code) from None
            bundle = build_integrator_bundle(
                research=research,
                company=company,
                credential_refs=references,
                validation=result,
                stage="normal",
                operational_notes=(
                    ()
                    if result is not None
                    else ("Credential was owner-submitted; live validation is not reviewed.",)
                ),
            )

            if result is None:
                final_status: RunStatus = "credentials_ready"
                final_phase = "credential_ready"
                reason_code = "owner_credentials_vaulted_unvalidated"
            elif result.status == "valid":
                final_status = "completed"
                final_phase = "completed"
                reason_code = result.reason_code
            else:
                final_status = "configuration_required"
                final_phase = "credential_validation_failed"
                reason_code = (
                    result.reason_code
                    if result.status in {"invalid", "failed"}
                    else "validation_outcome_unknown"
                )

            validation_payload = (
                {
                    "status": result.status,
                    "reason_code": result.reason_code,
                    "http_status": result.http_status,
                    "endpoint": result.endpoint,
                    "checked_at": result.checked_at,
                    "account_identifier": result.account_identifier,
                }
                if result is not None
                else {
                    "status": "not_reviewed",
                    "reason_code": "validation_policy_not_reviewed",
                }
            )
            with self.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                updated = transaction.update_run(
                    run_id,
                    status=final_status,
                    phase=final_phase,
                    reason_code=reason_code,
                    state_revision=revision,
                    last_projected_revision=revision,
                    external_actions=True,
                    integrator_bundle=bundle.model_dump(mode="json"),
                    validation=validation_payload,
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
                if result is not None:
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
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="run_completed"
                    if final_status == "completed"
                    else "credentials_ready",
                    payload={"status": final_status, "external_actions": True},
                )
                projected = _public_run(updated)
                release_provider = cast(
                    BrowserProvider, current.get("browser_provider", "playwright")
                )
            self.storage.update_side_effect(
                run_id=run_id,
                operation_key=effect_identity,
                status="completed",
            )
        except Exception:
            # If the state commit fails after vaulting, do not strand raw material
            # outside a run that can reference it.
            if references and self.storage.get_run(run_id) is not None:
                latest = self.storage.get_run(run_id)
                if latest is None or latest.get("phase") == "credential_submission_reserved":
                    for reference in references.values():
                        try:
                            store.delete(reference)
                        except Exception:  # pragma: no cover - best-effort cleanup
                            pass
            raise
        finally:
            lock.release()
        self._context._release_browser_session(
            self._context._session_context_for(run_id),
            release_provider,
            reason=(
                "credentials_ready"
                if final_status == "credentials_ready"
                else f"credentials_{final_status}"
            ),
        )
        return projected


__all__ = [
    "RunCredentialContext",
    "RunCredentialService",
    "_CredentialOutcome",
]
