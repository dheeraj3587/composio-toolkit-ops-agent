"""Resume of a run parked at a human gate, on the SAME browser session.

Resume continues the durable workflow through the EXISTING thread id: no new
session is created, so the human's browser and the agent's browser are the same
one. That is the whole point of the method and it constrains everything else here.

Three outcomes are possible and each must be reported truthfully. A repeated
interrupt keeps the run waiting with a refreshed instruction. A cleared gate
advances toward the credential page, where a deterministic capture may complete the
run outright. A blocked or failed observation ends the run: projecting those as
browser_running used to park the run permanently, because nothing drives a
browser_running run (the advancer only sweeps waiting_for_hitl, retry records no
action, and the UI offers no resume), so it held the single browser slot until the
next API restart.

Injected sign-in values are resolved in memory for exactly one workflow.resume
call, passed through the provider's one-time secret boundary, and dropped as soon
as it returns. Only the non-secret field names and their source reach the ledger,
which is what makes an autonomous vault reuse distinguishable from an owner
submission in the timeline.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Mapping
from typing import Any, Protocol, cast

from pydantic import SecretStr

from ops.browser_link_log import log_event
from ops.browser_worker import BrowserWorker
from ops.models import OperationalResearch, OperationsRequest
from ops.run_errors import CredentialSubmissionError, RunConflictError
from ops.run_projections import _TERMINAL_BROWSER_STATUSES, _browser_result_reason, _public_run
from ops.secret_store import SQLiteSecretStore
from ops.state import BrowserProvider, RunStatus, validate_status_transition
from ops.storage import OperationsStorage


class RunResumeContext(Protocol):
    """Run-service state and helpers the resume path drives."""

    storage: OperationsStorage
    _workflow: Any
    _secret_store: SQLiteSecretStore | None
    _credential_validator: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _browser_worker_for(self, record: Any) -> BrowserWorker | None: ...

    def _remember_reusable_login(
        self, *, app_slug: str, values: Mapping[str, SecretStr]
    ) -> tuple[str, ...]: ...

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
    ) -> Any: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunResumeService:
    """Continue a waiting_for_hitl run on its existing session and thread."""

    def __init__(self, context: RunResumeContext) -> None:
        self._context = context

    def resume_run(
        self,
        run_id: str,
        *,
        signal: str = "completed",
        browser_login: Mapping[str, SecretStr] | None = None,
    ) -> dict[str, Any]:
        """Resume a waiting_for_hitl run on the SAME browser session/thread.

        Continues the durable workflow through the existing thread id (no new
        session is created), then projects the resumed state. A repeated
        interrupt keeps the run at waiting_for_hitl with a refreshed instruction;
        a cleared path advances toward the credential page.

        When ``browser_login`` is supplied (owner-only, loopback), its raw values
        are resolved in-memory ONLY for the single ``workflow.resume`` call and
        injected through the selected provider's one-time secret boundary so the
        agent logs in autonomously. The raw values are never written to run state,
        checkpoints, audit events, or logs, and are dropped as soon as resume
        returns; only the non-secret field names are recorded.
        """

        context = self._context

        if context._workflow is None:
            raise CredentialSubmissionError("workflow_not_configured")
        lock = context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, "resume")
        try:
            current = context.storage.get_run(run_id)
            if current is None:
                raise KeyError("run was not found")
            if current["status"] != "waiting_for_hitl":
                raise CredentialSubmissionError("run_not_waiting_for_hitl")
            thread_id = str(current.get("thread_id") or run_id)
            app_slug = str(current.get("app_slug") or "unknown")
            remembered_fields: tuple[str, ...] = ()
            if browser_login:
                # Remember the owner's sign-in credentials so the NEXT resume (or
                # the next run) can authenticate without asking again.
                remembered_fields = context._remember_reusable_login(
                    app_slug=app_slug, values=browser_login
                )
            login_values: Mapping[str, SecretStr] | None = browser_login
            login_source = "owner_supplied"
            # Resume never recreates consumed credential references. Only values
            # explicitly included in THIS owner request may be injected. Reusable
            # credentials can seed a fresh run, but CAPTCHA/provider-verification
            # resume must inspect and continue the existing browser session.
            injected_login_fields: list[str] = sorted(login_values) if login_values else []
            sensitive_data: dict[str, str] | None = None
            if login_values:
                sensitive_data = context._browser_login_payload(
                    provider=cast(
                        BrowserProvider,
                        current.get("browser_provider", "browser_use"),
                    ),
                    app_slug=app_slug,
                    scope_id=run_id,
                    values=login_values,
                )
            try:
                state = context._workflow.resume(thread_id, signal, sensitive_data=sensitive_data)
            finally:
                # Drop the resolved raw values as soon as resume returns.
                if sensitive_data is not None:
                    sensitive_data.clear()
                    sensitive_data = None
            interrupts = context._workflow.get_interrupts(thread_id)

            observation = state.get("browser_observation")
            observation_status = (
                str(observation.get("status")) if isinstance(observation, Mapping) else None
            )
            current_url = state.get("current_url")
            still_blocked = bool(interrupts) or observation_status == "human_action_required"
            next_status: RunStatus
            capture_events: list[tuple[str, dict[str, object]]] = []
            capture_updates: dict[str, object] = {}
            provider_browser = "running"
            validation_status = "not_started"

            if signal == "cancelled":
                next_status = "blocked"
                provider_browser = "blocked"
            elif still_blocked:
                next_status = "waiting_for_hitl"
            elif observation_status in {"credential_page_ready", "developer_console_ready"}:
                next_status = "browser_running"
                provider_browser = "credential_page_ready"
                capture_events.append(
                    (
                        "credential_page_ready",
                        {
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                )
                research_payload = state.get("operational_research")
                if not isinstance(research_payload, Mapping):
                    research_payload = current.get("operational_research")
                request_payload = state.get("request")
                try:
                    research_obj = OperationalResearch.model_validate(research_payload)
                    request_obj = OperationsRequest.model_validate(request_payload)
                except Exception:
                    research_obj = None
                    request_obj = None

                selected_worker = context._browser_worker_for(
                    cast(BrowserProvider, current.get("browser_provider", "browser_use"))
                )
                auto_capture = getattr(selected_worker, "auto_capture_credentials", None)
                captured_refs: dict[str, str] | None = None
                if (
                    research_obj is not None
                    and request_obj is not None
                    and callable(auto_capture)
                    and context._credential_validator is not None
                    and context._secret_store is not None
                ):
                    capture_events.append(
                        (
                            "credential_capture_started",
                            {
                                "app_slug": research_obj.app_slug,
                                "external_actions": True,
                            },
                        )
                    )
                    handle = str(
                        state.get("browser_session_id") or current.get("browser_session_id") or ""
                    )
                    try:
                        captured_refs = asyncio.run(
                            auto_capture(handle, research_obj.app_slug, context._secret_store)
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.autocapture_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_capture_failed"
                        capture_events.append(
                            (
                                "credential_capture_failed",
                                {
                                    "reason_code": "credential_capture_failed",
                                    "external_actions": True,
                                },
                            )
                        )

                if captured_refs and research_obj is not None and request_obj is not None:
                    try:
                        outcome = context._finalize_captured_credentials(
                            research_obj, request_obj, captured_refs
                        )
                    except Exception as exc:
                        log_event(
                            "browser.resume.credential_finalization_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        # Finalization never persisted these refs. Remove the
                        # just-captured entries best-effort so an unexpected
                        # validator/bundle error cannot leave unreachable vault
                        # rows behind.
                        store = context._secret_store
                        if store is not None:
                            for reference in captured_refs.values():
                                with contextlib.suppress(Exception):
                                    store.delete(reference)
                        next_status = "configuration_required"
                        validation_status = "configuration_required"
                        capture_updates["route_reason_code"] = "credential_finalization_failed"
                        capture_events.append(
                            (
                                "credential_finalization_failed",
                                {
                                    "reason_code": "credential_finalization_failed",
                                    "external_actions": True,
                                },
                            )
                        )
                    else:
                        next_status = cast(RunStatus, outcome.status)
                        validation_status = outcome.validation_status or "configuration_required"
                        capture_updates["route_reason_code"] = outcome.reason_code
                        if outcome.bundle is not None:
                            capture_updates["integrator_bundle"] = outcome.bundle
                        capture_events.extend(outcome.events)
            elif observation_status in {"blocked", "failed"}:
                # A resume that ends blocked/failed must say so. Projecting these as
                # ``browser_running`` parked the run permanently: nothing drives a
                # browser_running run (the advancer only sweeps waiting_for_hitl,
                # retry records no action, and the UI offers no resume), so the run
                # held the single browser slot until the next API restart.
                next_status = "blocked" if observation_status == "blocked" else "failed"
                provider_browser = next_status
                capture_updates["route_reason_code"] = _browser_result_reason(
                    state, f"browser_resume_{observation_status}"
                )
                capture_events.append(
                    (
                        "browser_resume_terminal",
                        {
                            "status": next_status,
                            "reason_code": capture_updates["route_reason_code"],
                            "external_actions": True,
                        },
                    )
                )
                # The shared terminal-release block at the end of this method hands
                # the browser session back for these statuses.
            else:
                # "navigating" (or an absent status) is genuinely still in progress.
                next_status = "browser_running"

            with context.storage.unit_of_work() as transaction:
                record = transaction.get_run(run_id)
                if record is None:  # pragma: no cover - re-checked under lock
                    raise KeyError("run was not found")
                revision = int(record.get("state_revision", 0) or 0) + 1
                if next_status == "completed":
                    # Capture completed all three domain phases during this one
                    # atomic resume projection; validate every legal edge even
                    # though only the terminal row is persisted.
                    validate_status_transition("waiting_for_hitl", "browser_running", "resume")
                    validate_status_transition("browser_running", "credentials_ready", "resume")
                    validate_status_transition("credentials_ready", "completed", "resume")
                else:
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
                    "provider_status": {
                        "research": "baseline_ready",
                        "browser": provider_browser,
                        "email": "not_started",
                        "validation": validation_status,
                    },
                    **capture_updates,
                }
                if isinstance(current_url, str) and current_url:
                    changes["browser_live_url"] = None  # never persist the signed URL
                updated = transaction.update_run(run_id, **changes)
                cancelled = signal == "cancelled"
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="hitl_cancelled" if cancelled else "hitl_resumed",
                    payload={
                        "status": "blocked" if cancelled else "browser_running",
                        "signal": signal,
                        "external_actions": True,
                    },
                )
                if injected_login_fields:
                    # Record ONLY the non-secret field names that were injected;
                    # the values never touch the ledger, state, or logs. The
                    # source distinguishes an owner submission from an autonomous
                    # vault reuse, which is what makes the timeline auditable.
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_injected",
                        payload={
                            "fields": injected_login_fields,
                            "source": login_source,
                            "external_actions": True,
                        },
                    )
                if remembered_fields:
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="login_credentials_remembered",
                        payload={
                            "fields": list(remembered_fields),
                            "external_actions": False,
                        },
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
                else:
                    for event_type, payload in capture_events:
                        transaction.append_audit_event(
                            run_id=run_id,
                            event_type=event_type,
                            payload=payload,
                        )
                projected = _public_run(updated)
            if next_status in _TERMINAL_BROWSER_STATUSES:
                # A cancelled (or otherwise terminal) resume ends the run, so the
                # session is released here instead of lingering as a held slot.
                context._release_browser_session(
                    context._session_context_for(run_id),
                    cast(BrowserProvider, current.get("browser_provider", "browser_use")),
                    reason=f"resume_{next_status}",
                )
            return projected
        finally:
            lock.release()


__all__ = [
    "RunResumeContext",
    "RunResumeService",
]
