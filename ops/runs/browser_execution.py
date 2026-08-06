"""Asynchronous browser execution: dispatch, terminal application, teardown.

A live browser run commits at ``browser_running`` with the live view already
available, and the bounded onboarding task then runs in a background thread. That
shape exists so the create request stays fast and the embedded live view and HITL
are usable for the whole multi-minute task, instead of the request blocking until
the task finishes.

Everything else here follows from that choice. The terminal state has to be applied
from the worker thread, under the per-run lock, and it must never clobber a resume
or another writer that already advanced the run. And because a Playwright
deployment runs a single-session display, EVERY terminal path has to release the
session: a slot left held by a finished run makes the next run fail with
capacity_exhausted until the idle sweep notices.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from typing import Any, Protocol, cast

from ops.browser.link_log import log_event
from ops.browser.provider import BrowserProvider as BrowserWorker
from ops.browser.worker import BrowserSessionContext
from ops.core.models import OperationalResearch, OperationsRequest
from ops.core.secret_store import SQLiteSecretStore
from ops.core.state import BrowserProvider, RunStatus, validate_status_transition
from ops.core.storage import OperationsStorage
from ops.runs.projections import _TERMINAL_BROWSER_STATUSES, _browser_result_reason


class RunBrowserExecutionContext(Protocol):
    """Run-service state and credential hooks the async browser path needs."""

    storage: OperationsStorage
    _workflow: Any
    _browser_threads: list[threading.Thread]
    _secret_store: SQLiteSecretStore | None
    _credential_capturer: Any
    _credential_validator: Any

    def _run_lock(self, run_id: str) -> Any: ...

    def _browser_worker_for(self, record: Any) -> BrowserWorker | None: ...

    def _finalize_captured_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
        credential_refs: dict[str, str],
    ) -> Any: ...

    def _run_m6_credentials(
        self,
        research: OperationalResearch,
        request: OperationsRequest,
    ) -> Any: ...


class RunBrowserExecutionService:
    """Drive the background navigate and apply its terminal outcome."""

    def __init__(self, context: RunBrowserExecutionContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def spawn_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Run the durable browser navigate for a run in a background thread."""

        thread = threading.Thread(
            target=self.run_async_browser,
            args=(run_id, thread_id, request, research, context, sensitive_data),
            name=f"browser-{run_id[:16]}",
            daemon=True,
        )
        self._context._browser_threads = [t for t in self._context._browser_threads if t.is_alive()]
        self._context._browser_threads.append(thread)
        thread.start()

    def run_async_browser(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        research: OperationalResearch,
        context: Any,
        sensitive_data: dict[str, str] | None,
    ) -> None:
        """Background worker: drive the durable navigate on the pre-created session.

        The session already exists (seeded into the workflow), so ``_browser_start``
        is a no-op and the bounded onboarding task runs against the live session.
        When the task pauses (HITL) or finishes, the terminal state is applied to
        the run so the frontend transitions from browser_running.
        """

        workflow = self._context._workflow
        if workflow is None:  # pragma: no cover - guarded by caller
            return
        try:
            seed = {
                "browser_profile_id": context.profile_id,
                "browser_session_id": context.session_id,
                "browser_live_view_available": context.live_view_available,
                "browser_session_started_at": context.created_at,
                "browser_session_last_active_at": context.created_at,
                "browser_session_inactivity_expires_at": context.inactivity_expires_at,
                "browser_session_max_expires_at": context.maximum_expires_at,
            }
            workflow_state = workflow.start(
                request.model_copy(update={"dry_run": False}),
                thread_id=thread_id,
                sensitive_data=sensitive_data,
                research=research,
                seed=seed,
            )
        except Exception as exc:
            log_event(
                "browser.async.workflow_error",
                level=40,
                run_id=run_id,
                thread_id=thread_id,
                error=type(exc).__name__,
            )
            self.mark_async_browser_failed(run_id)
            # The run is terminal, so its pre-created session must not keep the
            # single Playwright slot until the idle sweep.
            self.release_browser_session(
                context, request.browser_provider, reason="async_workflow_error"
            )
            return
        finally:
            if sensitive_data is not None:
                sensitive_data.clear()
        try:
            self.apply_async_browser_result(run_id, thread_id, request, workflow_state, context)
        except Exception as exc:  # pragma: no cover - defensive
            self.release_browser_session(
                context, request.browser_provider, reason="async_apply_error"
            )
            log_event(
                "browser.async.apply_error",
                level=40,
                run_id=run_id,
                error=type(exc).__name__,
            )

    def apply_async_browser_result(
        self,
        run_id: str,
        thread_id: str,
        request: OperationsRequest,
        workflow_state: Mapping[str, object],
        context: Any = None,
    ) -> None:
        """Transition a browser_running run based on the completed navigate."""

        service = self._context
        observation = workflow_state.get("browser_observation")
        observation_status = (
            str(observation.get("status")) if isinstance(observation, Mapping) else None
        )
        wf_status = str(workflow_state.get("status") or "")
        current_url = workflow_state.get("current_url")
        outcome_fallback = {
            "blocked": "browser_navigation_blocked",
            "configuration_required": "browser_configuration_required",
            "failed": "browser_operation_failed",
        }.get(wf_status, "browser_operation_failed")
        outcome_reason = _browser_result_reason(workflow_state, outcome_fallback)
        try:
            workflow = service._workflow
            interrupts = workflow.get_interrupts(thread_id) if workflow else ()
        except Exception:
            interrupts = ()
        waiting = (
            bool(interrupts)
            or observation_status == "human_action_required"
            or wf_status == "waiting_for_hitl"
        )

        lock = service._run_lock(run_id)
        with lock:
            record = self.storage.get_run(run_id)
            if record is None:
                self.release_browser_session(
                    context, request.browser_provider, reason="async_run_missing"
                )
                return
            previous = str(record.get("status") or "browser_running")
            if previous != "browser_running":
                # A resume or another writer already advanced the run; do not
                # clobber its state. If that writer made the run terminal, make
                # teardown idempotently certain here as well.
                log_event("browser.async.apply_skip", run_id=run_id, prev_status=previous)
                if previous in _TERMINAL_BROWSER_STATUSES:
                    self.release_browser_session(
                        context,
                        request.browser_provider,
                        reason=f"async_apply_skip_{previous}",
                    )
                return

            events: list[tuple[str, dict[str, object]]] = []
            extra_updates: dict[str, object] = {}
            hitl_payload: dict[str, object] | None = None
            provider_browser = "running"

            if waiting:
                next_status: RunStatus = "waiting_for_hitl"
                source = interrupts[0] if interrupts else workflow_state.get("hitl_request")
                if isinstance(source, Mapping):
                    hitl_payload = {str(k): v for k, v in source.items()}
                events.append(
                    (
                        "browser_hitl_required",
                        {
                            "status": "waiting_for_hitl",
                            "current_url": current_url,
                            "required_human_action": (
                                hitl_payload.get("type") if hitl_payload else None
                            ),
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "blocked":
                next_status = "blocked"
                provider_browser = "blocked"
                events.append(
                    (
                        "browser_navigation_blocked",
                        {
                            "status": "blocked",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "failed":
                next_status = "failed"
                provider_browser = "failed"
                events.append(
                    (
                        "browser_navigation_failed",
                        {
                            "status": "failed",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif wf_status == "configuration_required" and observation_status not in {
                "credential_page_ready",
                "developer_console_ready",
            }:
                next_status = "configuration_required"
                provider_browser = "configuration_required"
                events.append(
                    (
                        "browser_navigation_failed",
                        {
                            "status": "configuration_required",
                            "reason_code": outcome_reason,
                            "external_actions": True,
                        },
                    )
                )
            elif observation_status in {"credential_page_ready", "developer_console_ready"}:
                events.append(
                    (
                        "credential_page_ready",
                        {
                            "current_url": current_url,
                            "status": "browser_running",
                            "external_actions": True,
                        },
                    )
                )
                research_obj: OperationalResearch | None = None
                if "operational_research" in workflow_state:
                    try:
                        research_obj = OperationalResearch.model_validate(
                            workflow_state["operational_research"]
                        )
                    except Exception:
                        research_obj = None

                # Hands-off deterministic capture: open a logged-in standalone
                # browser from the session profile and read the API token over
                # CDP (no human copy, no LLM read). Falls back to owner paste.
                captured_refs: dict[str, str] | None = None
                selected_worker = service._browser_worker_for(request.browser_provider)
                auto_capture = getattr(selected_worker, "auto_capture_credentials", None)
                if (
                    research_obj is not None
                    and callable(auto_capture)
                    and service._credential_validator is not None
                    and service._secret_store is not None
                ):
                    handle = str(workflow_state.get("browser_session_id") or "")
                    try:
                        capture_scope_kwargs = (
                            {"capability_scope": run_id}
                            if bool(
                                getattr(
                                    selected_worker,
                                    "requires_session_capability_scope",
                                    False,
                                )
                            )
                            else {}
                        )
                        captured_refs = asyncio.run(
                            auto_capture(
                                handle,
                                research_obj.app_slug,
                                service._secret_store,
                                **capture_scope_kwargs,
                            )
                        )
                    except Exception as exc:
                        log_event(
                            "browser.async.autocapture_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        captured_refs = None

                if (
                    captured_refs
                    and research_obj is not None
                    and service._credential_validator is not None
                ):
                    outcome = service._finalize_captured_credentials(
                        research_obj, request, captured_refs
                    )
                    next_status = cast(RunStatus, outcome.status)
                    provider_browser = "credential_page_ready"
                    if outcome.bundle is not None:
                        extra_updates["integrator_bundle"] = outcome.bundle
                    events.extend(outcome.events)
                elif (
                    service._credential_capturer is not None
                    and service._credential_validator is not None
                    and research_obj is not None
                ):
                    try:
                        outcome = service._run_m6_credentials(research_obj, request)
                        next_status = cast(RunStatus, outcome.status)
                        provider_browser = "credential_page_ready"
                        if outcome.bundle is not None:
                            extra_updates["integrator_bundle"] = outcome.bundle
                        events.extend(outcome.events)
                    except Exception as exc:  # pragma: no cover - defensive
                        log_event(
                            "browser.async.m6_error",
                            level=40,
                            run_id=run_id,
                            error=type(exc).__name__,
                        )
                        next_status = "browser_running"
                else:
                    next_status = "browser_running"
            else:
                next_status = "browser_running"

            with self.storage.unit_of_work() as transaction:
                rec = transaction.get_run(run_id)
                if rec is None:  # pragma: no cover
                    self.release_browser_session(
                        context, request.browser_provider, reason="async_transaction_run_missing"
                    )
                    return
                revision = int(rec.get("state_revision", 0) or 0) + 1
                if previous != next_status:
                    if next_status == "completed":
                        # Capture and read-only validation completed the two legal
                        # domain hops in this one atomic projection. Validate both;
                        # a direct browser_running -> completed transition is illegal
                        # and previously stranded successful runs during apply.
                        validate_status_transition(
                            cast(RunStatus, previous), "credentials_ready", "browser"
                        )
                        validate_status_transition("credentials_ready", "completed", "browser")
                    else:
                        validate_status_transition(
                            cast(RunStatus, previous), next_status, "browser"
                        )
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
                        "validation": "not_started",
                    },
                    **extra_updates,
                }
                transaction.update_run(run_id, **changes)
                for event_type, payload in events:
                    transaction.append_audit_event(
                        run_id=run_id, event_type=event_type, payload=payload
                    )
        preserve_owner_handoff = next_status == "configuration_required" and observation_status in {
            "credential_page_ready",
            "developer_console_ready",
        }
        if not preserve_owner_handoff:
            self.stop_terminal_playwright_session(
                context,
                next_status,
                request.browser_provider,
            )
        log_event("browser.async.applied", run_id=run_id, status=next_status)

    def stop_terminal_playwright_session(
        self,
        context: Any,
        next_status: RunStatus,
        provider: BrowserProvider,
    ) -> None:
        """Close a self-hosted browser session once the run reaches a terminal state.

        A Playwright session is a real local Chromium process, so leaving it running
        after a terminal outcome leaks memory on a small VPS. Sessions are kept only
        while a run genuinely still needs the browser (``waiting_for_hitl`` for the
        human, or ``browser_running`` while the action loop is active).

        The Playwright harness is the only backend, and its sessions are real local
        Chromium processes, so a terminal run always releases its slot.
        """

        if next_status not in _TERMINAL_BROWSER_STATUSES:
            return
        self.release_browser_session(
            context,
            provider,
            reason=f"async_terminal_{next_status}",
        )

    def release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None:
        """Release a self-hosted browser session for a run that is finished.

        Idempotent and never fatal: the browser service's own close is idempotent,
        so a duplicate call is a no-op. Every TERMINAL path must come through here,
        because a Playwright deployment runs a single-session display: a slot left
        held by a finished run makes the NEXT run fail with capacity_exhausted
        until the idle sweep eventually notices.
        """

        worker = self._context._browser_worker_for(provider)
        if context is None or worker is None:
            return
        if str(getattr(worker, "provider_name", "playwright")) != "playwright":
            # Anything that is not the self-hosted harness owns its own retention.
            return
        try:
            asyncio.run(worker.stop(context))
        except Exception:
            log_event("browser.session.release_error", level=30, reason=reason)
        else:
            log_event("browser.session.released", reason=reason)

    def session_context_for(self, run_id: str) -> Any:
        """A minimal session handle for a persisted run, or None.

        Teardown only needs the session id, so this avoids reconstructing worker
        state that no longer exists after a restart.
        """

        record = self.storage.get_run(run_id)
        if record is None:
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        return BrowserSessionContext(
            profile_id=session_id,
            session_id=session_id,
            live_view_available=False,
            allowed_domains=(),
            created_at="",
            inactivity_expires_at="",
            maximum_expires_at="",
            capability_scope=run_id,
        )

    def mark_async_browser_failed(self, run_id: str) -> None:
        """Best-effort transition of a stuck browser_running run to failed."""

        try:
            lock = self._context._run_lock(run_id)
            with lock:
                record = self.storage.get_run(run_id)
                if record is None or str(record.get("status")) != "browser_running":
                    return
                with self.storage.unit_of_work() as transaction:
                    rec = transaction.get_run(run_id)
                    if rec is None:
                        return
                    revision = int(rec.get("state_revision", 0) or 0) + 1
                    validate_status_transition("browser_running", "failed", "browser")
                    transaction.update_run(
                        run_id,
                        status="failed",
                        state_revision=revision,
                        last_projected_revision=revision,
                        external_actions=True,
                    )
                    transaction.append_audit_event(
                        run_id=run_id,
                        event_type="browser_failed",
                        payload={"status": "failed", "external_actions": True},
                    )
        except Exception:  # pragma: no cover - defensive
            pass


__all__ = [
    "RunBrowserExecutionContext",
    "RunBrowserExecutionService",
]
