"""Recovery of runs left holding a browser with nothing driving them.

Two sweeps live here and they are deliberately paired. The startup sweep recovers
runs stranded by the previous shutdown; the periodic sweep recovers runs that
landed at ``browser_running`` without a live operation. Both end at the same
recoverable ``configuration_required`` state and both release the browser session,
so keeping them together makes it obvious they must stay consistent.

Both are best effort and must never crash boot or a sweep: a reconciliation error
is logged and skipped, because failing to recover a run is recoverable while
failing to start the service is not.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from ops.browser_link_log import log_event
from ops.browser_worker import BrowserWorker
from ops.config import Settings
from ops.run_projections import _parse_timestamp
from ops.state import BrowserProvider, RunStatus, validate_status_transition
from ops.storage import OperationsStorage

LOGGER = logging.getLogger("composio_ops.run_service")


class RunReconciliationContext(Protocol):
    """The run-service state and browser teardown hooks these sweeps need."""

    storage: OperationsStorage
    _settings: Settings | None

    def _browser_worker_for(self, record: Mapping[str, Any]) -> BrowserWorker | None: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunReconciliationService:
    """Move unrecoverable browser runs to a recoverable state and free the slot."""

    def __init__(self, context: RunReconciliationContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def reconcile_stranded_runs(self) -> None:
        """Recover runs stranded by the previous shutdown.

        A run left at ``browser_running`` cannot progress after an api restart
        because its in-process navigation thread is gone; move it to the
        recoverable ``configuration_required`` state so the operator can retry
        instead of watching it spin forever. ``waiting_for_hitl`` runs are left
        intact: the provider session id is now persisted, so they can be resumed.
        Best-effort and never fatal to startup.
        """

        # Provider capability decides which statuses are recoverable. Browser Use
        # sessions live in the cloud and can be reattached by provider session id, so
        # its waiting_for_hitl runs are left intact (unchanged behaviour). The
        # in-process Playwright browser dies with the API process, so BOTH
        # browser_running and waiting_for_hitl must be reconciled — claiming such a
        # run is resumable would be false.
        #
        # The browser SERVICE is the third case: Chromium is in its own container, so
        # a session can genuinely outlive an API restart. But the capability flag
        # alone is not evidence, so each waiting_for_hitl run is CHECKED against the
        # service (see _browser_session_is_live); only a session the service still
        # reports ACTIVE is left resumable.
        try:
            offset = 0
            while True:
                batch = self.storage.list_runs(limit=100, offset=offset)
                if not batch:
                    break
                for record in batch:
                    status = record.get("status")
                    run_id = str(record.get("run_id") or "")
                    worker = self._context._browser_worker_for(record)
                    reattach = bool(getattr(worker, "supports_restart_reattach", True))
                    stranded_statuses = (
                        ("browser_running",)
                        if reattach
                        else ("browser_running", "waiting_for_hitl")
                    )
                    reason = (
                        "api_restart_stranded_browser_run"
                        if reattach
                        else "playwright_session_lost_on_restart"
                    )
                    verifies_sessions = callable(getattr(worker, "reconcile_session", None))
                    if status in stranded_statuses:
                        self.reconcile_one_stranded(
                            run_id,
                            stranded_statuses=stranded_statuses,
                            reason=reason,
                        )
                    elif (
                        verifies_sessions
                        and status == "waiting_for_hitl"
                        and self.browser_session_is_live(record) is False
                    ):
                        # The service says this session is gone: the run cannot be
                        # resumed, so surface that instead of waiting forever on a
                        # browser that no longer exists.
                        self.reconcile_one_stranded(
                            run_id,
                            stranded_statuses=("waiting_for_hitl",),
                            reason="browser_service_session_lost",
                        )
                if len(batch) < 100:
                    break
                offset += 100
        except Exception:  # pragma: no cover - reconciliation must never crash boot
            LOGGER.warning("startup run reconciliation was skipped after an error")

    def browser_session_is_live(self, record: Mapping[str, Any]) -> bool | None:
        """Ask the browser service whether a persisted session id still exists.

        Returns ``True`` when the service reports the session ACTIVE, ``False``
        when it is definitively gone, and ``None`` when the answer is unknown
        (service unreachable, or the provider cannot be queried). ``None`` must be
        treated as "leave the run alone": tearing a run down because the service
        was briefly unreachable would destroy a session that is actually alive.
        """

        worker = self._context._browser_worker_for(record)
        reconcile = getattr(worker, "reconcile_session", None)
        if not callable(reconcile):
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return False
        try:
            outcome = asyncio.run(reconcile(session_id))
        except Exception:
            return None
        if outcome == "resumable":
            return True
        if outcome == "session_lost":
            return False
        # "unreachable" (or anything unexpected) is inconclusive, never a teardown.
        return None

    def reconcile_one_stranded(
        self,
        run_id: str,
        *,
        stranded_statuses: tuple[str, ...] = ("browser_running",),
        reason: str = "api_restart_stranded_browser_run",
    ) -> None:
        if not run_id:
            return
        release_provider: BrowserProvider | None = None
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None or current.get("status") not in stranded_statuses:
                    return
                release_provider = cast(
                    BrowserProvider, current.get("browser_provider", "browser_use")
                )
                previous_status = cast(RunStatus, current["status"])
                revision = int(current.get("state_revision", 0) or 0) + 1
                validate_status_transition(previous_status, "configuration_required", "reconcile")
                transaction.update_run(
                    run_id,
                    status="configuration_required",
                    state_revision=revision,
                    last_projected_revision=revision,
                )
                transaction.append_audit_event(
                    run_id=run_id,
                    event_type="run_reconciled_on_startup",
                    payload={
                        "previous_status": previous_status,
                        "status": "configuration_required",
                        "reason": reason,
                        "external_actions": False,
                    },
                )
            if release_provider is not None:
                self._context._release_browser_session(
                    self._context._session_context_for(run_id),
                    release_provider,
                    reason=f"reconcile_{reason}",
                )
        except Exception:  # pragma: no cover - per-run best effort
            LOGGER.warning("could not reconcile a stranded run on startup")

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int:
        """Recover runs stuck at ``browser_running`` with nothing driving them.

        A ``browser_running`` run is normally short-lived: either the navigation
        completes, or it stops at a human gate. Nothing sweeps this status, so a run
        whose projection landed here without a live operation used to sit forever and
        keep holding a browser slot — fatal where capacity is one session.

        This is the periodic counterpart to :meth:`reconcile_stranded_runs`, which
        only runs at startup. A run is touched ONLY when it has been idle far longer
        than any legitimate browser operation could take, so an in-flight navigation
        is never torn down: the threshold is derived from the provider operation
        timeout with a wide safety factor. The outcome is the same recoverable
        ``configuration_required`` state the startup path already produces, and the
        browser session is released.
        """

        settings = self._context._settings or Settings.from_env()
        idle_seconds = max(600, int(getattr(settings, "browser_use_task_timeout_seconds", 180)) * 4)
        cutoff = datetime.now(UTC) - timedelta(seconds=idle_seconds)
        reconciled = 0
        for record in self.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "browser_running":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            updated_at = _parse_timestamp(record.get("updated_at"))
            if updated_at is None or updated_at > cutoff:
                continue
            before = self.storage.get_run(run_id)
            self.reconcile_one_stranded(
                run_id,
                stranded_statuses=("browser_running",),
                reason="idle_browser_run_reconciled",
            )
            after = self.storage.get_run(run_id)
            if (
                isinstance(before, Mapping)
                and isinstance(after, Mapping)
                and before.get("status") != after.get("status")
            ):
                reconciled += 1
                log_event(
                    "browser.idle_run.reconciled",
                    run_id=run_id,
                    app_slug=record.get("app_slug"),
                    idle_seconds=idle_seconds,
                )
        return reconciled


__all__ = [
    "RunReconciliationContext",
    "RunReconciliationService",
]
