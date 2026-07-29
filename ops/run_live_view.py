"""Ephemeral live-view surfaces for an in-flight browser session.

All three operations resolve their answer from the in-memory browser worker at
request time. Nothing they return is persisted: the masked screenshot bytes, the
signed live-view URL and the interactive grant never reach SQLite, the checkpoint,
the audit ledger, or the logs. That is the whole reason they are grouped together
and kept out of the persistence paths.

The only durable value any of them reads is the provider session id from the
workflow checkpoint, which is non-secret and is what allows the embedded live view
to reconnect after an API restart.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Protocol, cast

from ops.browser_link_log import log_event
from ops.browser_worker import BrowserWorker
from ops.graph import DurableOperationsWorkflow
from ops.storage import OperationsStorage


class RunLiveViewContext(Protocol):
    """The run-service state the live-view queries need."""

    storage: OperationsStorage
    _workflow: DurableOperationsWorkflow | None

    def _browser_worker_for(self, record: Mapping[str, Any]) -> BrowserWorker | None: ...


class RunLiveViewService:
    """Resolve screenshots, signed live URLs and interactive grants on demand."""

    def __init__(self, context: RunLiveViewContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def get_browser_screenshot(self, run_id: str) -> tuple[bytes, str] | None:
        """Return the newest masked screenshot for a run's browser session.

        Only the self-hosted Playwright provider offers this (Browser Use supplies a
        hosted live URL instead). The bytes live solely in the worker's memory: they
        are never written to SQLite, disk, logs, or the checkpoint.
        """

        record = self.storage.get_run(run_id)
        if record is None:
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        worker = self._context._browser_worker_for(record)
        if worker is None:
            return None
        getter = getattr(worker, "latest_screenshot", None)
        if not callable(getter):
            return None
        scope_kwargs = (
            {"capability_scope": run_id}
            if bool(getattr(worker, "requires_session_capability_scope", False))
            else {}
        )
        result = getter(session_id, **scope_kwargs)
        if (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], bytes)
            and isinstance(result[1], str)
        ):
            return (result[0], result[1])
        return None

    def get_browser_interactive_grant(self, run_id: str) -> tuple[str, str, str, bool] | None:
        """Mint an ephemeral Playwright view/control grant for an active run.

        The signed URL is returned once to the API projection and is never written
        to storage, checkpoints, audit events, worker caches, or logs.
        """

        record = self.storage.get_run(run_id)
        if (
            record is None
            or record.get("browser_provider") != "playwright"
            or record.get("status") not in {"browser_running", "waiting_for_hitl"}
        ):
            return None
        provider_status = record.get("provider_status")
        if isinstance(provider_status, Mapping) and provider_status.get("browser") in {
            "credential_page_ready",
            "credentials_ready",
        }:
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        worker = self._context._browser_worker_for(record)
        requester = getattr(worker, "request_live_view_sync", None)
        if not callable(requester):
            return None
        scope_kwargs = (
            {"capability_scope": run_id}
            if bool(getattr(worker, "requires_session_capability_scope", False))
            else {}
        )
        result = requester(session_id, **scope_kwargs)
        if (
            isinstance(result, tuple)
            and len(result) == 4
            and result[0] == "interactive_remote"
            and isinstance(result[1], str)
            and isinstance(result[2], str)
            and isinstance(result[3], bool)
        ):
            return cast("tuple[str, str, str, bool]", result)
        return None

    def get_browser_live_url(self, run_id: str) -> str | None:
        """Return the ephemeral signed live-view URL for a run, if one is active.

        The URL is read from the in-memory BrowserWorker at request time and is
        never persisted to run state, checkpoints, the ledger, logs, or Git. It
        exists only while the worker holds the session, for owner interaction.
        """

        record = self.storage.get_run(run_id)
        if record is None:
            log_event("liveview.resolve.no_run", level=30, run_id=run_id)
            return None
        worker = self._context._browser_worker_for(record)
        if worker is None:
            log_event("liveview.resolve.no_worker", level=30, run_id=run_id)
            return None
        session_id = record.get("browser_session_id")
        if not isinstance(session_id, str) or not session_id:
            log_event(
                "liveview.resolve.no_session",
                run_id=run_id,
                run_status=record.get("status"),
            )
            return None
        live_url = worker.live_url(session_id)
        if live_url:
            log_event("liveview.resolve.cached", run_id=run_id, handle=session_id)
            return live_url
        # After an API restart the in-memory URL is gone but the provider session
        # may still be running. Recover the signed URL from the durable
        # checkpoint's (non-secret) provider session id so the embedded live view
        # reconnects. The signed URL itself is never persisted.
        recover = getattr(worker, "recover_live_url", None)
        workflow = self._context._workflow
        if not callable(recover) or workflow is None:
            log_event("liveview.resolve.no_recover", level=30, run_id=run_id, handle=session_id)
            return None
        thread_id = record.get("thread_id")
        if not isinstance(thread_id, str) or not thread_id:
            return None
        try:
            checkpoint_state = workflow.get_state(thread_id)
        except Exception:
            log_event("liveview.resolve.checkpoint_error", level=30, run_id=run_id)
            return None
        provider_session = checkpoint_state.get("browser_provider_session_id")
        if not isinstance(provider_session, str) or not provider_session:
            log_event(
                "liveview.resolve.no_provider_session",
                level=30,
                run_id=run_id,
                handle=session_id,
            )
            return None
        log_event("liveview.resolve.recover_attempt", run_id=run_id, handle=session_id)
        try:
            recovered = asyncio.run(recover(session_id, provider_session))
        except Exception as exc:
            log_event(
                "liveview.resolve.recover_error",
                level=30,
                run_id=run_id,
                error=type(exc).__name__,
            )
            return None
        log_event(
            "liveview.resolve.recover_result",
            run_id=run_id,
            handle=session_id,
            recovered=bool(recovered),
        )
        return cast("str | None", recovered)


__all__ = [
    "RunLiveViewContext",
    "RunLiveViewService",
]
