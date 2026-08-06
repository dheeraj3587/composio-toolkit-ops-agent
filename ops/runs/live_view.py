"""Ephemeral live-view surfaces for an in-flight browser session.

Both operations resolve their answer from the in-memory browser worker at request
time. Nothing they return is persisted: the masked screenshot bytes and the
interactive grant never reach SQLite, the checkpoint, the audit ledger, or the
logs. That is the whole reason they are grouped together and kept out of the
persistence paths.

A third query used to live here — ``get_browser_live_url``, which asked the worker
for an externally hosted signed URL and, failing that, replayed the provider
session id out of the workflow checkpoint to recover one after an API restart.
Only the retired cloud backend ever returned such a URL; the self-hosted workers
serve their session through this control plane, so the recovery path could not
succeed and the API no longer has a ``hosted_url`` mode to spend it on.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

# The backend contract, not a concrete backend: with Browser Use removed the
# only implementation is the Playwright harness, and these call sites only ever
# needed the protocol. Aliased so the annotations below read unchanged.
from ops.browser.provider import BrowserProvider as BrowserWorker
from ops.core.storage import OperationsStorage


class RunLiveViewContext(Protocol):
    """The run-service state the live-view queries need."""

    storage: OperationsStorage

    def _browser_worker_for(self, record: Mapping[str, Any]) -> BrowserWorker | None: ...


class RunLiveViewService:
    """Resolve masked screenshots and interactive grants on demand."""

    def __init__(self, context: RunLiveViewContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def get_browser_screenshot(self, run_id: str) -> tuple[bytes, str] | None:
        """Return the newest masked screenshot for a run's browser session.

        The bytes live solely in the worker's memory: they are never written to
        SQLite, disk, logs, or the checkpoint.
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


__all__ = [
    "RunLiveViewContext",
    "RunLiveViewService",
]
