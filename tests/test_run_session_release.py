"""Terminal run states must release the self-hosted browser session.

A Playwright deployment owns one interactive display, so a finished run that keeps
its session makes the NEXT run fail with capacity_exhausted until the idle sweep
eventually notices. These cover the paths that previously returned without any
teardown call.
"""

from __future__ import annotations

import inspect
from typing import Any

from ops.browser_worker import BrowserSessionContext
from ops.config import Settings
from ops.run_service import _TERMINAL_BROWSER_STATUSES, RunService


class _RecordingWorker:
    provider_name = "playwright"

    def __init__(self) -> None:
        self.stopped: list[str] = []

    async def stop(self, context: BrowserSessionContext) -> None:
        self.stopped.append(context.session_id)


class _BrowserUseWorker(_RecordingWorker):
    provider_name = "browser_use"


class _ExplodingWorker(_RecordingWorker):
    async def stop(self, context: BrowserSessionContext) -> None:
        self.stopped.append(context.session_id)
        raise RuntimeError("browser service unreachable")


def _service(worker: Any) -> RunService:
    service = RunService.__new__(RunService)
    service._settings = Settings(browser_provider="playwright")  # type: ignore[attr-defined]
    service._browser_workers = {worker.provider_name: worker}  # type: ignore[attr-defined]
    service._browser_worker = worker  # type: ignore[attr-defined]
    return service


def _context(session_id: str = "bs_test") -> BrowserSessionContext:
    return BrowserSessionContext(
        profile_id=session_id,
        session_id=session_id,
        live_view_available=False,
        allowed_domains=(),
        created_at="",
        inactivity_expires_at="",
        maximum_expires_at="",
    )


def test_release_stops_the_playwright_session() -> None:
    worker = _RecordingWorker()
    service = _service(worker)

    service._release_browser_session(_context(), "playwright", reason="async_workflow_error")

    assert worker.stopped == ["bs_test"]


def test_release_is_idempotent_and_safe_to_call_twice() -> None:
    worker = _RecordingWorker()
    service = _service(worker)

    service._release_browser_session(_context(), "playwright", reason="terminal")
    service._release_browser_session(_context(), "playwright", reason="terminal")

    # The service-side close is itself idempotent; a duplicate must not raise.
    assert worker.stopped == ["bs_test", "bs_test"]


def test_release_never_raises_when_teardown_fails() -> None:
    worker = _ExplodingWorker()
    service = _service(worker)

    # Cleanup failure is logged, never propagated into the run path.
    service._release_browser_session(_context(), "playwright", reason="terminal")

    assert worker.stopped == ["bs_test"]


def test_release_ignores_a_missing_context_or_worker() -> None:
    worker = _RecordingWorker()
    service = _service(worker)

    service._release_browser_session(None, "playwright", reason="terminal")

    assert worker.stopped == []


def test_release_never_stops_a_browser_use_session() -> None:
    """Browser Use retains its own sessions for inspection/reconciliation."""

    worker = _BrowserUseWorker()
    service = _service(worker)

    service._release_browser_session(_context(), "browser_use", reason="terminal")

    assert worker.stopped == []


# --- the terminal paths must actually call the release ------------------------
def test_async_workflow_and_apply_errors_release_the_session() -> None:
    source = inspect.getsource(RunService._run_async_browser)
    assert source.count("_release_browser_session") >= 2
    assert "async_workflow_error" in source
    assert "async_apply_error" in source


def test_a_terminal_resume_releases_the_session() -> None:
    source = inspect.getsource(RunService.resume_run)
    assert "_release_browser_session" in source
    assert "_TERMINAL_BROWSER_STATUSES" in source


def test_reconcile_projection_and_credentials_release_terminal_sessions() -> None:
    reconcile = inspect.getsource(RunService._reconcile_one_stranded)
    projection = inspect.getsource(RunService.project)
    guarded = inspect.getsource(RunService.guarded_status_update)
    credentials = inspect.getsource(RunService.submit_owner_credentials)

    assert "_release_browser_session" in reconcile
    assert "_release_browser_session" in projection
    assert "_release_browser_session" in guarded
    assert "_release_browser_session" in credentials


def test_a_waiting_for_hitl_resume_keeps_the_session() -> None:
    """waiting_for_hitl is not terminal, so resume must not tear the session down."""

    assert "waiting_for_hitl" not in _TERMINAL_BROWSER_STATUSES
    assert "browser_running" not in _TERMINAL_BROWSER_STATUSES
    assert {"completed", "failed", "blocked", "configuration_required"} <= set(
        _TERMINAL_BROWSER_STATUSES
    )
