"""Autonomous continuation of human gates the agent can resolve by itself.

Resume is deliberately non-autonomous: a consumed login reference is never
recreated after a CAPTCHA, verification prompt, or other HITL pause. Reusable
credentials may seed a fresh run, but continuing an existing session requires an
explicit owner resume (and new login values only when the owner submits them).
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Protocol

from pydantic import SecretStr

from ops.browser_link_log import log_event
from ops.config import Settings
from ops.run_errors import CredentialSubmissionError, RunConflictError
from ops.storage import OperationsStorage

# Human gates the agent may retry on its own. Only a login form backed by
# already-authorized reusable credentials may advance without a human. Everything
# else needs a real person in the live browser. Provider verification is deliberately
# excluded: it can represent CAPTCHA, device approval, consent, account selection,
# or another security prompt, and auto-resuming it both defeats HITL and can turn a
# solvable gate into a failed login before the evaluator can attach.
_AUTO_ADVANCEABLE_GATES: frozenset[str] = frozenset()


class RunAdvanceContext(Protocol):
    """Run-service state and actions the autonomous sweep drives.

    The thread handle and stop event stay owned by the service (a test replaces
    ``_advance_stop`` directly), so they are read and written through this context
    instead of being duplicated here.
    """

    storage: OperationsStorage
    _settings: Settings | None
    _autonomous_advances: dict[str, int]
    _advance_thread: threading.Thread | None
    _advance_stop: threading.Event

    def _hitl_action_type(self, record: Mapping[str, object]) -> str | None: ...

    def _reusable_login_values(self, app_slug: str) -> dict[str, SecretStr]: ...

    def resume_run(self, run_id: str, *, signal: str) -> dict[str, object] | None: ...

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int: ...


class RunAdvanceService:
    """Sweep waiting runs and resume the ones no human is needed for."""

    def __init__(self, context: RunAdvanceContext) -> None:
        self._context = context

    def start(self) -> None:
        """Start the sweep that auto-resumes machine-resolvable human gates.

        Deliberately independent of the email poller: that thread only starts when
        Gmail is configured, so autonomous login continuation would never have run
        on a deployment without an inbox.
        """

        context = self._context
        settings = context._settings or Settings.from_env()
        if int(getattr(settings, "max_autonomous_advances", 0)) <= 0:
            return
        if context._advance_thread is not None and context._advance_thread.is_alive():
            return
        interval = max(5, int(getattr(settings, "autonomous_advance_interval_seconds", 20)))
        context._advance_stop.clear()
        thread = threading.Thread(
            target=self._loop,
            args=(interval,),
            name="autonomous-advancer",
            daemon=True,
        )
        context._advance_thread = thread
        thread.start()

    def _loop(self, interval: int) -> None:
        while not self._context._advance_stop.wait(interval):
            try:
                self.advance_autonomous_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass
            try:
                self._context.reconcile_idle_browser_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass

    def advance_autonomous_runs(self, *, limit: int = 100) -> int:
        """Leave every existing browser HITL session for an explicit owner resume.

        The loop remains as a compatibility no-op while the old setting is removed
        from deployments. In particular, remembered credentials are not converted
        into fresh one-time references during Resume.
        """

        context = self._context
        settings = context._settings or Settings.from_env()
        budget = int(getattr(settings, "max_autonomous_advances", 0))
        if budget <= 0:
            return 0
        if not _AUTO_ADVANCEABLE_GATES:
            return 0
        advanced = 0
        for record in context.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "waiting_for_hitl":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            action_type = context._hitl_action_type(record)
            if action_type not in _AUTO_ADVANCEABLE_GATES:
                continue
            if context._autonomous_advances.get(run_id, 0) >= budget:
                continue
            if action_type == "login_required" and not context._reusable_login_values(
                str(record.get("app_slug") or "unknown")
            ):
                # Nothing to inject: asking the worker again would just re-raise
                # the same gate. The owner still needs to supply credentials once.
                continue
            context._autonomous_advances[run_id] = context._autonomous_advances.get(run_id, 0) + 1
            try:
                # resume_run injects the remembered credentials on its own.
                context.resume_run(run_id, signal="completed")
            except (RunConflictError, CredentialSubmissionError, KeyError):
                continue  # another writer owns the run, or it already moved on
            except Exception:
                log_event("browser.autonomous_advance.error", level=40, run_id=run_id)
                continue
            log_event(
                "browser.autonomous_advance.resumed",
                run_id=run_id,
                gate=action_type,
                attempt=context._autonomous_advances[run_id],
            )
            advanced += 1
        return advanced


__all__ = [
    "RunAdvanceContext",
    "RunAdvanceService",
]
