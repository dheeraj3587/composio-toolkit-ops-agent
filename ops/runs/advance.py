"""Autonomous continuation of human gates the agent can resolve by itself.

Which gates qualify is decided by ``ops.access.gate_policy``, not here: this module owns
the sweep, the attempt budget, and the audit trail, while the policy owns the
classification. Anything the policy does not explicitly classify stays paused for
an owner, so an unreviewed gate can never advance a run.

CAPTCHA, phone OTP, device approval, billing, and hardware authenticators are
permanently human-only. See ``ops.access.gate_policy`` for the rationale behind each.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Protocol

from pydantic import SecretStr

from ops.access.gate_policy import GateResolution, autonomous_gates, resolve_gate
from ops.browser.link_log import log_event
from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.runs.errors import CredentialSubmissionError, RunConflictError

# Retained as the module's published view of the autonomous gate set. It is now
# derived from the declarative policy instead of being hard-coded empty, so the
# two can never disagree.
_AUTO_ADVANCEABLE_GATES: frozenset[str] = autonomous_gates()


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

    def _reusable_login_values(self, app_slug: str, account_ref: str) -> dict[str, SecretStr]: ...

    def resume_run(self, run_id: str, *, signal: str) -> dict[str, object] | None: ...

    def resolve_email_otp(
        self,
        run_id: str,
        *,
        max_attempts: int | None = None,
    ) -> dict[str, object] | None: ...

    def reconcile_idle_browser_runs(self, *, limit: int = 100) -> int: ...

    def _reconcile_stranded_runs(self) -> None: ...


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
        if context._advance_thread is not None and context._advance_thread.is_alive():
            return
        interval = max(5, int(getattr(settings, "autonomous_advance_interval_seconds", 20)))
        initial_delay = max(
            1.0,
            float(getattr(settings, "ops_automation_start_delay_seconds", 30.0)),
        )
        context._advance_stop.clear()
        thread = threading.Thread(
            target=self._loop,
            args=(interval, initial_delay),
            name="autonomous-advancer",
            daemon=True,
        )
        context._advance_thread = thread
        thread.start()

    def _loop(self, interval: int, initial_delay: float) -> None:
        # Reconciliation can contact the isolated browser service. Delay it until
        # after process startup, and make the delay interruptible so a candidate
        # rejected during deployment performs no provider call.
        if self._context._advance_stop.wait(initial_delay):
            return
        settings = self._context._settings or Settings.from_env()
        if not wait_for_deployment_acceptance(settings, self._context._advance_stop):
            return
        try:
            self._context._reconcile_stranded_runs()
        except Exception:  # pragma: no cover - the loop must never die
            pass
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
        """Resolve every paused gate the policy classifies as autonomous.

        Returns how many runs were actually advanced. A gate the policy leaves
        ``human_only``, a run that has spent its attempt budget, and a login gate
        with no reusable credentials are all left paused for an owner rather than
        retried into failure.
        """

        context = self._context
        settings = context._settings or Settings.from_env()
        budget = int(getattr(settings, "max_autonomous_advances", 0))
        if budget <= 0:
            return 0
        advanced = 0
        for record in context.storage.list_runs(limit=limit, offset=0):
            if record.get("status") != "waiting_for_hitl":
                continue
            run_id = str(record.get("run_id") or "")
            if not run_id:
                continue
            app_slug = str(record.get("app_slug") or "unknown")
            action_type = context._hitl_action_type(record)
            resolution = resolve_gate(action_type, app_slug=app_slug)
            if resolution == "human_only":
                continue
            gate = str(action_type)
            attempts = context._autonomous_advances.get(run_id, 0)
            if attempts >= budget:
                # Log the exhaustion once, then stay quiet: this sweep runs every
                # few seconds and must not fill the log with the same escalation.
                if attempts == budget:
                    context._autonomous_advances[run_id] = attempts + 1
                    self._escalate(run_id, gate, "attempt_budget_exhausted")
                continue
            if resolution == "reusable_login" and not context._reusable_login_values(
                app_slug,
                str(record.get("browser_account_ref") or run_id),
            ):
                # Nothing to inject: asking the worker again would just re-raise
                # the same gate. The owner still needs to supply credentials once.
                self._escalate(run_id, gate, "reusable_login_unavailable")
                continue
            context._autonomous_advances[run_id] = attempts + 1
            if not self._attempt(run_id, resolution):
                continue
            log_event(
                "browser.autonomous_advance.resumed",
                run_id=run_id,
                gate=gate,
                resolution=resolution,
                attempt=context._autonomous_advances[run_id],
            )
            advanced += 1
        return advanced

    def _attempt(self, run_id: str, resolution: GateResolution) -> bool:
        """Drive one gate through its resolver; never raise into the sweep loop."""

        context = self._context
        try:
            if resolution == "emailed_verification":
                # The verification service owns recipient binding, sender
                # authentication, and the one-time resume injection.
                return context.resolve_email_otp(run_id) is not None
            # reusable_login and the two declared authorities (recipe_declared,
            # profile_declared) all continue the existing session; resume_run
            # injects any remembered credentials itself.
            context.resume_run(run_id, signal="completed")
            return True
        except (RunConflictError, CredentialSubmissionError, KeyError):
            # Another writer owns the run, or it already moved on.
            return False
        except Exception:
            log_event(
                "browser.autonomous_advance.error",
                level=40,
                run_id=run_id,
                resolution=resolution,
            )
            return False

    def _escalate(self, run_id: str, gate: str, reason_code: str) -> None:
        """Record that a gate is being handed back to an owner, with a cause."""

        log_event(
            "browser.autonomous_advance.escalated",
            run_id=run_id,
            gate=gate,
            reason_code=reason_code,
        )


__all__ = [
    "RunAdvanceContext",
    "RunAdvanceService",
]
