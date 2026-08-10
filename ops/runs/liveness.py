"""Marking a run whose action loop has stopped reporting progress.

The loop records one progress event per iteration, so the absence of new rows is
the only evidence that a run is stalled rather than slow. This sweep turns that
absence into a durable, sanitized fact (reliability R4.9) and pauses the run only
when no live lease holds it: a worker that is alive but slow is marked and left
alone, because pausing under it would be the watcher fighting the driver.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from math import ceil
from typing import Final, Protocol

from ops.browser.link_log import log_event
from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.deploy.acceptance import wait_for_deployment_acceptance
from ops.onboarding.driver import WAITING_PHASES, PhaseHistoryStore
from ops.onboarding.phase import TERMINAL_PHASES, OnboardingReasonCode
from ops.runs.resume import OnboardingRunControlService

STALE_REASON_CODE: Final[OnboardingReasonCode] = "run_progress_stale"
PROGRESS_STALE_EVENT: Final = "onboarding_progress_stale"

# Canonical phases that are WAITING ON A PERSON, not stalled. They keep
# ``status="browser_running"`` because that pair — browser_running plus one of
# these two phases — is exactly the precondition
# ``RunCredentialService.submit_credentials`` checks before accepting an owner's
# secret (see ops/runs/credentials.py). Treating them as staleness candidates
# meant the sweep failed the run roughly five minutes after it reached the very
# page it was asking a human to visit, and the failed row then refused the
# submission it had just invited. Every ``owner_submit`` app lost its window
# this way.
#
# Nothing leaks by exempting them: the browser session is still reclaimed by the
# session manager's own inactivity and maximum-lifetime TTLs, which is where a
# real Chromium process belongs. This sweep's job is detecting a driver that
# stopped stepping, and a run parked for a person has no driver to fence.
AWAITING_OWNER_PHASES: Final[frozenset[str]] = frozenset({"credential_ready", "entry_reached"})


class LeaseHolders(Protocol):
    """The one lease read this sweep needs: is a live holder driving this run?"""

    def holds(self, *, run_id: str) -> bool: ...


class CanonicalLivenessControl(Protocol):
    """The canonical runtime's guarded stale-browser teardown authority."""

    def pause_stale_run(
        self,
        run_id: str,
        *,
        reason_code: OnboardingReasonCode,
        expected_updated_at: str,
        stale_seconds: int,
    ) -> bool: ...


class RunLivenessService:
    """Mark — and where nothing is driving them, pause — runs that stopped stepping."""

    def __init__(
        self,
        *,
        storage: OperationsStorage,
        phases: PhaseHistoryStore,
        control: OnboardingRunControlService,
        leases: LeaseHolders,
        settings: Settings,
        canonical: CanonicalLivenessControl | None = None,
    ) -> None:
        self._storage = storage
        self._phases = phases
        self._control = control
        self._leases = leases
        self._settings = settings
        self._canonical = canonical

    def mark_stale_runs(self, *, limit: int = 100) -> int:
        """Mark every non-terminal, non-waiting run past its safe stale window."""

        now = datetime.now(UTC)
        marked = 0
        offset = 0
        while True:
            records = self._storage.list_runs(limit=limit, offset=offset)
            if not records:
                break
            for record in records:
                run_id = str(record.get("run_id") or "")
                if not run_id:
                    continue
                stale_seconds = self._stale_seconds(record)
                cutoff = now - timedelta(seconds=stale_seconds)
                try:
                    if self._mark_if_stale(record, cutoff, stale_seconds=stale_seconds):
                        marked += 1
                except Exception:
                    # One unreadable run must not end the sweep for the others.
                    continue
            offset += len(records)
            if len(records) < limit:
                break
        return marked

    def _stale_seconds(self, record: Mapping[str, object]) -> int:
        configured = int(self._settings.onboarding_progress_stale_seconds)
        if record.get("state_engine") != "canonical_v1":
            return configured
        # A canonical worker operation is one outer RPC. Never fence it while the
        # configured client is still entitled to wait for a response.
        rpc_budget = ceil(float(self._settings.browser_service_client_timeout_seconds)) + 1
        return max(configured, rpc_budget)

    def _mark_if_stale(
        self,
        record: Mapping[str, object],
        cutoff: datetime,
        *,
        stale_seconds: int,
    ) -> bool:
        run_id = str(record.get("run_id") or "")
        last_seen = self._last_progress(run_id, record)
        if last_seen is None or last_seen > cutoff:
            return False
        if record.get("state_engine") == "canonical_v1":
            if self._canonical is None:
                # Only the canonical runtime may tear a stale browser down, so
                # without it this run is knowingly left alone. Say so: a silent
                # skip here is indistinguishable from "nothing was stale", and it
                # is the difference between a healthy sweep and a stranded run.
                log_event(
                    "runs.liveness.canonical_control_unavailable",
                    run_id=run_id,
                    stale_seconds=stale_seconds,
                )
                return False
            return self._canonical.pause_stale_run(
                run_id,
                reason_code=STALE_REASON_CODE,
                expected_updated_at=str(record.get("updated_at") or ""),
                stale_seconds=stale_seconds,
            )

        newly_marked = self._record_stale_mark(run_id, stale_seconds=stale_seconds)
        # A first pass may mark the run while its lease is still live. Keep
        # reconsidering an already-marked run so that a later pass pauses it once
        # that lease expires; otherwise the stale reason itself would strand it.
        if not self._leases.holds(run_id=run_id):
            self._control.request_pause(run_id, reason_code=STALE_REASON_CODE)
        return newly_marked

    def _record_stale_mark(self, run_id: str, *, stale_seconds: int) -> bool:
        """Atomically write one mark and one audit fact for this stale episode."""

        with self._storage.unit_of_work() as transaction:
            current = transaction.get_run(run_id)
            if current is None or current.get("reason_code") == STALE_REASON_CODE:
                # The pause decision still happens in the caller: a lease may have
                # been live when this mark was first recorded and expired since.
                return False
            transaction.update_run(run_id, reason_code=STALE_REASON_CODE)
            transaction.append_audit_event(
                run_id=run_id,
                event_type=PROGRESS_STALE_EVENT,
                payload={
                    "reason_code": STALE_REASON_CODE,
                    "stale_seconds": stale_seconds,
                    "external_actions": False,
                },
            )
        return True

    def _last_progress(
        self,
        run_id: str,
        record: Mapping[str, object],
    ) -> datetime | None:
        """When the run last moved, or ``None`` when it is not a candidate.

        Phase-driver runs use their newest loop event or committed boundary. A
        canonical run has one bounded browser RPC in flight rather than a local
        action-loop lease, so its durable ``updated_at`` boundary is the heartbeat;
        only ``browser_running`` is eligible and its operation timeout remains below
        the staleness window under validated settings.

        The phase-driver branch below already exempts its own waiting states via
        ``WAITING_PHASES``; ``AWAITING_OWNER_PHASES`` is the canonical runtime's
        equivalent, and both say the same thing — a run waiting on a person is not
        a run that stopped.
        """

        if record.get("state_engine") == "canonical_v1":
            if record.get("status") != "browser_running":
                return None
            if str(record.get("phase") or "") in AWAITING_OWNER_PHASES:
                return None
            return _moment(str(record.get("updated_at") or ""))

        history = self._phases.history(run_id=run_id)
        if not history:
            return None
        boundary = history[-1]
        if boundary.to_phase in TERMINAL_PHASES or boundary.to_phase in WAITING_PHASES:
            return None
        moments = [_moment(boundary.committed_at)]
        moments += [
            _moment(str(event.get("recorded_at") or ""))
            for event in self._storage.list_progress_events(run_id, limit=1)
        ]
        readable = [moment for moment in moments if moment is not None]
        return max(readable) if readable else None


class RunLivenessContext(Protocol):
    """Run-service state the scheduled liveness sweep drives.

    The thread handle and stop event stay owned by the service, exactly as the
    autonomous advancer's do, so shutdown joins them in one place and a test can
    replace ``_liveness_stop`` directly.
    """

    _settings: Settings | None
    _liveness_thread: threading.Thread | None
    _liveness_stop: threading.Event

    def mark_stale_runs(self, *, limit: int = 100) -> int: ...


class RunLivenessScheduler:
    """The thread that runs the liveness sweep on a cadence of its own.

    Stall detection used to ride along inside the autonomous advancement loop,
    which meant a deployment that never advanced a run never noticed a stalled
    one either. It is its own sweep now, started alongside the others and gated
    on the same deployment acceptance marker.
    """

    def __init__(self, context: RunLivenessContext) -> None:
        self._context = context

    def start(self) -> None:
        """Start the sweep that marks runs whose loop stopped reporting progress."""

        context = self._context
        settings = context._settings or Settings.from_env()
        if context._liveness_thread is not None and context._liveness_thread.is_alive():
            return
        # Shares the advancement cadence rather than introducing a knob: this is
        # exactly how often the sweep already ran when it was a passenger there.
        # Both names are declared and range-validated on ``Settings`` (``ge=5``
        # and 1.0-300.0), so they are read directly: a ``getattr`` default here
        # would silently substitute a second, unvalidated cadence for a typo.
        interval = int(settings.autonomous_advance_interval_seconds)
        initial_delay = float(settings.ops_automation_start_delay_seconds)
        context._liveness_stop.clear()
        thread = threading.Thread(
            target=self._loop,
            args=(interval, initial_delay),
            name="run-liveness",
            daemon=True,
        )
        context._liveness_thread = thread
        thread.start()

    def _loop(self, interval: int, initial_delay: float) -> None:
        if self._context._liveness_stop.wait(initial_delay):
            return
        settings = self._context._settings or Settings.from_env()
        if not wait_for_deployment_acceptance(settings, self._context._liveness_stop):
            return
        while not self._context._liveness_stop.wait(interval):
            try:
                self._context.mark_stale_runs()
            except Exception:  # pragma: no cover - the loop must never die
                pass


def _moment(value: str) -> datetime | None:
    """One stored ``...Z`` instant as an aware datetime; ``None`` if unreadable."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


__all__ = [
    "PROGRESS_STALE_EVENT",
    "STALE_REASON_CODE",
    "CanonicalLivenessControl",
    "LeaseHolders",
    "RunLivenessContext",
    "RunLivenessScheduler",
    "RunLivenessService",
]
