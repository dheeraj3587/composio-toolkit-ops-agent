"""Marking a run whose action loop has stopped reporting progress.

The loop records one progress event per iteration, so the absence of new rows is
the only evidence that a run is stalled rather than slow. This sweep turns that
absence into a durable, sanitized fact (reliability R4.9) and pauses the run only
when no live lease holds it: a worker that is alive but slow is marked and left
alone, because pausing under it would be the watcher fighting the driver.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from math import ceil
from typing import Final, Protocol

from ops.core.config import Settings
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import WAITING_PHASES, PhaseHistoryStore
from ops.onboarding.phase import TERMINAL_PHASES, OnboardingReasonCode
from ops.runs.resume import OnboardingRunControlService

STALE_REASON_CODE: Final[OnboardingReasonCode] = "run_progress_stale"
PROGRESS_STALE_EVENT: Final = "onboarding_progress_stale"


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
        """

        if record.get("state_engine") == "canonical_v1":
            if record.get("status") != "browser_running":
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
    "RunLivenessService",
]
