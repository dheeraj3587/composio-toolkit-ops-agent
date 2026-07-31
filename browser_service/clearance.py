"""Read-only observation of whether a paused run's human gate is still present.

The API decides what a cleared gate means (``ops/browser/takeover.py``); this
module only reports facts and carries no page-derived content.
"""

from __future__ import annotations

from typing import Protocol

from browser_service.models import ClearanceProbeReason, GateClearanceReport
from browser_service.session_manager import SessionManager, SessionUnavailable
from ops.browser.worker import HumanActionType


class GateProbe(Protocol):
    """Structural mirror of ``ops.playwright.worker._GateProbe``.

    Declared as a protocol so this service stays importable without Playwright.
    """

    @property
    def gate(self) -> HumanActionType | None: ...

    @property
    def reason(self) -> str: ...

    @property
    def observed(self) -> bool: ...


class GateProbeWorker(Protocol):
    """The only worker verb this module may call."""

    async def probe_human_gate(self, session_id: str) -> GateProbe: ...


# An unrecognised spelling from a future worker fails closed as ``probe_failed``,
# never as a completed read. ``session_max_age_exceeded`` is the route's 410.
_PROBE_REASONS: dict[str, ClearanceProbeReason] = {
    "observed": "observed",
    "operation_in_flight": "operation_in_flight",
    "probe_failed": "probe_failed",
}


def _probe_reason_code(reason: str) -> ClearanceProbeReason:
    return _PROBE_REASONS.get(reason, "probe_failed")


async def observe_gate_clearance(
    manager: SessionManager,
    worker: GateProbeWorker,
    session_id: str,
) -> GateClearanceReport:
    """Report whether the gate a paused run is waiting on is still on the page.

    Raises :class:`SessionUnavailable` with ``session_not_found`` when the id has
    no session; the route owns the HTTP distinction from an aged-out session.
    """

    # No lease: SessionManager.lease() calls touch(), so a polling watcher would
    # keep the session alive and break the idle bound (R2.4).
    session = manager.get_if_present(session_id)
    if session is None:
        raise SessionUnavailable("session_not_found")

    attached = manager.is_attached(session_id)
    observed_generation = session.hitl_generation
    final_probe_owed = session.takeover_final_probe_generation == observed_generation

    gate: HumanActionType | None = None
    reason_code: ClearanceProbeReason = "probe_failed"
    observed = False
    if session.lifecycle == "ACTIVE" and session.hitl_pending:
        # The worker keys pages by the handle it returned from start().
        probe = await worker.probe_human_gate(session.current_page_id)
        gate = probe.gate
        reason_code = _probe_reason_code(probe.reason)
        observed = probe.observed

    final_probe_owed = bool(
        final_probe_owed
        and session.hitl_pending
        and session.takeover_final_probe_generation == observed_generation
    )
    if session.hitl_generation != observed_generation:
        # A resume/new gate crossed while the page read was in flight. The mixed
        # observation authorizes nothing; the next poll must bind to the new
        # generation after the run projection catches up.
        gate = None
        reason_code = "operation_in_flight"
        observed = False
        final_probe_owed = False
        observed_generation = session.hitl_generation

    if (
        not attached
        and observed
        and reason_code == "observed"
        and session.takeover_final_probe_generation == observed_generation
    ):
        # This report answers the one owed post-detach read for this exact
        # generation. Debt from any other generation is never consumed or
        # represented as authorization for this one.
        session.takeover_final_probe_generation = None

    return GateClearanceReport(
        session_id=session.session_id,
        lifecycle=session.lifecycle,
        hitl_pending=session.hitl_pending,
        attached=attached,
        final_probe_owed=final_probe_owed,
        gate=gate,
        # An absent gate alone is not clearance: the page must have been read.
        cleared=observed and gate is None,
        probe_reason_code=reason_code,
        hitl_generation=observed_generation,
    )


__all__ = ["GateProbe", "GateProbeWorker", "observe_gate_clearance"]
