"""Projection of durable graph state into the sanitized operations ledger.

Two invariants govern everything here and both are enforced in this one place.

Idempotency: a revision equal to or lower than the last projected revision is a
no-op, so a replayed projection rewrites no status and appends no audit event. The
ledger stays a DERIVED view and never overrides the checkpoint.

Single transition authority: every status write passes
``validate_status_transition`` first, including the collapsed multi-hop chain that
run creation produces. Nothing here writes a status directly.

``guarded_status_update`` adds per-run serialization on top: a competing command is
rejected with ``RunConflictError`` (HTTP 409) before any partial write or external
action, guarded by a per-run lock plus an optimistic revision check.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from ops.core.state import BrowserProvider, RunStatus, validate_status_transition
from ops.core.storage import OperationsStorage, OperationsUnitOfWork
from ops.runs.errors import RunConflictError
from ops.runs.projections import _TERMINAL_BROWSER_STATUSES, _public_run

# create_run collapses several legal graph transitions into one initial
# projection (for example a gated run that reaches waiting_for_reply). The chain
# is validated hop-by-hop through the single transition authority so no illegal
# jump is ever written to the ledger.
_CREATE_PROJECTION_CHAINS: dict[str, tuple[RunStatus, ...]] = {
    "waiting_for_reply": ("route_selected", "outreach_sent", "waiting_for_reply"),
    "outreach_sent": ("route_selected", "outreach_sent"),
    "browser_running": ("route_selected", "browser_running"),
    "waiting_for_hitl": ("route_selected", "browser_running", "waiting_for_hitl"),
    "credentials_ready": ("route_selected", "browser_running", "credentials_ready"),
    "completed": ("route_selected", "browser_running", "credentials_ready", "completed"),
}


def _validate_created_projection(final_status: str) -> None:
    chain = _CREATE_PROJECTION_CHAINS.get(final_status)
    if chain is None:
        validate_status_transition("created", cast(RunStatus, final_status), "create")
        return
    previous: RunStatus = "created"
    for nxt in chain:
        validate_status_transition(previous, nxt, "create")
        previous = nxt


class RunProjectionContext(Protocol):
    """Run-service state and browser teardown hooks the projection needs."""

    storage: OperationsStorage

    def _run_lock(self, run_id: str) -> Any: ...

    def _session_context_for(self, run_id: str) -> Any: ...

    def _release_browser_session(
        self,
        context: Any,
        provider: BrowserProvider,
        *,
        reason: str,
    ) -> None: ...


class RunProjectionService:
    """Apply idempotent state projections and serialized status updates."""

    def __init__(self, context: RunProjectionContext) -> None:
        self._context = context

    @property
    def storage(self) -> OperationsStorage:
        return self._context.storage

    def project(
        self,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        *,
        command: str = "workflow",
    ) -> dict[str, Any]:
        """Idempotently project durable graph state into the sanitized ledger.

        A revision equal to or lower than the last projected revision is a
        no-op: no status is rewritten and no audit event is appended. Every
        status write first passes the single ``validate_status_transition``
        authority. The operations ledger remains a derived projection and never
        overrides the checkpoint.
        """

        with self.storage.unit_of_work() as transaction:
            result = self.apply_projection(transaction, run_id, state, revision, command)
            projected = _public_run(result)
        projected_status = str(result.get("status") or "")
        if projected_status in _TERMINAL_BROWSER_STATUSES:
            self._context._release_browser_session(
                self._context._session_context_for(run_id),
                cast(BrowserProvider, result.get("browser_provider", "browser_use")),
                reason=f"project_{projected_status}",
            )
        return projected

    def apply_projection(
        self,
        transaction: OperationsUnitOfWork,
        run_id: str,
        state: Mapping[str, object],
        revision: int,
        command: str,
    ) -> dict[str, Any]:
        current = transaction.get_run(run_id)
        if current is None:
            raise KeyError("run was not found")
        last_projected = int(current.get("last_projected_revision", 0) or 0)
        if revision <= last_projected:
            return current
        previous_status = cast(RunStatus, current["status"])
        next_status = cast(RunStatus, state.get("status") or previous_status)
        validate_status_transition(previous_status, next_status, command)
        changes: dict[str, object] = {
            "status": next_status,
            "state_revision": revision,
            "last_projected_revision": revision,
        }
        access_route = state.get("access_route")
        if access_route is not None:
            changes["access_route"] = access_route
        route_reason_code = state.get("route_reason_code")
        if route_reason_code is not None:
            changes["route_reason_code"] = route_reason_code
        route_reason = state.get("route_reason")
        if route_reason is not None:
            changes["route_explanation"] = route_reason
        research = state.get("operational_research")
        if isinstance(research, Mapping):
            changes["operational_research"] = dict(research)
        missing = state.get("missing_fields")
        if isinstance(missing, list):
            changes["missing_fields"] = list(missing)
        updated = transaction.update_run(run_id, **changes)
        transaction.append_audit_event(
            run_id=run_id,
            event_type="state_projected",
            payload={
                "status": next_status,
                "revision": revision,
                "external_actions": False,
            },
        )
        return updated

    def guarded_status_update(
        self,
        run_id: str,
        *,
        expected_revision: int,
        next_status: RunStatus,
        command: str,
        **changes: object,
    ) -> dict[str, Any]:
        """Apply one mutating command under per-run serialization.

        Competing commands are rejected with ``RunConflictError`` (surfaced as
        HTTP 409) without any partial write or external action. Concurrency is
        guarded by a per-run lock plus an optimistic ``state_revision`` check.
        """

        lock = self._context._run_lock(run_id)
        if not lock.acquire(blocking=False):
            raise RunConflictError(run_id, command)
        try:
            with self.storage.unit_of_work() as transaction:
                current = transaction.get_run(run_id)
                if current is None:
                    raise KeyError("run was not found")
                if int(current.get("state_revision", 0) or 0) != expected_revision:
                    raise RunConflictError(run_id, command)
                previous_status = cast(RunStatus, current["status"])
                validate_status_transition(previous_status, next_status, command)
                new_revision = expected_revision + 1
                updated = transaction.update_run(
                    run_id,
                    status=next_status,
                    state_revision=new_revision,
                    last_projected_revision=new_revision,
                    **changes,
                )
                projected = _public_run(updated)
                release_provider = cast(
                    BrowserProvider, updated.get("browser_provider", "browser_use")
                )
        finally:
            lock.release()
        if next_status in _TERMINAL_BROWSER_STATUSES:
            self._context._release_browser_session(
                self._context._session_context_for(run_id),
                release_provider,
                reason=f"guarded_status_{next_status}",
            )
        return projected


__all__ = [
    "RunProjectionContext",
    "RunProjectionService",
]
