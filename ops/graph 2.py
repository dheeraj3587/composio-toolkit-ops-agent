"""Phase boundary for the future LangGraph workflow.

Phase 0/1 deliberately has no LangGraph imports. Keeping the exception here gives the CLI, UI,
and all provider stubs one stable way to report that a capability is intentionally unavailable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Never

if TYPE_CHECKING:
    from ops.models import OperationsRequest
    from ops.state import OperationsState


class PhaseUnavailableError(RuntimeError):
    """A requested capability belongs to a phase that has not been enabled."""

    def __init__(self, *, phase: int, capability: str) -> None:
        self.phase = phase
        self.capability = capability
        super().__init__(
            f"{capability} is unavailable in the Phase 0/1 foundation; "
            f"it is scheduled for Phase {phase}."
        )


def build_graph() -> Never:
    """Reject graph construction until encrypted checkpointing is implemented in Phase 3."""

    raise PhaseUnavailableError(phase=3, capability="LangGraph workflow")


async def start_workflow(request: OperationsRequest) -> Never:
    """Reject workflow execution without invoking LangGraph or any provider."""

    del request
    raise PhaseUnavailableError(phase=3, capability="workflow execution")


async def resume_workflow(thread_id: str, signal: str) -> Never:
    """Reject resume until same-thread durable HITL is implemented and tested."""

    del thread_id, signal
    raise PhaseUnavailableError(phase=3, capability="workflow resume")


async def get_workflow_state(thread_id: str) -> OperationsState:
    """Reject checkpoint reads until the Phase 3 state backend exists."""

    del thread_id
    raise PhaseUnavailableError(phase=3, capability="workflow checkpoint state")
