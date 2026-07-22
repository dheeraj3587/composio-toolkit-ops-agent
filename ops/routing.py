"""Reserved deterministic routing boundary for Phase 2."""

from __future__ import annotations

from typing import TYPE_CHECKING, Never

from ops.graph import PhaseUnavailableError

if TYPE_CHECKING:
    from ops.models import OperationalResearch


def classify_access(research: OperationalResearch) -> Never:
    """Refuse to treat evidence-derived model output as the final deterministic route yet."""

    del research
    raise PhaseUnavailableError(phase=2, capability="deterministic access routing")
