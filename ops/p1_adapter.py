"""Typed boundary for immutable P1 lookup and operational adaptation."""

from __future__ import annotations

from typing import Never

from ops.graph import PhaseUnavailableError
from ops.models import OperationalResearch


class P1OperationalAdapter:
    """Future adapter that will read, never mutate, the copied P1 snapshot."""

    async def get_operational_research(self, app_name: str) -> Never:
        del app_name
        raise PhaseUnavailableError(phase=2, capability="P1 operational adapter")


async def get_operational_research(app_name: str) -> OperationalResearch:
    """Preserve the plan's public interface without fabricating enrichment."""

    del app_name
    raise PhaseUnavailableError(phase=2, capability="P1 operational research")
