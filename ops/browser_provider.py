"""The browser-automation provider contract.

Both the paid Browser Use worker (``ops.browser_worker.BrowserWorker`` / the
production ``AssignmentBrowserWorker``) and the self-hosted Playwright harness
(added in a later phase) implement this protocol, so a run can select either
backend through the ``browser_provider`` setting without the orchestration layer
knowing which one it is. This module is typing/documentation only — it holds no
runtime behavior and changes nothing about the current path.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.models import OperationalResearch

BrowserProviderName = str  # "browser_use" | "playwright" (validated in Settings)


@runtime_checkable
class BrowserProvider(Protocol):
    """The bounded lifecycle every browser backend must expose.

    Contract notes shared by all providers:
    - A provider NEVER returns a raw credential value; capture is deterministic
      and writes only ``vault://`` references.
    - Host navigation stays within the run's reviewed allowlist.
    - Owner-submitted secrets are injected by code (never seen by any LLM) and
      surfaced to guidance only as placeholder key names.
    """

    async def start(self, profile_id: str | None) -> BrowserSessionContext: ...

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation: ...

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation: ...

    async def stop(self, context: BrowserSessionContext) -> None: ...

    async def close(self) -> None: ...


__all__ = ["BrowserProvider", "BrowserProviderName"]
