"""The browser-automation provider contract.

The self-hosted Playwright harness (``ops.playwright.worker.PlaywrightBrowserWorker``,
and the browser-service client that fronts it) is the only implementation. The
protocol still exists because the orchestration layer should depend on the
lifecycle, not on a concrete worker class — but it is now written to match that
one backend exactly rather than the lowest common denominator of two.

That distinction mattered: while this protocol described the retired Browser Use
adapter's narrower ``start``, every real call site passed keyword arguments the
protocol did not declare, so annotating a call site with it was a type error. The
signatures below are the ones callers actually use.

This module is typing/documentation only — it holds no runtime behavior.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from ops.browser.worker import BrowserObservation, BrowserSessionContext
from ops.core.models import OperationalResearch
from ops.recipes.app_recipes import AppRecipe

BrowserProviderName = str  # "playwright" (validated in Settings)


@runtime_checkable
class BrowserProvider(Protocol):
    """The bounded lifecycle every browser backend must expose.

    Contract notes:
    - A provider NEVER returns a raw credential value; capture is deterministic
      and writes only ``vault://`` references.
    - Host navigation stays within the run's reviewed allowlist.
    - Owner-submitted secrets are injected by code (never seen by any LLM) and
      surfaced to guidance only as placeholder key names.
    """

    # The identity a run is frozen onto. ``RunService`` keys its worker registry on
    # this and refuses to hand a run a worker whose name differs, so it is part of
    # the contract rather than an incidental attribute.
    provider_name: str

    async def start(
        self,
        profile_id: str | None,
        *,
        recipe: AppRecipe | None = ...,
        storage_state: dict[str, Any] | None = ...,
        app_slug: str = ...,
        account_ref: str | None = ...,
        secret_scope: str | None = ...,
        use_storage_state: bool = ...,
        live_view_mode: str = ...,
        display: str | None = ...,
        decision_model: str | None = ...,
        decision_effort: str | None = ...,
    ) -> BrowserSessionContext: ...

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        recipe: AppRecipe | None = ...,
        sensitive_data: Mapping[str, str] | None = ...,
        account_creation_requested: bool = ...,
        signup_fields: Mapping[str, str] | None = ...,
        setup_fields: Mapping[str, str] | None = ...,
        credential_creation_policy: str = ...,
    ) -> BrowserObservation: ...

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = ...,
        *,
        recipe: AppRecipe | None = ...,
        sensitive_data: Mapping[str, str] | None = ...,
        account_creation_requested: bool = ...,
        signup_fields: Mapping[str, str] | None = ...,
        setup_fields: Mapping[str, str] | None = ...,
        credential_creation_policy: str = ...,
        provider_session_id: str | None = ...,
    ) -> BrowserObservation: ...

    def provider_session_id(self, handle: str) -> str | None: ...

    def live_url(self, session_id: str) -> str | None: ...

    async def stop(self, context: BrowserSessionContext) -> None: ...

    async def close(self) -> None: ...


__all__ = ["BrowserProvider", "BrowserProviderName"]
