"""The canonical browser-automation provider contract.

Both the Browser Use worker and the self-hosted Playwright harness implement this
protocol. Policy arguments are part of the public boundary because account,
developer-app, and credential creation are independent consequential actions.
Their defaults must remain read-only for rolling deployments and third-party
provider implementations.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.models import OperationalResearch
from ops.policies import AccountPolicy, CredentialPolicy, DeveloperAppPolicy

BrowserProviderName = str  # "browser_use" | "playwright" (validated in Settings)


@runtime_checkable
class BrowserProvider(Protocol):
    """The bounded lifecycle every browser backend must expose.

    Contract notes shared by all providers:
    - A provider never returns a raw credential value; capture writes only
      ``vault://`` references.
    - Host navigation stays within the run's reviewed allowlist.
    - Owner-submitted secrets are injected by code and never exposed to an LLM.
    - Omitted automation policies are always ``reuse_existing``.
    """

    async def start(
        self,
        profile_id: str | None,
        *,
        app_slug: str = ...,
        account_ref: str | None = ...,
        secret_scope: str | None = ...,
        use_storage_state: bool = ...,
        live_view_mode: str = ...,
    ) -> BrowserSessionContext: ...

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_policy: AccountPolicy = "reuse_existing",
        developer_app_policy: DeveloperAppPolicy = "reuse_existing",
        credential_policy: CredentialPolicy = "reuse_existing",
    ) -> BrowserObservation: ...

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_policy: AccountPolicy = "reuse_existing",
        developer_app_policy: DeveloperAppPolicy = "reuse_existing",
        credential_policy: CredentialPolicy = "reuse_existing",
        provider_session_id: str | None = None,
    ) -> BrowserObservation: ...

    async def stop(self, context: BrowserSessionContext) -> None: ...

    async def close(self) -> None: ...


__all__ = ["BrowserProvider", "BrowserProviderName"]
