"""Typed, non-provider boundary for future developer-app creation."""

from __future__ import annotations

from dataclasses import dataclass

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.graph import PhaseUnavailableError
from ops.models import CompanyProfile, OperationalResearch


@dataclass(frozen=True, slots=True)
class DeveloperAppRequest:
    app_slug: str
    developer_app_name: str
    company: CompanyProfile
    callback_urls: tuple[str, ...]
    requested_scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeveloperAppResult:
    developer_app_id: str
    requested_scopes: tuple[str, ...]
    granted_scopes: tuple[str, ...]
    observation: BrowserObservation


class DeveloperAppWorker:
    """Future idempotent app worker; never creates an app in Phase 0/1."""

    async def find_or_create(
        self,
        *,
        context: BrowserSessionContext,
        research: OperationalResearch,
        request: DeveloperAppRequest,
    ) -> DeveloperAppResult:
        del context, research, request
        raise PhaseUnavailableError(phase=5, capability="developer app creation")
