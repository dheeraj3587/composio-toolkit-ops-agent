"""Secret-free typed boundary for future Browser Use navigation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ops.graph import PhaseUnavailableError
from ops.models import OperationalResearch

BrowserObservationStatus = Literal[
    "navigating",
    "human_action_required",
    "developer_console_ready",
    "credential_page_ready",
    "blocked",
    "failed",
]

HumanActionType = Literal[
    "captcha",
    "email_otp",
    "phone_otp",
    "passkey",
    "security_key",
    "device_approval",
    "provider_verification",
    "legal_acceptance",
    "billing",
    "account_selection",
]


@dataclass(frozen=True, slots=True)
class SelectorHint:
    """A non-secret selector hint for later deterministic Playwright code."""

    field_label: str
    selector: str


@dataclass(frozen=True, slots=True)
class BrowserObservation:
    """Narrow agent output schema with no generic container for credential values."""

    status: BrowserObservationStatus
    current_url: str
    page_title: str
    developer_app_id: str | None = None
    human_action_type: HumanActionType | None = None
    human_instruction: str | None = None
    credential_field_labels: tuple[str, ...] = ()
    stable_selector_hints: tuple[SelectorHint, ...] = ()
    non_secret_notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BrowserSessionContext:
    """Non-secret session metadata suitable for sanitized run state and UI display."""

    profile_id: str
    session_id: str
    live_url: str
    allowed_domains: tuple[str, ...]
    created_at: str
    inactivity_expires_at: str
    maximum_expires_at: str


class BrowserWorker:
    """Future Browser Use worker; Phase 0/1 methods are explicit no-call stubs."""

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        del profile_id
        raise PhaseUnavailableError(phase=5, capability="Browser Use session")

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
    ) -> BrowserObservation:
        del context, research
        raise PhaseUnavailableError(phase=5, capability="browser onboarding")

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
    ) -> BrowserObservation:
        del context, signal
        raise PhaseUnavailableError(phase=5, capability="browser HITL resume")

    async def stop(self, context: BrowserSessionContext) -> None:
        del context
        raise PhaseUnavailableError(phase=5, capability="Browser Use session stop")
