"""The shared browser-observation contract every backend reports through.

This module used to also hold the Browser Use Cloud v3 adapter. That adapter is
gone: the installed SDK exposed no ``allowed_domains`` control, so it could only
check host safety *after* a task returned a URL, whereas the Playwright harness
enforces it at the network layer for every request. The types below stay here, at
their original import path, because they are the contract — not the backend.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ops.browser.host_policy import BrowserHostDecision
from ops.providers.errors import PhaseUnavailableError

# Bounded windows used to describe session lifetime in sanitized state. The
# signed live-view URL is never represented; only its presence is recorded.
_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)


BrowserObservationStatus = Literal[
    "navigating",
    "human_action_required",
    "developer_console_ready",
    "credential_page_ready",
    "blocked",
    "failed",
]

# Bounded, value-free reason codes an observation may carry. Kept as a reference
# vocabulary (the field is validated by character class, not against this list, so
# a provider-specific code is still allowed) so callers share consistent names.
BrowserReasonCode = Literal[
    "authentication_failed",
    "login_required",
    "login_frame_unreviewed",
    "multiple_login_surfaces",
    "multiple_password_forms",
    "login_origin_unsafe",
    "login_email_fill_failed",
    "login_password_fill_failed",
    "login_submit_control_not_found",
    "login_incomplete",
    "otp_required",
    "otp_surface_not_verified",
    "otp_injection_failed",
    "magic_link_required",
    "verification_link_blocked",
    "verification_link_navigation_failed",
    "account_selection_required",
    "policy_blocked",
    "navigation_timeout",
    "postcondition_failed",
    "session_lost",
]

HumanActionType = Literal[
    "login_required",
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
    # Pre-execution business decision: may the system create an account with this
    # provider? Never inferred from a page — no page classifier may emit it —
    # and emitted only by the admission service after a vault probe finds no
    # credential reference for the run's app slug and account binding.
    "signup_authorization",
]

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)
T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


@dataclass(frozen=True, slots=True)
class SelectorHint:
    """A non-secret selector hint for deterministic Playwright code."""

    field_label: str
    selector: str

    def __post_init__(self) -> None:
        if not self.field_label or len(self.field_label) > 200:
            raise ValueError("selector field label is invalid")
        if not self.selector or len(self.selector) > 1_000 or "\x00" in self.selector:
            raise ValueError("selector is invalid")


@dataclass(frozen=True, slots=True)
class BrowserObservation:
    """Bounded agent output with no generic credential-value container."""

    status: BrowserObservationStatus
    current_url: str
    page_title: str
    developer_app_id: str | None = None
    human_action_type: HumanActionType | None = None
    human_instruction: str | None = None
    credential_field_labels: tuple[str, ...] = ()
    stable_selector_hints: tuple[SelectorHint, ...] = ()
    non_secret_notes: tuple[str, ...] = ()
    # A bounded, value-free reason code (e.g. "authentication_failed"). Optional so
    # existing Browser Use results need not supply one. NEVER page or exception
    # text — it is validated to a strict character class below.
    reason_code: str | None = None
    # Browser-service HITL generation. Zero means the provider does not expose a
    # generation and therefore cannot participate in autonomous takeover.
    hitl_generation: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "current_url", sanitize_browser_url(self.current_url))
        if (
            isinstance(self.hitl_generation, bool)
            or not isinstance(self.hitl_generation, int)
            or self.hitl_generation < 0
        ):
            raise ValueError("browser HITL generation is invalid")
        if not self.page_title or len(self.page_title) > 500:
            raise ValueError("browser page title is invalid")
        if self.reason_code is not None and (
            not self.reason_code
            or len(self.reason_code) > 100
            or re.fullmatch(r"[a-z0-9_:-]+", self.reason_code) is None
        ):
            raise ValueError("browser reason code is invalid")
        if self.status == "human_action_required" and (
            self.human_action_type is None or not self.human_instruction
        ):
            raise ValueError("human action observations require a typed instruction")
        if self.status != "human_action_required" and self.human_action_type is not None:
            raise ValueError("human action type is only valid for a human-action observation")
        if len(self.credential_field_labels) > 20 or any(
            not value or len(value) > 200 for value in self.credential_field_labels
        ):
            raise ValueError("credential field labels are invalid")
        if len(self.stable_selector_hints) > 20 or len(self.non_secret_notes) > 20:
            raise ValueError("browser observation exceeds its bounded collection size")
        if any(len(value) > 1_000 for value in self.non_secret_notes):
            raise ValueError("browser observation note is too long")


@dataclass(frozen=True, slots=True)
class BrowserSessionContext:
    """Sanitized session metadata; bearer capabilities are never represented."""

    profile_id: str
    session_id: str
    live_view_available: bool
    allowed_domains: tuple[str, ...]
    created_at: str
    inactivity_expires_at: str
    maximum_expires_at: str
    # Non-secret immutable run identifier used by the API to re-derive the
    # browser-service capability after a restart. The bearer value is never stored.
    capability_scope: str = ""


class TrustedRawBrowserOperation(Protocol[T_co]):
    """Internal adapter that validates every page host before secret work."""

    @property
    def allowed_domains(self) -> tuple[str, ...]: ...

    @property
    def enforces_host_validation(self) -> bool: ...

    async def execute(self, cdp_url: str) -> T_co: ...


def validate_allowed_domains(domains: tuple[str, ...]) -> tuple[str, ...]:
    """Validate Browser Use domain patterns with wildcard only at the left edge."""

    if not domains or len(domains) > 20:
        raise ValueError("one to twenty allowed domains are required")
    normalized: list[str] = []
    for value in domains:
        candidate = value.strip().rstrip(".").casefold()
        if not candidate or len(candidate) > 253 or "://" in candidate or "/" in candidate:
            raise ValueError("allowed domains must contain hostnames only")
        wildcard = candidate.startswith("*.")
        hostname = candidate[2:] if wildcard else candidate
        if "*" in hostname or "." not in hostname:
            raise ValueError("allowed domain wildcard is invalid")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            labels = hostname.split(".")
            if any(_HOST_LABEL.fullmatch(label) is None for label in labels):
                raise ValueError("allowed domain is invalid") from None
        else:
            if not address.is_global:
                raise ValueError("private or special IP domains are not allowed")
        if hostname in {"localhost", "localhost.localdomain"}:
            raise ValueError("loopback domains are not allowed")
        normalized.append(f"*.{hostname}" if wildcard else hostname)
    if len(set(normalized)) != len(normalized):
        raise ValueError("allowed domains must be unique")
    return tuple(normalized)


def is_allowed_browser_url(url: str, allowed_domains: tuple[str, ...]) -> bool:
    """Check the live page immediately before each deterministic secret operation."""

    domains = validate_allowed_domains(allowed_domains)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False
    host = parsed.hostname.rstrip(".").casefold()
    for domain in domains:
        if domain.startswith("*."):
            parent = domain[2:]
            if host.endswith(f".{parent}") and host != parent:
                return True
        elif host == domain:
            return True
    return False


def sanitize_browser_url(value: str) -> str:
    """Remove token-bearing query values before an observation enters state."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "about"}:
        raise ValueError("browser observations require an HTTPS or about URL")
    if parsed.scheme == "https" and (not parsed.hostname or parsed.username or parsed.password):
        raise ValueError("browser observation URL is invalid")
    query = urlencode(
        [
            (name, item)
            for name, item in parse_qsl(parsed.query, keep_blank_values=True)
            if name.casefold() not in _SENSITIVE_QUERY_NAMES
        ],
        doseq=True,
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _isoformat(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _blocked_observation(decision: BrowserHostDecision) -> BrowserObservation:
    """Fail-closed observation carrying sanitized blocked-navigation details."""

    notes = (
        f"blocked_hostname={decision.blocked_hostname or 'unknown'}",
        f"reason_code={decision.reason_code}",
        f"allowed_hosts={','.join(decision.allowed_hosts)}"[:1_000],
        f"backend_policy_update_required={str(decision.backend_policy_update_required).lower()}",
    )
    return BrowserObservation(
        status="failed",
        current_url=decision.current_url,
        page_title="Navigation blocked by app host policy",
        non_secret_notes=notes,
    )


def _classify_human_action(reason: str) -> HumanActionType:
    lowered = reason.casefold()
    mapping: tuple[tuple[tuple[str, ...], HumanActionType], ...] = (
        (("captcha", "recaptcha", "challenge"), "captcha"),
        (("email", "verification code", "verify your email"), "email_otp"),
        (("sms", "text message", "phone"), "phone_otp"),
        (("passkey",), "passkey"),
        (("security key", "hardware key", "yubikey"), "security_key"),
        (("device", "approve on"), "device_approval"),
        (("legal", "terms", "agreement", "consent"), "legal_acceptance"),
        (("billing", "payment", "card", "subscription"), "billing"),
        (("select account", "choose account", "which account"), "account_selection"),
    )
    for needles, action in mapping:
        if any(needle in lowered for needle in needles):
            return action
    return "provider_verification"


__all__ = [
    "BrowserObservation",
    "BrowserObservationStatus",
    "BrowserSessionContext",
    "HumanActionType",
    "PhaseUnavailableError",
    "SelectorHint",
    "TrustedRawBrowserOperation",
    "is_allowed_browser_url",
    "sanitize_browser_url",
    "validate_allowed_domains",
]
