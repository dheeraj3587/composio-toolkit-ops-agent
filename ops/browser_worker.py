"""Fail-closed Browser Use boundary and trusted raw-browser execution."""

from __future__ import annotations

import importlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Generic, Literal, Protocol, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ops.config import Settings
from ops.models import OperationalResearch
from ops.provider_errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderContractError,
    ProviderOperationError,
)

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

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)
T = TypeVar("T")


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "current_url", sanitize_browser_url(self.current_url))
        if not self.page_title or len(self.page_title) > 500:
            raise ValueError("browser page title is invalid")
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
    """Sanitized session metadata; bearer capability URLs are never represented."""

    profile_id: str
    session_id: str
    live_view_available: bool
    allowed_domains: tuple[str, ...]
    created_at: str
    inactivity_expires_at: str
    maximum_expires_at: str


class TrustedRawBrowserOperation(Protocol, Generic[T]):
    """Internal adapter that validates every page host before secret work."""

    @property
    def allowed_domains(self) -> tuple[str, ...]: ...

    @property
    def enforces_host_validation(self) -> bool: ...

    async def execute(self, cdp_url: str) -> T: ...


class BrowserWorker:
    """Browser Use Cloud adapter that refuses unsafe agent-session execution.

    Installed Browser Use v3 agent sessions do not expose a typed
    ``allowed_domains`` control or attachable CDP endpoint. Agent navigation is
    therefore contract-incompatible, not silently downgraded. V3 raw browsers
    are available only to a trusted deterministic operation that performs host
    checks immediately before each sensitive action.
    """

    def __init__(self, *, settings: Settings | None = None, client: object | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._client = client

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        del profile_id
        self._require_configuration()
        raise ProviderContractError(
            phase=5,
            capability="Browser Use agent session",
            reason_code="v3_domain_restriction_unavailable",
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
    ) -> BrowserObservation:
        del context, research
        self._require_configuration()
        raise ProviderContractError(
            phase=5,
            capability="browser onboarding",
            reason_code="v3_domain_restriction_unavailable",
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
    ) -> BrowserObservation:
        del context, signal
        self._require_configuration()
        raise ProviderContractError(
            phase=5,
            capability="browser HITL resume",
            reason_code="v3_domain_restriction_unavailable",
        )

    async def stop(self, context: BrowserSessionContext) -> None:
        del context
        self._require_configuration()
        raise ProviderContractError(
            phase=5,
            capability="Browser Use agent session stop",
            reason_code="v3_domain_restriction_unavailable",
        )

    async def run_trusted_raw_browser(
        self,
        *,
        profile_id: str,
        operation: TrustedRawBrowserOperation[T],
        timeout_seconds: int = 60,
    ) -> T:
        """Run a deterministic operation while keeping CDP/live URLs ephemeral."""

        self._require_configuration()
        if not profile_id or len(profile_id) > 500:
            raise ValueError("a bounded Browser Use profile ID is required")
        if not 1 <= timeout_seconds <= 240:
            raise ValueError("raw browser timeout must be between 1 and 240 seconds")
        validate_allowed_domains(operation.allowed_domains)
        if operation.enforces_host_validation is not True:
            raise ProviderContractError(
                phase=6,
                capability="trusted raw-browser operation",
                reason_code="adapter_host_validation_missing",
            )
        client = self._get_client()
        remote: object | None = None
        operation_succeeded = False
        missing = object()
        result: T | object = missing
        try:
            remote = await client.browsers.create(
                profile_id=profile_id,
                timeout=timeout_seconds,
                allow_resizing=False,
                enable_recording=False,
            )
            cdp_url = getattr(remote, "cdp_url", None)
            if not isinstance(cdp_url, str) or not cdp_url:
                raise ProviderContractError(
                    phase=6,
                    capability="trusted raw-browser operation",
                    reason_code="cdp_capability_missing",
                )
            result = await operation.execute(cdp_url)
            operation_succeeded = True
        except (ProviderContractError, ProviderOperationError):
            raise
        except Exception:
            raise ProviderOperationError(
                capability="trusted raw-browser operation",
                reason_code="provider_request_failed",
            ) from None
        finally:
            cleanup_failed = False
            if remote is not None:
                remote_id = getattr(remote, "id", None)
                if isinstance(remote_id, str) and remote_id:
                    try:
                        await client.browsers.stop(remote_id)
                    except Exception:
                        cleanup_failed = True
            if not await self._close_safely():
                cleanup_failed = True
            if operation_succeeded and cleanup_failed:
                raise ProviderOperationError(
                    capability="trusted raw-browser operation",
                    reason_code="cleanup_failed",
                )
        if result is missing:  # pragma: no cover - operation success implies a return value
            raise RuntimeError("trusted raw-browser operation returned no result")
        return result  # type: ignore[return-value]

    async def close(self) -> None:
        if not await self._close_safely():
            raise ProviderOperationError(
                capability="Browser Use client cleanup",
                reason_code="cleanup_failed",
            )

    async def _close_safely(self) -> bool:
        client = self._client
        self._client = None
        if client is not None and callable(getattr(client, "close", None)):
            try:
                await client.close()
            except Exception:
                return False
        return True

    def _require_configuration(self) -> None:
        if not self._settings.allow_live_browser:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Browser Use",
                reason_code="live_browser_opt_in_required",
            )
        if self._settings.browser_use_api_key is None:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Browser Use",
                reason_code="browser_use_api_key_missing",
            )

    def _get_client(self) -> object:
        if self._client is None:
            if self._settings.browser_use_api_key is None:  # pragma: no cover - guarded above
                raise RuntimeError("Browser Use configuration is missing")
            module = importlib.import_module("browser_use_sdk.v3")
            client_type = getattr(module, "AsyncBrowserUse")
            self._client = client_type(
                api_key=self._settings.browser_use_api_key.get_secret_value()
            )
        return self._client


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
                raise ValueError("allowed domain is invalid")
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


__all__ = [
    "BrowserObservation",
    "BrowserObservationStatus",
    "BrowserSessionContext",
    "BrowserWorker",
    "HumanActionType",
    "PhaseUnavailableError",
    "SelectorHint",
    "TrustedRawBrowserOperation",
    "is_allowed_browser_url",
    "sanitize_browser_url",
    "validate_allowed_domains",
]
