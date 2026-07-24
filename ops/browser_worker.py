"""Browser Use Cloud v3 boundary and trusted raw-browser execution."""

from __future__ import annotations

import importlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from ops.browser_api_trace_catalog import BrowserApiTrace, render_browser_api_trace
from ops.browser_host_policy import (
    BrowserHostDecision,
    BrowserPolicyInactiveError,
    build_browser_allowed_hosts,
    evaluate_navigation,
)
from ops.config import Settings
from ops.models import OperationalResearch
from ops.provider_errors import (
    ConfigurationRequiredError,
    PhaseUnavailableError,
    ProviderContractError,
    ProviderOperationError,
)

# Bounded windows used to describe session lifetime in sanitized state. The
# signed live-view URL is never represented; only its presence is recorded.
_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)


class BrowserTaskOutput(BaseModel):
    """Strict structured output required from every bounded Browser Use task.

    The agent never returns credential values, cookies, or tokens. It reports
    only where it is and whether a human must act. Host validation is performed
    against ``current_url`` after the task completes.
    """

    model_config = ConfigDict(extra="ignore")

    current_url: str = Field(min_length=1, max_length=2_000)
    reached_official_setup_page: bool = False
    hitl_required: bool = False
    hitl_reason: str | None = Field(default=None, max_length=500)
    safe_summary: str = Field(default="", max_length=1_000)


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


class TrustedRawBrowserOperation(Protocol[T_co]):
    """Internal adapter that validates every page host before secret work."""

    @property
    def allowed_domains(self) -> tuple[str, ...]: ...

    @property
    def enforces_host_validation(self) -> bool: ...

    async def execute(self, cdp_url: str) -> T_co: ...


class BrowserWorker:
    """Browser Use Cloud v3 agent-session adapter (browser-use-sdk>=3.10).

    A single ``keep_alive`` session is created without a task, then one bounded
    task runs against it and the same ``session_id`` is reused for HITL resume.
    The installed public ``run``/``sessions.create`` signatures do not expose an
    ``allowed_domains`` control, so host safety is enforced by verifying the
    structured ``current_url`` against domains derived from the verified research
    after each task; recording is disabled and the signed live URL is never
    persisted, logged, or returned across a boundary.
    """

    def __init__(self, *, settings: Settings | None = None, client: object | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._client: Any = client
        # Signed live-view URLs live only here, keyed by session, for the
        # worker's own operational use. They never cross a boundary.
        self._live_urls: dict[str, str] = {}
        # Verified research cached per session so a same-session HITL resume can
        # re-derive the official allowlist without changing the graph contract.
        self._research: dict[str, OperationalResearch] = {}

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        self._require_configuration()
        client = self._get_client()
        create_kwargs: dict[str, Any] = {
            "keep_alive": True,
            "enable_recording": False,
            "max_cost_usd": self._settings.browser_use_max_cost_usd,
        }
        # Only send profile_id when present: an explicit null is rejected by the
        # current Browser Use API deployment.
        if profile_id:
            create_kwargs["profile_id"] = profile_id
        try:
            session = await client.sessions.create(**create_kwargs)
        except Exception:
            # Ambiguous creation: the session may or may not exist (for example a
            # read timeout after the server provisioned it). Signal outcome-unknown
            # so the graph reconciles rather than blindly retrying.
            raise ProviderOperationError(
                capability="Browser Use session",
                reason_code="provider_outcome_unknown",
            ) from None
        data = _dump(session)
        session_id = _string(data.get("id"))
        if not session_id:
            raise ProviderOperationError(
                capability="Browser Use session",
                reason_code="provider_outcome_unknown",
            )
        live_url = _string(data.get("live_url"))
        if live_url:
            self._live_urls[session_id] = live_url
        now = datetime.now(UTC)
        return BrowserSessionContext(
            profile_id=profile_id or session_id,
            session_id=session_id,
            live_view_available=bool(live_url),
            allowed_domains=(),
            created_at=_isoformat(now),
            inactivity_expires_at=_isoformat(now + _INACTIVITY_WINDOW),
            maximum_expires_at=_isoformat(now + _MAXIMUM_WINDOW),
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        if context.session_id:
            self._research[context.session_id] = research
        return await self._run_bounded_task(
            context=context,
            research=research,
            resume_signal=None,
            sensitive_data=sensitive_data,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        resolved = research or self._research.get(context.session_id)
        if resolved is None:
            raise ProviderOperationError(
                capability="browser HITL resume",
                reason_code="verified_research_required",
            )
        # The base worker's session_id IS the provider session, so reconnection is
        # inherent; just re-seed the verified research if the in-memory cache was
        # cleared by an API restart.
        if context.session_id:
            self._research.setdefault(context.session_id, resolved)
        return await self._run_bounded_task(
            context=context,
            research=resolved,
            resume_signal=signal,
            sensitive_data=sensitive_data,
        )

    def provider_session_id(self, handle: str) -> str | None:
        """The base worker's session id is the provider session id."""

        return handle or None

    def live_url(self, session_id: str) -> str | None:
        """Owner-only, in-memory accessor for the ephemeral signed live URL.

        The value never crosses a durable boundary (state, checkpoint, ledger,
        API, or frontend). It exists only for the owner's local interaction while
        the worker instance is alive.
        """

        return self._live_urls.get(session_id)

    async def stop(self, context: BrowserSessionContext) -> None:
        self._require_configuration()
        client = self._get_client()
        self._live_urls.pop(context.session_id, None)
        try:
            await client.sessions.stop(context.session_id)
        except Exception:
            raise ProviderOperationError(
                capability="Browser Use agent session stop",
                reason_code="provider_request_failed",
            ) from None

    async def _safe_stop(self, session_id: str) -> None:
        """Best-effort session stop that reclaims credit and never raises."""

        self._live_urls.pop(session_id, None)
        client = self._client
        if client is None or not session_id:
            return
        try:
            await client.sessions.stop(session_id)
        except Exception:
            pass

    async def _run_bounded_task(
        self,
        *,
        context: BrowserSessionContext,
        research: OperationalResearch,
        resume_signal: str | None,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation:
        try:
            allowed = build_browser_allowed_hosts(
                research.app_slug,
                research,
                access_route=research.access_route,
            )
        except BrowserPolicyInactiveError as exc:
            # Fail closed: this app/route is not an approved browser route.
            raise ProviderContractError(
                phase=5,
                capability="browser onboarding",
                reason_code=exc.reason_code,
            ) from None
        patterns = validate_allowed_domains(allowed.patterns())
        target_url = _official_target_url(research, patterns)
        # Login placeholder keys (never values) are surfaced to the task text; the
        # Browser Use v3 provider injects the values via secure ``sensitive_data``
        # placeholders the agent can type but never read.
        login_fields = tuple(sensitive_data) if sensitive_data else ()
        task = _render_browser_task(target_url, patterns, resume_signal, login_fields)
        client = self._get_client()
        run_kwargs: dict[str, Any] = {
            "schema": BrowserTaskOutput,
            "session_id": context.session_id,
            "model": self._settings.browser_use_model,
            "keep_alive": True,
            "max_cost_usd": self._settings.browser_use_max_cost_usd,
            "enable_recording": False,
        }
        browser_secrets = to_browser_sensitive_data(sensitive_data)
        if browser_secrets:
            run_kwargs["sensitive_data"] = browser_secrets
        try:
            run_handle = client.run(task, **run_kwargs)
            result = await _await_if_needed(run_handle)
        except Exception:
            # Reclaim the session so a failed run never lingers idle burning credit.
            await self._safe_stop(context.session_id)
            raise ProviderOperationError(
                capability="browser onboarding",
                reason_code="provider_request_failed",
            ) from None
        output = _coerce_task_output(result)
        current_url = sanitize_browser_url(output.current_url)
        decision = evaluate_navigation(current_url, allowed)
        if not decision.allowed:
            # The agent left the app's reviewed host allowlist: stop and fail
            # closed, returning the sanitized blocked-navigation details.
            await self._safe_stop(context.session_id)
            return _blocked_observation(decision)
        title = (output.safe_summary or "Developer setup page")[:500]
        if output.hitl_required:
            # Keep the session alive: the owner must act in the live browser, then
            # the same session is resumed. This is the only path that stays alive.
            reason = output.hitl_reason or "A human action is required in the live browser."
            return BrowserObservation(
                status="human_action_required",
                current_url=current_url,
                page_title=title,
                human_action_type=_classify_human_action(reason),
                human_instruction=reason[:1_000],
            )
        # The agent task finished without needing a human. Reclaim the session so
        # it does not sit idle burning credit; the credential page (if reached) is
        # handled through the owner credential form, not the live browser.
        await self._safe_stop(context.session_id)
        status: BrowserObservationStatus = (
            "credential_page_ready" if output.reached_official_setup_page else "navigating"
        )
        return BrowserObservation(
            status=status,
            current_url=current_url,
            page_title=title,
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
        return result

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

    def _get_client(self) -> Any:
        if self._client is None:
            if self._settings.browser_use_api_key is None:  # pragma: no cover - guarded above
                raise RuntimeError("Browser Use configuration is missing")
            module = importlib.import_module("browser_use_sdk.v3")
            client_type = module.AsyncBrowserUse
            # Cloud session provisioning can exceed a short client timeout; a
            # generous bound avoids a ReadTimeout that would otherwise be treated
            # as an ambiguous (outcome-unknown) creation.
            self._client = client_type(
                api_key=self._settings.browser_use_api_key.get_secret_value(),
                timeout=120.0,
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


def _dump(value: object) -> dict[str, Any]:  # pragma: no cover - live only
    """Read documented public fields via ``model_dump``; never parse ``repr``."""

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            # JSON mode yields native types (UUID -> str, datetime -> ISO str),
            # so downstream string handling is uniform and never sees a UUID.
            result = dump(mode="json")
        except TypeError:
            result = dump()
        if isinstance(result, dict):
            return result
    if isinstance(value, dict):
        return dict(value)
    return {
        name: getattr(value, name)
        for name in ("id", "live_url", "status", "output", "is_task_successful")
        if hasattr(value, name)
    }


def _string(value: object) -> str:  # pragma: no cover - live only
    return value if isinstance(value, str) and value else ""


def _isoformat(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


async def _await_if_needed(value: Any) -> Any:  # pragma: no cover - live only
    if hasattr(value, "__await__"):
        return await value
    return value


def _coerce_task_output(result: Any) -> BrowserTaskOutput:  # pragma: no cover - live only
    """Validate the structured task output defensively from public fields only."""

    if isinstance(result, BrowserTaskOutput):
        return result
    data = _dump(result)
    output = data.get("output", data)
    if isinstance(output, BrowserTaskOutput):
        return output
    if isinstance(output, str):
        return BrowserTaskOutput.model_validate_json(output)
    if isinstance(output, dict):
        return BrowserTaskOutput.model_validate(output)
    dumped = getattr(output, "model_dump", None)
    if callable(dumped):
        return BrowserTaskOutput.model_validate(dumped())
    raise ProviderOperationError(
        capability="browser onboarding",
        reason_code="structured_output_missing",
    )


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


def _official_target_url(
    research: OperationalResearch,
    allowed_domains: tuple[str, ...],
    *,
    preferred_url: str | None = None,
) -> str:
    """Select the verified official entry URL within the app's allowlist.

    The verified P1 baseline leaves the specific URL fields empty, so the first
    allowlisted evidence URL is used as the entry point when enrichment has not
    populated a developer/setup URL.
    """

    for candidate in (
        preferred_url,
        research.developer_portal_url,
        research.signup_url,
        research.api_base_url,
        *research.evidence_urls,
    ):
        if isinstance(candidate, str) and candidate:
            try:
                safe = sanitize_browser_url(candidate)
            except ValueError:
                continue
            if is_allowed_browser_url(safe, allowed_domains):
                return safe
    raise ProviderOperationError(
        capability="browser onboarding",
        reason_code="official_target_url_unavailable",
    )


def _render_browser_task(
    target_url: str,
    allowed_domains: tuple[str, ...],
    resume_signal: str | None,
    login_fields: tuple[str, ...] = (),
    trace: BrowserApiTrace | None = None,
) -> str:  # pragma: no cover - live only
    """Render the bounded onboarding task.

    When ``login_fields`` is non-empty the owner has submitted login credentials
    that the Browser Use provider injects as secure ``sensitive_data``. The agent
    enters them by typing the bare ``x_``-prefixed placeholder keys (e.g.
    ``x_login_email``) verbatim; the Cloud replaces each with the real value and
    the model never sees it. Plain password entry is therefore no longer a hard
    stop, but every other human-only gate (CAPTCHA, OTP/MFA, passkey, device
    approval, billing, legal consent) still pauses for HITL.
    """

    allowlist = ", ".join(allowed_domains)
    resume_note = (
        f"A human just completed a step and reported: '{resume_signal}'. Do NOT restart from "
        f"the beginning. Continue from the CURRENT page and proceed to the next step. "
        if resume_signal
        else ""
    )
    trace_note = f"{render_browser_api_trace(trace)}\n\n" if trace is not None else ""
    has_login = "login_email" in login_fields or "login_password" in login_fields
    has_otp = "login_otp" in login_fields
    has_verify_link = "login_verification_url" in login_fields
    login_note = ""
    password_hard_stop = "entering a password, "  # pragma: allowlist secret
    otp_hard_stop = "any MFA/OTP/2FA code, email or phone verification, "
    if has_verify_link:
        # The START url is the one-time sign-in link fetched from the owner's
        # inbox; opening it completes sign-in, so email verification is no longer
        # a hard stop for this step.
        otp_hard_stop = ""
        login_note += (
            "SIGN-IN LINK: The START url above is a one-time sign-in link that was emailed to the "
            "account owner and fetched for you. Opening it in this browser IS the email "
            "verification. Navigate directly to it now, let it load and finish signing you in, "
            "then continue to the API credentials page. Do NOT stop for a 'check your email' "
            "prompt. If the link shows expired or invalid, stop with hitl_required=true.\n\n"
        )
    if has_login:
        password_hard_stop = ""
        login_note += (
            "LOGIN CREDENTIALS: The account owner has provided sign-in credentials as secure "
            "placeholders. When you reach a sign-in form, ALWAYS attempt the sign-in yourself "
            "first: into the account email/username field type exactly x_login_email and into the "
            "password field type exactly x_login_password (type those placeholder tokens verbatim "
            "with nothing added — the system replaces each with the real value before it is "
            "entered), tick a 'Remember me'/'Keep me signed in' checkbox if one is present, then "
            "click the Log in / Sign in button. Do NOT stop before you have actually filled both "
            "fields and clicked submit. Use these placeholders ONLY inside the app's own login "
            "form on the allowlisted hostnames. You cannot see their real values and must never "
            "print, echo, or report them.\n"
            "IMPORTANT: A 'Remember me' checkbox, a 'protected by reCAPTCHA' badge or footer text, "
            "or an invisible/background reCAPTCHA is NOT a CAPTCHA challenge and NOT a reason to "
            "stop — proceed and submit the form. Only treat it as a CAPTCHA hard stop if, after "
            "you submit, an actual interactive challenge appears and blocks you (an 'I'm not a "
            "robot' checkbox you must click, an image/grid/tile puzzle, or a slider).\n\n"
        )
    if has_otp:
        otp_hard_stop = ""
        login_note += (
            "ONE-TIME CODE: A verification/OTP code sent to the owner's email is available as the "
            "secure placeholder x_login_otp. When the site asks for the emailed "
            "sign-in/verification code, type exactly x_login_otp into the code field (type the "
            "placeholder token verbatim — the system replaces it with the real code) and submit. "
            "Use it ONLY in the app's own verification form on the allowlisted hostnames. You "
            "cannot see its real value and must never print, echo, or report it. If the code is "
            "rejected as expired/invalid, stop with hitl_required=true.\n\n"
        )
    return (
        "ROLE: You are an autonomous web agent helping an authorized account owner reach the "
        "page where they can create or view their developer API credentials. Act decisively and "
        "take real navigation steps; do not stop after only opening the first page.\n\n"
        f"{resume_note}"
        f"{trace_note}"
        f"{login_note}"
        f"START: Open {target_url}. Stay strictly within these hostnames: {allowlist}. Never "
        "navigate to any other domain.\n\n"
        "GOAL: Reach the page where the account's API credentials are shown or generated — an "
        "API key, API token, personal access token, client id/secret, or private-app access "
        "token.\n\n"
        "FIND-THE-CREDENTIALS STRATEGY — be persistent and exhaustive. Do NOT give up after one "
        "or two clicks; running out of ideas quickly is not acceptable. Work through ALL of these "
        "before concluding it cannot be found:\n"
        "1. Open the account/profile/workspace menu and Settings, then systematically check every "
        "plausible section by name: 'Personal preferences', 'API', 'Developer'/'Developers', "
        "'Integrations', 'Apps'/'Connected apps', 'Private apps', 'Marketplace', 'Security', "
        "'Access tokens', 'OAuth', 'Webhooks', 'Account settings', 'Data & privacy'.\n"
        "2. Use the app's OWN search box (a search icon, or press '/') and search terms like "
        "'API', 'API key', 'API token', 'personal access token', 'developer', 'client secret', "
        "'access token' to jump straight to the right page.\n"
        "3. If a section lists apps/integrations, open it and look for a 'Create'/'New'/'Generate' "
        "control (e.g. 'Create private app', 'New API key', 'Generate token', 'Add integration'). "
        "Follow it and complete the non-secret setup steps (name, scopes) to reach the screen "
        "where the key/secret is shown or a 'Show/Reveal/Copy token' control appears.\n"
        "4. If a menu is hard to find, try known deep-link paths on the SAME allowlisted host "
        "(for example /settings/api, /settings/integrations, /developers, /settings/tokens).\n"
        "5. Scroll the ENTIRE page and open each tab/sub-tab; the credential or its "
        "'Show/Reveal/Generate' button may be below the fold or behind a tab you have not opened "
        "yet.\n"
        "6. If one path dead-ends, BACK UP and try a different menu, tab, or search term — try "
        "many distinct routes over many steps. Persistence is required; keep going until you "
        "actually reach a page displaying or generating the credential, or you hit a genuine "
        "human-only gate below.\n\n"
        "SAFE ACTIONS you may do yourself: click navigation links/buttons, open menus and "
        "settings, dismiss cookie banners, and fill clearly non-secret fields (name, company, "
        "website, work email, use case) ONLY when their values are already visibly present on the "
        "page. Never invent values.\n\n"
        "HARD STOPS — set hitl_required=true and STOP (do not attempt these yourself): "
        f"{password_hard_stop}solving a VISIBLE INTERACTIVE CAPTCHA challenge that actually "
        "appears and blocks you (an 'I'm not a robot' checkbox, an image/grid/tile puzzle, or a "
        "slider) — a passive 'protected by reCAPTCHA' badge or a 'Remember me' checkbox is NOT a "
        f"CAPTCHA and must not stop you, {otp_hard_stop}"
        "passkey or security-key prompts, device approval, accepting "
        "legal/terms/consent, confirming account ownership, entering billing/payment details, or "
        "any 'reveal/copy your API token' step. In hitl_reason, name the single specific action "
        "the human must take (e.g. 'Enter the email verification code sent to your inbox').\n\n"
        "NEVER read, type, copy, transcribe, or report any password, secret, API token, cookie, "
        "or credential value, even if it is visible. The login placeholders are the only "
        "exception, and only for typing into the app's own login form.\n\n"
        "OUTPUT: When you stop (goal reached or a hard stop), return the structured fields: "
        "current_url (the exact current page URL), reached_official_setup_page (true only if the "
        "API credentials/token page is actually visible), hitl_required, hitl_reason (specific "
        "action or null), and safe_summary (one short sentence, no secrets)."
    )


# Browser Use v3 substitutes a ``sensitive_data`` value ONLY when the agent
# types the exact placeholder KEY, and the documented convention is a bare
# ``x_``-prefixed key referenced directly in the task (e.g. ``x_user``) — NOT a
# ``<secret>key</secret>`` wrapper, which the Cloud types literally into the
# field. We therefore expose the owner login to Browser Use under ``x_`` keys and
# reference those bare keys verbatim in the task text.
_BROWSER_SECRET_KEYS: dict[str, str] = {
    "login_email": "x_login_email",
    "login_password": "x_login_password",  # pragma: allowlist secret
    "login_otp": "x_login_otp",
}


def to_browser_sensitive_data(
    sensitive_data: Mapping[str, str] | None,
) -> dict[str, str] | None:
    """Map internal owner-login keys to Browser Use ``sensitive_data`` placeholders.

    Only the typed credential fields are forwarded, each under the ``x_`` key the
    task references verbatim so the Cloud substitutes the real value. Non-typed
    internal signals (for example the one-time sign-in URL, which is navigated to
    rather than typed) are dropped so they never reach the provider as a form
    secret. Returns ``None`` when there is nothing to inject.
    """

    if not sensitive_data:
        return None
    mapped = {
        placeholder: sensitive_data[internal]
        for internal, placeholder in _BROWSER_SECRET_KEYS.items()
        if sensitive_data.get(internal)
    }
    return mapped or None


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
    "BrowserTaskOutput",
    "BrowserWorker",
    "HumanActionType",
    "PhaseUnavailableError",
    "SelectorHint",
    "TrustedRawBrowserOperation",
    "is_allowed_browser_url",
    "sanitize_browser_url",
    "validate_allowed_domains",
]
