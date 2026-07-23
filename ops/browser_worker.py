"""Browser Use Cloud v3 boundary and trusted raw-browser execution."""

from __future__ import annotations

import importlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

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
    ) -> BrowserObservation:
        self._require_configuration()
        if context.session_id:
            self._research[context.session_id] = research
        return await self._run_bounded_task(
            context=context,
            research=research,
            resume_signal=None,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        resolved = research or self._research.get(context.session_id)
        if resolved is None:
            raise ProviderOperationError(
                capability="browser HITL resume",
                reason_code="verified_research_required",
            )
        return await self._run_bounded_task(
            context=context,
            research=resolved,
            resume_signal=signal,
        )

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
        task = _render_browser_task(target_url, patterns, resume_signal)
        client = self._get_client()
        try:
            run_handle = client.run(
                task,
                schema=BrowserTaskOutput,
                session_id=context.session_id,
                model=self._settings.browser_use_model,
                keep_alive=True,
                max_cost_usd=self._settings.browser_use_max_cost_usd,
                enable_recording=False,
            )
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
) -> str:
    """Select the verified official entry URL within the app's allowlist.

    The verified P1 baseline leaves the specific URL fields empty, so the first
    allowlisted evidence URL is used as the entry point when enrichment has not
    populated a developer/setup URL.
    """

    for candidate in (
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
) -> str:  # pragma: no cover - live only
    allowlist = ", ".join(allowed_domains)
    resume_note = (
        f"A human just completed a step and reported: '{resume_signal}'. Do NOT restart from "
        f"the beginning. Continue from the CURRENT page and proceed to the next step. "
        if resume_signal
        else ""
    )
    return (
        "ROLE: You are an autonomous web agent helping an authorized account owner reach the "
        "page where they can create or view their developer API credentials. Act decisively and "
        "take real navigation steps; do not stop after only opening the first page.\n\n"
        f"{resume_note}"
        f"START: Open {target_url}. Stay strictly within these hostnames: {allowlist}. Never "
        "navigate to any other domain.\n\n"
        "GOAL: Reach the account's API credentials / developer-app / API-token page (for example "
        "an account 'Settings -> Personal preferences -> API' or a developer app's credentials "
        "screen). Take the concrete steps a person would: click 'Log in' or 'Sign up' if shown, "
        "click through onboarding/continue buttons, open account or developer settings, and open "
        "the API/token section. Keep going step by step until you either reach that page or hit a "
        "gate that only a human can clear.\n\n"
        "SAFE ACTIONS you may do yourself: click navigation links/buttons, open menus and "
        "settings, dismiss cookie banners, and fill clearly non-secret fields (name, company, "
        "website, work email, use case) ONLY when their values are already visibly present on the "
        "page. Never invent values.\n\n"
        "HARD STOPS — set hitl_required=true and STOP (do not attempt these yourself): entering a "
        "password, solving a CAPTCHA, any MFA/OTP/2FA code, email or phone verification, passkey "
        "or security-key prompts, device approval, accepting legal/terms/consent, confirming "
        "account ownership, entering billing/payment details, or any 'reveal/copy your API token' "
        "step. In hitl_reason, name the single specific action the human must take (e.g. "
        "'Enter your Pipedrive password to log in').\n\n"
        "NEVER read, type, copy, transcribe, or report any password, secret, API token, cookie, "
        "or credential value, even if it is visible.\n\n"
        "OUTPUT: When you stop (goal reached or a hard stop), return the structured fields: "
        "current_url (the exact current page URL), reached_official_setup_page (true only if the "
        "API credentials/token page is actually visible), hitl_required, hitl_reason (specific "
        "action or null), and safe_summary (one short sentence, no secrets)."
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
