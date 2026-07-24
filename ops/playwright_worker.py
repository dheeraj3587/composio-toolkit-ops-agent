"""Self-hosted Playwright browser harness — Phase B core.

A drop-in ``BrowserProvider`` that drives REAL local Chromium instead of the paid
Browser Use cloud. This phase establishes the pieces that do not need the LLM
action brain (added next): the session lifecycle, genuine provider-side host
enforcement via route interception (abort any document navigation that would
leave the app's reviewed allowlist — something Browser Use v3 cannot do), coded
secret injection (the LLM never sees a value), and deterministic trace-driven
navigation to the credential page. The LLM decider plugs into ``_observe`` later.

Security parity with the Browser Use path: the same reviewed per-app host policy,
the same bounded ``BrowserObservation`` (no raw-credential container), and secrets
injected by code and surfaced to guidance only as placeholder key names.

KNOWN FOLLOW-UP before prod wiring (Phase E): Playwright's async objects are bound
to the event loop that created them. The current orchestrator runs each graph node
in its own ``asyncio.run`` loop, so a single browser session cannot yet span
start -> navigate -> resume across those separate loops. The fix is a dedicated
browser thread owning one persistent loop, with methods submitting coroutines to
it (``run_coroutine_threadsafe``). This phase is sandbox-only and single-loop, so
that runner is deliberately deferred and must land before Phase E.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    is_allowed_browser_url,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.config import Settings
from ops.models import OperationalResearch
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)
_NAV_TIMEOUT_MS = 45_000


def navigation_allowed(url: str, patterns: tuple[str, ...]) -> bool:
    """True when ``url`` is an https URL whose host is inside the allowlist."""

    return is_allowed_browser_url(url, patterns)


def make_route_handler(patterns: tuple[str, ...]) -> Any:
    """Build a Playwright route handler that aborts off-allowlist NAVIGATIONS.

    Only top-level document navigations are gated (the agent trying to leave the
    app). Subresources (fonts, scripts, images from CDNs) are allowed so real
    pages still render — the goal is to bound where the session can *navigate* and
    where credentials can be typed, not to proxy every asset.
    """

    async def _handler(route: Any) -> None:
        request = route.request
        try:
            is_doc = request.resource_type == "document" and request.is_navigation_request()
        except Exception:
            is_doc = False
        if is_doc and not navigation_allowed(request.url, patterns):
            await route.abort()
            return
        await route.continue_()

    return _handler


@dataclass(slots=True)
class _PwSession:
    playwright: Any
    browser: Any
    context: Any
    page: Any
    patterns: tuple[str, ...] = ()


class PlaywrightBrowserWorker:
    """BrowserProvider backed by local Chromium via Playwright."""

    def __init__(self, *, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._sessions: dict[str, _PwSession] = {}
        self._research: dict[str, OperationalResearch] = {}

    def _require_configuration(self) -> None:
        # The self-hosted harness needs the live opt-in but NO Browser Use key.
        if not self._settings.allow_live_browser:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser",
                reason_code="live_browser_opt_in_required",
            )

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        self._require_configuration()
        try:
            module = importlib.import_module("playwright.async_api")
        except ImportError:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser",
                reason_code="playwright_not_installed",
            ) from None
        playwright = await module.async_playwright().start()
        try:
            browser = await playwright.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context()
            page = await context.new_page()
        except Exception:
            await _safe(playwright.stop)
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="provider_request_failed"
            ) from None
        handle = f"pw_{uuid4().hex}"
        self._sessions[handle] = _PwSession(playwright, browser, context, page)
        now = datetime.now(UTC)
        return BrowserSessionContext(
            profile_id=profile_id or handle,
            session_id=handle,
            live_view_available=False,  # screenshot streaming is a later phase
            allowed_domains=(),
            created_at=now.isoformat(),
            inactivity_expires_at=(now + _INACTIVITY_WINDOW).isoformat(),
            maximum_expires_at=(now + _MAXIMUM_WINDOW).isoformat(),
        )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        session = self._sessions.get(context.session_id)
        if session is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="session_missing"
            )
        self._research[context.session_id] = research
        patterns = self._resolve_patterns(research)
        session.patterns = patterns
        # REAL enforcement: install the host guard before any navigation.
        await session.context.route("**/*", make_route_handler(patterns))

        trace = get_browser_api_trace(research.app_slug)
        target = trace.start_url if trace is not None else research.developer_portal_url
        if not target or not navigation_allowed(target, patterns):
            return _blocked(target or "https://unknown.invalid/")

        try:
            await session.page.goto(target, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS)
        except Exception:
            # A blocked navigation (host guard) or a load failure: fail closed.
            return _blocked(target)

        return await self._observe(session, sensitive_data=sensitive_data)

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del signal, provider_session_id
        self._require_configuration()
        session = self._sessions.get(context.session_id)
        if session is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="session_missing"
            )
        resolved = research or self._research.get(context.session_id)
        if resolved is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="verified_research_required"
            )
        return await self._observe(session, sensitive_data=sensitive_data)

    async def _observe(
        self, session: _PwSession, *, sensitive_data: Mapping[str, str] | None
    ) -> BrowserObservation:
        """Deterministic observation (pre-LLM-brain).

        If the page has a password field, coded credential injection is attempted
        (never via an LLM); if a login wall remains, a human action is requested.
        Otherwise the current allowlisted page is reported as credential-page-ready
        for the deterministic/reference apps. The LLM decider will refine this.
        """

        current = sanitize_browser_url(_page_url(session.page))
        if not navigation_allowed(current, session.patterns):
            return _blocked(current)
        title = (_page_title(session.page) or "Onboarding page")[:500]

        has_password = await _has_password_field(session.page)
        if has_password and sensitive_data:
            await _inject_login(session.page, sensitive_data)
            has_password = await _has_password_field(session.page)

        if has_password:
            return BrowserObservation(
                status="human_action_required",
                current_url=current,
                page_title=title,
                human_action_type="provider_verification",
                human_instruction="Sign-in is required in the live browser to continue.",
            )
        return BrowserObservation(
            status="credential_page_ready",
            current_url=current,
            page_title=title,
            non_secret_notes=("Reached an allowlisted onboarding/credential page.",),
        )

    def _resolve_patterns(self, research: OperationalResearch) -> tuple[str, ...]:
        try:
            allowed = build_browser_allowed_hosts(
                research.app_slug, research, access_route=research.access_route
            )
        except BrowserPolicyInactiveError as exc:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code=exc.reason_code
            ) from None
        return validate_allowed_domains(allowed.patterns())

    async def stop(self, context: BrowserSessionContext) -> None:
        session = self._sessions.pop(context.session_id, None)
        if session is not None:
            await self._teardown(session)

    async def close(self) -> None:
        for session in list(self._sessions.values()):
            await self._teardown(session)
        self._sessions.clear()

    async def _teardown(self, session: _PwSession) -> None:
        await _safe(session.context.close)
        await _safe(session.browser.close)
        await _safe(session.playwright.stop)


# --- small helpers (kept module-level for unit testing) -----------------------
async def _safe(coro_fn: Any) -> None:
    try:
        result = coro_fn()
        if result is not None:
            await result
    except Exception:
        pass


def _page_url(page: Any) -> str:
    url = getattr(page, "url", "")
    return url if isinstance(url, str) and url else "https://unknown.invalid/"


def _page_title(page: Any) -> str:
    # Playwright's title() is async; observation uses a best-effort cached value.
    getter = getattr(page, "_cached_title", None)
    return getter if isinstance(getter, str) else ""


async def _has_password_field(page: Any) -> bool:
    try:
        locator = page.locator("input[type='password']")
        return bool(await locator.count() > 0)
    except Exception:
        return False


async def _inject_login(page: Any, sensitive_data: Mapping[str, str]) -> None:
    """Fill login fields by code from placeholder->value pairs; the value is never
    logged and never passed to an LLM. Best-effort by common field heuristics."""

    email = sensitive_data.get("login_email") or sensitive_data.get("email")
    password = sensitive_data.get("login_password") or sensitive_data.get("password")
    if email:
        for selector in ("input[type='email']", "input[name='email']", "input[name='username']"):
            if await _try_fill(page, selector, email):
                break
    if password:
        await _try_fill(page, "input[type='password']", password)


async def _try_fill(page: Any, selector: str, value: str) -> bool:
    try:
        locator = page.locator(selector)
        if await locator.count() >= 1:
            await locator.first.fill(value, timeout=5_000)
            return True
    except Exception:
        return False
    return False


def _blocked(url: str) -> BrowserObservation:
    parsed = urlsplit(url)
    host = parsed.hostname or "unknown"
    return BrowserObservation(
        status="blocked",
        current_url=sanitize_browser_url(url),
        page_title=f"Navigation blocked by host policy ({host})"[:500],
        non_secret_notes=("Target was outside the reviewed host allowlist.",),
    )


__all__ = ["PlaywrightBrowserWorker", "make_route_handler", "navigation_allowed"]
