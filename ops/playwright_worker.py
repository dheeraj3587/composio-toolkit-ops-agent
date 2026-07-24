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

Event-loop ownership: Playwright's async objects are bound to the loop that
created them, and the orchestrator runs each graph node in its own
``asyncio.run`` loop. Every Playwright call here is therefore submitted to the
one persistent loop owned by ``ops.browser_loop.BrowserLoop``, so a session
created during ``start`` stays valid through ``navigate`` and ``resume`` no matter
how many short-lived caller loops come and go.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_loop import BrowserLoop, shared_browser_loop
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    is_allowed_browser_url,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.config import Settings
from ops.credential_capture_specs import get_capture_spec
from ops.models import OperationalResearch, validate_vault_reference
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import SecretStore

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
    # Latest sanitized screenshot (PNG bytes) for the HITL live view.
    screenshot: bytes | None = field(default=None)
    screenshot_at: str | None = field(default=None)


class PlaywrightBrowserWorker:
    """BrowserProvider backed by local Chromium via Playwright."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        secret_store: SecretStore | None = None,
        loop: BrowserLoop | None = None,
    ) -> None:
        self._settings = settings or Settings.from_env()
        self._secret_store = secret_store
        # All Playwright work runs on ONE persistent loop so a session survives
        # the orchestrator's separate per-node asyncio.run loops.
        self._loop = loop or shared_browser_loop()
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

        async def _launch() -> tuple[Any, Any, Any, Any]:
            playwright = await module.async_playwright().start()
            try:
                browser = await playwright.chromium.launch(
                    headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                context = await browser.new_context()
                page = await context.new_page()
            except Exception:
                await _safe(playwright.stop)
                raise
            return playwright, browser, context, page

        try:
            playwright, browser, context, page = await self._loop.run(_launch())
        except Exception:
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

        trace = get_browser_api_trace(research.app_slug)
        target = trace.start_url if trace is not None else research.developer_portal_url
        if not target or not navigation_allowed(target, patterns):
            return _blocked(target or "https://unknown.invalid/")

        async def _go() -> bool:
            # REAL enforcement: install the host guard before any navigation.
            await session.context.route("**/*", make_route_handler(patterns))
            try:
                await session.page.goto(
                    target, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                )
            except Exception:
                return False
            return True

        if not await self._loop.run(_go()):
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

        async def _inspect() -> tuple[str, str, bool]:
            url = _page_url(session.page)
            try:
                title = await session.page.title()
            except Exception:
                title = ""
            has_password = await _has_password_field(session.page)
            if has_password and sensitive_data:
                await _inject_login(session.page, sensitive_data)
                has_password = await _has_password_field(session.page)
            return url, (title if isinstance(title, str) else ""), has_password

        raw_url, raw_title, has_password = await self._loop.run(_inspect())
        current = sanitize_browser_url(raw_url)
        if not navigation_allowed(current, session.patterns):
            return _blocked(current)
        title = (raw_title or "Onboarding page")[:500]
        # Refresh the HITL live view for this step (best effort, never fatal).
        await self.refresh_live_view(session)

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

    async def auto_capture_credentials(
        self, handle: str, app_slug: str, secret_store: SecretStore | None = None
    ) -> dict[str, str] | None:
        """Deterministically read the app's credential from the live page and vault it.

        Reuses the same reviewed capture specs as the Browser Use path: navigate to
        the spec URL (inside the allowlist), verify the page host, then match input
        values against the spec's strict pattern. The value is never returned, never
        logged, and never shown to an LLM — only a ``vault://`` reference leaves.
        Returns None whenever capture is not possible so the caller can fall back to
        owner submission.
        """

        store = secret_store or self._secret_store
        session = self._sessions.get(handle)
        spec = get_capture_spec(app_slug)
        if session is None or spec is None or store is None:
            return None
        if not navigation_allowed(spec.url, session.patterns):
            return None
        pattern = re.compile(spec.value_pattern)

        async def _capture() -> str | None:
            try:
                await session.page.goto(
                    spec.url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                )
                await session.page.wait_for_timeout(1_500)
            except Exception:
                return None
            host = urlsplit(_page_url(session.page)).hostname or ""
            if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
                return None
            try:
                inputs = session.page.locator("input")
                total = await inputs.count()
            except Exception:
                return None
            for index in range(min(int(total), 60)):
                try:
                    value = await inputs.nth(index).input_value(timeout=2_000)
                except Exception:
                    continue
                candidate = value.strip() if isinstance(value, str) else ""
                if candidate and pattern.match(candidate):
                    return candidate
            return None

        token = await self._loop.run(_capture())
        if token is None:
            return None
        reference = store.put(app_slug=app_slug, kind=spec.field_kind, value=token)
        del token
        return {spec.field_kind: validate_vault_reference(reference)}

    async def refresh_live_view(self, session: _PwSession) -> bool:
        """Capture a PNG screenshot of the current page for the HITL live view.

        Self-hosted Playwright has no provider-hosted live URL, so the live view is
        served from these periodically refreshed screenshots. A screenshot is page
        pixels only — it can show a credential page, so it is held in memory for the
        session and never written to disk or logs.
        """

        async def _shot() -> bytes | None:
            try:
                data = await session.page.screenshot(type="png", full_page=False)
            except Exception:
                return None
            return data if isinstance(data, bytes) else None

        image = await self._loop.run(_shot())
        if image is None:
            return False
        session.screenshot = image
        session.screenshot_at = datetime.now(UTC).isoformat()
        return True

    def latest_screenshot(self, handle: str) -> tuple[bytes, str] | None:
        """Return the newest screenshot for a session handle, if any."""

        session = self._sessions.get(handle)
        if session is None or session.screenshot is None or session.screenshot_at is None:
            return None
        return session.screenshot, session.screenshot_at

    async def stop(self, context: BrowserSessionContext) -> None:
        session = self._sessions.pop(context.session_id, None)
        if session is not None:
            await self._teardown(session)

    async def close(self) -> None:
        for session in list(self._sessions.values()):
            await self._teardown(session)
        self._sessions.clear()

    async def _teardown(self, session: _PwSession) -> None:
        async def _shutdown() -> None:
            await _safe(session.context.close)
            await _safe(session.browser.close)
            await _safe(session.playwright.stop)

        # Teardown must also run on the owning loop.
        try:
            await self._loop.run(_shutdown())
        except Exception:
            pass
        session.screenshot = None


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
