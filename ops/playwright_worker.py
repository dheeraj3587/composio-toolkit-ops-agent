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

import asyncio
import importlib
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser_api_trace_catalog import get_browser_api_trace
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_loop import BrowserLoop, BrowserOperationTimeout, shared_browser_loop
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
_MAX_SCREENSHOT_BYTES = 4_000_000


def navigation_allowed(url: str, patterns: tuple[str, ...]) -> bool:
    """True when ``url`` is an https URL whose host is inside the allowlist."""

    return is_allowed_browser_url(url, patterns)


# Request kinds that can EXFILTRATE data (send it somewhere) as opposed to merely
# rendering the page. These are blocked off-allowlist even though they are not
# top-level navigations, because credentials are typed into the DOM and a
# compromised third-party script could otherwise beacon them out.
_ACTIVE_RESOURCE_TYPES = frozenset(
    {"document", "xhr", "fetch", "websocket", "eventsource", "manifest", "other"}
)
# Passive render-only asset kinds: allowed off-allowlist so real pages still work.
_PASSIVE_RESOURCE_TYPES = frozenset({"image", "font", "stylesheet", "media"})


def make_route_handler(patterns: tuple[str, ...]) -> Any:
    """Build a Playwright route handler enforcing a two-tier egress policy.

    * ACTIVE requests (document navigations, fetch/XHR, websockets, event streams,
      form posts, scripts) are ABORTED when the target host is off-allowlist — this
      is the exfiltration boundary, not just a navigation guard.
    * PASSIVE render-only assets (images, fonts, stylesheets, media) are allowed
      off-allowlist so real vendor pages still render.

    Unknown resource types fail CLOSED (treated as active).
    """

    async def _handler(route: Any) -> None:
        request = route.request
        try:
            resource_type = str(request.resource_type or "other")
            url = str(request.url)
        except Exception:
            await route.abort()
            return
        if navigation_allowed(url, patterns):
            await route.continue_()
            return
        # Off-allowlist: allow only passive, render-only assets.
        if resource_type in _PASSIVE_RESOURCE_TYPES:
            await route.continue_()
            return
        await route.abort()

    return _handler


@dataclass(slots=True)
class _PwSession:
    playwright: Any
    browser: Any
    context: Any
    page: Any
    patterns: tuple[str, ...] = ()
    app_slug: str = ""
    # Serializes page operations for THIS session (navigate/observe/capture/
    # screenshot/teardown) so two concurrent commands cannot interleave on one page.
    # Created on the browser loop, where every page operation also runs.
    operation_lock: Any = field(default_factory=asyncio.Lock)
    # Latest sanitized screenshot (PNG bytes) for the HITL live view.
    screenshot: bytes | None = field(default=None)
    screenshot_at: str | None = field(default=None)
    # TTL bookkeeping so idle/overlong sessions can be reaped (a session is a real
    # Chromium process; leaking them would exhaust a small VPS).
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_active_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def is_expired(self, now: datetime) -> bool:
        return (
            now - self.last_active_at > _INACTIVITY_WINDOW
            or now - self.created_at > _MAXIMUM_WINDOW
        )


class PlaywrightBrowserWorker:
    """BrowserProvider backed by local Chromium via Playwright."""

    # Provider identity for the effect ledger, audit events, health, and metrics —
    # so a Playwright run is never recorded as a Browser Use effect.
    provider_name = "playwright"
    supports_live_url = False  # HITL uses the screenshot live view instead
    supports_screenshot = True
    supports_restart_reattach = False  # in-process browser dies with the API

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
        # Concurrency cap: sized for a small VPS (each session is a Chromium process).
        self._max_sessions = max(1, int(getattr(self._settings, "playwright_max_sessions", 2)))
        # Registry mutation happens from several application threads.
        self._registry_lock = threading.Lock()

    def _launch_args(self) -> list[str]:
        """Chromium flags. ``--no-sandbox`` is OPT-IN, not a hardcoded default.

        Disabling Chromium's own sandbox weakens defence-in-depth, so it is only
        applied when the deployment explicitly asks for it (dev sandboxes and
        containers without the required seccomp/user-namespace support).
        """

        args = ["--disable-dev-shm-usage"]
        if bool(getattr(self._settings, "playwright_disable_sandbox", False)):
            args.append("--no-sandbox")
        return args

    def _reap_expired(self) -> tuple[str, ...]:
        """Drop sessions past their inactivity or maximum lifetime.

        Synchronous so it can run from ``start`` before admitting a new session;
        teardown of the reaped browsers is scheduled on the owning loop.
        """

        now = datetime.now(UTC)
        with self._registry_lock:
            expired = [
                handle for handle, session in self._sessions.items() if session.is_expired(now)
            ]
            reaped = [(handle, self._sessions.pop(handle)) for handle in expired]
        for _, session in reaped:
            try:
                self._loop.run_sync(_shutdown_session(session), timeout=30.0)
            except Exception:
                pass
        return tuple(handle for handle, _ in reaped)

    def touch(self, handle: str) -> None:
        """Mark a session active so the inactivity reaper does not collect it."""

        session = self._sessions.get(handle)
        if session is not None:
            session.last_active_at = datetime.now(UTC)

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
        # Capacity guard: each session is a real Chromium process, so an unbounded
        # count would exhaust a small VPS. Refuse rather than thrash.
        self._reap_expired()
        if len(self._sessions) >= self._max_sessions:
            raise ProviderOperationError(
                capability="Playwright browser",
                reason_code="browser_capacity_exceeded",
            )
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
                browser = await playwright.chromium.launch(headless=True, args=self._launch_args())
                # Service workers are blocked: during a secret-bearing session a
                # worker could persist and relay data outside the page lifecycle.
                context = await browser.new_context(service_workers="block")
                page = await context.new_page()
            except Exception:
                await _safe(playwright.stop)
                raise
            return playwright, browser, context, page

        try:
            playwright, browser, context, page = await self._loop.run(_launch())
        except BrowserOperationTimeout:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="browser_launch_timeout"
            ) from None
        except Exception as exc:
            # Distinguish the real failure modes instead of collapsing them all into
            # provider_request_failed, which hides a missing binary or dependency.
            raise ProviderOperationError(
                capability="Playwright browser", reason_code=_launch_reason_code(exc)
            ) from None
        now = datetime.now(UTC)
        handle = f"pw_{uuid4().hex}"
        session = _PwSession(playwright, browser, context, page)
        session.created_at = now
        session.last_active_at = now
        with self._registry_lock:
            self._sessions[handle] = session
        return BrowserSessionContext(
            profile_id=profile_id or handle,
            session_id=handle,
            # The screenshot live view is available for this provider (no hosted URL).
            live_view_available=True,
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
        session.app_slug = research.app_slug

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
        """Observe the page and classify it against VERIFIED trace signals.

        Two correctness rules this enforces:

        1. Filling a login form does not clear it — the form must be SUBMITTED and
           the page transition awaited. Only if a password field survives submission
           (or no credentials were supplied) is a human action requested.
        2. ``credential_page_ready`` is returned ONLY when a reviewed success signal
           from the app's STRICT APP TRACE is actually present on the page. The mere
           absence of a password field is never treated as success — an email-first
           login page has no password input, and must not be mistaken for the
           credential page.
        """

        trace = get_browser_api_trace(session.app_slug) if session.app_slug else None
        success_signals = tuple(trace.success_signals) if trace is not None else ()

        async def _inspect() -> tuple[str, str, bool, str]:
            if sensitive_data and await _has_password_field(session.page):
                # Fill AND submit, then wait for the resulting navigation/render.
                await _inject_login(session.page, sensitive_data)
                await _submit_login(session.page)
            url = _page_url(session.page)
            try:
                title = await session.page.title()
            except Exception:
                title = ""
            has_password = await _has_password_field(session.page)
            body = await _visible_text(session.page)
            return url, (title if isinstance(title, str) else ""), has_password, body

        async with session.operation_lock:
            raw_url, raw_title, has_password, body_text = await self._loop.run(_inspect())
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
                human_instruction="Sign-in could not be completed automatically.",
            )

        matched = matched_success_signals(success_signals, url=current, title=title, text=body_text)
        if matched:
            return BrowserObservation(
                status="credential_page_ready",
                current_url=current,
                page_title=title,
                non_secret_notes=(f"Verified success signal: {matched[0]}"[:1_000],),
            )
        # No verified signal: report progress honestly rather than claiming success.
        return BrowserObservation(
            status="navigating",
            current_url=current,
            page_title=title,
            non_secret_notes=("No reviewed success signal is present on this page yet.",),
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
            # Mask credential-bearing fields so a screenshot can never leak a secret
            # value (it is page pixels, and the credential page is exactly where the
            # agent ends up). Masking failures fall back to no screenshot, never to
            # an unmasked one.
            try:
                masks = [
                    session.page.locator("input[type='password']"),
                    session.page.locator("input[name*='token' i]"),
                    session.page.locator("input[name*='secret' i]"),
                    session.page.locator("input[name*='key' i]"),
                    session.page.locator("[data-secret]"),
                ]
                data = await session.page.screenshot(
                    type="png", full_page=False, mask=masks, timeout=15_000
                )
            except Exception:
                return None
            if not isinstance(data, bytes) or len(data) > _MAX_SCREENSHOT_BYTES:
                return None
            return data

        image = await self._loop.run(_shot())
        if image is None:
            return False
        session.screenshot = image
        session.screenshot_at = datetime.now(UTC).isoformat()
        return True

    def live_url(self, session_id: str) -> str | None:
        """No hosted live URL exists for a self-hosted browser.

        Required by the workflow browser contract: without it the live-view lookup
        would raise AttributeError and surface as an HTTP 500. Returning None makes
        the caller report "no live URL", and the screenshot live view is used instead.
        """

        del session_id
        return None

    def provider_session_id(self, handle: str) -> str | None:
        """The local session handle IS the provider session for a self-hosted browser."""

        return handle if handle in self._sessions else None

    def latest_screenshot(self, handle: str) -> tuple[bytes, str] | None:
        """Return the newest screenshot for a session handle, if any."""

        session = self._sessions.get(handle)
        if session is None or session.screenshot is None or session.screenshot_at is None:
            return None
        return session.screenshot, session.screenshot_at

    async def stop(self, context: BrowserSessionContext) -> None:
        with self._registry_lock:
            session = self._sessions.pop(context.session_id, None)
        if session is not None:
            await self._teardown(session)

    async def close(self) -> None:
        with self._registry_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            await self._teardown(session)

    async def _teardown(self, session: _PwSession) -> None:
        # Teardown must also run on the owning loop.
        try:
            await self._loop.run(_shutdown_session(session), timeout=60.0)
        except Exception:
            pass
        session.screenshot = None  # drop the in-memory image promptly


# --- small helpers (kept module-level for unit testing) -----------------------
async def _shutdown_session(session: _PwSession) -> None:
    """Close a session's page/context/browser/playwright in dependency order."""

    session.screenshot = None
    await _safe(session.context.close)
    await _safe(session.browser.close)
    await _safe(session.playwright.stop)


def _launch_reason_code(exc: BaseException) -> str:
    """Map a Chromium launch failure to a specific, sanitized reason code.

    Only the exception's own message text is inspected (never a URL, DOM content, or
    credential), so the resulting code is safe to log and surface.
    """

    text = f"{type(exc).__name__} {exc}".casefold()
    if "executable doesn't exist" in text or "please run the following command" in text:
        return "chromium_executable_missing"
    if "host system is missing dependencies" in text or "error while loading shared" in text:
        return "chromium_dependency_missing"
    if "singletonlock" in text or "profile" in text and "lock" in text:
        return "browser_profile_locked"
    if "timeout" in text or "timed out" in text:
        return "browser_launch_timeout"
    if "out of memory" in text or "cannot allocate" in text:
        return "browser_out_of_memory"
    return "browser_launch_failed"


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


async def _submit_login(page: Any) -> bool:
    """Submit the filled login form and wait for the page to settle.

    Filling inputs alone never advances a login flow. Tries the submit control, then
    falls back to pressing Enter in the password field. Always waits for the network
    to go idle (bounded) so the next observation sees the post-submit page.
    """

    submitted = False
    for selector in (
        "button[type='submit']",
        "input[type='submit']",
        "button:has-text('Log in')",
        "button:has-text('Sign in')",
        "button:has-text('Continue')",
    ):
        try:
            locator = page.locator(selector)
            if await locator.count() >= 1:
                await locator.first.click(timeout=5_000)
                submitted = True
                break
        except Exception:
            continue
    if not submitted:
        try:
            await page.locator("input[type='password']").first.press("Enter", timeout=5_000)
            submitted = True
        except Exception:
            submitted = False
    if submitted:
        try:
            await page.wait_for_load_state("networkidle", timeout=20_000)
        except Exception:
            pass
    return submitted


async def _visible_text(page: Any, *, limit: int = 20_000) -> str:
    """Best-effort visible body text, bounded. Used only for signal matching."""

    try:
        text = await page.inner_text("body", timeout=5_000)
    except Exception:
        return ""
    return text[:limit] if isinstance(text, str) else ""


def _normalize_signal(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def matched_success_signals(
    signals: Sequence[str], *, url: str, title: str, text: str
) -> tuple[str, ...]:
    """Return the reviewed success signals actually observed on the page.

    A signal counts only when it appears in the URL, the page title, or the visible
    body text. This is the gate for declaring the credential page reached, so it is
    deliberately evidence-based rather than inferred.
    """

    haystack = _normalize_signal(f"{url} {title} {text}")
    if not haystack:
        return ()
    hits = [
        signal for signal in signals if (needle := _normalize_signal(signal)) and needle in haystack
    ]
    return tuple(hits)


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
