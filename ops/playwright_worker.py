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

from ops.browser_api_trace_catalog import (
    BrowserApiTrace,
    BrowserApiTraceStep,
    get_browser_api_trace,
)
from ops.browser_decider import (
    MAX_ELEMENTS,
    BrowserAction,
    SnapshotElement,
    action_schema,
    build_decision_prompt,
    build_snapshot,
    match_checkpoint,
    validate_action,
)
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_loop import BrowserLoop, BrowserOperationTimeout, shared_browser_loop
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    HumanActionType,
    is_allowed_browser_url,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.config import Settings
from ops.credential_capture_specs import get_capture_spec
from ops.inference import build_json_inference
from ops.models import OperationalResearch, validate_vault_reference
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import SecretStore

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)
_NAV_TIMEOUT_MS = 45_000
_MAX_SCREENSHOT_BYTES = 4_000_000
_JANITOR_INTERVAL_SECONDS = 60.0
_OP_TIMEOUT_SECONDS = 90.0

# Bounds for the agent action loop: it must always terminate.
_MAX_AGENT_STEPS = 20
_MAX_AGENT_SECONDS = 180.0
_MAX_REPEATED_STATE = 3
_MAX_MODEL_FAILURES = 2

# Only these keyboard keys may be pressed by a model decision.
_ALLOWED_PRESS_KEYS = frozenset(
    {"Enter", "Escape", "Tab", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"}
)

# One bounded selector for interactive elements (never full HTML).
_INTERACTIVE_SELECTOR = (
    "a, button, input, select, textarea, "
    "[role='button'], [role='link'], [role='menuitem'], [contenteditable='true']"
)

# Page text that indicates a hard human gate the agent must never try to solve.
_HUMAN_GATE_PATTERNS: tuple[tuple[str, HumanActionType], ...] = (
    ("captcha", "captcha"),
    ("recaptcha", "captcha"),
    ("hcaptcha", "captcha"),
    ("i'm not a robot", "captcha"),
    ("verification code", "email_otp"),
    ("one-time code", "email_otp"),
    ("one time passcode", "email_otp"),
    ("enter the code we sent", "email_otp"),
    ("two-factor", "device_approval"),
    ("two factor", "device_approval"),
    ("passkey", "passkey"),
    ("security key", "security_key"),
    ("authenticator app", "device_approval"),
    ("approve this sign-in", "device_approval"),
    ("billing information", "billing"),
    ("payment method", "billing"),
    ("accept the terms", "legal_acceptance"),
    ("terms of service", "legal_acceptance"),
    ("choose an account", "account_selection"),
    ("select an account", "account_selection"),
)


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
    # REQUIRED and supplied explicitly: an asyncio.Lock binds to the loop that
    # created it, so this must be constructed INSIDE the browser loop (see
    # ``_launch``) and only ever acquired inside a browser-loop coroutine.
    operation_lock: asyncio.Lock
    patterns: tuple[str, ...] = ()
    app_slug: str = ""
    checkpoint_index: int = 0
    # Latest masked screenshot (PNG bytes) for the HITL live view.
    screenshot: bytes | None = field(default=None)
    screenshot_at: str | None = field(default=None)
    # TTL bookkeeping so idle/overlong sessions can be reaped (a session is a real
    # Chromium process; leaking them would exhaust a small VPS).
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_active_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Guarantees the capacity semaphore is released exactly once per session.
    capacity_released: bool = False

    def is_expired(self, now: datetime) -> bool:
        return (
            now - self.last_active_at > _INACTIVITY_WINDOW
            or now - self.created_at > _MAXIMUM_WINDOW
        )


@dataclass(frozen=True, slots=True)
class PageInspection:
    """A bounded, secret-free view of the current page for one decision step."""

    url: str
    title: str
    visible_text: str
    elements: tuple[SnapshotElement, ...]
    locators: tuple[Any, ...]
    fingerprint: str


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
        # Admission is a race-free semaphore, not a len() check outside the lock:
        # two concurrent start() calls must never both pass the capacity gate.
        self._capacity = threading.BoundedSemaphore(self._max_sessions)
        # The bounded action brain (deterministic-first; LLM only for ambiguity).
        self._inference = build_json_inference(self._settings)
        # A TTL janitor runs independently of new-session creation, so an idle
        # session is reclaimed even when no further run ever starts.
        self._janitor_stop = threading.Event()
        self._janitor_thread = threading.Thread(
            target=self._janitor_loop, name="playwright-session-janitor", daemon=True
        )
        self._janitor_thread.start()

    def _janitor_loop(self) -> None:
        while not self._janitor_stop.wait(_JANITOR_INTERVAL_SECONDS):
            try:
                self._reap_expired()
            except Exception:
                continue  # sanitized: never log page content or credentials

    def _release_capacity(self, session: _PwSession) -> None:
        """Release a session's capacity slot exactly once."""

        if session.capacity_released:
            return
        session.capacity_released = True
        try:
            self._capacity.release()
        except ValueError:  # pragma: no cover - defensive against double release
            pass

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
            finally:
                # The Chromium process is gone (or unreachable): free the slot so a
                # future run is not permanently starved by a wedged session.
                self._release_capacity(session)
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
        try:
            module = importlib.import_module("playwright.async_api")
        except ImportError:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser",
                reason_code="playwright_not_installed",
            ) from None

        # Reclaim expired slots first, then take a slot ATOMICALLY. A non-blocking
        # bounded semaphore makes two concurrent starts race-free (a len() check
        # outside the registry lock would admit both).
        self._reap_expired()
        if not self._capacity.acquire(blocking=False):
            raise ProviderOperationError(
                capability="Playwright browser",
                reason_code="browser_capacity_exceeded",
            )

        async def _launch() -> tuple[Any, Any, Any, Any, asyncio.Lock]:
            playwright = await module.async_playwright().start()
            try:
                browser = await playwright.chromium.launch(headless=True, args=self._launch_args())
                # Service workers are blocked: during a secret-bearing session a
                # worker could persist and relay data outside the page lifecycle.
                context = await browser.new_context(service_workers="block")
                page = await context.new_page()
                # Created HERE so the lock is bound to the browser-owned loop.
                operation_lock = asyncio.Lock()
            except Exception:
                await _safe(playwright.stop)
                raise
            return playwright, browser, context, page, operation_lock

        try:
            playwright, browser, context, page, operation_lock = await self._loop.run(_launch())
        except BrowserOperationTimeout:
            self._capacity.release()  # the slot was never used
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="browser_launch_timeout"
            ) from None
        except Exception as exc:
            self._capacity.release()
            # Distinguish the real failure modes instead of collapsing them all into
            # provider_request_failed, which hides a missing binary or dependency.
            raise ProviderOperationError(
                capability="Playwright browser", reason_code=_launch_reason_code(exc)
            ) from None
        now = datetime.now(UTC)
        handle = f"pw_{uuid4().hex}"
        session = _PwSession(playwright, browser, context, page, operation_lock)
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

        return await self._run_action_loop(session, research, sensitive_data=sensitive_data)

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
        return await self._run_action_loop(session, resolved, sensitive_data=sensitive_data)

    async def _run_action_loop(
        self,
        session: _PwSession,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None,
    ) -> BrowserObservation:
        """Drive the page toward the credential page under strict bounds.

        inspect -> verify host -> check reviewed success signals -> detect hard human
        gates -> deterministic checkpoint match -> (only if ambiguous) bounded model
        decision -> validate -> execute ONE action -> inspect again.

        Fail-closed invariants: the loop always terminates (step, wall-clock, repeated
        state and model-failure budgets); success is declared ONLY from reviewed trace
        signals actually visible on the page — never because a model said so.
        """

        trace = get_browser_api_trace(research.app_slug)
        if trace is None:
            return self._human_required(session, "No reviewed navigation trace is available.")

        # Code-owned login injection happens once, before the loop, and never via a
        # model action, so a credential value cannot reach a prompt.
        if sensitive_data:
            await self._inject_credentials(session, sensitive_data)

        deadline = asyncio.get_running_loop().time() + _MAX_AGENT_SECONDS
        repeated: dict[str, int] = {}
        model_failures = 0

        for _step in range(_MAX_AGENT_STEPS):
            if asyncio.get_running_loop().time() >= deadline:
                return self._failed_observation(session, "browser_operation_timeout")

            inspection = await self._inspect_page(session)
            if not navigation_allowed(inspection.url, session.patterns):
                return _blocked(inspection.url)
            await self.refresh_live_view(session)

            success = matched_success_signals(
                trace.success_signals,
                url=inspection.url,
                title=inspection.title,
                text=inspection.visible_text,
            )
            if success:
                return BrowserObservation(
                    status="credential_page_ready",
                    current_url=inspection.url,
                    page_title=inspection.title or "Credential page",
                    non_secret_notes=(f"Verified success signal: {success[0]}"[:1_000],),
                )

            gate = detect_human_gate(inspection)
            if gate is not None:
                return gate

            repeated[inspection.fingerprint] = repeated.get(inspection.fingerprint, 0) + 1
            if repeated[inspection.fingerprint] > _MAX_REPEATED_STATE:
                return self._human_required(
                    session, "The browser is repeating the same page state."
                )

            checkpoint = current_checkpoint(trace, session.checkpoint_index)
            deterministic = (
                match_checkpoint(inspection.elements, checkpoint)
                if checkpoint is not None
                else None
            )
            if deterministic is not None:
                action = BrowserAction(
                    kind="click",
                    index=deterministic.index,
                    text=None,
                    url=None,
                    reason="Unique reviewed checkpoint match.",
                )
                session.checkpoint_index += 1
            elif self._inference is None:
                return self._human_required(
                    session, "The deterministic navigation path is ambiguous."
                )
            else:
                try:
                    action = await self._decide_action(
                        session=session,
                        research=research,
                        trace=trace,
                        checkpoint=checkpoint,
                        inspection=inspection,
                    )
                except Exception:
                    model_failures += 1
                    if model_failures >= _MAX_MODEL_FAILURES:
                        return self._human_required(
                            session,
                            "The browser decision service could not choose a safe action.",
                        )
                    continue

            result = await self._execute_action(session, action, inspection, trace)
            if result is not None:
                return result

        return self._human_required(session, "The bounded browser action limit was reached.")

    async def _inspect_page(self, session: _PwSession) -> PageInspection:
        """Collect a bounded, secret-free view of the page (never full HTML)."""

        async def _locked() -> PageInspection:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                url = _page_url(page)
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                visible = await _visible_text(page)
                raw: list[dict[str, object]] = []
                locators: list[Any] = []
                try:
                    handles = page.locator(_INTERACTIVE_SELECTOR)
                    total = int(await handles.count())
                except Exception:
                    total = 0
                for index in range(min(total, MAX_ELEMENTS)):
                    locator = handles.nth(index)
                    raw.append(await _describe_element(locator))
                    locators.append(locator)
                elements = build_snapshot(raw)
                return PageInspection(
                    url=sanitize_browser_url(url),
                    title=(title if isinstance(title, str) else "")[:500],
                    visible_text=visible,
                    elements=elements,
                    locators=tuple(locators),
                    fingerprint=_fingerprint(url, elements),
                )

        return await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)

    async def _decide_action(
        self,
        *,
        session: _PwSession,
        research: OperationalResearch,
        trace: BrowserApiTrace,
        checkpoint: BrowserApiTraceStep | None,
        inspection: PageInspection,
    ) -> BrowserAction:
        """Ask the bounded inference chain for ONE validated action."""

        if self._inference is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no inference backend is configured")
        prompt = build_decision_prompt(
            app_name=research.app_name,
            credential_goal=trace.credential_goal,
            checkpoint=checkpoint,
            current_url=inspection.url,
            page_title=inspection.title,
            elements=inspection.elements,
            allowed_hosts=session.patterns,
        )
        result = await asyncio.to_thread(
            self._inference.generate,
            prompt,
            schema=action_schema(),
            validate=lambda payload: validate_action(
                payload,
                elements=inspection.elements,
                allowed_hosts=session.patterns,
                host_check=is_allowed_browser_url,
            ),
        )
        return validate_action(
            result.payload,
            elements=inspection.elements,
            allowed_hosts=session.patterns,
            host_check=is_allowed_browser_url,
        )

    async def _execute_action(
        self,
        session: _PwSession,
        action: BrowserAction,
        inspection: PageInspection,
        trace: BrowserApiTrace,
    ) -> BrowserObservation | None:
        """Execute one validated action. Returns an observation only when terminal."""

        if action.kind == "report_hitl":
            return self._human_required(session, action.reason or "A human action is required.")

        if action.kind == "report_blocked":
            # Verify the claim instead of trusting it.
            if not navigation_allowed(inspection.url, session.patterns):
                return _blocked(inspection.url)
            return None  # not actually blocked: keep going

        if action.kind == "report_credential_page":
            # A model may NOT declare success. Re-inspect and require a reviewed signal.
            fresh = await self._inspect_page(session)
            success = matched_success_signals(
                trace.success_signals,
                url=fresh.url,
                title=fresh.title,
                text=fresh.visible_text,
            )
            if success:
                return BrowserObservation(
                    status="credential_page_ready",
                    current_url=fresh.url,
                    page_title=fresh.title or "Credential page",
                    non_secret_notes=(f"Verified success signal: {success[0]}"[:1_000],),
                )
            return None  # unverified claim: ignore and continue the loop

        async def _locked() -> None:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                if action.kind == "click" and action.index is not None:
                    await inspection.locators[action.index].click(timeout=10_000)
                elif action.kind == "type" and action.index is not None:
                    await inspection.locators[action.index].fill(action.text or "", timeout=10_000)
                elif action.kind == "press" and action.text:
                    await page.keyboard.press(action.text)
                elif action.kind == "goto" and action.url:
                    await page.goto(
                        action.url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                    )
                # Playwright auto-waits on actions; add only a bounded readiness wait
                # rather than relying on networkidle (which never settles on many apps).
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=10_000)
                except Exception:
                    pass

        try:
            await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except BrowserOperationTimeout:
            return self._failed_observation(session, "browser_operation_timeout")
        except Exception:
            # A single failed action is not fatal: the next inspection decides.
            return None
        return None

    async def _inject_credentials(
        self, session: _PwSession, sensitive_data: Mapping[str, str]
    ) -> None:
        """Fill and submit the login form by code, then drop local references."""

        async def _locked() -> None:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                if not await _login_origin_is_safe(page, session.patterns):
                    return
                if not await _has_password_field(page):
                    return
                await _inject_login(page, sensitive_data)
                await _submit_login(page)

        try:
            await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except Exception:
            pass

    def _human_required(self, session: _PwSession, instruction: str) -> BrowserObservation:
        url = "https://unknown.invalid/"
        try:
            url = sanitize_browser_url(_page_url(session.page))
        except Exception:
            pass
        return BrowserObservation(
            status="human_action_required",
            current_url=url,
            page_title="Human action required",
            human_action_type=_classify_gate(instruction),
            human_instruction=instruction[:1_000],
        )

    def _failed_observation(self, session: _PwSession, reason_code: str) -> BrowserObservation:
        url = "https://unknown.invalid/"
        try:
            url = sanitize_browser_url(_page_url(session.page))
        except Exception:
            pass
        return BrowserObservation(
            status="failed",
            current_url=url,
            page_title="Browser step failed",
            non_secret_notes=(f"reason_code={reason_code}",),
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

        Reviewed and narrow, per the capture spec: navigate to the spec URL (inside
        the allowlist), verify host AND path prefix AND expected heading, optionally
        click the reviewed reveal control, then read ONLY the reviewed selectors and
        require ``fullmatch`` on the value pattern. Generic input scanning is not used
        — it can pick an unrelated field that happens to match. The value is never
        returned, logged, or shown to an LLM; only a ``vault://`` reference leaves.
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
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                try:
                    await page.goto(
                        spec.url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                    )
                except Exception:
                    return None
                current = _page_url(page)
                parsed = urlsplit(current)
                host = parsed.hostname or ""
                if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
                    return None
                if spec.expected_path_prefix and not (parsed.path or "/").startswith(
                    spec.expected_path_prefix
                ):
                    return None
                if spec.expected_heading:
                    text = await _visible_text(page)
                    if spec.expected_heading.casefold() not in text.casefold():
                        return None
                if spec.reveal_selector:
                    try:
                        reveal = page.locator(spec.reveal_selector)
                        if await reveal.count() >= 1:
                            await reveal.first.click(timeout=5_000)
                    except Exception:
                        pass
                for selector in spec.selectors:
                    try:
                        locator = page.locator(selector)
                        if await locator.count() < 1:
                            continue
                        value = await locator.first.input_value(timeout=2_000)
                    except Exception:
                        continue
                    candidate = value.strip() if isinstance(value, str) else ""
                    # fullmatch: a partial hit inside a longer string is not the token.
                    if candidate and pattern.fullmatch(candidate):
                        return candidate
                return None

        token = await self._loop.run(_capture(), timeout=_OP_TIMEOUT_SECONDS)
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
            async with session.operation_lock:
                return await _masked_screenshot(session.page)

        try:
            image = await self._loop.run(_shot(), timeout=_OP_TIMEOUT_SECONDS)
        except Exception:
            return False
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
        # Stop the janitor first so it cannot race the final teardown.
        self._janitor_stop.set()
        if self._janitor_thread.is_alive():
            self._janitor_thread.join(timeout=5.0)
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
        finally:
            # Drop the in-memory screenshot and free the capacity slot exactly once,
            # even if the browser was already unreachable.
            session.screenshot = None
            session.screenshot_at = None
            self._release_capacity(session)


# --- small helpers (kept module-level for unit testing) -----------------------
async def _describe_element(locator: Any) -> dict[str, object]:
    """Describe ONE element with accessibility-relevant, non-secret attributes.

    Collects role/tag, accessible name, input type, and whether a NON-secret field
    is filled. It never reads an input's value, cookies, storage, or headers.
    """

    async def _attr(name: str) -> str:
        try:
            value = await locator.get_attribute(name, timeout=2_000)
        except Exception:
            return ""
        return value if isinstance(value, str) else ""

    tag = ""
    try:
        tag = str(await locator.evaluate("el => el.tagName.toLowerCase()")) or ""
    except Exception:
        tag = ""
    element_type = await _attr("type")
    # Accessible name, preferring the sources Playwright/ARIA recommend.
    name = await _attr("aria-label") or await _attr("placeholder") or await _attr("title")
    if not name:
        try:
            text = await locator.inner_text(timeout=2_000)
            name = text.strip()[:120] if isinstance(text, str) else ""
        except Exception:
            name = ""
    role = await _attr("role") or tag or "element"
    secretish = bool(_SECRETISH_FIELD.search(f"{name} {element_type} {await _attr('name')}"))
    value_present = False
    if not secretish and tag in {"input", "textarea"}:
        try:
            current = await locator.input_value(timeout=2_000)
            value_present = bool(isinstance(current, str) and current)
        except Exception:
            value_present = False
    return {
        "role": role,
        "tag": tag,
        "name": name,
        "type": element_type,
        "value_present": value_present,
    }


_SECRETISH_FIELD = re.compile(r"(?i)pass|secret|token|otp|code|cvv|card|credential|api.?key")


def _fingerprint(url: str, elements: Sequence[SnapshotElement]) -> str:
    """A stable, non-secret signature of the current page state."""

    parts = [urlsplit(url).path or "/"]
    parts.extend(f"{element.role}:{element.name}" for element in elements[:15])
    return "|".join(parts)[:2_000]


def current_checkpoint(trace: BrowserApiTrace, index: int) -> BrowserApiTraceStep | None:
    """Return the checkpoint at ``index``, or None when the trace is exhausted."""

    if 0 <= index < len(trace.checkpoints):
        return trace.checkpoints[index]
    return None


def _classify_gate(text: str) -> HumanActionType:
    """Map gate text to a typed HumanActionType (defaults to provider verification)."""

    lowered = text.casefold()
    for needle, action_type in _HUMAN_GATE_PATTERNS:
        if needle in lowered:
            return action_type
    return "provider_verification"


def detect_human_gate(inspection: PageInspection) -> BrowserObservation | None:
    """Return a typed HITL observation when the page shows a hard human gate.

    CAPTCHA, OTP, MFA, passkey, billing, legal consent, and account selection are
    never attempted by the agent — it stops and asks for the human.
    """

    haystack = f"{inspection.title} {inspection.visible_text}".casefold()
    for needle, action_type in _HUMAN_GATE_PATTERNS:
        if needle in haystack:
            return BrowserObservation(
                status="human_action_required",
                current_url=inspection.url,
                page_title=inspection.title or "Human action required",
                human_action_type=action_type,
                human_instruction=(
                    f"A human must complete this step in the live browser ({action_type})."
                ),
            )
    return None


async def _login_origin_is_safe(page: Any, patterns: tuple[str, ...]) -> bool:
    """Verify the main frame is on a reviewed origin and the form is unambiguous.

    Credentials are only ever typed when: the page URL is inside the reviewed host
    allowlist, exactly one visible+enabled password input exists, and the enclosing
    form does not post to an off-allowlist host.
    """

    if not navigation_allowed(_page_url(page), patterns):
        return False
    try:
        passwords = page.locator("input[type='password']")
        visible = 0
        for index in range(min(int(await passwords.count()), 5)):
            field = passwords.nth(index)
            if await field.is_visible() and await field.is_enabled():
                visible += 1
        if visible != 1:
            return False  # zero, or an ambiguous/hidden multi-form page
    except Exception:
        return False
    try:
        action = await page.locator("form:has(input[type='password'])").first.get_attribute(
            "action", timeout=2_000
        )
    except Exception:
        action = None
    if isinstance(action, str) and action.casefold().startswith(("http://", "https://")):
        if not navigation_allowed(action, patterns):
            return False  # the form would post credentials off-allowlist
    return True


async def _masked_screenshot(page: Any) -> bytes | None:
    """Screenshot the viewport with every credential-bearing field masked.

    If masking cannot be applied, NO screenshot is returned — never an unmasked one.
    """

    try:
        masks = [
            page.locator("input[type='password']"),
            page.locator("input[name*='token' i]"),
            page.locator("input[name*='secret' i]"),
            page.locator("input[name*='key' i]"),
            page.locator("input[name*='otp' i]"),
            page.locator("input[name*='code' i]"),
            page.locator("textarea[name*='token' i]"),
            page.locator("textarea[name*='secret' i]"),
            page.locator("textarea[name*='key' i]"),
            page.locator("[data-secret]"),
            page.locator("[data-credential]"),
        ]
        data = await page.screenshot(type="png", full_page=False, mask=masks, timeout=15_000)
    except Exception:
        return None
    if not isinstance(data, bytes) or not data or len(data) > _MAX_SCREENSHOT_BYTES:
        return None
    return data


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
