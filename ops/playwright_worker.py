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
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser_api_trace_catalog import (
    BrowserApiTrace,
    BrowserApiTraceStep,
    CheckpointPredicate,
    get_browser_api_trace,
)
from ops.browser_candidates import (
    ActionCandidate,
    CandidatePostcondition,
    ElementPredicate,
    executable_candidates,
    generate_candidates,
    render_candidates,
    resolve_identity,
    select_candidate,
    validate_press_key,
)
from ops.browser_decider import (
    MAX_ELEMENTS,
    SnapshotElement,
    build_choice_prompt,
    build_snapshot,
    candidate_choice_schema,
    match_checkpoint,
    render_snapshot,
    validate_choice,
)
from ops.browser_egress import (
    BrowserEgressPolicy,
    EgressStage,
    EgressStageTracker,
    build_egress_policy,
)
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_login import (
    LoginInspection,
    drive_login,
    normalize_resume_signal,
)
from ops.browser_loop import BrowserLoop, BrowserOperationTimeout, shared_browser_loop
from ops.browser_pages import (
    BrowserPageRegistry,
    DialogPolicy,
    DialogRecord,
    DownloadPolicy,
    DownloadRecord,
    frame_path_is_reviewed,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser_risk import BrowserActionRiskPolicy
from ops.browser_snapshot import build_ranked_snapshot
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
from ops.model_input_dlp import (
    DROPPED,
    contains_secret_material,
    sanitize_element_name,
    sanitize_page_text,
    sanitize_reason,
    sanitize_url,
)
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
_MAX_ACTION_FAILURES = 3
# Trace schema version carried on every candidate (item 4 groundwork).
_TRACE_VERSION = "2.0"

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


def make_route_handler(
    patterns: tuple[str, ...],
    *,
    stage_provider: Any = None,
    asset_hosts: tuple[str, ...] = (),
) -> Any:
    """Build a Playwright route handler enforcing STAGED egress (item 6).

    Stage ``pre_auth`` — reviewed vendor hosts plus reviewed passive asset hosts may
    serve render-only resources (image/font/stylesheet/media); every ACTIVE request
    kind (document, fetch/XHR, WebSocket, EventSource, script, unknown) must be on
    the vendor allowlist.

    Stage ``post_auth`` — once credentials have been injected or a credential-bearing
    page is reached, EVERY off-allowlist request is aborted regardless of kind,
    including images, fonts, stylesheets and media. That closes the pixel/CSS/font
    beacon channels a compromised page could use to exfiltrate a credential.

    ``stage_provider`` is a zero-arg callable returning the current stage, so one
    installed route reflects later tightening. Unknown kinds fail CLOSED, and a
    stage_provider error is treated as post_auth (the stricter stage).
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

        stage = "pre_auth"
        if callable(stage_provider):
            try:
                stage = str(stage_provider() or "pre_auth")
            except Exception:
                stage = "post_auth"  # fail closed
        if stage != "pre_auth":
            # Authenticated / credential-bearing: nothing off-allowlist may leave.
            await route.abort()
            return

        if resource_type in _PASSIVE_RESOURCE_TYPES and (
            not asset_hosts or is_allowed_browser_url(url, asset_hosts)
        ):
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
    # Confirmed vs attempted checkpoint state: `checkpoint_index` advances ONLY
    # after a verified postcondition, so a failed action cannot skip a checkpoint.
    checkpoint_index: int = 0
    attempted_checkpoint_index: int = 0
    # Monotonic DOM generation: every inspection gets one, and an execution that
    # planned against an older generation must re-resolve or replan.
    dom_generation: int = 0
    # Egress stage: tightened permanently once credentials are injected or a
    # credential-bearing page is reached (item 6).
    egress_stage: str = "pre_auth"
    # Once a credential-bearing state is seen, screenshots are disabled for the
    # rest of the session unless a reviewed safe state is re-established (item 5).
    screenshots_disabled: bool = False
    # Lifecycle state + in-flight operation count (item 7).
    lifecycle: str = "ACTIVE"
    active_operations: int = 0
    # --- Phase 2: multi-page, dialog, download and staged-egress state ---
    # Page registry (popups/new tabs). Set up in _launch; the newest page is
    # never trusted automatically (see BrowserPageRegistry.consider_popup).
    pages: BrowserPageRegistry | None = field(default=None)
    dialog_records: list[DialogRecord] = field(default_factory=list)
    download_records: list[DownloadRecord] = field(default_factory=list)
    egress: EgressStageTracker = field(default_factory=EgressStageTracker)
    egress_policy: BrowserEgressPolicy | None = field(default=None)
    # Current checkpoint's expected signals, so the snapshot can RANK by
    # checkpoint relevance rather than DOM order.
    checkpoint_signals: tuple[str, ...] = ()
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
    # Monotonic DOM generation this inspection was taken at (item 3).
    generation: int = 0

    def accessible_names(self) -> tuple[str, ...]:
        return tuple(element.name for element in self.elements if element.name)


# Typed reason codes for core browser/action failures. A programming error
# (TypeError/AttributeError/AssertionError) is NEVER mapped to one of these — it
# must propagate so tests and monitoring see it.
ActionReasonCode = Literal[
    "target_not_found",
    "target_ambiguous",
    "target_stale",
    "action_timeout",
    "navigation_timeout",
    "policy_blocked",
    "postcondition_failed",
    "authentication_failed",
    "model_unavailable",
    "model_invalid_choice",
]


@dataclass(frozen=True, slots=True)
class ActionExecutionResult:
    """The typed outcome of executing exactly one candidate action.

    ``executed`` means the action ran (the checkpoint predicate is verified
    separately by the caller); ``stale`` means the DOM changed under us and we
    must replan; ``blocked`` means navigation left the host allowlist; ``failed``
    means a typed action/navigation failure.
    """

    status: Literal["executed", "stale", "blocked", "failed"]
    candidate_id: str
    before_url: str
    after_url: str
    before_generation: int
    after_generation: int
    reason_code: ActionReasonCode | None = None


def predicate_satisfied(predicate: CheckpointPredicate, inspection: PageInspection) -> bool:
    """True only when every POSITIVE condition holds and no forbidden text appears.

    A predicate with no positive condition can never PROVE progress and returns
    False (the state machine then relies on ``requires_hitl`` to escalate).
    """

    path = urlsplit(inspection.url).path.casefold()
    title = inspection.title.casefold()
    text = inspection.visible_text.casefold()
    names = tuple(name.casefold() for name in inspection.accessible_names())

    for token in predicate.forbidden_text:
        needle = token.casefold()
        if needle and (needle in text or needle in title):
            return False
    if not predicate.has_positive_condition():
        return False
    if any(token.casefold() not in path for token in predicate.url_path_contains):
        return False
    if any(token.casefold() not in title for token in predicate.title_contains):
        return False
    if any(token.casefold() not in text for token in predicate.visible_text_contains):
        return False
    for required in predicate.required_accessible_names:
        needle = required.casefold()
        if not any(needle in name for name in names):
            return False
    return True


def checkpoint_satisfied(checkpoint: BrowserApiTraceStep, inspection: PageInspection) -> bool:
    """True when the checkpoint's reviewed completion predicate is proven on the page."""

    return predicate_satisfied(checkpoint.completion, inspection)


def _predicate_present(predicate: ElementPredicate, inspection: PageInspection) -> bool:
    return any(predicate.matches(element) for element in inspection.elements)


def postcondition_satisfied(
    postcondition: CandidatePostcondition,
    *,
    before: PageInspection,
    after: PageInspection,
) -> bool:
    """Verify an ACTION's own state transition (Phase 2, section 3/5).

    A successful click is not a successful transition. This compares a freshly
    inspected page against the pre-action inspection and requires the action's
    specific assertion to hold. ANY satisfied assertion counts (a click may
    legitimately either navigate or replace part of the DOM), which is what makes
    it work for SPAs: client-side routing changes the URL, partial DOM
    replacement makes the control disappear or new text appear.

    Deliberately NOT ``networkidle`` (a persistent WebSocket or background poll
    means idle may never arrive) and never a sleep.
    """

    if postcondition.is_empty():
        return False

    if postcondition.url_matches:
        path = urlsplit(after.url).path.casefold()
        if any(token.casefold() in path for token in postcondition.url_matches):
            return True

    if postcondition.url_changed and after.url != before.url:
        return True

    for predicate in postcondition.element_appears:
        if _predicate_present(predicate, after) and not _predicate_present(predicate, before):
            return True

    for predicate in postcondition.element_disappears:
        if _predicate_present(predicate, before) and not _predicate_present(predicate, after):
            return True

    if postcondition.text_appears:
        text = after.visible_text.casefold()
        before_text = before.visible_text.casefold()
        if any(
            token.casefold() in text and token.casefold() not in before_text
            for token in postcondition.text_appears
        ):
            return True

    if postcondition.checked_state is not None:
        for element in after.elements:
            if element.checked is postcondition.checked_state:
                return True

    if postcondition.selected_value is not None:
        needle = postcondition.selected_value.casefold()
        for element in after.elements:
            if element.selected and needle in element.name.casefold():
                return True

    return False


def structural_change(before: PageInspection, after: PageInspection) -> bool:
    """A bounded structural DOM change: the interactive surface actually differs.

    Used as the SPA fallback when a candidate asserted no specific postcondition:
    it proves *something* changed without trusting a click's return value.
    """

    return before.fingerprint != after.fingerprint


class ApprovedBrowserValueResolver:
    """Resolves a reviewed NON-SECRET value reference to its configured value.

    Only the reviewed set is resolvable; a vault reference, password, API key,
    OTP, or magic link can never be produced here (they are not in the map).
    """

    _VAULTISH = ("vault://", "password", "secret", "token", "otp", "api_key", "apikey")

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def resolve(self, value_ref: str) -> str | None:
        application_name = (
            getattr(self._settings, "company_legal_name", None) or ""
        ) and f"{self._settings.company_legal_name} integration"
        mapping = {
            "company_name": getattr(self._settings, "company_legal_name", None),
            "company_website": getattr(self._settings, "company_website", None),
            "application_name": application_name or None,
            "use_case": getattr(self._settings, "company_use_case", None),
            "expected_volume": getattr(self._settings, "company_expected_volume", None),
        }
        value = mapping.get(value_ref)
        if not isinstance(value, str) or not value.strip():
            return None
        # Defense in depth: never emit anything that looks like a secret.
        if any(marker in value.casefold() for marker in self._VAULTISH):
            return None
        return value.strip()[:500]


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
        # Resolves reviewed NON-SECRET form values (never a credential).
        self._value_resolver = ApprovedBrowserValueResolver(self._settings)
        # One central risk authority for every action (Phase 2, section 4).
        self._risk_policy = BrowserActionRiskPolicy()
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

        # Phase 2 guards are installed HERE (not at launch) because they need the
        # app's reviewed host patterns, which only exist once research resolves.
        await self._install_interaction_guards(session, patterns)

        async def _go() -> bool:
            # REAL enforcement: install the STAGED host guard before any navigation.
            # The stage is read live, so post-auth tightening applies to this route.
            await session.context.route(
                "**/*",
                make_route_handler(patterns, stage_provider=lambda: session.egress_stage),
            )
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
        del provider_session_id
        self._require_configuration()
        # The resume signal is no longer discarded: only a recognized signal
        # resumes the run; an unknown signal fails closed with a typed reason.
        if normalize_resume_signal(signal) is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="unrecognized_resume_signal"
            )
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
        # A "cancelled" resume ends the run at a human gate rather than re-driving.
        if normalize_resume_signal(signal) == "cancelled":
            return self._human_required(session, "The human cancelled the browser step.")
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
        action_failures = 0

        for _step in range(_MAX_AGENT_STEPS):
            if asyncio.get_running_loop().time() >= deadline:
                return self._failed_observation(session, "navigation_timeout")

            inspection = await self._inspect_page(session)
            if not navigation_allowed(inspection.url, session.patterns):
                return _blocked(inspection.url)

            # Item 5: sensitive-page and success detection happen BEFORE any capture,
            # so a credential page is never screenshotted "just once" first. Success
            # is proven by the STRUCTURED predicate (an approved URL/path indicator
            # AND a specific label) — never by natural-language body text.
            if trace.success.has_positive_condition() and predicate_satisfied(
                trace.success, inspection
            ):
                session.egress_stage = "post_auth"
                session.screenshots_disabled = True
                session.screenshot = None
                session.screenshot_at = None
                return BrowserObservation(
                    status="credential_page_ready",
                    current_url=inspection.url,
                    page_title=inspection.title or "Credential page",
                    non_secret_notes=("Verified structured success predicate.",),
                )
            if _looks_credential_bearing(inspection):
                # Not a reviewed success, but credential-shaped: suppress capture.
                session.screenshots_disabled = True
                session.screenshot = None
                session.screenshot_at = None

            gate = detect_human_gate(inspection)
            if gate is not None:
                return gate

            # Only now, on a page proven non-sensitive, refresh the live view.
            await self.refresh_live_view(session)

            repeated[inspection.fingerprint] = repeated.get(inspection.fingerprint, 0) + 1
            if repeated[inspection.fingerprint] > _MAX_REPEATED_STATE:
                return self._human_required(
                    session, "The browser is repeating the same page state."
                )

            checkpoint = current_checkpoint(trace, session.checkpoint_index)
            if checkpoint is None:
                return self._human_required(session, "The reviewed navigation trace is exhausted.")

            # A checkpoint whose completion cannot be reliably auto-verified escalates
            # to a human rather than the agent inventing progress.
            if checkpoint.requires_hitl:
                return self._human_required(
                    session,
                    f"Checkpoint {checkpoint.order} requires a human: {checkpoint.instruction}",
                )

            # Rank the NEXT snapshot by this checkpoint's signals.
            session.checkpoint_signals = tuple(checkpoint.expected_signals)
            deterministic = match_checkpoint(inspection.elements, checkpoint)

            # Policy generates the bounded candidate set; the model only chooses. The
            # checkpoint's reviewed non-secret value refs are now wired through.
            candidates = generate_candidates(
                elements=inspection.elements,
                checkpoint_signals=checkpoint.expected_signals,
                checkpoint_order=checkpoint.order,
                trace_version=_TRACE_VERSION,
                expected_postcondition=f"checkpoint_{checkpoint.order}_complete",
                reviewed_goto_urls=(trace.start_url,),
                allow_value_refs=checkpoint.allowed_value_refs,
            )
            if not executable_candidates(candidates):
                # Every option needs a human (e.g. only irreversible controls exist).
                return self._human_required(
                    session, "Only actions requiring human authorization are available."
                )

            chosen: ActionCandidate | None = None
            if deterministic is not None:
                # Deterministic path: prefer the policy candidate whose identity is
                # the unique checkpoint match, so even this path is policy-bounded.
                for candidate in executable_candidates(candidates):
                    if candidate.identity is not None and candidate.identity.matches(deterministic):
                        chosen = candidate
                        break
            if chosen is None:
                if self._inference is None:
                    return self._human_required(
                        session, "The deterministic navigation path is ambiguous."
                    )
                try:
                    outcome = await self._choose_candidate(
                        session=session,
                        research=research,
                        trace=trace,
                        checkpoint=checkpoint,
                        inspection=inspection,
                        candidates=candidates,
                    )
                except (TypeError, AttributeError, AssertionError, NameError):
                    raise  # a programming error must surface, never be swallowed
                except Exception:
                    model_failures += 1
                    if model_failures >= _MAX_MODEL_FAILURES:
                        return self._human_required(
                            session,
                            "The browser decision service could not choose a safe action.",
                        )
                    continue
                if isinstance(outcome, BrowserObservation):
                    return outcome
                chosen = outcome

            # Phase 2: one central risk verdict gates every action. An
            # irreversible or unauthorized intent never runs autonomously.
            target_element = None
            if chosen.identity is not None:
                status, target_element = resolve_identity(chosen.identity, inspection.elements)
                del status  # execution re-resolves; this is only for risk context
            risk = self._risk_policy.classify(
                candidate=chosen, checkpoint=checkpoint, element=target_element
            )
            if not risk.autonomous_allowed:
                return self._human_required(
                    session, f"Action requires human authorization ({risk.reason_code})."
                )

            execution = await self._execute_candidate(session, chosen, inspection)
            if execution.status == "blocked":
                return _blocked(execution.after_url)
            if execution.status == "failed":
                action_failures += 1
                if action_failures >= _MAX_ACTION_FAILURES:
                    return self._failed_observation(
                        session, execution.reason_code or "postcondition_failed"
                    )
                continue  # replan on the next iteration
            if execution.status == "stale":
                # The DOM changed under us (navigated, or the target vanished /
                # became ambiguous): replan against a fresh page.
                continue

            # executed: advance the state machine ONLY when the reviewed completion
            # predicate is proven on a FRESHLY inspected page. Never advance because
            # the click "worked", the URL changed, or the model chose an action.
            fresh = await self._inspect_page(session)
            if not navigation_allowed(fresh.url, session.patterns):
                return _blocked(fresh.url)

            # A dialog or popup that needs a human is surfaced before replanning.
            gate = self._pending_interaction_gate(session)
            if gate is not None:
                return gate

            # The ACTION's own transition is verified too (SPA-aware): either its
            # specific postcondition holds, or — when it asserted none — the
            # interactive surface structurally changed.
            transitioned = (
                postcondition_satisfied(chosen.postcondition, before=inspection, after=fresh)
                if not chosen.postcondition.is_empty()
                else structural_change(inspection, fresh)
            )
            if checkpoint_satisfied(checkpoint, fresh):
                session.checkpoint_index += 1
                session.attempted_checkpoint_index = session.checkpoint_index
            else:
                session.attempted_checkpoint_index = session.checkpoint_index + 1
                if not transitioned:
                    # Nothing observably changed: count it so a control that does
                    # nothing cannot spin the loop.
                    action_failures += 1
                    if action_failures >= _MAX_ACTION_FAILURES:
                        return self._failed_observation(session, "postcondition_failed")

        return self._human_required(session, "The bounded browser action limit was reached.")

    async def _inspect_page(self, session: _PwSession) -> PageInspection:
        """Collect a bounded, secret-free view of the page (never full HTML)."""

        async def _locked() -> PageInspection:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                url = _page_url(page)
                try:
                    raw_title = await page.title()
                except Exception:
                    raw_title = ""
                raw_visible = await _visible_text(page)
                # DLP boundary: every page-derived value is sanitized HERE, at the
                # single source, so nothing downstream can leak it to a model.
                title = sanitize_page_text(
                    raw_title if isinstance(raw_title, str) else "", max_length=300
                )
                visible = sanitize_page_text(raw_visible)
                # Phase 2: a RANKED, frame-aware accessible snapshot (no raw HTML,
                # never "the first 40 DOM nodes"). Only reviewed frame origins are
                # inspected. Falls back to the Phase 1 main-frame walk if the
                # richer collection cannot run at all.
                try:
                    elements, locator_tuple = await build_ranked_snapshot(
                        page,
                        reviewed_patterns=session.patterns,
                        checkpoint_signals=session.checkpoint_signals,
                        limit=MAX_ELEMENTS,
                    )
                    locators = list(locator_tuple)
                except (TypeError, AttributeError, AssertionError, NameError):
                    raise
                except Exception:
                    raw: list[dict[str, object]] = []
                    locators = []
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
                session.dom_generation += 1
                return PageInspection(
                    url=sanitize_url(url),
                    title=title[:500],
                    visible_text=visible,
                    elements=elements,
                    locators=tuple(locators),
                    fingerprint=_fingerprint(url, elements),
                    generation=session.dom_generation,
                )

        return await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)

    async def _choose_candidate(
        self,
        *,
        session: _PwSession,
        research: OperationalResearch,
        trace: BrowserApiTrace,
        checkpoint: BrowserApiTraceStep,
        inspection: PageInspection,
        candidates: Sequence[ActionCandidate],
    ) -> ActionCandidate | BrowserObservation:
        """Ask the inference chain to CHOOSE one policy candidate.

        The model receives only DLP-sanitized page text and a list of opaque
        candidate ids; it cannot author a selector, URL, or value. The prompt is
        asserted secret-free before it leaves the process, and is never logged or
        persisted.
        """

        if self._inference is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("no inference backend is configured")
        options = executable_candidates(candidates)
        if not options:
            return self._human_required(session, "No approved action is available on this page.")
        ids = [candidate.candidate_id for candidate in options]
        prompt = build_choice_prompt(
            app_name=research.app_name,
            credential_goal=sanitize_reason(trace.credential_goal),
            checkpoint_instruction=sanitize_reason(checkpoint.instruction),
            checkpoint_signals=[sanitize_reason(s) for s in checkpoint.expected_signals],
            current_url=inspection.url,  # already sanitized by _inspect_page
            page_title=inspection.title,
            rendered_candidates=render_candidates(options),
            rendered_page=render_snapshot(inspection.elements),
        )
        # Last-line DLP assertion: refuse to send anything that still looks like it
        # carries credential material, rather than trusting upstream sanitization.
        if contains_secret_material(prompt):
            return self._human_required(
                session, "The page could not be summarized safely for a decision."
            )
        result = await asyncio.to_thread(
            self._inference.generate,
            prompt,
            schema=candidate_choice_schema(ids),
            validate=lambda payload: validate_choice(payload, candidate_ids=ids),
        )
        choice = validate_choice(result.payload, candidate_ids=ids)
        if choice.decision == "report_hitl":
            return self._human_required(session, sanitize_reason(choice.reason) or "Human action.")
        if choice.decision == "report_blocked":
            if not navigation_allowed(inspection.url, session.patterns):
                return _blocked(inspection.url)
            return self._human_required(session, "The agent reported a block it cannot prove.")
        assert choice.candidate_id is not None  # guaranteed by validate_choice
        return select_candidate(options, choice.candidate_id)

    async def _execute_candidate(
        self,
        session: _PwSession,
        candidate: ActionCandidate,
        inspection: PageInspection,
    ) -> ActionExecutionResult:
        """Re-validate immediately before acting, then execute the candidate.

        Time-of-check-to-time-of-use protection: the page is re-inspected, the URL
        and generation are re-confirmed, and the target is resolved by STABLE
        role/name/type identity requiring exactly one unique match. A stale
        positional locator from the planning inspection is never executed. Returns
        a typed :class:`ActionExecutionResult` for every outcome — never an
        untyped None.
        """

        before_url = inspection.url
        before_gen = inspection.generation

        def _result(
            status: Literal["executed", "stale", "blocked", "failed"],
            after_url: str,
            after_gen: int,
            reason: ActionReasonCode | None = None,
        ) -> ActionExecutionResult:
            return ActionExecutionResult(
                status=status,
                candidate_id=candidate.candidate_id,
                before_url=before_url,
                after_url=after_url,
                before_generation=before_gen,
                after_generation=after_gen,
                reason_code=reason,
            )

        fresh = await self._inspect_page(session)
        if not navigation_allowed(fresh.url, session.patterns):
            return _result("blocked", fresh.url, fresh.generation, "policy_blocked")
        if fresh.url != inspection.url:
            return _result("stale", fresh.url, fresh.generation, "target_stale")

        target_index: int | None = None
        if candidate.identity is not None:
            matches = [element for element in fresh.elements if candidate.identity.matches(element)]
            if len(matches) == 0:
                return _result("stale", fresh.url, fresh.generation, "target_not_found")
            if len(matches) > 1:
                return _result("stale", fresh.url, fresh.generation, "target_ambiguous")
            target_index = matches[0].index

        async def _locked() -> str:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                if candidate.action == "goto" and candidate.url:
                    await page.goto(
                        candidate.url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                    )
                elif target_index is not None:
                    locator = fresh.locators[target_index]
                    if candidate.action == "click":
                        await locator.click(timeout=10_000)
                    elif candidate.action == "type" and candidate.value_ref:
                        value = self._approved_value(candidate.value_ref)
                        if value:
                            await locator.fill(value, timeout=10_000)
                    elif candidate.action == "press" and candidate.press_key:
                        # Bound to the reviewed element, never page-global input.
                        await locator.press(validate_press_key(candidate.press_key), timeout=10_000)
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=10_000)
                except Exception:
                    pass
                return _page_url(page)

        try:
            after_url = await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except BrowserOperationTimeout:
            return _result("failed", before_url, session.dom_generation, "action_timeout")
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface, never be swallowed
        except Exception:
            return _result("failed", before_url, session.dom_generation, "action_timeout")
        return _result("executed", sanitize_url(after_url), session.dom_generation)

    def _approved_value(self, value_ref: str) -> str:
        """Resolve an approved NON-SECRET value reference from configuration."""

        return self._value_resolver.resolve(value_ref) or ""

    async def verify_credential_page(
        self, session: _PwSession, trace: BrowserApiTrace
    ) -> BrowserObservation | None:
        """Re-inspect and return success ONLY when reviewed signals are present.

        A model can never declare success: this is the single place the
        ``credential_page_ready`` outcome is produced, and it requires structural
        evidence from the reviewed trace on a freshly inspected page.
        """

        fresh = await self._inspect_page(session)
        if not navigation_allowed(fresh.url, session.patterns):
            return _blocked(fresh.url)
        success = matched_success_signals(
            trace.success_signals,
            url=fresh.url,
            title=fresh.title,
            text=fresh.visible_text,
        )
        if not success:
            return None
        # A credential page is sensitive: stop screenshotting for this session and
        # drop any frame captured before we knew what the page was (item 5).
        session.egress_stage = "post_auth"
        session.screenshots_disabled = True
        session.screenshot = None
        session.screenshot_at = None
        return BrowserObservation(
            status="credential_page_ready",
            current_url=fresh.url,
            page_title=fresh.title or "Credential page",
            non_secret_notes=(f"Verified success signal: {success[0]}"[:1_000],),
        )

    async def _inject_credentials(
        self, session: _PwSession, sensitive_data: Mapping[str, str]
    ) -> LoginInspection | None:
        """Drive the deterministic login state machine by code.

        Handles email-first, one-page, and password-after-email flows. The
        moment any credential could enter the DOM, egress is tightened and
        screenshots are disabled for the session. Credential values are never
        logged or passed to an LLM. Returns the post-attempt login inspection
        (or None if the login step could not run).
        """

        async def _locked() -> LoginInspection | None:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = session.page
                # Phase 2: NEVER inject into an unreviewed frame origin. A login
                # field inside a third-party iframe is refused even when the main
                # frame is approved.
                if not await _login_frames_are_reviewed(page, session.patterns):
                    return LoginInspection(
                        state="unknown",
                        email_field=None,
                        password_field=None,
                        otp_fields=(),
                        submit_control=None,
                        current_url=_page_url(page),
                        reason_code="login_frame_unreviewed",
                    )
                # Tighten BEFORE any fill: even an email/username is account data.
                session.egress_stage = "post_auth"
                session.egress.advance_to(EgressStage.AUTHENTICATING)
                session.screenshots_disabled = True
                session.screenshot = None
                session.screenshot_at = None
                return await drive_login(page, sensitive_data, session.patterns)

        try:
            return await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface, never be swallowed
        except Exception:
            return None

    async def _install_interaction_guards(
        self, session: _PwSession, patterns: tuple[str, ...]
    ) -> None:
        """Install the page/popup registry, dialog handler and download guard.

        All three are installed BEFORE any navigation or action, so a popup,
        dialog or download can never appear unguarded. Host sets come only from
        the reviewed per-app patterns — never from page content or model output.
        """

        session.egress_policy = build_egress_policy(patterns)
        registry = BrowserPageRegistry(url_allowed=lambda url: navigation_allowed(url, patterns))

        async def _wire() -> None:
            registry.register(session.page, active=True)
            install_dialog_handler(session.page, DialogPolicy(), session.dialog_records)
            # Downloads are refused by default; a trace may approve one later.
            install_download_guard(session.page, DownloadPolicy(), session.download_records)

            def _on_page(popup: Any) -> None:
                # The newest page is NEVER trusted automatically: validate first.
                # The handler runs on the browser loop, which owns these objects.
                asyncio.ensure_future(  # noqa: RUF006 - fire-and-forget on the browser loop
                    registry.consider_popup(popup, opener_page_id=registry.active_page_id)
                )

            session.context.on("page", _on_page)

        try:
            await self._loop.run(_wire(), timeout=_OP_TIMEOUT_SECONDS)
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface
        except Exception:
            pass  # guards are best-effort to install; the host route guard still applies
        session.pages = registry

    def _pending_interaction_gate(self, session: _PwSession) -> BrowserObservation | None:
        """Surface a dialog/download that needs a human, then clear the record.

        A ``confirm``/``prompt`` was already dismissed by the handler (so the page
        is never wedged), but the RUN must still stop for a human decision rather
        than silently proceeding as if the dialog had been answered.
        """

        for record in list(session.dialog_records):
            if record.outcome == "requires_human":
                session.dialog_records.clear()
                return self._human_required(
                    session, f"A browser dialog needs a human decision ({record.reason_code})."
                )
        session.dialog_records.clear()

        for download in list(session.download_records):
            if not download.allowed:
                session.download_records.clear()
                return self._human_required(
                    session, f"A download was refused by policy ({download.reason_code})."
                )
        session.download_records.clear()
        return None

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

        if session.screenshots_disabled:
            # A credential-bearing or authenticated state was reached: no further
            # frames are produced for this session, and any old frame is gone.
            session.screenshot = None
            session.screenshot_at = None
            return False

        async def _shot() -> bytes | None:
            # Masking alone is not relied upon: capture only happens on a page that
            # has already been checked for credential-bearing content. Masking
            # failures yield NO screenshot, never an unmasked one.
            async with session.operation_lock:
                if await _has_credential_content(session.page):
                    return None
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
    field_name = await _attr("name")
    secretish = bool(_SECRETISH_FIELD.search(f"{name} {element_type} {field_name}"))
    # Sanitize the accessible name at the source: a credential-describing name
    # becomes a semantic placeholder, and any token-shaped text is redacted.
    origin = "contenteditable" if tag == "div" and await _attr("contenteditable") else tag
    name = sanitize_element_name(name, element_type=element_type, origin=origin, role=tag or role)
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
    """Return a typed HITL observation only for a STRUCTURAL human gate (item 8).

    Substring matching on body text produced false positives: a footer "Terms of
    Service" link or a passive reCAPTCHA badge would halt an otherwise fine run. A
    gate is now recognized only when the page presents an ACTIONABLE surface:

    * an interactive challenge widget / reviewed challenge iframe, or
    * a visible input that collects the challenge (an OTP/code field), or
    * a genuine choice control (account selection, an explicit consent button).

    Passive mentions of a gate keyword are ignored.
    """

    gate = classify_structural_gate(inspection)
    if gate is None:
        return None
    action_type, detail = gate
    return BrowserObservation(
        status="human_action_required",
        current_url=inspection.url,
        page_title=inspection.title or "Human action required",
        human_action_type=action_type,
        human_instruction=sanitize_reason(detail)[:1_000],
    )


# Structural gate rules: (matcher on an element, action type, instruction).
_OTP_NAME = re.compile(
    r"(?i)one[-_ ]?time|verification code|security code|\botp\b|passcode|\bcode\b"
)
_CAPTCHA_NAME = re.compile(r"(?i)captcha|i'?m not a robot|are you human")
_CONSENT_NAME = re.compile(
    r"(?i)^(?:i )?(?:agree|accept)\b|accept (?:the )?terms|accept and continue"
)
_ACCOUNT_CHOICE = re.compile(
    r"(?i)choose an account|select an account|use another account|continue as "
)
_BILLING_NAME = re.compile(
    r"(?i)add (?:a )?payment|payment method|card number|billing details|upgrade plan"
)
_PASSKEY_NAME = re.compile(r"(?i)passkey|security key|use your (?:device|fingerprint|face)")
_MFA_NAME = re.compile(
    r"(?i)authenticator|two[- ]factor|2fa|approve (?:this )?sign|verify it'?s you"
)

_INTERACTIVE_ROLES = frozenset(
    {"button", "link", "input", "select", "textarea", "iframe", "menuitem", "a"}
)


def _is_actionable(element: SnapshotElement) -> bool:
    return element.role.casefold() in _INTERACTIVE_ROLES


def classify_structural_gate(
    inspection: PageInspection,
) -> tuple[HumanActionType, str] | None:
    """Identify a human gate from actionable page STRUCTURE, or None."""

    for element in inspection.elements:
        name = element.name
        element_type = element.element_type.casefold()
        role = element.role.casefold()

        # An interactive challenge: a captcha widget/iframe or its control. A passive
        # badge is a non-actionable node and therefore ignored.
        if _CAPTCHA_NAME.search(name) and (_is_actionable(element) or role == "iframe"):
            return "captcha", "An interactive CAPTCHA must be completed by a human."

        # A real OTP/code entry field (an input, not prose mentioning a code).
        if element_type in {"text", "tel", "number", "password", ""} and role in {
            "input",
            "textarea",
        }:
            if _OTP_NAME.search(name) or (element.secretish and _OTP_NAME.search(name)):
                return "email_otp", "A one-time verification code must be entered by a human."

        if _PASSKEY_NAME.search(name) and _is_actionable(element):
            return "passkey", "A passkey or security key must be used by a human."

        if _MFA_NAME.search(name) and _is_actionable(element):
            return "device_approval", "A multi-factor approval must be completed by a human."

        if _BILLING_NAME.search(name) and _is_actionable(element):
            return "billing", "A billing decision must be made by a human."

        # Explicit consent CONTROL (a button), not a footer terms LINK.
        if _CONSENT_NAME.search(name) and role in {"button", "input"}:
            return "legal_acceptance", "Legal acceptance must be granted by a human."

        if _ACCOUNT_CHOICE.search(name) and _is_actionable(element):
            return "account_selection", "An account choice must be made by a human."

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


_CREDENTIAL_SURFACE_SELECTOR = (
    "input[type='password'], input[name*='token' i], input[name*='secret' i], "
    "input[name*='key' i], input[name*='otp' i], code, pre, samp, kbd, textarea, "
    "[data-secret], [data-credential], [contenteditable='true']"
)


def _looks_credential_bearing(inspection: PageInspection) -> bool:
    """True when the inspected page structurally exposes credential material.

    Structural, not substring-based: a secret-ish INPUT, or a dropped unsafe region
    in the snapshot, means a credential could be rendered on this page.
    """

    if any(element.secretish for element in inspection.elements):
        return True
    if DROPPED in inspection.visible_text:
        return True
    return any(DROPPED in element.name for element in inspection.elements)


async def _has_credential_content(page: Any) -> bool:
    """Structural check for credential-bearing surfaces before any capture.

    Covers plain-text tokens in code/pre, textarea, contenteditable and custom
    components carrying data-secret/data-credential — cases that masking selectors
    alone would miss. Fails CLOSED when safety cannot be established.
    """

    try:
        locator = page.locator(_CREDENTIAL_SURFACE_SELECTOR)
        if int(await locator.count()) > 0:
            return True
    except Exception:
        return True  # cannot prove safety -> treat as sensitive
    try:
        text = await page.inner_text("body", timeout=3_000)
    except Exception:
        return True
    return contains_secret_material(text if isinstance(text, str) else "")


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


async def _login_frames_are_reviewed(page: Any, patterns: tuple[str, ...]) -> bool:
    """True when every frame hosting a password field is on a reviewed origin.

    A credential field inside an UNREVIEWED (e.g. third-party) iframe is never
    filled, even when the top-level page is approved — the main frame being
    allowlisted says nothing about who owns the nested document.
    """

    from ops.browser_snapshot import frame_chain, frame_host

    try:
        frames = list(page.frames)
    except Exception:
        return False  # cannot enumerate frames -> fail closed
    for frame in frames:
        try:
            count = int(await frame.locator("input[type='password']").count())
        except Exception:
            continue
        if count <= 0:
            continue
        try:
            is_main = frame is page.main_frame
        except Exception:
            is_main = False
        if is_main:
            if not navigation_allowed(_page_url(page), patterns):
                return False
            continue
        host = frame_host(frame)
        if not host or not navigation_allowed(f"https://{host}/", patterns):
            return False
        if not frame_path_is_reviewed(frame_chain(frame), patterns):
            return False
    return True


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
