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
import contextlib
import importlib
import os
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser_api_trace_catalog import (
    BrowserApiTrace,
    BrowserApiTraceStep,
    get_browser_api_trace,
)
from ops.browser_candidates import (
    ActionCandidate,
    executable_candidates,
    generate_candidates,
    render_candidates,
    resolve_identity,
    select_candidate,
    validate_press_key,
)
from ops.browser_decider import (
    MAX_ELEMENTS,
    build_choice_prompt,
    build_snapshot,
    candidate_choice_schema,
    match_checkpoint,
    render_snapshot,
    validate_choice,
)
from ops.browser_egress import (
    EgressStage,
    build_egress_policy,
    reviewed_egress_extensions,
)
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_login import (
    LoginInspection,
    apply_resume_secrets,
    inspect_after_login_submit,
    inspect_login,
    normalize_resume_signal,
    visible_login_challenge,
)
from ops.browser_loop import BrowserLoop, BrowserOperationTimeout, shared_browser_loop
from ops.browser_metrics import BrowserDecisionEvent, SelectionSource, build_decision_event
from ops.browser_pages import (
    BrowserPageRegistry,
    DialogPolicy,
    DownloadPolicy,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser_risk import BrowserActionRiskPolicy
from ops.browser_snapshot import build_ranked_snapshot
from ops.browser_target_selection import derive_account_state
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    HumanActionType,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.config import Settings
from ops.credential_capture_specs import get_capture_spec
from ops.inference import build_json_inference
from ops.model_input_dlp import (
    contains_secret_material,
    sanitize_page_text,
    sanitize_reason,
    sanitize_url,
)
from ops.models import OperationalResearch, validate_vault_reference
from ops.playwright_capture_safety import (  # noqa: F401
    _CREDENTIAL_SURFACE_SELECTOR,
    _MAX_SCREENSHOT_BYTES,
    _has_credential_content,
    _has_unmasked_secret_content,
    _looks_credential_bearing,
    _masked_screenshot,
)
from ops.playwright_gates import (  # noqa: F401
    _ACCOUNT_CHOICE,
    _ACTIVE_CAPTCHA_IFRAME,
    _BILLING_NAME,
    _CAPTCHA_NAME,
    _CONSENT_NAME,
    _HUMAN_GATE_PATTERNS,
    _INTERACTIVE_ROLES,
    _MFA_NAME,
    _OTP_NAME,
    _PASSKEY_NAME,
    _classify_gate,
    _is_actionable,
)
from ops.playwright_gates import classify_structural_gate as classify_structural_gate
from ops.playwright_gates import detect_human_gate as detect_human_gate
from ops.playwright_login_dom import (  # noqa: F401
    _has_password_field,
    _inject_login,
    _login_frames_are_reviewed,
    _login_origin_is_safe,
    _submit_login,
    _try_fill,
)

# Imported for use below AND re-exported: ``ops.playwright_worker`` stays the
# import home these names already have across ops, api and the tests.
from ops.playwright_page_inspection import (  # noqa: F401
    _SECRETISH_FIELD,
    _describe_element,
    _fingerprint,
    _page_url,
    _visible_text,
)
from ops.playwright_page_inspection import PageInspection as PageInspection
from ops.playwright_predicates import (  # noqa: F401
    _normalize_signal,
    _predicate_present,
    _unique_target,
)
from ops.playwright_predicates import checkpoint_satisfied as checkpoint_satisfied
from ops.playwright_predicates import current_checkpoint as current_checkpoint
from ops.playwright_predicates import matched_success_signals as matched_success_signals
from ops.playwright_predicates import postcondition_satisfied as postcondition_satisfied
from ops.playwright_predicates import predicate_satisfied as predicate_satisfied
from ops.playwright_predicates import structural_change as structural_change
from ops.playwright_routing import (  # noqa: F401
    _ACTIVE_RESOURCE_TYPES,
    _PASSIVE_RESOURCE_TYPES,
    _blocked,
)
from ops.playwright_routing import make_egress_route_handler as make_egress_route_handler
from ops.playwright_routing import make_route_handler as make_route_handler
from ops.playwright_routing import navigation_allowed as navigation_allowed
from ops.playwright_routing import select_initial_target as select_initial_target
from ops.playwright_session import (  # noqa: F401
    _INACTIVITY_WINDOW,
    _MAXIMUM_WINDOW,
    _PwSession,
    _safe,
    _shutdown_session,
)

# Explicit re-export: ops.browser_readiness resolves this through
# ``ops.playwright_worker`` at call time to classify a Chromium launch failure.
from ops.playwright_session import _launch_reason_code as _launch_reason_code
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import SecretStore

_NAV_TIMEOUT_MS = 45_000
# Per-action Playwright timeout. Playwright auto-waits for actionability, so this
# is a ceiling on that wait rather than a substitute for it.
_ACTION_TIMEOUT_MS = 10_000
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


def _classify_action_error(exc: BaseException) -> ActionReasonCode:
    """Map a Playwright failure onto an accurate reason code.

    Previously every non-programming exception became ``action_timeout``, which
    hid browser disconnection, renderer crashes and closed targets — all of which
    need different operator responses. Playwright's error classes are imported
    lazily so this module still imports without the browser installed.
    """

    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    except ImportError:  # pragma: no cover - Playwright is a declared dependency
        return "action_timeout"

    if isinstance(exc, PlaywrightTimeoutError):
        return "action_timeout"

    # TargetClosedError subclasses Error but is NOT re-exported from async_api
    # (verified against the installed package), so it is imported from its real
    # module. Its message is inspected for documented phrasing only — never page
    # content.
    try:
        from playwright._impl._errors import TargetClosedError
    except ImportError:  # pragma: no cover - older Playwright layout
        pass
    else:
        if isinstance(exc, TargetClosedError):
            return "browser_disconnected"

    if isinstance(exc, PlaywrightError):
        message = str(exc).casefold()
        if "crash" in message:
            return "page_crashed"
        if any(
            token in message
            for token in ("closed", "disconnected", "browser has been closed", "target page")
        ):
            return "browser_disconnected"
        if "timeout" in message:
            return "action_timeout"
        if "net::" in message or "navigation" in message:
            return "navigation_timeout"

    return "action_timeout"


def _active_page(session: _PwSession) -> Any:
    """The page the harness should currently operate on.

    Canonical accessor: when the page registry has approved and activated a popup,
    that popup IS the working surface. Reading ``session.page`` directly meant
    inspection, actions, login and capture all kept using the opener while the
    real interaction had moved to the popup.
    """

    registry = session.pages
    if registry is not None:
        page = registry.active_page
        if page is not None:
            return page
    return session.page


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
    # An action the candidate policy can EMIT but the executor cannot perform.
    # Without this, such a candidate silently fell through and reported success.
    "unsupported_candidate_action",
    # A candidate that needs an approved value reference did not carry one, or the
    # reference could not be resolved from reviewed configuration.
    "approved_value_missing",
    "approved_value_unavailable",
    # A `goto` candidate whose reviewed URL was absent.
    "goto_url_missing",
    # A reviewed key was missing for a `press` candidate.
    "press_key_missing",
    # HTTP outcomes. Playwright treats 404/5xx as successful RESPONSES, not failed
    # requests, so they must be read from the response status explicitly.
    "http_not_found",
    "http_server_error",
    # The browser or page went away underneath us.
    "browser_disconnected",
    "page_crashed",
]


class BrowserEventSink(Protocol):
    """Receives sanitized decision events from the real action loop.

    Injected rather than imported so the worker has no hard dependency on a metrics
    backend, and so tests can capture exactly what a run would have emitted.
    """

    def record(self, event: BrowserDecisionEvent) -> None: ...


class BrowserActionExpectedError(RuntimeError):
    """A typed, expected action failure carrying its reason code.

    Distinct from a programming error: these are outcomes the loop knows how to
    report and replan around, so they are converted into a typed
    :class:`ActionExecutionResult` rather than propagated.
    """

    def __init__(self, reason_code: ActionReasonCode) -> None:
        self.reason_code: ActionReasonCode = reason_code
        super().__init__(reason_code)


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
    # For `select_option`: the RESOLVED option label the executor actually asked
    # for, so postcondition verification compares against what was requested
    # rather than against an approved-value REFERENCE name.
    expected_selected_label: str | None = None


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
        headless: bool = True,
        service_mode: bool = False,
        event_sink: BrowserEventSink | None = None,
    ) -> None:
        self._settings = settings or Settings.from_env()
        self._secret_store = secret_store
        # Headed Chromium is required for interactive HITL: a headless browser
        # renders nothing on the VNC desktop, so remote control would show an empty
        # screen. Headless remains the default everywhere else.
        self._headless = headless
        # In service mode the browser-service SessionManager owns capacity and TTL,
        # so the worker's own janitor is not started — two independent reapers with
        # two capacity counters would disagree about what is alive.
        self._service_mode = service_mode
        # Sanitized decision events from the REAL action loop (never page content).
        self._event_sink = event_sink
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
        self._janitor_thread: threading.Thread | None = None
        if not service_mode:
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
        """Release a worker-owned capacity slot exactly once.

        In service mode the worker never acquired a slot, so there is nothing to
        release — the manager owns capacity. Releasing here would corrupt the
        worker's semaphore count.
        """

        if not session.worker_capacity_owned:
            return
        if session.capacity_released:
            return
        session.capacity_released = True
        session.worker_capacity_owned = False
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

    @staticmethod
    def _launch_env(display: str | None) -> dict[str, str] | None:
        """Chromium's environment, pinned to this session's private X display.

        Returns ``None`` when no display was leased, so the launch call omits
        ``env`` entirely and Chromium inherits the process environment unchanged
        (the headless and in-process paths).

        The merge with ``os.environ`` is load-bearing: Playwright REPLACES the
        browser process environment with whatever ``env`` contains rather than
        merging it. Passing ``{"DISPLAY": ...}`` alone would strip HOME, PATH and
        the XDG variables that ``docker/browser-entrypoint.sh`` deliberately points
        at a writable tmpfs — and a headful Chromium without a writable HOME dies
        instantly with SIGTRAP, which surfaces only as "Target page, context or
        browser has been closed".
        """

        if not display:
            return None
        return {**os.environ, "DISPLAY": display}

    def _reap_expired(self) -> tuple[str, ...]:
        """Drop sessions past their inactivity or maximum lifetime.

        Synchronous so it can run from ``start`` before admitting a new session;
        teardown of the reaped browsers is scheduled on the owning loop. In service
        mode this is a no-op: the manager owns expiry, and reaping here would close
        a session the manager still believes is alive.
        """

        if self._service_mode:
            return ()
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

    async def start(
        self,
        profile_id: str | None,
        *,
        storage_state: dict[str, Any] | None = None,
        app_slug: str = "",
        account_ref: str | None = None,
        secret_scope: str | None = None,
        use_storage_state: bool = False,
        live_view_mode: str = "screenshot",
        display: str | None = None,
    ) -> BrowserSessionContext:
        # ``display`` is the PRIVATE X display leased to this session by the browser
        # service (e.g. ":100"). Headful Chromium renders to exactly that display,
        # which is what keeps concurrent interactive sessions isolated: x11vnc
        # serves a whole display, so sharing one would let a grant for session A
        # stream session B's browser window. None means "inherit the process
        # DISPLAY", which is the headless and in-process case.
        # Accept the provider-neutral session metadata so the graph and the async
        # run-creation path have ONE call site for every provider. In-process
        # Chromium resolves nothing through the service RPC, so these are recorded
        # only for logging: host policy is applied per navigation, storage state is
        # supplied directly via ``storage_state``, and the live view is always the
        # screenshot mode. The browser SERVICE (BrowserServiceClient) is where these
        # values actually matter.
        # ``app_slug`` is re-recorded on the session at navigation time.
        del app_slug, account_ref, secret_scope, use_storage_state, live_view_mode
        self._require_configuration()
        try:
            module = importlib.import_module("playwright.async_api")
        except ImportError:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser",
                reason_code="playwright_not_installed",
            ) from None

        # In service mode the browser-service SessionManager is the SOLE owner of
        # admission, capacity and TTL. The worker must not run its own reaper or
        # take its own semaphore, or two independent limits would disagree (a run
        # admitted by the service could still be refused here, or a session the
        # service considers alive could be reaped from under it).
        capacity_owned = False
        if not self._service_mode:
            # Reclaim expired slots first, then take a slot ATOMICALLY. A
            # non-blocking bounded semaphore makes two concurrent starts race-free
            # (a len() check outside the registry lock would admit both).
            self._reap_expired()
            if not self._capacity.acquire(blocking=False):
                raise ProviderOperationError(
                    capability="Playwright browser",
                    reason_code="browser_capacity_exceeded",
                )
            capacity_owned = True

        launch_env = self._launch_env(display)

        async def _launch() -> tuple[Any, Any, Any, Any, asyncio.Lock]:
            playwright = await module.async_playwright().start()
            try:
                browser = await playwright.chromium.launch(
                    headless=self._headless,
                    args=self._launch_args(),
                    **({"env": launch_env} if launch_env is not None else {}),
                )
                # Service workers are blocked: during a secret-bearing session a
                # worker could persist and relay data outside the page lifecycle.
                # storage_state is a VALIDATED dict supplied by the service (never a
                # caller-supplied filesystem path), so previously-authenticated
                # cookies can be restored without a fresh login.
                context = await browser.new_context(
                    service_workers="block",
                    locale="en-SG",
                    timezone_id="Asia/Singapore",
                    viewport={"width": 1440, "height": 900},
                    **({"storage_state": storage_state} if storage_state else {}),
                )
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
            if capacity_owned:
                self._capacity.release()  # the slot was never used
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="browser_launch_timeout"
            ) from None
        except Exception as exc:
            if capacity_owned:
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
        session.handle = handle
        # Only a worker-owned slot is later released by the worker; in service mode
        # the manager releases its own slot.
        session.worker_capacity_owned = capacity_owned
        # This assignment happens only after `browser.new_context` succeeded, so
        # it describes a successful local restore without retaining raw state.
        session.restored_storage_state = storage_state is not None
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
        account_creation_requested: bool = False,
        credential_creation_policy: str = "reuse_only",
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
        account_state = derive_account_state(
            restored_storage_state=session.restored_storage_state,
            sensitive_data=sensitive_data,
            account_creation_requested=account_creation_requested,
        )
        target = select_initial_target(research, trace, patterns, account_state=account_state)
        if not target or not navigation_allowed(target, patterns):
            return _blocked(target or "https://unknown.invalid/")

        # Phase 2 guards are installed HERE (not at launch) because they need the
        # app's reviewed host patterns, which only exist once research resolves.
        await self._install_interaction_guards(session, patterns)

        # A login-bound run must enter the reviewed authentication egress stage
        # before the first document is requested. Modern login pages load their
        # IdP/challenge iframe as part of that initial document, before our code can
        # locate and fill the form. Advancing only inside ``_inject_credentials``
        # was therefore too late: Pipedrive's reviewed reCAPTCHA document was
        # blocked at PRE_AUTH and the vendor rejected the otherwise valid login.
        # This does not broaden the host policy; it only activates the app's static,
        # reviewed IdP set when owner-supplied credentials prove that authentication
        # is the intended next operation. The tracker is monotonic, so the stage can
        # never loosen again later in the run.
        if sensitive_data:
            session.egress.advance_to(EgressStage.AUTHENTICATING)

        async def _go() -> bool:
            # The staged egress route was already installed at CONTEXT level by
            # _install_interaction_guards (which fails closed), so navigation is
            # never reached with an unguarded network.
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

        # Publish the first safe, masked frame before authentication begins. This
        # gives the control plane something truthful to render immediately while
        # the background browser task continues.
        await self.refresh_live_view(session)

        return await self._run_action_loop(
            session,
            research,
            sensitive_data=sensitive_data,
            credential_creation_policy=credential_creation_policy,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del provider_session_id
        self._require_configuration()
        # The resume signal is no longer discarded: only a recognized signal
        # resumes the run; an unknown signal fails closed with a typed reason.
        normalized_signal = normalize_resume_signal(signal)
        if normalized_signal is None:
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
        if normalized_signal == "cancelled":
            return self._human_required(session, "The human cancelled the browser step.")
        return await self._run_action_loop(
            session,
            resolved,
            sensitive_data=sensitive_data,
            credential_creation_policy=credential_creation_policy,
            resume_signal=normalized_signal,
        )

    async def _run_action_loop(
        self,
        session: _PwSession,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None,
        credential_creation_policy: str = "reuse_only",
        resume_signal: str | None = None,
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

        if not sensitive_data and resume_signal in {
            "human_completed",
            "captcha_completed",
            "account_selected",
        }:
            resume_observation = await self._resume_login_after_hitl(session, trace)
            if resume_observation is not None:
                return resume_observation

        # Code-owned login injection happens once, before the loop, and never via a
        # model action, so a credential value cannot reach a prompt. Its typed
        # result is HANDLED rather than discarded: a proven authentication failure
        # or an ambiguous/gated login must stop here with an accurate reason, not
        # fall through into the general LLM action loop.
        if sensitive_data:
            login_result = await self._inject_credentials(session, sensitive_data)
            if login_result is not None:
                login_observation = self._observation_from_login_result(
                    session, login_result, had_credentials=True
                )
                if login_observation is not None:
                    return login_observation
                # The absence of a login surface is not success. Probe the reviewed
                # credential target once, then let its structured predicate prove it.
                if login_result.reason_code == "no_recognized_login_surface":
                    post_login = await self._inspect_page(session)
                    already_at_goal = (
                        trace.success.has_positive_condition()
                        and predicate_satisfied(trace.success, post_login)
                    )
                    if not already_at_goal and not await self._probe_reviewed_target_before_auth(
                        session, trace
                    ):
                        return self._failed_observation(
                            session, "credential_page_navigation_failed"
                        )
                    disposition = await self._login_disposition_after_target(session, trace)
                    if disposition is not None:
                        return disposition

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
                session.egress.advance_to(EgressStage.CREDENTIAL_SURFACE)
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

            # A visible login form is a credential request, not a CAPTCHA merely
            # because the page embeds a passive reCAPTCHA anchor/badge iframe.
            # Inspect the actual form BEFORE generic structural gates on the
            # initial no-secret pass. Real challenges still win when no login form
            # is present, and post-submit challenges are classified by drive_login.
            # Applies on a resumed pass too: an action inside the loop can be
            # redirected back to the sign-in wall, and the checkpoint matcher must
            # never be asked to interpret a login page. The per-session handoff
            # bound still caps how many login pauses one session may raise.
            if not sensitive_data:
                login_gate = await self._login_gate_for_current_page(session)
                if login_gate is not None:
                    return login_gate
                # With no login form, inspect iframe metadata directly so a
                # normal visible reCAPTCHA checkbox anchor is still a real gate.
                # Snapshot names alone cannot distinguish it from an invisible
                # provider badge.
                if await visible_login_challenge(_active_page(session)):
                    return self._human_required(
                        session,
                        "An interactive CAPTCHA must be completed by a human.",
                        action_type="captcha",
                    )

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
                policy_note = ""
                instruction = checkpoint.instruction.casefold()
                is_creation_step = any(
                    marker in instruction
                    for marker in ("create", "generate", "new api", "new app", "new token")
                )
                if is_creation_step and credential_creation_policy == "reuse_only":
                    policy_note = " The run policy permits reuse only; do not create anything."
                elif is_creation_step and credential_creation_policy == "create_if_missing":
                    policy_note = (
                        " Creation was requested, but this reviewed trace keeps the irreversible "
                        "step human-authorized."
                    )
                return self._human_required(
                    session,
                    f"Checkpoint {checkpoint.order} requires a human: "
                    f"{checkpoint.instruction}{policy_note}",
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
            # Where the decision came from, recorded for the sanitized metric event.
            selection_source: SelectionSource = "deterministic"
            decision_started = asyncio.get_running_loop().time()
            if deterministic is not None:
                # Deterministic path: prefer the policy candidate whose identity is
                # the unique checkpoint match, so even this path is policy-bounded.
                for candidate in executable_candidates(candidates):
                    if candidate.identity is not None and candidate.identity.matches(deterministic):
                        chosen = candidate
                        break
            if chosen is None:
                selection_source = "llm"
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
            # Emit the sanitized decision event from the REAL loop, so metrics and
            # replay fixtures describe actual runs rather than reconstructed ones.
            self._emit_decision(
                session=session,
                checkpoint_order=checkpoint.order,
                inspection=inspection,
                candidates=candidates,
                chosen=chosen,
                selection_source=selection_source,
                execution=execution,
                latency_ms=(asyncio.get_running_loop().time() - decision_started) * 1000.0,
            )
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
                postcondition_satisfied(
                    chosen.postcondition,
                    before=inspection,
                    after=fresh,
                    # The label the executor actually requested, so a select is
                    # verified against the option text rather than a reference name.
                    expected_selected_label=execution.expected_selected_label,
                )
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
                page = _active_page(session)
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

    def _emit_decision(
        self,
        *,
        session: _PwSession,
        checkpoint_order: int,
        inspection: PageInspection,
        candidates: Sequence[ActionCandidate],
        chosen: ActionCandidate | None,
        selection_source: SelectionSource,
        execution: ActionExecutionResult,
        latency_ms: float,
    ) -> None:
        """Record one sanitized decision. Never page content, never a raw URL.

        The URL is fingerprinted inside ``build_decision_event``, candidate ids are
        opaque by construction, and a sink failure is swallowed: observability must
        never break a run.
        """

        sink = self._event_sink
        if sink is None:
            return
        provider = None
        if selection_source == "llm" and self._inference is not None:
            provider = getattr(self._inference, "last_provider", None)
        event = build_decision_event(
            session_id=session.handle,
            checkpoint_order=checkpoint_order,
            url=inspection.url,
            candidate_ids=[candidate.candidate_id for candidate in candidates],
            selected_candidate_id=chosen.candidate_id if chosen is not None else None,
            selection_source=selection_source,
            result_code=execution.reason_code or execution.status,
            latency_ms=latency_ms,
            inference_provider=provider if isinstance(provider, str) else None,
            action_type=chosen.action if chosen is not None else None,
        )
        with contextlib.suppress(Exception):
            sink.record(event)

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

        # Set by the select_option branch so the caller can verify the option that
        # was actually requested (never the approved-value reference name).
        selected_label: dict[str, str] = {}

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
                expected_selected_label=selected_label.get("label"),
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

        def _approved_or_raise() -> str:
            """Resolve an approved value reference, or fail with a typed reason."""

            if not candidate.value_ref:
                raise BrowserActionExpectedError("approved_value_missing")
            value = self._approved_value(session, candidate.value_ref)
            if not value:
                raise BrowserActionExpectedError("approved_value_unavailable")
            return value

        async def _locked() -> str:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = _active_page(session)
                action = candidate.action

                if action == "goto":
                    if not candidate.url:
                        raise BrowserActionExpectedError("goto_url_missing")
                    response = await page.goto(
                        candidate.url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS
                    )
                    # Playwright reports 404/5xx as a successful RESPONSE, so the
                    # status must be inspected explicitly or an error page would be
                    # treated as a completed navigation.
                    if response is not None:
                        status_code = int(response.status)
                        if status_code >= 500:
                            raise BrowserActionExpectedError("http_server_error")
                        if status_code == 404:
                            raise BrowserActionExpectedError("http_not_found")
                elif target_index is None:
                    # Every remaining action needs a resolved element.
                    raise BrowserActionExpectedError("target_not_found")
                else:
                    locator = fresh.locators[target_index]
                    if action == "click":
                        await locator.click(timeout=_ACTION_TIMEOUT_MS)
                    elif action in {"fill", "type"}:
                        # `type` is the Phase 1 alias for `fill`; both go through the
                        # approved-reference resolver, never model-supplied text.
                        await locator.fill(_approved_or_raise(), timeout=_ACTION_TIMEOUT_MS)
                    elif action == "press":
                        if not candidate.press_key:
                            raise BrowserActionExpectedError("press_key_missing")
                        # Bound to the reviewed element, never page-global input.
                        await locator.press(
                            validate_press_key(candidate.press_key), timeout=_ACTION_TIMEOUT_MS
                        )
                    elif action == "select_option":
                        label = _approved_or_raise()
                        # Recorded so verification compares the requested LABEL, not
                        # the reference name that produced it.
                        selected_label["label"] = label
                        await locator.select_option(label=label, timeout=_ACTION_TIMEOUT_MS)
                    elif action == "check":
                        await locator.check(timeout=_ACTION_TIMEOUT_MS)
                    elif action == "uncheck":
                        await locator.uncheck(timeout=_ACTION_TIMEOUT_MS)
                    elif action == "scroll_into_view":
                        await locator.scroll_into_view_if_needed(timeout=_ACTION_TIMEOUT_MS)
                    elif action == "focus":
                        await locator.focus(timeout=_ACTION_TIMEOUT_MS)
                    else:
                        # An action the policy can emit but this executor cannot
                        # perform must NEVER report success.
                        raise BrowserActionExpectedError("unsupported_candidate_action")

                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("domcontentloaded", timeout=_ACTION_TIMEOUT_MS)
                return _page_url(page)

        try:
            after_url = await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except BrowserOperationTimeout:
            return _result("failed", before_url, session.dom_generation, "action_timeout")
        except BrowserActionExpectedError as exc:
            return _result("failed", before_url, session.dom_generation, exc.reason_code)
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface, never be swallowed
        except Exception as exc:
            # Classify rather than collapsing everything into action_timeout, which
            # hid disconnection, crashes and closed targets.
            return _result(
                "failed", before_url, session.dom_generation, _classify_action_error(exc)
            )
        return _result("executed", sanitize_url(after_url), session.dom_generation)

    def _approved_value(self, session: _PwSession, value_ref: str) -> str:
        """Resolve an approved NON-SECRET value reference from configuration."""

        # Creation retries must search and fill the exact same name. Derive it
        # solely from immutable reviewed run state, never page content or model
        # output, so a restart cannot accidentally create a differently named app.
        if value_ref == "application_name" and session.app_slug:
            return f"composio-{session.app_slug}-integration"[:200]
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
        # ONE authoritative success definition. This previously used the legacy
        # `trace.success_signals` + matched_success_signals() while the action loop
        # used the structured `trace.success` predicate — two incompatible notions
        # of success, so a page could be "successful" in one and not the other.
        if not (
            trace.success.has_positive_condition() and predicate_satisfied(trace.success, fresh)
        ):
            return None
        # A credential page is sensitive: stop screenshotting for this session and
        # drop any frame captured before we knew what the page was (item 5).
        session.egress.advance_to(EgressStage.CREDENTIAL_SURFACE)
        session.screenshots_disabled = True
        session.screenshot = None
        session.screenshot_at = None
        return BrowserObservation(
            status="credential_page_ready",
            current_url=fresh.url,
            page_title=fresh.title or "Credential page",
            non_secret_notes=("Verified the reviewed structured success predicate.",),
        )

    async def _navigate_reviewed_target(self, session: _PwSession, trace: BrowserApiTrace) -> bool:
        """Navigate to the reviewed credential target in the current context."""

        target = trace.start_url
        if not navigation_allowed(target, session.patterns):
            return False

        async def _goto() -> bool:
            async with session.operation_lock:
                page = _active_page(session)
                try:
                    response = await page.goto(
                        target,
                        wait_until="domcontentloaded",
                        timeout=_NAV_TIMEOUT_MS,
                    )
                except Exception:
                    return False
                if response is not None and int(response.status) >= 400:
                    return False
                return True

        try:
            return await self._loop.run(_goto(), timeout=_OP_TIMEOUT_SECONDS)
        except Exception:
            return False

    async def _probe_reviewed_target_before_auth(
        self, session: _PwSession, trace: BrowserApiTrace
    ) -> bool:
        """Probe once while authentication may still be awaiting verification."""

        if session.pre_auth_target_probed:
            return False
        session.pre_auth_target_probed = True
        return await self._navigate_reviewed_target(session, trace)

    async def _retry_reviewed_target_after_login(
        self, session: _PwSession, trace: BrowserApiTrace
    ) -> bool:
        """Open the reviewed post-login target once after a human handoff."""

        if session.post_login_target_retried:
            return False
        session.post_login_target_retried = True
        return await self._navigate_reviewed_target(session, trace)

    async def _inspect_login_after_handoff(
        self, session: _PwSession, previous: str
    ) -> LoginInspection | None:
        """Briefly recheck a human-controlled login surface without resubmitting."""

        try:
            return await self._loop.run(
                inspect_after_login_submit(
                    _active_page(session),
                    previous=previous,  # type: ignore[arg-type]
                    patterns=session.patterns,
                    timeout_seconds=0.5,
                ),
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except Exception:
            return None

    async def _visible_login_challenge(self, session: _PwSession) -> bool:
        """Inspect only a visible challenge frame; passive badges do not match."""

        try:
            return await self._loop.run(
                visible_login_challenge(_active_page(session)),
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except Exception:
            return False

    async def _login_disposition_after_target(
        self, session: _PwSession, trace: BrowserApiTrace
    ) -> BrowserObservation | None:
        """Prove the reviewed goal or classify the current login wall."""

        verified = await self.verify_credential_page(session, trace)
        if verified is not None:
            return verified
        try:
            login = await self._loop.run(
                inspect_login(_active_page(session), session.patterns),
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except Exception:
            return self._failed_observation(session, "login_incomplete")

        immediate = self._observation_from_login_result(session, login, had_credentials=False)
        if immediate is not None:
            return immediate
        if await self._visible_login_challenge(session):
            challenge = LoginInspection(
                state="unknown",
                email_field=None,
                password_field=None,
                otp_fields=(),
                submit_control=None,
                current_url=login.current_url,
                reason_code="captcha_required",
            )
            return self._observation_from_login_result(session, challenge, had_credentials=True)
        if login.state in {"email_required", "password_required", "credentials_ready"}:
            after = await self._inspect_login_after_handoff(session, login.state)
            if after is None:
                return self._failed_observation(session, "login_incomplete")
            return self._observation_from_login_result(session, after, had_credentials=True)
        # No login surface, no challenge, and not yet at the reviewed goal: this is
        # an ordinary post-login landing page (a dashboard or a redirect), so the
        # bounded trace loop must keep driving toward the credential page.
        #
        # This previously returned a login_verification_required human gate, which
        # is what stopped every run one step after authentication: the agent was
        # already signed in and simply needed to navigate. Returning None is not a
        # claim of success — success is still proven ONLY by the trace predicate,
        # and the loop remains bounded by its step, wall-clock and repeated-state
        # budgets, so a genuinely stuck page still ends at an honest gate.
        return None

    async def _resume_login_after_hitl(
        self, session: _PwSession, trace: BrowserApiTrace
    ) -> BrowserObservation | None:
        """Re-evaluate human progress, then probe the reviewed target exactly once."""

        verified = await self.verify_credential_page(session, trace)
        if verified is not None:
            return verified
        try:
            login = await self._loop.run(
                inspect_login(_active_page(session), session.patterns),
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except Exception:
            return self._failed_observation(session, "login_incomplete")

        immediate = self._observation_from_login_result(session, login, had_credentials=False)
        if immediate is not None:
            return immediate
        # A challenge overlay can hide the email/password fields. Check it before
        # navigating anywhere so Resume never leaves a still-active CAPTCHA.
        if await self._visible_login_challenge(session):
            challenge = LoginInspection(
                state="unknown",
                email_field=None,
                password_field=None,
                otp_fields=(),
                submit_control=None,
                current_url=login.current_url,
                reason_code="captcha_required",
            )
            return self._observation_from_login_result(session, challenge, had_credentials=True)
        if login.state in {"email_required", "password_required", "credentials_ready"}:
            after = await self._inspect_login_after_handoff(session, login.state)
            if after is None:
                return self._failed_observation(session, "login_incomplete")
            return self._observation_from_login_result(session, after, had_credentials=True)
        if not session.post_login_target_retried:
            if not await self._retry_reviewed_target_after_login(session, trace):
                return self._failed_observation(session, "credential_page_navigation_failed")
        return await self._login_disposition_after_target(session, trace)

    async def _login_gate_for_current_page(self, session: _PwSession) -> BrowserObservation | None:
        """Classify a real initial login surface before trace-prose fallback.

        This path never guesses from checkpoint wording. A structurally visible
        challenge retains its CAPTCHA classification; an email/password surface
        becomes ``login_required`` so the owner can submit credentials into the
        same browser session through the transient secret channel.
        """

        try:
            login = await self._loop.run(
                inspect_login(_active_page(session), session.patterns),
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except Exception:
            return None

        immediate = self._observation_from_login_result(session, login, had_credentials=False)
        if immediate is not None:
            return immediate
        if await self._visible_login_challenge(session):
            challenge = LoginInspection(
                state="unknown",
                email_field=None,
                password_field=None,
                otp_fields=(),
                submit_control=None,
                current_url=login.current_url,
                reason_code="captcha_required",
            )
            return self._observation_from_login_result(session, challenge, had_credentials=True)
        if login.state in {"email_required", "password_required", "credentials_ready"}:
            return self._bounded_login_handoff(
                session,
                "Enter the account login credentials to continue in this browser session.",
                reason_code="login_required",
                action_type="login_required",
            )
        return None

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
                page = _active_page(session)
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
                session.egress.advance_to(EgressStage.AUTHENTICATING)
                # Drop the pre-auth frame before filling. Screenshot requests are
                # serialized on this same lock and can resume afterwards with all
                # form fields masked; credential values never appear in a frame.
                session.screenshot = None
                session.screenshot_at = None
                # apply_resume_secrets, not drive_login: it handles a resume-time
                # OTP or verification link (which drive_login ignores entirely) and
                # otherwise delegates to drive_login for email/password.
                return await apply_resume_secrets(
                    page=page, sensitive_data=sensitive_data, patterns=session.patterns
                )

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

        extras = reviewed_egress_extensions(session.app_slug)
        session.egress_policy = build_egress_policy(
            patterns,
            identity_provider_hosts=extras.identity_provider_hosts,
            active_api_hosts=extras.active_api_hosts,
            active_script_hosts=extras.active_script_hosts,
            passive_asset_hosts=extras.passive_asset_hosts,
            post_auth_hosts=extras.post_auth_hosts,
        )
        policy = session.egress_policy
        registry = BrowserPageRegistry(url_allowed=lambda url: navigation_allowed(url, patterns))
        dialog_policy = DialogPolicy()
        # Downloads are refused by default; a trace may approve one later.
        download_policy = DownloadPolicy()

        async def _wire() -> None:
            # The FOUR-STAGE policy is the network authority, installed at CONTEXT
            # level so it also covers popups and any page opened later. The single
            # source of stage truth is session.egress.stage.
            await session.context.route(
                "**/*",
                make_egress_route_handler(
                    policy=policy, stage_provider=lambda: session.egress.stage
                ),
            )
            registry.register(session.page, active=True)
            install_dialog_handler(session.page, dialog_policy, session.dialog_records)
            install_download_guard(session.page, download_policy, session.download_records)

            async def _configure_new_page(popup: Any) -> None:
                """Admit a popup only after policy approval, then guard it too."""

                decision = await registry.consider_popup(
                    popup, opener_page_id=registry.active_page_id
                )
                if not decision.activated:
                    return
                if decision.page_id is None:  # pragma: no cover - invariant
                    raise RuntimeError("activated popup has no page id")
                page_id = decision.page_id
                # An approved popup becomes a working surface, so it needs the SAME
                # protections as the opener rather than being unguarded.
                install_dialog_handler(popup, dialog_policy, session.dialog_records)
                install_download_guard(popup, download_policy, session.download_records)

                # Close by PAGE ID (the registry key), not the Page object — passing
                # the Page silently no-ops and leaves the registry on a closed page.
                popup.on("close", lambda _page=None: registry.close_page(page_id))

            def _on_page(popup: Any) -> None:
                # The newest page is NEVER trusted automatically: validate first.
                # A STRONG reference is kept: the loop retains only weak references to
                # tasks, so a fire-and-forget task can vanish before it finishes.
                task = asyncio.create_task(_configure_new_page(popup))
                session.popup_tasks.add(task)
                task.add_done_callback(session.popup_tasks.discard)

            session.context.on("page", _on_page)

        try:
            await self._loop.run(_wire(), timeout=_OP_TIMEOUT_SECONDS)
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface
        except Exception:
            # Popup, dialog, download and egress guards are SECURITY controls, not
            # telemetry. Continuing without them would leave an unguarded browser,
            # so this fails closed instead of proceeding.
            raise ProviderOperationError(
                capability="Playwright interaction guards",
                reason_code="interaction_guard_install_failed",
            ) from None
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

    def _observation_from_login_result(
        self,
        session: _PwSession,
        result: LoginInspection,
        *,
        had_credentials: bool,
    ) -> BrowserObservation | None:
        """Turn a deterministic login result into a typed observation, or None.

        None means "no login-level verdict — continue into the trace loop", which
        happens only when no login surface was recognised (authentication is proven
        by the reviewed checkpoint predicate, never by the absence of login fields).
        """

        reason = result.reason_code

        if result.state == "authentication_failed":
            return self._failed_observation(session, "authentication_failed")

        if reason in {"captcha_required", "login_verification_required"}:
            if reason == "captcha_required":
                return self._bounded_login_handoff(
                    session,
                    "Pipedrive requires a browser verification step. Complete the visible "
                    "CAPTCHA or security prompt in the live browser, then resume.",
                    reason_code=reason,
                    action_type="captcha",
                )
            return self._bounded_login_handoff(
                session,
                "The submitted login did not reach an authenticated page. Review "
                "Pipedrive's verification or new-device prompt in the interactive "
                "browser, complete it, then resume.",
                reason_code=reason,
                action_type="provider_verification",
            )

        # Hard blocks: a reviewed-frame or safe-link violation is a failure.
        if reason in {"login_frame_unreviewed", "verification_link_blocked"}:
            return self._failed_observation(session, reason)

        # Ambiguity or an unverified surface needs a human, with an accurate reason.
        if reason in {
            "multiple_login_surfaces",
            "multiple_password_forms",
            "login_origin_unsafe",
            "otp_surface_not_verified",
            "otp_injection_failed",
            "verification_link_navigation_failed",
        }:
            return self._bounded_login_handoff(
                session,
                f"The deterministic login flow requires review ({reason}).",
                reason_code=reason,
                action_type="provider_verification",
            )

        if result.state == "otp_required":
            return self._bounded_login_handoff(
                session,
                "Enter the emailed one-time code.",
                reason_code="otp_required",
                action_type="email_otp",
            )
        if result.state == "magic_link_required":
            return self._bounded_login_handoff(
                session,
                "Complete the reviewed email verification link.",
                reason_code="magic_link_required",
                action_type="provider_verification",
            )
        if result.state == "account_selection_required":
            return self._bounded_login_handoff(
                session,
                "Select the intended account.",
                reason_code="account_selection_required",
                action_type="account_selection",
            )

        # Credentials were supplied but a login form is still present: the login did
        # not complete, so stop rather than looping the model on a login wall.
        if had_credentials and result.state in {
            "email_required",
            "password_required",
            "credentials_ready",
        }:
            return self._failed_observation(session, "login_incomplete")

        # No recognised login surface: authentication is decided by the trace
        # predicate downstream, so let the loop continue.
        return None

    def _bounded_login_handoff(
        self,
        session: _PwSession,
        instruction: str,
        *,
        reason_code: str,
        action_type: HumanActionType,
    ) -> BrowserObservation:
        """Issue at most two login-specific HITL pauses in one session."""

        if session.login_handoff_count >= 2:
            return self._failed_observation(session, "login_incomplete")
        session.login_handoff_count += 1
        return self._human_required(
            session,
            instruction,
            reason_code=reason_code,
            action_type=action_type,
        )

    def _human_required(
        self,
        session: _PwSession,
        instruction: str,
        *,
        reason_code: str | None = None,
        action_type: HumanActionType | None = None,
    ) -> BrowserObservation:
        url = "https://unknown.invalid/"
        try:
            url = sanitize_browser_url(_page_url(_active_page(session)))
        except Exception:
            pass
        return BrowserObservation(
            status="human_action_required",
            current_url=url,
            page_title="Human action required",
            human_action_type=action_type or _classify_gate(instruction),
            human_instruction=instruction[:1_000],
            reason_code=reason_code,
        )

    def _failed_observation(self, session: _PwSession, reason_code: str) -> BrowserObservation:
        url = "https://unknown.invalid/"
        try:
            url = sanitize_browser_url(_page_url(_active_page(session)))
        except Exception:
            pass
        return BrowserObservation(
            status="failed",
            current_url=url,
            page_title="Browser step failed",
            non_secret_notes=(f"reason_code={reason_code}",),
            # The typed reason travels in the dedicated field, so a caller (and the
            # storage-state invalidation decision) can key on it precisely.
            reason_code=reason_code,
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
                page = _active_page(session)
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
                live = _active_page(session)
                if await _has_unmasked_secret_content(live):
                    return None
                return await _masked_screenshot(live)

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

    def _session_for_context(self, context: BrowserSessionContext) -> _PwSession:
        """Public-contract lookup so callers never touch the private registry.

        The browser service used to read ``worker._sessions[...]`` directly, coupling
        it to the private ``_PwSession`` shape. These accessor methods are the
        supported surface instead.
        """

        session = self._sessions.get(context.session_id)
        if session is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="session_missing"
            )
        return session

    async def refresh_session_screenshot(self, context: BrowserSessionContext) -> bytes | None:
        """Refresh and return the current screenshot for a session (or None).

        Public method for the service, replacing direct ``_sessions`` access. Returns
        None when capture is unavailable or the page is credential-bearing.
        """

        session = self._session_for_context(context)
        await self.refresh_live_view(session)
        return session.screenshot

    async def export_storage_state(
        self, context: BrowserSessionContext, *, include_indexed_db: bool = True
    ) -> dict[str, object]:
        """Export the session's authenticated storage state via the public contract.

        ``indexed_db=True`` is used only because the installed Playwright supports it
        (verified by signature inspection). The result is a dict Playwright can later
        restore; it is bearer credential material and is encrypted by the caller.
        """

        session = self._session_for_context(context)

        async def _export() -> dict[str, object]:
            async with session.operation_lock:
                result = await session.context.storage_state(indexed_db=include_indexed_db)
                if not isinstance(result, dict):
                    raise ProviderOperationError(
                        capability="Playwright browser", reason_code="storage_state_invalid"
                    )
                return result

        return await self._loop.run(_export(), timeout=_OP_TIMEOUT_SECONDS)

    async def stop(self, context: BrowserSessionContext) -> None:
        with self._registry_lock:
            session = self._sessions.pop(context.session_id, None)
        if session is not None:
            await self._teardown(session)

    async def close(self) -> None:
        # Stop the janitor first so it cannot race the final teardown.
        self._janitor_stop.set()
        if self._janitor_thread is not None and self._janitor_thread.is_alive():
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


__all__ = [
    "BrowserActionExpectedError",
    "PlaywrightBrowserWorker",
    "make_egress_route_handler",
    "make_route_handler",
    "navigation_allowed",
    "select_initial_target",
]
