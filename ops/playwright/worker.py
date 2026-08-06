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
one persistent loop owned by ``ops.browser.loop.BrowserLoop``, so a session
created during ``start`` stays valid through ``navigate`` and ``resume`` no matter
how many short-lived caller loops come and go.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from ops.browser.api_trace_catalog import (
    BrowserApiTrace,
    BrowserApiTraceStep,
)
from ops.browser.candidates import (
    ActionCandidate,
    executable_candidates,
    generate_candidates,
    render_candidates,
    resolve_identity,
    select_candidate,
    validate_press_key,
)
from ops.browser.decider import (
    MAX_ELEMENTS,
    build_choice_prompt,
    build_snapshot,
    candidate_choice_schema,
    match_checkpoint,
    render_snapshot,
    validate_choice,
)
from ops.browser.egress import (
    EgressStage,
    build_egress_policy,
    reviewed_egress_extensions,
)
from ops.browser.host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser.login import (
    LoginInspection,
    apply_resume_secrets,
    inspect_after_login_submit,
    inspect_login,
    normalize_resume_signal,
    visible_login_challenge,
)
from ops.browser.loop import BrowserLoop, BrowserOperationTimeout, shared_browser_loop
from ops.browser.metrics import SelectionSource, build_decision_event
from ops.browser.pages import (
    BrowserPageRegistry,
    DialogPolicy,
    DownloadPolicy,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser.process_hardening import (
    chromium_launch_environment,
    harden_playwright_parent_process,
)
from ops.browser.risk import BrowserActionRiskPolicy
from ops.browser.setup_values import normalize_browser_setup_fields
from ops.browser.signup import (
    SignupResult,
    SignupSessionState,
    drive_signup,
    normalize_signup_fields,
    signup_secret_continuation_ready,
)
from ops.browser.snapshot import build_ranked_snapshot
from ops.browser.target_selection import derive_account_state
from ops.browser.worker import (
    BrowserObservation,
    BrowserSessionContext,
    HumanActionType,
    sanitize_browser_url,
    validate_allowed_domains,
)
from ops.core.config import Settings
from ops.core.inference import JsonInference, build_json_inference
from ops.core.model_catalog import selection_from_record
from ops.core.model_input_dlp import (
    contains_secret_material,
    sanitize_page_text,
    sanitize_reason,
    sanitize_url,
)
from ops.core.models import OperationalResearch, validate_vault_reference
from ops.core.secret_store import SecretStore
from ops.credentials.capture_specs import CredentialCaptureSpec
from ops.playwright.actions import ActionExecutionResult as ActionExecutionResult
from ops.playwright.actions import ActionReasonCode as ActionReasonCode
from ops.playwright.actions import ApprovedBrowserValueResolver as ApprovedBrowserValueResolver
from ops.playwright.actions import BrowserActionExpectedError as BrowserActionExpectedError
from ops.playwright.actions import BrowserEventSink as BrowserEventSink
from ops.playwright.actions import _classify_action_error  # noqa: F401
from ops.playwright.capture_safety import (  # noqa: F401
    _CREDENTIAL_SURFACE_SELECTOR,
    _MAX_SCREENSHOT_BYTES,
    _has_credential_content,
    _has_unmasked_secret_content,
    _looks_credential_bearing,
    _masked_screenshot,
)
from ops.playwright.gates import (  # noqa: F401
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
from ops.playwright.gates import classify_structural_gate as classify_structural_gate
from ops.playwright.gates import detect_human_gate as detect_human_gate
from ops.playwright.live_mask import install_live_pixel_mask as _install_live_pixel_mask
from ops.playwright.login_dom import _login_frames_are_reviewed

# Imported for use below AND re-exported: ``ops.playwright.worker`` stays the
# import home these names already have across ops, api and the tests.
from ops.playwright.page_inspection import (  # noqa: F401
    _SECRETISH_FIELD,
    _describe_element,
    _fingerprint,
    _page_url,
    _visible_text,
)
from ops.playwright.page_inspection import PageInspection as PageInspection
from ops.playwright.predicates import (  # noqa: F401
    _normalize_signal,
    _predicate_present,
    _unique_target,
)
from ops.playwright.predicates import checkpoint_satisfied as checkpoint_satisfied
from ops.playwright.predicates import current_checkpoint as current_checkpoint
from ops.playwright.predicates import matched_success_signals as matched_success_signals
from ops.playwright.predicates import postcondition_satisfied as postcondition_satisfied
from ops.playwright.predicates import predicate_satisfied as predicate_satisfied
from ops.playwright.predicates import structural_change as structural_change
from ops.playwright.routing import (  # noqa: F401
    _ACTIVE_RESOURCE_TYPES,
    _PASSIVE_RESOURCE_TYPES,
    _blocked,
)
from ops.playwright.routing import make_egress_route_handler as make_egress_route_handler
from ops.playwright.routing import make_route_handler as make_route_handler
from ops.playwright.routing import navigation_allowed as navigation_allowed
from ops.playwright.routing import select_initial_target as select_initial_target
from ops.playwright.session import (  # noqa: F401
    _INACTIVITY_WINDOW,
    _MAXIMUM_WINDOW,
    _PwSession,
    _safe,
    _shutdown_session,
)

# Explicit re-export: ops.browser.readiness resolves this through
# ``ops.playwright.worker`` at call time to classify a Chromium launch failure.
from ops.playwright.session import _launch_reason_code as _launch_reason_code
from ops.providers.errors import ConfigurationRequiredError, ProviderOperationError
from ops.recipes.app_recipes import (
    AppRecipe,
    SignupPolicy,
    get_app_recipe,
    recipe_to_browser_trace,
    recipe_to_capture_spec,
)


def chromium_launch_args(*, headless: bool, sandbox_disabled: bool) -> list[str]:
    """Chromium flags for one launch mode. ONE definition for every launcher.

    ``--no-sandbox`` is OPT-IN, not a hardcoded default. Disabling Chromium's own
    sandbox weakens defence-in-depth, so it is only applied when the deployment
    explicitly asks for it (dev sandboxes and hosts without the required
    seccomp/user-namespace support).

    Headed Chromium additionally disables the GPU process. On a virtual X display
    with no GPU device, ``Page.captureScreenshot`` fails inside the GPU
    compositor ("Unable to capture screenshot") while rendering still succeeds —
    so the readiness probe and every masked live-view screenshot broke while the
    page itself looked fine. Software rendering makes capture deterministic on
    any host. Headless Chromium already captures through its own path.

    Do not add ``--disable-dev-shm-usage`` here. Production provisions a private,
    bounded ``/dev/shm`` specifically for Chromium; redirecting shared-memory
    files into the smaller ``/tmp`` tmpfs defeats that limit.
    """

    args: list[str] = []
    if sandbox_disabled:
        args.append("--no-sandbox")
    if not headless:
        args.append("--disable-gpu")
    return args


_NAV_TIMEOUT_MS = 45_000
# Per-action Playwright timeout. Playwright auto-waits for actionability, so this
# is a ceiling on that wait rather than a substitute for it.
_ACTION_TIMEOUT_MS = 10_000
_JANITOR_INTERVAL_SECONDS = 60.0
_OP_TIMEOUT_SECONDS = 120.0

# Bounds for the agent action loop: it must always terminate.
_MAX_AGENT_STEPS = 20
# Keep the autonomous loop below the browser-service 300 second outer deadline,
# leaving time for serialization, encrypted-state persistence and the RPC reply.
_MAX_AGENT_SECONDS = 270.0
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

# Account identifiers are secret-bearing user data too. Recipe selectors protect
# vendor-specific token fields; these fixed selectors protect login/signup email
# values on the headed X11/noVNC desktop for every Playwright recipe.
_ACCOUNT_IDENTIFIER_MASKS = (
    "input[type='email']",
    "input[autocomplete='username']",
    "input[name='email' i]",
    "input[name='username' i]",
)


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


@dataclass(frozen=True, slots=True)
class _GateProbe:
    """The whole answer of ONE read-only human-gate observation.

    Internal to this module and deliberately tiny: the browser service's clearance
    endpoint is the only caller, and it projects these three facts onto the strict
    ``GateClearanceReport`` contract. There is no URL, no page text and no
    instruction here, so nothing page-derived can leave the container through a
    probe.

    ``reason`` is drawn from the same closed set the report's ``probe_reason_code``
    names, minus the two reasons only the session manager can know (an id that
    never existed, an id the absolute lifetime bound closed): ``observed`` when the
    page was read, ``operation_in_flight`` when the session's operation lock was
    held and nothing was read at all, ``probe_failed`` when the read could not
    complete. One spelling across the three modules that carry this vocabulary —
    here, ``browser_service/models.py`` and ``ops/browser/takeover.py``.
    """

    gate: HumanActionType | None
    reason: str
    # True only when the page was actually READ. ``gate is None`` on its own does
    # not mean the gate is gone: a held lock and a failed read also carry no gate,
    # so the caller decides "cleared" from this AND the absent gate, never from the
    # absent gate alone.
    observed: bool = False


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
        attachment_probe: Callable[[str], bool] | None = None,
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
        # Answers "is a human attached to this handle's session, which is paused on a
        # human-only gate, right now?". Optional and injected, so the worker needs no
        # knowledge of the live-view relay: the installer supplies the SAME
        # conjunction the service janitor uses (``hitl_pending and is_attached(id)``)
        # and owns the "a raising probe means attached" rule, exactly as
        # ``SessionManager.is_attached`` does. Absent, the worker reaps as before.
        self._attachment_probe = attachment_probe
        # All Playwright work runs on ONE persistent loop so a session survives
        # the orchestrator's separate per-node asyncio.run loops.
        self._loop = loop or shared_browser_loop()
        self._sessions: dict[str, _PwSession] = {}
        self._research: dict[str, OperationalResearch] = {}
        # Value-free signup state is kept beside the browser session. It stores
        # only whether this session filled/submitted the form, never field values.
        self._signup_states: dict[str, SignupSessionState] = {}
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
        """Chromium flags for this worker's launch mode."""

        return chromium_launch_args(
            headless=self._headless,
            sandbox_disabled=bool(getattr(self._settings, "playwright_disable_sandbox", False)),
        )

    def _chromium_sandbox_enabled(self) -> bool:
        """Playwright defaults this option to false, so enable it explicitly."""

        return not bool(getattr(self._settings, "playwright_disable_sandbox", False))

    @staticmethod
    def _launch_env(display: str | None, *, headless: bool) -> dict[str, str]:
        """Build Chromium's strict, secret-free child environment.

        Playwright replaces the child environment when ``env`` is supplied. That
        is intentional here: inheriting the worker environment would give every
        renderer process the worker RPC tokens, broker token, storage-state key,
        and inference/provider credentials. Only process essentials are copied.

        A leased display always wins. Local headed development may use the
        process's existing display when no lease is supplied; headless Chromium
        receives no ``DISPLAY`` at all.
        """

        return chromium_launch_environment(display, headless=headless)

    def _reap_expired(self) -> tuple[str, ...]:
        """Drop sessions past their inactivity or maximum lifetime.

        Synchronous so it can run from ``start`` before admitting a new session;
        teardown of the reaped browsers is scheduled on the owning loop. In service
        mode this is a no-op: the manager owns expiry, and reaping here would close
        a session the manager still believes is alive.

        The attachment fact is an INPUT to the lifetime rule rather than a branch
        here, so an attached human postpones an idle reap and never postpones the
        absolute maximum age. The rule is the one in
        ``ops/browser/session_liveness.py`` that the service janitor also calls.
        """

        if self._service_mode:
            return ()
        now = datetime.now(UTC)
        with self._registry_lock:
            expired = [
                handle
                for handle, session in self._sessions.items()
                if session.is_expired(
                    now,
                    hitl_attached=self._attachment_probe(handle)
                    if self._attachment_probe
                    else False,
                )
            ]
            reaped = [(handle, self._sessions.pop(handle)) for handle in expired]
            for handle, _session in reaped:
                self._signup_states.pop(handle, None)
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
        recipe: AppRecipe | None = None,
        storage_state: dict[str, Any] | None = None,
        app_slug: str = "",
        account_ref: str | None = None,
        secret_scope: str | None = None,
        use_storage_state: bool = False,
        live_view_mode: str = "screenshot",
        display: str | None = None,
        decision_model: str | None = None,
        decision_effort: str | None = None,
    ) -> BrowserSessionContext:
        # ``display`` is the PRIVATE X display leased to this session by the browser
        # service (e.g. ":100"). Headful Chromium renders to exactly that display,
        # which is what keeps concurrent interactive sessions isolated: x11vnc
        # serves a whole display, so sharing one would let a grant for session A
        # stream session B's browser window. A local headed worker may use its
        # process DISPLAY when no lease is supplied; a headless launch gets none.
        # Accept the provider-neutral session metadata so the graph and the async
        # run-creation path have ONE call site for every provider. In-process
        # Chromium resolves nothing through the service RPC, so these are recorded
        # only for logging: host policy is applied per navigation, storage state is
        # supplied directly via ``storage_state``, and the live view is always the
        # screenshot mode. The browser SERVICE (BrowserServiceClient) is where these
        # values actually matter.
        # ``app_slug`` is re-recorded on the session at navigation time.
        del recipe, app_slug, account_ref, secret_scope, use_storage_state, live_view_mode
        self._require_configuration()
        try:
            module = importlib.import_module("playwright.async_api")
        except ImportError:
            raise ConfigurationRequiredError(
                phase=5,
                capability="Playwright browser",
                reason_code="playwright_not_installed",
            ) from None
        # This class is also available behind the explicitly local
        # PLAYWRIGHT_IN_PROCESS_SANDBOX path. Protect that secret-bearing API
        # parent before Playwright creates its Node driver, just as the isolated
        # browser service protects itself during lifespan startup.
        harden_playwright_parent_process()

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

        launch_env = self._launch_env(display, headless=self._headless)

        async def _launch() -> tuple[Any, Any, Any, Any, asyncio.Lock]:
            playwright = await module.async_playwright().start()
            try:
                browser = await playwright.chromium.launch(
                    headless=self._headless,
                    args=self._launch_args(),
                    chromium_sandbox=self._chromium_sandbox_enabled(),
                    env=launch_env,
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
        # The run's pinned decision model, resolved against THIS process's own
        # keys. ``selection_from_record`` returns None for a model this deployment
        # cannot serve — the control plane and the browser service are separate
        # processes with separate environments, so a model accepted at run
        # creation may be unavailable here. That leaves the deployment chain in
        # place rather than failing a run over a preference.
        selection = selection_from_record(
            self._settings, model_id=decision_model, effort=decision_effort
        )
        if selection is not None:
            session.inference = build_json_inference(self._settings, selection=selection)
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
        recipe: AppRecipe | None = None,
        sensitive_data: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation:
        self._require_configuration()
        session = self._sessions.get(context.session_id)
        if session is None:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="session_missing"
            )
        self._research[context.session_id] = research
        bound_recipe = recipe or get_app_recipe(research.app_slug)
        if (
            bound_recipe is None
            or bound_recipe.app_slug != research.app_slug
            or bound_recipe.route_kind != "playwright"
        ):
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="immutable_recipe_required"
            )
        patterns = self._resolve_patterns(research, recipe=bound_recipe)
        session.patterns = patterns
        session.app_slug = research.app_slug
        session.approved_values = normalize_browser_setup_fields(setup_fields)
        approved_signup_fields = (
            normalize_signup_fields(signup_fields) if account_creation_requested else {}
        )

        # Screenshot masking cannot protect the headed X11 desktop. Install the
        # recipe-owned document-start mask before the first vendor navigation; in
        # production the browser service also requires this before issuing any
        # live-view grant.
        if not session.live_pixel_mask_installed:
            if not await self.install_live_pixel_mask(
                context,
                research.app_slug,
                recipe=bound_recipe,
            ):
                raise ProviderOperationError(
                    capability="Playwright live view",
                    reason_code="live_pixel_mask_install_failed",
                )

        trace = recipe_to_browser_trace(bound_recipe)
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
        await self._install_interaction_guards(session, patterns, recipe=bound_recipe)

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
            recipe=bound_recipe,
            sensitive_data=sensitive_data,
            account_creation_requested=account_creation_requested,
            signup_fields=approved_signup_fields,
            credential_creation_policy=credential_creation_policy,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        recipe: AppRecipe | None = None,
        sensitive_data: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
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
        bound_recipe = recipe or get_app_recipe(resolved.app_slug)
        if (
            bound_recipe is None
            or bound_recipe.app_slug != resolved.app_slug
            or bound_recipe.route_kind != "playwright"
        ):
            raise ProviderOperationError(
                capability="Playwright browser", reason_code="immutable_recipe_required"
            )
        # A "cancelled" resume ends the run at a human gate rather than re-driving.
        if normalized_signal == "cancelled":
            return self._human_required(session, "The human cancelled the browser step.")
        session.approved_values = normalize_browser_setup_fields(setup_fields)
        return await self._run_action_loop(
            session,
            resolved,
            recipe=bound_recipe,
            sensitive_data=sensitive_data,
            account_creation_requested=account_creation_requested,
            signup_fields=(
                normalize_signup_fields(signup_fields) if account_creation_requested else {}
            ),
            credential_creation_policy=credential_creation_policy,
            resume_signal=normalized_signal,
        )

    async def install_live_pixel_mask(
        self,
        context: BrowserSessionContext,
        app_slug: str,
        *,
        recipe: AppRecipe | None = None,
    ) -> bool:
        """Install AppRecipe masking on the real browser context, fail closed.

        Selectors are resolved locally from the checked-in recipe; an RPC caller
        can select an app but can never supply or widen the masking policy.
        """

        session = self._sessions.get(context.session_id)
        bound_recipe = recipe or get_app_recipe(app_slug)
        browser_recipe = bound_recipe.browser if bound_recipe is not None else None
        if (
            session is None
            or bound_recipe is None
            or bound_recipe.app_slug != app_slug
            or bound_recipe.route_kind != "playwright"
            or browser_recipe is None
        ):
            return False
        if session.live_pixel_mask_installed:
            return True

        async def _install() -> bool:
            selectors = tuple(
                dict.fromkeys((*browser_recipe.sensitive_selectors, *_ACCOUNT_IDENTIFIER_MASKS))
            )
            return await _install_live_pixel_mask(
                context=session.context,
                page=_active_page(session),
                selectors=selectors,
            )

        try:
            installed = await self._loop.run(_install(), timeout=_OP_TIMEOUT_SECONDS)
        except Exception:
            return False
        session.live_pixel_mask_installed = installed is True
        return session.live_pixel_mask_installed

    async def _run_action_loop(
        self,
        session: _PwSession,
        research: OperationalResearch,
        *,
        recipe: AppRecipe,
        sensitive_data: Mapping[str, str] | None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
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

        trace = recipe_to_browser_trace(recipe)
        if trace is None:
            return self._human_required(session, "No reviewed navigation trace is available.")

        if account_creation_requested:
            signup_state = self._signup_states.setdefault(
                session.handle,
                SignupSessionState(),
            )
            # After registration submitted, OTP/magic-link values still use the
            # established deterministic login secret injector. They remain local
            # to the worker and never enter the signup state or model path.
            if sensitive_data is not None and signup_secret_continuation_ready(
                signup_state, sensitive_data
            ):
                continuation = await self._inject_credentials(session, sensitive_data)
                if continuation is not None:
                    continuation_observation = self._observation_from_login_result(
                        session,
                        continuation,
                        # Before the final registration submit, a successful
                        # email verification may legitimately reveal the signup
                        # password/details form. It is not an incomplete
                        # existing-account login; let the deterministic signup
                        # driver consume the re-issued generated pair below.
                        had_credentials=signup_state.submit_attempted,
                    )
                    if continuation_observation is not None:
                        return continuation_observation
            signup_result = await self._drive_signup(
                session,
                sensitive_data=sensitive_data or {},
                signup_fields=signup_fields or {},
                state=signup_state,
                signup_policy=(recipe.browser.signup if recipe.browser is not None else None),
                resume_signal=resume_signal,
            )
            signup_observation = self._observation_from_signup_result(
                session,
                signup_result,
                state=signup_state,
            )
            if signup_observation is not None:
                return signup_observation
            # Signup consumed the email/password channel. Do not feed those same
            # values into the existing-account login injector on the next page.
            sensitive_data = None

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
            success_proven = trace.success.has_positive_condition() and predicate_satisfied(
                trace.success, inspection
            )
            if success_proven:
                entry_only = bool(
                    recipe.route_kind == "playwright"
                    and recipe.browser is not None
                    and recipe.browser.scope == "entry_only"
                )
                if entry_only:
                    await self.refresh_live_view(session)
                    return BrowserObservation(
                        status="developer_console_ready",
                        current_url=inspection.url,
                        page_title=inspection.title or "Reviewed public entry",
                        non_secret_notes=("Verified reviewed public-entry predicate.",),
                        reason_code="reviewed_public_entry_reached",
                    )

                # A credential-management heading proves only that navigation
                # succeeded. Under create_if_missing it must not end the action
                # loop until every reviewed capture selector is structurally
                # present; otherwise the worker would stop before clicking Create.
                capture_spec = recipe_to_capture_spec(recipe)
                creation_reviewed = any(
                    checkpoint.credential_creation_controls for checkpoint in trace.checkpoints
                )
                capture_present = (
                    await self._capture_contract_present(session, capture_spec)
                    if capture_spec is not None
                    else False
                )
                if (
                    credential_creation_policy != "create_if_missing"
                    or not creation_reviewed
                    or capture_present
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
                # provider badge. It goes through ``_visible_login_challenge``,
                # not the module function: the page belongs to the browser loop,
                # and awaiting its coroutine on the caller's loop deadlocks both.
                if await self._visible_login_challenge(session):
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
            # Authentication/direct navigation can land beyond one or more
            # checkpoints before the action loop starts. Advance only predicates
            # already proven on this fresh page. A credential-creation checkpoint
            # deliberately stays active until its capture selectors exist; its
            # management-page predicate alone is not proof that a key was issued.
            while (
                checkpoint is not None
                and not checkpoint.credential_creation_controls
                and checkpoint_satisfied(checkpoint, inspection)
            ):
                session.checkpoint_index += 1
                session.attempted_checkpoint_index = session.checkpoint_index
                checkpoint = current_checkpoint(trace, session.checkpoint_index)
            if checkpoint is None:
                return self._human_required(session, "The reviewed navigation trace is exhausted.")

            # Legacy traces may still mark an unprovable checkpoint as HITL. Do
            # not turn that metadata into a blanket credential-creation veto:
            # explicit create-if-missing authority may execute only the reviewed
            # create/generate/save controls, while the normal structured success
            # predicate still has to prove completion. Other unprovable steps,
            # including reuse-only creation attempts, remain human-gated.
            if checkpoint.requires_hitl:
                instruction = checkpoint.instruction.casefold()
                is_creation_step = any(
                    marker in instruction
                    for marker in ("create", "generate", "new api", "new app", "new token")
                )
                if not (
                    is_creation_step
                    and credential_creation_policy == "create_if_missing"
                    and checkpoint.credential_creation_controls
                ):
                    policy_note = (
                        " The run policy permits reuse only; do not create anything."
                        if is_creation_step and credential_creation_policy == "reuse_only"
                        else ""
                    )
                    return self._human_required(
                        session,
                        f"Checkpoint {checkpoint.order} requires a human because its "
                        f"completion is not structurally provable: "
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
                # A deterministic element may still map to several actions or
                # approved values. Choose without a model only when the policy
                # leaves exactly one executable candidate for that identity.
                matches = tuple(
                    candidate
                    for candidate in executable_candidates(candidates)
                    if candidate.identity is not None and candidate.identity.matches(deterministic)
                )
                if len(matches) == 1:
                    chosen = matches[0]
            if chosen is None:
                selection_source = "llm"
                if self._chain_for(session) is None:
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
                candidate=chosen,
                checkpoint=checkpoint,
                element=target_element,
                credential_creation_authorized=(
                    credential_creation_policy == "create_if_missing"
                    and bool(checkpoint.credential_creation_controls)
                ),
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
            if (
                checkpoint_satisfied(checkpoint, fresh)
                and not checkpoint.credential_creation_controls
            ):
                session.checkpoint_index += 1
                session.attempted_checkpoint_index = session.checkpoint_index
            else:
                # Creation checkpoints stay active while a multi-step form is
                # being filled. They complete only when the next loop observes
                # all reviewed capture selectors and enters the secret boundary.
                session.attempted_checkpoint_index = session.checkpoint_index + 1
                if not transitioned:
                    # Nothing observably changed: count it so a control that does
                    # nothing cannot spin the loop.
                    action_failures += 1
                    if action_failures >= _MAX_ACTION_FAILURES:
                        return self._failed_observation(session, "postcondition_failed")

        return self._human_required(session, "The bounded browser action limit was reached.")

    async def _drive_signup(
        self,
        session: _PwSession,
        *,
        sensitive_data: Mapping[str, str],
        signup_fields: Mapping[str, str],
        state: SignupSessionState,
        signup_policy: SignupPolicy | None = None,
        resume_signal: str | None,
    ) -> SignupResult:
        """Run deterministic signup under the session's serialized browser lock."""

        async def _locked() -> SignupResult:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                # Email and password are account data. Tighten egress and discard
                # any pre-fill frame before the first possible injection.
                session.egress.advance_to(EgressStage.AUTHENTICATING)
                session.screenshot = None
                session.screenshot_at = None
                return await drive_signup(
                    page=_active_page(session),
                    patterns=session.patterns,
                    sensitive_data=sensitive_data,
                    approved_fields=signup_fields,
                    state=state,
                    signup_policy=signup_policy,
                    resume_signal=resume_signal,
                    identity_handoff=getattr(
                        self._settings, "signup_identity_handoff_provider", None
                    ),
                )

        try:
            return await self._loop.run(_locked(), timeout=_OP_TIMEOUT_SECONDS)
        except (TypeError, AttributeError, AssertionError, NameError):
            raise
        except Exception:
            return SignupResult(status="failed", reason_code="signup_execution_failed")

    def _observation_from_signup_result(
        self,
        session: _PwSession,
        result: SignupResult,
        *,
        state: SignupSessionState,
    ) -> BrowserObservation | None:
        """Project a value-free signup outcome into the provider contract."""

        if result.status == "continue":
            return None
        if result.status == "failed":
            return self._failed_observation(session, result.reason_code)
        # Signup commonly has three legitimate gates (terms, CAPTCHA, then email
        # verification), so it uses its own bounded counter rather than consuming
        # the existing-login two-handoff budget.
        if state.handoff_count >= 5:
            return self._failed_observation(session, "signup_handoff_limit_reached")
        state.handoff_count += 1
        return self._human_required(
            session,
            result.instruction or "Complete the signup step in the live browser.",
            reason_code=result.reason_code,
            action_type=result.action_type or "provider_verification",
        )

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

    async def probe_human_gate(self, session_id: str) -> _GateProbe:
        """Say which human gate the page presents right now, changing nothing.

        This is the observation half of the autonomous takeover. The watcher that
        decides whether a paused run may continue lives in the API and cannot see
        the page; the page lives here, next to the recipe-installed mask and the
        gate classifier, so the reading happens here and only the reading.

        ``session_id`` is the worker-side handle (``pw_...``), the same key
        :meth:`provider_session_id` and :meth:`latest_screenshot` take. The work
        runs on the one persistent browser loop like every other verb, because a
        Playwright page belongs to the loop that created it.

        **Lock politeness.** The session's operation lock is CHECKED and never
        waited on. A probe that waited would deadlock against exactly the case it
        exists for — an operation parked at the very gate it came to look at — and
        would delay real work in every other case. A held lock is reported as
        ``operation_in_flight`` and the next interval tries again.

        **What it refreshes: nothing.** Every prohibition below holds by
        construction, and each is named so a later edit has to argue with it:

        * ``dom_generation`` is READ, never incremented. An execution that planned
          against generation *N* must re-resolve when the DOM moves on, so a
          watcher bumping it could force a replan of work a human is mid-way
          through.
        * ``last_active_at`` is not refreshed, on this session or on the managed
          session in the service: the watcher must never become the thing keeping a
          session alive, or the absolute lifetime bound stops meaning anything.
        * no screenshot is taken and none is refreshed.
        * ``checkpoint_index``, ``attempted_checkpoint_index``,
          ``login_handoff_count``, ``hitl_generation``, ``hitl_pending``,
          ``credential_surface_ready`` and ``secret_capture_boundary_entered`` are
          not touched.
        * no pause is raised. The probe never returns a ``human_action_required``
          observation and never reaches the worker's human-gate handoff
          (``_human_required`` / ``_bounded_login_handoff``, the
          ``pause_for_captcha`` step in the design), so no CAPTCHA prompt is
          counted and the pause budget cannot creep.
        * no ``goto``, no click, no fill. The reads are ``page.title()``,
          ``page.inner_text("body")`` and the snapshot's per-element
          ``get_attribute`` / ``inner_text`` / ``input_value`` for non-secret
          fields — none of which move focus or dispatch input, so a human typing in
          the live view is undisturbed. Sanitization is inherited from
          ``build_ranked_snapshot`` and ``sanitize_page_text`` rather than
          re-implemented.
        """

        session = self._sessions.get(session_id)
        if session is None:
            # Telling "never existed" apart from "closed by the absolute bound" is
            # the session manager's job, not the worker's: it keeps the closure
            # ring. From here an absent session is only ever a read that could not
            # happen, which the takeover state machine treats as "not cleared".
            return _GateProbe(gate=None, reason="probe_failed")

        async def _locked() -> _GateProbe:
            # TRY-lock, not a wait. This check and the acquire below run in ONE
            # browser-loop coroutine with NO await between them, and the lock is
            # only ever acquired from a browser-loop coroutine, so nothing can take
            # it in the gap and the acquire is uncontended by construction.
            if session.operation_lock.locked():
                return _GateProbe(gate=None, reason="operation_in_flight")
            async with session.operation_lock:
                page = _active_page(session)
                try:
                    raw_title = await page.title()
                except Exception:
                    raw_title = ""
                raw_visible = await _visible_text(page)
                # The same ranked, frame-aware snapshot the observe path builds,
                # with the same reviewed-frame restriction. A collection failure is
                # reported as a failed read below rather than falling back to a
                # wider walk: a probe is allowed to know nothing.
                elements, locators = await build_ranked_snapshot(
                    page,
                    reviewed_patterns=session.patterns,
                    checkpoint_signals=session.checkpoint_signals,
                    limit=MAX_ELEMENTS,
                )
                url = _page_url(page)
                inspection = PageInspection(
                    url=sanitize_url(url),
                    title=sanitize_page_text(
                        raw_title if isinstance(raw_title, str) else "", max_length=300
                    )[:500],
                    visible_text=sanitize_page_text(raw_visible),
                    elements=elements,
                    locators=locators,
                    fingerprint=_fingerprint(url, elements),
                    # READ, never ``session.dom_generation += 1``.
                    generation=session.dom_generation,
                )
                gate = classify_structural_gate(inspection)
                # Only the typed gate travels back; the classifier's instruction
                # text stays here, because the report carries no prompt.
                return _GateProbe(
                    gate=gate[0] if gate is not None else None,
                    reason="observed",
                    observed=True,
                )

        try:
            return await self._loop.run(
                _locked(),
                # The API applies the same bounded budget to the RPC, so a slow read
                # is reported as a failed probe by whichever side notices first.
                timeout=float(self._settings.onboarding_takeover_probe_timeout_seconds),
            )
        except (TypeError, AttributeError, AssertionError, NameError):
            raise
        except Exception:
            # A raise or a timeout is a failed read, never clearance: the watcher
            # must keep the run waiting rather than continue it on no evidence.
            return _GateProbe(gate=None, reason="probe_failed")

    def _chain_for(self, session: _PwSession) -> JsonInference | None:
        """The chain that decides for THIS session.

        A run that pinned a model gets its own chain; every other session shares
        the deployment's. Read through one accessor so a decision, its guard, and
        the provider recorded against it can never disagree about which chain ran.
        """

        pinned = session.inference
        if isinstance(pinned, JsonInference):
            return pinned
        return self._inference

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

        chain = self._chain_for(session)
        if chain is None:  # pragma: no cover - guarded by the caller
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
            chain.generate,
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
        chain = self._chain_for(session)
        if selection_source == "llm" and chain is not None:
            provider = getattr(chain, "last_provider", None)
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
        """Resolve a reviewed non-secret value reference."""

        if value_ref in session.approved_values:
            return session.approved_values[value_ref]
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
        self,
        session: _PwSession,
        patterns: tuple[str, ...],
        *,
        recipe: AppRecipe,
    ) -> None:
        """Install the page/popup registry, dialog handler and download guard.

        All three are installed BEFORE any navigation or action, so a popup,
        dialog or download can never appear unguarded. Host sets come only from
        the reviewed per-app patterns — never from page content or model output.
        """

        extras = reviewed_egress_extensions(session.app_slug, recipe=recipe)
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

    def _session_app_name(self, session: _PwSession) -> str:
        """The bound app's display name for operator-facing prose, never a guess."""

        recipe = get_app_recipe(session.app_slug) if session.app_slug else None
        if recipe is not None:
            return recipe.app_name
        return session.app_slug or "The app"

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

        # The app the session is actually bound to. These messages named Pipedrive
        # literally, so every other app's operator was told to look for a Pipedrive
        # prompt that does not exist.
        app = self._session_app_name(session)

        if reason in {"captcha_required", "login_verification_required"}:
            if reason == "captcha_required":
                return self._bounded_login_handoff(
                    session,
                    f"{app} requires a browser verification step. Complete the visible "
                    "CAPTCHA or security prompt in the live browser, then resume.",
                    reason_code=reason,
                    action_type="captcha",
                )
            return self._bounded_login_handoff(
                session,
                "The submitted login did not reach an authenticated page. Review "
                f"{app}'s verification or new-device prompt in the interactive "
                "browser, complete it, then resume.",
                reason_code=reason,
                action_type="provider_verification",
            )

        # Hard blocks: a reviewed-frame or safe-link violation is a failure.
        if reason in {"login_frame_unreviewed", "verification_link_blocked"}:
            return self._failed_observation(session, reason)

        # The deterministic driver could not act on the page: the field it needed was
        # not fillable, or the form's own submit control was not reachable. Saying so
        # is the point — these used to submit anyway and surface as a verification
        # prompt, which sent the owner looking for the wrong thing.
        if reason in {
            "login_email_fill_failed",
            "login_password_fill_failed",
            "login_submit_control_not_found",
        }:
            return self._bounded_login_handoff(
                session,
                f"The {app} sign-in form could not be completed automatically "
                f"({reason}). Finish signing in in the live browser, then resume.",
                reason_code=reason,
                action_type="provider_verification",
            )

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
                # The Gmail verification worker handles both a numeric OTP and a
                # reviewed magic link through the same bound, one-time channel.
                action_type="email_otp",
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

    def _resolve_patterns(
        self,
        research: OperationalResearch,
        *,
        recipe: AppRecipe,
    ) -> tuple[str, ...]:
        try:
            allowed = build_browser_allowed_hosts(
                research.app_slug,
                research,
                access_route=research.access_route,
                recipe=recipe,
            )
        except BrowserPolicyInactiveError as exc:
            raise ProviderOperationError(
                capability="Playwright browser", reason_code=exc.reason_code
            ) from None
        return validate_allowed_domains(allowed.patterns())

    async def _capture_contract_present(
        self,
        session: _PwSession,
        spec: CredentialCaptureSpec,
    ) -> bool:
        """Prove all reviewed capture selectors exist without reading a value."""

        async def _present() -> bool:
            async with session.operation_lock:
                page = _active_page(session)
                parsed = urlsplit(_page_url(page))
                host = (parsed.hostname or "").casefold()
                if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
                    return False
                if spec.expected_path_prefix and not (parsed.path or "/").startswith(
                    spec.expected_path_prefix
                ):
                    return False
                for field in spec.capture_fields:
                    found = False
                    for selector in field.selectors:
                        try:
                            if int(await page.locator(selector).count()) == 1:
                                found = True
                                break
                        except Exception:
                            return False
                    if not found:
                        return False
                return bool(spec.capture_fields)

        try:
            return bool(await self._loop.run(_present(), timeout=_OP_TIMEOUT_SECONDS))
        except Exception:
            return False

    async def auto_capture_credentials(
        self,
        handle: str,
        app_slug: str,
        secret_store: SecretStore | None = None,
        *,
        recipe: AppRecipe | None = None,
    ) -> dict[str, str] | None:
        """Capture every reviewed field and return vault references only.

        If the session is already on the credential path, the page is never
        reloaded: several providers display a secret once and a navigation would
        irretrievably destroy it. All required values are extracted and pattern-
        checked before the first vault write, preventing a selector miss from
        producing a knowingly partial credential bundle.
        """

        store = secret_store or self._secret_store
        session = self._sessions.get(handle)
        bound_recipe = recipe or get_app_recipe(app_slug)
        if bound_recipe is None or bound_recipe.app_slug != app_slug:
            return None
        spec = recipe_to_capture_spec(bound_recipe)
        if session is None or spec is None or store is None or not spec.capture_fields:
            return None
        if not navigation_allowed(spec.url, session.patterns):
            return None

        async def _capture() -> dict[str, str] | None:
            async with session.operation_lock:
                session.last_active_at = datetime.now(UTC)
                page = _active_page(session)
                parsed = urlsplit(_page_url(page))
                on_expected_surface = bool(
                    (parsed.hostname or "").casefold() == spec.vendor_domain
                    or (parsed.hostname or "").casefold().endswith("." + spec.vendor_domain)
                ) and bool(
                    not spec.expected_path_prefix
                    or (parsed.path or "/").startswith(spec.expected_path_prefix)
                )
                if not on_expected_surface:
                    try:
                        await page.goto(
                            spec.url,
                            wait_until="domcontentloaded",
                            timeout=_NAV_TIMEOUT_MS,
                        )
                    except Exception:
                        return None

                current = urlsplit(_page_url(page))
                host = (current.hostname or "").casefold()
                if not (host == spec.vendor_domain or host.endswith("." + spec.vendor_domain)):
                    return None
                if spec.expected_path_prefix and not (current.path or "/").startswith(
                    spec.expected_path_prefix
                ):
                    return None
                if spec.expected_heading:
                    text = await _visible_text(page)
                    if spec.expected_heading.casefold() not in text.casefold():
                        return None

                captured: dict[str, str] = {}
                activated_reveals: set[str] = set()
                for field in spec.capture_fields:
                    if field.reveal_selector and field.reveal_selector not in activated_reveals:
                        try:
                            reveal = page.locator(field.reveal_selector)
                            reveal_count = int(await reveal.count())
                            if reveal_count > 1:
                                return None
                            if reveal_count == 1:
                                await reveal.click(timeout=5_000)
                            activated_reveals.add(field.reveal_selector)
                        except Exception:
                            return None

                    pattern = re.compile(field.value_pattern)
                    value: str | None = None
                    for selector in field.selectors:
                        try:
                            locator = page.locator(selector)
                            if int(await locator.count()) != 1:
                                continue
                            if field.source == "input_value":
                                raw = await locator.input_value(timeout=2_000)
                                candidate = raw.strip() if isinstance(raw, str) else ""
                                if candidate and pattern.fullmatch(candidate):
                                    value = candidate
                                    break
                            else:
                                raw = await locator.text_content(timeout=2_000)
                                candidate = raw.strip() if isinstance(raw, str) else ""
                                match = pattern.search(candidate) if candidate else None
                                if match is not None:
                                    value = (
                                        match.group(1) if pattern.groups == 1 else match.group(0)
                                    )
                                    break
                        except Exception:
                            continue
                    if not value:
                        captured.clear()
                        return None
                    captured[field.field_kind] = value
                return captured

        raw_values = await self._loop.run(_capture(), timeout=_OP_TIMEOUT_SECONDS)
        if not raw_values:
            return None
        references: dict[str, str] = {}
        try:
            for kind, raw_value in raw_values.items():
                reference = store.put(app_slug=app_slug, kind=kind, value=raw_value)
                references[kind] = validate_vault_reference(reference)
            return references
        except Exception:
            delete = getattr(store, "delete", None)
            if callable(delete):
                for reference in references.values():
                    with contextlib.suppress(Exception):
                        delete(reference)
            raise
        finally:
            raw_values.clear()

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
            self._signup_states.pop(context.session_id, None)
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
            self._signup_states.clear()
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
