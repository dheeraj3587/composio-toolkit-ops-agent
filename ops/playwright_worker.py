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
import re
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
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
    reviewed_egress_extensions,
)
from ops.browser_host_policy import BrowserPolicyInactiveError, build_browser_allowed_hosts
from ops.browser_link_log import log_event
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
    DialogRecord,
    DownloadPolicy,
    DownloadRecord,
    frame_path_is_reviewed,
    install_dialog_handler,
    install_download_guard,
)
from ops.browser_risk import BrowserActionRiskPolicy
from ops.browser_snapshot import build_ranked_snapshot
from ops.browser_target_selection import AccountState, derive_account_state, select_browser_target
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
from ops.policies import (
    account_creation_requested as should_create_account,
)
from ops.policies import (
    legacy_credential_creation_policy,
    validate_account_policy,
    validate_credential_policy,
    validate_developer_app_policy,
)
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError
from ops.secret_store import SecretStore

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)
_NAV_TIMEOUT_MS = 45_000
# Per-action Playwright timeout. Playwright auto-waits for actionability, so this
# is a ceiling on that wait rather than a substitute for it.
_ACTION_TIMEOUT_MS = 10_000
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


def select_initial_target(
    research: Any,
    trace: Any,
    patterns: Sequence[str],
    *,
    account_state: AccountState = "unknown",
) -> str | None:
    """Choose the shared account-aware reviewed starting URL for Playwright.

    The shared selector preserves Playwright's conservative compatibility fallback:
    an unverified developer-portal field is considered only when this app has no
    reviewed trace.  Field-level claims, trace host validation, and strict URL
    rejection are centralized with the Browser Use implementation.
    """

    return select_browser_target(
        research=research,
        trace=trace,
        allowed_domains=patterns,
        account_state=account_state,
        is_allowed_url=is_allowed_browser_url,
        fallback_mode="playwright",
    )


def make_egress_route_handler(
    *,
    policy: BrowserEgressPolicy,
    stage_provider: Callable[[], EgressStage],
) -> Callable[[Any], Awaitable[None]]:
    """Build the route handler that makes ``BrowserEgressPolicy`` the authority.

    The four-stage policy already existed but was never installed: the context
    route used the older two-stage string handler, so per-kind and per-stage host
    sets (reviewed IdP hosts, post-auth hosts, credential-surface tightening) had
    no effect on the network.

    Unknown resource kinds fail closed inside ``policy.permits``. A stage-provider
    error is treated as the STRICTEST stage rather than the most permissive.
    """

    blocked_seen: set[tuple[str, str, str]] = set()

    async def _handler(route: Any) -> None:
        request = route.request
        try:
            kind = str(request.resource_type or "").casefold()
            url = str(request.url)
        except Exception:
            await route.abort(error_code="blockedbyclient")
            return

        try:
            stage = stage_provider()
        except Exception:
            stage = EgressStage.CREDENTIAL_SURFACE  # fail closed: tightest stage

        if policy.permits(url=url, kind=kind, stage=stage):
            await route.continue_()
        else:
            host = (urlsplit(url).hostname or "").casefold()
            finding = (host, kind, stage.value)
            if host and finding not in blocked_seen and len(blocked_seen) < 32:
                blocked_seen.add(finding)
                log_event(
                    "playwright.egress.blocked",
                    blocked_host=host,
                    resource_kind=kind,
                    stage=stage.value,
                )
            await route.abort(error_code="blockedbyclient")

    return _handler


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
    # The opaque worker-side handle (pw_...), used only to correlate sanitized
    # decision events for one session. Never a URL, account or credential.
    handle: str = ""
    # Strong references to in-flight popup-configuration tasks. Without this the
    # event loop keeps only a WEAK reference and a task can be garbage-collected
    # before it finishes installing the popup's guards.
    popup_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    # True only when the WORKER acquired its own capacity slot for this session.
    # False in service mode, where the manager owns capacity — so the worker must
    # not release a slot it never took.
    worker_capacity_owned: bool = False
    # True only when `browser.new_context(storage_state=...)` completed for this
    # session. It is a local authentication fact, never a cookie/state payload.
    restored_storage_state: bool = False
    # Confirmed vs attempted checkpoint state: `checkpoint_index` advances ONLY
    # after a verified postcondition, so a failed action cannot skip a checkpoint.
    checkpoint_index: int = 0
    attempted_checkpoint_index: int = 0
    # Monotonic DOM generation: every inspection gets one, and an execution that
    # planned against an older generation must re-resolve or replan.
    dom_generation: int = 0
    # Egress stage: tightened permanently once credentials are injected or a
    # credential-bearing page is reached (item 6).
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
    # Login verification handoffs are bounded so Resume cannot loop forever.
    login_handoff_count: int = 0
    # An early target probe may reveal a provider challenge before authentication
    # is complete. It must not consume the separate post-HITL navigation budget.
    pre_auth_target_probed: bool = False
    # The reviewed post-login target is retried at most once in this session.
    post_login_target_retried: bool = False

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


def _unique_target(
    predicate: ElementPredicate | None, inspection: PageInspection
) -> SnapshotElement | None:
    """Resolve a postcondition target to EXACTLY one element, else None.

    Ambiguity must fail the postcondition rather than pick a match: two identical
    checkboxes would otherwise let the wrong one prove the transition.
    """

    if predicate is None:
        return None
    matches = [element for element in inspection.elements if predicate.matches(element)]
    return matches[0] if len(matches) == 1 else None


def postcondition_satisfied(
    postcondition: CandidatePostcondition,
    *,
    before: PageInspection,
    after: PageInspection,
    expected_selected_label: str | None = None,
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

    # Checked/selected assertions are TARGET-BOUND: they must hold for the element
    # the action was performed on. Scanning every element let an unrelated control
    # that already had the desired state prove a no-op.
    if postcondition.checked_state is not None:
        target = _unique_target(postcondition.target, after)
        if target is not None and target.checked is postcondition.checked_state:
            return True

    # For a select, the expected LABEL comes from the executor (the resolved option
    # text), because the approved-value reference name is not the option's label.
    needle_source = expected_selected_label or postcondition.selected_value
    if needle_source:
        target = _unique_target(postcondition.target, after)
        if target is not None:
            needle = needle_source.casefold()
            observed = (target.selected_label or "").casefold()
            if observed and needle in observed:
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
    ) -> BrowserSessionContext:
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

        async def _launch() -> tuple[Any, Any, Any, Any, asyncio.Lock]:
            playwright = await module.async_playwright().start()
            try:
                browser = await playwright.chromium.launch(
                    headless=self._headless, args=self._launch_args()
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
        account_policy: str | None = None,
        developer_app_policy: str | None = None,
        credential_policy: str | None = None,
        account_creation_requested: bool | None = None,
        credential_creation_policy: str | None = None,
    ) -> BrowserObservation:
        self._require_configuration()
        resolved_account = validate_account_policy(
            account_policy
            or ("create_if_missing" if account_creation_requested else "reuse_existing")
        )
        resolved_developer = validate_developer_app_policy(developer_app_policy)
        resolved_credential = validate_credential_policy(
            credential_policy
            or ("create_if_missing" if credential_creation_policy == "create_if_missing" else None)
        )
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
            account_creation_requested=should_create_account(resolved_account),
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
            credential_creation_policy=legacy_credential_creation_policy(resolved_credential),
            developer_app_policy=resolved_developer,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: OperationalResearch | None = None,
        *,
        sensitive_data: Mapping[str, str] | None = None,
        account_policy: str | None = None,
        developer_app_policy: str | None = None,
        credential_policy: str | None = None,
        credential_creation_policy: str | None = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del provider_session_id
        resolved_credential = validate_credential_policy(
            credential_policy
            or ("create_if_missing" if credential_creation_policy == "create_if_missing" else None)
        )
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
            credential_creation_policy=legacy_credential_creation_policy(resolved_credential),
            developer_app_policy=validate_developer_app_policy(developer_app_policy),
            resume_signal=normalized_signal,
        )

    async def _run_action_loop(
        self,
        session: _PwSession,
        research: OperationalResearch,
        *,
        sensitive_data: Mapping[str, str] | None,
        credential_creation_policy: str = "reuse_only",
        developer_app_policy: str = "reuse_existing",
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

        # Carried durably now so later developer-application creation can be
        # authorized independently of API-key creation. Phase 1-5 does not execute
        # that side effect yet.
        validate_developer_app_policy(developer_app_policy)
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
# Provider pages commonly embed a visible reCAPTCHA anchor/badge iframe even
# before a challenge exists. For iframe snapshots, require evidence that the
# presented frame is the actual challenge/checkbox surface; ``reCAPTCHA`` alone
# is intentionally insufficient.
_ACTIVE_CAPTCHA_IFRAME = re.compile(r"(?i)challenge|checkbox|bframe|i'?m not a robot|are you human")
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
    return element.role.casefold() in _INTERACTIVE_ROLES and element.actionable()


def classify_structural_gate(
    inspection: PageInspection,
) -> tuple[HumanActionType, str] | None:
    """Identify a human gate from actionable page STRUCTURE, or None."""

    for element in inspection.elements:
        name = element.name
        element_type = element.element_type.casefold()
        role = element.role.casefold()

        # A provider badge/anchor iframe named only "reCAPTCHA" is passive and
        # must not preempt a real login form. Actual challenge/checkbox frames and
        # ordinary actionable CAPTCHA controls remain human gates.
        captcha_control = role != "iframe" and _CAPTCHA_NAME.search(name)
        captcha_frame = role == "iframe" and _ACTIVE_CAPTCHA_IFRAME.search(name)
        if (captcha_control or captcha_frame) and _is_actionable(element):
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


async def _has_unmasked_secret_content(page: Any) -> bool:
    """Return true only when page text itself may expose credential material.

    Login inputs are safe to capture only because ``_masked_screenshot`` masks
    every form field. Plain-text secrets elsewhere in the page remain a hard
    refusal, and inspection errors fail closed.
    """

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
            # Mask every editable value, not only fields whose names look secret.
            # Email/user identifiers are account data too.
            page.locator("input"),
            page.locator("textarea"),
            page.locator("[contenteditable='true']"),
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
    # Cancel and DRAIN any in-flight popup-configuration tasks first, so a popup
    # guard cannot finish installing against a context that is being torn down.
    pending = list(session.popup_tasks)
    for task in pending:
        task.cancel()
    if pending:
        with contextlib.suppress(Exception):
            await asyncio.gather(*pending, return_exceptions=True)
    session.popup_tasks.clear()
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


__all__ = [
    "BrowserActionExpectedError",
    "PlaywrightBrowserWorker",
    "make_egress_route_handler",
    "make_route_handler",
    "navigation_allowed",
    "select_initial_target",
]
