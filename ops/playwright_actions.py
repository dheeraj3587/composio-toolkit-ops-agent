"""Typed outcomes for one browser action, and the reviewed values it may use.

Two distinctions carry the design.

Expected failure versus programming error. ``BrowserActionExpectedError`` and the
reason codes describe outcomes the loop knows how to report and replan around, so
they become a typed result instead of propagating. A TypeError, AttributeError or
AssertionError is NEVER mapped onto a reason code: it must propagate so tests and
monitoring see it. The classifier exists because every non-programming exception
used to collapse into ``action_timeout``, which hid browser disconnection, renderer
crashes and closed targets — outcomes needing different operator responses. HTTP
404/5xx are read from the response status explicitly, since Playwright treats them
as successful RESPONSES rather than failed requests.

Reviewed values versus secrets. ``ApprovedBrowserValueResolver`` can only ever
produce non-secret company facts, because nothing else is in its map, and it
additionally refuses to emit any value that merely looks like a vault reference,
password, token, OTP or API key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from ops.browser_metrics import BrowserDecisionEvent
from ops.config import Settings


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
