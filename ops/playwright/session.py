"""One live Chromium session: its record, its TTL, and its ordered teardown.

A session is a real Chromium process, so the bookkeeping here is about not leaking
one and not lying about its state:

* TTL fields exist because leaking sessions would exhaust a small VPS, so an idle
  or overlong session can be reaped.
* ``operation_lock`` is supplied explicitly rather than defaulted, because an
  asyncio.Lock binds to the loop that created it: it must be constructed inside the
  browser loop and only acquired from a browser-loop coroutine.
* ``popup_tasks`` holds STRONG references to in-flight popup-configuration tasks,
  since the event loop keeps only a weak one and a task could otherwise be
  garbage-collected before it finishes installing a popup's guards.
* ``checkpoint_index`` advances only after a verified postcondition, which is what
  stops a failed action from skipping a checkpoint; the attempted index is tracked
  separately.
* ``worker_capacity_owned`` and ``capacity_released`` make the capacity slot exactly
  once semantics explicit, including service mode where the manager owns capacity
  and the worker must not release a slot it never took.

Teardown cancels and DRAINS popup tasks before closing anything, so a popup guard
cannot finish installing against a context that is being destroyed, then closes
page/context/browser/playwright in dependency order. Launch failures are mapped from
the exception's own message text only — never a URL, DOM content or credential — so
the resulting reason code is safe to log and surface.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ops.browser.egress import BrowserEgressPolicy, EgressStageTracker
from ops.browser.pages import (
    BrowserPageRegistry,
    DialogRecord,
    DownloadRecord,
)
from ops.browser.session_liveness import session_expiry

_INACTIVITY_WINDOW = timedelta(minutes=15)
_MAXIMUM_WINDOW = timedelta(hours=4)


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
    approved_values: dict[str, str] = field(default_factory=dict)
    # The opaque worker-side handle (pw_...), used only to correlate sanitized
    # decision events for one session. Never a URL, account or credential.
    handle: str = ""
    # Strong references to in-flight popup-configuration tasks. Without this the
    # event loop keeps only a WEAK reference and a task can be garbage-collected
    # before it finishes installing the popup's guards.
    popup_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    # This session's OWN decision chain, when the run pinned a model. None means
    # the worker's deployment chain decides, which is the ordinary case. It lives
    # on the session rather than on the worker because the worker is one process
    # serving several runs, and a model is a property of the run that asked for it.
    inference: Any = None
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
    # True only after the AppRecipe selectors were installed at document start on
    # this browser context. Unlike screenshot masking, this protects the actual
    # X11 pixels relayed through noVNC.
    live_pixel_mask_installed: bool = False
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

    def is_expired(self, now: datetime, *, hitl_attached: bool = False) -> bool:
        """Whether this session may be reaped, per the ONE shared liveness rule.

        The policy itself lives in ``ops/browser/session_liveness.py`` and this
        method keeps no copy of it: the service janitor calls the same function, so
        the two processes cannot drift back into the disagreement that closed a
        browser under an operator solving a CAPTCHA. Only the worker's own windows
        are supplied from here.

        ``hitl_attached`` defaults to False, which is exactly what every existing
        caller already meant — a worker with no attachment probe installed knows of
        no human inside the session — so the default keeps current behaviour.
        """

        return (
            session_expiry(
                now=now,
                created_at=self.created_at,
                last_active_at=self.last_active_at,
                inactivity=_INACTIVITY_WINDOW,
                maximum_age=_MAXIMUM_WINDOW,
                hitl_attached=hitl_attached,
            )
            is not None
        )


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
    # A sandbox refusal is its own operational fact: the host restricts
    # unprivileged user namespaces (Ubuntu 24.04 default) or the process is root.
    # Reporting it as a generic failure sent operators looking for a broken
    # Chromium instead of a missing host capability.
    if (
        "sandboxing failed" in text
        or "without --no-sandbox is not supported" in text
        or "no usable sandbox" in text
        or "failed to move to new namespace" in text
    ):
        return "browser_sandbox_unavailable"
    # Playwright's message embeds the entire Chromium command line, which always
    # contains "--user-data-dir=/tmp/playwright_chromiumdev_profile-..." and
    # "--disable-popup-blocking". Matching loose "profile" plus "lock" substrings
    # therefore reported browser_profile_locked for EVERY launch failure and hid
    # the real cause. Only Chromium's own profile-lock wording counts.
    if (
        "singletonlock" in text
        or "profile appears to be in use" in text
        or "profile directory is already in use" in text
        or "failed to create a processsingleton" in text
    ):
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
