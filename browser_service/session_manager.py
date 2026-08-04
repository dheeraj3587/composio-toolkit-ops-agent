"""Lifecycle-safe browser session management.

The invariant this module exists to guarantee: **the janitor never closes a
session in the middle of an action**, and **capacity is released exactly once**.

Every operation takes a LEASE. Closing is a state machine:

``ACTIVE`` -> ``CLOSING`` (reject new leases) -> wait a bounded drain for
in-flight leases -> cancel whatever remains -> close context/browser -> ``CLOSED``
-> release the capacity slot exactly once.

A lease acquired while ``ACTIVE`` is allowed to finish; a lease requested once
``CLOSING`` is refused with a typed reason. That ordering is what makes an idle
or over-age reap safe to run concurrently with real work.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import threading
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from browser_service.display_pool import DisplaySlot
from browser_service.models import LiveViewMode, SessionLifecycle, SessionSummary
from ops.browser.host_policy import (
    BrowserAllowedHosts,
    BrowserHostDecision,
    evaluate_navigation,
)
from ops.browser.session_liveness import session_expiry


class SessionUnavailable(RuntimeError):
    """A typed refusal (session missing, closing, or capacity exhausted)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


# The ONLY run-level reasons that release a bound session before the janitor's own
# policy would expire it: a terminal run status, an operator cancel, an operator
# reset. Anything else that wants a session gone goes through the janitor or the
# service's own teardown paths (launch failure, explicit delete, shutdown).
RUN_RELEASE_REASONS: frozenset[str] = frozenset(
    {
        "run_terminal_status",
        "run_cancelled",
        "run_reset",
    }
)

# Events that MUST NOT end a bound session. Each of these used to be a plausible
# place for a caller to "clean up" a session it still needs: the run is waiting on
# an email link, parked at a CAPTCHA gate, retrying a navigation, being picked up
# by a replacement worker or a restarted API, or simply had its live view tab
# closed by the operator.
SESSION_CONTINUITY_EVENTS: frozenset[str] = frozenset(
    {
        "email_verification",
        "captcha_paused",
        "navigation_retry",
        "worker_restart",
        "api_restart",
        "live_view_client_disconnect",
    }
)

# Continuity events that mean the RUN is still making progress, so they refresh the
# idle clock the same way a lease does. A live-view client going away is not run
# progress: it keeps the session, but it must not buy the session more idle budget.
_IDLE_REFRESHING_CONTINUITY_EVENTS: frozenset[str] = SESSION_CONTINUITY_EVENTS - {
    "live_view_client_disconnect"
}

# How many closed session ids keep their reason code in memory. Small on purpose:
# this is a diagnostic ring for the sessions a caller may still ask about moments
# after they were reaped, not a history.
_RECENT_CLOSURE_CAPACITY = 64

# A bound the shared lifetime rule can never reach. The two single-question
# delegations on ManagedSession pass it for the bound they are NOT asking about, so
# each one still answers exactly the question its name asks. The ranking of the two
# bounds against one another is made once, in SessionManager.expired_session_ids.
_UNREACHABLE_WINDOW: timedelta = timedelta.max


@dataclass(slots=True)
class ManagedSession:
    """One browser session plus everything needed to close it safely."""

    session_id: str
    owner: str
    app_slug: str
    # SHA-256 of the API-derived run capability. The bearer value itself is never
    # retained in manager state or exposed by SessionSummary.
    session_capability_digest: bytes = b""
    # The WORKER-side handle for the real browser. Explicit ownership: the manager
    # closes the session through the worker rather than reaching into Playwright
    # objects it never actually held (previously `page` was assigned a private
    # _PwSession and context/browser/playwright stayed None, so the closer had
    # nothing to close and the janitor leaked Chromium).
    worker_context: Any = None
    # The PRIVATE X display this session's headful Chromium renders to, leased for
    # the session's whole lifetime. None in a headless deployment. Isolation
    # depends on this being exclusive: x11vnc serves a whole display, so two
    # sessions on one display would let a grant for A stream B's browser window.
    display_slot: DisplaySlot | None = None
    pages: dict[str, Any] = field(default_factory=dict)
    current_page_id: str = ""
    # Live-view availability, tracked from reality rather than assumed.
    screenshot_available: bool = False
    interactive_ready: bool = False
    # Revoked permanently before a reviewed credential surface can be captured.
    # Existing relays are drained at the same transition; new grants fail closed.
    live_view_allowed: bool = True
    # Browser-context document-start mask installed from the checked-in AppRecipe.
    # This protects headed X11 pixels, not only API-served PNG screenshots.
    live_pixel_mask_installed: bool = False
    # Set only after the worker proves the reviewed credential-page predicate.
    credential_surface_ready: bool = False
    # Monotonic server-side boundary: grants are revoked and attachments drained
    # before any automatic reveal or capture operation is allowed to run.
    secret_capture_boundary_entered: bool = False
    # The (app, account, owner) triple this session's authenticated state is bound
    # to. None means storage state is not being persisted for this session.
    storage_binding: Any = None
    # Opaque account reference and run scope, used to bind storage state and to
    # consume one-time login references only for the matching run.
    account_ref: str | None = None
    secret_scope: str = ""
    # The durable run this session belongs to. Together with app_slug and
    # account_ref this is the session's binding: a session is only ever reattached
    # for the same run, app, and account.
    run_id: str = ""
    # The run's allow-list, rebuilt from the caller's serialized patterns at
    # creation. Present for onboarding runs; when present it is enforced HERE, in
    # the container, so a caller bug cannot walk the browser off the provider's
    # domain. None means no run allow-list was supplied and the reviewed
    # recipe-derived policy inside the worker remains the only boundary.
    allowed_hosts: BrowserAllowedHosts | None = None
    # --- the loop seam: one observation's inspection, held for its one action ----
    #
    # The action loop runs in the CONTROL PLANE and acts through two RPCs, so the
    # inspection an action was planned against cannot cross the wire (it holds live
    # Playwright locators). It is cached here between ``/observe`` and ``/act``.
    #
    # ``loop_generation`` is the token the client echoes back. It is COMPARED AND
    # CONSUMED inside ``loop_lock``, which makes the token do two jobs at once:
    #
    #  * TOCTOU-ish staleness: an ``/act`` planned against an older observation is
    #    refused rather than executed against a page the client has not seen.
    #  * duplicate dispatch: if ``/act`` succeeds but its response is lost, the
    #    client's retry carries a consumed token and is refused instead of
    #    submitting a second time. That matters because an action can be
    #    provider-visible (a signup submit) while the effect ledger is
    #    phase-granular, not per-action, so the ledger would not catch it.
    #
    # It is NOT a page fingerprint, and the distinction is load-bearing. The real
    # time-of-check-to-time-of-use guard is the strict ``resolve_identity``
    # re-resolution inside the worker immediately before the click: a JS redirect or
    # an async re-render moves the page without any inspection happening, so the
    # generation stays equal while the locators die. Both guards are required and
    # neither replaces the other.
    loop_inspection: Any = None
    loop_generation: int = 0
    loop_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # Lifecycle + lease accounting.
    lifecycle: SessionLifecycle = "ACTIVE"
    active_operations: int = 0
    capacity_released: bool = False
    # HITL state.
    hitl_pending: bool = False
    # Incremented every time the session enters a new human-action gate. Live
    # control grants are bound to this generation so a token from an earlier
    # pause cannot become valid again during a later pause.
    hitl_generation: int = 0
    live_view_mode: LiveViewMode = "screenshot"
    hitl_reason_code: str = ""
    # One post-detach observation is owed when the LAST live-view client leaves a
    # session that is still paused on a human gate: the operator may have cleared
    # the gate and then closed the tab, and nobody would look again. Bound to the
    # exact HITL generation so debt from an earlier challenge cannot authorize a
    # later one. Cleared on every HITL transition and by the observation that
    # answers it. PROCESS-LOCAL: this is never persisted and never leaves the
    # container except as a generation-matched boolean on the clearance report,
    # so no durable store gains a record that a human was attached (R2.8).
    takeover_final_probe_generation: int | None = None
    # Timestamps.
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_active_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    maximum_expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Sanitized last-known page path (never a full URL with a query string).
    current_url_path: str = ""
    reason_code: str = ""
    # Last recorded keep-alive event from the closed continuity enumeration. Kept
    # for observability only: it never changes whether the session may be reaped.
    last_continuity_event: str = ""

    def touch(self) -> None:
        self.last_active_at = datetime.now(UTC)

    @property
    def is_confined(self) -> bool:
        """Whether this session carries a run allow-list this service enforces."""

        return self.allowed_hosts is not None

    def authorize_navigation(self, url: str) -> BrowserHostDecision:
        """Check one URL against this session's run allow-list, fail-closed.

        The host check itself is ``ops.browser.host_policy.evaluate_navigation`` —
        the service does not carry a second implementation. A session without an
        allow-list is evaluated against an EMPTY one, so every URL is denied rather
        than admitted by omission; callers gate on :attr:`is_confined` when the
        recipe-derived worker policy is the intended boundary instead.
        """

        return evaluate_navigation(
            url,
            self.allowed_hosts
            or BrowserAllowedHosts(
                app_slug=self.app_slug,
                exact_hosts=(),
                vendor_wildcard_domains=(),
            ),
        )

    @property
    def maximum_age_window(self) -> timedelta:
        """This session's absolute ceiling expressed as a window from creation.

        The manager precomputes the ceiling as :attr:`maximum_expires_at`, while the
        shared rule takes a window measured from :attr:`created_at`. Deriving the
        window from the two timestamps keeps the precomputed ceiling authoritative —
        ``now - created_at >= maximum_age_window`` is exactly
        ``now >= maximum_expires_at`` — so moving the ceiling on one session still
        moves that session's expiry.
        """

        return self.maximum_expires_at - self.created_at

    def is_idle_expired(self, now: datetime, inactivity: timedelta) -> bool:
        """Whether the idle window has elapsed, ignoring the attachment exemption.

        A thin delegation to ``ops.browser.session_liveness.session_expiry`` so this
        service holds no second copy of the comparison. The maximum age is passed as
        an unreachable window because this method answers the idle question alone.
        """

        return (
            session_expiry(
                now=now,
                created_at=self.created_at,
                last_active_at=self.last_active_at,
                inactivity=inactivity,
                maximum_age=_UNREACHABLE_WINDOW,
                hitl_attached=False,
            )
            == "session_idle_expired"
        )

    def is_age_expired(self, now: datetime) -> bool:
        """Whether the absolute ceiling has been reached.

        The same thin delegation, with the idle window made unreachable: the ceiling
        is absolute and takes no attachment fact, so this answers on age alone.
        """

        return (
            session_expiry(
                now=now,
                created_at=self.created_at,
                last_active_at=self.last_active_at,
                inactivity=_UNREACHABLE_WINDOW,
                maximum_age=self.maximum_age_window,
                hitl_attached=False,
            )
            == "session_max_age_exceeded"
        )

    def summary(self) -> SessionSummary:
        return SessionSummary(
            session_id=self.session_id,
            lifecycle=self.lifecycle,
            app_slug=self.app_slug,
            created_at=self.created_at.isoformat(),
            last_active_at=self.last_active_at.isoformat(),
            maximum_expires_at=self.maximum_expires_at.isoformat(),
            active_operations=self.active_operations,
            live_view_mode=self.live_view_mode,
            # Previously `mode == "interactive_remote" or True`, which is always
            # True. Now reports what is actually available.
            live_view_available=self.screenshot_available
            or (self.interactive_ready and self.live_view_allowed),
            hitl_pending=self.hitl_pending,
            hitl_generation=self.hitl_generation,
            # Distinct capability facts. The build includes the interactive relay;
            # availability remains session-specific and false unless enabled.
            screenshot_supported=True,
            screenshot_available=self.screenshot_available,
            interactive_supported=True,
            interactive_available=self.interactive_ready and self.live_view_allowed,
            current_url_path=self.current_url_path,
            reason_code=self.reason_code,
            # Echo back exactly what this container will enforce, so the caller can
            # verify its allow-list was accepted instead of assuming it was.
            allowed_host_patterns=(
                self.allowed_hosts.patterns() if self.allowed_hosts is not None else ()
            ),
        )


class SessionManager:
    """Owns the session registry, capacity, leases, and the reaping janitor."""

    def __init__(
        self,
        *,
        max_sessions: int,
        inactivity_seconds: int,
        maximum_age_seconds: int,
        drain_seconds: float,
        closer: Callable[[ManagedSession], Awaitable[None]] | None = None,
        attachment_probe: Callable[[str], bool] | None = None,
    ) -> None:
        self._sessions: dict[str, ManagedSession] = {}
        self._lock = threading.RLock()
        self._max_sessions = max_sessions
        self._inactivity = timedelta(seconds=inactivity_seconds)
        self._maximum_age = timedelta(seconds=maximum_age_seconds)
        self._drain_seconds = drain_seconds
        # Race-free admission: two concurrent creates must not both pass.
        self._capacity = threading.BoundedSemaphore(max_sessions)
        # Held capacity is accounted PER SESSION rather than as a bare counter: the
        # ledger records which session ids hold a slot, so "in use" is derived from
        # the sessions actually holding capacity and cannot drift away from them.
        self._held_slots: set[str] = set()
        # Deployment/backup drain gate. Admission and toggling use the SAME lock,
        # so a racing create is linearized either wholly before begin_drain()
        # (and may finish) or wholly after it (and is refused).
        self._accepting_new_sessions = True
        self._closer = closer
        # Answers "is a human attached to this session's interactive relay right
        # now?". Injected so the manager needs no knowledge of the WebSocket layer.
        self._attachment_probe = attachment_probe
        # The last few closures, id -> closure reason code, newest last. In memory
        # and bounded at _RECENT_CLOSURE_CAPACITY, holding closed reason codes and
        # nothing else. Without it a session this janitor reaped at max age and an
        # id that never existed are the same absent session, so a caller asking
        # about a paused run's session would attribute the wrong cause.
        self._recent_closures: OrderedDict[str, str] = OrderedDict()
        self.janitor_running = False

    def set_attachment_probe(self, probe: Callable[[str], bool]) -> None:
        """Install the live-attachment probe used by the idle sweep."""

        self._attachment_probe = probe

    def is_attached(self, session_id: str) -> bool:
        """Whether an authorized interactive client currently holds this session.

        A probe failure is treated as ATTACHED: wrongly reaping a session a human
        is driving is far worse than briefly holding one slot until max age.
        """

        probe = self._attachment_probe
        if probe is None:
            return False
        try:
            return bool(probe(session_id))
        except Exception:
            return True

    def set_closer(self, closer: Callable[[ManagedSession], Awaitable[None]]) -> None:
        """Install the closer after construction.

        The browser worker is created lazily (so /internal/health can answer without
        importing Playwright), but the manager must exist first. This lets the real
        worker-backed closer be attached as soon as the worker exists, instead of
        leaving the manager with a closer that closes nothing.
        """

        self._closer = closer

    # --- capacity -------------------------------------------------------------
    @property
    def capacity_total(self) -> int:
        return self._max_sessions

    @property
    def capacity_in_use(self) -> int:
        with self._lock:
            return len(self._held_slots)

    def held_capacity_session_ids(self) -> tuple[str, ...]:
        """The sessions that currently hold a pool slot, newest order unspecified.

        Per-session accounting is the point: a slot is attributable to the session
        that took it, so a leak is diagnosable as "session X still holds capacity"
        instead of only "one slot is missing".
        """

        with self._lock:
            return tuple(self._held_slots)

    def holds_capacity(self, session_id: str) -> bool:
        """Whether this specific session still holds its pool slot."""

        with self._lock:
            return session_id in self._held_slots

    @property
    def accepting_new_sessions(self) -> bool:
        with self._lock:
            return self._accepting_new_sessions

    def drain_status(self) -> tuple[bool, int, int]:
        """Return one atomic, deliberately minimal admission/capacity snapshot."""

        with self._lock:
            return self._accepting_new_sessions, len(self._held_slots), self._max_sessions

    def begin_drain(self) -> None:
        """Atomically reject new sessions while preserving every existing lease."""

        with self._lock:
            self._accepting_new_sessions = False

    def undrain(self) -> None:
        """Atomically reopen admission after a deployment/backup attempt."""

        with self._lock:
            self._accepting_new_sessions = True

    def _acquire_capacity(self, session_id: str) -> None:
        """Take one slot FOR one session, under the admission gate."""

        with self._lock:
            if not self._accepting_new_sessions:
                raise SessionUnavailable("service_draining")
            if not self._capacity.acquire(blocking=False):
                raise SessionUnavailable("capacity_exhausted")
            self._held_slots.add(session_id)

    def _release_capacity(self, session: ManagedSession) -> None:
        """Release the slot EXACTLY once, even across repeated close attempts."""

        with self._lock:
            if session.capacity_released:
                return
            session.capacity_released = True
            self._held_slots.discard(session.session_id)
        with contextlib.suppress(ValueError):
            self._capacity.release()

    # --- registry -------------------------------------------------------------
    def create(
        self,
        *,
        owner: str,
        app_slug: str,
        live_view_mode: LiveViewMode,
        session_capability_digest: bytes = b"",
        secret_scope: str = "",
        account_ref: str | None = None,
        run_id: str = "",
        allowed_hosts: BrowserAllowedHosts | None = None,
    ) -> ManagedSession:
        # Refuse an unusable allow-list BEFORE a capacity slot is taken: an
        # allow-list that names another app, or that admits nothing, would leave a
        # session whose confinement means nothing.
        if allowed_hosts is not None:
            if allowed_hosts.app_slug != app_slug:
                raise SessionUnavailable("browser_allow_list_app_mismatch")
            if not allowed_hosts.patterns():
                raise SessionUnavailable("browser_allow_list_empty")
        # The id exists before the slot is taken so the held slot is attributable
        # to this session from the moment admission succeeds.
        session_id = f"bs_{uuid4().hex}"
        self._acquire_capacity(session_id)
        now = datetime.now(UTC)
        session = ManagedSession(
            session_id=session_id,
            owner=owner,
            app_slug=app_slug,
            session_capability_digest=session_capability_digest,
            secret_scope=secret_scope,
            account_ref=account_ref,
            # Canonical callers already scope a session by run id; an explicit
            # run_id is preferred and the scope is the fallback, so the binding is
            # always populated for a real run.
            run_id=run_id or secret_scope,
            allowed_hosts=allowed_hosts,
            live_view_mode=live_view_mode,
            created_at=now,
            last_active_at=now,
            maximum_expires_at=now + self._maximum_age,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def find_bound_sessions(
        self,
        *,
        owner: str,
        session_capability_digest: bytes,
        app_slug: str,
        secret_scope: str,
        account_ref: str,
        run_id: str = "",
    ) -> tuple[str, ...]:
        """Return only live sessions matching an exact browser-start binding.

        The binding is (run id, app slug, account reference) on top of the caller's
        authority. ``run_id`` defaults to the run scope, which canonical callers
        already set to the run id.
        """

        with self._lock:
            matched: list[str] = []
            for session in self._sessions.values():
                if session.lifecycle not in {"ACTIVE", "CLOSING"}:
                    continue
                # Always execute BOTH constant-time authority comparisons. Do not
                # reveal through timing whether a guessed tenant was correct.
                owner_matches = hmac.compare_digest(session.owner, owner)
                capability_matches = hmac.compare_digest(
                    session.session_capability_digest,
                    session_capability_digest,
                )
                authority_matches = owner_matches and capability_matches
                if (
                    authority_matches
                    and session.app_slug == app_slug
                    and session.secret_scope == secret_scope
                    and session.run_id == (run_id or secret_scope)
                    and session.account_ref == account_ref
                ):
                    matched.append(session.session_id)
            return tuple(matched)

    def get(self, session_id: str) -> ManagedSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise SessionUnavailable("session_not_found")
        return session

    def get_if_present(self, session_id: str) -> ManagedSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def all_sessions(self) -> tuple[ManagedSession, ...]:
        with self._lock:
            return tuple(self._sessions.values())

    def recent_closure_reason(self, session_id: str) -> str | None:
        """Why this id was closed, for the last few closures, or ``None``.

        ``None`` means "not one of the recent closures": either the id is still live,
        or it was closed longer than :data:`_RECENT_CLOSURE_CAPACITY` closures ago, or
        it never existed. A caller that needs to distinguish a live session from a
        reaped one asks :meth:`get_if_present` first and this second.
        """

        with self._lock:
            return self._recent_closures.get(session_id)

    # --- operation leases -----------------------------------------------------
    @contextlib.contextmanager
    def lease(self, session_id: str) -> Iterator[ManagedSession]:
        """Hold an operation lease for the duration of one action.

        A lease is only granted while the session is ``ACTIVE``; once ``CLOSING``
        the request is refused so the janitor can finish draining.
        """

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionUnavailable("session_not_found")
            if session.lifecycle != "ACTIVE":
                raise SessionUnavailable("session_closing")
            session.active_operations += 1
            session.touch()
        try:
            yield session
        finally:
            with self._lock:
                session.active_operations = max(0, session.active_operations - 1)
                session.touch()

    # --- keep-alive -----------------------------------------------------------
    def retain(self, session_id: str, *, event: str) -> ManagedSession:
        """Record a continuity event and keep the bound session ACTIVE.

        This is the explicit counterpart to :meth:`release_run`: verification waits,
        CAPTCHA pauses, navigation retries, worker restarts, API restarts, and
        live-view disconnects all route through here, so "keep the session" is a
        call a caller makes on purpose rather than the absence of a close call.

        Run-progress events refresh the idle clock; a live-view disconnect does not,
        because a closed browser tab is not the run doing work. Neither one moves the
        absolute maximum-age ceiling, so the janitor's policy stays the only expiry.
        """

        if event not in SESSION_CONTINUITY_EVENTS:
            raise SessionUnavailable("session_continuity_event_unknown")
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionUnavailable("session_not_found")
            if session.lifecycle != "ACTIVE":
                # Retention keeps a live session live; it never resurrects one that
                # is already draining towards CLOSED.
                raise SessionUnavailable("session_closing")
            session.last_continuity_event = event
            if event in _IDLE_REFRESHING_CONTINUITY_EVENTS:
                session.touch()
            return session

    # --- run-level release ----------------------------------------------------
    def bound_run_session_ids(self, run_id: str, *, owner: str | None = None) -> tuple[str, ...]:
        """Live session ids bound to one run, optionally narrowed to one owner."""

        if not run_id:
            return ()
        with self._lock:
            return tuple(
                session.session_id
                for session in self._sessions.values()
                if session.lifecycle in {"ACTIVE", "CLOSING"}
                and session.run_id == run_id
                # Constant-time owner comparison, same discipline as the reattach
                # lookup: a caller must not learn another tenant's run bindings.
                and (owner is None or hmac.compare_digest(session.owner, owner))
            )

    async def release_run(
        self,
        run_id: str,
        *,
        reason_code: str,
        owner: str | None = None,
    ) -> tuple[str, ...]:
        """Release every session bound to a run; returns the ids actually closed.

        Only the closed :data:`RUN_RELEASE_REASONS` enumeration is accepted, so the
        deliberate release paths (terminal run status, cancel, reset) are the only
        ones that can end a run's authenticated session early. Idempotent: releasing
        a run twice closes nothing the second time.
        """

        if reason_code not in RUN_RELEASE_REASONS:
            raise SessionUnavailable("session_release_reason_not_allowed")
        if not run_id:
            # An empty binding would match every unbound session in the pool.
            raise SessionUnavailable("session_run_binding_missing")
        released: list[str] = []
        for session_id in self.bound_run_session_ids(run_id, owner=owner):
            await self.close(session_id, reason_code=reason_code)
            if self.get_if_present(session_id) is None:
                released.append(session_id)
        return tuple(released)

    # --- closing --------------------------------------------------------------
    async def close(self, session_id: str, *, reason_code: str = "closed") -> str:
        """Close a session safely: CLOSING -> bounded drain -> close -> CLOSED.

        Returns the terminal reason code. Idempotent: closing an already-closed
        session is a no-op that still reports success.
        """

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return "session_not_found"
            if session.lifecycle == "CLOSED":
                return session.reason_code or "closed"
            # Mark CLOSING first so no NEW lease can be granted from here on.
            session.lifecycle = "CLOSING"
            session.reason_code = reason_code

        # Wait a bounded period for in-flight operations to finish on their own.
        deadline = asyncio.get_running_loop().time() + self._drain_seconds
        while asyncio.get_running_loop().time() < deadline:
            with self._lock:
                if session.active_operations == 0:
                    break
            await asyncio.sleep(0.05)

        with self._lock:
            abandoned = session.active_operations
        if abandoned:
            # The drain expired: proceed to close anyway, but record that an
            # operation was cancelled rather than pretending it completed.
            session.reason_code = f"{reason_code}:operations_cancelled"

        if self._closer is not None:
            try:
                await self._closer(session)
            except Exception:
                # Never release a capacity slot (or its leased display) while the
                # browser or a live RFB attachment may still exist. The CLOSING
                # session is retained so teardown can be retried once the
                # dependency clears.
                session.reason_code = f"{reason_code}:teardown_failed"
                return session.reason_code

        with self._lock:
            session.lifecycle = "CLOSED"
            session.pages.clear()
            # Record WHY, immediately before the id stops resolving: after the pop
            # there is nothing left to read the reason from. The bare argument is
            # recorded rather than session.reason_code, whose ":operations_cancelled"
            # suffix describes the teardown rather than the cause.
            self._record_closure(session_id, reason_code)
            self._sessions.pop(session_id, None)
        self._release_capacity(session)
        return session.reason_code or "closed"

    def _record_closure(self, session_id: str, reason_code: str) -> None:
        """Add one closure to the bounded ring. Caller MUST hold ``self._lock``."""

        # Re-insert so a re-closed id moves to the newest end instead of keeping an
        # older position and being evicted early.
        self._recent_closures.pop(session_id, None)
        self._recent_closures[session_id] = reason_code
        while len(self._recent_closures) > _RECENT_CLOSURE_CAPACITY:
            self._recent_closures.popitem(last=False)

    # --- janitor --------------------------------------------------------------
    def expired_session_ids(self, now: datetime | None = None) -> tuple[tuple[str, str], ...]:
        """(session_id, reason) pairs for idle/over-age sessions.

        A session with an ACTIVE operation is NOT reported: the janitor must not
        interrupt work in progress. It will be caught on a later sweep.

        These two configured policies — idle timeout and maximum age — plus a retry
        of a failed teardown are the ONLY grounds on which this sweep expires a
        session. No continuity event (verification, CAPTCHA pause, navigation retry,
        worker or API restart, live-view disconnect) is ever an expiry reason.

        The idle/max-age/exemption decision itself is not made here. It is
        ``ops.browser.session_liveness.session_expiry``, the one rule the in-worker
        lifetime check reads too, so the janitor and the worker cannot disagree about
        whether an attached human keeps a paused session alive.
        """

        moment = now or datetime.now(UTC)
        expired: list[tuple[str, str]] = []
        with self._lock:
            for session in self._sessions.values():
                if session.active_operations > 0:
                    continue
                if session.lifecycle == "CLOSING" and session.reason_code.endswith(
                    ":teardown_failed"
                ):
                    # Retry one failed closer on the next bounded janitor sweep.
                    # Capacity remains held until a retry actually succeeds.
                    expired.append(
                        (
                            session.session_id,
                            session.reason_code.removesuffix(":teardown_failed"),
                        )
                    )
                    continue
                if session.lifecycle != "ACTIVE":
                    continue
                expiry = session_expiry(
                    now=moment,
                    created_at=session.created_at,
                    last_active_at=session.last_active_at,
                    inactivity=self._inactivity,
                    maximum_age=session.maximum_age_window,
                    # The exemption is this conjunction, and it is resolved HERE
                    # rather than inside the rule: the rule reads one boolean and
                    # imports no settings, so nothing on the exemption path can
                    # observe whether the takeover watcher is enabled. "Idle" means
                    # no autonomous operation ran recently, which is precisely the
                    # state of a paused session a person is working inside, so a
                    # pending HITL gate with an attached client is not idle. The
                    # maximum age stays absolute and bounds this session anyway.
                    hitl_attached=(session.hitl_pending and self.is_attached(session.session_id)),
                )
                if expiry is not None:
                    expired.append((session.session_id, expiry))
        return tuple(expired)

    async def sweep(self) -> tuple[str, ...]:
        """Close every currently expired session; returns the ids closed."""

        closed: list[str] = []
        for session_id, reason in self.expired_session_ids():
            await self.close(session_id, reason_code=reason)
            if self.get_if_present(session_id) is None:
                closed.append(session_id)
        return tuple(closed)

    async def run_janitor(self, interval_seconds: float = 60.0) -> None:
        """Background sweep loop (started/stopped by the service lifespan)."""

        self.janitor_running = True
        try:
            while True:
                await asyncio.sleep(interval_seconds)
                with contextlib.suppress(Exception):
                    await self.sweep()
        except asyncio.CancelledError:
            raise
        finally:
            self.janitor_running = False

    async def close_all(self) -> None:
        sessions = self.all_sessions()
        if sessions:
            await asyncio.gather(
                *(
                    self.close(session.session_id, reason_code="service_shutdown")
                    for session in sessions
                ),
                return_exceptions=True,
            )


__all__ = [
    "RUN_RELEASE_REASONS",
    "SESSION_CONTINUITY_EVENTS",
    "ManagedSession",
    "SessionManager",
    "SessionUnavailable",
]
