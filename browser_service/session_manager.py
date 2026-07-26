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
import threading
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from browser_service.models import LiveViewMode, SessionLifecycle, SessionSummary


class SessionUnavailable(RuntimeError):
    """A typed refusal (session missing, closing, or capacity exhausted)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(slots=True)
class ManagedSession:
    """One browser session plus everything needed to close it safely."""

    session_id: str
    owner: str
    app_slug: str
    # The WORKER-side handle for the real browser. Explicit ownership: the manager
    # closes the session through the worker rather than reaching into Playwright
    # objects it never actually held (previously `page` was assigned a private
    # _PwSession and context/browser/playwright stayed None, so the closer had
    # nothing to close and the janitor leaked Chromium).
    worker_context: Any = None
    pages: dict[str, Any] = field(default_factory=dict)
    current_page_id: str = ""
    # Live-view availability, tracked from reality rather than assumed.
    screenshot_available: bool = False
    interactive_ready: bool = False
    # The (app, account, owner) triple this session's authenticated state is bound
    # to. None means storage state is not being persisted for this session.
    storage_binding: Any = None
    # Opaque account reference and run scope, used to bind storage state and to
    # consume one-time login references only for the matching run.
    account_ref: str | None = None
    secret_scope: str = ""
    # Lifecycle + lease accounting.
    lifecycle: SessionLifecycle = "ACTIVE"
    active_operations: int = 0
    capacity_released: bool = False
    # HITL state.
    hitl_pending: bool = False
    live_view_mode: LiveViewMode = "screenshot"
    hitl_reason_code: str = ""
    # Timestamps.
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_active_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    maximum_expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Sanitized last-known page path (never a full URL with a query string).
    current_url_path: str = ""
    reason_code: str = ""

    def touch(self) -> None:
        self.last_active_at = datetime.now(UTC)

    def is_idle_expired(self, now: datetime, inactivity: timedelta) -> bool:
        return now - self.last_active_at > inactivity

    def is_age_expired(self, now: datetime) -> bool:
        return now >= self.maximum_expires_at

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
            live_view_available=self.screenshot_available or self.interactive_ready,
            hitl_pending=self.hitl_pending,
            # Distinct capability facts. The build includes the interactive relay;
            # availability remains session-specific and false unless enabled.
            screenshot_supported=True,
            screenshot_available=self.screenshot_available,
            interactive_supported=True,
            interactive_available=self.interactive_ready,
            current_url_path=self.current_url_path,
            reason_code=self.reason_code,
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
        self._in_use = 0
        self._closer = closer
        # Answers "is a human attached to this session's interactive relay right
        # now?". Injected so the manager needs no knowledge of the WebSocket layer.
        self._attachment_probe = attachment_probe
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
            return self._in_use

    def _acquire_capacity(self) -> None:
        if not self._capacity.acquire(blocking=False):
            raise SessionUnavailable("capacity_exhausted")
        with self._lock:
            self._in_use += 1

    def _release_capacity(self, session: ManagedSession) -> None:
        """Release the slot EXACTLY once, even across repeated close attempts."""

        with self._lock:
            if session.capacity_released:
                return
            session.capacity_released = True
            self._in_use = max(0, self._in_use - 1)
        with contextlib.suppress(ValueError):
            self._capacity.release()

    # --- registry -------------------------------------------------------------
    def create(self, *, owner: str, app_slug: str, live_view_mode: LiveViewMode) -> ManagedSession:
        self._acquire_capacity()
        now = datetime.now(UTC)
        session = ManagedSession(
            session_id=f"bs_{uuid4().hex}",
            owner=owner,
            app_slug=app_slug,
            live_view_mode=live_view_mode,
            created_at=now,
            last_active_at=now,
            maximum_expires_at=now + self._maximum_age,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

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
                # Never release a single-display capacity slot while its browser
                # or live RFB attachment may still exist. The CLOSING session is
                # retained so teardown can be retried once the dependency clears.
                session.reason_code = f"{reason_code}:teardown_failed"
                return session.reason_code

        with self._lock:
            session.lifecycle = "CLOSED"
            session.pages.clear()
            self._sessions.pop(session_id, None)
        self._release_capacity(session)
        return session.reason_code or "closed"

    # --- janitor --------------------------------------------------------------
    def expired_session_ids(self, now: datetime | None = None) -> tuple[tuple[str, str], ...]:
        """(session_id, reason) pairs for idle/over-age sessions.

        A session with an ACTIVE operation is NOT reported: the janitor must not
        interrupt work in progress. It will be caught on a later sweep.
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
                if session.is_age_expired(moment):
                    # The maximum-age ceiling is absolute: it bounds even a session
                    # a human is still attached to, so a slot can never be held for
                    # ever.
                    expired.append((session.session_id, "session_max_age_exceeded"))
                elif session.is_idle_expired(moment, self._inactivity):
                    # "Idle" means no autonomous operation ran recently, which is
                    # precisely the state of a waiting_for_hitl session while a
                    # person works in the interactive view. Reaping that would close
                    # the browser under the human it is waiting for, so a pending
                    # HITL gate with an attached client is not idle.
                    if session.hitl_pending and self.is_attached(session.session_id):
                        continue
                    expired.append((session.session_id, "session_idle_expired"))
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
        for session in self.all_sessions():
            await self.close(session.session_id, reason_code="service_shutdown")


__all__ = ["ManagedSession", "SessionManager", "SessionUnavailable"]
