"""Session-slot accounting and cleanup for the single-display browser service.

The blocker these cover: with ``PLAYWRIGHT_MAX_SESSIONS=1`` the whole deployment
has exactly one slot, so every path that ends a run must release it and no path
may release a session a human is still using.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from browser_service.session_manager import SessionManager, SessionUnavailable

OWNER = "assignment-owner"


def _manager(
    *,
    max_sessions: int = 1,
    inactivity_seconds: int = 900,
    maximum_age_seconds: int = 3600,
    drain_seconds: float = 0.1,
    closer: Any = None,
) -> SessionManager:
    return SessionManager(
        max_sessions=max_sessions,
        inactivity_seconds=inactivity_seconds,
        maximum_age_seconds=maximum_age_seconds,
        drain_seconds=drain_seconds,
        closer=closer,
    )


def _create(manager: SessionManager, app_slug: str = "pipedrive") -> Any:
    return manager.create(owner=OWNER, app_slug=app_slug, live_view_mode="screenshot")


# --- 1/9. a failed launch must not consume the only slot ----------------------
def test_failed_launch_releases_capacity_and_allows_the_next_create() -> None:
    """Mirrors browser_service create_session: reserve, launch, close on failure."""

    manager = _manager(max_sessions=1)

    async def scenario() -> None:
        first = _create(manager)
        assert manager.capacity_in_use == 1
        # The launch raised, so the endpoint closes the reserved session.
        reason = await manager.close(first.session_id, reason_code="browser_launch_failed")
        assert reason == "browser_launch_failed"
        assert manager.capacity_in_use == 0
        # The next run must be admitted without a worker restart.
        second = _create(manager)
        assert second.session_id != first.session_id
        assert manager.capacity_in_use == 1

    asyncio.run(scenario())


def test_an_active_session_blocks_a_second_create_until_it_closes() -> None:
    manager = _manager(max_sessions=1)

    async def scenario() -> None:
        first = _create(manager)
        with pytest.raises(SessionUnavailable) as excinfo:
            _create(manager)
        assert excinfo.value.reason_code == "capacity_exhausted"

        await manager.close(first.session_id, reason_code="closed_by_api")
        assert manager.capacity_in_use == 0
        _create(manager)  # the slot is reusable

    asyncio.run(scenario())


# --- 6/7. cleanup is idempotent ----------------------------------------------
def test_closing_the_same_session_twice_is_safe() -> None:
    manager = _manager(max_sessions=1)

    async def scenario() -> None:
        session = _create(manager)
        first = await manager.close(session.session_id, reason_code="closed_by_api")
        second = await manager.close(session.session_id, reason_code="closed_by_api")
        assert first == "closed_by_api"
        # Already gone: reported as success, and the slot is released exactly once.
        assert second == "session_not_found"
        assert manager.capacity_in_use == 0
        # The single slot is still usable, i.e. it was not released twice.
        _create(manager)
        assert manager.capacity_in_use == 1

    asyncio.run(scenario())


def test_a_failing_closer_never_leaks_the_slot_silently() -> None:
    """A teardown failure holds the slot ON PURPOSE and stays retryable."""

    attempts: list[str] = []

    async def _closer(session: Any) -> None:
        attempts.append(session.session_id)
        if len(attempts) == 1:
            raise RuntimeError("live_attachment_drain_failed")

    manager = _manager(max_sessions=1, closer=_closer)

    async def scenario() -> None:
        session = _create(manager)
        reason = await manager.close(session.session_id, reason_code="closed_by_api")
        assert reason.endswith(":teardown_failed")
        # Capacity is deliberately retained while the browser may still exist.
        assert manager.capacity_in_use == 1
        # The janitor must offer it again so teardown is retried.
        assert session.session_id in {sid for sid, _ in manager.expired_session_ids()}
        closed = await manager.sweep()
        assert session.session_id in closed
        assert manager.capacity_in_use == 0

    asyncio.run(scenario())


# --- 7/8. janitor behaviour ---------------------------------------------------
def test_janitor_reaps_an_abandoned_session() -> None:
    manager = _manager(max_sessions=1, inactivity_seconds=60)

    async def scenario() -> None:
        session = _create(manager)
        session.last_active_at = datetime.now(UTC) - timedelta(minutes=10)
        expired = dict(manager.expired_session_ids())
        assert expired.get(session.session_id) == "session_idle_expired"
        assert await manager.sweep() == (session.session_id,)
        assert manager.capacity_in_use == 0

    asyncio.run(scenario())


def test_janitor_does_not_reap_an_attached_interactive_hitl_session() -> None:
    """A human solving a CAPTCHA runs no operation; that is not abandonment."""

    manager = _manager(max_sessions=1, inactivity_seconds=60)

    async def scenario() -> None:
        session = _create(manager)
        session.hitl_pending = True
        session.last_active_at = datetime.now(UTC) - timedelta(minutes=10)
        manager.set_attachment_probe(lambda session_id: session_id == session.session_id)

        assert manager.expired_session_ids() == ()
        assert await manager.sweep() == ()
        assert manager.get_if_present(session.session_id) is not None

        # Once the human disconnects, the session becomes reapable again.
        manager.set_attachment_probe(lambda session_id: False)
        assert dict(manager.expired_session_ids()).get(session.session_id) == (
            "session_idle_expired"
        )

    asyncio.run(scenario())


def test_maximum_age_still_bounds_an_attached_hitl_session() -> None:
    """The absolute ceiling applies even to an attached human, so a slot is never
    held for ever."""

    manager = _manager(max_sessions=1, maximum_age_seconds=1)

    async def scenario() -> None:
        session = _create(manager)
        session.hitl_pending = True
        session.maximum_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        manager.set_attachment_probe(lambda session_id: True)
        assert dict(manager.expired_session_ids()).get(session.session_id) == (
            "session_max_age_exceeded"
        )

    asyncio.run(scenario())


def test_a_probe_failure_is_treated_as_attached() -> None:
    """Fail safe: never close a session because the probe itself broke."""

    manager = _manager(max_sessions=1, inactivity_seconds=60)

    def _broken(session_id: str) -> bool:
        raise RuntimeError("probe exploded")

    async def scenario() -> None:
        session = _create(manager)
        session.hitl_pending = True
        session.last_active_at = datetime.now(UTC) - timedelta(minutes=10)
        manager.set_attachment_probe(_broken)
        assert manager.is_attached(session.session_id) is True
        assert manager.expired_session_ids() == ()

    asyncio.run(scenario())


# --- 4/5. a live HITL session survives and is reused by resume ---------------
def test_waiting_for_hitl_session_survives_and_is_leased_again_on_resume() -> None:
    manager = _manager(max_sessions=1)

    async def scenario() -> None:
        session = _create(manager)
        session.hitl_pending = True
        # Resume takes a lease on the SAME session rather than creating one.
        with manager.lease(session.session_id) as leased:
            assert leased.session_id == session.session_id
            assert leased.active_operations == 1
        assert manager.get_if_present(session.session_id) is not None
        assert manager.capacity_in_use == 1

    asyncio.run(scenario())


def test_a_session_with_an_operation_in_flight_is_never_reaped() -> None:
    manager = _manager(max_sessions=1, inactivity_seconds=60)

    async def scenario() -> None:
        session = _create(manager)
        session.last_active_at = datetime.now(UTC) - timedelta(minutes=10)
        with manager.lease(session.session_id):
            assert manager.expired_session_ids() == ()

    asyncio.run(scenario())


# --- 10. concurrent creates cannot both take one slot -----------------------
def test_concurrent_creates_cannot_both_acquire_the_single_slot() -> None:
    manager = _manager(max_sessions=1)
    granted: list[str] = []
    refused: list[str] = []

    def attempt() -> None:
        try:
            granted.append(_create(manager).session_id)
        except SessionUnavailable as exc:
            refused.append(exc.reason_code)

    import threading

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(granted) == 1
    assert refused == ["capacity_exhausted"] * 7
    assert manager.capacity_in_use == 1
    assert len(manager.all_sessions()) == 1
