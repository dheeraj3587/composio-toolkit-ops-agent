"""Property tests for the shared browser-session attachment lifetime rule."""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from browser_service.session_manager import SessionManager
from ops.browser import session_liveness as liveness_module
from ops.browser.session_liveness import session_expiry
from ops.playwright.session import _INACTIVITY_WINDOW, _MAXIMUM_WINDOW, _PwSession

_BASE_TIME = datetime(2025, 1, 1, tzinfo=UTC)
_INACTIVITY_SECONDS = int(_INACTIVITY_WINDOW.total_seconds())
_MAXIMUM_SECONDS = int(_MAXIMUM_WINDOW.total_seconds())


def _worker_session(*, created_at: datetime, last_active_at: datetime) -> _PwSession:
    return _PwSession(
        playwright=None,
        browser=None,
        context=None,
        page=None,
        operation_lock=asyncio.Lock(),
        created_at=created_at,
        last_active_at=last_active_at,
    )


def _manager() -> SessionManager:
    return SessionManager(
        max_sessions=1,
        inactivity_seconds=_INACTIVITY_SECONDS,
        maximum_age_seconds=_MAXIMUM_SECONDS,
        drain_seconds=0.1,
    )


# Feature: autonomous-onboarding-reliability, Property 10: The maximum lifetime bound is absolute
@given(
    maximum_seconds=st.integers(min_value=1, max_value=_MAXIMUM_SECONDS),
    excess_seconds=st.integers(min_value=0, max_value=_MAXIMUM_SECONDS),
    hitl_attached=st.booleans(),
)
@settings(max_examples=100)
def test_the_maximum_lifetime_bound_is_absolute(
    maximum_seconds: int,
    excess_seconds: int,
    hitl_attached: bool,
) -> None:
    """**Validates: Requirements 2.3, 2.5**"""

    maximum_age = timedelta(seconds=maximum_seconds)
    now = _BASE_TIME + maximum_age + timedelta(seconds=excess_seconds)

    assert (
        session_expiry(
            now=now,
            created_at=_BASE_TIME,
            last_active_at=now,
            inactivity=_INACTIVITY_WINDOW,
            maximum_age=maximum_age,
            hitl_attached=hitl_attached,
        )
        == "session_max_age_exceeded"
    )


@st.composite
def _within_maximum_states(draw: st.DrawFn) -> tuple[int, int, bool, bool]:
    age_seconds = draw(st.integers(min_value=0, max_value=_MAXIMUM_SECONDS - 1))
    idle_seconds = draw(st.integers(min_value=0, max_value=age_seconds))
    hitl_pending = draw(st.booleans())
    attached = draw(st.booleans())
    return age_seconds, idle_seconds, hitl_pending, attached


# Feature: autonomous-onboarding-reliability, Property 11: Attachment exempts idle expiry, and both consumers agree
@given(state=_within_maximum_states())
@settings(max_examples=100)
def test_attachment_exempts_idle_expiry_and_both_consumers_agree(
    state: tuple[int, int, bool, bool],
) -> None:
    """**Validates: Requirements 2.1, 2.2, 2.4**"""

    age_seconds, idle_seconds, hitl_pending, attached = state
    now = _BASE_TIME + timedelta(seconds=age_seconds)
    last_active_at = now - timedelta(seconds=idle_seconds)
    hitl_attached = hitl_pending and attached
    expected_reason = (
        "session_idle_expired" if idle_seconds > _INACTIVITY_SECONDS and not hitl_attached else None
    )

    shared_reason = session_expiry(
        now=now,
        created_at=_BASE_TIME,
        last_active_at=last_active_at,
        inactivity=_INACTIVITY_WINDOW,
        maximum_age=_MAXIMUM_WINDOW,
        hitl_attached=hitl_attached,
    )
    worker_expired = _worker_session(
        created_at=_BASE_TIME,
        last_active_at=last_active_at,
    ).is_expired(now, hitl_attached=hitl_attached)

    manager = _manager()
    managed = manager.create(
        owner="property-owner",
        app_slug="example-provider",
        live_view_mode="screenshot",
    )
    managed.created_at = _BASE_TIME
    managed.last_active_at = last_active_at
    managed.maximum_expires_at = _BASE_TIME + _MAXIMUM_WINDOW
    managed.hitl_pending = hitl_pending
    manager.set_attachment_probe(lambda session_id: attached)
    manager_reason = dict(manager.expired_session_ids(now)).get(managed.session_id)

    assert shared_reason == expected_reason
    assert worker_expired is (expected_reason is not None)
    assert manager_reason == expected_reason


def test_the_shared_liveness_rule_imports_no_settings() -> None:
    """The attachment exemption cannot depend on the takeover feature switch."""

    source = inspect.getsource(liveness_module)
    assert "ops.core.config" not in source


# Feature: autonomous-onboarding-reliability, Property 12: A live-view disconnect grants no idle budget
@given(
    age_seconds=st.integers(min_value=0, max_value=_MAXIMUM_SECONDS * 2),
    idle_seconds=st.integers(min_value=0, max_value=_MAXIMUM_SECONDS * 2),
    hitl_pending=st.booleans(),
    attached=st.booleans(),
)
@settings(max_examples=100)
def test_a_live_view_disconnect_grants_no_idle_budget(
    age_seconds: int,
    idle_seconds: int,
    hitl_pending: bool,
    attached: bool,
) -> None:
    """**Validates: Requirement 2.9**"""

    now = _BASE_TIME + timedelta(seconds=age_seconds)
    manager = _manager()
    managed = manager.create(
        owner="property-owner",
        app_slug="example-provider",
        live_view_mode="screenshot",
    )
    managed.created_at = _BASE_TIME
    managed.last_active_at = now - timedelta(seconds=idle_seconds)
    managed.maximum_expires_at = _BASE_TIME + _MAXIMUM_WINDOW
    managed.hitl_pending = hitl_pending
    manager.set_attachment_probe(lambda session_id: attached)

    before_timestamp = managed.last_active_at
    before_reason = dict(manager.expired_session_ids(now)).get(managed.session_id)
    manager.retain(managed.session_id, event="live_view_client_disconnect")
    after_reason = dict(manager.expired_session_ids(now)).get(managed.session_id)

    assert managed.last_active_at == before_timestamp
    assert after_reason == before_reason
