"""The one session lifetime rule, shared by the worker and the service janitor.

Two processes decide whether a browser session may be reaped: the in-worker rule in
``ops/playwright/session.py`` and the janitor in
``browser_service/session_manager.py``. They used to hold separate copies of the same
policy, and the copies disagreed about whether an attached human keeps a paused session
alive. That disagreement is what closed the browser under an operator solving a CAPTCHA.

This module holds the rule once, as a pure function of its arguments. It imports no
settings and reads no environment, so nothing on the exemption path can observe whether
the takeover watcher is enabled: a deployment with takeover switched off keeps exactly
the same lifetime guarantee.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

SessionExpiry = Literal["session_max_age_exceeded", "session_idle_expired"]


def session_expiry(
    *,
    now: datetime,
    created_at: datetime,
    last_active_at: datetime,
    inactivity: timedelta,
    maximum_age: timedelta,
    hitl_attached: bool,
) -> SessionExpiry | None:
    """The one reason this session may be reaped, or ``None``.

    Maximum age is checked first and unconditionally. The absolute bound outranks an
    attached human: an attachment may postpone an idle reap, but it may never extend the
    ceiling, so a session slot can never be held for ever and a run cannot park a
    browser indefinitely by keeping a live view open.

    Then, and only then, the idle window, and the attachment exemption applies only to
    it. "Idle" here means no autonomous operation ran recently -- which is exactly the
    state of a session a person is working inside, because the human's clicks arrive
    through the live-view relay and refresh no operation clock. So an attached HITL
    session is not idle, and ``hitl_attached`` suppresses idle expiry alone.

    Args:
        now: The moment the decision is made.
        created_at: When the session was opened; the origin of the absolute bound.
        last_active_at: When an autonomous operation last touched the session.
        inactivity: The idle window.
        maximum_age: The absolute lifetime ceiling, measured from ``created_at``.
        hitl_attached: Whether a live-view client is attached to a session paused on a
            human-only gate. Callers pass the conjunction; this function reads only the
            boolean.

    Returns:
        ``"session_max_age_exceeded"`` when the ceiling is reached,
        ``"session_idle_expired"`` when the idle window has elapsed and no attachment
        exempts it, otherwise ``None``.
    """

    # Inclusive: reaching the ceiling ends the session. This matches the janitor's
    # precomputed ``maximum_expires_at`` comparison, so both consumers of this rule
    # decide the boundary itself the same way.
    if now - created_at >= maximum_age:
        return "session_max_age_exceeded"
    if hitl_attached:
        return None
    if now - last_active_at > inactivity:
        return "session_idle_expired"
    return None


__all__ = ["SessionExpiry", "session_expiry"]
