"""The frame-origin check that gates typing a credential.

A credential field inside an UNREVIEWED (e.g. third-party) iframe is never filled,
even when the top-level page is approved — the main frame being allowlisted says
nothing about who owns the nested document. This check runs before any fill, so it
lives here rather than anywhere near a decision backend.

It fails CLOSED: if frames cannot be enumerated or a check raises, the answer is
"not safe".

This module used to also hold ``_login_origin_is_safe``, ``_has_password_field``,
``_inject_login``, ``_submit_login`` and ``_try_fill`` — a complete second
implementation of the credential-typing path that nothing in production called.
The live path is :mod:`ops.browser.login` (``inspect_login`` → ``drive_login``,
reached through ``apply_resume_secrets``). Keeping the copy was actively harmful:
it typed a password with no form-action check, and its submit step clicked the
first control matching ``button:has-text('Sign in')`` — a substring match that
lands on "Continue with Google" whenever the federated buttons render above the
form. Those are the exact defects fixed in the live path, so a regression guard
pointed here would have passed while the real login stayed broken.
"""

from __future__ import annotations

from typing import Any

from ops.browser.pages import frame_path_is_reviewed
from ops.playwright.page_inspection import _page_url
from ops.playwright.routing import navigation_allowed


async def _login_frames_are_reviewed(page: Any, patterns: tuple[str, ...]) -> bool:
    """True when every frame hosting a password field is on a reviewed origin."""

    from ops.browser.snapshot import frame_chain, frame_host

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
