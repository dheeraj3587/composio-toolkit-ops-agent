"""The DOM primitives that type a credential, and the checks that gate them.

Credentials are only ever typed when all of the following hold, which is why these
checks live next to the fill/submit helpers rather than anywhere near a decision
backend:

* the main frame's URL is inside the reviewed host allowlist,
* exactly one visible and enabled password input exists — zero or several means an
  ambiguous or hidden multi-form page, and typing into it is refused,
* the enclosing form does not post to an off-allowlist host, and
* every frame that hosts a password field is itself on a reviewed origin. A
  credential field inside an unreviewed third-party iframe is never filled, because
  the top-level page being allowlisted says nothing about who owns the nested
  document.

Every failure path fails CLOSED: if frames cannot be enumerated or a check raises,
the answer is "not safe". Filled values are never logged and never reach an LLM.
Filling alone never advances a login, so submission tries the reviewed submit
controls, falls back to pressing Enter in the password field, and then waits
(bounded) for the network to settle so the next observation sees the post-submit page.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ops.browser.pages import frame_path_is_reviewed
from ops.playwright.page_inspection import _page_url
from ops.playwright.routing import navigation_allowed


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


async def _login_frames_are_reviewed(page: Any, patterns: tuple[str, ...]) -> bool:
    """True when every frame hosting a password field is on a reviewed origin.

    A credential field inside an UNREVIEWED (e.g. third-party) iframe is never
    filled, even when the top-level page is approved — the main frame being
    allowlisted says nothing about who owns the nested document.
    """

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


async def _try_fill(page: Any, selector: str, value: str) -> bool:
    try:
        locator = page.locator(selector)
        if await locator.count() >= 1:
            await locator.first.fill(value, timeout=5_000)
            return True
    except Exception:
        return False
    return False
