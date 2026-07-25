"""Deterministic login state machine for the self-hosted Playwright harness.

Login is driven ENTIRELY by code — never by the LLM. The model chooses opaque
navigation candidates elsewhere; here, credential/OTP/magic-link values are
filled by deterministic Playwright calls and are NEVER placed in a prompt, log,
audit event, checkpoint, or run-state field.

The state machine recognizes: email-first login, email+password on one page, a
password page after email submission, OTP entry (single field or per-character
fields), an account-selection page, authentication failure, and the
authenticated transition. Anything it cannot safely handle deterministically is
reported as a typed state so the worker escalates to a human.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from ops.browser_candidates import ElementIdentity

LoginState = Literal[
    "unknown",
    "email_required",
    "password_required",
    "credentials_ready",
    "submitted",
    "otp_required",
    "magic_link_required",
    "account_selection_required",
    "authenticated",
    "authentication_failed",
]

# Resume signals the worker will accept after a HITL pause. An unknown signal
# fails closed (see ``normalize_resume_signal``).
ResumeSignal = Literal[
    "human_completed",
    "otp_available",
    "verification_link_available",
    "account_selected",
    "captcha_completed",
    "cancelled",
]
_RESUME_SIGNALS: frozenset[str] = frozenset(
    {
        "human_completed",
        "otp_available",
        "verification_link_available",
        "account_selected",
        "captcha_completed",
        "cancelled",
    }
)


@dataclass(frozen=True, slots=True)
class LoginInspection:
    """A deterministic, secret-free view of the current login surface."""

    state: LoginState
    email_field: ElementIdentity | None
    password_field: ElementIdentity | None
    otp_fields: tuple[ElementIdentity, ...]
    submit_control: ElementIdentity | None
    current_url: str
    reason_code: str


# --- Selectors and text patterns (structure-first, never body-text guessing) ---
_EMAIL_SELECTOR = (
    "input[type='email'], input[name='email' i], input[name='username' i], "
    "input[autocomplete='username'], input[id='email' i], input[id='username' i]"
)
_PASSWORD_SELECTOR = "input[type='password']"
_OTP_SELECTOR = (
    "input[autocomplete='one-time-code'], input[name*='otp' i], input[name*='code' i], "
    "input[id*='otp' i], input[id*='code' i], input[inputmode='numeric']"
)
_SUBMIT_SELECTOR = (
    "button[type='submit'], input[type='submit'], "
    "button:has-text('Log in'), button:has-text('Sign in'), button:has-text('Continue'), "
    "button:has-text('Next'), button:has-text('Log In'), button:has-text('Sign In')"
)
_ACCOUNT_CHOICE_SELECTOR = (
    "button:has-text('Continue as'), button:has-text('Use another account'), "
    "[role='button']:has-text('Continue as'), a:has-text('Choose an account')"
)
_AUTH_FAIL = re.compile(
    r"(?i)(incorrect|invalid|wrong)\s+(password|email|username|credentials)"
    r"|couldn'?t (sign|log) you in|that account (doesn'?t|does not) exist"
    r"|your (password|email) (is|was) incorrect|login failed|authentication failed"
)
_MAGIC_LINK = re.compile(
    r"(?i)check your (email|inbox)|magic link|we (?:sent|emailed) you a (?:link|sign)"
    r"|sign[- ]in link|verification link (?:has been )?sent"
)
_AUTH_PATH = re.compile(r"(?i)/(login|signin|sign-in|auth|sso|session|account/login)")


async def _count_visible_enabled(page: Any, selector: str, *, limit: int = 8) -> int:
    try:
        locator = page.locator(selector)
        total = min(int(await locator.count()), limit)
    except Exception:
        return 0
    count = 0
    for index in range(total):
        field = locator.nth(index)
        try:
            if await field.is_visible() and await field.is_enabled():
                count += 1
        except Exception:
            continue
    return count


async def _first_identity(page: Any, selector: str, role: str) -> ElementIdentity | None:
    try:
        locator = page.locator(selector)
        if int(await locator.count()) < 1:
            return None
        first = locator.first
        if not (await first.is_visible() and await first.is_enabled()):
            return None
        name = ""
        for attr in ("name", "id", "aria-label", "placeholder"):
            try:
                value = await first.get_attribute(attr, timeout=1_000)
            except Exception:
                value = None
            if value:
                name = value
                break
        element_type = ""
        try:
            element_type = (await first.get_attribute("type", timeout=1_000)) or ""
        except Exception:
            element_type = ""
        return ElementIdentity(role=role, name=name[:120], element_type=element_type[:40])
    except Exception:
        return None


async def _visible_body_text(page: Any) -> str:
    try:
        text = await page.inner_text("body", timeout=3_000)
    except Exception:
        return ""
    return text[:8_000] if isinstance(text, str) else ""


async def inspect_login(page: Any, patterns: Sequence[str]) -> LoginInspection:
    """Deterministically classify the current login surface.

    Never types anything; only observes structure (visible/enabled fields) and a
    bounded slice of body text for failure/magic-link detection.
    """

    del patterns  # host safety is enforced separately before any fill
    url = getattr(page, "url", "") or "https://unknown.invalid/"
    email_n = await _count_visible_enabled(page, _EMAIL_SELECTOR)
    password_n = await _count_visible_enabled(page, _PASSWORD_SELECTOR)
    otp_n = await _count_visible_enabled(page, _OTP_SELECTOR)
    body = await _visible_body_text(page)

    email_field = await _first_identity(page, _EMAIL_SELECTOR, "input") if email_n else None
    password_field = (
        await _first_identity(page, _PASSWORD_SELECTOR, "input") if password_n else None
    )
    submit_control = await _first_identity(page, _SUBMIT_SELECTOR, "button")

    otp_fields: tuple[ElementIdentity, ...] = ()
    if otp_n and password_n == 0:  # an OTP field on a page WITHOUT a password field
        ident = await _first_identity(page, _OTP_SELECTOR, "input")
        otp_fields = (ident,) if ident is not None else ()

    account_choice = await _count_visible_enabled(page, _ACCOUNT_CHOICE_SELECTOR)

    def result(state: LoginState, reason: str) -> LoginInspection:
        return LoginInspection(
            state=state,
            email_field=email_field,
            password_field=password_field,
            otp_fields=otp_fields,
            submit_control=submit_control,
            current_url=url,
            reason_code=reason,
        )

    if password_n > 1:
        return result("unknown", "multiple_password_forms")
    if _AUTH_FAIL.search(body) and (password_n or email_n):
        return result("authentication_failed", "authentication_failed")
    if otp_fields:
        return result("otp_required", "otp_required")
    if account_choice and password_n == 0 and email_n == 0:
        return result("account_selection_required", "account_selection_required")
    if password_n == 0 and email_n == 0 and _MAGIC_LINK.search(body):
        return result("magic_link_required", "magic_link_required")
    if email_n >= 1 and password_n >= 1:
        return result("credentials_ready", "credentials_ready")
    if password_n >= 1:
        return result("password_required", "password_required")
    if email_n >= 1:
        return result("email_required", "email_required")
    if not _AUTH_PATH.search(urlsplit(url).path):
        return result("authenticated", "authenticated")
    return result("unknown", "no_recognized_login_surface")


async def _origin_safe_and_unique(page: Any, patterns: Sequence[str]) -> bool:
    """Credentials may be filled only on an approved origin with a single form."""

    from ops.playwright_worker import navigation_allowed

    if not navigation_allowed(getattr(page, "url", "") or "", tuple(patterns)):
        return False
    if await _count_visible_enabled(page, _PASSWORD_SELECTOR) != 1:
        return False
    try:
        action = await page.locator("form:has(input[type='password'])").first.get_attribute(
            "action", timeout=2_000
        )
    except Exception:
        action = None
    if isinstance(action, str) and action.casefold().startswith(("http://", "https://")):
        if not navigation_allowed(action, tuple(patterns)):
            return False
    return True


async def _fill_first(page: Any, selector: str, value: str) -> bool:
    try:
        locator = page.locator(selector)
        if int(await locator.count()) < 1:
            return False
        field = locator.first
        if not (await field.is_visible() and await field.is_enabled()):
            return False
        await field.fill(value, timeout=5_000)
        return True
    except Exception:
        return False


async def _click_submit(page: Any) -> bool:
    try:
        locator = page.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
            await _settle(page)
            return True
    except Exception:
        pass
    try:
        await page.locator(_PASSWORD_SELECTOR).first.press("Enter", timeout=5_000)
        await _settle(page)
        return True
    except Exception:
        return False


async def _click_email_continue(page: Any) -> bool:
    try:
        locator = page.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
            await _settle(page)
            return True
    except Exception:
        pass
    try:
        await page.locator(_EMAIL_SELECTOR).first.press("Enter", timeout=5_000)
        await _settle(page)
        return True
    except Exception:
        return False


async def _settle(page: Any) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        pass


async def drive_login(
    page: Any, sensitive_data: Mapping[str, str], patterns: Sequence[str]
) -> LoginInspection:
    """Advance the login flow deterministically as far as safely possible.

    Handles email-first, one-page email+password, and password-after-email.
    Credentials are only ever filled when the origin is approved and the form is
    unambiguous. OTP / magic-link / account-selection / CAPTCHA are left to the
    caller (they need a human or the trusted Gmail worker). Returns the login
    inspection AFTER attempting to advance.
    """

    email = sensitive_data.get("login_email") or sensitive_data.get("email")
    password = sensitive_data.get("login_password") or sensitive_data.get("password")

    inspection = await inspect_login(page, patterns)

    # One-page email + password.
    if inspection.state == "credentials_ready":
        if not await _origin_safe_and_unique(page, patterns):
            return LoginInspection(
                state="unknown",
                email_field=inspection.email_field,
                password_field=inspection.password_field,
                otp_fields=(),
                submit_control=inspection.submit_control,
                current_url=getattr(page, "url", "") or "https://unknown.invalid/",
                reason_code="login_origin_unsafe",
            )
        if email:
            await _fill_first(page, _EMAIL_SELECTOR, email)
        if password:
            await _fill_first(page, _PASSWORD_SELECTOR, password)
        await _click_submit(page)
        return await inspect_login(page, patterns)

    # Email-first: submit the email, then handle the resulting password page.
    if inspection.state == "email_required":
        if email:
            await _fill_first(page, _EMAIL_SELECTOR, email)
            await _click_email_continue(page)
            after = await inspect_login(page, patterns)
            if after.state == "password_required" and password:
                if not await _origin_safe_and_unique(page, patterns):
                    return after
                await _fill_first(page, _PASSWORD_SELECTOR, password)
                await _click_submit(page)
                return await inspect_login(page, patterns)
            return after
        return inspection

    # Password page (email already submitted earlier).
    if inspection.state == "password_required":
        if password and await _origin_safe_and_unique(page, patterns):
            await _fill_first(page, _PASSWORD_SELECTOR, password)
            await _click_submit(page)
            return await inspect_login(page, patterns)
        return inspection

    return inspection


async def inject_otp(page: Any, value: str, inspection: LoginInspection) -> bool:
    """Fill an OTP by code — one whole-code field, or per-character fields.

    The OTP value is never logged, never sent to an LLM, and is not retained. A
    numeric or alphanumeric code is supported. Returns True when the code was
    entered and submitted.
    """

    if not value or not inspection.otp_fields:
        return False
    try:
        single = page.locator(_OTP_SELECTOR)
        count = int(await single.count())
    except Exception:
        return False

    # Per-character fields: as many single-maxlength inputs as code characters.
    if count >= len(value) and count > 1:
        per_char = True
        for index in range(len(value)):
            field = single.nth(index)
            try:
                maxlength = await field.get_attribute("maxlength", timeout=1_000)
            except Exception:
                maxlength = None
            if maxlength not in ("1", None):
                per_char = False
                break
        if per_char:
            ok = True
            for index, char in enumerate(value):
                try:
                    await single.nth(index).fill(char, timeout=3_000)
                except Exception:
                    ok = False
                    break
            if ok:
                await _submit_otp(page)
                return True

    # Single field holding the whole code.
    try:
        await single.first.fill(value, timeout=3_000)
    except Exception:
        return False
    await _submit_otp(page)
    return True


async def _submit_otp(page: Any) -> None:
    try:
        locator = page.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
        else:
            await page.locator(_OTP_SELECTOR).first.press("Enter", timeout=5_000)
    except Exception:
        pass
    await _settle(page)


def normalize_resume_signal(signal: str | None) -> ResumeSignal | None:
    """Return a recognized resume signal, or None to fail closed on unknown input."""

    if not signal:
        return None
    normalized = signal.strip().casefold()
    if normalized in _RESUME_SIGNALS:
        return normalized  # type: ignore[return-value]
    return None


def magic_link_is_safe(url: str, patterns: Sequence[str]) -> bool:
    """A magic/sign-in link may be opened only when HTTPS and on a reviewed host."""

    from ops.playwright_worker import navigation_allowed

    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return navigation_allowed(url, tuple(patterns))


__all__ = [
    "LoginInspection",
    "LoginState",
    "ResumeSignal",
    "drive_login",
    "inject_otp",
    "inspect_login",
    "magic_link_is_safe",
    "normalize_resume_signal",
]
