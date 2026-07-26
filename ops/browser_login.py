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
from dataclasses import dataclass, replace
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
# Backward-compatible aliases. The public resume endpoint defaults to "completed",
# so without this mapping every existing caller's resume failed closed on the
# Playwright path while working fine on Browser Use.
_RESUME_ALIASES: dict[str, str] = {"completed": "human_completed"}


@dataclass(frozen=True, slots=True)
class LoginSurface:
    """Where the login form actually lives.

    A login form inside an iframe cannot be reached with ``page.locator(...)``,
    which only searches the main frame. Carrying the resolved frame (plus its
    reviewed host chain) is what lets the state machine fill the RIGHT surface
    instead of silently finding nothing.
    """

    frame_path: tuple[str, ...]
    frame_url: str
    frame: Any

    @property
    def is_main_frame(self) -> bool:
        return not self.frame_path


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
    # The reviewed frame the form was found in; () means the main frame. Defaulted
    # so existing constructions keep working unchanged.
    frame_path: tuple[str, ...] = ()


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
_CHALLENGE_IFRAME_SELECTOR = (
    "iframe[src*='recaptcha' i], iframe[title*='recaptcha' i], "
    "iframe[src*='hcaptcha' i], iframe[title*='hcaptcha' i]"
)
_ACTIVE_CHALLENGE_IFRAME = re.compile(
    r"(?i)(?:/bframe(?:[/?#]|$)|challenge|checkbox|i'?m not a robot|are you human)"
)


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


def reviewed_login_surfaces(page: Any, patterns: Sequence[str]) -> list[LoginSurface]:
    """The main frame plus every REVIEWED child frame, as fillable surfaces.

    An unreviewed frame is excluded entirely: it is neither inspected nor filled,
    so a third-party login iframe can never receive a credential.
    """

    from ops.browser_host_policy import host_matches_patterns
    from ops.browser_snapshot import frame_chain, frame_host

    allow = tuple(patterns)
    surfaces: list[LoginSurface] = []
    try:
        frames = list(page.frames)
    except Exception:
        return [LoginSurface(frame_path=(), frame_url=getattr(page, "url", "") or "", frame=page)]

    for frame in frames:
        try:
            chain = frame_chain(frame)
        except Exception:
            continue
        if not chain:
            # The main frame; its own host is validated by the caller's guard.
            surfaces.append(
                LoginSurface(frame_path=(), frame_url=getattr(frame, "url", "") or "", frame=frame)
            )
            continue
        host = frame_host(frame)
        if not host or not host_matches_patterns(host, allow):
            continue  # unreviewed origin: never inspected, never filled
        surfaces.append(
            LoginSurface(frame_path=chain, frame_url=getattr(frame, "url", "") or "", frame=frame)
        )
    if not surfaces:
        surfaces.append(
            LoginSurface(frame_path=(), frame_url=getattr(page, "url", "") or "", frame=page)
        )
    return surfaces


def resolve_reviewed_frame(
    page: Any, frame_path: Sequence[str], patterns: Sequence[str]
) -> Any | None:
    """Re-resolve the surface identified by ``frame_path``, or None.

    Called immediately before filling, so the frame is verified reviewed at the
    moment of use rather than only at inspection time.
    """

    target = tuple(frame_path)
    for surface in reviewed_login_surfaces(page, patterns):
        if surface.frame_path == target:
            return surface.frame
    return None


async def _inspect_surface(surface: Any, url: str) -> tuple[LoginState, str, dict[str, Any]]:
    """Classify ONE surface. Returns (state, reason, identity fields)."""

    email_n = await _count_visible_enabled(surface, _EMAIL_SELECTOR)
    password_n = await _count_visible_enabled(surface, _PASSWORD_SELECTOR)
    otp_n = await _count_visible_enabled(surface, _OTP_SELECTOR)
    body = await _visible_body_text(surface)

    email_field = await _first_identity(surface, _EMAIL_SELECTOR, "input") if email_n else None
    password_field = (
        await _first_identity(surface, _PASSWORD_SELECTOR, "input") if password_n else None
    )
    submit_control = await _first_identity(surface, _SUBMIT_SELECTOR, "button")

    otp_fields: tuple[ElementIdentity, ...] = ()
    if otp_n and password_n == 0:  # an OTP field on a surface WITHOUT a password field
        ident = await _first_identity(surface, _OTP_SELECTOR, "input")
        otp_fields = (ident,) if ident is not None else ()

    account_choice = await _count_visible_enabled(surface, _ACCOUNT_CHOICE_SELECTOR)
    fields = {
        "email_field": email_field,
        "password_field": password_field,
        "otp_fields": otp_fields,
        "submit_control": submit_control,
    }

    if password_n > 1:
        return "unknown", "multiple_password_forms", fields
    if _AUTH_FAIL.search(body) and (password_n or email_n):
        return "authentication_failed", "authentication_failed", fields
    if otp_fields:
        return "otp_required", "otp_required", fields
    if account_choice and password_n == 0 and email_n == 0:
        return "account_selection_required", "account_selection_required", fields
    if password_n == 0 and email_n == 0 and _MAGIC_LINK.search(body):
        return "magic_link_required", "magic_link_required", fields
    if email_n >= 1 and password_n >= 1:
        return "credentials_ready", "credentials_ready", fields
    if password_n >= 1:
        return "password_required", "password_required", fields
    if email_n >= 1:
        return "email_required", "email_required", fields
    del url  # kept for signature symmetry; the caller owns URL-based reasoning
    return "unknown", "no_recognized_login_surface", fields


# Login states that mean "a form is present here", used to detect ambiguity across
# multiple reviewed surfaces.
_FORM_STATES: frozenset[str] = frozenset(
    {"credentials_ready", "password_required", "email_required", "otp_required"}
)

# Reasons that classify a surface DEFINITIVELY even though the state is "unknown".
# Without this, an ambiguity finding was overwritten by the generic no-surface
# fallback and the operator lost the actual explanation.
_DEFINITE_UNKNOWN_REASONS: frozenset[str] = frozenset({"multiple_password_forms"})


async def inspect_login(page: Any, patterns: Sequence[str]) -> LoginInspection:
    """Deterministically classify the current login surface.

    Never types anything; only observes structure (visible/enabled fields) and a
    bounded slice of body text for failure/magic-link detection.

    Searches the main frame AND reviewed child frames, because a login form inside
    an iframe is invisible to ``page.locator(...)``. When more than one reviewed
    surface exposes a form the result is ``multiple_login_surfaces`` — ambiguity is
    escalated, never guessed.
    """

    url = getattr(page, "url", "") or "https://unknown.invalid/"
    surfaces = reviewed_login_surfaces(page, patterns)

    findings: list[tuple[LoginSurface, LoginState, str, dict[str, Any]]] = []
    for surface in surfaces:
        state, reason, fields = await _inspect_surface(surface.frame, url)
        findings.append((surface, state, reason, fields))

    with_forms = [item for item in findings if item[1] in _FORM_STATES]
    if len(with_forms) > 1:
        # Two reviewed surfaces both offering a login form: a human must choose.
        return LoginInspection(
            state="unknown",
            email_field=None,
            password_field=None,
            otp_fields=(),
            submit_control=None,
            current_url=url,
            reason_code="multiple_login_surfaces",
        )

    def _build(
        surface: LoginSurface, state: LoginState, reason: str, fields: dict[str, Any]
    ) -> LoginInspection:
        return LoginInspection(
            state=state,
            email_field=fields["email_field"],
            password_field=fields["password_field"],
            otp_fields=fields["otp_fields"],
            submit_control=fields["submit_control"],
            current_url=url,
            reason_code=reason,
            frame_path=surface.frame_path,
        )

    if with_forms:
        return _build(*with_forms[0])

    # An ambiguous surface (e.g. two password forms) is a DEFINITE finding even
    # though its state is "unknown": its reason code must survive rather than being
    # replaced by the generic no-surface fallback below.
    for surface, state, reason, fields in findings:
        if reason in _DEFINITE_UNKNOWN_REASONS:
            return _build(surface, state, reason, fields)

    # No form anywhere. Prefer a definite non-form classification from any surface
    # (auth failure, magic link, account selection) before falling back.
    for surface, state, reason, fields in findings:
        if state != "unknown":
            return _build(surface, state, reason, fields)

    main = findings[0] if findings else None
    fallback_fields: dict[str, Any] = {
        "email_field": None,
        "password_field": None,
        "otp_fields": (),
        "submit_control": None,
    }
    # NOT "authenticated": the absence of login controls is not evidence of a
    # successful login — an error page, a loading skeleton or a blank page all look
    # like this. `authenticated` must come from a reviewed checkpoint predicate.
    return _build(
        main[0] if main else LoginSurface(frame_path=(), frame_url=url, frame=page),
        "unknown",
        "no_recognized_login_surface",
        main[3] if main else fallback_fields,
    )


async def _origin_safe_and_unique(page: Any, patterns: Sequence[str], surface: Any = None) -> bool:
    """Credentials may be filled only on an approved origin with a single form.

    ``surface`` is the resolved frame the form lives in (defaults to the page). The
    page's own URL is still validated, so a reviewed iframe on an unreviewed page
    is refused.
    """

    from ops.playwright_worker import navigation_allowed

    target = surface if surface is not None else page
    if not navigation_allowed(getattr(page, "url", "") or "", tuple(patterns)):
        return False
    if await _count_visible_enabled(target, _PASSWORD_SELECTOR) != 1:
        return False
    try:
        action = await target.locator("form:has(input[type='password'])").first.get_attribute(
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


async def _click_submit(surface: Any) -> bool:
    try:
        locator = surface.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
            await _settle(surface)
            return True
    except Exception:
        pass
    try:
        await surface.locator(_PASSWORD_SELECTOR).first.press("Enter", timeout=5_000)
        await _settle(surface)
        return True
    except Exception:
        return False


async def _click_email_continue(surface: Any) -> bool:
    try:
        locator = surface.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
            await _settle(surface)
            return True
    except Exception:
        pass
    try:
        await surface.locator(_EMAIL_SELECTOR).first.press("Enter", timeout=5_000)
        await _settle(surface)
        return True
    except Exception:
        return False


async def _settle(surface: Any) -> None:
    """Wait for the DOM to be ready — deliberately NOT ``networkidle``.

    A site with a persistent WebSocket or a background poll may never reach network
    idle, so using it as a generic settle condition stalls the whole login for the
    full timeout. ``domcontentloaded`` plus Playwright's own auto-waiting on the
    next action is both faster and correct; callers that need a specific transition
    use :func:`wait_for_login_state_change`.
    """

    try:
        await surface.wait_for_load_state("domcontentloaded", timeout=5_000)
    except Exception:
        pass


async def wait_for_login_state_change(
    page: Any,
    *,
    previous: LoginState,
    patterns: Sequence[str],
    timeout_seconds: float = 10.0,
) -> LoginInspection:
    """Poll the login state until it leaves ``previous`` or the budget expires.

    Waits for an OBSERVED state transition rather than a network condition, so it
    works on sites that never go idle. Bounded, and never a fixed sleep — the
    interval only yields control between structural inspections.
    """

    import asyncio

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.5, timeout_seconds)
    while loop.time() < deadline:
        current = await inspect_login(page, patterns)
        if current.state != previous:
            return current
        await asyncio.sleep(0.1)
    return await inspect_login(page, patterns)


async def visible_login_challenge(page: Any) -> bool:
    """Whether an actual CAPTCHA challenge frame is visible right now.

    Passive badges and hidden response controls are deliberately ignored; a
    challenge is a human gate only when its iframe is visibly presented.
    """

    try:
        locator = page.locator(_CHALLENGE_IFRAME_SELECTOR)
        count = min(int(await locator.count()), 8)
    except Exception:
        return False
    for index in range(count):
        try:
            frame = locator.nth(index)
            if not await frame.is_visible():
                continue
            title = (await frame.get_attribute("title", timeout=1_000)) or ""
            source = (await frame.get_attribute("src", timeout=1_000)) or ""
            metadata = f"{title} {source}"
            visible_anchor = (
                "/anchor" in source.casefold()
                and re.search(r"(?i)(?:[?&])size=invisible(?:[&#]|$)", source) is None
            )
            if visible_anchor or _ACTIVE_CHALLENGE_IFRAME.search(metadata):
                return True
        except Exception:
            continue
    return False


async def inspect_after_login_submit(
    page: Any,
    *,
    previous: LoginState,
    patterns: Sequence[str],
    timeout_seconds: float = 20.0,
) -> LoginInspection:
    """Wait for a submitted login to change, then classify any visible gate."""

    result = await wait_for_login_state_change(
        page,
        previous=previous,
        patterns=patterns,
        timeout_seconds=timeout_seconds,
    )
    # Preserve every explicit result (wrong password, OTP, account selection,
    # magic link, or an email-first password step). A no-surface result can still
    # be a visible challenge whose form was hidden by the provider overlay.
    if result.state != previous and result.reason_code != "no_recognized_login_surface":
        return result
    if await visible_login_challenge(page):
        return replace(result, state="unknown", reason_code="captcha_required")
    if result.state != previous:
        return result
    # No explicit bad-credential evidence appeared. On a new device this may be a
    # risk decision or delayed provider verification, so escalate rather than lie.
    return replace(result, state="unknown", reason_code="login_verification_required")


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

    # Resolve the REVIEWED surface the form lives in. All fills go through this,
    # so an iframe login form is actually reachable — and an unreviewed frame is
    # never resolved in the first place.
    surface = resolve_reviewed_frame(page, inspection.frame_path, patterns)
    if surface is None:
        return LoginInspection(
            state="unknown",
            email_field=None,
            password_field=None,
            otp_fields=(),
            submit_control=None,
            current_url=getattr(page, "url", "") or "https://unknown.invalid/",
            reason_code="login_frame_unreviewed",
            frame_path=inspection.frame_path,
        )

    # One-page email + password.
    if inspection.state == "credentials_ready":
        if not await _origin_safe_and_unique(page, patterns, surface):
            return LoginInspection(
                state="unknown",
                email_field=inspection.email_field,
                password_field=inspection.password_field,
                otp_fields=(),
                submit_control=inspection.submit_control,
                current_url=getattr(page, "url", "") or "https://unknown.invalid/",
                reason_code="login_origin_unsafe",
                frame_path=inspection.frame_path,
            )
        if email:
            await _fill_first(surface, _EMAIL_SELECTOR, email)
        if password:
            await _fill_first(surface, _PASSWORD_SELECTOR, password)
        submitted = await _click_submit(surface)
        if not submitted:
            return inspection
        return await inspect_after_login_submit(
            page, previous="credentials_ready", patterns=patterns
        )

    # Email-first: submit the email, then handle the resulting password page.
    if inspection.state == "email_required":
        if email:
            await _fill_first(surface, _EMAIL_SELECTOR, email)
            submitted = await _click_email_continue(surface)
            if not submitted:
                return inspection
            after = await inspect_after_login_submit(
                page, previous="email_required", patterns=patterns
            )
            next_surface = resolve_reviewed_frame(page, after.frame_path, patterns)
            if after.state == "password_required" and password and next_surface is not None:
                if not await _origin_safe_and_unique(page, patterns, next_surface):
                    return after
                await _fill_first(next_surface, _PASSWORD_SELECTOR, password)
                submitted = await _click_submit(next_surface)
                if not submitted:
                    return after
                return await inspect_after_login_submit(
                    page, previous="password_required", patterns=patterns
                )
            return after
        return inspection

    # Password page (email already submitted earlier).
    if inspection.state == "password_required":
        if password and await _origin_safe_and_unique(page, patterns, surface):
            await _fill_first(surface, _PASSWORD_SELECTOR, password)
            submitted = await _click_submit(surface)
            if not submitted:
                return inspection
            return await inspect_after_login_submit(
                page, previous="password_required", patterns=patterns
            )
        return inspection

    return inspection


async def inject_otp(
    page: Any, value: str, inspection: LoginInspection, patterns: Sequence[str] = ()
) -> bool:
    """Fill an OTP by code — one whole-code field, or per-character fields.

    The OTP value is never logged, never sent to an LLM, and is not retained. A
    numeric or alphanumeric code is supported. Returns True when the code was
    entered and submitted.

    Operates on the REVIEWED surface recorded in the inspection, so an OTP field
    inside a reviewed iframe is reachable. ``patterns`` is optional for backward
    compatibility: without it, only the main frame is used (Phase 1 behaviour).
    """

    if not value or not inspection.otp_fields:
        return False
    surface: Any = page
    if inspection.frame_path and patterns:
        resolved = resolve_reviewed_frame(page, inspection.frame_path, patterns)
        if resolved is None:
            return False  # never type an OTP into an unreviewed frame
        surface = resolved
    try:
        single = surface.locator(_OTP_SELECTOR)
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
                await _submit_otp(surface)
                return True

    # Single field holding the whole code.
    try:
        await single.first.fill(value, timeout=3_000)
    except Exception:
        return False
    await _submit_otp(surface)
    return True


async def _submit_otp(surface: Any) -> None:
    try:
        locator = surface.locator(_SUBMIT_SELECTOR)
        if int(await locator.count()) >= 1:
            await locator.first.click(timeout=5_000)
        else:
            await surface.locator(_OTP_SELECTOR).first.press("Enter", timeout=5_000)
    except Exception:
        pass
    await _settle(surface)


def normalize_resume_signal(signal: str | None) -> ResumeSignal | None:
    """Return a recognized resume signal, or None to fail closed on unknown input.

    ``completed`` is accepted as an alias for ``human_completed``: the public API's
    resume endpoint defaults to it, so without the alias every existing caller's
    resume was silently rejected by the Playwright path. Browser Use behaviour is
    untouched.
    """

    if not signal:
        return None
    normalized = signal.strip().casefold()
    if normalized in _RESUME_ALIASES:
        normalized = _RESUME_ALIASES[normalized]
    if normalized in _RESUME_SIGNALS:
        return normalized  # type: ignore[return-value]
    return None


async def apply_resume_secrets(
    *,
    page: Any,
    sensitive_data: Mapping[str, str],
    patterns: Sequence[str],
) -> LoginInspection:
    """Apply a resume-time secret (OTP or verification link), else drive login.

    This is the missing link that made autonomous OTP/magic-link resolution a
    no-op on the Playwright path: ``drive_login`` only ever reads email/password,
    so ``login_otp`` and ``login_verification_url`` were carried into the worker
    and then ignored.

    Both values are code-owned: they are used by deterministic Playwright calls,
    dropped immediately, and never enter a prompt, log, audit event, decision
    event, screenshot or run state.
    """

    inspection = await inspect_login(page, patterns)

    def _refused(reason: str) -> LoginInspection:
        return LoginInspection(
            state="unknown",
            email_field=inspection.email_field,
            password_field=inspection.password_field,
            otp_fields=inspection.otp_fields,
            submit_control=inspection.submit_control,
            current_url=getattr(page, "url", "") or "https://unknown.invalid/",
            reason_code=reason,
            frame_path=inspection.frame_path,
        )

    otp = sensitive_data.get("login_otp")
    if otp:
        # The OTP surface must be PROVEN, not assumed: typing a code into an
        # unverified page could send it somewhere it does not belong.
        if inspection.state != "otp_required":
            return _refused("otp_surface_not_verified")
        entered = await inject_otp(page, otp, inspection, patterns)
        del otp  # drop the value as soon as it has been used
        if not entered:
            return _refused("otp_injection_failed")
        return await inspect_login(page, patterns)

    verification_url = sensitive_data.get("login_verification_url")
    if verification_url:
        if not magic_link_is_safe(verification_url, patterns):
            return _refused("verification_link_blocked")
        try:
            await page.goto(verification_url, wait_until="domcontentloaded", timeout=15_000)
        except Exception:
            del verification_url
            return _refused("verification_link_navigation_failed")
        del verification_url
        return await inspect_login(page, patterns)

    return await drive_login(page, sensitive_data, patterns)


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
    "LoginSurface",
    "ResumeSignal",
    "apply_resume_secrets",
    "drive_login",
    "inject_otp",
    "inspect_after_login_submit",
    "inspect_login",
    "magic_link_is_safe",
    "normalize_resume_signal",
    "resolve_reviewed_frame",
    "reviewed_login_surfaces",
    "visible_login_challenge",
    "wait_for_login_state_change",
]
