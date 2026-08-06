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

The second half of the file drives a *phase* rather than a page: the onboarding
login route (design "Sequence Diagram 3"). It hands the worker vault
*references* plus one transient grant each, so plaintext resolves inside the
browser process only, and it returns a phase step the driver commits — see the
section banner further down.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Protocol
from urllib.parse import urlsplit

from ops.browser.candidates import ElementIdentity
from ops.browser.worker import HumanActionType
from ops.core.secret_store import parse_vault_reference
from ops.onboarding.admission import REQUIRED_LOGIN_FIELDS, AdmissionDecision
from ops.onboarding.driver import OnboardingDeps, PhaseNotDrivable, PhaseStep
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode

if TYPE_CHECKING:  # imported for typing only; the driver never imports this module
    from ops.onboarding.lease import Lease
    from ops.providers.profile import ProviderProfile

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
    "input[autocomplete='username'], input[autocomplete='email'], "
    "input[name='login' i], input[id='email' i], input[id='username' i]"
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
# Playwright's ``:has-text()`` is a SUBSTRING match, so ``button:has-text('Continue')``
# in _SUBMIT_SELECTOR also matches "Continue with GitHub" and "Continue with Google".
# Login pages routinely place those federated buttons ABOVE the email form, so
# clicking the first match sent the run to a third-party identity provider instead of
# submitting the credential the owner supplied. A control naming a provider is never
# the form's own submit control; the ladder reaches an identity provider through the
# reviewed handoff path, never by a click chosen here.
_FEDERATED_CONTROL = re.compile(
    r"(?i)\b(google|github|gitlab|bitbucket|microsoft|azure|apple|facebook|meta|"
    r"linkedin|twitter|okta|auth0|saml|sso|single sign|slack|salesforce)\b"
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

    from ops.browser.host_policy import host_matches_patterns
    from ops.browser.snapshot import frame_chain, frame_host

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


async def _form_action_is_safe(target: Any, patterns: Sequence[str], *, field: str) -> bool:
    """False when the form enclosing ``field`` posts to an off-allowlist host.

    A relative or absent action posts back to the current (already reviewed) origin,
    so only an absolute http(s) action is checked.
    """

    from ops.playwright.worker import navigation_allowed

    try:
        action = await target.locator(f"form:has({field})").first.get_attribute(
            "action", timeout=2_000
        )
    except Exception:
        return True
    if isinstance(action, str) and action.casefold().startswith(("http://", "https://")):
        return navigation_allowed(action, tuple(patterns))
    return True


async def _email_origin_is_safe(page: Any, patterns: Sequence[str], surface: Any) -> bool:
    """The email-first equivalent of :func:`_origin_safe_and_unique`.

    An email-first page has no password field yet, so the password-uniqueness rule
    cannot apply — but the page origin and the form's post target still must, because
    an email address is account data. This path previously typed the owner's email
    with no origin or action check at all.
    """

    from ops.playwright.worker import navigation_allowed

    if not navigation_allowed(getattr(page, "url", "") or "", tuple(patterns)):
        return False
    return await _form_action_is_safe(surface, patterns, field=_EMAIL_SELECTOR)


async def _origin_safe_and_unique(page: Any, patterns: Sequence[str], surface: Any = None) -> bool:
    """Credentials may be filled only on an approved origin with a single form.

    ``surface`` is the resolved frame the form lives in (defaults to the page). The
    page's own URL is still validated, so a reviewed iframe on an unreviewed page
    is refused.
    """

    from ops.playwright.worker import navigation_allowed

    target = surface if surface is not None else page
    if not navigation_allowed(getattr(page, "url", "") or "", tuple(patterns)):
        return False
    if await _count_visible_enabled(target, _PASSWORD_SELECTOR) != 1:
        return False
    return await _form_action_is_safe(target, patterns, field=_PASSWORD_SELECTOR)


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


async def _control_label(control: Any) -> str:
    """The visible label of a control, for ``input[type=submit]`` too.

    An ``<input type=submit>`` has no text content — its label is the ``value``
    attribute — so reading only ``inner_text`` would classify every one of them as
    unlabelled and defeat the federated-control check.
    """

    for reader in ("inner_text", "get_attribute"):
        try:
            if reader == "inner_text":
                text = await control.inner_text(timeout=1_000)
            else:
                text = await control.get_attribute("value", timeout=1_000)
        except Exception:
            continue
        if isinstance(text, str) and text.strip():
            return text.strip()[:200]
    try:
        label = await control.get_attribute("aria-label", timeout=1_000)
    except Exception:
        return ""
    return label.strip()[:200] if isinstance(label, str) else ""


async def _click_own_submit(surface: Any, *, limit: int = 8) -> bool:
    """Click the form's OWN submit control, skipping federated sign-in buttons.

    Every candidate is checked for visible+enabled and for a provider name before it
    is clicked, rather than taking ``.first`` in DOM order. That ordering is exactly
    what broke: the federated buttons are usually rendered above the email form.
    """

    try:
        locator = surface.locator(_SUBMIT_SELECTOR)
        total = min(int(await locator.count()), limit)
    except Exception:
        return False
    for index in range(total):
        control = locator.nth(index)
        try:
            if not (await control.is_visible() and await control.is_enabled()):
                continue
        except Exception:
            continue
        if _FEDERATED_CONTROL.search(await _control_label(control)):
            continue
        try:
            await control.click(timeout=5_000)
        except Exception:
            continue
        await _settle(surface)
        return True
    return False


async def _press_enter(surface: Any, selector: str) -> bool:
    try:
        await surface.locator(selector).first.press("Enter", timeout=5_000)
    except Exception:
        return False
    await _settle(surface)
    return True


async def _click_submit(surface: Any) -> bool:
    if await _click_own_submit(surface):
        return True
    return await _press_enter(surface, _PASSWORD_SELECTOR)


async def _click_email_continue(surface: Any) -> bool:
    if await _click_own_submit(surface):
        return True
    return await _press_enter(surface, _EMAIL_SELECTOR)


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

    def _refused(reason: str, source: LoginInspection = inspection) -> LoginInspection:
        return LoginInspection(
            state="unknown",
            email_field=source.email_field,
            password_field=source.password_field,
            otp_fields=(),
            submit_control=source.submit_control,
            current_url=getattr(page, "url", "") or "https://unknown.invalid/",
            reason_code=reason,
            frame_path=source.frame_path,
        )

    # One-page email + password.
    if inspection.state == "credentials_ready":
        if not await _origin_safe_and_unique(page, patterns, surface):
            return _refused("login_origin_unsafe")
        # A fill that silently failed used to be followed by a submit anyway, so the
        # site rejected a blank field and the run reported "verification required" —
        # a wrong reason that sent the owner looking for a device prompt that was
        # never there. An unfilled field is its own, nameable outcome.
        if email and not await _fill_first(surface, _EMAIL_SELECTOR, email):
            return _refused("login_email_fill_failed")
        if password and not await _fill_first(surface, _PASSWORD_SELECTOR, password):
            return _refused("login_password_fill_failed")
        submitted = await _click_submit(surface)
        if not submitted:
            return _refused("login_submit_control_not_found")
        return await inspect_after_login_submit(
            page, previous="credentials_ready", patterns=patterns
        )

    # Email-first: submit the email, then handle the resulting password page.
    if inspection.state == "email_required":
        if email:
            if not await _email_origin_is_safe(page, patterns, surface):
                return _refused("login_origin_unsafe")
            if not await _fill_first(surface, _EMAIL_SELECTOR, email):
                return _refused("login_email_fill_failed")
            submitted = await _click_email_continue(surface)
            if not submitted:
                return _refused("login_submit_control_not_found")
            after = await inspect_after_login_submit(
                page, previous="email_required", patterns=patterns
            )
            next_surface = resolve_reviewed_frame(page, after.frame_path, patterns)
            if after.state == "password_required" and password and next_surface is not None:
                if not await _origin_safe_and_unique(page, patterns, next_surface):
                    return _refused("login_origin_unsafe", after)
                if not await _fill_first(next_surface, _PASSWORD_SELECTOR, password):
                    return _refused("login_password_fill_failed", after)
                submitted = await _click_submit(next_surface)
                if not submitted:
                    return _refused("login_submit_control_not_found", after)
                return await inspect_after_login_submit(
                    page, previous="password_required", patterns=patterns
                )
            return after
        return inspection

    # Password page (email already submitted earlier).
    if inspection.state == "password_required":
        if password:
            if not await _origin_safe_and_unique(page, patterns, surface):
                return _refused("login_origin_unsafe")
            if not await _fill_first(surface, _PASSWORD_SELECTOR, password):
                return _refused("login_password_fill_failed")
            submitted = await _click_submit(surface)
            if not submitted:
                return _refused("login_submit_control_not_found")
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

    from ops.playwright.worker import navigation_allowed

    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return navigation_allowed(url, tuple(patterns))


# --- the onboarding login route ---------------------------------------------
#
# Everything above drives a page. Everything below drives a *phase*: it is the
# ``route_selected_login`` handler the onboarding phase driver dispatches to
# (design "Sequence Diagram 3"), and it never touches a page itself.
#
# Three properties are the reason it looks the way it does.
#
# The orchestrator holds references, never values (Requirement 8.1). The
# handler reads the admission decision's ``credential_refs`` — already in the
# ``vault://app/kind/id`` grammar — mints exactly one transient grant per
# reference through the broker's reservation verb, and hands reference + grant to
# the worker. There is no method here that could return plaintext: resolution
# happens inside the browser process, through the broker's ``consume`` verb
# (LL-2.5).
#
# The driver is the only committer (Requirement 12.9). This handler returns a
# :class:`~ops.onboarding.driver.PhaseStep` and writes nothing, so "commit
# ``authenticated`` on acceptance" is expressed as an *advancing step*.
#
# The account binding is the probed one (Requirement 8.8). The binding, the app
# slug, and the references all come from one read of the login context, and every
# reference is checked to name that same app slug — so a reference minted for
# another provider or another account cannot be handed to the worker.

# The one mid-flight gate an operator is ever prompted for; every other gate type
# is the gate-resolution seam's business (Requirements 8.7, 11.1).
CAPTCHA_GATE: HumanActionType = "captcha"

# The broker action a login reference is granted under. Login reads; it captures
# nothing, so the capture verb never appears on this path.
LOGIN_GRANT_ACTION: Literal["consume"] = "consume"

# The reason code an accepted login carries into ``authenticated``. The login
# route exists because the vault already held this account's credentials, and
# that is the fact the boundary records — the same code the admission decision
# carries, so the two halves of one autonomous route read as one thread.
LOGIN_ACCEPTED: OnboardingReasonCode = "credentials_present"

# How long a login grant may be redeemed for. One form fill, so the shortest
# value the vault admits is enough; the broker refuses anything under 30 s.
DEFAULT_LOGIN_GRANT_TTL_SECONDS = 300

# How long a run waits before re-entering the login phase after the seam resolved
# a gate. A deferral, not a sleep: the driver re-queues the run and the session
# stays bound, so the retry continues on the same page.
DEFAULT_GATE_RETRY_SECONDS = 5


@dataclass(frozen=True, slots=True)
class LoginGrant:
    """One reference the worker may resolve exactly once, inside its own process.

    Carries no value and cannot carry one: ``reference`` names a vault row and
    ``grant`` is the opaque bearer that authorizes a single ``consume`` of it.
    """

    field: str  # login_email | login_password
    reference: str
    kind: str  # the reference's vault kind, e.g. account_login_password
    grant: str


@dataclass(frozen=True, slots=True)
class LoginRouteContext:
    """The durable facts one login attempt is driven from.

    ``decision`` is the recorded admission decision, so the references and the
    route come from the same row an operator (or the vault probe) produced.
    ``account_ref`` is the binding that probe used, and the handler drives under
    it rather than re-deriving one (Requirement 8.8).
    """

    decision: AdmissionDecision
    session_id: str
    app_slug: str
    account_ref: str
    effect_identity: str


@dataclass(frozen=True, slots=True)
class LoginObservation:
    """What the worker saw after submitting the login.

    ``gate_type`` is a typed gate or ``None``; page text never reaches here.
    ``reason_code`` is only read when the attempt neither succeeded nor named a
    gate, which is the "nothing provable happened" case.
    """

    accepted: bool
    gate_type: HumanActionType | None = None
    reason_code: OnboardingReasonCode = "postcondition_failed"


@dataclass(frozen=True, slots=True)
class GateDisposition:
    """The gate-resolution seam's answer for one non-CAPTCHA gate.

    ``resolved`` means the gate is gone and the phase may be re-driven on the
    same session. Otherwise ``reason_code`` is the pause the run takes, drawn
    from the closed onboarding vocabulary so no seam can invent one.
    """

    resolved: bool
    reason_code: OnboardingReasonCode


class LoginRouteContextStore(Protocol):
    """Where the handler reads the run's admission decision and session binding."""

    def login_context(self, *, run_id: str) -> LoginRouteContext | None:
        """The login context for ``run_id``, or ``None`` when there is none."""


class LoginGrantBroker(Protocol):
    """The broker's grant *reservation* verb, and deliberately nothing else.

    Satisfied structurally by ``ops.core.secret_store.SQLiteSecretStore``. There is no
    read here, so the orchestrator side of the broker cannot resolve a value even
    by mistake.
    """

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        """Reserve one exact broker operation and return its opaque grant.

        POST: deterministic in ``operation_key``, so a retry that derives the same
              key redeems the same grant rather than minting a second one.
        """


class LoginRouteWorker(Protocol):
    """The trusted browser worker that fills and submits the login form."""

    async def submit_login(
        self,
        *,
        run_id: str,
        session_id: str,
        account_ref: str,
        grants: Sequence[LoginGrant],
    ) -> LoginObservation:
        """Fill the login form from ``grants`` and report what the provider did.

        PRE:  each grant authorizes exactly one ``consume`` for this run and this
              session.
        POST: no credential value crosses back — the return carries an acceptance
              flag, an optional typed gate, and a closed reason code.
        """


class GateResolutionSeam(Protocol):
    """The seam owned by the ``autonomous-gate-resolution`` spec (Requirement 8.7).

    Consumed here, never reimplemented: this module classifies a gate as
    "not CAPTCHA" and hands the disposition question over.
    """

    async def dispose(
        self,
        *,
        run_id: str,
        session_id: str,
        gate_type: HumanActionType,
        account_ref: str,
    ) -> GateDisposition:
        """Decide what happens to one non-CAPTCHA gate."""


def login_grants(
    context: LoginRouteContext,
    *,
    broker: LoginGrantBroker,
    ttl_seconds: int = DEFAULT_LOGIN_GRANT_TTL_SECONDS,
) -> tuple[LoginGrant, ...]:
    """Mint one transient grant per login reference, in a deterministic order.

    PRE:  ``context.decision`` routes to login and carries a reference for every
          field in :data:`~ops.onboarding.admission.REQUIRED_LOGIN_FIELDS`.
    POST: one grant per required field, ordered by field name so two workers
          driving the same attempt derive the same operation keys. Every
          reference is parsed and must name ``context.app_slug``; anything else
          raises, because a reference for another provider is not a login this
          run may attempt (Requirement 8.8).

    Nothing here resolves a reference. The grant is a bearer for the worker's own
    ``consume`` call, so plaintext appears only inside the browser process
    (Requirement 8.1, LL-2.5).
    """

    references = dict(context.decision.credential_refs)
    missing = sorted(REQUIRED_LOGIN_FIELDS - set(references))
    if missing:
        raise ValueError("login route requires a reference for every login field")
    grants: list[LoginGrant] = []
    for field in sorted(REQUIRED_LOGIN_FIELDS):
        reference = references[field]
        parts = parse_vault_reference(reference)
        if parts.app_slug != context.app_slug:
            raise ValueError("a login reference must name the run's provider")
        grants.append(
            LoginGrant(
                field=field,
                reference=reference,
                kind=parts.kind,
                grant=broker.reserve_browser_secret_grant(
                    operation_key=f"{context.effect_identity}:{LOGIN_GRANT_ACTION}:{field}",
                    run_id=context.decision.run_id,
                    session_id=context.session_id,
                    app_slug=context.app_slug,
                    kind=parts.kind,
                    action=LOGIN_GRANT_ACTION,
                    reference=reference,
                    ttl_seconds=ttl_seconds,
                ),
            )
        )
    return tuple(grants)


def step_for_login_observation(observation: LoginObservation) -> PhaseStep | None:
    """Map an observation onto a step, or ``None`` when a gate must be disposed.

    Three of the four outcomes are decided here. Acceptance advances into
    ``authenticated`` (Requirement 8.6); a CAPTCHA advances into
    ``captcha_paused``, the one mid-flight prompt that exists; an attempt that
    neither succeeded nor named a gate pauses with the code the worker reported.
    A non-CAPTCHA gate returns ``None``, which is this function saying *not mine*
    — the seam decides (Requirement 8.7).
    """

    if observation.accepted:
        return PhaseStep.advance("authenticated", LOGIN_ACCEPTED)
    if observation.gate_type == CAPTCHA_GATE:
        return PhaseStep.advance("captcha_paused", "captcha_detected")
    if observation.gate_type is not None:
        return None
    return PhaseStep.pause(observation.reason_code)


class LoginRouteHandler:
    """The ``route_selected_login`` phase handler (Requirements 8.1, 8.6 - 8.8).

    A :class:`~ops.onboarding.driver.PhaseHandler`: it drives one login attempt
    and returns the transition it wants, which the driver alone commits.
    """

    def __init__(
        self,
        *,
        context: LoginRouteContextStore,
        broker: LoginGrantBroker,
        worker: LoginRouteWorker,
        gates: GateResolutionSeam,
        grant_ttl_seconds: int = DEFAULT_LOGIN_GRANT_TTL_SECONDS,
        gate_retry_seconds: int = DEFAULT_GATE_RETRY_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._context = context
        self._broker = broker
        self._worker = worker
        self._gates = gates
        self._grant_ttl_seconds = grant_ttl_seconds
        self._gate_retry_seconds = gate_retry_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Drive the login route once and report what should happen to the phase.

        POST: an accepted login returns an advancing step into ``authenticated``;
              a CAPTCHA returns one into ``captcha_paused``; any other gate is
              delegated to the seam, which either clears it (a deferral, so the
              phase is re-entered on the same session with nothing committed) or
              names the pause. Nothing is committed here, and no credential value
              is read, held, or returned.
        """

        del profile, lease, deps  # the login route needs neither the goal nor the ledger
        context = self._context.login_context(run_id=run_id)
        if context is None or context.decision.route != "login":
            # A wiring error rather than a run outcome: this handler is reachable
            # only for a run the admission service routed to login.
            raise PhaseNotDrivable(phase, "the run has no recorded login admission decision")

        grants = login_grants(context, broker=self._broker, ttl_seconds=self._grant_ttl_seconds)
        observation = await self._worker.submit_login(
            run_id=run_id,
            session_id=context.session_id,
            account_ref=context.account_ref,
            grants=grants,
        )
        step = step_for_login_observation(observation)
        if step is not None:
            return step

        gate_type = observation.gate_type
        assert gate_type is not None  # step_for_login_observation returned None
        disposition = await self._gates.dispose(
            run_id=run_id,
            session_id=context.session_id,
            gate_type=gate_type,
            account_ref=context.account_ref,
        )
        if disposition.resolved:
            return PhaseStep.defer(self._retry_at(), disposition.reason_code)
        return PhaseStep.pause(disposition.reason_code)

    def _retry_at(self) -> str:
        """When a run whose gate the seam cleared becomes ready again."""

        moment = self._clock().astimezone(UTC).replace(microsecond=0)
        ready = moment + timedelta(seconds=max(self._gate_retry_seconds, 0))
        return ready.isoformat().replace("+00:00", "Z")


__all__ = [
    "CAPTCHA_GATE",
    "DEFAULT_GATE_RETRY_SECONDS",
    "DEFAULT_LOGIN_GRANT_TTL_SECONDS",
    "LOGIN_ACCEPTED",
    "LOGIN_GRANT_ACTION",
    "GateDisposition",
    "GateResolutionSeam",
    "LoginGrant",
    "LoginGrantBroker",
    "LoginInspection",
    "LoginObservation",
    "LoginRouteContext",
    "LoginRouteContextStore",
    "LoginRouteHandler",
    "LoginRouteWorker",
    "LoginState",
    "LoginSurface",
    "ResumeSignal",
    "apply_resume_secrets",
    "drive_login",
    "inject_otp",
    "inspect_after_login_submit",
    "inspect_login",
    "login_grants",
    "magic_link_is_safe",
    "normalize_resume_signal",
    "resolve_reviewed_frame",
    "reviewed_login_surfaces",
    "step_for_login_observation",
    "visible_login_challenge",
    "wait_for_login_state_change",
]
