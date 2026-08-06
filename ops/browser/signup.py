"""Deterministic, policy-bounded signup for the Playwright browser harness.

This module is deliberately not an autonomous form-filling agent.  It accepts
only four backend-approved, non-secret company fields and the existing
email/password secret channel. Generic signup locates one unambiguous form;
reviewed recipe metadata may instead authorize an exact email-first flow. Every
automatic form is submitted at most once per browser session.

No page text, field value, or secret is returned.  Legal consent, billing,
CAPTCHA, MFA, passkeys, and unknown required fields always stop at a typed human
gate.  The model is never involved in this path.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from time import monotonic
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol
from urllib.parse import urljoin, urlsplit

from ops.browser.login import inspect_login, reviewed_login_surfaces, visible_login_challenge
from ops.core.effect_ledger import EffectStore
from ops.email.verification import canonical_address
from ops.onboarding.driver import (
    DEFAULT_CAPTCHA_BUDGET,
    OnboardingDeps,
    PausedSession,
    PhaseHandler,
    PhaseStep,
    pause_for_captcha,
)
from ops.onboarding.effects import (
    EffectPlan,
    complete_effect,
    mark_effect_failed,
    mark_effect_outcome_unknown,
    plan_effect,
    signup_submit_key,
)
from ops.onboarding.lease import Lease
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.playwright.page_inspection import PageInspection, _page_url
from ops.playwright.predicates import predicate_satisfied
from ops.playwright.routing import navigation_allowed
from ops.providers.profile import ProviderProfile
from ops.recipes.app_recipes import get_app_recipe, recipe_predicate

if TYPE_CHECKING:
    from ops.browser.api_trace_catalog import CheckpointPredicate
    from ops.recipes.app_recipes import SignupPolicy

LOGGER = logging.getLogger("composio_ops.browser_signup")

SignupActionType = Literal[
    "captcha",
    "email_otp",
    "phone_otp",
    "passkey",
    "security_key",
    "provider_verification",
    "legal_acceptance",
    "billing",
    "account_selection",
]
SignupStatus = Literal["continue", "human_action_required", "failed"]
# The two step orderings this module can drive. A reviewed recipe names one of
# them directly; a researched route resolves to one by looking at the live form.
ResolvedSignupFlow = Literal["email_first", "email_password"]

# How long a researched route is given to DRAW its registration form before the
# absence of one is believed. Client-rendered consoles are the normal case, not
# the exception: Apify's sign-up form first appears between four and nine seconds
# after ``domcontentloaded``. Fifteen seconds clears the observed range with
# margin and still sits inside the ~30s per-step ceiling this harness works to.
# The cost of waiting is a slower pause; the cost of not waiting is a drivable
# signup handed to a human, which is the failure this whole path exists to avoid.
_SURFACE_RENDER_BUDGET_SECONDS: Final[float] = 15.0
_SURFACE_RENDER_POLL_SECONDS: Final[float] = 0.5

_APPROVED_FIELDS: dict[str, int] = {
    "company_name": 200,
    "company_website": 2_000,
    "use_case": 2_000,
    "expected_volume": 200,
}
_SAFE_TEXT = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$")

_EMAIL_SELECTOR = (
    "input[type='email'], input[autocomplete='email'], "
    "input[name='email' i], input[name='work_email' i], "
    "input[name='user_email' i], input[id='email' i], input[id='work_email' i]"
)
_PASSWORD_SELECTOR = "input[type='password']"
_COMPANY_SELECTORS: dict[str, str] = {
    "company_name": (
        "input[autocomplete='organization'], input[name='company' i], "
        "input[name='company_name' i], input[name='organization' i], "
        "input[name='organization_name' i], input[id='company' i], "
        "input[id='company_name' i], input[id='organization' i]"
    ),
    "company_website": (
        "input[autocomplete='url'], input[name='website' i], "
        "input[name='company_website' i], input[name='organization_url' i], "
        "input[id='website' i], input[id='company_website' i]"
    ),
    "use_case": (
        "textarea[name='use_case' i], textarea[name='description' i], "
        "textarea[id='use_case' i], textarea[id='description' i], "
        "input[name='use_case' i], input[id='use_case' i]"
    ),
    "expected_volume": (
        "input[name='expected_volume' i], input[name='monthly_volume' i], "
        "input[id='expected_volume' i], input[id='monthly_volume' i], "
        "select[name='expected_volume' i], select[name='monthly_volume' i]"
    ),
}
_SUBMIT_SELECTOR = (
    "button[type='submit'], input[type='submit'], "
    "button:has-text('Create account'), button:has-text('Create Account'), "
    "button:has-text('Sign up'), button:has-text('Sign Up'), "
    "button:has-text('Register'), button:has-text('Get started'), "
    "button:has-text('Get Started')"
)
_BILLING_SELECTOR = (
    "input[autocomplete^='cc-'], input[name*='card_number' i], "
    "input[name*='credit_card' i], input[name*='cvc' i], "
    "input[name*='billing' i], iframe[src*='stripe' i], "
    "iframe[src*='braintree' i]"
)
_OTP_SELECTOR = (
    "input[autocomplete='one-time-code'], input[name*='otp' i], "
    "input[id*='otp' i], input[name='verification_code' i], "
    "input[id='verification_code' i]"
)
_PHONE_OTP_SELECTOR = (
    "input[autocomplete='tel-national'], input[autocomplete='tel'], "
    "input[name='phone_otp' i], input[id='phone_otp' i]"
)
_PASSKEY_SELECTOR = (
    "button:has-text('Passkey'), button:has-text('Security key'), "
    "[role='button']:has-text('Passkey'), [role='button']:has-text('Security key')"
)
_LEGAL_WORDS = re.compile(
    r"(?i)\b(terms|privacy|legal|agreement|consent|agree|policy|conditions)\b"
)
# Whether the agent may accept a vendor's terms on the operator's behalf is a
# BUSINESS decision, not a browser-safety one, and the operator has made it: the
# recipe catalog is a hand-curated set of partner apps whose terms the company
# has already reviewed and agreed to out of band. Signing up is the act of
# recording an agreement that already exists, so pausing for a human to re-read
# it added latency without adding review.
#
# The authorization is scoped to that curated set, not granted globally. It is
# carried as an explicit ``accept_legal`` argument threaded from
# :func:`drive_signup`, which turns it on only where a reviewed
# :class:`SignupPolicy` came from the catalog. A signup surface reached without
# a recipe -- the ``signup_policy is None`` path -- is NOT a partner route and
# still hands its acceptance to a human.
#
# Everything else about the boundary is unchanged: the form must still sit on an
# evidence-bound host and reviewed entry path, billing actions still stop, and
# the submit-at-most-once guarantee still holds. Acceptance is recorded on the
# session state and logged, so what was agreed to is auditable after the fact.
_IMPLICIT_LEGAL_ACCEPTANCE = re.compile(
    r"(?is)\bby\s+(?:signing\s+up|registering|creating|continuing|submitting)\b"
    r".{0,240}\b(?:accept|agree|consent)\b"
)
_BILLING_WORDS = re.compile(
    r"(?i)\b(pay|payment|purchase|subscribe|subscription|checkout|billing|card|upgrade)\b"
)
_CONFIRM_PASSWORD = re.compile(r"(?i)(confirm|repeat|verify|again|confirmation)")
# Controls that hand registration to a THIRD-PARTY identity provider rather than
# submitting the form we validated. They routinely sit inside that same form
# element -- Apify's sign-up form carries "Continue with Google", "Continue with
# GitHub" and "Next" as siblings -- so a count of submit controls says "ambiguous"
# for a page whose own submit action is perfectly unambiguous. These are excluded
# from consideration, never clicked: an OAuth handoff would authenticate as some
# other account entirely, and the vault would end up holding a credential for it.
_THIRD_PARTY_IDENTITY = re.compile(
    r"(?i)\b(google|github|gitlab|apple|microsoft|facebook|twitter|slack|okta|auth0|linkedin"
    r"|sso|saml|single\s+sign[\s-]?on)\b"
)
# The handoff above, taken deliberately instead of refused.
#
# Some vendors do not merely prefer an identity provider, they REQUIRE one for a
# given identity: Apify rejects every ``@gmail.com`` address in its own email
# field and tells the operator to use "Continue with Google". For those routes
# the email path is not blocked by a gate of ours that could be relaxed -- it is
# closed by the vendor -- so refusing the handoff refuses the signup itself.
#
# The operator authorized this per deployment. What the authorization does NOT
# do is loosen anything else:
#
# * Only a provider named in ``SIGNUP_IDENTITY_HANDOFF_PROVIDER`` is eligible,
#   and its control must be the single unambiguous match on a form that already
#   passed the surface, host and form-action checks. Two candidates still stop.
# * The click happens at most once per session (``identity_handoff_attempted``),
#   under the same submit-at-most-once discipline as a real submit.
# * The destination must be an ``identity_provider_hosts`` entry the recipe
#   already declares, so egress is unchanged -- the handoff cannot introduce a
#   host the run was not already allowed to reach.
# * Authenticating AT the provider is still a human's job. The agent does not
#   type a Google password; it lands on the provider and hands over.
#
# The residual risk is the real one and it is the operator's to accept: the run
# completes as whichever account the identity provider signs in, so the vault
# ends up holding a credential for that account rather than for an address we
# chose. That is recorded on the session for the audit trail.
_IDENTITY_HANDOFF_PROVIDERS: dict[str, re.Pattern[str]] = {
    "google": re.compile(r"(?i)\bgoogle\b"),
    "github": re.compile(r"(?i)\bgithub\b"),
    "gitlab": re.compile(r"(?i)\bgitlab\b"),
    "microsoft": re.compile(r"(?i)\bmicrosoft\b"),
    "apple": re.compile(r"(?i)\bapple\b"),
}


@dataclass(slots=True)
class SignupSessionState:
    """Value-free state retained only for the lifetime of one browser session."""

    form_filled: bool = False
    email_step_filled: bool = False
    email_step_submit_attempted: bool = False
    email_step_completed: bool = False
    submit_attempted: bool = False
    handoff_count: int = 0
    legal_gate_issued: bool = False
    legal_reviewed: bool = False
    #: Bounded, value-free descriptions of every acceptance this session made on
    #: the operator's behalf -- checkbox labels and the acceptance-bearing submit
    #: label. Populated only on the authorized partner path; the record is what
    #: makes an autonomous acceptance auditable later.
    legal_accepted: list[str] = field(default_factory=list)
    #: Set before the identity-provider control is clicked, never after, so a
    #: click whose outcome is unknown is not retried into a second handoff.
    identity_handoff_attempted: bool = False
    #: The provider actually handed off to, kept for the audit trail.
    identity_handoff_provider: str | None = None
    human_submit_pending: bool = False
    pending_submit_path: str | None = None
    submitted_path: str | None = None
    #: Which step ordering a ``dom_detected`` route turned out to use. Latched on
    #: the first call that actually recognizes a form shape, so a later page --
    #: a password continuation, or a form that failed to re-render -- cannot move
    #: an in-flight signup onto the other driver's state machine.
    resolved_flow: ResolvedSignupFlow | None = None


@dataclass(frozen=True, slots=True)
class SignupResult:
    status: SignupStatus
    reason_code: str
    action_type: SignupActionType | None = None
    instruction: str | None = None


def signup_secret_continuation_ready(
    state: SignupSessionState,
    sensitive_data: Mapping[str, str] | None,
) -> bool:
    """Whether the login injector may run during a signup continuation.

    Email/password must not bypass the reviewed password/details step. They are
    eligible only after the final registration submit; before that point only an
    OTP or reviewed magic link may use the established login secret injector.
    """

    if not sensitive_data:
        return False
    if state.submit_attempted:
        return True
    return state.email_step_completed and bool(
        "login_otp" in sensitive_data or "login_verification_url" in sensitive_data
    )


def normalize_signup_fields(values: Mapping[str, object] | None) -> dict[str, str]:
    """Validate the only non-secret values allowed across the browser RPC.

    Unknown keys are rejected instead of silently becoming generic model/form
    inputs.  The returned values are safe to retain as run-derived browser state;
    credentials use the separate one-time vault-reference channel.
    """

    if not values:
        return {}
    unknown = set(values) - set(_APPROVED_FIELDS)
    if unknown:
        raise ValueError("signup field is not approved")
    normalized: dict[str, str] = {}
    for key, maximum in _APPROVED_FIELDS.items():
        raw = values.get(key)
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError("signup field must be text")
        value = raw.strip()
        if not value or len(value) > maximum or _SAFE_TEXT.fullmatch(value) is None:
            raise ValueError("signup field value is invalid")
        if key == "company_website":
            from ops.core.models import validate_https_url

            value = validate_https_url(value)
        normalized[key] = value
    return normalized


async def _visible_enabled(locator: Any, *, limit: int = 12) -> list[Any]:
    matches: list[Any] = []
    try:
        total = min(int(await locator.count()), limit)
    except Exception:
        return matches
    for index in range(total):
        candidate = locator.nth(index)
        try:
            if await candidate.is_visible() and await candidate.is_enabled():
                matches.append(candidate)
        except Exception:
            continue
    return matches


async def _unique_visible(root: Any, selector: str) -> tuple[str, Any | None]:
    matches = await _visible_enabled(root.locator(selector))
    if not matches:
        return "missing", None
    if len(matches) != 1:
        return "ambiguous", None
    return "unique", matches[0]


def _url_path(url: str) -> str:
    """Return a value-free normalized path (never query or fragment data)."""

    return urlsplit(url).path.rstrip("/") or "/"


def _current_path(page: Any) -> str:
    return _url_path(_page_url(page))


def _path_matches(path: str, prefixes: Sequence[str]) -> bool:
    for raw_prefix in prefixes:
        prefix = raw_prefix.rstrip("/") or "/"
        if path == prefix or (prefix != "/" and path.startswith(f"{prefix}/")):
            return True
    return False


async def _form_action_allowed(
    form: Any,
    *,
    surface_url: str,
    patterns: Sequence[str],
) -> bool:
    try:
        action = await form.get_attribute("action", timeout=1_000)
    except Exception:
        action = None
    if not isinstance(action, str) or not action.strip():
        return True
    return navigation_allowed(urljoin(surface_url, action), tuple(patterns))


async def _submit_text(submit: Any) -> str:
    try:
        text = str(
            (await submit.inner_text(timeout=1_000))
            or (await submit.get_attribute("value", timeout=1_000))
            or ""
        )
        return " ".join(text.split())
    except Exception:
        return ""


async def _form_implies_legal_acceptance(form: Any) -> bool:
    """Detect prose that makes the submit itself a legal acceptance action."""

    try:
        text = str((await form.inner_text(timeout=1_000)) or "")[:2_000]
    except Exception:
        return False
    return _IMPLICIT_LEGAL_ACCEPTANCE.search(text) is not None


async def _field_marker(field: Any) -> str:
    parts: list[str] = []
    for attribute in ("name", "id", "autocomplete", "aria-label", "placeholder"):
        try:
            value = await field.get_attribute(attribute, timeout=1_000)
        except Exception:
            value = None
        if isinstance(value, str) and value:
            parts.append(value[:120])
    return " ".join(parts)


async def _checkbox_text(checkbox: Any) -> str:
    """Return bounded local-only text used solely for gate classification."""

    try:
        return str(
            await checkbox.evaluate(
                """element => {
                    const id = element.id;
                    const explicit = id
                      ? document.querySelector(`label[for="${CSS.escape(id)}"]`)
                      : null;
                    const enclosing = element.closest("label");
                    const parent = element.parentElement;
                    return (
                      explicit?.innerText ||
                      enclosing?.innerText ||
                      element.getAttribute("aria-label") ||
                      parent?.innerText ||
                      ""
                    ).slice(0, 500);
                }"""
            )
            or ""
        )
    except Exception:
        return ""


def _record_acceptance(state: SignupSessionState, description: str) -> None:
    """Note one thing the agent agreed to, bounded and value-free."""

    entry = " ".join(description.split())[:200]
    if entry and entry not in state.legal_accepted:
        state.legal_accepted.append(entry)
        LOGGER.info(
            "signup accepted vendor terms autonomously",
            extra={"acceptance": entry},
        )


async def _tick_acceptance_checkbox(checkbox: Any) -> bool:
    """Check one consent box, reporting whether it is now actually checked.

    Reports the OBSERVED state rather than the absence of an exception: a click
    that lands on an overlay leaves the box clear, and treating that as accepted
    would mean submitting a form whose required consent is unchecked.
    """

    try:
        await checkbox.check(timeout=5_000)
    except Exception:
        return False
    try:
        return bool(await checkbox.is_checked())
    except Exception:
        return False


async def _human_gate_before_fill(
    page: Any,
    form: Any,
    *,
    include_legal: bool,
    accept_legal: bool,
    resume_signal: str | None,
    state: SignupSessionState,
) -> SignupResult | None:
    if await visible_login_challenge(page):
        return SignupResult(
            status="human_action_required",
            reason_code="captcha_required",
            action_type="captcha",
            instruction="Complete the visible CAPTCHA in the live browser, then resume.",
        )
    billing = await _visible_enabled(form.locator(_BILLING_SELECTOR), limit=4)
    if billing:
        return SignupResult(
            status="human_action_required",
            reason_code="billing_required",
            action_type="billing",
            instruction="Review and complete the billing step in the live browser.",
        )
    passkeys = await _visible_enabled(page.locator(_PASSKEY_SELECTOR), limit=4)
    if passkeys:
        return SignupResult(
            status="human_action_required",
            reason_code="passkey_required",
            action_type="passkey",
            instruction="Complete or dismiss the passkey/security-key prompt, then resume.",
        )
    if not include_legal:
        return None
    checkboxes = await _visible_enabled(form.locator("input[type='checkbox']"), limit=12)
    for checkbox in checkboxes:
        try:
            checked = bool(await checkbox.is_checked())
        except Exception:
            checked = False
        text = await _checkbox_text(checkbox)
        try:
            required = await checkbox.get_attribute("required", timeout=1_000) is not None
        except Exception:
            required = False
        if required or _LEGAL_WORDS.search(text):
            if state.legal_gate_issued and resume_signal == "human_completed" and checked:
                state.legal_reviewed = True
                continue
            if state.legal_reviewed and checked:
                continue
            if checked:
                continue
            if accept_legal:
                # A partner route: tick the operator's already-made agreement.
                # Only a box the agent could not actually set falls through to a
                # human -- that is a mechanism failure, not a policy one, and
                # submitting past it would send an unchecked required consent.
                if await _tick_acceptance_checkbox(checkbox):
                    _record_acceptance(state, text or "unlabelled required consent checkbox")
                    state.legal_reviewed = True
                    continue
            state.legal_gate_issued = True
            return SignupResult(
                status="human_action_required",
                reason_code="legal_acceptance_required",
                action_type="legal_acceptance",
                instruction=(
                    "Review the vendor terms and choose whether to accept them in the live browser."
                ),
            )
    return None


async def _unfilled_required_control(form: Any) -> bool:
    required = await _visible_enabled(
        form.locator("input[required], textarea[required], select[required]"),
        limit=30,
    )
    for control in required:
        try:
            tag = str(await control.evaluate("element => element.tagName.toLowerCase()"))
            control_type = str((await control.get_attribute("type", timeout=1_000)) or "").lower()
            if control_type in {"hidden", "submit", "button", "reset"}:
                continue
            if control_type in {"checkbox", "radio"}:
                if not await control.is_checked():
                    return True
                continue
            if tag == "select":
                value = await control.input_value(timeout=1_000)
            else:
                value = await control.input_value(timeout=1_000)
            if not isinstance(value, str) or not value.strip():
                return True
        except Exception:
            return True
    return False


async def _email_only_surfaces(
    page: Any,
    patterns: Sequence[str],
) -> list[tuple[Any, Any, Any]]:
    """Return reviewed forms containing one email field and no password field."""

    surfaces: list[tuple[Any, Any, Any]] = []
    for surface in reviewed_login_surfaces(page, patterns):
        if surface.frame_url and not navigation_allowed(surface.frame_url, tuple(patterns)):
            continue
        email_status, email_field = await _unique_visible(surface.frame, _EMAIL_SELECTOR)
        if email_status != "unique" or email_field is None:
            continue
        if await _visible_enabled(surface.frame.locator(_PASSWORD_SELECTOR), limit=4):
            continue
        try:
            form = email_field.locator("xpath=ancestor::form[1]")
            if int(await form.count()) != 1:
                continue
        except Exception:
            continue
        form_email_status, _form_email = await _unique_visible(form, _EMAIL_SELECTOR)
        if form_email_status != "unique":
            continue
        if await _visible_enabled(form.locator(_PASSWORD_SELECTOR), limit=4):
            continue
        surfaces.append((surface, form, email_field))
    return surfaces


async def _email_password_surfaces(
    page: Any,
    patterns: Sequence[str],
) -> list[tuple[Any, Any, Any, list[Any]]]:
    """Return reviewed forms with one email field and one or two passwords.

    Every password must belong to the same form as the email field. Multiple
    detached forms on one page are refused by the caller rather than resolved by
    picking the first, so a login form sitting beside a registration form can
    never be mistaken for the registration form.
    """

    surfaces: list[tuple[Any, Any, Any, list[Any]]] = []
    for surface in reviewed_login_surfaces(page, patterns):
        if surface.frame_url and not navigation_allowed(surface.frame_url, tuple(patterns)):
            continue
        email_status, email_field = await _unique_visible(surface.frame, _EMAIL_SELECTOR)
        if email_status != "unique" or email_field is None:
            continue
        passwords = await _visible_enabled(surface.frame.locator(_PASSWORD_SELECTOR), limit=4)
        if len(passwords) not in {1, 2}:
            continue
        try:
            form = email_field.locator("xpath=ancestor::form[1]")
            if int(await form.count()) != 1:
                continue
        except Exception:
            continue
        form_passwords = await _visible_enabled(form.locator(_PASSWORD_SELECTOR), limit=4)
        if len(form_passwords) != len(passwords):
            continue
        surfaces.append((surface, form, email_field, form_passwords))
    return surfaces


async def _password_continuation_surfaces(
    page: Any,
    patterns: Sequence[str],
) -> list[tuple[Any, Any, Any | None, list[Any]]]:
    """Return reviewed forms with one password and optional confirmation/email."""

    surfaces: list[tuple[Any, Any, Any | None, list[Any]]] = []
    for surface in reviewed_login_surfaces(page, patterns):
        if surface.frame_url and not navigation_allowed(surface.frame_url, tuple(patterns)):
            continue
        passwords = await _visible_enabled(surface.frame.locator(_PASSWORD_SELECTOR), limit=4)
        if len(passwords) not in {1, 2}:
            continue
        try:
            form = passwords[0].locator("xpath=ancestor::form[1]")
            if int(await form.count()) != 1:
                continue
        except Exception:
            continue
        form_passwords = await _visible_enabled(form.locator(_PASSWORD_SELECTOR), limit=4)
        if len(form_passwords) != len(passwords):
            continue
        email_status, email_field = await _unique_visible(form, _EMAIL_SELECTOR)
        if email_status == "ambiguous":
            continue
        surfaces.append((surface, form, email_field, form_passwords))
    return surfaces


async def _page_shape(page: Any) -> str:
    """A value-free structural summary of the current page, for diagnosis only.

    Input TYPES and button LABELS are static UI vocabulary, not account data; no
    field value is read. This exists because the pauses below describe what the
    driver expected rather than what the page actually offered, which is the one
    thing needed to tell a mis-detected surface from a rejected submission.
    """

    try:
        shape = await page.evaluate(
            """() => ({
                path: location.pathname,
                inputs: [...document.querySelectorAll('form input')]
                  .map(i => i.type).slice(0, 20),
                buttons: [...document.querySelectorAll('form button')]
                  .map(b => (b.innerText || '').trim()).filter(Boolean).slice(0, 12),
            })"""
        )
    except Exception:
        return "<unavailable>"
    return str(shape)[:600]


async def _submit_obstructed_gate() -> SignupResult:
    return SignupResult(
        status="human_action_required",
        reason_code="signup_submit_obstructed",
        action_type="provider_verification",
        instruction=(
            "The signup form is filled but something on the page is covering its "
            "submit control. Clear it in the live browser and resume; nothing has "
            "been submitted yet."
        ),
    )


async def _await_clickable(control: Any, *, budget_seconds: float) -> bool:
    """Wait until a real click on ``control`` would reach it.

    A single-page console commonly paints its form UNDER a full-page loading
    overlay: the control is visible, enabled and stable, and the click still
    lands on the overlay. Apify's ``#appLoader`` does exactly this, and the
    click's own actionability window expired against it.

    Hovering runs the same actionability checks as clicking -- including "does
    this element receive pointer events" -- while changing nothing on the page,
    so it can be retried freely. That matters because the click it guards cannot
    be: the click is the one-shot, and a click that times out against an overlay
    is indistinguishable from one the server accepted, which costs the whole run.
    """

    deadline = monotonic() + budget_seconds
    while True:
        try:
            await control.hover(timeout=2_000)
            return True
        except Exception as error:
            if monotonic() >= deadline:
                # The pause this produces names the obstruction only in prose.
                # Record what actually blocked the pointer so the route can be
                # fixed rather than re-diagnosed by hand on every run.
                LOGGER.warning(
                    "signup submit never became clickable: %s: %s",
                    type(error).__name__,
                    str(error)[:2000],
                )
                return False
        await asyncio.sleep(_SURFACE_RENDER_POLL_SECONDS)


async def _exact_submit(
    form: Any,
    labels: Sequence[str],
) -> tuple[str, Any | None]:
    wanted = {label.strip().casefold() for label in labels}
    controls = await _visible_enabled(form.locator("button, input[type='submit']"), limit=12)
    matches: list[Any] = []
    for control in controls:
        if (await _submit_text(control)).casefold() in wanted:
            matches.append(control)
    if not matches:
        return "missing", None
    if len(matches) != 1:
        return "ambiguous", None
    return "unique", matches[0]


async def _own_submit(form: Any) -> tuple[str, Any | None]:
    """The one control that submits THIS form, read off the live page.

    For a researched route the reviewed labels are the wrong authority. Research
    reads a route from the vendor's own site; it never executes the page, so for
    a client-rendered console it records the marketing link's wording ("Sign up")
    while the hydrated form's button says something else entirely ("Next"). A
    strict label match then reports "the reviewed submit action is no longer
    present" about a form that is sitting there, complete and fillable.

    So the control is resolved structurally instead of by wording: among the
    visible, enabled submit controls of the form ALREADY validated -- on a URL
    that is still evidence-bound, in a surface that is still the single
    unambiguous one -- the third-party identity handoffs are set aside and
    exactly one must remain. Two remaining is still ``ambiguous`` and still
    stops. This resolves a control inside a form that was already accepted; it
    grants no new page, no new host, and no new form.
    """

    controls = await _visible_enabled(form.locator("button, input[type='submit']"), limit=12)
    matches: list[Any] = []
    for control in controls:
        if not _THIRD_PARTY_IDENTITY.search(await _submit_text(control)):
            matches.append(control)
    if not matches:
        return "missing", None
    if len(matches) != 1:
        return "ambiguous", None
    return "unique", matches[0]


async def _identity_handoff_control(form: Any, provider: str) -> tuple[str, Any | None]:
    """The single control on this form that hands registration to ``provider``.

    Resolved the same way :func:`_own_submit` resolves the form's own submit: off
    the live page, among visible enabled controls of a form that has already been
    accepted, requiring exactly one match. "Continue with Google" and "Continue
    with GitHub" sitting side by side is precisely why the provider is named
    rather than inferred -- with a name, each is unambiguous; without one, both
    are candidates and nothing may be clicked.
    """

    pattern = _IDENTITY_HANDOFF_PROVIDERS.get(provider)
    if pattern is None:
        return "missing", None
    controls = await _visible_enabled(
        form.locator("button, input[type='submit'], a[role='button'], a"), limit=16
    )
    matches = [control for control in controls if pattern.search(await _submit_text(control))]
    if not matches:
        return "missing", None
    if len(matches) != 1:
        return "ambiguous", None
    return "unique", matches[0]


async def _drive_identity_handoff(
    *,
    page: Any,
    form: Any,
    provider: str,
    patterns: Sequence[str],
    state: SignupSessionState,
) -> SignupResult | None:
    """Click the vendor's own identity-provider control, at most once.

    Returns ``None`` when no unambiguous control for ``provider`` is on this
    form, which leaves the caller's original outcome intact -- the handoff is an
    alternative to a dead end, never a replacement for a working email path.

    The click is recorded on the session BEFORE it happens, so a navigation that
    times out is an outcome-unknown handoff and is never clicked a second time.
    Landing on the provider is where the agent stops: signing in there is the
    operator's, because it is the operator's identity being spent.
    """

    if state.identity_handoff_attempted:
        return None
    status, control = await _identity_handoff_control(form, provider)
    if status != "unique" or control is None:
        return None

    label = await _submit_text(control)
    state.identity_handoff_attempted = True
    state.identity_handoff_provider = provider
    LOGGER.info("signup handing off to identity provider %s via %r", provider, label)
    try:
        await control.click(timeout=10_000)
    except Exception:
        return SignupResult(status="failed", reason_code="signup_identity_handoff_failed")

    # Give the provider's page time to become the thing the operator sees. The
    # destination is not asserted here: egress already confines navigation to the
    # recipe's declared identity-provider hosts, so a redirect somewhere else is
    # refused by the boundary rather than by a string comparison.
    deadline = monotonic() + _SURFACE_RENDER_BUDGET_SECONDS
    while monotonic() < deadline:
        if not navigation_allowed(_page_url(page), tuple(patterns)):
            return SignupResult(status="failed", reason_code="signup_origin_unsafe")
        if _current_path(page) != "/" and _page_url(page):
            break
        await asyncio.sleep(_SURFACE_RENDER_POLL_SECONDS)

    return SignupResult(
        status="human_action_required",
        reason_code="signup_identity_provider_signin",
        action_type="account_selection",
        instruction=(
            f"This provider requires {provider.title()} sign-in for the configured "
            "email, so the agent opened it. Complete the sign-in in the live "
            "browser; the run continues from the account you choose."
        ),
    )


async def _fill_company_fields(
    form: Any,
    fields: Mapping[str, str],
) -> SignupResult | None:
    for field_name, selector in _COMPANY_SELECTORS.items():
        value = fields.get(field_name)
        if value is None:
            continue
        status, control = await _unique_visible(form, selector)
        if status == "ambiguous":
            return SignupResult(status="failed", reason_code="signup_field_ambiguous")
        if control is None:
            continue
        try:
            tag = str(await control.evaluate("element => element.tagName.toLowerCase()"))
            if tag == "select":
                # Select only an exact, unique match to the approved backend value.
                # Fuzzy matching would be the agent inventing a vendor-owned choice.
                options = await control.locator("option").all()
                matches: list[str] = []
                wanted = value.strip().casefold()
                for option in options[:50]:
                    label = str((await option.inner_text(timeout=1_000)) or "").strip()
                    option_value = str(
                        (await option.get_attribute("value", timeout=1_000)) or ""
                    ).strip()
                    if label.casefold() == wanted or option_value.casefold() == wanted:
                        matches.append(option_value)
                if len(matches) != 1:
                    return SignupResult(
                        status="human_action_required",
                        reason_code="signup_selection_required",
                        action_type="provider_verification",
                        instruction="Choose the required signup option in the live browser.",
                    )
                await control.select_option(value=matches[0], timeout=5_000)
                continue
            await control.fill(value, timeout=5_000)
        except Exception:
            return SignupResult(status="failed", reason_code="signup_field_injection_failed")
    return None


async def _classify_after_submit(
    page: Any,
    patterns: Sequence[str],
    *,
    before_path: str | None,
) -> SignupResult:
    current = _page_url(page)
    if not navigation_allowed(current, tuple(patterns)):
        return SignupResult(status="failed", reason_code="signup_navigation_blocked")
    if await visible_login_challenge(page):
        return SignupResult(
            status="human_action_required",
            reason_code="captcha_required",
            action_type="captcha",
            instruction="Complete the visible CAPTCHA in the live browser, then resume.",
        )
    try:
        login = await inspect_login(page, tuple(patterns))
    except Exception:
        login = None
    if login is not None:
        if login.state == "otp_required":
            return SignupResult(
                status="human_action_required",
                reason_code="otp_required",
                action_type="email_otp",
                instruction="Enter the one-time code sent to the signup email address.",
            )
        if login.state == "magic_link_required":
            return SignupResult(
                status="human_action_required",
                reason_code="magic_link_required",
                action_type="email_otp",
                instruction="Open the reviewed verification link sent to the signup email.",
            )
        if login.state == "account_selection_required":
            return SignupResult(
                status="human_action_required",
                reason_code="account_selection_required",
                action_type="account_selection",
                instruction="Select the intended account or workspace in the live browser.",
            )
    if await _visible_enabled(page.locator(_OTP_SELECTOR), limit=8):
        return SignupResult(
            status="human_action_required",
            reason_code="otp_required",
            action_type="email_otp",
            instruction="Enter the one-time code sent to the signup email address.",
        )
    if await _visible_enabled(page.locator(_PHONE_OTP_SELECTOR), limit=4):
        return SignupResult(
            status="human_action_required",
            reason_code="phone_otp_required",
            action_type="phone_otp",
            instruction="Complete the phone verification step in the live browser.",
        )
    if await _visible_enabled(page.locator(_BILLING_SELECTOR), limit=4):
        return SignupResult(
            status="human_action_required",
            reason_code="billing_required",
            action_type="billing",
            instruction="Review and complete the billing step in the live browser.",
        )
    # Generic registration can advance only on a positive, value-free transition.
    # A form disappearing or an error message appearing on the same path is not
    # evidence that the provider accepted the step.
    current_path = _current_path(page)
    if before_path is not None and current_path != before_path:
        return SignupResult(status="continue", reason_code="signup_step_transition_verified")
    return SignupResult(
        status="human_action_required",
        reason_code="signup_postcondition_unverified",
        action_type="provider_verification",
        instruction=(
            "The provider did not expose a reviewed post-submit transition. Inspect the "
            "current page in the live browser; do not submit the form again unless it "
            "clearly shows that the previous attempt was rejected."
        ),
    )


def _partner_acceptance_authorized(policy: SignupPolicy | None) -> bool:
    """Whether the agent may accept this route's vendor terms without a human.

    A reviewed :class:`SignupPolicy` exists only for an app the operator put in
    the curated catalog, which is the same set they hold partner agreements with
    and whose terms they have already reviewed. No recipe means no partnership
    on record, so no autonomous acceptance.
    """

    return policy is not None


def _legal_submit_gate(*, reason_code: str = "legal_acceptance_required") -> SignupResult:
    return SignupResult(
        status="human_action_required",
        reason_code=reason_code,
        action_type="legal_acceptance",
        instruction=(
            "Review the vendor terms and submit this acceptance-bearing action yourself "
            "in the live browser, then resume."
        ),
    )


def _complete_email_step(state: SignupSessionState, *, legal_reviewed: bool) -> None:
    # Preserve only the value-free path that preceded this accepted transition;
    # later resumes use it to prove they did not fall back to the entry page.
    state.submitted_path = state.pending_submit_path or state.submitted_path
    state.email_step_completed = True
    state.human_submit_pending = False
    state.pending_submit_path = None
    if legal_reviewed:
        state.legal_reviewed = True


async def _drive_password_continuation(
    *,
    page: Any,
    patterns: Sequence[str],
    sensitive_data: Mapping[str, str],
    fields: Mapping[str, str],
    state: SignupSessionState,
    resume_signal: str | None,
    researched: bool = False,
    accept_legal: bool = False,
) -> SignupResult:
    """Fill one reviewed password/details continuation after an email-first step.

    ``researched`` carries the same meaning it has in the single-step driver: the
    route came from research rather than review, so the form's own submit control
    may be resolved past sibling OAuth buttons. The continuation needs it because
    a researched email-first route reaches its password step through here.

    ``accept_legal`` likewise carries the partner-catalog authorization down from
    :func:`drive_signup`; a continuation is where a two-step signup usually puts
    its terms checkbox.
    """

    if state.human_submit_pending:
        if resume_signal != "human_completed":
            return _legal_submit_gate()
        result = await _classify_after_submit(
            page,
            patterns,
            before_path=state.pending_submit_path,
        )
        if result.reason_code == "signup_postcondition_unverified":
            return _legal_submit_gate(reason_code="legal_submission_not_observed")
        state.submit_attempted = True
        state.human_submit_pending = False
        state.pending_submit_path = None
        return result
    if state.submit_attempted:
        return await _classify_after_submit(
            page,
            patterns,
            before_path=state.submitted_path,
        )

    surfaces = await _password_continuation_surfaces(page, patterns)
    if not surfaces:
        # The email step has already produced a positive transition. A typed
        # verification gate is handled here; otherwise return control to the
        # reviewed credential trace, which alone can prove final success.
        return await _classify_after_submit(
            page,
            patterns,
            before_path=state.submitted_path or state.pending_submit_path,
        )
    if len(surfaces) != 1:
        return SignupResult(status="failed", reason_code="multiple_signup_surfaces")

    surface, form, email_field, password_fields = surfaces[0]
    if not await _form_action_allowed(
        form,
        surface_url=surface.frame_url or _page_url(page),
        patterns=patterns,
    ):
        return SignupResult(status="failed", reason_code="signup_form_action_unsafe")

    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=False,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate

    if len(password_fields) == 2:
        second_marker = await _field_marker(password_fields[1])
        if _CONFIRM_PASSWORD.search(second_marker) is None:
            return SignupResult(status="failed", reason_code="password_confirmation_ambiguous")

    email = sensitive_data.get("login_email")
    password = sensitive_data.get("login_password")
    if not state.form_filled and (not email or not password):
        return SignupResult(
            status="human_action_required",
            reason_code="signup_credentials_required",
            action_type="provider_verification",
            instruction="Signup requires the configured email identity and generated password.",
        )
    if state.form_filled:
        try:
            present = all(
                [
                    bool(await field.evaluate("element => Boolean(element.value)"))
                    for field in password_fields
                ]
            )
            if email_field is not None:
                present = present and bool(
                    await email_field.evaluate("element => Boolean(element.value)")
                )
        except Exception:
            present = False
        if not present:
            return SignupResult(
                status="human_action_required",
                reason_code="signup_credentials_required",
                action_type="provider_verification",
                instruction=(
                    "The signup form no longer contains the configured credentials. "
                    "Restart the signup attempt."
                ),
            )
    else:
        assert email is not None and password is not None
        try:
            if email_field is not None:
                await email_field.fill(email, timeout=5_000)
            await password_fields[0].fill(password, timeout=5_000)
            if len(password_fields) == 2:
                await password_fields[1].fill(password, timeout=5_000)
        except Exception:
            return SignupResult(status="failed", reason_code="signup_secret_injection_failed")
        state.form_filled = True

    field_result = await _fill_company_fields(form, fields)
    if field_result is not None:
        return field_result
    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=True,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate
    if await _unfilled_required_control(form):
        return SignupResult(
            status="human_action_required",
            reason_code="signup_required_field_unknown",
            action_type="provider_verification",
            instruction="Complete the remaining required signup field in the live browser.",
        )

    submit_status, submit = await _unique_visible(form, _SUBMIT_SELECTOR)
    if submit_status != "unique" and researched:
        # Sibling OAuth buttons inside the same form make the plain count read
        # "ambiguous" for a form with one real submit action. Reviewed recipes
        # keep the plain count; only a researched route looks past them.
        submit_status, submit = await _own_submit(form)
    if submit_status == "missing" or submit is None:
        return SignupResult(
            status="human_action_required",
            reason_code="signup_submit_not_found",
            action_type="provider_verification",
            instruction="Review and submit the completed signup form in the live browser.",
        )
    if submit_status == "ambiguous":
        return SignupResult(status="failed", reason_code="signup_submit_ambiguous")
    submit_text = await _submit_text(submit)
    if _BILLING_WORDS.search(submit_text):
        return SignupResult(
            status="human_action_required",
            reason_code="billing_required",
            action_type="billing",
            instruction="Review the payment or subscription action in the live browser.",
        )
    if _LEGAL_WORDS.search(submit_text) or await _form_implies_legal_acceptance(form):
        if not accept_legal:
            state.human_submit_pending = True
            state.pending_submit_path = _current_path(page)
            return _legal_submit_gate()
        _record_acceptance(state, f"submit: {submit_text}")

    # Nothing has been submitted yet, so an obstruction here is recoverable.
    # Check it BEFORE the one-shot state below: past that line the run can never
    # try again, because a timed-out click may still have registered.
    if not await _await_clickable(submit, budget_seconds=_SURFACE_RENDER_BUDGET_SECONDS):
        return await _submit_obstructed_gate()

    state.submit_attempted = True
    state.submitted_path = _current_path(page)
    try:
        await submit.click(timeout=10_000)
    except Exception as error:
        # This outcome is terminal by design -- the click may have registered, so
        # it is never retried -- which makes the swallowed cause the only thing
        # that could explain it later. Record the class and message; a Playwright
        # actionability failure names the obstruction, and no typed value reaches
        # here to be leaked.
        LOGGER.warning(
            "signup submit click did not complete: %s: %s",
            type(error).__name__,
            str(error)[:2000],
        )
        return SignupResult(status="failed", reason_code="signup_submit_outcome_unknown")
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    return await _classify_after_submit(
        page,
        patterns,
        before_path=state.submitted_path,
    )


async def _drive_email_first_signup(
    *,
    page: Any,
    patterns: Sequence[str],
    sensitive_data: Mapping[str, str],
    fields: Mapping[str, str],
    state: SignupSessionState,
    policy: SignupPolicy,
    resume_signal: str | None,
    identity_handoff: str | None = None,
) -> SignupResult:
    """Drive a reviewed email-first registration for a catalog app."""

    accept_legal = _partner_acceptance_authorized(policy)
    if state.email_step_completed:
        return await _drive_password_continuation(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            resume_signal=resume_signal,
            researched=policy.flow == "dom_detected",
            accept_legal=accept_legal,
        )

    # Reached only when an earlier attempt handed the acceptance-bearing entry
    # submit to a human -- which now happens only for a route with no reviewed
    # recipe, or one whose consent checkbox could not be set. Resume is evidence
    # only when the page positively transitions or exposes the uniquely
    # recognized password continuation.
    if state.human_submit_pending:
        if resume_signal != "human_completed":
            return _legal_submit_gate()
        password_surfaces = await _password_continuation_surfaces(page, patterns)
        if len(password_surfaces) > 1:
            return SignupResult(status="failed", reason_code="multiple_signup_surfaces")
        current_path = _current_path(page)
        transitioned = bool(password_surfaces) or (
            state.pending_submit_path is not None and current_path != state.pending_submit_path
        )
        result = await _classify_after_submit(
            page,
            patterns,
            before_path=state.pending_submit_path,
        )
        typed_post_submit_gate = result.action_type in {
            "email_otp",
            "phone_otp",
            "billing",
            "account_selection",
        }
        if not transitioned and not typed_post_submit_gate:
            if result.action_type == "captcha":
                return result
            return _legal_submit_gate(reason_code="legal_submission_not_observed")
        _complete_email_step(state, legal_reviewed=True)
        if password_surfaces:
            return await _drive_password_continuation(
                page=page,
                patterns=patterns,
                sensitive_data=sensitive_data,
                fields=fields,
                state=state,
                resume_signal=resume_signal,
                researched=policy.flow == "dom_detected",
                accept_legal=accept_legal,
            )
        return result

    if state.email_step_submit_attempted:
        # The step's own outcome needs the same render budget the entry needed.
        # A console answers "Next" by swapping the password step in at the SAME
        # path a second or two later -- Apify does exactly this -- so reading the
        # page the instant the click returns sees the pre-submit form and calls a
        # working signup unverified. Poll until something recognizable appears.
        deadline = monotonic() + _SURFACE_RENDER_BUDGET_SECONDS
        while True:
            password_surfaces = await _password_continuation_surfaces(page, patterns)
            if len(password_surfaces) > 1:
                return SignupResult(status="failed", reason_code="multiple_signup_surfaces")
            result = await _classify_after_submit(
                page,
                patterns,
                before_path=state.submitted_path,
            )
            transitioned = bool(password_surfaces) or (
                state.submitted_path is not None and _current_path(page) != state.submitted_path
            )
            recognized = transitioned or result.action_type in {
                "email_otp",
                "phone_otp",
                "billing",
                "account_selection",
            }
            if recognized:
                break
            if monotonic() >= deadline:
                LOGGER.warning(
                    "signup email step produced no recognized continuation: %s",
                    await _page_shape(page),
                )
                break
            await asyncio.sleep(_SURFACE_RENDER_POLL_SECONDS)
        if recognized:
            _complete_email_step(state, legal_reviewed=False)
            if password_surfaces:
                return await _drive_password_continuation(
                    page=page,
                    patterns=patterns,
                    sensitive_data=sensitive_data,
                    fields=fields,
                    state=state,
                    resume_signal=resume_signal,
                    researched=policy.flow == "dom_detected",
                    accept_legal=accept_legal,
                )
        return result

    current_path = _current_path(page)
    if not _path_matches(current_path, policy.entry_path_prefixes):
        return SignupResult(status="failed", reason_code="signup_entry_path_unreviewed")
    email = sensitive_data.get("login_email")
    if not state.email_step_filled and not email:
        return SignupResult(
            status="human_action_required",
            reason_code="signup_credentials_required",
            action_type="provider_verification",
            instruction="Signup requires the configured email identity.",
        )

    surfaces = await _email_only_surfaces(page, patterns)
    if not surfaces:
        return SignupResult(
            status="human_action_required",
            reason_code="signup_email_step_not_supported",
            action_type="provider_verification",
            instruction=(
                "The reviewed email-first signup page no longer exposes one unambiguous "
                "email-only form."
            ),
        )
    if len(surfaces) != 1:
        return SignupResult(status="failed", reason_code="multiple_signup_surfaces")
    surface, form, email_field = surfaces[0]
    if not await _form_action_allowed(
        form,
        surface_url=surface.frame_url or _page_url(page),
        patterns=patterns,
    ):
        return SignupResult(status="failed", reason_code="signup_form_action_unsafe")

    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=False,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate
    if state.email_step_filled:
        try:
            present = bool(await email_field.evaluate("element => Boolean(element.value)"))
        except Exception:
            present = False
        if not present:
            # The configured email went in and the vendor took it back out. That
            # is the shape of an identity the provider refuses -- Apify empties
            # the field for any ``@gmail.com`` address and points at "Continue
            # with Google" -- so where the operator has authorized a handoff,
            # take the route the vendor is actually offering instead of parking
            # a signup that the email path can never complete.
            if identity_handoff is not None:
                handoff = await _drive_identity_handoff(
                    page=page,
                    form=form,
                    provider=identity_handoff,
                    patterns=patterns,
                    state=state,
                )
                if handoff is not None:
                    return handoff
            return SignupResult(
                status="human_action_required",
                reason_code="signup_credentials_required",
                action_type="provider_verification",
                instruction=(
                    "The signup form no longer contains the configured email. Restart the "
                    "signup attempt."
                ),
            )
    else:
        assert email is not None
        try:
            await email_field.fill(email, timeout=5_000)
        except Exception:
            return SignupResult(status="failed", reason_code="signup_secret_injection_failed")
        state.email_step_filled = True

    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=True,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate
    if await _unfilled_required_control(form):
        return SignupResult(
            status="human_action_required",
            reason_code="signup_required_field_unknown",
            action_type="provider_verification",
            instruction="Complete the remaining required signup field in the live browser.",
        )
    submit_status, submit = await _exact_submit(form, policy.entry_submit_labels)
    if submit_status == "missing" and policy.flow == "dom_detected":
        # A RESEARCHED route's labels are a guess about wording, not evidence
        # about this form. Fall back to the form's own submit control; a reviewed
        # recipe keeps its strict label match and never reaches this line.
        submit_status, submit = await _own_submit(form)
    if submit_status == "missing" or submit is None:
        # The email is in the field and the submit control is not available --
        # typically because the vendor has disabled it, which ``_visible_enabled``
        # reads as absent. That is the same refusal as a cleared field wearing a
        # different shape, so it gets the same authorized alternative.
        if identity_handoff is not None:
            handoff = await _drive_identity_handoff(
                page=page,
                form=form,
                provider=identity_handoff,
                patterns=patterns,
                state=state,
            )
            if handoff is not None:
                return handoff
        return SignupResult(
            status="human_action_required",
            reason_code="signup_submit_not_found",
            action_type="provider_verification",
            instruction="The reviewed signup submit action is no longer present.",
        )
    if submit_status == "ambiguous":
        return SignupResult(status="failed", reason_code="signup_submit_ambiguous")
    submit_text = await _submit_text(submit)
    if _BILLING_WORDS.search(submit_text):
        return SignupResult(
            status="human_action_required",
            reason_code="billing_required",
            action_type="billing",
            instruction="Review the payment or subscription action in the live browser.",
        )

    if (
        policy.entry_submit_implies_legal_acceptance
        or _LEGAL_WORDS.search(submit_text)
        or await _form_implies_legal_acceptance(form)
    ):
        if not accept_legal:
            state.legal_gate_issued = True
            state.human_submit_pending = True
            state.pending_submit_path = current_path
            return _legal_submit_gate()
        _record_acceptance(state, f"submit: {submit_text}")

    # Nothing has been submitted yet, so an obstruction here is recoverable.
    # Check it BEFORE the one-shot state below: past that line the run can never
    # try again, because a timed-out click may still have registered.
    if not await _await_clickable(submit, budget_seconds=_SURFACE_RENDER_BUDGET_SECONDS):
        return await _submit_obstructed_gate()

    state.email_step_submit_attempted = True
    state.submitted_path = current_path
    try:
        await submit.click(timeout=10_000)
    except Exception as error:
        # This outcome is terminal by design -- the click may have registered, so
        # it is never retried -- which makes the swallowed cause the only thing
        # that could explain it later. Record the class and message; a Playwright
        # actionability failure names the obstruction, and no typed value reaches
        # here to be leaked.
        LOGGER.warning(
            "signup submit click did not complete: %s: %s",
            type(error).__name__,
            str(error)[:2000],
        )
        return SignupResult(status="failed", reason_code="signup_submit_outcome_unknown")
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    return await _drive_email_first_signup(
        page=page,
        patterns=patterns,
        sensitive_data=sensitive_data,
        fields=fields,
        state=state,
        policy=policy,
        resume_signal=resume_signal,
        identity_handoff=identity_handoff,
    )


async def _drive_dom_detected_signup(
    *,
    page: Any,
    patterns: Sequence[str],
    sensitive_data: Mapping[str, str],
    fields: Mapping[str, str],
    state: SignupSessionState,
    policy: SignupPolicy,
    resume_signal: str | None,
    identity_handoff: str | None = None,
) -> SignupResult:
    """Drive a researched route whose step ordering is read off the live form.

    Research establishes *where* registration lives and what its submit control
    says; it cannot establish whether the provider asks for an email alone first.
    So the shape is resolved here, once, against the page the run is actually
    standing on, and both branches are the drivers a reviewed recipe already
    uses -- with the same single-unambiguous-surface rule, the same form-action
    check, the same pre-fill human gates and the same submit-at-most-once state.

    Neither shape being present is a pause, not a guess: the alternative is to
    pick a driver on no evidence and have it fill a form nobody recognized.

    That judgement is only worth making against a page that has finished drawing.
    A researched route is routinely a client-rendered application whose form does
    not exist at ``domcontentloaded`` -- Apify's takes between four and nine
    seconds -- so a single immediate read reports "no surface" for a page that
    was merely still empty, and parks a perfectly drivable signup on a human.
    The scan therefore repeats until a surface appears or the budget is spent.
    Waiting cannot manufacture a surface that is not there: an unrecognized page
    still pauses, just later and on better evidence.
    """

    if state.resolved_flow is None:
        if not _path_matches(_current_path(page), policy.entry_path_prefixes):
            return SignupResult(status="failed", reason_code="signup_entry_path_unreviewed")
        deadline = monotonic() + _SURFACE_RENDER_BUDGET_SECONDS
        while True:
            if await _email_only_surfaces(page, patterns):
                state.resolved_flow = "email_first"
                break
            if await _email_password_surfaces(page, patterns):
                state.resolved_flow = "email_password"
                break
            if monotonic() >= deadline:
                return SignupResult(
                    status="human_action_required",
                    reason_code="signup_surface_not_supported",
                    action_type="provider_verification",
                    instruction=(
                        "The researched registration page exposes neither an email-only "
                        "step nor a single email-and-password form. Complete this "
                        "vendor-specific step in the live browser."
                    ),
                )
            # Re-check the path each round: a client-side redirect away from the
            # reviewed entry point must not be waited out and then driven.
            if not _path_matches(_current_path(page), policy.entry_path_prefixes):
                return SignupResult(status="failed", reason_code="signup_entry_path_unreviewed")
            await asyncio.sleep(_SURFACE_RENDER_POLL_SECONDS)
    if state.resolved_flow == "email_first":
        return await _drive_email_first_signup(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            policy=policy,
            resume_signal=resume_signal,
            identity_handoff=identity_handoff,
        )
    return await _drive_email_password_signup(
        page=page,
        patterns=patterns,
        sensitive_data=sensitive_data,
        fields=fields,
        state=state,
        resume_signal=resume_signal,
        researched=True,
        accept_legal=_partner_acceptance_authorized(policy),
        identity_handoff=identity_handoff,
    )


async def drive_signup(
    *,
    page: Any,
    patterns: Sequence[str],
    sensitive_data: Mapping[str, str],
    approved_fields: Mapping[str, object] | None,
    state: SignupSessionState,
    signup_policy: SignupPolicy | None = None,
    resume_signal: str | None = None,
    identity_handoff: str | None = None,
) -> SignupResult:
    """Fill and submit one reviewed signup form, at most once.

    ``state.submit_attempted`` is set *before* the click.  A click timeout is an
    outcome-unknown failure and is never retried, which prevents duplicate vendor
    accounts after a slow response.

    ``identity_handoff`` names the one identity provider the operator authorized
    this deployment to fall back to when the vendor refuses the email path
    outright; ``None`` keeps the original behavior, where such a route stops for
    a human. See :data:`_IDENTITY_HANDOFF_PROVIDERS` for what the authorization
    does and does not permit.
    """

    if not navigation_allowed(_page_url(page), tuple(patterns)):
        return SignupResult(status="failed", reason_code="signup_origin_unsafe")
    if identity_handoff is not None and identity_handoff not in _IDENTITY_HANDOFF_PROVIDERS:
        # An unrecognized provider name is a misconfiguration, and the safe
        # reading of a misconfigured authorization is that nothing was authorized.
        LOGGER.warning("ignoring unknown identity handoff provider %r", identity_handoff)
        identity_handoff = None
    fields = normalize_signup_fields(approved_fields)
    if signup_policy is None:
        return await _drive_email_password_signup(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            resume_signal=resume_signal,
            identity_handoff=identity_handoff,
        )
    if signup_policy.flow == "email_first":
        return await _drive_email_first_signup(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            policy=signup_policy,
            resume_signal=resume_signal,
            identity_handoff=identity_handoff,
        )
    if signup_policy.flow != "dom_detected":
        return SignupResult(status="failed", reason_code="signup_policy_unsupported")
    return await _drive_dom_detected_signup(
        page=page,
        patterns=patterns,
        sensitive_data=sensitive_data,
        fields=fields,
        state=state,
        policy=signup_policy,
        resume_signal=resume_signal,
        identity_handoff=identity_handoff,
    )


async def _drive_email_password_signup(
    *,
    page: Any,
    patterns: Sequence[str],
    sensitive_data: Mapping[str, str],
    fields: Mapping[str, str],
    state: SignupSessionState,
    resume_signal: str | None,
    researched: bool = False,
    accept_legal: bool = False,
    identity_handoff: str | None = None,
) -> SignupResult:
    """Fill and submit one single-step email-and-password registration form.

    ``researched`` marks a route that came from research rather than review. It
    changes nothing about which page or form is acceptable; it only allows the
    form's own submit control to be resolved past sibling OAuth buttons, for the
    reason :func:`_own_submit` documents.

    ``accept_legal`` is the partner-catalog authorization; it defaults off so the
    recipe-less path reached directly from :func:`drive_signup` keeps handing
    acceptance to a human.
    """

    if state.human_submit_pending:
        if resume_signal != "human_completed":
            return _legal_submit_gate()
        result = await _classify_after_submit(
            page,
            patterns,
            before_path=state.pending_submit_path,
        )
        if result.reason_code == "signup_postcondition_unverified":
            return _legal_submit_gate(reason_code="legal_submission_not_observed")
        # The human, not the agent, owned the acceptance-bearing submit. Record
        # completion only after the reviewed path transition or typed gate proves
        # that the page advanced.
        state.submit_attempted = True
        state.human_submit_pending = False
        state.pending_submit_path = None
        return result
    if state.submit_attempted:
        return await _classify_after_submit(
            page,
            patterns,
            before_path=state.submitted_path,
        )
    email = sensitive_data.get("login_email")
    password = sensitive_data.get("login_password")
    if not state.form_filled and (not email or not password):
        return SignupResult(
            status="human_action_required",
            reason_code="signup_credentials_required",
            action_type="provider_verification",
            instruction="Signup requires the configured email identity and generated password.",
        )

    surfaces = await _email_password_surfaces(page, patterns)
    if not surfaces:
        return SignupResult(
            status="human_action_required",
            reason_code="signup_surface_not_supported",
            action_type="provider_verification",
            instruction=(
                "The reviewed signup page does not expose one unambiguous email-and-password "
                "form. Complete this vendor-specific step in the live browser."
            ),
        )
    if len(surfaces) != 1:
        return SignupResult(status="failed", reason_code="multiple_signup_surfaces")

    surface, form, email_field, password_fields = surfaces[0]
    if not await _form_action_allowed(
        form,
        surface_url=surface.frame_url or _page_url(page),
        patterns=patterns,
    ):
        return SignupResult(status="failed", reason_code="signup_form_action_unsafe")

    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=False,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate

    if len(password_fields) == 2:
        second_marker = await _field_marker(password_fields[1])
        if _CONFIRM_PASSWORD.search(second_marker) is None:
            return SignupResult(status="failed", reason_code="password_confirmation_ambiguous")

    if state.form_filled:
        # Do not read values back into Python. A boolean DOM check proves that the
        # same live session still contains the previously injected credentials.
        try:
            present = bool(await email_field.evaluate("element => Boolean(element.value)"))
            present = present and all(
                [
                    bool(await field.evaluate("element => Boolean(element.value)"))
                    for field in password_fields
                ]
            )
        except Exception:
            present = False
        if not present:
            return SignupResult(
                status="human_action_required",
                reason_code="signup_credentials_required",
                action_type="provider_verification",
                instruction=(
                    "The signup form no longer contains the configured credentials. "
                    "Restart the signup attempt."
                ),
            )
    else:
        assert email is not None and password is not None
        try:
            await email_field.fill(email, timeout=5_000)
            await password_fields[0].fill(password, timeout=5_000)
            if len(password_fields) == 2:
                await password_fields[1].fill(password, timeout=5_000)
        except Exception:
            return SignupResult(status="failed", reason_code="signup_secret_injection_failed")
        state.form_filled = True

    field_result = await _fill_company_fields(form, fields)
    if field_result is not None:
        return field_result

    gate = await _human_gate_before_fill(
        page,
        form,
        include_legal=True,
        accept_legal=accept_legal,
        resume_signal=resume_signal,
        state=state,
    )
    if gate is not None:
        return gate

    if await _unfilled_required_control(form):
        return SignupResult(
            status="human_action_required",
            reason_code="signup_required_field_unknown",
            action_type="provider_verification",
            instruction="Complete the remaining required signup field in the live browser.",
        )

    submit_status, submit = await _unique_visible(form, _SUBMIT_SELECTOR)
    if submit_status != "unique" and researched:
        # Sibling OAuth buttons inside the same form make the plain count read
        # "ambiguous" for a form with one real submit action. Reviewed recipes
        # keep the plain count; only a researched route looks past them.
        submit_status, submit = await _own_submit(form)
    if submit_status == "missing" or submit is None:
        if identity_handoff is not None:
            handoff = await _drive_identity_handoff(
                page=page,
                form=form,
                provider=identity_handoff,
                patterns=patterns,
                state=state,
            )
            if handoff is not None:
                return handoff
        return SignupResult(
            status="human_action_required",
            reason_code="signup_submit_not_found",
            action_type="provider_verification",
            instruction="Review and submit the completed signup form in the live browser.",
        )
    if submit_status == "ambiguous":
        return SignupResult(status="failed", reason_code="signup_submit_ambiguous")
    submit_text = await _submit_text(submit)
    if _BILLING_WORDS.search(submit_text):
        return SignupResult(
            status="human_action_required",
            reason_code="billing_required",
            action_type="billing",
            instruction="Review the payment or subscription action in the live browser.",
        )
    if _LEGAL_WORDS.search(submit_text) or await _form_implies_legal_acceptance(form):
        if not accept_legal:
            state.human_submit_pending = True
            state.pending_submit_path = _current_path(page)
            return _legal_submit_gate()
        _record_acceptance(state, f"submit: {submit_text}")

    # Nothing has been submitted yet, so an obstruction here is recoverable.
    # Check it BEFORE the one-shot state below: past that line the run can never
    # try again, because a timed-out click may still have registered.
    if not await _await_clickable(submit, budget_seconds=_SURFACE_RENDER_BUDGET_SECONDS):
        return await _submit_obstructed_gate()

    # Set before the click: a timeout may mean the server accepted registration.
    # Retrying would risk a duplicate account.
    state.submit_attempted = True
    state.submitted_path = _current_path(page)
    try:
        await submit.click(timeout=10_000)
    except Exception as error:
        # This outcome is terminal by design -- the click may have registered, so
        # it is never retried -- which makes the swallowed cause the only thing
        # that could explain it later. Record the class and message; a Playwright
        # actionability failure names the obstruction, and no typed value reaches
        # here to be leaked.
        LOGGER.warning(
            "signup submit click did not complete: %s: %s",
            type(error).__name__,
            str(error)[:2000],
        )
        return SignupResult(status="failed", reason_code="signup_submit_outcome_unknown")
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    return await _classify_after_submit(
        page,
        patterns,
        before_path=state.submitted_path,
    )


# --- the signup phase (Requirement 6) ---------------------------------------
#
# Everything above drives one form inside the browser. What follows is the phase
# the driver dispatches: the ordering that makes a crashed signup recoverable.
#
# The ordering is the whole requirement, and it reads in one direction:
#
#   generate -> stage in the vault -> one reference per field -> one grant per
#   fill -> reserve the signup operation key -> submit -> record completion ->
#   commit ``email_verification``
#
# Every arrow is there because reversing it loses something. Storing before
# submitting is Requirement 6.2: a crash mid-submit can otherwise leave a real
# provider account whose password nobody holds. Reserving the operation key
# before submitting is Requirement 6.4: the reservation is what makes a second
# worker skip rather than create a second account. Committing
# ``email_verification`` before the first verification search is Requirement
# 6.10, and the driver does that from the returned :class:`PhaseStep` — this
# handler commits nothing (Requirement 4.20).
#
# Deriving the operation key is *not* reserving it, which is why the key is
# derived first and presented to the ledger last: derivation is a pure function
# of durable facts (:func:`ops.onboarding.effects.signup_submit_key`) and the
# grants need it to name themselves.
#
# No value is returned to the orchestrator (Requirement 6.6). The generated pair
# exists here for exactly as long as it takes to hand it to the vault; from that
# point on this module holds references and grants, and a reference is redeemed
# once, inside the browser process, through the broker (Requirement 6.5).

SIGNUP_LOGIN_FIELDS: Final[tuple[str, ...]] = ("login_email", "login_password")

# The transient vault kinds the broker already allows for a login fill. Reused
# rather than extended: a new kind would be a new secret path to review.
_TRANSIENT_LOGIN_KINDS: Final[dict[str, str]] = {
    field_name: f"browser_login_{field_name}" for field_name in SIGNUP_LOGIN_FIELDS
}

# How long a staged reference and its grant stay redeemable. Long enough for one
# reviewed form walk, short enough that an abandoned run leaves nothing usable.
SIGNUP_SECRET_TTL_SECONDS: Final = 600

# Receipt key per login field. Spelled out rather than derived because the effect
# ledger refuses a receipt whose *key* looks secret-shaped, and it is right to:
# a key named ``login_password_reference_id`` is one refactor away from carrying a
# password. These two keys carry a vault reference id and nothing else.
_RECEIPT_KEYS: Final[dict[str, str]] = {
    "login_email": "login_email_reference_id",
    "login_password": "login_pw_reference_id",  # pragma: allowlist secret
}

# A generated vendor password: a fixed complexity prefix so a provider's own
# policy check cannot reject it, plus 24 bytes from the system CSPRNG. Same
# construction the existing signup path uses, so there is one generator.
_PASSWORD_PREFIX: Final = "Rr7!"
_PASSWORD_ENTROPY_BYTES: Final = 24

# What the submitter observed, mapped onto the closed reason vocabulary. A gate
# other than CAPTCHA pauses: its disposition belongs to the gate-resolution seam,
# not to this handler.
_GATE_REASON_CODES: Final[dict[str, OnboardingReasonCode]] = {
    "captcha": "captcha_detected",
    "billing": "billing_required",
}

SignupSubmissionStatus = Literal[
    "submitted",
    "duplicate_account",
    "human_action_required",
    "outcome_unknown",
    "failed",
]


@dataclass(frozen=True, slots=True)
class SignupIdentity:
    """The durable bindings one signup attempt runs under. Carries no value.

    ``account_ref`` is the mailbox identity the admission probe already used, so
    the signup operation key and the vault rows agree with what the run was
    admitted for. ``signup_address`` is the address the generated identity is
    built from — durable configuration, never a value this module invents.
    """

    account_ref: str
    session_id: str
    signup_address: str

    @property
    def verification_recipient(self) -> str:
        """The canonical alias the verification search binds to (Requirement 7.3)."""

        canonical = canonical_address(self.signup_address)
        if canonical is None:
            raise ValueError("a signup identity requires one parseable signup address")
        return canonical.address


@dataclass(frozen=True, slots=True)
class SignupSecretFill:
    """One field's authorization to be typed once into the live page.

    Deliberately value-free: a reference names a one-time vault row and a grant
    names one exact broker operation over it. Both are safe to hold, log by id,
    and hand across the browser RPC; neither can be turned back into a value on
    this side (Requirements 6.3, 6.5, 6.6).
    """

    field: str
    kind: str
    reference: str
    grant: str

    @property
    def reference_id(self) -> str:
        """The trailing identifier of the reference, for a non-secret receipt."""

        return self.reference.rsplit("/", 1)[-1]


@dataclass(frozen=True, slots=True)
class StagedSignupCredentials:
    """The signup credentials as they exist once storage has happened.

    Holding this value *is* the proof Requirement 6.2 asks for: it cannot be
    constructed without one vault reference per field, so a submit that takes it
    as an argument cannot run before the credentials are durable.
    """

    account_ref: str
    operation_key: str
    fills: tuple[SignupSecretFill, ...]

    def __post_init__(self) -> None:
        if tuple(fill.field for fill in self.fills) != SIGNUP_LOGIN_FIELDS:
            raise ValueError("a staged signup carries exactly one fill per login field")
        if not all(fill.reference and fill.grant for fill in self.fills):
            raise ValueError("a staged signup fill requires a reference and a grant")

    def references(self) -> dict[str, str]:
        """Field name -> one-time vault reference. No value is present."""

        return {fill.field: fill.reference for fill in self.fills}

    def receipt(self) -> dict[str, str]:
        """The non-secret identifiers the effect completion records."""

        receipt = {"account_ref": self.account_ref}
        receipt.update({_RECEIPT_KEYS[fill.field]: fill.reference_id for fill in self.fills})
        return receipt


@dataclass(frozen=True, slots=True)
class SignupSubmission:
    """What the browser reported about the one submission it was asked to make.

    ``failed`` means the attempt provably did not reach the provider, which is
    the only failure that may be retried; anything ambiguous is
    ``outcome_unknown`` and authorizes nothing further (Requirement 13.10).
    """

    status: SignupSubmissionStatus
    human_action_type: SignupActionType | None = None
    receipt: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status == "human_action_required" and self.human_action_type is None:
            raise ValueError("a signup gate names the human action it requires")


class SignupCredentialVault(Protocol):
    """The vault operations one signup needs, and no others.

    Structurally satisfied by :class:`ops.core.secret_store.SQLiteSecretStore`. There
    is no read verb here on purpose: this module writes the pair, takes back
    references, and can never resolve one.
    """

    def stage_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str, email: str, password: str
    ) -> dict[str, str]:
        """Atomically stage one generated pair under this exact run."""

    def get_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> dict[str, str]:
        """This run's already-staged pair, or an empty mapping."""

    def promote_staged_signup_login_pair(
        self, *, app_slug: str, account_ref: str, run_id: str
    ) -> tuple[str, ...]:
        """Promote the staged pair into the reusable account scope."""

    def put_transient(
        self, *, app_slug: str, kind: str, scope_id: str, value: str, ttl_seconds: int = 600
    ) -> str:
        """Store one one-time, run-scoped value and return its reference."""

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
        """Reserve one exact broker operation and return its opaque grant."""


class SignupRunBinding(Protocol):
    """Where the handler learns the run's durable bindings."""

    def signup_identity(self, *, run_id: str) -> SignupIdentity:
        """The account binding, browser session, and signup address for this run."""


class SignupMailboxBinder(Protocol):
    """Where the run's expected verification recipient is recorded.

    One write verb: the address the ``email_verification`` phase binds its search
    to is the alias this signup submitted under, so the operation key and the
    recipient cannot name different accounts (Requirements 7.3, 7.4).
    """

    def bind_verification_recipient(self, *, run_id: str, session_id: str, address: str) -> None:
        """Record the canonical mailbox alias this run verifies on."""


class SignupSubmitter(Protocol):
    """The browser seam: fill the reviewed form from grants, submit it once."""

    async def observe_signup(self) -> PageInspection:
        """A fresh, bounded inspection of the page the submission landed on."""

    async def submit_signup(
        self,
        *,
        run_id: str,
        session_id: str,
        fills: Sequence[SignupSecretFill],
        fields: Mapping[str, str],
    ) -> SignupSubmission:
        """Fill and submit the reviewed signup form exactly once.

        PRE:  every fill carries a live one-time reference and its grant; the
              operation key is already reserved.
        POST: the returned status classifies the provider's response, and no
              credential value is returned to the caller (Requirement 6.6).
        """


def generate_signup_credentials(*, signup_address: str) -> dict[str, str]:
    """Generate the signup identity and its password (Requirement 6.1).

    The address is durable configuration — the mailbox the verification search
    will read — and the password comes from the system CSPRNG through
    :mod:`secrets`. Nothing here is derived from a clock, a counter, or page
    text, so a generated pair is never guessable from anything the run exposes.
    """

    address = signup_address.strip()
    if not address:
        raise ValueError("a signup identity requires a configured signup address")
    return {
        "login_email": address,
        "login_password": f"{_PASSWORD_PREFIX}{secrets.token_urlsafe(_PASSWORD_ENTROPY_BYTES)}",
    }


def stage_signup_credentials(
    *,
    vault: SignupCredentialVault,
    run_id: str,
    profile: ProviderProfile,
    identity: SignupIdentity,
    operation_key: str,
    ttl_seconds: int = SIGNUP_SECRET_TTL_SECONDS,
) -> StagedSignupCredentials:
    """Store the signup pair and take back one reference and one grant per field.

    PRE:  ``operation_key`` was derived from durable facts only; no submission
          has been reserved yet.
    POST: the pair is durable in the vault, and the returned value carries one
          one-time reference and one grant per login field and no value at all
          (Requirements 6.2, 6.3, 6.5).

    A resumed run re-reads its own staged pair rather than generating a second
    one: staging is keyed by ``(app_slug, account_ref)`` and owned by this run,
    so the identity a retry submits is the identity the first attempt stored.
    """

    staged = dict(
        vault.get_staged_signup_login_pair(
            app_slug=profile.app_slug, account_ref=identity.account_ref, run_id=run_id
        )
    )
    if set(staged) != set(SIGNUP_LOGIN_FIELDS):
        generated = generate_signup_credentials(signup_address=identity.signup_address)
        staged = dict(
            vault.stage_signup_login_pair(
                app_slug=profile.app_slug,
                account_ref=identity.account_ref,
                run_id=run_id,
                email=generated["login_email"],
                password=generated["login_password"],
            )
        )
    if set(staged) != set(SIGNUP_LOGIN_FIELDS):
        raise ValueError("the staged signup pair is incomplete")

    fills: list[SignupSecretFill] = []
    for field_name in SIGNUP_LOGIN_FIELDS:
        kind = _TRANSIENT_LOGIN_KINDS[field_name]
        # The value crosses into the vault here and is never read back: from the
        # next line on, this process holds a reference and a grant only.
        reference = vault.put_transient(
            app_slug=profile.app_slug,
            kind=kind,
            scope_id=run_id,
            value=staged[field_name],
            ttl_seconds=ttl_seconds,
        )
        grant = vault.reserve_browser_secret_grant(
            # One grant per fill (Requirement 6.5), named after the submission it
            # belongs to so a re-reservation after a lost response is the same
            # grant rather than a second one.
            operation_key=f"{operation_key}:consume:{field_name}",
            run_id=run_id,
            session_id=identity.session_id,
            app_slug=profile.app_slug,
            kind=kind,
            action="consume",
            reference=reference,
        )
        fills.append(
            SignupSecretFill(field=field_name, kind=kind, reference=reference, grant=grant)
        )
    staged.clear()
    return StagedSignupCredentials(
        account_ref=identity.account_ref, operation_key=operation_key, fills=tuple(fills)
    )


@dataclass(frozen=True, slots=True)
class _PausedSignupSession:
    """The bound session id a signup CAPTCHA pause records, and nothing else.

    The submitter owns the live session; all the pause path may do is read its id
    (Requirement 11.4), so this one-member value is what crosses rather than a
    handle that could release the session the operator is about to work in.
    """

    session_id: str


def _paused_session_conformance(session: _PausedSignupSession) -> PausedSession:
    """Typecheck-only proof that the id carrier satisfies the pause port."""

    return session


def declared_signup_policy(app_slug: str) -> SignupPolicy | None:
    """The reviewed signup policy one app's recipe declares, or ``None`` (7.1, 7.2)."""

    recipe = get_app_recipe(app_slug)
    browser = None if recipe is None else recipe.browser
    return None if browser is None else browser.signup


def declared_signup_postcondition(app_slug: str) -> CheckpointPredicate | None:
    """The recipe's own completion predicate for the signup step (Requirement 7.5).

    The signup step is the declared step whose target lies under the policy's own
    entry prefixes. ``None`` means the recipe declares no signup step, so there is
    no declared postcondition to hold the submission against — an invented one
    would pause runs on a bar no reviewer set.
    """

    recipe = get_app_recipe(app_slug)
    browser = None if recipe is None else recipe.browser
    if browser is None or browser.signup is None:
        return None
    step = next(
        (
            candidate
            for candidate in browser.steps
            if candidate.target_url is not None
            and _path_matches(_url_path(candidate.target_url), browser.signup.entry_path_prefixes)
        ),
        None,
    )
    return None if step is None else recipe_predicate(step.completion)


async def enter_signup(
    *,
    run_id: str,
    phase: OnboardingPhase,
    profile: ProviderProfile | None,
    lease: Lease,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Gate ``route_selected_signup -> signup`` on the same policy read (7.1, 7.2).

    An app whose recipe declares no signup policy never enters the phase, so it
    never stages a credential either.
    """

    if phase != "route_selected_signup":
        raise ValueError("the signup admission gate drives route_selected_signup only")
    if profile is None:
        return PhaseStep.pause("capture_spec_unavailable")
    if declared_signup_policy(profile.app_slug) is None:
        return PhaseStep.pause("signup_policy_absent")
    return PhaseStep.advance("signup", "operator_approved_signup")


@dataclass(frozen=True, slots=True)
class SignupPhaseHandler:
    """The ``signup`` phase, as a :class:`~ops.onboarding.driver.PhaseHandler`.

    Registered in ``OnboardingDeps.handlers`` under ``"signup"``, which is how a
    phase with provider-visible ordering takes over from the generic loop
    dispatch. It returns a :class:`~ops.onboarding.driver.PhaseStep` and commits
    nothing: the driver is the only committer (Requirement 4.20), and it is the
    driver that therefore makes ``email_verification`` durable before the first
    verification search runs (Requirement 6.10).
    """

    vault: SignupCredentialVault
    effects: EffectStore
    binding: SignupRunBinding
    submitter: SignupSubmitter
    # Where the verification recipient is recorded. Optional for the reason the
    # driver's own mailbox ports are: a deployment that never verifies by email
    # needs nothing wired, and an unwired binder records nothing rather than
    # inventing a recipient.
    mailbox: SignupMailboxBinder | None = None
    approved_fields: Mapping[str, str] = field(default_factory=dict)
    ttl_seconds: int = SIGNUP_SECRET_TTL_SECONDS

    async def __call__(
        self,
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        """Drive one signup attempt and report the transition it earned.

        PRE:  ``phase == "signup"`` and its boundary is durably committed (the
              driver refuses to enter an effect-bearing phase otherwise), and
              ``profile`` carries the signup URL the key is derived from.
        POST: at most one signup submission exists for this run, and a returned
              ``advance`` into ``email_verification`` implies the effect
              completion was recorded first (Requirements 6.4, 6.9, 6.10).
        """

        if phase != "signup":
            raise ValueError("the signup handler drives the signup phase only")
        if profile is None or profile.signup_url is None:
            # Neither the allow-list nor the operation key can be derived without
            # a profile that names where signup happens.
            return PhaseStep.pause("capture_spec_unavailable")
        # Requirements 7.1, 7.2: read before staging and before the reservation, so
        # a refusal leaves no staged credential and no vault entry behind.
        if declared_signup_policy(profile.app_slug) is None:
            return PhaseStep.pause("signup_policy_absent")

        identity = self.binding.signup_identity(run_id=run_id)
        recipient = identity.verification_recipient
        # Derivation, not reservation: pure in the run, the profile digest, the
        # canonicalized signup URL, and the account binding (Requirement 6.11).
        operation_key = signup_submit_key(run_id, profile, identity.account_ref)

        # Requirement 6.2: storage happens here, strictly before the reservation
        # and the submit below.
        staged = stage_signup_credentials(
            vault=self.vault,
            run_id=run_id,
            profile=profile,
            identity=identity,
            operation_key=operation_key,
            ttl_seconds=self.ttl_seconds,
        )

        # Requirement 6.4: the submission is reserved before it is made.
        plan = plan_effect(self.effects, operation_key=operation_key, action="signup_submit")
        if self.mailbox is not None:
            # Requirements 7.3, 7.4: bound as the effect is reserved, from the same
            # identity the key names, so the search and the key agree on the account.
            self.mailbox.bind_verification_recipient(
                run_id=run_id, session_id=identity.session_id, address=recipient
            )
        if plan.disposition == "skip":
            # A submission already happened under this key. Adopt it rather than
            # creating a second account.
            self._promote(run_id=run_id, profile=profile, identity=identity)
            return PhaseStep.advance("email_verification", "signup_submitted")
        if plan.disposition != "execute":
            # ``reconcile`` and ``pause_outcome_unknown`` both mean a prior
            # attempt may have reached the provider; neither authorizes a resend.
            return PhaseStep.pause(plan.reason_code)

        submission = await self.submitter.submit_signup(
            run_id=run_id,
            session_id=identity.session_id,
            fills=staged.fills,
            fields=dict(self.approved_fields),
        )
        return await self._step_for(
            submission,
            run_id=run_id,
            profile=profile,
            identity=identity,
            staged=staged,
            plan=plan,
            deps=deps,
        )

    async def _step_for(
        self,
        submission: SignupSubmission,
        *,
        run_id: str,
        profile: ProviderProfile,
        identity: SignupIdentity,
        staged: StagedSignupCredentials,
        plan: EffectPlan,
        deps: OnboardingDeps | None = None,
    ) -> PhaseStep:
        """Turn one submission outcome into the transition it earned."""

        if submission.status == "submitted":
            # Requirement 6.9, before the phase advances: the completion is what
            # makes every later arrival skip instead of submitting again.
            receipt = {**staged.receipt(), **dict(submission.receipt)}
            complete_effect(self.effects, plan, receipt=receipt)
            self._promote(run_id=run_id, profile=profile, identity=identity)
            # Requirements 7.5, 7.6, after the completion write: the submission did
            # reach the provider, so an unmet postcondition must pause a run whose
            # retry skips rather than create a second account.
            if not await self._postcondition_met(profile.app_slug):
                return PhaseStep.pause("signup_postcondition_unmet")
            return PhaseStep.advance("email_verification", "signup_submitted")
        if submission.status == "duplicate_account":
            # The submission reached the provider and was answered, so the effect
            # is complete; the account already exists and its credentials are the
            # ones this run stored, so the login route can take over with no
            # operator prompt (Requirements 6.7, 6.8).
            complete_effect(self.effects, plan, receipt=staged.receipt())
            self._promote(run_id=run_id, profile=profile, identity=identity)
            return PhaseStep.advance("route_selected_login", "signup_rejected_duplicate_account")
        if submission.status == "human_action_required":
            action = submission.human_action_type
            reason = _GATE_REASON_CODES.get(action or "", "postcondition_failed")
            if action == "captcha":
                # The one mid-flight operator prompt that exists. Taken through the
                # driver's pause path when a pause store is wired, so the phase at
                # pause is durable and the prompt is counted before the boundary is
                # committed — without that record a resume has no phase to re-enter
                # (Requirements 11.2, 11.3, 11.10).
                pauses = None if deps is None else deps.pauses
                if pauses is not None:
                    return await pause_for_captcha(
                        run_id=run_id,
                        phase_at_pause="signup",
                        session=_PausedSignupSession(identity.session_id),
                        pauses=pauses,
                        budget=(deps.captcha_budget if deps else None) or DEFAULT_CAPTCHA_BUDGET,
                    )
                return PhaseStep.advance("captcha_paused", reason)
            return PhaseStep.pause(reason)
        if submission.status == "failed":
            # Provably did not reach the provider, so the key may be retried.
            mark_effect_failed(self.effects, plan)
            return PhaseStep.pause("postcondition_failed")
        mark_effect_outcome_unknown(self.effects, plan)
        return PhaseStep.pause("outcome_unknown")

    async def _postcondition_met(self, app_slug: str) -> bool:
        """Whether the recipe's signup completion holds on a fresh observation."""

        predicate = declared_signup_postcondition(app_slug)
        if predicate is None:
            return True
        return predicate_satisfied(predicate, await self.submitter.observe_signup())

    def _promote(self, *, run_id: str, profile: ProviderProfile, identity: SignupIdentity) -> None:
        """Promote the staged pair into the reusable account scope.

        Idempotent, and deliberately best-effort: the pair is already durable in
        the staged scope, so a promotion that fails costs reuse on a later run
        and never the account this run just created.
        """

        try:
            self.vault.promote_staged_signup_login_pair(
                app_slug=profile.app_slug, account_ref=identity.account_ref, run_id=run_id
            )
        except Exception:
            LOGGER.info(
                "signup credential promotion for run %s did not complete; the staged pair stands",
                run_id,
            )


def _handler_conformance(handler: SignupPhaseHandler) -> PhaseHandler:
    """Typecheck-only proof that the handler satisfies the driver's port."""

    return handler


def _admission_conformance() -> PhaseHandler:
    """Typecheck-only proof that the admission gate satisfies the same port."""

    return enter_signup


__all__ = [
    "SIGNUP_LOGIN_FIELDS",
    "SIGNUP_SECRET_TTL_SECONDS",
    "SignupCredentialVault",
    "SignupIdentity",
    "SignupMailboxBinder",
    "SignupPhaseHandler",
    "SignupResult",
    "SignupRunBinding",
    "SignupSecretFill",
    "SignupSessionState",
    "SignupSubmission",
    "SignupSubmissionStatus",
    "SignupSubmitter",
    "StagedSignupCredentials",
    "declared_signup_policy",
    "declared_signup_postcondition",
    "drive_signup",
    "enter_signup",
    "generate_signup_credentials",
    "normalize_signup_fields",
    "signup_secret_continuation_ready",
    "stage_signup_credentials",
]
