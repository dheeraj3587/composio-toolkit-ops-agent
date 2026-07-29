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

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urljoin, urlsplit

from ops.browser_login import inspect_login, reviewed_login_surfaces, visible_login_challenge
from ops.playwright_page_inspection import _page_url
from ops.playwright_routing import navigation_allowed

if TYPE_CHECKING:
    from ops.app_recipes import SignupPolicy

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
_IMPLICIT_LEGAL_ACCEPTANCE = re.compile(
    r"(?is)\bby\s+(?:signing\s+up|registering|creating|continuing|submitting)\b"
    r".{0,240}\b(?:accept|agree|consent)\b"
)
_BILLING_WORDS = re.compile(
    r"(?i)\b(pay|payment|purchase|subscribe|subscription|checkout|billing|card|upgrade)\b"
)
_CONFIRM_PASSWORD = re.compile(r"(?i)(confirm|repeat|verify|again|confirmation)")


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
    human_submit_pending: bool = False
    pending_submit_path: str | None = None
    submitted_path: str | None = None


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
            from ops.models import validate_https_url

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


def _current_path(page: Any) -> str:
    """Return a value-free normalized path (never query or fragment data)."""

    path = urlsplit(_page_url(page)).path
    return path.rstrip("/") or "/"


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


async def _human_gate_before_fill(
    page: Any,
    form: Any,
    *,
    include_legal: bool,
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
            state.legal_gate_issued = True
            return SignupResult(
                status="human_action_required",
                reason_code="legal_acceptance_required",
                action_type="legal_acceptance",
                instruction=(
                    "Review the vendor terms and choose whether to accept them in the live "
                    "browser. The agent will not accept legal terms."
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
) -> SignupResult:
    """Fill one reviewed password/details continuation after an email-first step."""

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
        state.human_submit_pending = True
        state.pending_submit_path = _current_path(page)
        return _legal_submit_gate()

    state.submit_attempted = True
    state.submitted_path = _current_path(page)
    try:
        await submit.click(timeout=10_000)
    except Exception:
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
) -> SignupResult:
    """Drive a reviewed email-first registration without accepting legal terms."""

    if state.email_step_completed:
        return await _drive_password_continuation(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            resume_signal=resume_signal,
        )

    # The acceptance-bearing entry submit is always human-owned for Pipedrive.
    # Resume is evidence only when the page positively transitions or exposes the
    # uniquely recognized password continuation.
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
            )
        return result

    if state.email_step_submit_attempted:
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
        if transitioned or result.action_type in {
            "email_otp",
            "phone_otp",
            "billing",
            "account_selection",
        }:
            _complete_email_step(state, legal_reviewed=False)
            if password_surfaces:
                return await _drive_password_continuation(
                    page=page,
                    patterns=patterns,
                    sensitive_data=sensitive_data,
                    fields=fields,
                    state=state,
                    resume_signal=resume_signal,
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
    if submit_status == "missing" or submit is None:
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
        state.legal_gate_issued = True
        state.human_submit_pending = True
        state.pending_submit_path = current_path
        return _legal_submit_gate()

    state.email_step_submit_attempted = True
    state.submitted_path = current_path
    try:
        await submit.click(timeout=10_000)
    except Exception:
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
) -> SignupResult:
    """Fill and submit one reviewed signup form, at most once.

    ``state.submit_attempted`` is set *before* the click.  A click timeout is an
    outcome-unknown failure and is never retried, which prevents duplicate vendor
    accounts after a slow response.
    """

    if not navigation_allowed(_page_url(page), tuple(patterns)):
        return SignupResult(status="failed", reason_code="signup_origin_unsafe")
    fields = normalize_signup_fields(approved_fields)
    if signup_policy is not None:
        if signup_policy.flow != "email_first":
            return SignupResult(status="failed", reason_code="signup_policy_unsupported")
        return await _drive_email_first_signup(
            page=page,
            patterns=patterns,
            sensitive_data=sensitive_data,
            fields=fields,
            state=state,
            policy=signup_policy,
            resume_signal=resume_signal,
        )
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
        # Every password must belong to that same form. Multiple detached/login
        # forms on one page are refused rather than choosing the first.
        form_passwords = await _visible_enabled(form.locator(_PASSWORD_SELECTOR), limit=4)
        if len(form_passwords) != len(passwords):
            continue
        surfaces.append((surface, form, email_field, form_passwords))

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
        state.human_submit_pending = True
        state.pending_submit_path = _current_path(page)
        return _legal_submit_gate()

    # Set before the click: a timeout may mean the server accepted registration.
    # Retrying would risk a duplicate account.
    state.submit_attempted = True
    state.submitted_path = _current_path(page)
    try:
        await submit.click(timeout=10_000)
    except Exception:
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


__all__ = [
    "SignupResult",
    "SignupSessionState",
    "drive_signup",
    "normalize_signup_fields",
    "signup_secret_continuation_ready",
]
