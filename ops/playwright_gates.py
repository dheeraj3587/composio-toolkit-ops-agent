"""Recognizing a genuine human gate from page STRUCTURE, not from page text.

Substring matching on body text produced false positives: a footer "Terms of
Service" link or a passive reCAPTCHA badge would halt an otherwise healthy run. So a
gate is recognized only when the page presents an ACTIONABLE surface — an
interactive challenge widget or reviewed challenge iframe, a visible input that
collects the challenge, or a real choice control such as account selection or an
explicit consent button. Passive mentions of a gate keyword are ignored.

The iframe rule is the subtle one and is kept deliberately narrow: provider pages
commonly embed a visible reCAPTCHA anchor/badge iframe before any challenge exists,
so for iframes the frame must show evidence of being the actual challenge or
checkbox surface. The name "reCAPTCHA" alone is intentionally insufficient, because
treating it as a gate would preempt a perfectly usable login form.
"""

from __future__ import annotations

import re

from ops.browser_decider import SnapshotElement
from ops.browser_worker import BrowserObservation, HumanActionType
from ops.model_input_dlp import sanitize_reason
from ops.playwright_page_inspection import PageInspection

# Page text that indicates a hard human gate the agent must never try to solve.
_HUMAN_GATE_PATTERNS: tuple[tuple[str, HumanActionType], ...] = (
    ("captcha", "captcha"),
    ("recaptcha", "captcha"),
    ("hcaptcha", "captcha"),
    ("i'm not a robot", "captcha"),
    ("verification code", "email_otp"),
    ("one-time code", "email_otp"),
    ("one time passcode", "email_otp"),
    ("enter the code we sent", "email_otp"),
    ("two-factor", "device_approval"),
    ("two factor", "device_approval"),
    ("passkey", "passkey"),
    ("security key", "security_key"),
    ("authenticator app", "device_approval"),
    ("approve this sign-in", "device_approval"),
    ("billing information", "billing"),
    ("payment method", "billing"),
    ("accept the terms", "legal_acceptance"),
    ("terms of service", "legal_acceptance"),
    ("choose an account", "account_selection"),
    ("select an account", "account_selection"),
)


def _classify_gate(text: str) -> HumanActionType:
    """Map gate text to a typed HumanActionType (defaults to provider verification)."""

    lowered = text.casefold()
    for needle, action_type in _HUMAN_GATE_PATTERNS:
        if needle in lowered:
            return action_type
    return "provider_verification"


def detect_human_gate(inspection: PageInspection) -> BrowserObservation | None:
    """Return a typed HITL observation only for a STRUCTURAL human gate (item 8).

    Substring matching on body text produced false positives: a footer "Terms of
    Service" link or a passive reCAPTCHA badge would halt an otherwise fine run. A
    gate is now recognized only when the page presents an ACTIONABLE surface:

    * an interactive challenge widget / reviewed challenge iframe, or
    * a visible input that collects the challenge (an OTP/code field), or
    * a genuine choice control (account selection, an explicit consent button).

    Passive mentions of a gate keyword are ignored.
    """

    gate = classify_structural_gate(inspection)
    if gate is None:
        return None
    action_type, detail = gate
    return BrowserObservation(
        status="human_action_required",
        current_url=inspection.url,
        page_title=inspection.title or "Human action required",
        human_action_type=action_type,
        human_instruction=sanitize_reason(detail)[:1_000],
    )


# Structural gate rules: (matcher on an element, action type, instruction).
_OTP_NAME = re.compile(
    r"(?i)one[-_ ]?time|verification code|security code|\botp\b|passcode|\bcode\b"
)


_CAPTCHA_NAME = re.compile(r"(?i)captcha|i'?m not a robot|are you human")


# Provider pages commonly embed a visible reCAPTCHA anchor/badge iframe even
# before a challenge exists. For iframe snapshots, require evidence that the
# presented frame is the actual challenge/checkbox surface; ``reCAPTCHA`` alone
# is intentionally insufficient.
_ACTIVE_CAPTCHA_IFRAME = re.compile(r"(?i)challenge|checkbox|bframe|i'?m not a robot|are you human")


_CONSENT_NAME = re.compile(
    r"(?i)^(?:i )?(?:agree|accept)\b|accept (?:the )?terms|accept and continue"
)


_ACCOUNT_CHOICE = re.compile(
    r"(?i)choose an account|select an account|use another account|continue as "
)


_BILLING_NAME = re.compile(
    r"(?i)add (?:a )?payment|payment method|card number|billing details|upgrade plan"
)


_PASSKEY_NAME = re.compile(r"(?i)passkey|security key|use your (?:device|fingerprint|face)")


_MFA_NAME = re.compile(
    r"(?i)authenticator|two[- ]factor|2fa|approve (?:this )?sign|verify it'?s you"
)


_INTERACTIVE_ROLES = frozenset(
    {"button", "link", "input", "select", "textarea", "iframe", "menuitem", "a"}
)


def _is_actionable(element: SnapshotElement) -> bool:
    return element.role.casefold() in _INTERACTIVE_ROLES and element.actionable()


def classify_structural_gate(
    inspection: PageInspection,
) -> tuple[HumanActionType, str] | None:
    """Identify a human gate from actionable page STRUCTURE, or None."""

    for element in inspection.elements:
        name = element.name
        element_type = element.element_type.casefold()
        role = element.role.casefold()

        # A provider badge/anchor iframe named only "reCAPTCHA" is passive and
        # must not preempt a real login form. Actual challenge/checkbox frames and
        # ordinary actionable CAPTCHA controls remain human gates.
        captcha_control = role != "iframe" and _CAPTCHA_NAME.search(name)
        captcha_frame = role == "iframe" and _ACTIVE_CAPTCHA_IFRAME.search(name)
        if (captcha_control or captcha_frame) and _is_actionable(element):
            return "captcha", "An interactive CAPTCHA must be completed by a human."

        # A real OTP/code entry field (an input, not prose mentioning a code).
        if element_type in {"text", "tel", "number", "password", ""} and role in {
            "input",
            "textarea",
        }:
            if _OTP_NAME.search(name) or (element.secretish and _OTP_NAME.search(name)):
                return "email_otp", "A one-time verification code must be entered by a human."

        if _PASSKEY_NAME.search(name) and _is_actionable(element):
            return "passkey", "A passkey or security key must be used by a human."

        if _MFA_NAME.search(name) and _is_actionable(element):
            return "device_approval", "A multi-factor approval must be completed by a human."

        if _BILLING_NAME.search(name) and _is_actionable(element):
            return "billing", "A billing decision must be made by a human."

        # Explicit consent CONTROL (a button), not a footer terms LINK.
        if _CONSENT_NAME.search(name) and role in {"button", "input"}:
            return "legal_acceptance", "Legal acceptance must be granted by a human."

        if _ACCOUNT_CHOICE.search(name) and _is_actionable(element):
            return "account_selection", "An account choice must be made by a human."

    return None
