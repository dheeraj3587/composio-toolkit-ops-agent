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
from typing import get_args

from ops.browser.decider import SnapshotElement
from ops.browser.worker import BrowserObservation, HumanActionType
from ops.core.model_input_dlp import sanitize_reason
from ops.playwright.page_inspection import PageInspection
from ops.recipes.app_recipes import HitlGate

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


# Split deliberately. A passkey is a SOFTWARE credential a headless context can
# satisfy (CDP can attach a virtual authenticator); a security key is physical
# hardware that no automation can produce. Matched by one pattern they were one
# gate, so unblocking the solvable half would have silently unblocked the
# unsolvable one. Security key is checked first because "use your security key"
# also contains a passkey-ish phrase on several providers.
_SECURITY_KEY_NAME = re.compile(r"(?i)security key|hardware key|\byubikey\b|insert your key")


_PASSKEY_NAME = re.compile(r"(?i)passkey|use your (?:device|fingerprint|face)")


# An OAuth/OIDC consent screen. This is the "Allow"/"Authorize"/"Grant access"
# control a provider shows when one application asks for access to an account —
# NOT a terms-of-service acceptance, which is why it does not fold into
# _CONSENT_NAME: legal_acceptance is recipe-declarable and would have let a
# declared ToS acceptance auto-click "Allow this app to read your data". The gate
# is named oauth_GRANT rather than oauth_consent because driver.py asserts at
# import that no HumanActionType member contains "consent" — that assertion is
# what keeps a cookie/consent banner from ever becoming an operator prompt.
# Anchored or access-qualified so an ordinary "Allow notifications" prompt or a
# nav link reading "Authorized apps" is not mistaken for the grant button.
_OAUTH_GRANT = re.compile(
    r"(?i)^allow$|^authorize$|^allow access\b|^grant access\b"
    r"|(?:allow|authorize|grant)\b[^.]{0,60}\baccess\b"
    r"|^(?:allow|authorize)\b[^.]{0,60}\bto (?:access|view|manage)\b"
)


_MFA_NAME = re.compile(
    r"(?i)authenticator|two[- ]factor|2fa|approve (?:this )?sign|verify it'?s you"
)


# A handoff to a THIRD-PARTY identity provider. Deliberately not "any sign-in
# control": the deterministic login machine exists to drive an ordinary
# email/password form, and classifying that as a gate would halt precisely the
# runs this agent is meant to complete. What it cannot drive is a federated
# bounce to Google/Okta/SAML, which leaves the reviewed host, renders a form
# nobody reviewed, and carries its own MFA. So an identity provider must be
# NAMED — "Continue with email" is a local path and stays automatable.
_IDENTITY_PROVIDER = (
    r"(?:google|microsoft|azure|apple|github|gitlab|okta|auth0|facebook|linkedin"
    r"|slack|saml|sso|single sign[- ]?on|your (?:company|work|organization) account)"
)


_FEDERATED_LOGIN = re.compile(
    rf"(?i)(?:(?:sign|log)\s?(?:in|on)|continue|proceed)\s+with\s+{_IDENTITY_PROVIDER}\b"
    rf"|\b(?:use|via)\s+(?:sso|single sign[- ]?on)\b"
    rf"|^single sign[- ]?on$"
)


# A local credential form the login machine CAN drive. Its presence is what
# demotes a federated button from "the only way in" to "one option among two".
_LOCAL_CREDENTIAL_NAME = re.compile(r"(?i)e-?mail|user\s?name|\bpassword\b|\blogin\b")


def _has_local_credential_form(inspection: PageInspection) -> bool:
    """True when the page offers an email/username/password field code can fill."""

    for element in inspection.elements:
        if element.role.casefold() not in {"input", "textarea"}:
            continue
        if element.secretish or element.element_type.casefold() in {"password", "email"}:
            return True
        if _LOCAL_CREDENTIAL_NAME.search(element.name):
            return True
    return False


_INTERACTIVE_ROLES = frozenset(
    {"button", "link", "input", "select", "textarea", "iframe", "menuitem", "a"}
)


def _is_actionable(element: SnapshotElement) -> bool:
    return element.role.casefold() in _INTERACTIVE_ROLES and element.actionable()


def classify_structural_gate(
    inspection: PageInspection,
) -> tuple[HumanActionType, str] | None:
    """Identify a human gate from actionable page STRUCTURE, or None."""

    # Computed once over the whole page, because the federated-login rule below
    # is a statement about the page's ONLY way in, not about one button.
    federated_is_the_only_way_in = not _has_local_credential_form(inspection)

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

        if _SECURITY_KEY_NAME.search(name) and _is_actionable(element):
            return "security_key", "A hardware security key must be used by a human."

        if _PASSKEY_NAME.search(name) and _is_actionable(element):
            return "passkey", "A passkey must be used by a human."

        # Checked before the terms-acceptance rule: "Allow"/"Authorize" is an
        # access grant, not a legal acceptance, and the two resolve differently.
        if _OAUTH_GRANT.search(name) and role in {"button", "input"}:
            return (
                "oauth_grant",
                "An application access grant must be authorized by a human.",
            )

        if _MFA_NAME.search(name) and _is_actionable(element):
            return "device_approval", "A multi-factor approval must be completed by a human."

        if _BILLING_NAME.search(name) and _is_actionable(element):
            return "billing", "A billing decision must be made by a human."

        # Explicit consent CONTROL (a button), not a footer terms LINK.
        if _CONSENT_NAME.search(name) and role in {"button", "input"}:
            return "legal_acceptance", "Legal acceptance must be granted by a human."

        if _ACCOUNT_CHOICE.search(name) and _is_actionable(element):
            return "account_selection", "An account choice must be made by a human."

        # LAST, and the weakest rule here: every gate above is a more specific
        # reading of the same page, so a federated button next to a CAPTCHA is a
        # CAPTCHA. Gated on the whole-page check so a signup form that merely
        # OFFERS "Continue with Google" beside its own email field is not halted.
        if (
            federated_is_the_only_way_in
            and _FEDERATED_LOGIN.search(name)
            and _is_actionable(element)
        ):
            return (
                "login_required",
                "Sign-in through the provider's identity provider must be completed by a human.",
            )

    return None


# --- The two gate vocabularies, reconciled -----------------------------------
#
# ``HumanActionType`` is the RUNTIME vocabulary (what a live page was classified
# as); ``HitlGate`` is the RECIPE-AUTHORING one (what a reviewer wrote down that a
# step is expected to hit). They were named independently and disagree —
# ``legal_acceptance``/``legal_consent`` and ``device_approval``/``mfa`` are the
# same concepts under different spellings — so nothing could check a run's actual
# gate against the gate its recipe predicted.
#
# The map is deliberately LOSSY and one-way-checked. The recipe vocabulary is
# coarser: it has no member for an OAuth access grant, and it folds every second
# factor into ``mfa``, so ``phone_otp``, ``passkey`` and ``security_key`` all land
# on ``mfa`` and cannot be recovered from it. ``None`` means "no recipe-declarable
# equivalent" and is a real answer, not a gap: ``login_required`` and
# ``provider_verification`` are runtime dispositions, and ``signup_authorization``
# is a pre-execution business decision no reviewer annotates a step with.
GATE_TO_HITL_GATE: dict[HumanActionType, HitlGate | None] = {
    "captcha": "captcha",
    "email_otp": "email_verification",
    "phone_otp": "mfa",
    "passkey": "mfa",
    "security_key": "mfa",
    "device_approval": "device_approval",
    "legal_acceptance": "legal_consent",
    "billing": "billing",
    "account_selection": "account_selection",
    "oauth_grant": None,
    "login_required": None,
    "provider_verification": None,
    "signup_authorization": None,
}

# The reverse reading, for asking "which runtime gate would satisfy this declared
# one". ``mfa`` resolves to ``device_approval`` because that is the only one of
# its three runtime spellings a recipe can currently mean without naming hardware.
HITL_GATE_TO_GATE: dict[HitlGate, HumanActionType] = {
    "captcha": "captcha",
    "mfa": "device_approval",
    "account_selection": "account_selection",
    "device_approval": "device_approval",
    "email_verification": "email_otp",
    "legal_consent": "legal_acceptance",
    "billing": "billing",
}


# Import-time proof that neither vocabulary can drift without this failing: a new
# member on either side lands here rather than in a silently unmapped run.
assert set(GATE_TO_HITL_GATE) == set(get_args(HumanActionType)), (
    "every runtime gate must declare its recipe-vocabulary equivalent, or None"
)
assert set(HITL_GATE_TO_GATE) == set(get_args(HitlGate)), (
    "every recipe-declarable gate must name the runtime gate that satisfies it"
)
assert {gate for gate in GATE_TO_HITL_GATE.values() if gate is not None} <= set(
    get_args(HitlGate)
), "a runtime gate may only map onto a declared recipe gate"
