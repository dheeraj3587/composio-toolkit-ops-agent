"""Value-free detection of human gates on a prepared signup surface.

This module inspects only visible control metadata and accessibility names. It
never reads input values, raw HTML, cookies, storage state, or secret references.
A failed control inspection safe-stops because silently dropping one control
could hide a legal, billing, phone, ownership, or CAPTCHA gate.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ops.automation_contracts import BrowserAutomationContract

SubmissionGate = Literal[
    "captcha",
    "legal_acceptance",
    "billing",
    "phone_verification",
    "ownership_or_admin_change",
]

_ARIA_LINE = re.compile(
    r'^\s*-\s+(?P<role>[A-Za-z][A-Za-z0-9_-]*)'
    r'(?:\s+"(?P<name>(?:[^"\\]|\\.)*)")?'
)
_MAX_GATE_CONTROLS = 120
_GATE_SELECTOR = (
    "input:not([type='hidden']), button, select, textarea, label, iframe, "
    "[role='checkbox'], [role='button'], [role='dialog'], [role='alert'], "
    "[role='heading']"
)
_GATE_METADATA_SCRIPT = r"""
(el) => {
  const clean = (value) => {
    if (typeof value !== "string") return "";
    return value.replace(/\s+/g, " ").trim().slice(0, 240);
  };
  return {
    tag: (el.tagName || "").toLowerCase(),
    type: (typeof el.type === "string" ? el.type : el.getAttribute("type") || "")
      .toLowerCase(),
    role: (el.getAttribute("role") || "").toLowerCase(),
    autocomplete: (el.getAttribute("autocomplete") || "").toLowerCase(),
    name: clean(el.getAttribute("name") || ""),
    id: clean(el.getAttribute("id") || ""),
    ariaLabel: clean(el.getAttribute("aria-label") || ""),
    placeholder: clean(el.getAttribute("placeholder") || ""),
    title: clean(el.getAttribute("title") || ""),
    src: clean(el.getAttribute("src") || ""),
    text: clean(el.textContent || ""),
    required: el.required === true || el.getAttribute("aria-required") === "true",
  };
}
"""


class SignupGatePage(Protocol):
    def locator(self, selector: str) -> Any: ...


class SignupSubmissionGateInspection(BaseModel):
    """Sanitized gate findings immediately before signup submission."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    status: Literal["clear", "gated", "safe_stop"]
    reason_code: str = Field(pattern=r"^[a-z0-9_:-]+$", max_length=100)
    present_gates: tuple[SubmissionGate, ...] = Field(default=(), max_length=5)
    inspected_controls: int = Field(default=0, ge=0, le=_MAX_GATE_CONTROLS)

    @model_validator(mode="after")
    def _status_matches_gates(self) -> SignupSubmissionGateInspection:
        if self.status == "clear" and self.present_gates:
            raise ValueError("a clear gate inspection cannot contain gates")
        if self.status == "gated" and not self.present_gates:
            raise ValueError("a gated inspection requires at least one gate")
        return self


async def inspect_signup_submission_gates(
    page: SignupGatePage,
    contract: BrowserAutomationContract,
) -> SignupSubmissionGateInspection:
    """Inspect visible controls for hard human gates without reading values."""

    try:
        contract.assert_usable()
    except Exception:
        return SignupSubmissionGateInspection(
            status="safe_stop",
            reason_code="signup_gate_contract_invalid",
        )
    try:
        locators = await page.locator(_GATE_SELECTOR).all()
    except Exception:
        return SignupSubmissionGateInspection(
            status="safe_stop",
            reason_code="signup_gate_surface_unavailable",
        )
    if len(locators) > _MAX_GATE_CONTROLS:
        return SignupSubmissionGateInspection(
            status="safe_stop",
            reason_code="signup_gate_surface_too_large",
        )

    signatures: list[tuple[dict[str, object], str]] = []
    for locator in locators:
        try:
            if not await locator.is_visible():
                continue
            metadata = await locator.evaluate(_GATE_METADATA_SCRIPT)
            if not isinstance(metadata, Mapping):
                raise TypeError("gate metadata is not a mapping")
            role, accessible_name = _parse_aria_snapshot(
                await locator.aria_snapshot(timeout=2_000)
            )
            material = " ".join(
                str(metadata.get(key) or "")
                for key in (
                    "tag",
                    "type",
                    "role",
                    "autocomplete",
                    "name",
                    "id",
                    "ariaLabel",
                    "placeholder",
                    "title",
                    "src",
                    "text",
                )
            )
            signatures.append(
                (
                    dict(metadata),
                    _normalize(f"{material} {role} {accessible_name}"),
                )
            )
        except Exception:
            return SignupSubmissionGateInspection(
                status="safe_stop",
                reason_code="signup_gate_inspection_failed",
                inspected_controls=len(signatures),
            )

    gates: set[SubmissionGate] = set()
    captcha_tokens = _normalized_predicates(contract.signup.captcha_predicates)
    phone_tokens = _normalized_predicates(
        contract.signup.phone_verification_predicates
    )
    legal_billing_tokens = _normalized_predicates(
        contract.signup.legal_billing_predicates
    )

    for metadata, signature in signatures:
        tag = str(metadata.get("tag") or "").casefold()
        element_type = str(metadata.get("type") or "").casefold()
        role = str(metadata.get("role") or "").casefold()
        autocomplete = str(metadata.get("autocomplete") or "").casefold()
        required = bool(metadata.get("required"))

        if _looks_like_captcha(
            signature,
            tag=tag,
            source=str(metadata.get("src") or ""),
            title=str(metadata.get("title") or ""),
        ) or _matches_any(signature, captcha_tokens):
            gates.add("captcha")

        if _looks_like_legal_acceptance(signature, tag=tag, role=role):
            gates.add("legal_acceptance")
        if _looks_like_billing(
            signature,
            element_type=element_type,
            autocomplete=autocomplete,
        ):
            gates.add("billing")
        if _looks_like_phone_gate(
            signature,
            element_type=element_type,
            autocomplete=autocomplete,
            required=required,
        ) or _matches_any(signature, phone_tokens):
            gates.add("phone_verification")
        if _looks_like_ownership_or_admin(signature):
            gates.add("ownership_or_admin_change")

        _apply_legal_billing_predicates(
            gates,
            signature=signature,
            predicates=legal_billing_tokens,
        )

    ordered: tuple[SubmissionGate, ...] = tuple(
        gate
        for gate in (
            "captcha",
            "legal_acceptance",
            "billing",
            "phone_verification",
            "ownership_or_admin_change",
        )
        if gate in gates
    )
    if ordered:
        return SignupSubmissionGateInspection(
            status="gated",
            reason_code="signup_submission_gate_present",
            present_gates=ordered,
            inspected_controls=len(signatures),
        )
    return SignupSubmissionGateInspection(
        status="clear",
        reason_code="signup_submission_gates_clear",
        inspected_controls=len(signatures),
    )


def _apply_legal_billing_predicates(
    gates: set[SubmissionGate],
    *,
    signature: str,
    predicates: tuple[str, ...],
) -> None:
    for predicate in predicates:
        if not predicate or predicate not in signature:
            continue
        legal = _contains_any(
            predicate,
            ("agree", "terms", "privacy", "consent", "legal"),
        )
        billing = _contains_any(
            predicate,
            (
                "billing",
                "payment",
                "card",
                "purchase",
                "subscribe",
                "upgrade",
            ),
        )
        # An under-specified combined predicate fails closed as both categories.
        if not legal and not billing:
            legal = billing = True
        if legal:
            gates.add("legal_acceptance")
        if billing:
            gates.add("billing")


def _parse_aria_snapshot(snapshot: object) -> tuple[str, str]:
    if not isinstance(snapshot, str):
        return "", ""
    first = next((line for line in snapshot.splitlines() if line.strip()), "")
    match = _ARIA_LINE.match(first)
    if match is None:
        return "", ""
    role = (match.group("role") or "").casefold()
    encoded_name = match.group("name")
    if not encoded_name:
        return role, ""
    try:
        name = json.loads(f'"{encoded_name}"')
    except json.JSONDecodeError:
        name = encoded_name
    return role[:50], str(name).strip()[:240]


def _normalized_predicates(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        item
        for item in dict.fromkeys(_normalize(value) for value in values)
        if item
    )


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _matches_any(signature: str, predicates: tuple[str, ...]) -> bool:
    return any(predicate and predicate in signature for predicate in predicates)


def _contains_any(value: str, tokens: tuple[str, ...]) -> bool:
    return any(token in value for token in tokens)


def _looks_like_captcha(
    signature: str,
    *,
    tag: str,
    source: str,
    title: str,
) -> bool:
    explicit_markers = (
        "i m not a robot",
        "verify you are human",
        "are you human",
        "complete the captcha",
        "security challenge",
    )
    if _contains_any(signature, explicit_markers):
        return True
    if tag != "iframe":
        return _contains_any(signature, ("hcaptcha challenge", "turnstile challenge"))

    raw_metadata = f"{source} {title}".casefold()
    visible_recaptcha_anchor = (
        "/anchor" in raw_metadata
        and re.search(r"(?:[?&])size=invisible(?:[&#]|$)", raw_metadata) is None
    )
    active_frame = _contains_any(
        raw_metadata,
        ("/bframe", "challenge", "checkbox", "i'm not a robot"),
    )
    return visible_recaptcha_anchor or active_frame


def _looks_like_legal_acceptance(
    signature: str,
    *,
    tag: str,
    role: str,
) -> bool:
    if tag not in {"input", "button", "label"} and role not in {
        "checkbox",
        "button",
    }:
        return False
    return _contains_any(
        signature,
        (
            "i agree",
            "agree to",
            "accept terms",
            "terms of service",
            "privacy policy",
            "legal consent",
        ),
    )


def _looks_like_billing(
    signature: str,
    *,
    element_type: str,
    autocomplete: str,
) -> bool:
    if autocomplete.startswith("cc-"):
        return True
    if element_type in {"number", "text", "password"} and _contains_any(
        signature,
        ("card number", "security code", "cvv", "cvc", "expiry"),
    ):
        return True
    return _contains_any(
        signature,
        (
            "payment method",
            "billing information",
            "add payment",
            "purchase",
            "subscribe",
            "upgrade plan",
        ),
    )


def _looks_like_phone_gate(
    signature: str,
    *,
    element_type: str,
    autocomplete: str,
    required: bool,
) -> bool:
    if required and (element_type == "tel" or autocomplete.startswith("tel")):
        return True
    return _contains_any(
        signature,
        (
            "verify phone",
            "phone verification",
            "mobile verification",
            "sms code",
            "text message code",
        ),
    )


def _looks_like_ownership_or_admin(signature: str) -> bool:
    return _contains_any(
        signature,
        (
            "transfer ownership",
            "make admin",
            "grant administrator",
            "change owner",
        ),
    )


__all__ = [
    "SignupSubmissionGateInspection",
    "SubmissionGate",
    "inspect_signup_submission_gates",
]
