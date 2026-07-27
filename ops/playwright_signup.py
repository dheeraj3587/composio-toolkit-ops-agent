"""Playwright adapter for deterministic signup inspection and filling.

The adapter extracts only value-free control metadata. Secret values are resolved
inside the trusted browser process, screenshots are disabled before injection,
and every filled control is verified without returning its value. Submit is never
clicked in Parts 12-13.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

from ops.approved_run_values import ApprovedRunValues
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractSelectOption,
    ContractSignup,
    ContractSignupFieldHints,
    SignupSemanticField,
)
from ops.signup_credentials import SignupAccountBinding, SignupCredentialManager
from ops.signup_forms import (
    SIGNUP_FIELD_ORDER,
    SignupControlCandidate,
    SignupControlKind,
    SignupFieldMatch,
    SignupFillResult,
    SignupFormInspection,
    detect_signup_form,
)

_CONTROL_SELECTOR = (
    "input:not([type='hidden']), textarea, select, button, "
    "[role='textbox'], [role='combobox'], [role='button']"
)
_TOKEN = re.compile(r"^sf_[0-9a-f]{32}$")
_EMAIL = re.compile(r"^[^@\s<>;,]+@[^@\s<>;,]+$")
_ARIA_LINE = re.compile(
    r'^\s*-\s+(?P<role>[A-Za-z][A-Za-z0-9_-]*)'
    r'(?:\s+"(?P<name>(?:[^"\\]|\\.)*)")?'
)
_MAX_CONTROLS = 80
_ACTION_TIMEOUT_MS = 10_000

_METADATA_SCRIPT = r"""
(el, token) => {
  const clean = (value) => {
    if (typeof value !== "string") return "";
    return value.replace(/\s+/g, " ").trim().slice(0, 200);
  };
  const headings = [];
  let node = el.parentElement;
  for (let depth = 0; node && depth < 4 && headings.length < 8; depth += 1) {
    const legend = node.querySelector(":scope > legend");
    if (legend) headings.push(clean(legend.textContent || ""));
    const directSelector = [
      ":scope > h1",
      ":scope > h2",
      ":scope > h3",
      ":scope > h4",
      ":scope > h5",
      ":scope > h6",
      ":scope > [role='heading']",
    ].join(", ");
    const direct = node.querySelector(directSelector);
    if (direct) headings.push(clean(direct.textContent || ""));
    let sibling = node.previousElementSibling;
    for (let seen = 0; sibling && seen < 3 && headings.length < 8; seen += 1) {
      const tag = (sibling.tagName || "").toLowerCase();
      const role = (sibling.getAttribute("role") || "").toLowerCase();
      if (/^h[1-6]$/.test(tag) || role === "heading") {
        headings.push(clean(sibling.textContent || ""));
      }
      sibling = sibling.previousElementSibling;
    }
    node = node.parentElement;
  }
  el.setAttribute("data-ops-signup-ref", token);
  return {
    tag: (el.tagName || "").toLowerCase(),
    inputType: (el.getAttribute("type") || "").toLowerCase(),
    role: (el.getAttribute("role") || "").toLowerCase(),
    testId: clean(el.getAttribute("data-testid") || ""),
    ariaLabel: clean(el.getAttribute("aria-label") || ""),
    associatedLabels: Array.from(el.labels || [])
      .map((label) => clean(label.textContent || ""))
      .filter(Boolean)
      .slice(0, 8),
    placeholder: clean(el.getAttribute("placeholder") || ""),
    nearbyHeadings: headings.filter(Boolean).slice(0, 8),
    required: el.required === true || el.getAttribute("aria-required") === "true",
    disabled: el.disabled === true || el.getAttribute("aria-disabled") === "true",
  };
}
"""


class PageLike(Protocol):
    def locator(self, selector: str) -> Any: ...


class SignupSecretStore(Protocol):
    def get(self, reference: str) -> str: ...


@dataclass(frozen=True, slots=True)
class _PlannedField:
    match: SignupFieldMatch
    value: str
    select_option: ContractSelectOption | None
    secret: bool


async def inspect_signup_form(
    page: PageLike,
    contract: BrowserAutomationContract,
) -> SignupFormInspection:
    """Inspect a live page through Playwright's accessibility metadata.

    ``Locator.all()`` returns concrete locator objects, so this implementation does
    not enumerate an ambiguous locator with ``nth()``. Each visible element receives
    a random, code-owned token that later filling resolves strictly.
    """

    contract.assert_usable()
    controls = page.locator(_CONTROL_SELECTOR)
    locators = await controls.all()
    if len(locators) > _MAX_CONTROLS:
        return SignupFormInspection(
            status="safe_stop",
            reason_code="signup_surface_too_large",
            contract_version=contract.contract_version,
        )

    candidates: list[SignupControlCandidate] = []
    inspection_failed = False
    for locator in locators:
        try:
            if not await locator.is_visible():
                continue
            token = f"sf_{uuid4().hex}"
            metadata = await locator.evaluate(_METADATA_SCRIPT, token)
            if not isinstance(metadata, Mapping):
                inspection_failed = True
                break
            aria_snapshot = await locator.aria_snapshot(timeout=2_000)
            role, accessible_name = _parse_aria_snapshot(aria_snapshot)
            kind = _control_kind(
                tag=str(metadata.get("tag") or ""),
                input_type=str(metadata.get("inputType") or ""),
                role=role or str(metadata.get("role") or ""),
            )
            if kind is None:
                continue
            candidates.append(
                SignupControlCandidate(
                    token=token,
                    control_kind=kind,
                    role=role or str(metadata.get("role") or ""),
                    accessible_name=accessible_name,
                    aria_label=str(metadata.get("ariaLabel") or ""),
                    associated_labels=tuple(
                        str(item)
                        for item in (metadata.get("associatedLabels") or ())
                        if isinstance(item, str) and item
                    ),
                    placeholder=str(metadata.get("placeholder") or ""),
                    nearby_headings=tuple(
                        str(item)
                        for item in (metadata.get("nearbyHeadings") or ())
                        if isinstance(item, str) and item
                    ),
                    test_id=str(metadata.get("testId") or ""),
                    required=bool(metadata.get("required")),
                    disabled=bool(metadata.get("disabled")),
                    visible=True,
                )
            )
        except Exception:
            # Dropping one control could turn a duplicate into a false unique match.
            # Fail closed and let the caller retry after the DOM stabilizes.
            inspection_failed = True
            break

    if inspection_failed:
        return SignupFormInspection(
            status="safe_stop",
            reason_code="signup_control_inspection_failed",
            contract_version=contract.contract_version,
        )
    return detect_signup_form(candidates, contract.signup, contract.contract_version)


async def fill_signup_form(
    page: PageLike,
    *,
    inspection: SignupFormInspection,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    run_id: str,
    session_id: str,
    secret_store: SignupSecretStore,
    credential_manager: SignupCredentialManager,
    account_binding: SignupAccountBinding,
    disable_screenshots: Callable[[], None],
) -> SignupFillResult:
    """Fill and verify the detected form without clicking its submit control."""

    contract.assert_usable()
    approved_values.assert_binding(run_id=run_id, session_id=session_id)
    if inspection.status != "detected":
        return SignupFillResult(
            status="failed",
            reason_code="signup_form_not_detected",
            contract_version=contract.contract_version,
            screenshots_disabled=False,
        )
    if inspection.contract_version != contract.contract_version:
        return SignupFillResult(
            status="failed",
            reason_code="signup_contract_version_changed",
            contract_version=contract.contract_version,
            screenshots_disabled=False,
        )
    if inspection.match_for("signup_submit") is None:
        return SignupFillResult(
            status="failed",
            reason_code="signup_submit_control_missing",
            contract_version=contract.contract_version,
            screenshots_disabled=False,
        )

    required = set(contract.signup.required_semantic_fields)
    required.update(
        field.semantic_field for field in inspection.fields if field.required
    )
    planned, missing_values, reason = _build_fill_plan(
        inspection=inspection,
        signup=contract.signup,
        approved_values=approved_values,
        required=required,
    )
    if missing_values or reason is not None:
        return SignupFillResult(
            status="configuration_required",
            reason_code=reason or "signup_required_value_missing",
            contract_version=contract.contract_version,
            missing_values=tuple(missing_values),
            screenshots_disabled=False,
        )

    secret_fields = {
        item.match.semantic_field
        for item in planned
        if item.match.semantic_field in {"email", "password", "password_confirmation"}
    }
    screenshots_disabled = False
    email = ""
    password = ""
    secret_tokens_filled: list[str] = []
    filled: list[SignupSemanticField] = []
    verified: list[SignupSemanticField] = []

    try:
        if secret_fields:
            # Masking is defence-in-depth, not the authorization boundary. Once a
            # secret can enter the DOM, capture is disabled for the session.
            disable_screenshots()
            screenshots_disabled = True

        if "email" in secret_fields:
            email = secret_store.get(approved_values.signup_email_ref)
            if not isinstance(email, str) or _EMAIL.fullmatch(email) is None:
                return SignupFillResult(
                    status="configuration_required",
                    reason_code="signup_email_unavailable",
                    contract_version=contract.contract_version,
                    missing_values=("email",),
                    screenshots_disabled=screenshots_disabled,
                )

        if secret_fields & {"password", "password_confirmation"}:
            registered_ref = credential_manager.get_account_password_reference(account_binding)
            if registered_ref != approved_values.account_password_ref:
                return SignupFillResult(
                    status="configuration_required",
                    reason_code="signup_password_binding_mismatch",
                    contract_version=contract.contract_version,
                    missing_values=("password",),
                    screenshots_disabled=screenshots_disabled,
                )
            password = secret_store.get(approved_values.account_password_ref)
            if not _password_satisfies(password, contract.signup):
                return SignupFillResult(
                    status="configuration_required",
                    reason_code="signup_password_policy_mismatch",
                    contract_version=contract.contract_version,
                    missing_values=("password",),
                    screenshots_disabled=screenshots_disabled,
                )

        # Non-secret fields first, then email, then password/confirmation last.
        ordered = sorted(
            planned,
            key=lambda item: (
                item.secret,
                item.match.semantic_field in {"password", "password_confirmation"},
                SIGNUP_FIELD_ORDER.index(item.match.semantic_field),
            ),
        )
        for item in ordered:
            semantic = item.match.semantic_field
            value = (
                email
                if semantic == "email"
                else password
                if semantic in {"password", "password_confirmation"}
                else item.value
            )
            locator = await _strict_token_locator(page, item.match.token)
            if locator is None:
                await _clear_secret_controls(page, secret_tokens_filled)
                return SignupFillResult(
                    status="failed",
                    reason_code="signup_control_stale_or_ambiguous",
                    contract_version=contract.contract_version,
                    filled_fields=tuple(filled),
                    verified_fields=tuple(verified),
                    screenshots_disabled=screenshots_disabled,
                )
            try:
                if item.match.control_kind == "select":
                    target, by_label = _resolved_select_target(item.select_option, value)
                    if by_label:
                        await locator.select_option(
                            label=target,
                            timeout=_ACTION_TIMEOUT_MS,
                        )
                    else:
                        await locator.select_option(
                            value=target,
                            timeout=_ACTION_TIMEOUT_MS,
                        )
                    ok = await locator.evaluate(
                        """(el, args) => {
                          const option = el.options && el.selectedIndex >= 0
                            ? el.options[el.selectedIndex]
                            : null;
                          if (!option) return false;
                          return args.byLabel
                            ? option.label === args.expected
                            : option.value === args.expected;
                        }""",
                        {"expected": target, "byLabel": by_label},
                    )
                elif item.match.control_kind == "combobox":
                    await _clear_secret_controls(page, secret_tokens_filled)
                    return SignupFillResult(
                        status="configuration_required",
                        reason_code="custom_combobox_requires_review",
                        contract_version=contract.contract_version,
                        filled_fields=tuple(filled),
                        verified_fields=tuple(verified),
                        screenshots_disabled=screenshots_disabled,
                    )
                else:
                    await locator.fill(value, timeout=_ACTION_TIMEOUT_MS)
                    ok = await locator.evaluate(
                        "(el, expected) => "
                        "typeof el.value === 'string' && el.value === expected",
                        value,
                    )
            except Exception:
                await _clear_secret_controls(page, secret_tokens_filled)
                return SignupFillResult(
                    status="failed",
                    reason_code="signup_field_fill_failed",
                    contract_version=contract.contract_version,
                    filled_fields=tuple(filled),
                    verified_fields=tuple(verified),
                    screenshots_disabled=screenshots_disabled,
                )
            if semantic in {"email", "password", "password_confirmation"}:
                secret_tokens_filled.append(item.match.token)
            filled.append(semantic)
            if ok is not True:
                await _clear_secret_controls(page, secret_tokens_filled)
                return SignupFillResult(
                    status="failed",
                    reason_code="signup_field_verification_failed",
                    contract_version=contract.contract_version,
                    filled_fields=tuple(filled),
                    verified_fields=tuple(verified),
                    screenshots_disabled=screenshots_disabled,
                )
            verified.append(semantic)

        return SignupFillResult(
            status="filled",
            reason_code="signup_form_filled_and_verified",
            contract_version=contract.contract_version,
            filled_fields=tuple(filled),
            verified_fields=tuple(verified),
            screenshots_disabled=screenshots_disabled,
            submit_clicked=False,
        )
    except Exception:
        await _clear_secret_controls(page, secret_tokens_filled)
        return SignupFillResult(
            status="failed",
            reason_code="signup_value_resolution_failed",
            contract_version=contract.contract_version,
            filled_fields=tuple(filled),
            verified_fields=tuple(verified),
            screenshots_disabled=screenshots_disabled,
        )
    finally:
        # Drop the only local plaintext bindings immediately. Python cannot promise
        # zeroization, but no plaintext is retained on a model, result, log, or ledger.
        email = ""
        password = ""


def _build_fill_plan(
    *,
    inspection: SignupFormInspection,
    signup: ContractSignup,
    approved_values: ApprovedRunValues,
    required: set[str],
) -> tuple[list[_PlannedField], list[SignupSemanticField], str | None]:
    values: dict[SignupSemanticField, str | None] = {
        "email": "__secret_email__",
        "password": "__secret_password__",
        "password_confirmation": "__secret_password__",
        "first_name": approved_values.first_name,
        "last_name": approved_values.last_name,
        "full_name": _full_name(approved_values),
        "company_name": approved_values.legal_name,
        "website": approved_values.company_website,
        "workspace_name": approved_values.workspace_name,
        "country": approved_values.country,
        "role_title": approved_values.job_title,
        "signup_submit": None,
    }
    planned: list[_PlannedField] = []
    missing: list[SignupSemanticField] = []
    for match in inspection.fields:
        semantic = match.semantic_field
        if semantic == "signup_submit":
            continue
        value = values[semantic]
        if value is None or not str(value).strip():
            if semantic in required:
                missing.append(semantic)
            continue
        select_rule = signup.field_hints.get(
            semantic,
            ContractSignupFieldHints(),
        ).select_option
        if match.control_kind in {"select", "combobox"} and select_rule is None:
            return planned, missing, "select_option_not_reviewed"
        planned.append(
            _PlannedField(
                match=match,
                value=str(value),
                select_option=select_rule,
                secret=semantic in {"email", "password", "password_confirmation"},
            )
        )
    return planned, missing, None


def _resolved_select_target(
    option: ContractSelectOption | None,
    approved_value: str,
) -> tuple[str, bool]:
    if option is None:
        raise ValueError("reviewed select option is missing")
    if option.mode == "approved_label":
        return approved_value, True
    if option.mode == "approved_value":
        return approved_value, False
    if option.mode == "fixed_label":
        return str(option.fixed_option), True
    return str(option.fixed_option), False


async def _strict_token_locator(page: PageLike, token: str) -> Any | None:
    if _TOKEN.fullmatch(token) is None:
        return None
    locator = page.locator(f'[data-ops-signup-ref="{token}"]')
    if await locator.count() != 1:
        return None
    if not await locator.is_visible():
        return None
    if await locator.is_disabled():
        return None
    return locator


async def _clear_secret_controls(page: PageLike, tokens: Sequence[str]) -> None:
    for token in dict.fromkeys(tokens):
        try:
            locator = await _strict_token_locator(page, token)
            if locator is not None:
                await locator.fill("", timeout=2_000)
        except Exception:
            continue


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
    return role[:50], str(name).strip()[:200]


def _control_kind(
    *,
    tag: str,
    input_type: str,
    role: str,
) -> SignupControlKind | None:
    normalized_tag = tag.casefold()
    normalized_type = input_type.casefold()
    normalized_role = role.casefold()
    if normalized_tag == "select":
        return "select"
    if normalized_role == "combobox":
        return "combobox"
    if (
        normalized_tag == "button"
        or normalized_role == "button"
        or normalized_type == "submit"
    ):
        return "button"
    if normalized_type == "password":
        return "password"
    if normalized_type == "email":
        return "email"
    if normalized_tag in {"input", "textarea"} or normalized_role == "textbox":
        return "text"
    return None


def _password_satisfies(password: object, signup: ContractSignup) -> bool:
    if not isinstance(password, str):
        return False
    policy = signup.password_policy
    if not policy.min_length <= len(password) <= policy.max_length:
        return False
    if policy.require_lower and not any(character.islower() for character in password):
        return False
    if policy.require_upper and not any(character.isupper() for character in password):
        return False
    if policy.require_digit and not any(character.isdigit() for character in password):
        return False
    if policy.require_symbol and not any(
        character in policy.allowed_symbols for character in password
    ):
        return False
    return True


def _full_name(values: ApprovedRunValues) -> str | None:
    parts = [part for part in (values.first_name, values.last_name) if part]
    return " ".join(parts) if parts else None


__all__ = [
    "fill_signup_form",
    "inspect_signup_form",
]
