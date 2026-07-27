"""Live re-verification of required signup fields before submission.

Part 13 verifies values immediately after filling. Part 14 repeats verification
against the live DOM because the page may have rerendered, cleared, or mutated a
field before the irreversible submit click. Secret plaintext is resolved only
inside this function, compared inside the page context, and discarded.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Protocol, cast

from ops.approved_run_values import ApprovedRunValues
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractSelectOption,
    ContractSignupFieldHints,
    SignupSemanticField,
)
from ops.secret_store import SecretStore
from ops.signup_credentials import SignupAccountBinding, SignupCredentialManager
from ops.signup_forms import SignupFillResult, SignupFormInspection

_TOKEN = re.compile(r"^sf_[0-9a-f]{32}$")
_EMAIL = re.compile(r"^[^@\s<>;,]+@[^@\s<>;,]+$")

SecretCaptureGuard = Callable[[], None]


class SignupVerificationPage(Protocol):
    def locator(self, selector: str) -> Any: ...


async def verify_required_signup_fields(
    page: SignupVerificationPage,
    *,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    secret_store: SecretStore,
    credential_manager: SignupCredentialManager,
    account_binding: SignupAccountBinding,
    assert_secret_capture_disabled: SecretCaptureGuard | None = None,
) -> tuple[tuple[SignupSemanticField, ...], str | None]:
    """Return verified semantic fields and a stable failure reason, never values.

    ``ContractSignup`` validates every semantic-field string before this boundary.
    The explicit cast narrows that already-validated tuple for static typing; it
    does not suppress validation or widen the accepted contract vocabulary.
    """

    required = set(
        cast(
            tuple[SignupSemanticField, ...],
            contract.signup.required_semantic_fields,
        )
    )
    required.update(
        field.semantic_field
        for field in inspection.fields
        if field.required and field.semantic_field != "signup_submit"
    )
    required.discard("signup_submit")
    if not required.issubset(set(fill_result.verified_fields)):
        return (), "signup_submit_fields_not_verified"

    secret_required = bool(
        required & {"email", "password", "password_confirmation"}
    )
    if secret_required:
        if assert_secret_capture_disabled is None:
            return (), "signup_secret_capture_guard_missing"
        try:
            # Playwright evaluate arguments may be retained by tracing/HAR/video
            # tooling. The trusted worker must prove those captures are disabled
            # before plaintext is resolved or passed into the page process.
            assert_secret_capture_disabled()
        except Exception:
            return (), "signup_secret_capture_guard_failed"

    values: dict[SignupSemanticField, str | None] = {
        "first_name": approved_values.first_name,
        "last_name": approved_values.last_name,
        "full_name": _full_name(approved_values),
        "company_name": approved_values.legal_name,
        "website": approved_values.company_website,
        "workspace_name": approved_values.workspace_name,
        "country": approved_values.country,
        "role_title": approved_values.job_title,
        "email": None,
        "password": None,
        "password_confirmation": None,
        "signup_submit": None,
    }
    email = ""
    password = ""
    verified: list[SignupSemanticField] = []
    try:
        if "email" in required:
            email = secret_store.get(approved_values.signup_email_ref)
            if not isinstance(email, str) or _EMAIL.fullmatch(email) is None:
                return tuple(verified), "signup_email_unavailable"
            values["email"] = email

        if required & {"password", "password_confirmation"}:
            registered_ref = credential_manager.get_account_password_reference(
                account_binding
            )
            if registered_ref != approved_values.account_password_ref:
                return tuple(verified), "signup_password_binding_mismatch"
            password = secret_store.get(approved_values.account_password_ref)
            if not _password_satisfies(password, contract):
                return tuple(verified), "signup_password_policy_mismatch"
            values["password"] = password
            values["password_confirmation"] = password

        for semantic in _ordered_required(required):
            match = inspection.match_for(semantic)
            if match is None:
                return tuple(verified), "signup_required_control_missing"
            expected = values.get(semantic)
            if expected is None or not str(expected).strip():
                return tuple(verified), "signup_required_value_missing"
            locator = await strict_signup_token_locator(page, match.token)
            if locator is None:
                return tuple(verified), "signup_required_control_stale_or_ambiguous"
            try:
                if match.control_kind == "select":
                    option = contract.signup.field_hints.get(
                        semantic,
                        ContractSignupFieldHints(),
                    ).select_option
                    target, by_label = _resolved_select_target(
                        option,
                        str(expected),
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
                elif match.control_kind == "combobox":
                    return tuple(verified), "custom_combobox_requires_review"
                else:
                    ok = await locator.evaluate(
                        "(el, expected) => "
                        "typeof el.value === 'string' && el.value === expected",
                        str(expected),
                    )
            except Exception:
                return tuple(verified), "signup_required_field_verification_failed"
            if ok is not True:
                return tuple(verified), "signup_required_field_verification_failed"
            verified.append(semantic)
        return tuple(verified), None
    except Exception:
        return tuple(verified), "signup_required_value_resolution_failed"
    finally:
        # Python cannot guarantee zeroization, but plaintext does not survive in a
        # result model, log, checkpoint, ledger receipt, or object field.
        email = ""
        password = ""
        values["email"] = None
        values["password"] = None
        values["password_confirmation"] = None


async def strict_signup_token_locator(
    page: SignupVerificationPage,
    token: str,
) -> Any | None:
    """Resolve one trusted token to exactly one visible, enabled control."""

    if _TOKEN.fullmatch(token) is None:
        return None
    locator = page.locator(f'[data-ops-signup-ref="{token}"]')
    try:
        if await locator.count() != 1:
            return None
        if not await locator.is_visible() or await locator.is_disabled():
            return None
    except Exception:
        return None
    return locator


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


def _ordered_required(
    required: set[SignupSemanticField],
) -> tuple[SignupSemanticField, ...]:
    order: tuple[SignupSemanticField, ...] = (
        "email",
        "password",
        "password_confirmation",
        "first_name",
        "last_name",
        "full_name",
        "company_name",
        "website",
        "workspace_name",
        "country",
        "role_title",
    )
    return tuple(field for field in order if field in required)


def _password_satisfies(
    password: object,
    contract: BrowserAutomationContract,
) -> bool:
    if not isinstance(password, str):
        return False
    policy = contract.signup.password_policy
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
    "SecretCaptureGuard",
    "strict_signup_token_locator",
    "verify_required_signup_fields",
]
