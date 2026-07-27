"""Value-free signup form models and deterministic semantic resolution.

Part 12 resolves controls in a fixed priority order and requires exactly one
compatible match. This module has no Playwright dependency and never represents
an input value, raw HTML, coordinate, XPath, or model-generated selector.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops.automation_contracts import (
    ContractSignup,
    ContractSignupFieldHints,
    SignupSemanticField,
)

SignupMatchStrategy = Literal[
    "reviewed_test_id",
    "accessible_label",
    "accessible_role_name",
    "associated_label",
    "placeholder",
    "reviewed_nearby_heading",
]
SignupControlKind = Literal["text", "email", "password", "select", "combobox", "button"]
SignupInspectionStatus = Literal["detected", "safe_stop"]
SignupFillStatus = Literal["filled", "configuration_required", "failed"]

SIGNUP_FIELD_ORDER: tuple[SignupSemanticField, ...] = (
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
    "signup_submit",
)

_TOKEN = re.compile(r"^sf_[0-9a-f]{32}$")

_CANONICAL_NAMES: dict[SignupSemanticField, tuple[str, ...]] = {
    "email": ("email", "email address", "work email", "business email"),
    "password": ("password", "create password", "new password"),
    "password_confirmation": (
        "confirm password",
        "password confirmation",
        "repeat password",
        "re-enter password",
        "retype password",
    ),
    "first_name": ("first name", "given name"),
    "last_name": ("last name", "family name", "surname"),
    "full_name": ("full name", "your name", "name"),
    "company_name": ("company", "company name", "organization", "organization name"),
    "website": ("website", "company website", "organization website", "website url"),
    "workspace_name": (
        "workspace",
        "workspace name",
        "account name",
        "organization slug",
        "team name",
    ),
    "country": ("country", "country or region", "country/region", "region"),
    "role_title": ("role", "title", "job title", "your role"),
    "signup_submit": ("sign up", "signup", "create account", "register", "create my account"),
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class SignupControlCandidate(_StrictModel):
    """Value-free metadata for one visible signup control."""

    token: str
    control_kind: SignupControlKind
    role: str = Field(default="", max_length=50)
    accessible_name: str = Field(default="", max_length=200)
    aria_label: str = Field(default="", max_length=200)
    associated_labels: tuple[str, ...] = Field(default=(), max_length=8)
    placeholder: str = Field(default="", max_length=200)
    nearby_headings: tuple[str, ...] = Field(default=(), max_length=8)
    test_id: str = Field(default="", max_length=160)
    required: bool = False
    disabled: bool = False
    visible: bool = True

    @field_validator("token")
    @classmethod
    def _token_was_generated_by_code(cls, value: str) -> str:
        if _TOKEN.fullmatch(value) is None:
            raise ValueError("signup control token is invalid")
        return value

    @field_validator("associated_labels", "nearby_headings")
    @classmethod
    def _bounded_text_collections(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 200 or "\x00" in item for item in values):
            raise ValueError("signup control metadata is invalid")
        return tuple(dict.fromkeys(values))


class SignupFieldMatch(_StrictModel):
    semantic_field: SignupSemanticField
    token: str
    strategy: SignupMatchStrategy
    control_kind: SignupControlKind
    required: bool

    @field_validator("token")
    @classmethod
    def _token_is_bounded(cls, value: str) -> str:
        if _TOKEN.fullmatch(value) is None:
            raise ValueError("signup control token is invalid")
        return value


class SignupFormInspection(_StrictModel):
    """Structured, value-free output of Part 12."""

    status: SignupInspectionStatus
    reason_code: str = Field(pattern=r"^[a-z0-9_:-]+$", max_length=100)
    contract_version: str = Field(min_length=1, max_length=64)
    fields: tuple[SignupFieldMatch, ...] = Field(default=(), max_length=20)
    missing_required_fields: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    ambiguous_fields: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    unmapped_required_controls: int = Field(default=0, ge=0, le=80)
    password_fields_present: bool = False
    screenshot_capture_allowed: bool = True

    @model_validator(mode="after")
    def _matches_are_unique(self) -> SignupFormInspection:
        semantic = [field.semantic_field for field in self.fields]
        tokens = [field.token for field in self.fields]
        if len(semantic) != len(set(semantic)) or len(tokens) != len(set(tokens)):
            raise ValueError("signup inspection contains duplicate field bindings")
        if self.status == "detected":
            if (
                self.missing_required_fields
                or self.ambiguous_fields
                or self.unmapped_required_controls
            ):
                raise ValueError("detected signup form cannot contain unresolved fields")
            if "signup_submit" not in semantic:
                raise ValueError("detected signup form requires one submit control")
        return self

    def match_for(self, semantic_field: SignupSemanticField) -> SignupFieldMatch | None:
        return next(
            (field for field in self.fields if field.semantic_field == semantic_field),
            None,
        )

    def prompt_safe_projection(self) -> dict[str, object]:
        """Optional model input containing mapping facts only, never run values."""

        return {
            "contract_version": self.contract_version,
            "status": self.status,
            "matched_fields": [
                {
                    "semantic_field": field.semantic_field,
                    "strategy": field.strategy,
                    "control_kind": field.control_kind,
                    "required": field.required,
                }
                for field in self.fields
            ],
            "missing_required_fields": list(self.missing_required_fields),
            "ambiguous_fields": list(self.ambiguous_fields),
            "unmapped_required_controls": self.unmapped_required_controls,
        }


class SignupFillResult(_StrictModel):
    """Value-free output of Part 13. Submit is deliberately untouched."""

    status: SignupFillStatus
    reason_code: str = Field(pattern=r"^[a-z0-9_:-]+$", max_length=100)
    contract_version: str = Field(min_length=1, max_length=64)
    filled_fields: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    verified_fields: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    missing_values: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    screenshots_disabled: bool
    submit_clicked: bool = False

    @model_validator(mode="after")
    def _submission_is_never_part_of_this_phase(self) -> SignupFillResult:
        if self.submit_clicked:
            raise ValueError("Parts 12-13 must not submit the signup form")
        if "signup_submit" in self.filled_fields or "signup_submit" in self.verified_fields:
            raise ValueError("the submit control is verified by inspection, not filled")
        if self.status == "filled":
            if not self.filled_fields:
                raise ValueError("a filled signup result requires at least one field")
            if set(self.filled_fields) != set(self.verified_fields):
                raise ValueError("every filled signup field must be verified")
            if (
                {"password", "password_confirmation"} & set(self.filled_fields)
                and not self.screenshots_disabled
            ):
                raise ValueError("password-filled results require screenshots disabled")
        return self


def detect_signup_form(
    candidates: Sequence[SignupControlCandidate],
    signup: ContractSignup,
    contract_version: str,
) -> SignupFormInspection:
    """Resolve every supported semantic field in the mandated priority order."""

    viable = tuple(
        candidate
        for candidate in candidates
        if candidate.visible and not candidate.disabled
    )
    required = set(signup.required_semantic_fields)
    required.add("signup_submit")
    fields: list[SignupFieldMatch] = []
    ambiguous: list[SignupSemanticField] = []
    missing: list[SignupSemanticField] = []
    claimed_tokens: set[str] = set()

    for semantic_field in SIGNUP_FIELD_ORDER:
        hints = signup.field_hints.get(semantic_field, ContractSignupFieldHints())
        resolution = _resolve_field(viable, semantic_field, hints)
        if resolution is None:
            if semantic_field in required:
                missing.append(semantic_field)
            continue
        strategy, matches = resolution
        if len(matches) != 1:
            ambiguous.append(semantic_field)
            continue
        candidate = matches[0]
        if candidate.token in claimed_tokens:
            ambiguous.append(semantic_field)
            continue
        claimed_tokens.add(candidate.token)
        fields.append(
            SignupFieldMatch(
                semantic_field=semantic_field,
                token=candidate.token,
                strategy=strategy,
                control_kind=candidate.control_kind,
                required=semantic_field in required or candidate.required,
            )
        )

    unmapped_required = sum(
        1
        for candidate in viable
        if candidate.required and candidate.token not in claimed_tokens
    )
    password_present = any(
        field.semantic_field in {"password", "password_confirmation"}
        for field in fields
    )
    if ambiguous:
        return SignupFormInspection(
            status="safe_stop",
            reason_code="signup_field_ambiguous",
            contract_version=contract_version,
            fields=tuple(fields),
            missing_required_fields=tuple(missing),
            ambiguous_fields=tuple(dict.fromkeys(ambiguous)),
            unmapped_required_controls=unmapped_required,
            password_fields_present=password_present,
        )
    if missing:
        return SignupFormInspection(
            status="safe_stop",
            reason_code="required_signup_field_missing",
            contract_version=contract_version,
            fields=tuple(fields),
            missing_required_fields=tuple(missing),
            unmapped_required_controls=unmapped_required,
            password_fields_present=password_present,
        )
    if unmapped_required:
        return SignupFormInspection(
            status="safe_stop",
            reason_code="unmapped_required_signup_control",
            contract_version=contract_version,
            fields=tuple(fields),
            unmapped_required_controls=unmapped_required,
            password_fields_present=password_present,
        )
    return SignupFormInspection(
        status="detected",
        reason_code="signup_form_detected",
        contract_version=contract_version,
        fields=tuple(fields),
        password_fields_present=password_present,
    )


def _resolve_field(
    candidates: Sequence[SignupControlCandidate],
    semantic_field: SignupSemanticField,
    hints: ContractSignupFieldHints,
) -> tuple[SignupMatchStrategy, tuple[SignupControlCandidate, ...]] | None:
    compatible = tuple(
        candidate
        for candidate in candidates
        if _control_compatible(semantic_field, candidate.control_kind)
    )
    canonical_names = {
        _normalize_text(name)
        for name in _CANONICAL_NAMES[semantic_field] + hints.accessible_names
    }
    placeholder_names = {
        _normalize_text(name)
        for name in _CANONICAL_NAMES[semantic_field] + hints.placeholders
    }
    reviewed_test_ids = set(hints.reviewed_test_ids)
    reviewed_headings = {_normalize_text(item) for item in hints.nearby_headings}

    strategies: tuple[
        tuple[SignupMatchStrategy, Callable[[SignupControlCandidate], bool]], ...
    ] = (
        (
            "reviewed_test_id",
            lambda candidate: bool(candidate.test_id)
            and candidate.test_id in reviewed_test_ids,
        ),
        (
            "accessible_label",
            lambda candidate: bool(candidate.aria_label)
            and _normalize_text(candidate.aria_label) in canonical_names,
        ),
        (
            "accessible_role_name",
            lambda candidate: bool(candidate.accessible_name)
            and _normalize_text(candidate.accessible_name) in canonical_names,
        ),
        (
            "associated_label",
            lambda candidate: any(
                _normalize_text(label) in canonical_names
                for label in candidate.associated_labels
            ),
        ),
        (
            "placeholder",
            lambda candidate: bool(candidate.placeholder)
            and _normalize_text(candidate.placeholder) in placeholder_names,
        ),
        (
            "reviewed_nearby_heading",
            lambda candidate: bool(reviewed_headings)
            and any(
                _normalize_text(heading) in reviewed_headings
                for heading in candidate.nearby_headings
            ),
        ),
    )
    for strategy, predicate in strategies:
        matches = tuple(candidate for candidate in compatible if predicate(candidate))
        if matches:
            return strategy, matches
    return None


def _control_compatible(
    semantic_field: SignupSemanticField,
    control_kind: SignupControlKind,
) -> bool:
    if semantic_field == "signup_submit":
        return control_kind == "button"
    if semantic_field in {"password", "password_confirmation"}:
        return control_kind == "password"
    if semantic_field == "email":
        return control_kind in {"email", "text"}
    if semantic_field in {"country", "role_title"}:
        return control_kind in {"text", "select", "combobox"}
    return control_kind == "text"


def _normalize_text(value: str) -> str:
    return " ".join(value.casefold().split())


__all__ = [
    "SIGNUP_FIELD_ORDER",
    "SignupControlCandidate",
    "SignupFieldMatch",
    "SignupFillResult",
    "SignupFormInspection",
    "SignupMatchStrategy",
    "detect_signup_form",
]
