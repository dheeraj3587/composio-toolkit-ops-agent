"""Deterministic, value-free classification of post-submit signup outcomes.

Part 15 never asks an LLM whether signup succeeded. It evaluates bounded browser
observations against the active automation contract and a small set of structural
browser facts. The returned model contains only stable outcome metadata; page
text, input values, URLs, selectors, and secret references never leave this
module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ops.automation_contracts import BrowserAutomationContract
from ops.signup_state_machine import SignupState
from ops.signup_submission_gates import SignupSubmissionGateInspection

SignupResultOutcome = Literal[
    "account_created_authenticated",
    "email_verification_required",
    "otp_required",
    "activation_link_required",
    "account_already_exists",
    "password_policy_rejected",
    "captcha_required",
    "phone_verification_required",
    "billing_required",
    "legal_acceptance_required",
    "provider_approval_required",
    "generic_failure",
    "outcome_unknown",
]
SignupResultStatus = Literal["classified", "outcome_unknown", "safe_stop"]
SignupResultNextPhase = Literal[
    "authenticated",
    "gmail_verification",
    "login",
    "hitl",
    "provider_approval",
    "retry_signup",
    "failed",
    "reconcile",
]

_MAX_PAGE_TEXT = 12_000
_MAX_STATUS_TEXT = 4_000
_MAX_ACCESSIBLE_NAMES = 160
_MAX_ACCESSIBLE_NAME = 240
_PREDICATE_PREFIX = re.compile(
    r"^(?P<kind>url_path|title|text|accessible_name|status)\s*:\s*(?P<value>.+)$",
    re.IGNORECASE,
)
_OTP_MARKERS = (
    "one time code",
    "one time password",
    "verification code",
    "enter code",
    "security code",
    "otp",
)
_ACTIVATION_LINK_MARKERS = (
    "activation link",
    "verification link",
    "confirm your email",
    "verify your email",
    "check your inbox",
    "check your email",
    "link has been sent",
)
_PASSWORD_REJECTION_MARKERS = (
    "weak password",
    "password is too short",
    "password too short",
    "password must",
    "password needs",
    "password does not meet",
    "password requirements",
    "choose a stronger password",
)
_PROVIDER_APPROVAL_MARKERS = (
    "pending approval",
    "approval required",
    "administrator approval",
    "admin approval",
    "request submitted for review",
    "under review",
    "provider review",
)
_GENERIC_FAILURE_MARKERS = (
    "something went wrong",
    "unable to create account",
    "could not create account",
    "couldn t create account",
    "signup failed",
    "registration failed",
    "request failed",
    "try again later",
    "temporarily unavailable",
)


@dataclass(frozen=True, slots=True)
class SignupResultObservation:
    """Ephemeral browser facts used by the classifier.

    Text fields may contain ordinary page content and therefore must never be
    logged or persisted. They are excluded from repr and are normalized and
    bounded at construction time.
    """

    page_url: str = field(repr=False)
    title: str = field(repr=False)
    visible_text: str = field(repr=False)
    status_text: str = field(repr=False)
    accessible_names: tuple[str, ...] = field(repr=False)
    native_password_invalid: bool = False
    visible_alert_present: bool = False
    inspected_controls: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "page_url", str(self.page_url)[:2_048])
        object.__setattr__(self, "title", _normalize(self.title)[:500])
        object.__setattr__(
            self,
            "visible_text",
            _normalize(self.visible_text)[:_MAX_PAGE_TEXT],
        )
        object.__setattr__(
            self,
            "status_text",
            _normalize(self.status_text)[:_MAX_STATUS_TEXT],
        )
        names = tuple(
            item
            for item in dict.fromkeys(
                _normalize(name)[:_MAX_ACCESSIBLE_NAME]
                for name in self.accessible_names[:_MAX_ACCESSIBLE_NAMES]
            )
            if item
        )
        object.__setattr__(self, "accessible_names", names)

    @property
    def url_path(self) -> str:
        try:
            path = unquote(urlsplit(self.page_url).path or "/")
        except Exception:
            return "/"
        return path.casefold()[:2_048]

    @property
    def searchable_text(self) -> str:
        return " ".join(
            (
                self.visible_text,
                self.status_text,
                " ".join(self.accessible_names),
            )
        )


class SignupResultClassification(BaseModel):
    """Persistable and API-safe classification output."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    status: SignupResultStatus
    outcome: SignupResultOutcome
    reason_code: str = Field(pattern=r"^[a-z0-9_:-]+$", max_length=120)
    contract_version: str = Field(min_length=1, max_length=64)
    durable_state: SignupState
    next_phase: SignupResultNextPhase
    hitl_required: bool = False
    retryable: bool = False
    matched_contract_group: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9_.+-]+$",
        max_length=100,
    )
    stable_observations: int = Field(default=1, ge=0, le=10)

    @model_validator(mode="after")
    def _classification_is_consistent(self) -> "SignupResultClassification":
        if self.status == "classified" and self.outcome == "outcome_unknown":
            raise ValueError("classified signup result requires a concrete outcome")
        if self.status != "classified" and self.outcome != "outcome_unknown":
            raise ValueError("unresolved signup result must use outcome_unknown")
        if self.next_phase == "hitl" and not self.hitl_required:
            raise ValueError("HITL routing must declare hitl_required")
        if self.durable_state == SignupState.ACCOUNT_CREATED and self.next_phase != "authenticated":
            raise ValueError("account-created state must route to authenticated")
        return self

    def with_stable_observations(self, count: int) -> "SignupResultClassification":
        return self.model_copy(update={"stable_observations": count})

    def prompt_safe_projection(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_none=True)


def classify_signup_result(
    observation: SignupResultObservation,
    contract: BrowserAutomationContract,
    gates: SignupSubmissionGateInspection,
) -> SignupResultClassification:
    """Classify one browser observation without guessing or using an LLM."""

    try:
        contract.assert_usable()
    except Exception:
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_result_contract_inactive",
        )
    if not _url_is_contract_allowed(observation.page_url, contract):
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_result_off_contract_origin",
        )
    if gates.status == "safe_stop":
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code=gates.reason_code,
        )

    evaluated = _evaluate_contract_groups(observation, contract)
    if evaluated.invalid_predicate:
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_result_contract_predicate_invalid",
        )

    candidates: set[SignupResultOutcome] = set()
    groups: dict[SignupResultOutcome, str] = {}

    if "ownership_or_admin_change" in gates.present_gates:
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_ownership_or_admin_change_detected",
        )

    for gate in gates.present_gates:
        outcome = {
            "captcha": "captcha_required",
            "phone_verification": "phone_verification_required",
            "billing": "billing_required",
            "legal_acceptance": "legal_acceptance_required",
        }[gate]
        candidates.add(outcome)
        groups[outcome] = "signup.live_gate"

    if evaluated.captcha:
        candidates.add("captcha_required")
        groups["captcha_required"] = "signup.captcha"
    if evaluated.phone:
        candidates.add("phone_verification_required")
        groups["phone_verification_required"] = "signup.phone_verification"

    if evaluated.account_exists:
        candidates.add("account_already_exists")
        groups["account_already_exists"] = "signup.existing_account"

    verification_outcome, verification_ambiguous = _verification_outcome(
        observation,
        evaluated.verification,
    )
    if verification_ambiguous:
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_verification_type_ambiguous",
        )
    if verification_outcome is not None:
        candidates.add(verification_outcome)
        groups[verification_outcome] = "signup.verification"

    if observation.native_password_invalid or (
        observation.visible_alert_present
        and _contains_any(observation.status_text, _PASSWORD_REJECTION_MARKERS)
    ):
        candidates.add("password_policy_rejected")
        groups["password_policy_rejected"] = "browser.password_validity"

    if (
        contract.routing.production_approval_required is True
        and _contains_any(observation.status_text, _PROVIDER_APPROVAL_MARKERS)
    ):
        candidates.add("provider_approval_required")
        groups["provider_approval_required"] = "routing.production_approval"

    if evaluated.success and evaluated.authenticated:
        candidates.add("account_created_authenticated")
        groups["account_created_authenticated"] = (
            "signup.success+login.authentication_success"
        )

    if evaluated.authentication_failure or (
        observation.visible_alert_present
        and _contains_any(observation.status_text, _GENERIC_FAILURE_MARKERS)
    ):
        candidates.add("generic_failure")
        groups["generic_failure"] = (
            "login.authentication_failure"
            if evaluated.authentication_failure
            else "browser.error_surface"
        )

    # A generic failure is subordinate to a more precise failure or gate.
    if "generic_failure" in candidates and len(candidates) > 1:
        candidates.discard("generic_failure")
        groups.pop("generic_failure", None)

    if len(candidates) > 1:
        return _unresolved(
            contract,
            status="safe_stop",
            reason_code="signup_result_ambiguous",
        )
    if len(candidates) == 1:
        outcome = next(iter(candidates))
        return _classified(
            contract,
            outcome=outcome,
            matched_contract_group=groups.get(outcome),
        )

    if evaluated.success and not evaluated.authenticated:
        return _unresolved(
            contract,
            status="outcome_unknown",
            reason_code="signup_success_without_authentication_proof",
        )
    return _unresolved(
        contract,
        status="outcome_unknown",
        reason_code="signup_result_not_yet_proven",
    )


@dataclass(frozen=True, slots=True)
class _ContractGroupEvaluation:
    success: bool = False
    authenticated: bool = False
    account_exists: bool = False
    verification: bool = False
    captcha: bool = False
    phone: bool = False
    authentication_failure: bool = False
    invalid_predicate: bool = False


def _evaluate_contract_groups(
    observation: SignupResultObservation,
    contract: BrowserAutomationContract,
) -> _ContractGroupEvaluation:
    groups = (
        ("success", contract.signup.success_predicates),
        ("authenticated", contract.login.authentication_success_predicates),
        ("account_exists", contract.signup.existing_account_predicates),
        ("verification", contract.signup.verification_predicates),
        ("captcha", contract.signup.captcha_predicates),
        ("phone", contract.signup.phone_verification_predicates),
        ("authentication_failure", contract.login.authentication_failure_predicates),
    )
    values: dict[str, bool] = {}
    invalid = False
    for name, predicates in groups:
        matched, malformed = _matches_any_contract_predicate(observation, predicates)
        values[name] = matched
        invalid = invalid or malformed
    return _ContractGroupEvaluation(
        success=values["success"],
        authenticated=values["authenticated"],
        account_exists=values["account_exists"],
        verification=values["verification"],
        captcha=values["captcha"],
        phone=values["phone"],
        authentication_failure=values["authentication_failure"],
        invalid_predicate=invalid,
    )


def _matches_any_contract_predicate(
    observation: SignupResultObservation,
    predicates: tuple[str, ...],
) -> tuple[bool, bool]:
    malformed = False
    for raw in predicates:
        parsed = _parse_predicate(raw)
        if parsed is None:
            malformed = True
            continue
        kind, needle = parsed
        haystack = {
            "url_path": observation.url_path,
            "title": observation.title,
            "text": observation.visible_text,
            "accessible_name": " ".join(observation.accessible_names),
            "status": observation.status_text,
        }[kind]
        if needle in haystack:
            return True, malformed
    return False, malformed


def _parse_predicate(raw: str) -> tuple[str, str] | None:
    candidate = raw.strip()
    if not candidate or "\x00" in candidate or len(candidate) > 300:
        return None
    match = _PREDICATE_PREFIX.fullmatch(candidate)
    if match is None:
        needle = _normalize(candidate)
        return ("text", needle) if needle else None
    kind = match.group("kind").casefold()
    value = match.group("value").strip()
    if kind == "url_path":
        if not value.startswith("/") or "?" in value or "#" in value:
            return None
        needle = unquote(value).casefold()
    else:
        needle = _normalize(value)
    if not needle or len(needle) > 240:
        return None
    return kind, needle


def _verification_outcome(
    observation: SignupResultObservation,
    verification_proven: bool,
) -> tuple[SignupResultOutcome | None, bool]:
    if not verification_proven:
        return None, False
    material = observation.searchable_text
    otp = _contains_any(material, _OTP_MARKERS)
    activation = _contains_any(material, _ACTIVATION_LINK_MARKERS)
    if otp and activation:
        return None, True
    if otp:
        return "otp_required", False
    if activation:
        return "activation_link_required", False
    return "email_verification_required", False


def _classified(
    contract: BrowserAutomationContract,
    *,
    outcome: SignupResultOutcome,
    matched_contract_group: str | None,
) -> SignupResultClassification:
    mapping: dict[
        SignupResultOutcome,
        tuple[str, SignupState, SignupResultNextPhase, bool, bool],
    ] = {
        "account_created_authenticated": (
            "signup_account_created_authenticated",
            SignupState.ACCOUNT_CREATED,
            "authenticated",
            False,
            False,
        ),
        "email_verification_required": (
            "signup_email_verification_required",
            SignupState.EMAIL_VERIFICATION_REQUIRED,
            "gmail_verification",
            False,
            True,
        ),
        "otp_required": (
            "signup_otp_required",
            SignupState.EMAIL_VERIFICATION_REQUIRED,
            "gmail_verification",
            False,
            True,
        ),
        "activation_link_required": (
            "signup_activation_link_required",
            SignupState.EMAIL_VERIFICATION_REQUIRED,
            "gmail_verification",
            False,
            True,
        ),
        "account_already_exists": (
            "signup_account_already_exists",
            SignupState.ACCOUNT_EXISTS_DETECTED,
            "login",
            False,
            True,
        ),
        "password_policy_rejected": (
            "signup_password_policy_rejected",
            SignupState.SIGNUP_FAILED,
            "retry_signup",
            False,
            True,
        ),
        "captcha_required": (
            "signup_captcha_required",
            SignupState.SIGNUP_HITL_REQUIRED,
            "hitl",
            True,
            True,
        ),
        "phone_verification_required": (
            "signup_phone_verification_required",
            SignupState.SIGNUP_HITL_REQUIRED,
            "hitl",
            True,
            True,
        ),
        "billing_required": (
            "signup_billing_required",
            SignupState.SIGNUP_HITL_REQUIRED,
            "hitl",
            True,
            True,
        ),
        "legal_acceptance_required": (
            "signup_legal_acceptance_required",
            SignupState.SIGNUP_HITL_REQUIRED,
            "hitl",
            True,
            True,
        ),
        "provider_approval_required": (
            "signup_provider_approval_required",
            SignupState.PROVIDER_APPROVAL_REQUIRED,
            "provider_approval",
            False,
            True,
        ),
        "generic_failure": (
            "signup_provider_failure",
            SignupState.SIGNUP_FAILED,
            "failed",
            False,
            False,
        ),
        "outcome_unknown": (
            "signup_result_not_yet_proven",
            SignupState.SIGNUP_SUBMITTED,
            "reconcile",
            False,
            True,
        ),
    }
    reason, state, phase, hitl, retryable = mapping[outcome]
    return SignupResultClassification(
        status="classified",
        outcome=outcome,
        reason_code=reason,
        contract_version=contract.contract_version,
        durable_state=state,
        next_phase=phase,
        hitl_required=hitl,
        retryable=retryable,
        matched_contract_group=matched_contract_group,
    )


def _unresolved(
    contract: BrowserAutomationContract,
    *,
    status: Literal["outcome_unknown", "safe_stop"],
    reason_code: str,
) -> SignupResultClassification:
    return SignupResultClassification(
        status=status,
        outcome="outcome_unknown",
        reason_code=reason_code,
        contract_version=contract.contract_version,
        durable_state=SignupState.SIGNUP_SUBMITTED,
        next_phase="reconcile",
        hitl_required=False,
        retryable=True,
        stable_observations=0,
    )


def _url_is_contract_allowed(
    url: str,
    contract: BrowserAutomationContract,
) -> bool:
    try:
        parsed = urlsplit(url)
    except Exception:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    from ops.browser_host_policy import host_matches_patterns

    host = parsed.hostname.rstrip(".").casefold()
    if host_matches_patterns(host, contract.hosts.prohibited_hosts):
        return False
    active = (
        *contract.hosts.vendor_hosts,
        *contract.hosts.authentication_hosts,
        *contract.hosts.email_verification_hosts,
    )
    return bool(active) and host_matches_patterns(host, active)


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    normalized = _normalize(value)
    return any(needle in normalized for needle in needles)


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9/._+-]+", " ", str(value).casefold()).strip()


__all__ = [
    "SignupResultClassification",
    "SignupResultNextPhase",
    "SignupResultObservation",
    "SignupResultOutcome",
    "SignupResultStatus",
    "classify_signup_result",
]
