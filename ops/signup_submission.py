"""Crash-safe authorization and dispatch for normal signup submission.

Part 14 may click exactly one reviewed signup submit control after every required
field has been re-verified. The external click is protected by the shared effect
ledger, so a restart or ambiguous Playwright timeout produces reconciliation and
never a blind second account-creation attempt. Part 15 owns result classification.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ops.approved_run_values import ApprovedRunValues
from ops.automation_contracts import BrowserAutomationContract, SignupSemanticField
from ops.browser_risk import ActionAuthorizationContext, BrowserActionRiskPolicy
from ops.effect_ledger import EffectStore
from ops.policies import AccountPolicy
from ops.secret_store import SecretStore
from ops.signup_credentials import SignupAccountBinding, SignupCredentialManager
from ops.signup_forms import SignupFillResult, SignupFormInspection
from ops.signup_state_machine import SignupState
from ops.signup_submission_fields import (
    SecretCaptureGuard,
    strict_signup_token_locator,
    verify_required_signup_fields,
)
from ops.signup_submission_gates import (
    SubmissionGate,
    inspect_signup_submission_gates,
)

SubmissionStatus = Literal[
    "submitted",
    "authorization_denied",
    "configuration_required",
    "outcome_unknown",
    "failed",
]
_PreflightFailureStatus = Literal[
    "authorization_denied",
    "configuration_required",
    "failed",
]

_ACTION_TIMEOUT_MS = 10_000
_SUBMIT_METADATA_SCRIPT = r"""
(el) => {
  const form = el.form || null;
  return {
    tag: (el.tagName || "").toLowerCase(),
    type: (typeof el.type === "string" ? el.type : el.getAttribute("type") || "")
      .toLowerCase(),
    role: (el.getAttribute("role") || "").toLowerCase(),
    formAction: form ? (el.formAction || form.action || "") : "",
    formMethod: form ? (el.formMethod || form.method || "get") : "",
    formTarget: form ? (el.formTarget || form.target || "") : "",
    insideForm: Boolean(form),
  };
}
"""


class PageLike(Protocol):
    url: str

    def locator(self, selector: str) -> Any: ...


class SignupSubmissionResult(BaseModel):
    """Sanitized result of authorizing or dispatching the signup click."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    status: SubmissionStatus
    reason_code: str = Field(pattern=r"^[a-z0-9_:-]+$", max_length=100)
    contract_version: str = Field(min_length=1, max_length=64)
    purpose: Literal["signup_submit"] = "signup_submit"
    verified_fields: tuple[SignupSemanticField, ...] = Field(default=(), max_length=20)
    present_gates: tuple[SubmissionGate, ...] = Field(default=(), max_length=5)
    submit_clicked: bool = False
    effect_replayed: bool = False
    navigation_observed: bool = False

    @model_validator(mode="after")
    def _result_is_truthful(self) -> SignupSubmissionResult:
        if self.status == "submitted":
            if not (self.submit_clicked or self.effect_replayed):
                raise ValueError("submitted result requires a click or completed effect replay")
        elif self.submit_clicked or self.effect_replayed:
            raise ValueError("only submitted results may claim a click or effect replay")
        if "signup_submit" in self.verified_fields:
            raise ValueError("submit control is authorized separately from field verification")
        return self


@dataclass(frozen=True, slots=True)
class _PreflightDecision:
    """Static/identity decision that deliberately carries no executable locator."""

    status: Literal[
        "authorized",
        "authorization_denied",
        "configuration_required",
        "failed",
    ]
    reason_code: str
    verified_fields: tuple[SignupSemanticField, ...] = ()
    present_gates: tuple[SubmissionGate, ...] = ()


@dataclass(frozen=True, slots=True)
class _AuthorizedPreflight:
    """A live authorization result whose executable locator is mandatory."""

    locator: Any
    verified_fields: tuple[SignupSemanticField, ...]
    present_gates: tuple[SubmissionGate, ...]
    status: Literal["authorized"] = "authorized"
    reason_code: str = "signup_submit_authorized"


@dataclass(frozen=True, slots=True)
class _DeniedPreflight:
    status: _PreflightFailureStatus
    reason_code: str
    verified_fields: tuple[SignupSemanticField, ...] = ()
    present_gates: tuple[SubmissionGate, ...] = ()


_LivePreflight = _AuthorizedPreflight | _DeniedPreflight


async def submit_signup_form(
    page: PageLike,
    *,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    account_policy: AccountPolicy,
    current_state: SignupState,
    run_id: str,
    session_id: str,
    secret_store: SecretStore,
    credential_manager: SignupCredentialManager,
    account_binding: SignupAccountBinding,
    effect_store: EffectStore,
    risk_policy: BrowserActionRiskPolicy | None = None,
    assert_secret_capture_disabled: SecretCaptureGuard | None = None,
) -> SignupSubmissionResult:
    """Authorize and dispatch one normal signup submit action at most once."""

    policy = risk_policy or BrowserActionRiskPolicy()
    identity = _effect_identity_preflight(
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        run_id=run_id,
        session_id=session_id,
        account_binding=account_binding,
    )
    if identity.status != "authorized":
        return _result_from_decision(identity, contract.contract_version)

    provider = contract.app_slug
    action = "signup_submit"
    idempotency_key = _signup_effect_key(
        run_id=run_id,
        contract_version=contract.contract_version,
        account_binding_id=account_binding.binding_id,
    )
    try:
        reservation = effect_store.reserve(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
    except Exception:
        return SignupSubmissionResult(
            status="failed",
            reason_code="signup_submit_effect_reservation_failed",
            contract_version=contract.contract_version,
            verified_fields=tuple(fill_result.verified_fields),
        )

    if reservation.status == "completed":
        if not _completed_receipt_valid(
            reservation.receipt,
            contract_version=contract.contract_version,
            account_binding_id=account_binding.binding_id,
        ):
            return SignupSubmissionResult(
                status="outcome_unknown",
                reason_code="signup_submit_receipt_invalid",
                contract_version=contract.contract_version,
                verified_fields=tuple(fill_result.verified_fields),
            )
        return SignupSubmissionResult(
            status="submitted",
            reason_code="signup_submit_already_dispatched",
            contract_version=contract.contract_version,
            verified_fields=tuple(fill_result.verified_fields),
            effect_replayed=True,
        )
    if reservation.status == "reconcile_required":
        return SignupSubmissionResult(
            status="outcome_unknown",
            reason_code="signup_submit_reconciliation_required",
            contract_version=contract.contract_version,
            verified_fields=tuple(fill_result.verified_fields),
        )

    first = await _submission_preflight(
        page,
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        account_policy=account_policy,
        current_state=current_state,
        run_id=run_id,
        session_id=session_id,
        secret_store=secret_store,
        credential_manager=credential_manager,
        account_binding=account_binding,
        risk_policy=policy,
        assert_secret_capture_disabled=assert_secret_capture_disabled,
    )
    if isinstance(first, _DeniedPreflight):
        _mark_failed_best_effort(
            effect_store,
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
        return _result_from_decision(first, contract.contract_version)

    # Re-run every live check after the first pass. A changed DOM, new gate,
    # altered field, expired contract, or moved control invalidates the reservation.
    second = await _submission_preflight(
        page,
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        account_policy=account_policy,
        current_state=current_state,
        run_id=run_id,
        session_id=session_id,
        secret_store=secret_store,
        credential_manager=credential_manager,
        account_binding=account_binding,
        risk_policy=policy,
        assert_secret_capture_disabled=assert_secret_capture_disabled,
    )
    if isinstance(second, _DeniedPreflight):
        _mark_failed_best_effort(
            effect_store,
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
        return _result_from_decision(second, contract.contract_version)

    before_url = _page_url(page)
    try:
        # `_AuthorizedPreflight` makes a missing locator unrepresentable. The click
        # can therefore no longer crash through an `Any | None` union.
        await second.locator.click(timeout=_ACTION_TIMEOUT_MS)
    except Exception:
        _mark_unknown_best_effort(
            effect_store,
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
        return SignupSubmissionResult(
            status="outcome_unknown",
            reason_code="signup_submit_outcome_unknown",
            contract_version=contract.contract_version,
            verified_fields=second.verified_fields,
        )

    after_url = _page_url(page)
    try:
        effect_store.complete(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
            receipt={
                "result": "dispatched",
                "purpose": "signup_submit",
                "contract_version": contract.contract_version,
                "account_binding_id": account_binding.binding_id,
            },
        )
    except Exception:
        _mark_unknown_best_effort(
            effect_store,
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
        return SignupSubmissionResult(
            status="outcome_unknown",
            reason_code="signup_submit_receipt_persistence_failed",
            contract_version=contract.contract_version,
            verified_fields=second.verified_fields,
        )

    return SignupSubmissionResult(
        status="submitted",
        reason_code="signup_submit_dispatched",
        contract_version=contract.contract_version,
        verified_fields=second.verified_fields,
        submit_clicked=True,
        navigation_observed=bool(before_url and after_url and before_url != after_url),
    )


def _signup_effect_key(
    *,
    run_id: str,
    contract_version: str,
    account_binding_id: str,
) -> str:
    """Bind at-most-once identity to every stable account-creation component."""

    return (
        f"signup-submit:v1:{run_id}:{contract_version}:"
        f"{account_binding_id}"
    )


def _effect_identity_preflight(
    *,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    run_id: str,
    session_id: str,
    account_binding: SignupAccountBinding,
) -> _PreflightDecision:
    try:
        approved_values.assert_binding(run_id=run_id, session_id=session_id)
    except Exception:
        return _PreflightDecision(
            status="configuration_required",
            reason_code="signup_submit_binding_invalid",
        )
    if contract.app_slug != account_binding.app_slug:
        return _PreflightDecision(
            status="configuration_required",
            reason_code="signup_submit_account_binding_mismatch",
        )
    if inspection.status != "detected" or fill_result.status != "filled":
        return _PreflightDecision(
            status="configuration_required",
            reason_code="signup_submit_form_not_prepared",
        )
    if (
        inspection.contract_version != contract.contract_version
        or fill_result.contract_version != contract.contract_version
    ):
        return _PreflightDecision(
            status="configuration_required",
            reason_code="signup_submit_contract_version_changed",
        )
    return _PreflightDecision(
        status="authorized",
        reason_code="signup_submit_effect_identity_verified",
        verified_fields=tuple(fill_result.verified_fields),
    )


def _static_submission_preflight(
    *,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    account_policy: AccountPolicy,
    current_state: SignupState,
    run_id: str,
    session_id: str,
    account_binding: SignupAccountBinding,
) -> _PreflightDecision:
    identity = _effect_identity_preflight(
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        run_id=run_id,
        session_id=session_id,
        account_binding=account_binding,
    )
    if identity.status != "authorized":
        return identity
    try:
        contract.assert_usable()
    except Exception:
        return _PreflightDecision(
            status="configuration_required",
            reason_code="signup_submit_contract_inactive",
            verified_fields=identity.verified_fields,
        )
    if account_policy != "create_if_missing":
        return _PreflightDecision(
            status="authorization_denied",
            reason_code="signup_submit_account_policy_blocked",
            verified_fields=identity.verified_fields,
        )
    if not contract.routing.signup_supported:
        return _PreflightDecision(
            status="authorization_denied",
            reason_code="signup_submit_not_supported_by_contract",
            verified_fields=identity.verified_fields,
        )
    if current_state != SignupState.SIGNUP_SUBMISSION_READY:
        return _PreflightDecision(
            status="authorization_denied",
            reason_code="signup_submit_state_not_ready",
            verified_fields=identity.verified_fields,
        )
    return _PreflightDecision(
        status="authorized",
        reason_code="signup_submit_static_authorization_passed",
        verified_fields=identity.verified_fields,
    )


async def _submission_preflight(
    page: PageLike,
    *,
    inspection: SignupFormInspection,
    fill_result: SignupFillResult,
    contract: BrowserAutomationContract,
    approved_values: ApprovedRunValues,
    account_policy: AccountPolicy,
    current_state: SignupState,
    run_id: str,
    session_id: str,
    secret_store: SecretStore,
    credential_manager: SignupCredentialManager,
    account_binding: SignupAccountBinding,
    risk_policy: BrowserActionRiskPolicy,
    assert_secret_capture_disabled: SecretCaptureGuard | None,
) -> _LivePreflight:
    static = _static_submission_preflight(
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        account_policy=account_policy,
        current_state=current_state,
        run_id=run_id,
        session_id=session_id,
        account_binding=account_binding,
    )
    if static.status != "authorized":
        return _denied(static)
    if not _signup_url_allowed(_page_url(page), contract):
        return _DeniedPreflight(
            status="configuration_required",
            reason_code="signup_submit_page_origin_blocked",
            verified_fields=static.verified_fields,
        )

    gates = await inspect_signup_submission_gates(page, contract)
    if gates.status == "safe_stop":
        return _DeniedPreflight(
            status="failed",
            reason_code=gates.reason_code,
            present_gates=gates.present_gates,
        )

    submit_match = inspection.match_for("signup_submit")
    if submit_match is None or submit_match.control_kind != "button":
        return _DeniedPreflight(
            status="configuration_required",
            reason_code="signup_submit_control_missing",
            present_gates=gates.present_gates,
        )
    submit_locator = await strict_signup_token_locator(page, submit_match.token)
    if submit_locator is None:
        return _DeniedPreflight(
            status="failed",
            reason_code="signup_submit_control_stale_or_ambiguous",
            present_gates=gates.present_gates,
        )
    try:
        metadata = await submit_locator.evaluate(_SUBMIT_METADATA_SCRIPT)
    except Exception:
        return _DeniedPreflight(
            status="failed",
            reason_code="signup_submit_control_inspection_failed",
            present_gates=gates.present_gates,
        )
    semantic_reason = _validate_submit_semantics(
        metadata,
        match_strategy=submit_match.strategy,
        contract=contract,
    )
    if semantic_reason is not None:
        return _DeniedPreflight(
            status="configuration_required",
            reason_code=semantic_reason,
            present_gates=gates.present_gates,
        )

    verified_fields, verification_reason = await verify_required_signup_fields(
        page,
        inspection=inspection,
        fill_result=fill_result,
        contract=contract,
        approved_values=approved_values,
        secret_store=secret_store,
        credential_manager=credential_manager,
        account_binding=account_binding,
        assert_secret_capture_disabled=assert_secret_capture_disabled,
    )
    decision = risk_policy.authorize_purpose(
        ActionAuthorizationContext(
            purpose="signup_submit",
            account_policy=account_policy,
            contract_active=contract.status == "active" and not contract.is_expired(),
            signup_supported=contract.routing.signup_supported,
            signup_state=current_state.value,
            required_fields_verified=verification_reason is None,
            submit_control_unique=True,
            captcha_present="captcha" in gates.present_gates,
            legal_acceptance_present="legal_acceptance" in gates.present_gates,
            billing_present="billing" in gates.present_gates,
            phone_verification_present="phone_verification" in gates.present_gates,
            ownership_or_admin_change_present=(
                "ownership_or_admin_change" in gates.present_gates
            ),
            code_owned=True,
        )
    )
    if not decision.autonomous_allowed:
        return _DeniedPreflight(
            status="authorization_denied",
            reason_code=decision.reason_code,
            verified_fields=verified_fields,
            present_gates=gates.present_gates,
        )
    if verification_reason is not None:
        return _DeniedPreflight(
            status="configuration_required",
            reason_code=verification_reason,
            verified_fields=verified_fields,
            present_gates=gates.present_gates,
        )

    try:
        await submit_locator.click(trial=True, timeout=_ACTION_TIMEOUT_MS)
    except Exception:
        return _DeniedPreflight(
            status="failed",
            reason_code="signup_submit_not_actionable",
            verified_fields=verified_fields,
            present_gates=gates.present_gates,
        )

    return _AuthorizedPreflight(
        locator=submit_locator,
        verified_fields=verified_fields,
        present_gates=gates.present_gates,
    )


def _denied(decision: _PreflightDecision) -> _DeniedPreflight:
    if decision.status == "authorized":
        raise ValueError("authorized static decision cannot be converted to denial")
    return _DeniedPreflight(
        status=decision.status,
        reason_code=decision.reason_code,
        verified_fields=decision.verified_fields,
        present_gates=decision.present_gates,
    )


def _validate_submit_semantics(
    metadata: object,
    *,
    match_strategy: str,
    contract: BrowserAutomationContract,
) -> str | None:
    if not isinstance(metadata, Mapping):
        return "signup_submit_control_metadata_invalid"
    tag = str(metadata.get("tag") or "").casefold()
    element_type = str(metadata.get("type") or "").casefold()
    role = str(metadata.get("role") or "").casefold()
    inside_form = bool(metadata.get("insideForm"))
    native_submit = (
        tag in {"button", "input"}
        and element_type == "submit"
        and inside_form
    )
    if not native_submit:
        if match_strategy != "reviewed_test_id" or role not in {"button", ""}:
            return "signup_submit_non_native_control_not_reviewed"
        return None
    method = str(metadata.get("formMethod") or "get").casefold()
    if method == "get":
        return "signup_submit_get_form_blocked"
    target = str(metadata.get("formTarget") or "").casefold()
    if target not in {"", "_self"}:
        return "signup_submit_external_target_blocked"
    action = str(metadata.get("formAction") or "")
    if action and not _signup_url_allowed(action, contract):
        return "signup_submit_form_action_blocked"
    return None


def _signup_url_allowed(action: str, contract: BrowserAutomationContract) -> bool:
    try:
        parsed = urlsplit(action)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return False
    host = parsed.hostname.casefold().rstrip(".")
    if any(_host_matches(host, pattern) for pattern in contract.hosts.prohibited_hosts):
        return False
    allowed = list(contract.hosts.vendor_hosts)
    allowed.extend(contract.hosts.authentication_hosts)
    allowed.extend(
        urlsplit(entrypoint).hostname or ""
        for entrypoint in contract.signup.entrypoints
    )
    return any(
        pattern and _host_matches(host, pattern)
        for pattern in dict.fromkeys(allowed)
    )


def _host_matches(host: str, pattern: str) -> bool:
    normalized = pattern.casefold().rstrip(".")
    if normalized.startswith("*."):
        suffix = normalized[2:]
        return host == suffix or host.endswith(f".{suffix}")
    return host == normalized


def _completed_receipt_valid(
    receipt: dict[str, str] | None,
    *,
    contract_version: str,
    account_binding_id: str,
) -> bool:
    expected = {
        "result": "dispatched",
        "purpose": "signup_submit",
        "contract_version": contract_version,
        "account_binding_id": account_binding_id,
    }
    return receipt == expected


def _result_from_decision(
    preflight: _PreflightDecision | _DeniedPreflight,
    contract_version: str,
) -> SignupSubmissionResult:
    if preflight.status == "authorized":
        raise ValueError("authorized decision cannot be projected as a failure")
    return SignupSubmissionResult(
        status=preflight.status,
        reason_code=preflight.reason_code,
        contract_version=contract_version,
        verified_fields=preflight.verified_fields,
        present_gates=preflight.present_gates,
    )


def _mark_failed_best_effort(
    store: EffectStore,
    *,
    provider: str,
    action: str,
    idempotency_key: str,
) -> None:
    try:
        store.mark_failed(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
    except Exception:
        pass


def _mark_unknown_best_effort(
    store: EffectStore,
    *,
    provider: str,
    action: str,
    idempotency_key: str,
) -> None:
    try:
        store.mark_outcome_unknown(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
        )
    except Exception:
        pass


def _page_url(page: PageLike) -> str:
    value = getattr(page, "url", "")
    return value if isinstance(value, str) else ""


__all__ = [
    "SignupSubmissionResult",
    "SubmissionGate",
    "SubmissionStatus",
    "inspect_signup_submission_gates",
    "submit_signup_form",
]
