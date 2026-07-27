from __future__ import annotations

from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractLogin,
    ContractRouting,
    ContractSignup,
    evidence_hash_for,
)
from ops.signup_result import SignupResultObservation, classify_signup_result
from ops.signup_state_machine import SignupState
from ops.signup_submission_gates import SignupSubmissionGateInspection


def contract(*, approval_required: bool = False) -> BrowserAutomationContract:
    sources = ("https://docs.example.test/signup",)
    return BrowserAutomationContract(
        app_slug="example",
        app_name="Example",
        contract_version="2026.07.27",
        status="active",
        generated_at="2026-07-27T00:00:00Z",
        expires_at="2027-07-27T00:00:00Z",
        confidence=0.99,
        evidence_hash=evidence_hash_for(sources),
        routing=ContractRouting(
            route_classification="self_serve",
            signup_supported=True,
            login_supported=True,
            production_approval_required=approval_required,
        ),
        hosts=ContractHosts(
            vendor_hosts=("app.example.test",),
            authentication_hosts=("auth.example.test",),
            email_verification_hosts=("verify.example.test",),
        ),
        signup=ContractSignup(
            entrypoints=("https://app.example.test/signup",),
            success_predicates=("url_path:/welcome",),
            existing_account_predicates=("status:account already exists",),
            verification_predicates=("status:verification required",),
            captcha_predicates=("status:verify you are human",),
            phone_verification_predicates=("status:verify your phone",),
        ),
        login=ContractLogin(
            entrypoints=("https://auth.example.test/login",),
            authentication_success_predicates=("accessible_name:dashboard",),
            authentication_failure_predicates=("status:unable to create account",),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def observation(
    *,
    path: str = "/signup",
    status: str = "",
    names: tuple[str, ...] = (),
    native_password_invalid: bool = False,
    visible_alert: bool = False,
    host: str = "app.example.test",
) -> SignupResultObservation:
    return SignupResultObservation(
        page_url=f"https://{host}{path}",
        title="Example",
        visible_text=status,
        status_text=status,
        accessible_names=names,
        native_password_invalid=native_password_invalid,
        visible_alert_present=visible_alert,
        inspected_controls=8,
    )


def clear_gates() -> SignupSubmissionGateInspection:
    return SignupSubmissionGateInspection(
        status="clear",
        reason_code="signup_submission_gates_clear",
        inspected_controls=8,
    )


def test_account_creation_requires_success_and_authentication_proof() -> None:
    current = contract()
    proven = classify_signup_result(
        observation(path="/welcome", names=("Dashboard",)),
        current,
        clear_gates(),
    )
    unproven = classify_signup_result(
        observation(path="/welcome"),
        current,
        clear_gates(),
    )

    assert proven.status == "classified"
    assert proven.outcome == "account_created_authenticated"
    assert proven.durable_state is SignupState.ACCOUNT_CREATED
    assert proven.next_phase == "authenticated"
    assert unproven.status == "outcome_unknown"
    assert unproven.reason_code == "signup_success_without_authentication_proof"


def test_existing_account_routes_to_login() -> None:
    result = classify_signup_result(
        observation(status="Account already exists"),
        contract(),
        clear_gates(),
    )

    assert result.outcome == "account_already_exists"
    assert result.durable_state is SignupState.ACCOUNT_EXISTS_DETECTED
    assert result.next_phase == "login"
    assert result.retryable is True


def test_verification_routes_to_gmail_and_specializes_known_types() -> None:
    current = contract()
    generic = classify_signup_result(
        observation(status="Verification required"),
        current,
        clear_gates(),
    )
    otp_contract = current.model_copy(
        update={
            "signup": current.signup.model_copy(
                update={"verification_predicates": ("status:enter verification code",)}
            )
        }
    )
    otp = classify_signup_result(
        observation(status="Enter verification code"),
        otp_contract,
        clear_gates(),
    )
    link_contract = current.model_copy(
        update={
            "signup": current.signup.model_copy(
                update={"verification_predicates": ("status:check your inbox",)}
            )
        }
    )
    link = classify_signup_result(
        observation(status="Check your inbox for the activation link"),
        link_contract,
        clear_gates(),
    )

    assert generic.outcome == "email_verification_required"
    assert otp.outcome == "otp_required"
    assert link.outcome == "activation_link_required"
    for result in (generic, otp, link):
        assert result.durable_state is SignupState.EMAIL_VERIFICATION_REQUIRED
        assert result.next_phase == "gmail_verification"


def test_captcha_routes_to_hitl() -> None:
    gates = SignupSubmissionGateInspection(
        status="gated",
        reason_code="signup_submission_gate_present",
        present_gates=("captcha",),
        inspected_controls=4,
    )

    result = classify_signup_result(observation(), contract(), gates)

    assert result.outcome == "captcha_required"
    assert result.durable_state is SignupState.SIGNUP_HITL_REQUIRED
    assert result.next_phase == "hitl"
    assert result.hitl_required is True


def test_native_password_rejection_is_retryable() -> None:
    result = classify_signup_result(
        observation(native_password_invalid=True),
        contract(),
        clear_gates(),
    )

    assert result.outcome == "password_policy_rejected"
    assert result.durable_state is SignupState.SIGNUP_FAILED
    assert result.next_phase == "retry_signup"
    assert result.retryable is True


def test_provider_approval_requires_contract_and_visible_status() -> None:
    result = classify_signup_result(
        observation(status="Your request is pending approval"),
        contract(approval_required=True),
        clear_gates(),
    )

    assert result.outcome == "provider_approval_required"
    assert result.durable_state is SignupState.PROVIDER_APPROVAL_REQUIRED
    assert result.next_phase == "provider_approval"


def test_conflicting_contract_outcomes_safe_stop() -> None:
    current = contract()
    current = current.model_copy(
        update={
            "signup": current.signup.model_copy(
                update={"verification_predicates": ("status:verification required",)}
            )
        }
    )

    result = classify_signup_result(
        observation(
            path="/welcome",
            status="Verification required",
            names=("Dashboard",),
        ),
        current,
        clear_gates(),
    )

    assert result.status == "safe_stop"
    assert result.outcome == "outcome_unknown"
    assert result.reason_code == "signup_result_ambiguous"
    assert result.next_phase == "reconcile"


def test_off_contract_origin_never_classifies_success() -> None:
    result = classify_signup_result(
        observation(
            path="/welcome",
            names=("Dashboard",),
            host="attacker.example",
        ),
        contract(),
        clear_gates(),
    )

    assert result.status == "safe_stop"
    assert result.reason_code == "signup_result_off_contract_origin"
    assert result.durable_state is SignupState.SIGNUP_SUBMITTED
