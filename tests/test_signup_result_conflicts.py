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


def contract(*, legal_billing: tuple[str, ...] = ()) -> BrowserAutomationContract:
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
        ),
        hosts=ContractHosts(vendor_hosts=("app.example.test",)),
        signup=ContractSignup(
            entrypoints=("https://app.example.test/signup",),
            success_predicates=("url_path:/welcome",),
            legal_billing_predicates=legal_billing,
        ),
        login=ContractLogin(
            entrypoints=("https://app.example.test/login",),
            authentication_success_predicates=("accessible_name:dashboard",),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def observation(
    *,
    path: str = "/signup",
    status: str = "",
    names: tuple[str, ...] = (),
    feedback: bool = False,
) -> SignupResultObservation:
    return SignupResultObservation(
        page_url=f"https://app.example.test{path}",
        title="Example",
        visible_text=status,
        status_text=status,
        accessible_names=names,
        visible_alert_present=feedback,
        inspected_controls=5,
    )


def clear_gates() -> SignupSubmissionGateInspection:
    return SignupSubmissionGateInspection(
        status="clear",
        reason_code="signup_submission_gates_clear",
        inspected_controls=5,
    )


def test_success_never_overrides_simultaneous_failure_feedback() -> None:
    result = classify_signup_result(
        observation(
            path="/welcome",
            status="Something went wrong",
            names=("Dashboard",),
            feedback=True,
        ),
        contract(),
        clear_gates(),
    )

    assert result.status == "safe_stop"
    assert result.reason_code == "signup_result_ambiguous"
    assert result.outcome == "outcome_unknown"


def test_server_password_feedback_is_not_treated_as_page_instructions() -> None:
    result = classify_signup_result(
        observation(
            status="Password does not meet the password requirements",
            feedback=True,
        ),
        contract(),
        clear_gates(),
    )

    assert result.outcome == "password_policy_rejected"
    assert result.durable_state is SignupState.SIGNUP_FAILED
    assert result.next_phase == "retry_signup"


def test_contract_proven_legal_and_billing_results_route_to_hitl() -> None:
    legal = classify_signup_result(
        observation(status="Accept terms to continue"),
        contract(legal_billing=("status:accept terms",)),
        clear_gates(),
    )
    billing = classify_signup_result(
        observation(status="Payment method required"),
        contract(legal_billing=("status:payment method required",)),
        clear_gates(),
    )

    assert legal.outcome == "legal_acceptance_required"
    assert billing.outcome == "billing_required"
    for result in (legal, billing):
        assert result.durable_state is SignupState.SIGNUP_HITL_REQUIRED
        assert result.next_phase == "hitl"
        assert result.hitl_required is True


def test_under_specified_combined_gate_predicate_safe_stops() -> None:
    result = classify_signup_result(
        observation(status="Additional action required"),
        contract(legal_billing=("status:additional action required",)),
        clear_gates(),
    )

    assert result.status == "safe_stop"
    assert result.reason_code == "signup_result_ambiguous"
    assert result.outcome == "outcome_unknown"
