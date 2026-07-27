from __future__ import annotations

from pathlib import Path

from ops.approved_run_values import ApprovedRunValuesRegistry
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractRouting,
    ContractSignup,
    SQLiteAutomationContractRegistry,
    evidence_hash_for,
)
from ops.autonomous_signup_foundation import AutonomousSignupFoundation
from ops.models import CompanyProfile, OperationsRequest
from ops.signup_forms import (
    SignupControlCandidate,
    SignupFillResult,
    detect_signup_form,
)
from ops.signup_state_machine import (
    SQLiteSignupStateStore,
    SignupState,
    SignupStateMachine,
)


def contract() -> BrowserAutomationContract:
    sources = ("https://docs.example.test/signup",)
    return BrowserAutomationContract(
        app_slug="pipedrive",
        app_name="Pipedrive",
        contract_version="2026.07.27",
        status="active",
        generated_at="2026-07-27T00:00:00Z",
        expires_at="2027-07-27T00:00:00Z",
        confidence=0.99,
        evidence_hash=evidence_hash_for(sources),
        routing=ContractRouting(
            route_classification="self_serve",
            signup_supported=True,
        ),
        hosts=ContractHosts(vendor_hosts=("example.test",)),
        signup=ContractSignup(
            entrypoints=("https://example.test/signup",),
            required_semantic_fields=("email", "password"),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def bound_foundation(tmp_path: Path):
    contract_registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    contract_registry.put(contract())
    foundation = AutonomousSignupFoundation(
        values_registry=ApprovedRunValuesRegistry(),
        contract_registry=contract_registry,
        signup_state_machine=SignupStateMachine(
            SQLiteSignupStateStore(tmp_path / "signup-state.db")
        ),
    )
    request = OperationsRequest(
        app_name="Pipedrive",
        account_policy="create_if_missing",
        company=CompanyProfile(
            legal_name="Example Labs",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Authorized integration provisioning",
        ),
    )
    prepared = foundation.prepare_run(
        run_id="run_1",
        app_slug="pipedrive",
        request=request,
        signup_email_ref="vault://pipedrive/signup_email/email_1",
        account_password_ref="vault://pipedrive/account_password/password_1",
    )
    return foundation, foundation.bind_session(
        prepared,
        session_id="bs_1",
        account_exists=False,
    )


def detected_inspection(bound):
    return detect_signup_form(
        (
            SignupControlCandidate(
                token="sf_00000000000000000000000000000001",
                control_kind="email",
                accessible_name="Email",
            ),
            SignupControlCandidate(
                token="sf_00000000000000000000000000000002",
                control_kind="password",
                accessible_name="Password",
            ),
            SignupControlCandidate(
                token="sf_00000000000000000000000000000003",
                control_kind="button",
                accessible_name="Create account",
            ),
        ),
        bound.automation_contract.signup,
        bound.automation_contract.contract_version,
    )


def test_detected_and_filled_results_advance_only_to_submission_ready(
    tmp_path: Path,
) -> None:
    foundation, bound = bound_foundation(tmp_path)
    after_detection = foundation.record_form_inspection(
        bound,
        detected_inspection(bound),
    )
    assert after_detection.state == SignupState.SIGNUP_FORM_DETECTED

    filled = SignupFillResult(
        status="filled",
        reason_code="signup_form_filled_and_verified",
        contract_version="2026.07.27",
        filled_fields=("email", "password"),
        verified_fields=("email", "password"),
        screenshots_disabled=True,
        submit_clicked=False,
    )
    after_fill = foundation.record_form_fill(bound, filled)

    assert after_fill.state == SignupState.SIGNUP_SUBMISSION_READY
    assert after_fill.revision == after_detection.revision + 3


def test_configuration_required_keeps_detected_form_retryable(
    tmp_path: Path,
) -> None:
    foundation, bound = bound_foundation(tmp_path)
    after_detection = foundation.record_form_inspection(
        bound,
        detected_inspection(bound),
    )

    result = SignupFillResult(
        status="configuration_required",
        reason_code="signup_required_value_missing",
        contract_version="2026.07.27",
        missing_values=("first_name",),
        screenshots_disabled=False,
    )
    after_configuration = foundation.record_form_fill(bound, result)

    assert after_configuration == after_detection
    assert after_configuration.state == SignupState.SIGNUP_FORM_DETECTED
