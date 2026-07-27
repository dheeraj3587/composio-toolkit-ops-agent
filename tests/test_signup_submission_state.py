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
from ops.signup_state_machine import (
    SQLiteSignupStateStore,
    SignupState,
    SignupStateMachine,
)
from ops.signup_submission import SignupSubmissionResult


def contract() -> BrowserAutomationContract:
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
        ),
        hosts=ContractHosts(vendor_hosts=("app.example.test",)),
        signup=ContractSignup(
            entrypoints=("https://app.example.test/signup",),
            required_semantic_fields=("email", "password"),
        ),
        evidence=ContractEvidence(source_urls=sources),
    )


def ready_foundation(tmp_path: Path):
    registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    registry.put(contract())
    machine = SignupStateMachine(
        SQLiteSignupStateStore(tmp_path / "signup-state.db")
    )
    foundation = AutonomousSignupFoundation(
        values_registry=ApprovedRunValuesRegistry(),
        contract_registry=registry,
        signup_state_machine=machine,
    )
    request = OperationsRequest(
        app_name="Example",
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
        app_slug="example",
        request=request,
        signup_email_ref="vault://example/signup_email/email_1",
        account_password_ref="vault://example/account_password/password_1",
    )
    bound = foundation.bind_session(
        prepared,
        session_id="bs_1",
        account_exists=False,
    )
    snapshot = machine.snapshot("run_1")
    snapshot = machine.advance(
        "run_1",
        SignupState.SIGNUP_FORM_DETECTED,
        expected_revision=snapshot.revision,
    )
    snapshot = machine.advance(
        "run_1",
        SignupState.SIGNUP_VALUES_READY,
        expected_revision=snapshot.revision,
    )
    snapshot = machine.advance(
        "run_1",
        SignupState.SIGNUP_FORM_FILLED,
        expected_revision=snapshot.revision,
    )
    snapshot = machine.advance(
        "run_1",
        SignupState.SIGNUP_SUBMISSION_READY,
        expected_revision=snapshot.revision,
    )
    return foundation, bound, snapshot


def test_completed_signup_effect_advances_to_submitted(tmp_path: Path) -> None:
    foundation, bound, ready = ready_foundation(tmp_path)
    result = SignupSubmissionResult(
        status="submitted",
        reason_code="signup_submit_dispatched",
        contract_version="2026.07.27",
        verified_fields=("email", "password"),
        submit_clicked=True,
    )

    submitted = foundation.record_submission(bound, result)

    assert ready.state == SignupState.SIGNUP_SUBMISSION_READY
    assert submitted.state == SignupState.SIGNUP_SUBMITTED
    assert submitted.revision == ready.revision + 1
    assert foundation.record_submission(bound, result) == submitted


def test_ambiguous_submission_does_not_claim_submitted(tmp_path: Path) -> None:
    foundation, bound, ready = ready_foundation(tmp_path)
    result = SignupSubmissionResult(
        status="outcome_unknown",
        reason_code="signup_submit_reconciliation_required",
        contract_version="2026.07.27",
        verified_fields=("email", "password"),
    )

    unchanged = foundation.record_submission(bound, result)

    assert unchanged == ready
    assert unchanged.state == SignupState.SIGNUP_SUBMISSION_READY
