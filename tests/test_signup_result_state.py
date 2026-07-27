from __future__ import annotations

import sqlite3
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
from ops.signup_result import SignupResultClassification
from ops.signup_state_machine import (
    SQLiteSignupStateStore,
    SignupState,
    SignupStateMachine,
)


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


def submitted_foundation(tmp_path: Path):
    contract_registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    contract_registry.put(contract())
    state_path = tmp_path / "signup-state.db"
    machine = SignupStateMachine(SQLiteSignupStateStore(state_path))
    foundation = AutonomousSignupFoundation(
        values_registry=ApprovedRunValuesRegistry(),
        contract_registry=contract_registry,
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
    for state in (
        SignupState.SIGNUP_FORM_DETECTED,
        SignupState.SIGNUP_VALUES_READY,
        SignupState.SIGNUP_FORM_FILLED,
        SignupState.SIGNUP_SUBMISSION_READY,
        SignupState.SIGNUP_SUBMITTED,
    ):
        snapshot = machine.advance(
            "run_1",
            state,
            expected_revision=snapshot.revision,
        )
    return foundation, bound, state_path, snapshot


def result(
    *,
    outcome: str,
    reason_code: str,
    state: SignupState,
    next_phase: str,
    hitl: bool = False,
) -> SignupResultClassification:
    return SignupResultClassification(
        status="classified",
        outcome=outcome,
        reason_code=reason_code,
        contract_version="2026.07.27",
        durable_state=state,
        next_phase=next_phase,
        hitl_required=hitl,
        retryable=True,
        matched_contract_group="test.fixture",
        stable_observations=2,
    )


def test_legacy_signup_database_is_migrated_without_losing_state(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE signup_states (
                run_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                revision INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO signup_states(run_id, state, revision, updated_at)
            VALUES ('run_legacy', 'signup_submitted', 7, '2026-07-27T00:00:00Z')
            """
        )
        connection.commit()

    snapshot = SQLiteSignupStateStore(path).get_or_create("run_legacy")

    assert snapshot.state is SignupState.SIGNUP_SUBMITTED
    assert snapshot.revision == 7
    assert snapshot.reason_code == "signup_state_legacy"
    assert snapshot.outcome is None


def test_existing_account_outcome_persists_and_routes_to_login(tmp_path: Path) -> None:
    foundation, bound, state_path, submitted = submitted_foundation(tmp_path)
    classified = result(
        outcome="account_already_exists",
        reason_code="signup_account_already_exists",
        state=SignupState.ACCOUNT_EXISTS_DETECTED,
        next_phase="login",
    )

    recorded = foundation.record_signup_result(bound, classified)
    restarted = SignupStateMachine(SQLiteSignupStateStore(state_path)).snapshot("run_1")

    assert recorded.revision == submitted.revision + 1
    assert recorded.state is SignupState.ACCOUNT_EXISTS_DETECTED
    assert recorded.reason_code == "signup_account_already_exists"
    assert recorded.outcome == "account_already_exists"
    assert restarted == recorded
    assert foundation.record_signup_result(bound, classified) == recorded


def test_captcha_outcome_persists_as_hitl_state(tmp_path: Path) -> None:
    foundation, bound, state_path, _submitted = submitted_foundation(tmp_path)
    classified = result(
        outcome="captcha_required",
        reason_code="signup_captcha_required",
        state=SignupState.SIGNUP_HITL_REQUIRED,
        next_phase="hitl",
        hitl=True,
    )

    recorded = foundation.record_signup_result(bound, classified)
    restarted = SignupStateMachine(SQLiteSignupStateStore(state_path)).snapshot("run_1")

    assert recorded.state is SignupState.SIGNUP_HITL_REQUIRED
    assert recorded.reason_code == "signup_captcha_required"
    assert recorded.outcome == "captcha_required"
    assert restarted == recorded


def test_unknown_result_stays_submitted_for_reconciliation(tmp_path: Path) -> None:
    foundation, bound, state_path, submitted = submitted_foundation(tmp_path)
    classified = SignupResultClassification(
        status="outcome_unknown",
        outcome="outcome_unknown",
        reason_code="signup_result_unproven_timeout",
        contract_version="2026.07.27",
        durable_state=SignupState.SIGNUP_SUBMITTED,
        next_phase="reconcile",
        retryable=True,
        stable_observations=0,
    )

    recorded = foundation.record_signup_result(bound, classified)
    restarted = SignupStateMachine(SQLiteSignupStateStore(state_path)).snapshot("run_1")

    assert recorded.state is SignupState.SIGNUP_SUBMITTED
    assert recorded.revision == submitted.revision + 1
    assert recorded.reason_code == "signup_result_unproven_timeout"
    assert recorded.outcome == "outcome_unknown"
    assert restarted == recorded
