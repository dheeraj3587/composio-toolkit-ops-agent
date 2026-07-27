from __future__ import annotations

import pytest

from browser_service.models import CreateSessionRequest, NavigateRequest
from ops.approved_run_values import ApprovedRunValuesRegistry
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractLogin,
    ContractRouting,
    ContractSignup,
    SQLiteAutomationContractRegistry,
    evidence_hash_for,
)
from ops.autonomous_signup_foundation import AutonomousSignupFoundation
from ops.models import CompanyProfile, OperationsRequest
from ops.signup_state_machine import SQLiteSignupStateStore, SignupState, SignupStateMachine

_SOURCE = "https://docs.example.com/automation"


def _request(company: str, *, account_policy: str = "create_if_missing") -> OperationsRequest:
    return OperationsRequest(
        app_name="Example",
        company=CompanyProfile(
            legal_name=company,
            website="https://example.com",
            work_email_ref="vault://company/work_email/operator",
            use_case="Provision an authorized integration.",
        ),
        account_policy=account_policy,  # type: ignore[arg-type]
    )


def _contract() -> BrowserAutomationContract:
    sources = (_SOURCE,)
    return BrowserAutomationContract(
        app_slug="example",
        app_name="Example",
        contract_version="1.0.0",
        status="active",
        generated_at="2026-07-27T00:00:00Z",
        expires_at="2099-07-27T00:00:00Z",
        confidence=0.9,
        evidence_hash=evidence_hash_for(sources),
        routing=ContractRouting(
            route_classification="self_serve",
            signup_supported=True,
            login_supported=True,
        ),
        hosts=ContractHosts(
            vendor_hosts=("app.example.com",),
            authentication_hosts=("login.example.com",),
            credential_surface_hosts=("keys.example.com",),
        ),
        signup=ContractSignup(entrypoints=("https://app.example.com/signup",)),
        login=ContractLogin(entrypoints=("https://login.example.com/",)),
        evidence=ContractEvidence(source_urls=sources),
    )


def _foundation(tmp_path) -> AutonomousSignupFoundation:
    contract_registry = SQLiteAutomationContractRegistry(tmp_path / "contracts.db")
    contract_registry.put(_contract())
    return AutonomousSignupFoundation(
        values_registry=ApprovedRunValuesRegistry(),
        contract_registry=contract_registry,
        signup_state_machine=SignupStateMachine(
            SQLiteSignupStateStore(tmp_path / "signup-state.db")
        ),
    )


def test_foundation_models_create_then_bind_rpc_flow(tmp_path) -> None:
    request = _request("Alpha Labs")
    foundation = _foundation(tmp_path)
    prepared = foundation.prepare_run(
        run_id="run_alpha",
        app_slug="example",
        request=request,
        signup_email_ref="vault://gmail/signup_email/run_alpha",
        account_password_ref="vault://example/account_password/run_alpha",
    )

    create_payload = CreateSessionRequest.model_validate(prepared.create_session_payload())
    assert create_payload.approved_values is not None
    assert create_payload.approved_values.session_id is None

    bound = foundation.bind_session(
        prepared,
        session_id="session_alpha",
        account_exists=False,
    )
    assert bound.signup_decision is not None
    assert bound.signup_decision.state is SignupState.SIGNUP_PAGE_LOADING

    navigate_payload = NavigateRequest.model_validate(bound.navigate_payload(research={}))
    assert navigate_payload.approved_values is not None
    assert navigate_payload.approved_values.session_id == "session_alpha"
    assert navigate_payload.automation_contract == _contract()
    assert "vault://" not in str(bound.approved_values.prompt_safe_projection())


def test_foundation_keeps_two_bound_sessions_isolated(tmp_path) -> None:
    foundation = _foundation(tmp_path)
    alpha = foundation.prepare_run(
        run_id="run_alpha",
        app_slug="example",
        request=_request("Alpha Labs"),
        signup_email_ref="vault://gmail/signup_email/run_alpha",
        account_password_ref="vault://example/account_password/run_alpha",
    )
    beta = foundation.prepare_run(
        run_id="run_beta",
        app_slug="example",
        request=_request("Beta Labs"),
        signup_email_ref="vault://gmail/signup_email/run_beta",
        account_password_ref="vault://example/account_password/run_beta",
    )
    foundation.bind_session(alpha, session_id="session_alpha", account_exists=False)
    foundation.bind_session(beta, session_id="session_beta", account_exists=False)

    assert foundation.get_values(
        run_id="run_alpha", session_id="session_alpha"
    ).legal_name == "Alpha Labs"
    assert foundation.get_values(
        run_id="run_beta", session_id="session_beta"
    ).legal_name == "Beta Labs"
    with pytest.raises(PermissionError):
        foundation.get_values(run_id="run_beta", session_id="session_alpha")


def test_reuse_existing_policy_skips_signup_creation(tmp_path) -> None:
    foundation = _foundation(tmp_path)
    prepared = foundation.prepare_run(
        run_id="run_existing",
        app_slug="example",
        request=_request("Existing Company", account_policy="reuse_existing"),
        signup_email_ref="vault://gmail/signup_email/run_existing",
        account_password_ref="vault://example/account_password/run_existing",
    )
    bound = foundation.bind_session(
        prepared,
        session_id="session_existing",
        account_exists=False,
    )

    assert bound.signup_decision is not None
    assert bound.signup_decision.state is SignupState.ACCOUNT_EXISTS_DETECTED
    assert bound.signup_decision.account_creation_authorized is False
