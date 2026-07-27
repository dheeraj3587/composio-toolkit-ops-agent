from __future__ import annotations

import pytest
from pydantic import ValidationError

from browser_service.models import CreateSessionRequest, NavigateRequest
from ops.approved_run_values import build_approved_run_values
from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractEvidence,
    ContractHosts,
    ContractLogin,
    ContractRouting,
    ContractSignup,
    evidence_hash_for,
)
from ops.models import CompanyProfile, OperationsRequest

_SOURCE = "https://docs.example.com/automation"


def _approved(run_id: str):
    request = OperationsRequest(
        app_name="Example",
        company=CompanyProfile(
            legal_name="RPC Company",
            website="https://example.com",
            work_email_ref="vault://company/work_email/operator",
            use_case="Provision an authorized integration.",
        ),
    )
    return build_approved_run_values(
        run_id=run_id,
        request=request,
        signup_email_ref=f"vault://gmail/signup_email/{run_id}",
        account_password_ref=f"vault://example/account_password/{run_id}",
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


def test_create_rpc_accepts_unbound_values_for_same_run_and_app() -> None:
    payload = CreateSessionRequest(
        app_slug="example",
        run_id="run_rpc",
        approved_values=_approved("run_rpc"),
        automation_contract=_contract(),
    )

    assert payload.approved_values is not None
    assert payload.approved_values.session_id is None
    assert payload.automation_contract is not None
    assert payload.automation_contract.app_slug == "example"


def test_navigation_rpc_accepts_values_bound_to_the_browser_session() -> None:
    bound = _approved("run_rpc").bind_to_session("session_rpc")

    payload = NavigateRequest(
        research={},
        approved_values=bound,
        automation_contract=_contract(),
    )

    assert payload.approved_values == bound
    assert payload.automation_contract == _contract()
    assert "vault://" not in str(bound.prompt_safe_projection())


def test_rpc_rejects_cross_run_or_cross_app_payloads() -> None:
    with pytest.raises(ValidationError):
        CreateSessionRequest(
            app_slug="example",
            run_id="run_b",
            approved_values=_approved("run_a"),
            automation_contract=_contract(),
        )

    with pytest.raises(ValidationError):
        CreateSessionRequest(
            app_slug="different",
            run_id="run_a",
            approved_values=_approved("run_a"),
            automation_contract=_contract(),
        )


def test_navigation_rejects_unbound_values() -> None:
    with pytest.raises(ValidationError):
        NavigateRequest(
            research={},
            approved_values=_approved("run_rpc"),
            automation_contract=_contract(),
        )
