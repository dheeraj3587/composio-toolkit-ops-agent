from __future__ import annotations

import pytest
from pydantic import ValidationError

from ops.approved_run_values import ApprovedRunValuesRegistry, build_approved_run_values
from ops.models import CompanyProfile, OperationsRequest


def _request(company_name: str) -> OperationsRequest:
    return OperationsRequest(
        app_name="Example",
        company=CompanyProfile(
            legal_name=company_name,
            website="https://example.com",
            work_email_ref="vault://company/work_email/operator",
            use_case="Provision an authorized integration.",
            expected_volume="100 requests per day",
            callback_urls=["https://example.com/oauth/callback"],
        ),
    )


def approved(run_id: str, company_name: str):
    return build_approved_run_values(
        run_id=run_id,
        request=_request(company_name),
        signup_email_ref=f"vault://gmail/signup_email/{run_id}",
        account_password_ref=f"vault://example/account_password/{run_id}",
        profile_fields={"first_name": "A", "last_name": "Operator", "country": "IN"},
    )


def test_two_runs_keep_different_approved_company_values() -> None:
    registry = ApprovedRunValuesRegistry()
    first = registry.bind(approved("run_a", "Alpha Labs"), session_id="session_a")
    second = registry.bind(approved("run_b", "Beta Labs"), session_id="session_b")

    assert first.legal_name == "Alpha Labs"
    assert second.legal_name == "Beta Labs"
    assert registry.get(run_id="run_a", session_id="session_a") == first
    assert registry.get(run_id="run_b", session_id="session_b") == second


def test_browser_session_cannot_read_another_runs_values() -> None:
    registry = ApprovedRunValuesRegistry()
    registry.bind(approved("run_a", "Alpha Labs"), session_id="session_a")

    with pytest.raises(PermissionError):
        registry.get(run_id="run_b", session_id="session_a")
    with pytest.raises(KeyError):
        registry.get(run_id="run_a", session_id="session_missing")


def test_approved_values_are_immutable_and_cannot_be_rebound() -> None:
    values = approved("run_a", "Alpha Labs").bind_to_session("session_a")

    with pytest.raises(ValidationError):
        values.__setattr__("legal_name", "Changed")
    with pytest.raises(ValueError):
        values.bind_to_session("session_b")

    projection = values.prompt_safe_projection()
    assert set(projection) == {"run_id", "available_semantic_fields"}
    assert "vault://" not in str(projection)
