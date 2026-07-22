from __future__ import annotations

from typing import get_type_hints

import pytest
from pydantic import ValidationError

from ops.config import Settings
from ops.models import CompanyProfile, IntegratorBundle, OperationsRequest
from ops.state import OperationsState


def company_profile(**overrides: object) -> CompanyProfile:
    values: dict[str, object] = {
        "legal_name": "Example Labs, Inc.",
        "website": "https://example.test",
        "work_email_ref": "vault://company/work_email/profile_1",
        "use_case": "Build a customer-authorized integration.",
    }
    values.update(overrides)
    return CompanyProfile.model_validate(values)


def bundle(**overrides: object) -> IntegratorBundle:
    values: dict[str, object] = {
        "app_name": "Example",
        "app_slug": "example",
        "readiness": "credentials_ready",
        "api_type": "REST",
        "api_base_url": "https://api.example.test",
        "auth_scheme": "oauth2",
        "authorization_url": "https://example.test/oauth/authorize",
        "token_url": "https://example.test/oauth/token",
        "scopes": ["contacts.read"],
        "callback_urls": ["https://integrator.test/oauth/callback"],
        "credential_refs": {
            "client_id": "vault://example/client_id/id_123",
            "client_secret": "vault://example/client_secret/secret_456",  # pragma: allowlist secret
        },
        "access_route": "self_serve",
        "provider_account_id": "account-1",
        "developer_app_id": "app-1",
        "evidence_urls": ["https://example.test/docs"],
        "operational_notes": ["Created in a controlled dry run."],
        "created_at": "2026-07-22T12:00:00Z",
    }
    values.update(overrides)
    return IntegratorBundle.model_validate(values)


def test_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        OperationsRequest(
            app_name="Example",
            company=company_profile(),
            raw_api_key="must-not-be-representable",  # type: ignore[call-arg]  # pragma: allowlist secret
        )


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "raw-client-secret",
        "Bearer abcdefghijklmnop",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123",  # pragma: allowlist secret
        "vault://UPPER/client_secret/id",
        "vault://example/client.secret/id",
        "vault://example/client_secret/id/extra",
    ],
)
def test_integrator_bundle_rejects_non_reference_credentials(
    unsafe_value: str,
) -> None:
    with pytest.raises(ValidationError) as raised:
        bundle(credential_refs={"client_secret": unsafe_value})

    assert unsafe_value not in str(raised.value)


def test_company_email_is_an_opaque_vault_reference() -> None:
    with pytest.raises(ValidationError) as raised:
        company_profile(work_email_ref="operator@example.test")

    assert "operator@example.test" not in str(raised.value)


def test_valid_references_survive_contract_serialization() -> None:
    validated = bundle()

    assert validated.credential_refs["client_secret"].startswith("vault://example/")
    assert validated.model_dump()["credential_refs"] == validated.credential_refs


def test_mutable_defaults_are_not_shared() -> None:
    first = company_profile()
    second = company_profile()

    first.callback_urls.append("https://first.test/callback")

    assert second.callback_urls == []


def test_operations_state_has_expiry_metadata_and_no_raw_secret_fields() -> None:
    fields = get_type_hints(OperationsState)

    assert {
        "browser_session_started_at",
        "browser_session_last_active_at",
        "browser_session_inactivity_expires_at",
        "browser_session_max_expires_at",
    }.issubset(fields)
    assert {
        "password",
        "api_key",
        "client_secret",
        "access_token",
        "refresh_token",
        "authorization_code",
        "cookie",
    }.isdisjoint(fields)


def test_settings_default_to_no_live_email_and_hide_secret_repr() -> None:
    marker = "config-secret-value-that-must-not-render"
    settings = Settings.from_env(
        env={
            "SECRET_VAULT_KEY": marker,
            "COMPANY_WORK_EMAIL_REF": "vault://company/work_email/profile_1",
        }
    )

    assert settings.allow_live_vendor_email is False
    assert settings.company_work_email_ref == "vault://company/work_email/profile_1"
    assert marker not in repr(settings)
    assert marker not in str(settings)
    assert "company_work_email" not in Settings.model_fields
