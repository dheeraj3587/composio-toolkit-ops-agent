from __future__ import annotations

from typing import get_type_hints

import pytest
from pydantic import ValidationError

from ops.core.config import Settings
from ops.core.models import CompanyProfile, IntegratorBundle, OperationsRequest
from ops.core.state import OperationsState


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


def test_operations_state_carries_onboarding_references_and_no_credential_material() -> None:
    fields = get_type_hints(OperationsState)

    assert {
        "onboarding_phase",
        "onboarding_phase_at_pause",
        "profile_digest",
        "provider_registrable_domain",
        "onboarding_account_ref",
        "developer_app_id",
        "onboarding_credential_generation",
        "onboarding_reason_code",
    }.issubset(fields)
    assert {
        "onboarding_credential",
        "onboarding_credential_value",
        "onboarding_login_password",
        "onboarding_account_password",
        "verification_link",
        "verification_code",
    }.isdisjoint(fields)
    assert OperationsState.__total__ is False


def test_settings_default_to_no_live_email_and_hide_secret_repr() -> None:
    marker = "config-secret-value-that-must-not-render"
    settings = Settings.from_env(
        env={
            "SECRET_VAULT_KEY": marker,
            "COMPANY_WORK_EMAIL_REF": "vault://company/work_email/profile_1",
        }
    )

    assert settings.allow_live_vendor_email is False
    assert settings.browser_interactive_hitl_enabled is False
    assert settings.company_work_email_ref == "vault://company/work_email/profile_1"
    assert marker not in repr(settings)
    assert marker not in str(settings)
    assert "company_work_email" not in Settings.model_fields


def test_interactive_browser_capability_is_explicitly_env_backed() -> None:
    settings = Settings.from_env(env={"BROWSER_INTERACTIVE_HITL_ENABLED": "true"})
    assert settings.browser_interactive_hitl_enabled is True


# ---- Autonomous provider onboarding budgets ----------------------------------
def test_onboarding_budget_defaults_match_the_stated_bounds() -> None:
    """Every onboarding budget default is the number the requirements state.

    The defaults are the contract: the loop, the CAPTCHA pause, verification, and
    the lease all terminate on these, so a silent drift here would change when a
    run stops touching a provider.
    """

    settings = Settings.from_env(env={})

    assert settings.onboarding_loop_max_actions == 60
    assert settings.onboarding_loop_max_model_calls == 80
    assert settings.onboarding_loop_max_no_progress == 6
    assert settings.onboarding_loop_max_wallclock_seconds == 900
    assert settings.onboarding_loop_max_navigation_denials == 10
    assert settings.onboarding_captcha_pause_budget == 3
    assert settings.onboarding_verification_base_delay_seconds == 5.0
    assert settings.onboarding_verification_attempt_budget == 3
    assert settings.onboarding_verification_max_message_age_seconds == 3_600
    assert settings.onboarding_lease_ttl_seconds == 60
    assert settings.onboarding_lease_renew_interval_seconds == 20
    # Requirement 21.3: the onboarding browser pool capacity is the existing
    # Playwright session cap, not a second setting that could disagree with it.
    assert settings.playwright_max_sessions == 2
    assert "onboarding_browser_pool_capacity" not in Settings.model_fields


def test_credential_ladder_budgets_are_configured_and_bounded() -> None:
    """The two budgets that give the retry -> supersede -> pause ladder an end."""

    assert Settings().credential_validation_attempt_budget == 3
    assert Settings().credential_generation_budget == 2

    overridden = Settings.from_env(
        env={
            "CREDENTIAL_VALIDATION_ATTEMPT_BUDGET": "10",
            "CREDENTIAL_GENERATION_BUDGET": "5",
        }
    )
    assert overridden.credential_validation_attempt_budget == 10
    assert overridden.credential_generation_budget == 5


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("CREDENTIAL_VALIDATION_ATTEMPT_BUDGET", "0"),
        ("CREDENTIAL_VALIDATION_ATTEMPT_BUDGET", "11"),
        ("CREDENTIAL_GENERATION_BUDGET", "0"),
        ("CREDENTIAL_GENERATION_BUDGET", "6"),
        ("ONBOARDING_CAPTCHA_PAUSE_BUDGET", "0"),
        ("ONBOARDING_VERIFICATION_ATTEMPT_BUDGET", "0"),
        # Requirement 7.11 bounds the configured maximum message age at 3600 s.
        ("ONBOARDING_VERIFICATION_MAX_MESSAGE_AGE_SECONDS", "3601"),
        ("ONBOARDING_LOOP_MAX_ACTIONS", "0"),
        ("ONBOARDING_LOOP_MAX_NO_PROGRESS", "0"),
    ],
)
def test_onboarding_budgets_reject_out_of_range_values(variable: str, value: str) -> None:
    """A budget outside its bound fails at startup, not mid-run."""

    with pytest.raises(ValidationError):
        Settings.from_env(env={variable: value})


def test_lease_renewal_interval_must_stay_within_a_third_of_the_lease() -> None:
    """Requirements 16.5 and 16.7: two renewals may fail before the deadline.

    That is only true while the renew interval is at most a third of the TTL, so a
    wider cadence is rejected rather than silently fencing a live worker out.
    """

    with pytest.raises(ValidationError, match="one third"):
        Settings.from_env(
            env={
                "ONBOARDING_LEASE_TTL_SECONDS": "60",
                "ONBOARDING_LEASE_RENEW_INTERVAL_SECONDS": "30",
            }
        )

    tightened = Settings.from_env(
        env={
            "ONBOARDING_LEASE_TTL_SECONDS": "120",
            "ONBOARDING_LEASE_RENEW_INTERVAL_SECONDS": "30",
        }
    )
    assert tightened.onboarding_lease_ttl_seconds == 120
    assert tightened.onboarding_lease_renew_interval_seconds == 30
