"""The closed onboarding timeline schemas (design LL-7)."""

from __future__ import annotations

from api.models import TimelineCorrelation, TimelineDetail, TimelineEvent


def test_onboarding_timeline_event_carries_correlation_and_detail() -> None:
    event = TimelineEvent(
        event_id=7,
        event_type="onboarding_credentials_validated",
        summary="Credential validation passed.",
        status="completed",
        created_at="2024-05-01T12:00:00Z",
        correlation=TimelineCorrelation(
            run_id="run_0123456789abcdef0123456789abcdef",
            correlation_id="corr_0123456789ab",
            onboarding_phase="credential_validation",
            profile_digest="a" * 64,
            attempt=1,
            reason_code="credential_valid",
            browser_session_id="sess_0123456789ab",
            vault_reference_id="id_0123456789ab",
        ),
        detail=TimelineDetail(
            registrable_domain="example.test",
            credential_kind="api_key",
            validation_endpoint="https://api.example.test/v1/me",
            validation_http_status=200,
            checked_at="2024-05-01T12:00:00Z",
        ),
    )

    assert event.correlation is not None
    assert event.correlation.onboarding_phase == "credential_validation"
    assert event.detail is not None
    assert event.detail.validation_http_status == 200
    # Fields the schema does not declare are simply absent, never free text.
    assert event.detail.host is None


def test_legacy_timeline_event_omits_onboarding_fields() -> None:
    event = TimelineEvent(
        event_id=1,
        event_type="run_created",
        summary="Run state updated.",
        status="recorded",
        created_at="2024-05-01T12:00:00Z",
    )

    assert event.correlation is None
    assert event.detail is None
