"""The timeline projector and its static summary allow-list (design LL-7)."""

from __future__ import annotations

from api.models import TimelineCorrelation
from api.service import _EVENT_SUMMARIES, _timeline_model
from ops.runs.projections import onboarding_timeline_event


def test_durable_row_projects_static_summary_and_correlation() -> None:
    """A durable onboarding row projects attribution; an unknown type degrades."""

    # The audit row as stored, joined with the run's durable onboarding columns.
    durable = {
        "run_id": "run_0123456789abcdef0123456789abcdef",
        "correlation_id": "corr_0123456789ab",
        "phase": "credential_generation",
        "profile_digest": "a" * 64,
        "attempt": 2,
        "reason_code": "credential_generated",
        "provider_session_id": "sess_0123456789ab",
        "credential_reference": "vault://acme/api_key/abc123XYZ_-",
        "credential_kind": "api_key",
    }
    row = {
        "id": 11,
        "event_type": "onboarding_credentials_generated",
        # A payload can never reach the projection, so its content is irrelevant.
        "payload": {"note": "ignored"},
        "created_at": "2024-05-01T12:00:00Z",
    }

    projected = onboarding_timeline_event(row, durable=durable)
    correlation = _timeline_model(TimelineCorrelation, projected.correlation)

    assert correlation is not None
    assert correlation.onboarding_phase == "credential_generation"
    assert correlation.attempt == 2
    assert correlation.browser_session_id == "sess_0123456789ab"
    # Derived from the reference's id segment, not from the secret.
    assert correlation.vault_reference_id == "abc123XYZ_-"
    assert projected.detail == {"credential_kind": "api_key"}
    assert (
        _EVENT_SUMMARIES["onboarding_credentials_generated"]
        == "Credential generated and stored behind a vault reference."
    )

    # An event type outside the allow-list has no summary to project.
    unknown = onboarding_timeline_event(
        {**row, "event_type": "onboarding_future_event"}, durable=durable
    )
    assert unknown.event_type not in _EVENT_SUMMARIES
    assert unknown.detail is None
