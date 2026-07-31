"""The timeline projector and its static summary allow-list (design LL-7)."""

from __future__ import annotations

import pytest

from api.models import TimelineCorrelation
from api.service import _EVENT_SUMMARIES, LocalRunService, _timeline_model
from ops.runs.projections import onboarding_timeline_event

# The event types the reliability feature adds, each with the whole of what the
# timeline is allowed to say about it. The mapping is the assertion: a summary is
# looked up by event type and is a fixed constant, so a durable row can never
# author timeline text (Requirements 1.13, 2.7, 9.4).
RELIABILITY_SUMMARIES: dict[str, str] = {
    "onboarding_takeover_continued": "Gate cleared; the agent continued the run by itself.",
    "onboarding_takeover_withheld": "Takeover withheld; the run stays paused for an operator.",
    "onboarding_attachment_changed": "Live browser view attachment changed.",
    "onboarding_route_divergence": "The run left the surface its plan declared.",
    "onboarding_progress_stale": "No loop progress within the staleness window.",
    "onboarding_plan_recorded": "Pre-flight route plan recorded.",
    "onboarding_plan_superseded": "Route plan superseded by a replacement revision.",
}


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


@pytest.mark.parametrize(("event_type", "summary"), sorted(RELIABILITY_SUMMARIES.items()))
def test_reliability_event_types_project_a_fixed_summary(event_type: str, summary: str) -> None:
    """Each new event type is allow-listed, and its row contributes no text.

    Two rows of the same type carrying different payloads must project the same
    summary and keep their own event type rather than degrading to the generic
    run-updated pair. That is the closed default read from the other side: the
    allow-list decides the words, and the payload is never consulted.
    """

    durable = {
        "run_id": "run_0123456789abcdef0123456789abcdef",
        "correlation_id": "corr_0123456789ab",
        "phase": "captcha_paused",
        "profile_digest": "b" * 64,
        "attempt": 1,
        "reason_code": "captcha_resolved",
    }
    base = {"id": 7, "created_at": "2024-05-01T12:00:00Z", "event_type": event_type}

    composed = [
        LocalRunService._timeline_event(
            onboarding_timeline_event({**base, "payload": payload}, durable=durable)
        )
        for payload in ({}, {"summary": "https://evil.example/?token=abc"})
    ]

    assert {event.event_type for event in composed} == {event_type}
    assert {event.summary for event in composed} == {summary}
    assert _EVENT_SUMMARIES[event_type] == summary
