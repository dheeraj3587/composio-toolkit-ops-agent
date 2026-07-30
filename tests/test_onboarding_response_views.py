"""The onboarding response views (design LL-6.2, LL-6.3)."""

from __future__ import annotations

from pydantic import SecretStr

from api.models import (
    AutonomyOutcomeView,
    FieldEvidenceView,
    FlowSpecView,
    OnboardingControlsView,
    OnboardingStateView,
    ProviderProfileView,
    RunDetailResponse,
)

ONBOARDING_VIEWS = (
    OnboardingStateView,
    OnboardingControlsView,
    AutonomyOutcomeView,
    FieldEvidenceView,
    FlowSpecView,
    ProviderProfileView,
)


def test_onboarding_views_project_state_controls_outcome_and_profile() -> None:
    state = OnboardingStateView(
        phase="credential_validation",
        profile_digest="a" * 64,
        reason_code="credential_valid",
        goal="Generate an API credential",
        step="Validating the stored credential",
        latest_decision="Called the provider's identity endpoint",
        attempt=1,
        admission_prompts=1,
        captcha_prompts=0,
        correlation_id="corr_0123456789ab",
    )
    controls = OnboardingControlsView(can_pause=True, can_cancel=True)
    autonomy = AutonomyOutcomeView(
        verdict="fully_autonomous",
        terminal_phase="completed",
        reason_code="credential_valid",
        admission_prompts=1,
        captcha_prompts=0,
        duration_seconds=412,
    )
    profile = ProviderProfileView(
        run_id="run_0123456789abcdef",
        profile_digest="b" * 64,
        provider_name="Example Provider",
        app_slug="example-provider",
        registrable_domain="example.test",
        allowed_host_patterns=["*.example.test"],
        auxiliary_hosts=[{"host": "login.okta.test", "kind": "identity_provider"}],
        developer_portal_url="https://developers.example.test",
        flows=[
            FlowSpecView(
                kind="api_key",
                supported=True,
                entry_url="https://developers.example.test/keys",
                steps=["Open the developer portal"],
                produces=["api_key"],
            )
        ],
        approval_requirement="unknown",
        billing_requirement="unknown",
        evidence=[
            FieldEvidenceView(
                field="signup_url",
                value="https://example.test/signup",
                source_url="https://example.test/docs",
                source_digest="c" * 64,
                adapters=["perplexity_search"],
                corroborations=2,
                confidence=0.9,
            )
        ],
        confidence=0.9,
        built_at="2024-05-01T12:00:00Z",
    )

    assert {"onboarding", "controls", "autonomy"} <= set(RunDetailResponse.model_fields)
    assert state.phase_at_pause is None
    # A control is unavailable unless the backend proved otherwise.
    assert controls.can_decide_admission is False
    assert controls.retryable_step is None
    assert autonomy.verdict == "fully_autonomous"
    assert profile.auxiliary_hosts[0].kind == "identity_provider"
    assert profile.flows[0].produces == ["api_key"]
    # Requirement 19.7, 19.8: contract drift is forbidden and no onboarding view
    # declares a secret-string field.
    for view in ONBOARDING_VIEWS:
        assert view.model_config["extra"] == "forbid"
        assert all(
            SecretStr.__name__ not in repr(field.annotation) for field in view.model_fields.values()
        ), view.__name__
