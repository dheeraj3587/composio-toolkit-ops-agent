"""Happy-path check on operation-key derivation and retry disposition.

Two things are worth one test each. A key is a *pure function of durable facts*,
so the same facts derive the same key while a changed fact derives a different
one — that is what makes a retry safe and a supersede a genuinely new effect. And
the ledger's four row statuses each authorize exactly one disposition, because
"execute" on the wrong status means a second account, application, or credential.
"""

from __future__ import annotations

from dataclasses import replace

from ops.onboarding.effects import (
    EFFECT_KEY_VERSION,
    EFFECT_PROVIDER,
    EffectRowStatus,
    create_dev_app_key,
    generate_credential_key,
    plan_for_row_status,
    signup_submit_key,
)
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile, compute_profile_digest

DIGEST = "a" * 64


def _profile() -> ProviderProfile:
    profile = ProviderProfile(
        run_id="run-1",
        provider_name="Provider",
        app_slug="provider",
        registrable_domain="provider.com",
        auxiliary_hosts=(),
        developer_portal_url="https://developers.provider.com/",
        signup_url="https://provider.com/signup",
        login_url="https://app.provider.com/login",
        developer_docs_url="https://developers.provider.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://developers.provider.com/apps/new",
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://app.provider.com/settings/api",
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(
            FieldEvidence(
                field="signup_url",
                value="https://provider.com/signup",
                source_url="https://provider.com/docs",
                source_digest=DIGEST,
                adapters=("fake-discovery",),
                corroborations=2,
                confidence=0.9,
                extracted_at="2025-01-01T00:00:00Z",
            ),
        ),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


def test_keys_are_stable_across_retries_and_distinct_across_facts() -> None:
    profile = _profile()

    signup = signup_submit_key("run-1", profile, "mailbox-1")
    dev_app = create_dev_app_key("run-1", profile, "ops-run-1")
    credential = generate_credential_key("run-1", "app-9", "api_key", 0)

    # Same durable facts, derived again: byte-identical, so a retry, a second
    # worker, and a resumed run collide on one ledger row.
    assert signup == signup_submit_key("run-1", profile, "mailbox-1")
    assert dev_app == create_dev_app_key("run-1", profile, "ops-run-1")
    assert credential == generate_credential_key("run-1", "app-9", "api_key", 0)
    assert len({signup, dev_app, credential}) == 3
    assert signup.endswith(f":v{EFFECT_KEY_VERSION}")

    # A canonicalization-only difference is the same effect: upper-case host,
    # default port, query, and a trailing slash all fold away. The digest is held
    # fixed because it, too, would otherwise change with the URL.
    noisy = replace(profile, signup_url="https://PROVIDER.com:443/signup/?ref=a")
    assert (
        signup_submit_key(
            "run-1", replace(noisy, profile_digest=profile.profile_digest), "mailbox-1"
        )
        == signup
    )

    # A changed durable fact is a different effect.
    assert signup_submit_key("run-2", profile, "mailbox-1") != signup
    assert signup_submit_key("run-1", profile, "mailbox-2") != signup
    assert create_dev_app_key("run-1", profile, "ops-run-2") != dev_app
    # The supersede path advances the generation, which is the only escape hatch.
    assert generate_credential_key("run-1", "app-9", "api_key", 1) != credential


def test_row_status_maps_to_its_only_safe_disposition() -> None:
    expected: dict[EffectRowStatus | None, str] = {
        None: "execute",
        "failed": "execute",
        "pending": "reconcile",
        "outcome_unknown": "reconcile",
        "completed": "skip",
    }
    for row_status, disposition in expected.items():
        receipt = {"developer_app_id": "app-9"} if row_status == "completed" else None
        plan = plan_for_row_status(
            operation_key="run-1:create-dev-app:abc:v1",
            action="create_dev_app",
            row_status=row_status,
            receipt=receipt,
        )
        assert plan.disposition == disposition
        assert plan.provider == EFFECT_PROVIDER
        assert plan.action == "create_dev_app"

    skipped = plan_for_row_status(
        operation_key="run-1:create-dev-app:abc:v1",
        action="create_dev_app",
        row_status="completed",
        receipt={"developer_app_id": "app-9"},
    )
    assert skipped.receipt == {"developer_app_id": "app-9"}
    assert skipped.reason_code == "developer_app_created"
