"""Happy path for the profile-derived capture contract, plus its one refusal."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ops.onboarding.capture_specs import (
    CaptureContractUnavailable,
    profile_capture_contract,
)
from ops.onboarding.credentials import CREDENTIAL_VALUE_PATTERNS
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore

SOURCE_DIGEST = "a" * 64
ENTRY_URL = "https://app.provider.com/settings/api"


class _Core:
    """The one attribute ``profile_capture_contract`` reads off the run service."""

    def __init__(self, store: SQLiteProviderProfileStore) -> None:
        self.provider_profile_store = store


def _profile(run_id: str) -> ProviderProfile:
    evidence = FieldEvidence(
        field="api_key_flow",
        value=ENTRY_URL,
        source_url="https://developers.provider.com/docs",
        source_digest=SOURCE_DIGEST,
        adapters=("fake-discovery",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2025-01-01T00:00:00Z",
    )
    profile = ProviderProfile(
        run_id=run_id,
        provider_name="Provider",
        app_slug="provider",
        registrable_domain="provider.com",
        auxiliary_hosts=(),
        developer_portal_url="https://developers.provider.com/",
        signup_url="https://provider.com/signup",
        login_url="https://app.provider.com/login",
        developer_docs_url="https://developers.provider.com/docs",
        developer_app_flow=FlowSpec(kind="developer_app", supported=False, entry_url=None),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url=ENTRY_URL,
            produces=("api_key",),
            evidence=(evidence,),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="unknown",
        evidence=(replace(evidence, field="signup_url", value="https://provider.com/signup"),),
        confidence=0.85,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:01Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@pytest.fixture
def core(tmp_path) -> _Core:
    store = SQLiteProviderProfileStore(
        tmp_path / "private" / "provider_profiles.db", owner="ops-owner"
    )
    store.put(_profile("run-capture-001"))
    return _Core(store)


def test_committed_profile_yields_the_checked_in_contract(core) -> None:
    spec = profile_capture_contract(core, run_id="run-capture-001", kind="api_key")

    assert spec.app_slug == "provider"
    assert spec.url == ENTRY_URL
    assert spec.vendor_domain == "provider.com"
    assert spec.field_kind == "api_key"
    assert spec.value_pattern == CREDENTIAL_VALUE_PATTERNS["api_key"]
    # The profile-driven path proves the credential surface through the loop's
    # postcondition classification, so no reviewed selector list exists.
    assert spec.selectors == ()


def test_a_kind_no_declared_flow_mints_is_capture_spec_unavailable(core) -> None:
    with pytest.raises(CaptureContractUnavailable) as raised:
        profile_capture_contract(core, run_id="run-capture-001", kind="oauth_client_secret")

    assert raised.value.reason_code == "capture_spec_unavailable"
    assert raised.value.detail == "flow_entry_url_absent"
