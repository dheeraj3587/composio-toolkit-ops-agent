"""Happy path for the content-addressed profile store: put, read back, put again."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore

SOURCE_DIGEST = "a" * 64


def _profile() -> ProviderProfile:
    evidence = FieldEvidence(
        field="signup_url",
        value="https://provider.com/signup",
        source_url="https://provider.com/docs",
        source_digest=SOURCE_DIGEST,
        adapters=("fake-discovery",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2025-01-01T00:00:00Z",
    )
    profile = ProviderProfile(
        run_id="run-001",
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
            entry_url="https://app.provider.com/settings/api",
            produces=("api_key",),
            evidence=(replace(evidence, field="api_key_flow"),),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="unknown",
        evidence=(evidence,),
        confidence=0.85,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:01Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@pytest.fixture
def store(tmp_path) -> SQLiteProviderProfileStore:
    return SQLiteProviderProfileStore(
        tmp_path / "private" / "provider_profiles.db", owner="ops-owner"
    )


def test_put_reads_back_and_stays_one_row_on_a_second_put(store, tmp_path) -> None:
    profile = _profile()

    digest = store.put(profile)
    assert digest == profile.profile_digest

    stored = store.get(profile_digest=digest)
    assert stored == profile
    assert store.get_for_run(run_id="run-001") == profile

    citations = store.evidence_for(profile_digest=digest)
    assert {(item.field, item.value) for item in citations} == {
        ("signup_url", "https://provider.com/signup"),
        ("api_key_flow", "https://provider.com/signup"),
    }
    assert all(item.source_digest == SOURCE_DIGEST for item in citations)

    # The same body again is a no-op that returns the same address.
    assert store.put(profile) == digest

    with sqlite3.connect(tmp_path / "private" / "provider_profiles.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM provider_profiles").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM provider_profile_runs").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM provider_profile_evidence").fetchone()[
            0
        ] == len(citations)
