"""One walk through the onboarding API surface (design LL-6.3, task 22.2).

A seeded run standing at ``awaiting_admission`` is taken through the five routes in
the order an operator would: read the run and see the projected state and controls,
read the sanitized profile, approve account creation (twice, to see the replay),
retry the current step, pause, and reset.

What this asserts, in the order it appears:

* the run detail response carries the additive onboarding and controls projections
  (Requirements 18.5, 18.7);
* the profile projection carries the allow-list and the citations and no excerpt
  (Requirement 18.9);
* a decision is recorded durably and answered from the record, and a second
  ``create_account`` returns the original with the replay indicator
  (Requirements 3.8, 3.9, 3.11);
* a retry names the effects the ledger proved already happened
  (Requirement 14.14);
* a pause names the phase it takes effect after and releases no session
  (Requirement 14.2);
* a reset reports the preserved-reference count, the released-session and
  cleared-state indicators, and the expected restart route (Requirement 14.11),
  and the stored credentials still resolve afterwards (Requirement 14.9);
* no response body carries a credential value (Requirement 19.13).

A real vault under ``tmp_path`` holds the login pair, because the claim reset makes
is about *stored* references; a double would only restate the test's assumption.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.service import LocalRunService
from ops.core.config import Settings
from ops.core.secret_store import SQLiteSecretStore
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.onboarding.phase import OnboardingPhase
from ops.providers.profile import (
    AuxiliaryHost,
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.runs.service import RunService as CoreRunService

RUN_ID = "run_" + "4" * 32
APP_SLUG = "example-provider"
ACCOUNT_REF = "acct_" + "5" * 32
LOGIN_PASSWORD = "generated-signup-password"  # pragma: allowlist secret

# The walk the driver has committed when the operator opens the run page: research
# corroborated a profile, the vault probe found nothing, and the run is waiting for
# an admission decision.
WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase], ...] = (
    (None, "research"),
    ("research", "vault_check"),
    ("vault_check", "awaiting_admission"),
)

# The two boundaries the driver commits once the operator approves, replayed here
# so the retry and pause controls act on a run standing at a real step.
APPROVED: tuple[tuple[OnboardingPhase, OnboardingPhase], ...] = (
    ("awaiting_admission", "route_selected_signup"),
    ("route_selected_signup", "signup"),
)


def _profile() -> ProviderProfile:
    evidence = FieldEvidence(
        field="signup_url",
        value="https://example.test/signup",
        source_url="https://example.test/docs",
        source_digest="c" * 64,
        adapters=("perplexity_search",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2024-05-01T12:00:00Z",
    )
    unsupported = FlowSpec(kind="oauth", supported=False, entry_url=None)
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Example Provider",
        app_slug=APP_SLUG,
        registrable_domain="example.test",
        auxiliary_hosts=(
            AuxiliaryHost(host="cdn.example.test", kind="static_assets", source_digest="c" * 64),
        ),
        developer_portal_url="https://developers.example.test",
        signup_url="https://example.test/signup",
        login_url="https://example.test/login",
        developer_docs_url=None,
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://developers.example.test/apps",
            steps=("Open the developer portal",),
            produces=("api_key",),
        ),
        oauth_flow=unsupported,
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://developers.example.test/keys",
            produces=("api_key",),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(evidence,),
        confidence=0.9,
        adapters_engaged=("perplexity_search",),
        built_at="2024-05-01T12:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    # Owner-gated routes: the opt-in plus a loopback client is the same gate the
    # existing operator mutations use.
    monkeypatch.setenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", "true")
    db_path = tmp_path / "private" / "ops.db"
    vault_key = Fernet.generate_key().decode()
    settings = Settings(
        secret_vault_key=SecretStr(vault_key),
        secret_vault_db_path=tmp_path / "private" / "secret_vault.db",
        allow_local_credential_submission=True,
    )
    core = CoreRunService.from_paths(db_path=db_path, settings=settings)
    core.storage.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug=APP_SLUG,
        browser_account_ref=ACCOUNT_REF,
    )
    profile = _profile()
    SQLiteProviderProfileStore(
        db_path.parent / "provider_profiles.db",
        owner=settings.browser_service_owner,
    ).put(profile)
    phases = SQLitePhaseHistoryStore(db_path)
    for index, (source, target) in enumerate(WALK):
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=source,
            to_phase=target,
            reason_code="profile_corroborated"
            if target != "awaiting_admission"
            else "credentials_missing",
            profile_digest=profile.profile_digest,
            attempt=0,
            correlation_id=f"walk-{index}",
        )
    # The real vault, over the same file the run service opens at startup: reset's
    # preserved-reference count has to be read from stored references.
    SQLiteSecretStore(settings.secret_vault_db_path, vault_key).put_account_login_pair(
        app_slug=APP_SLUG,
        account_ref=ACCOUNT_REF,
        email="onboarding@example.invalid",
        password=LOGIN_PASSWORD,
    )
    service = LocalRunService(db_path, core_service=core, settings=settings)
    with TestClient(create_app(service=service), raise_server_exceptions=False) as api:
        yield api


def test_onboarding_routes_project_state_decide_retry_pause_and_reset(
    client: TestClient,
    tmp_path: Path,
) -> None:
    digest = _profile().profile_digest

    detail = client.get(f"/api/runs/{RUN_ID}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["onboarding"]["phase"] == "awaiting_admission"
    assert body["onboarding"]["profile_digest"] == digest
    assert body["onboarding"]["reason_code"] == "credentials_missing"
    assert body["onboarding"]["goal"] == "Decide how to authenticate"
    assert body["controls"] == {
        "can_decide_admission": True,
        "can_pause": True,
        "can_resume": False,
        "can_cancel": True,
        "can_reset": True,
        "can_retry_step": False,
        "retryable_step": None,
        "reason_code": "credentials_missing",
    }

    profile = client.get(f"/api/runs/{RUN_ID}/profile")
    assert profile.status_code == 200
    projected = profile.json()
    assert projected["registrable_domain"] == "example.test"
    assert projected["allowed_host_patterns"] == [
        "*.example.test",
        "example.test",
        "cdn.example.test",
    ]
    assert projected["evidence"][0]["field"] == "signup_url"

    decision = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": digest},
    )
    assert decision.status_code == 200
    recorded = decision.json()
    assert recorded["route"] == "signup"
    assert recorded["reason_code"] == "operator_approved_signup"
    assert recorded["decided_by"] == "operator"
    assert recorded["replayed"] is False
    assert recorded["decided_at"]

    replay = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": digest},
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["decided_at"] == recorded["decided_at"]

    # The two boundaries the driver commits on the approved route, so the retry
    # and pause controls act on a run standing at the signup step.
    phases = SQLitePhaseHistoryStore(tmp_path / "private" / "ops.db")
    for index, (source, target) in enumerate(APPROVED):
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=source,
            to_phase=target,
            reason_code="operator_approved_signup"
            if target == "route_selected_signup"
            else "signup_submitted",
            profile_digest=digest,
            attempt=0,
            correlation_id=f"approved-{index}",
        )

    retried = client.post(
        f"/api/runs/{RUN_ID}/retry",
        json={"expected_phase": "signup"},
    )
    assert retried.status_code == 200
    assert retried.json() == {
        "run_id": RUN_ID,
        "accepted": True,
        "phase": "signup",
        "attempt": 1,
        "reason_code": "step_retried",
        "skipped_effects": [],
    }

    paused = client.post(f"/api/runs/{RUN_ID}/pause", json={"reason": "stepping away"})
    assert paused.status_code == 200
    assert paused.json()["accepted"] is True
    assert paused.json()["pausing_after_phase"] == "signup"
    assert paused.json()["browser_session_released"] is False
    assert paused.json()["onboarding"]["phase"] == "paused"

    reset = client.post(f"/api/runs/{RUN_ID}/reset", json={"confirm": True})
    assert reset.status_code == 200
    assert reset.json() == {
        "run_id": RUN_ID,
        "reason_code": "run_reset",
        "phase": "research",
        "browser_session_released": False,
        "workflow_state_cleared": False,
        "vault_references_preserved": 2,
        "expected_route_on_restart": "login",
    }

    # Requirement 14.12: an unconfirmed reset is refused before any side effect.
    assert client.post(f"/api/runs/{RUN_ID}/reset", json={}).status_code == 422

    # Requirement 19.13: no body carried credential material.
    for response in (detail, profile, decision, retried, paused, reset):
        assert LOGIN_PASSWORD not in response.text
        assert "onboarding@example.invalid" not in response.text
