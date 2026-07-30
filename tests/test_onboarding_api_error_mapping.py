"""The onboarding error mapping, one case per row of design LL-6.4 (task 22.3).

Six refusals and two non-refusals, all read off the same seeded pair of runs:

* a decision naming a profile the run has not committed is 409 `phase_replay_noop`
  and leaves the recorded decision and the committed phase alone (Requirement 3.10);
* a decision on a run that never reached the admission gate is 409 carrying the
  run's *current* reason code (Requirement 3.15);
* a `cancel` arriving after signup was approved is 409 `operator_approved_signup`
  and leaves the recorded route as it was (Requirement 3.12);
* a retry naming a phase the run is not standing in is 409 `phase_replay_noop`
  with the phase history unchanged (Requirement 14.16);
* a retry while an effect stands at `outcome_unknown` is 409 `outcome_unknown`
  with the key's submission count unmoved, so no submission was authorized
  (Requirement 14.17);
* a reset without `confirm` is 422, and the vault pair and the phase history are
  exactly what they were before it (Requirement 14.12);
* a blocked run and a paused run are *not* errors: both read 200 carrying the
  phase and the reason code.

The blocked run is seeded as its own run because "not awaiting admission" has to
be observed with no decision on record — reusing the approved run would only
re-test the replay path.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.service import LocalRunService
from ops.core.config import Settings
from ops.core.secret_store import SQLiteSecretStore
from ops.core.storage import OnboardingAuditContext, OperationsStorage
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.onboarding.phase import OnboardingPhase
from ops.providers.profile import FlowSpec, ProviderProfile, compute_profile_digest
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.runs.service import RunService as CoreRunService

RUN_ID = "run_" + "6" * 32
BLOCKED_RUN_ID = "run_" + "7" * 32
APP_SLUG = "example-provider"
ACCOUNT_REF = "acct_" + "8" * 32
LOGIN_PASSWORD = "generated-signup-password"  # pragma: allowlist secret
CORRELATION_ID = "e" * 32
OPERATION_KEY = f"{RUN_ID}:signup-submit:0123456789abcdef:v1"
OTHER_DIGEST = "d" * 64

# The walk that leaves the run at the admission gate.
WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase], ...] = (
    (None, "research"),
    ("research", "vault_check"),
    ("vault_check", "awaiting_admission"),
)


def _profile() -> ProviderProfile:
    unsupported = FlowSpec(kind="oauth", supported=False, entry_url=None)
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Example Provider",
        app_slug=APP_SLUG,
        registrable_domain="example.test",
        auxiliary_hosts=(),
        developer_portal_url="https://developers.example.test",
        signup_url="https://example.test/signup",
        login_url="https://example.test/login",
        developer_docs_url=None,
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://developers.example.test/apps",
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
        evidence=(),
        confidence=0.9,
        adapters_engaged=("perplexity_search",),
        built_at="2024-05-01T12:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@dataclass(frozen=True, slots=True)
class _Harness:
    """The client and the run's own vault, so "unchanged" can be read, not assumed."""

    api: TestClient
    vault: SQLiteSecretStore
    db_path: Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Harness]:
    monkeypatch.setenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", "true")
    db_path = tmp_path / "private" / "ops.db"
    vault_key = Fernet.generate_key().decode()
    settings = Settings(
        secret_vault_key=SecretStr(vault_key),
        secret_vault_db_path=tmp_path / "private" / "secret_vault.db",
        allow_local_credential_submission=True,
    )
    core = CoreRunService.from_paths(db_path=db_path, settings=settings)
    for run_id in (RUN_ID, BLOCKED_RUN_ID):
        core.storage.create_run(
            run_id=run_id,
            thread_id=f"thread-{run_id}",
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
            reason_code=(
                "profile_corroborated" if target != "awaiting_admission" else "credentials_missing"
            ),
            profile_digest=profile.profile_digest,
            attempt=0,
            correlation_id=f"walk-{index}",
        )
    # The second run stops at a terminal, non-error condition: research could not
    # be corroborated, so the run is blocked and holds no admission decision.
    for index, (source, target) in enumerate(((None, "research"), ("research", "blocked"))):
        assert phases.commit_phase(
            run_id=BLOCKED_RUN_ID,
            from_phase=source,
            to_phase=target,
            reason_code=(
                "profile_corroborated" if target == "research" else "research_inconclusive"
            ),
            profile_digest=profile.profile_digest,
            attempt=0,
            correlation_id=f"blocked-{index}",
        )
    vault = SQLiteSecretStore(settings.secret_vault_db_path, vault_key)
    vault.put_account_login_pair(
        app_slug=APP_SLUG,
        account_ref=ACCOUNT_REF,
        email="onboarding@example.invalid",
        password=LOGIN_PASSWORD,
    )
    service = LocalRunService(db_path, core_service=core, settings=settings)
    with TestClient(create_app(service=service), raise_server_exceptions=False) as api:
        yield _Harness(api=api, vault=vault, db_path=db_path)


def _seed_unknown_signup_effect(db_path: Path, *, digest: str) -> SQLitePhaseHistoryStore:
    """Take the approved run to ``signup`` with its submission outcome ambiguous.

    Both halves are needed for the API to see it: the reservation row the retry
    control reads, and the audit row the effect-ledger port uses as its index.
    """

    phases = SQLitePhaseHistoryStore(db_path)
    assert phases.commit_phase(
        run_id=RUN_ID,
        from_phase="awaiting_admission",
        to_phase="route_selected_signup",
        reason_code="operator_approved_signup",
        profile_digest=digest,
        attempt=0,
        correlation_id="approved-0",
    )
    commit = phases.commit_phase_with_reservation(
        run_id=RUN_ID,
        from_phase="route_selected_signup",
        to_phase="signup",
        reason_code="signup_submitted",
        profile_digest=digest,
        attempt=0,
        correlation_id="approved-1",
        effect="signup_submit",
        operation_key=OPERATION_KEY,
    )
    assert commit.committed
    record = phases.mark_effect_reservation_outcome_unknown(
        run_id=RUN_ID, operation_key=OPERATION_KEY
    )
    assert record.disposition == "pause_outcome_unknown"
    context = OnboardingAuditContext(
        run_id=RUN_ID,
        phase="signup",
        profile_digest=digest,
        attempt=0,
        correlation_id=CORRELATION_ID,
    )
    with OperationsStorage(db_path).unit_of_work() as transaction:
        transaction.record_effect_reservation_audit(
            context=context,
            operation_key=OPERATION_KEY,
            effect="signup_submit",
            generation=0,
            disposition="execute",
            reason_code="signup_submitted",
        )
    return phases


def test_onboarding_refusals_carry_their_reason_code_and_change_nothing(
    harness: _Harness,
) -> None:
    client = harness.api
    db_path = harness.db_path
    digest = _profile().profile_digest

    # Requirement 3.10: a decision about another profile is refused outright.
    mismatch = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": OTHER_DIGEST},
    )
    assert mismatch.status_code == 409
    assert mismatch.json()["reason_code"] == "phase_replay_noop"

    # Requirement 3.15: a decision on a run that is not at the gate reports the
    # run's own reason code — and the blocked run itself still reads 200.
    not_awaiting = client.post(
        f"/api/runs/{BLOCKED_RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": digest},
    )
    assert not_awaiting.status_code == 409
    assert not_awaiting.json()["reason_code"] == "research_inconclusive"
    blocked_detail = client.get(f"/api/runs/{BLOCKED_RUN_ID}")
    assert blocked_detail.status_code == 200
    assert blocked_detail.json()["onboarding"]["phase"] == "blocked"
    assert blocked_detail.json()["onboarding"]["reason_code"] == "research_inconclusive"

    approved = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": digest},
    )
    assert approved.status_code == 200
    assert approved.json()["route"] == "signup"

    # Requirement 3.12: withdrawing an approved signup is refused, route intact.
    cancelled = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "cancel", "profile_digest": digest},
    )
    assert cancelled.status_code == 409
    assert cancelled.json()["reason_code"] == "operator_approved_signup"
    replay = client.post(
        f"/api/runs/{RUN_ID}/decision",
        json={"decision": "create_account", "profile_digest": digest},
    )
    assert replay.status_code == 200
    assert replay.json()["route"] == "signup"

    phases = _seed_unknown_signup_effect(db_path, digest=digest)
    history_before = len(phases.history(run_id=RUN_ID))

    # Requirement 14.16: the retry names a step the run has already left.
    stale = client.post(
        f"/api/runs/{RUN_ID}/retry",
        json={"expected_phase": "email_verification"},
    )
    assert stale.status_code == 409
    assert stale.json()["reason_code"] == "phase_replay_noop"

    # Requirement 14.17: an ambiguous outcome authorizes no submission at all.
    unknown = client.post(f"/api/runs/{RUN_ID}/retry", json={"expected_phase": "signup"})
    assert unknown.status_code == 409
    assert unknown.json()["reason_code"] == "outcome_unknown"
    assert phases.submission_count(run_id=RUN_ID, operation_key=OPERATION_KEY) == 1
    assert len(phases.history(run_id=RUN_ID)) == history_before

    # A pause is not an error: 200, carrying the phase and the reason code.
    paused = client.post(f"/api/runs/{RUN_ID}/pause", json={"reason": "stepping away"})
    assert paused.status_code == 200
    assert paused.json()["onboarding"]["phase"] == "paused"
    assert paused.json()["onboarding"]["reason_code"] == "run_paused_by_operator"

    # Requirement 14.12: an unconfirmed reset releases nothing and changes nothing.
    history_before = len(phases.history(run_id=RUN_ID))
    unconfirmed = client.post(f"/api/runs/{RUN_ID}/reset", json={})
    assert unconfirmed.status_code == 422
    assert unconfirmed.json()["fields"] == ["body.confirm"]
    assert len(phases.history(run_id=RUN_ID)) == history_before
    assert phases.history(run_id=RUN_ID)[-1].to_phase == "paused"
    # Read as references, never as values: both halves of the login pair are still
    # stored for this app slug and account binding.
    assert set(
        harness.vault.account_login_references(app_slug=APP_SLUG, account_ref=ACCOUNT_REF)
    ) == {"login_email", "login_password"}

    # No refusal body carried credential material.
    for response in (mismatch, not_awaiting, cancelled, stale, unknown, unconfirmed):
        assert LOGIN_PASSWORD not in response.text
        assert "onboarding@example.invalid" not in response.text
