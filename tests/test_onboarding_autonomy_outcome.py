"""The autonomy outcome, written once when a run reaches a terminal phase.

One walk: a run seeded at ``credential_validation`` is driven to ``completed``,
and the driver writes the durable record the autonomy metrics are computed from
(Requirements 20.4, 20.5, 20.7). The store is the real SQLite run ledger in
``tmp_path``, because write-once is a property of the table's primary key rather
than of the driver's bookkeeping — so the second drive of the same terminal run
has to leave the first record standing.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    LedgerAutonomyOutcomes,
    OnboardingDeps,
    PhaseStep,
    SQLitePhaseHistoryStore,
    drive_run,
)
from ops.onboarding.lease import Lease
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)

RUN_ID = "run-autonomy-001"

# The walk that leaves the run standing at ``credential_validation``, one legal
# transition away from ``completed``.
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "route_selected_login", "credentials_present"),
    ("route_selected_login", "authenticated", "credentials_present"),
    ("authenticated", "developer_app", "credentials_present"),
    ("developer_app", "credential_generation", "developer_app_created"),
    ("credential_generation", "vault_storage", "credential_generated"),
    ("vault_storage", "credential_validation", "credential_stored"),
)


def _profile() -> ProviderProfile:
    evidence = FieldEvidence(
        field="developer_portal_url",
        value="https://console.example.com/apps",
        source_url="https://console.example.com/docs",
        source_digest="a" * 64,
        adapters=("fake-discovery",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2025-01-01T00:00:00Z",
    )
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name="Example Provider",
        app_slug="example-provider",
        registrable_domain="example.com",
        auxiliary_hosts=(),
        developer_portal_url="https://console.example.com/apps",
        signup_url="https://example.com/signup",
        login_url="https://console.example.com/login",
        developer_docs_url="https://console.example.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app",
            supported=True,
            entry_url="https://console.example.com/apps",
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://console.example.com/settings/api",
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(evidence,),
        confidence=0.9,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:00Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


class _Profiles:
    """The run's one committed profile, looked up by digest or by run."""

    def __init__(self, profile: ProviderProfile) -> None:
        self.profile = profile

    def get(self, *, profile_digest: str) -> ProviderProfile | None:
        return self.profile if profile_digest == self.profile.profile_digest else None

    def get_for_run(self, *, run_id: str) -> ProviderProfile | None:
        return self.profile if run_id == RUN_ID else None


class _Unused:
    """The ports this walk never reaches: the one phase driven has a handler."""

    def goal_for(self, *, phase: OnboardingPhase, profile: ProviderProfile) -> object:
        raise AssertionError("this walk drives no browser phase")

    async def session_for(
        self, *, run_id: str, phase: OnboardingPhase, lease: Lease
    ) -> object:  # pragma: no cover - never called
        raise AssertionError("this walk opens no session")

    async def choose(self, prompt: str, *, schema: object) -> object:  # pragma: no cover
        raise AssertionError("this walk makes no model call")

    def denial(self, reason_code: str) -> None:  # pragma: no cover
        return None

    def reject(self, reason_code: str) -> None:  # pragma: no cover
        return None

    def dlp_refusal(self) -> None:  # pragma: no cover
        return None

    def action(self, *, candidate_id: str, actions_executed: int) -> None:  # pragma: no cover
        return None

    def model_call(self, *, model_calls: int) -> None:  # pragma: no cover
        return None


async def _validate_credential(
    *,
    run_id: str,
    phase: OnboardingPhase,
    profile: ProviderProfile | None,
    lease: Lease,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Stands in for the validation phase: the credential is valid, so finish."""

    return PhaseStep.advance("completed", "credential_valid")


@pytest.fixture
def wired(tmp_path):
    db_path = tmp_path / "private" / "ops.db"
    ledger = OperationsStorage(db_path)
    ledger.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug="example-provider",
    )
    profile = _profile()
    phases = SQLitePhaseHistoryStore(db_path)
    for from_phase, to_phase, reason_code in _SEED_WALK:
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason_code,
            profile_digest=profile.profile_digest,
            attempt=0,
            correlation_id="seed",
        )
    stub = _Unused()
    deps = OnboardingDeps(
        leases=SQLiteLeaseStore(db_path),
        phases=phases,
        profiles=_Profiles(profile),
        queue=SQLiteRunQueue(db_path),
        goals=stub,
        sessions=stub,
        decider=stub,
        telemetry=stub,
        handlers={"credential_validation": _validate_credential},
        outcomes=LedgerAutonomyOutcomes(ledger),
    )
    return deps, ledger, profile


def test_terminal_run_records_one_autonomy_outcome(wired) -> None:
    deps, ledger, profile = wired

    outcome = asyncio.run(drive_run(run_id=RUN_ID, worker_id="worker-a", deps=deps))

    assert outcome is not None
    assert outcome.terminal_phase == "completed"
    assert outcome.verdict == "fully_autonomous"

    # Requirement 20.5: the durable record carries all 19 fields, and it is the
    # outcome the driver computed rather than a summary of it.
    record = ledger.read_autonomy_outcome(RUN_ID)
    assert record == outcome.as_record()
    assert len(record) == 19
    assert record["profile_digest"] == profile.profile_digest
    assert record["reason_code"] == "credential_valid"
    # Requirement 20.7 / 11.15: fully autonomous means no prompt but admission.
    assert (record["captcha_prompts"], record["other_operator_prompts"]) == (0, 0)
    assert record["duration_seconds"] >= 0

    # Requirement 20.4: driving the already-terminal run again writes no second
    # record and does not overwrite the first.
    again = asyncio.run(drive_run(run_id=RUN_ID, worker_id="worker-b", deps=deps))
    assert again is not None
    assert again.reason_code == "lease_claimed"
    assert ledger.read_autonomy_outcome(RUN_ID) == record
