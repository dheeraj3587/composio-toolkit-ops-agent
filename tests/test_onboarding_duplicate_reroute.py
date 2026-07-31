"""Happy path for the autonomous duplicate-account re-route (Requirements 6.7, 6.8).

One walk: the run stands at ``signup``, the provider answers "that account already
exists", and the driver commits ``signup -> route_selected_login`` with
``signup_rejected_duplicate_account``, adopts the stored signup references as the
run's login references, and asks no human anything.

The phase store, the lease store, and the queue are the real SQLite ones in
``tmp_path``; the two phase handlers and the reference binder are fakes injected
through the driver's ports.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.action_loop import PhaseGoal
from ops.onboarding.driver import (
    OnboardingDeps,
    PhaseStep,
    SQLitePhaseHistoryStore,
    drive_run,
)
from ops.onboarding.lease import Lease, deadline_after
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore

RUN_ID = "run-duplicate-001"
OWNER = "owner-onboarding"

# The walk that puts the run durably at ``signup``: signup reserves a
# provider-visible effect, so the driver refuses to enter it without a committed
# boundary into it.
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "awaiting_admission", "credentials_missing"),
    ("awaiting_admission", "route_selected_signup", "operator_approved_signup"),
    ("route_selected_signup", "signup", "operator_approved_signup"),
)

_REFERENCES = (
    ("login_email", "vault://example-provider/account_login_email/1"),
    ("login_password", "vault://example-provider/account_login_password/1"),
)


def _profile() -> ProviderProfile:
    evidence = FieldEvidence(
        field="signup_url",
        value="https://example.com/signup",
        source_url="https://example.com/docs",
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
        developer_portal_url="https://example.com/apps",
        signup_url="https://example.com/signup",
        login_url="https://example.com/login",
        developer_docs_url="https://example.com/docs",
        developer_app_flow=FlowSpec(
            kind="developer_app", supported=True, entry_url="https://example.com/apps"
        ),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key", supported=True, entry_url="https://example.com/settings/api"
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


class _Binder:
    """The stored signup references, adopted as login references on demand."""

    def __init__(self, trace: list[str]) -> None:
        self.calls: list[tuple[str, str]] = []
        self._trace = trace

    def adopt_signup_references_for_login(
        self, *, run_id: str, profile_digest: str
    ) -> tuple[tuple[str, str], ...]:
        self.calls.append((run_id, profile_digest))
        self._trace.append("adopt")
        return _REFERENCES


class _Goals:
    def goal_for(self, *, phase: OnboardingPhase, profile: ProviderProfile) -> PhaseGoal:
        raise AssertionError("both phases are handler-driven in this walk")


class _Sessions:
    async def session_for(self, *, run_id: str, phase: OnboardingPhase, lease: Lease) -> object:
        raise AssertionError("both phases are handler-driven in this walk")


class _Decider:
    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        raise AssertionError("no model call happens on this walk")


class _Telemetry:
    def denial(self, reason_code: str) -> None:
        return None

    def reject(self, reason_code: str) -> None:
        return None

    def dlp_refusal(self) -> None:
        return None

    def action(self, *, candidate_id: str, actions_executed: int) -> None:
        return None

    def model_call(self, *, model_calls: int) -> None:
        return None

    def progress(self, *, step_index: int, stage: str, elapsed_ms: int) -> None:
        return None


@pytest.fixture
def wired(tmp_path):
    db_path = tmp_path / "private" / "ops.db"
    OperationsStorage(db_path).create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug="example-provider",
    )
    profile = _profile()
    profiles = SQLiteProviderProfileStore(
        tmp_path / "private" / "provider_profiles.db", owner=OWNER
    )
    profiles.put(profile)

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

    trace: list[str] = []
    binder = _Binder(trace)

    async def duplicate_account(
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        trace.append("signup")
        return PhaseStep.advance("route_selected_login", "signup_rejected_duplicate_account")

    async def login(
        *,
        run_id: str,
        phase: OnboardingPhase,
        profile: ProviderProfile | None,
        lease: Lease,
        deps: OnboardingDeps,
    ) -> PhaseStep:
        trace.append("login")
        return PhaseStep.defer(deadline_after(300), "step_retried")

    deps = OnboardingDeps(
        leases=SQLiteLeaseStore(db_path),
        phases=phases,
        profiles=profiles,
        queue=SQLiteRunQueue(db_path),
        goals=_Goals(),
        sessions=_Sessions(),
        decider=_Decider(),
        telemetry=_Telemetry(),
        logins=binder,
        handlers={"signup": duplicate_account, "route_selected_login": login},
    )
    return deps, binder, trace, profile


def test_duplicate_account_reroutes_to_login_under_the_stored_references(wired) -> None:
    deps, binder, trace, profile = wired

    outcome = asyncio.run(drive_run(run_id=RUN_ID, worker_id="worker-a", deps=deps))

    assert outcome is not None
    # Requirement 6.7: one committed boundary, carrying the duplicate reason code.
    committed = deps.phases.history(run_id=RUN_ID)[-1]
    assert (committed.from_phase, committed.to_phase) == ("signup", "route_selected_login")
    assert committed.reason_code == "signup_rejected_duplicate_account"

    # Requirement 6.8: the stored signup references were adopted as the login
    # references before the login route was driven, and nobody was prompted.
    assert binder.calls == [(RUN_ID, profile.profile_digest)]
    assert trace == ["signup", "adopt", "login"]
    assert (outcome.captcha_prompts, outcome.admission_prompts) == (0, 0)
    assert outcome.other_operator_prompts == 0
