"""Happy path for ``recover_run``: read durable state, reattach, commit nothing.

One walk through what task 19.1 exists for. A run is seeded through the phase
history as far as ``developer_app`` and its worker disappears; another worker
recovers it. The plan names the last committed phase, carries the profile digest
that phase recorded, and reports the run's still-bound browser session under the
same id it always had — while the phase history is byte-for-byte what it was
before recovery ran.

The store is the real SQLite one in ``tmp_path``, so "recovery committed nothing"
is a property of the rows rather than of a fake. The bound session and the effect
view are fakes injected through the two narrow ports.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from browser_service.session_manager import SESSION_CONTINUITY_EVENTS
from ops.browser.host_policy import BrowserAllowedHosts
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    RECOVERY_TRIGGERS,
    SESSION_REATTACHED,
    OnboardingDeps,
    RecoveryTrigger,
    SQLitePhaseHistoryStore,
    recover_run,
)
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore

RUN_ID = "run-recovery-001"
OWNER = "owner-onboarding"
BOUND_SESSION = "sess-bound-001"

# The walk that leaves ``developer_app`` as the last durably committed phase, so
# recovery resumes exactly there (Requirement 12.10, Property 5).
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "route_selected_login", "credentials_present"),
    ("route_selected_login", "authenticated", "credentials_present"),
    ("authenticated", "developer_app", "credentials_present"),
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


class _Sessions:
    """A bound session that survived the restart, plus a create verb nobody calls."""

    def __init__(self) -> None:
        self.retained: list[RecoveryTrigger] = []
        self.created = 0

    async def reattach_bound_session(
        self, *, run_id: str, app_slug: str, event: RecoveryTrigger
    ) -> str | None:
        self.retained.append(event)
        return BOUND_SESSION

    async def create_session(
        self, *, run_id: str, app_slug: str, allowed: BrowserAllowedHosts
    ) -> str | None:
        self.created += 1
        return "sess-fresh-001"


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
            correlation_id=f"seed-{to_phase}",
        )

    sessions = _Sessions()
    deps = OnboardingDeps(
        leases=SQLiteLeaseStore(db_path),
        phases=phases,
        profiles=profiles,
        queue=SQLiteRunQueue(db_path),
        goals=None,  # type: ignore[arg-type]  # recovery drives nothing
        sessions=None,  # type: ignore[arg-type]
        decider=None,  # type: ignore[arg-type]
        telemetry=None,  # type: ignore[arg-type]
    )
    return deps, sessions, profile


def test_recover_run_resumes_the_last_phase_on_the_reattached_session(wired) -> None:
    deps, sessions, profile = wired
    before = deps.phases.history(run_id=RUN_ID)

    plan = asyncio.run(
        recover_run(
            run_id=RUN_ID,
            worker_id="worker-b",
            deps=deps,
            sessions=sessions,
            trigger="api_restart",
        )
    )

    # The last durably committed phase, under the digest that phase recorded: no
    # research ran and the digest is unchanged (Requirements 16.9, 16.10).
    assert plan.is_resumable is True
    assert (plan.disposition, plan.phase, plan.attempt) == ("continue", "developer_app", 0)
    assert plan.profile_digest == profile.profile_digest

    # Reattached before anything was created, keeping the session id, so the phase
    # continues rather than restarting (Requirements 15.2, 15.4, 15.5).
    assert plan.reason_code == SESSION_REATTACHED
    assert plan.session_id == BOUND_SESSION
    assert plan.reenter_phase_from_start is False
    assert sessions.created == 0
    # The reattach is recorded under a continuity event the browser service holds
    # non-terminating, so a restart cannot cost the run its session.
    assert sessions.retained == ["api_restart"]
    assert set(RECOVERY_TRIGGERS) <= SESSION_CONTINUITY_EVENTS

    # Read-only over durable state: the phase history is what it was, and the run
    # is still claimable because recovery neither claimed nor released a lease
    # (Requirement 16.11).
    assert deps.phases.history(run_id=RUN_ID) == before
    assert deps.leases.claim(run_id=RUN_ID, worker_id="worker-c", ttl_seconds=60) is not None
