"""Happy path for ``drive_run``: claim, drive one phase, commit, release.

One walk through what the driver exists for. The run is seeded at phase
``developer_app`` with a stored profile; the action loop drives that phase to
``done`` against a fake two-step page; the driver maps that outcome onto the one
transition Requirement 9.11 declares, commits it, and releases the lease.

The stores are the real SQLite ones in ``tmp_path`` — the commit and the lease
are properties of their SQL — while the page, the inference backend, and the
next phase's handler are fakes injected through the LL-2 ports.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

import pytest

from ops.browser.candidates import ActionCandidate
from ops.browser.worker import BrowserObservation
from ops.core.storage import OperationsStorage
from ops.onboarding import driver
from ops.onboarding.action_loop import LoopObservation, PhaseGoal
from ops.onboarding.driver import (
    OnboardingDeps,
    PhaseStep,
    PhaseTransition,
    RunPlanner,
    RunPlanningPorts,
    RunPlanValidator,
    SQLitePhaseHistoryStore,
    drive_run,
    plan_admission,
    resumption_phase,
)
from ops.onboarding.lease import Lease, deadline_after
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.phase import RESUMABLE_PHASES, OnboardingPhase, OnboardingReasonCode
from ops.planner.plan import RunPlan
from ops.planner.store import RunPlanStore
from ops.planner.validator import PlanRefusal, validate_plan
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.recipes.app_recipes import AppRecipe, get_app_recipe

RUN_ID = "run-driver-001"
OWNER = "owner-onboarding"

# The walk that puts the run at ``developer_app`` durably, so the driver resumes
# there rather than at ``research`` (Requirement 12.10).
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "route_selected_login", "credentials_present"),
    ("route_selected_login", "authenticated", "credentials_present"),
    ("authenticated", "developer_app", "credentials_present"),
)

_RAW_ELEMENTS: tuple[Mapping[str, object], ...] = (
    {"role": "button", "name": "Create app", "visible": True, "enabled": True},
)


def _profile() -> ProviderProfile:
    """A profile whose single registrable domain admits the fake console."""

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


class _Session:
    """A two-step page: the create-app control, then a created app."""

    def __init__(self) -> None:
        self.acted: list[ActionCandidate] = []

    async def observe(self) -> LoopObservation:
        if self.acted:
            return LoopObservation(
                observation=BrowserObservation(
                    status="developer_console_ready",
                    current_url="https://console.example.com/apps/created",
                    page_title="App created",
                    developer_app_id="app_1",
                ),
            )
        return LoopObservation(
            observation=BrowserObservation(
                status="developer_console_ready",
                current_url="https://console.example.com/apps",
                page_title="Apps",
            ),
            raw_elements=_RAW_ELEMENTS,
        )

    async def act(self, candidate: ActionCandidate) -> None:
        self.acted.append(candidate)


class _Sessions:
    """Hands the driver the one session this run is driven through."""

    def __init__(self, session: _Session) -> None:
        self.session = session
        self.opened: list[OnboardingPhase] = []

    async def session_for(self, *, run_id: str, phase: OnboardingPhase, lease: Lease) -> _Session:
        self.opened.append(phase)
        return self.session


class _Goals:
    """The developer-app goal, built from the run's committed profile."""

    def goal_for(self, *, phase: OnboardingPhase, profile: ProviderProfile) -> PhaseGoal:
        return PhaseGoal.for_phase(
            phase,
            provider_name=profile.provider_name,
            description="Create a developer app so an API key can be generated.",
            instruction="Create a new developer application.",
            success_reason_code="developer_app_created",
            signals=("Create app",),
        )


class _Decider:
    """Picks the first id the schema offers, as a constrained backend would."""

    async def choose(self, prompt: str, *, schema: Mapping[str, object]) -> Mapping[str, object]:
        properties = schema["properties"]
        assert isinstance(properties, Mapping)
        candidate_id = properties["candidate_id"]
        assert isinstance(candidate_id, Mapping)
        ids = candidate_id["enum"]
        assert isinstance(ids, Sequence)
        return {"decision": "select_candidate", "candidate_id": ids[0], "reason": "next step"}


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


class _CountingLeaseStore(SQLiteLeaseStore):
    """The real store, plus a count of how many releases reached it."""

    releases = 0

    def release(self, *, lease: Lease) -> bool:
        self.releases += 1
        return super().release(lease=lease)


class _EmptyPlanStore:
    """An admission store that proves a refusal writes no plan row."""

    def __init__(self) -> None:
        self.records = 0

    def record_initial_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        self.records += 1
        return plan

    def record_plan(
        self, *, run_id: str, plan: RunPlan, reason_code: OnboardingReasonCode
    ) -> RunPlan:
        self.records += 1
        return plan

    def read_active_plan(self, *, run_id: str) -> RunPlan | None:
        return None

    def count_plans(self, *, run_id: str) -> int:
        return 0


class _RefusingPlanner:
    def __init__(self) -> None:
        self.calls = 0

    def plan_for(
        self,
        *,
        revision: int,
        recipe: AppRecipe | None = None,
        profile: ProviderProfile | None = None,
        evidence: str = "",
        run_id: str | None = None,
    ) -> PlanRefusal:
        self.calls += 1
        return PlanRefusal(
            reason_code="plan_surface_not_in_catalog",
            detail="recipe_route_not_browser",
            ordinal=0,
        )


@dataclass
class _PlanningPorts:
    plans: RunPlanStore | None
    planner: RunPlanner | None
    plan_validator: RunPlanValidator = validate_plan


async def _defer_credential_generation(
    *,
    run_id: str,
    phase: OnboardingPhase,
    profile: ProviderProfile | None,
    lease: Lease,
    deps: OnboardingDeps,
) -> PhaseStep:
    """Stands in for the credential phase (task 17): asks to come back later."""

    return PhaseStep.defer(deadline_after(300), "step_retried")


def test_plan_admission_propagates_a_planner_refusal_without_recording() -> None:
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None
    plans = _EmptyPlanStore()
    planner = _RefusingPlanner()
    ports: RunPlanningPorts = _PlanningPorts(plans=plans, planner=planner)

    refusal = plan_admission(
        run_id="run-plan-refused",
        profile=None,
        recipe=recipe,
        deps=ports,
    )

    assert refusal is not None
    assert refusal.reason_code == "plan_surface_not_in_catalog"
    assert planner.calls == 1
    assert plans.records == 0


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

    session = _Session()
    sessions = _Sessions(session)
    leases = _CountingLeaseStore(db_path)
    deps = OnboardingDeps(
        leases=leases,
        phases=phases,
        profiles=profiles,
        queue=SQLiteRunQueue(db_path),
        goals=_Goals(),
        sessions=sessions,
        decider=_Decider(),
        telemetry=_Telemetry(),
        handlers={"credential_generation": _defer_credential_generation},
    )
    return deps, sessions, leases, profile


def test_drive_run_drives_one_phase_commits_it_and_releases(wired) -> None:
    deps, sessions, leases, profile = wired

    outcome = asyncio.run(drive_run(run_id=RUN_ID, worker_id="worker-a", deps=deps))

    assert outcome is not None
    # The loop drove developer_app, and the driver mapped `done` onto the one
    # transition Requirement 9.11 declares.
    assert sessions.opened == ["developer_app"]
    committed = deps.phases.history(run_id=RUN_ID)[-1]
    assert (committed.from_phase, committed.to_phase) == ("developer_app", "credential_generation")
    assert committed.reason_code == "developer_app_created"
    assert committed.profile_digest == profile.profile_digest
    assert deps.phases.current_phase(run_id=RUN_ID) == ("credential_generation", 0)

    # The next phase deferred, so nothing further was committed and the run is
    # queued for later rather than ready now.
    assert len(deps.phases.history(run_id=RUN_ID)) == len(_SEED_WALK) + 1
    assert deps.queue.dequeue_candidates(limit=5) == ()

    # One loop's counters reached the outcome, and no human was involved.
    assert (outcome.actions_executed, outcome.model_calls, outcome.navigation_denials) == (1, 1, 0)
    assert outcome.terminal_phase == "credential_generation"
    assert outcome.verdict == "operator_assisted"
    assert outcome.captcha_prompts == 0
    assert outcome.is_fully_autonomous() is True

    # Released exactly once, so another worker can claim the run right away.
    assert leases.releases == 1
    assert leases.claim(run_id=RUN_ID, worker_id="worker-b", ttl_seconds=60) is not None


def _boundary(
    sequence: int,
    from_phase: OnboardingPhase | None,
    to_phase: OnboardingPhase,
    attempt: int = 0,
) -> PhaseTransition:
    return PhaseTransition(
        sequence=sequence,
        from_phase=from_phase,
        to_phase=to_phase,
        reason_code="credentials_present",
        profile_digest="a" * 64,
        attempt=attempt,
        correlation_id="seed",
        committed_at="2025-01-01T00:00:00Z",
    )


def test_resumption_phase_recomputes_from_the_prior_durable_phase(monkeypatch) -> None:
    """Requirement 12.13, plus the three cases that resume as committed."""

    history = (
        _boundary(1, None, "research"),
        _boundary(2, "research", "vault_check"),
        _boundary(3, "vault_check", "route_selected_login"),
        _boundary(4, "route_selected_login", "authenticated", attempt=2),
    )

    assert resumption_phase(()) == ("research", 0)
    # The ordinary case: the last committed phase is where the walk re-enters.
    assert resumption_phase(history) == ("authenticated", 2)
    # A terminal phase is reported as-is so the driver stops rather than redoing
    # a finished run, even though it too sits outside the resumable set.
    assert resumption_phase((*history[:1], _boundary(2, "research", "blocked"))) == ("blocked", 0)

    # Every non-terminal phase is resumable today, so the recompute path is
    # exercised by narrowing the resumable set to what it guards against: a phase
    # that is a transient computation rather than a place to stand.
    monkeypatch.setattr(driver, "RESUMABLE_PHASES", RESUMABLE_PHASES - frozenset({"authenticated"}))
    assert resumption_phase(history) == ("route_selected_login", 0)
