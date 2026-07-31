"""Happy path for the CAPTCHA pause and resume seam (design LL-3.6).

One walk through the only mid-flight interruption an onboarding run may have. A
run standing at ``developer_app`` meets a CAPTCHA: the pause records where it
paused and counts the prompt, the driver commits the boundary the pause asked
for, a ``completed`` resume re-enters the recorded phase, a second CAPTCHA is a
new boundary rather than a swallowed replay, and a ``cancelled`` resume ends the
run and releases the session.

The second walk takes the same pause out through the committer the owner's resume
signal now reaches. ``POST /api/runs/{id}/resume`` no longer drives the LangGraph
resume for an onboarding run standing at a waiting phase: it reaches
``OnboardingRunControlService.resume_from_pause`` through the run-service
boundary, and that path has to commit the boundary this file already pins —
``captcha_paused -> phase_at_pause`` at ``captcha_resolved`` and ``attempt + 1``
— or the owner signal and the autonomous takeover would be two mechanisms rather
than one (Requirements 1.9, 1.10).

The phase-history store is the real SQLite one in ``tmp_path`` — the commit, the
replay refusal, and the durable prompt count are properties of its SQL — while
the session is a fake whose only interesting property is whether anything
released it.
"""

from __future__ import annotations

import asyncio

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    MIDFLIGHT_OPERATOR_PROMPTS,
    PHASE_REPLAY_NOOP,
    CaptchaPause,
    OnboardingDeps,
    PhaseStep,
    SQLitePhaseHistoryStore,
    midflight_gate_disposition,
    pause_for_captcha,
    phase_correlation_id,
    resume_from_captcha,
)
from ops.onboarding.lease_store import SQLiteLeaseStore, SQLiteRunQueue
from ops.onboarding.phase import OnboardingPhase, OnboardingReasonCode
from ops.providers.profile import ProviderProfile
from ops.runs.resume import (
    CAPTCHA_RESOLVED_EVENT,
    CAPTCHA_RESUME_REASON_CODE,
    OnboardingRunControlService,
)

RUN_ID = "run-captcha-001"
APP_SLUG = "example-provider"
SESSION_ID = "browser-session-captcha-001"
DIGEST = "a" * 64

# The walk that puts the run durably at ``developer_app``, which is where the
# challenge appears below.
_SEED_WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase, OnboardingReasonCode], ...] = (
    (None, "research", "profile_corroborated"),
    ("research", "vault_check", "profile_corroborated"),
    ("vault_check", "route_selected_login", "credentials_present"),
    ("route_selected_login", "authenticated", "credentials_present"),
    ("authenticated", "developer_app", "credentials_present"),
)


class _Session:
    """The bound session the pause holds open, plus a count of its releases."""

    def __init__(self) -> None:
        self.session_id = SESSION_ID
        self.releases = 0

    async def release(self) -> None:
        self.releases += 1


class _Profiles:
    """The profile port, which this path never reads: a resume commits from the
    digest the paused boundary already carries."""

    def get(self, *, profile_digest: str) -> ProviderProfile | None:
        return None

    def get_for_run(self, *, run_id: str) -> ProviderProfile | None:
        return None


class _Unused:
    """The loop-facing ports, which no pause or resume reaches."""


def _commit(phases: SQLitePhaseHistoryStore, *, phase: OnboardingPhase, attempt: int) -> None:
    """Commit the ``captcha_paused`` boundary the pause step asked for.

    This is the driver's job, not the pause path's, so the test does what the
    driver would: it commits under the correlation id derived from the phase the
    run paused in and that phase's attempt.
    """

    assert phases.commit_phase(
        run_id=RUN_ID,
        from_phase=phase,
        to_phase="captcha_paused",
        reason_code="captcha_detected",
        profile_digest=DIGEST,
        attempt=attempt,
        correlation_id=phase_correlation_id(run_id=RUN_ID, phase=phase, attempt=attempt),
    )


def _continuations(storage: OperationsStorage) -> int:
    """How many CAPTCHA continuations the run's durable audit trail carries."""

    return sum(
        1
        for event in storage.list_audit_events(RUN_ID)
        if str(event.get("event_type") or "") == CAPTCHA_RESOLVED_EVENT
    )


@pytest.fixture
def wired(tmp_path):
    db_path = tmp_path / "private" / "ops.db"
    OperationsStorage(db_path).create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug=APP_SLUG,
    )
    phases = SQLitePhaseHistoryStore(db_path)
    for from_phase, to_phase, reason_code in _SEED_WALK:
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason_code,
            profile_digest=DIGEST,
            attempt=0,
            correlation_id=f"seed-{to_phase}",
        )
    deps = OnboardingDeps(
        leases=SQLiteLeaseStore(db_path),
        phases=phases,
        profiles=_Profiles(),
        queue=SQLiteRunQueue(db_path),
        goals=_Unused(),
        sessions=_Unused(),
        decider=_Unused(),
        telemetry=_Unused(),
    )
    return deps, _Session()


def test_captcha_pause_records_the_phase_and_resume_re_enters_it(wired) -> None:
    deps, session = wired
    phases = deps.phases

    # --- the pause ----------------------------------------------------------
    paused = asyncio.run(
        pause_for_captcha(
            run_id=RUN_ID, phase_at_pause="developer_app", session=session, pauses=phases
        )
    )
    # Requirements 11.2 and 11.3: the step asks for ``captcha_paused``, the phase
    # at pause is durable, and the prompt is counted exactly once.
    assert paused == PhaseStep.advance("captcha_paused", "captcha_detected")
    assert phases.captcha_pause(run_id=RUN_ID) == CaptchaPause(
        phase_at_pause="developer_app", prompts=1
    )
    # Requirement 11.4: the pause held the session rather than ending it.
    assert (session.session_id, session.releases) == (SESSION_ID, 0)
    _commit(phases, phase="developer_app", attempt=0)

    # --- resume: completed --------------------------------------------------
    resumed = asyncio.run(
        resume_from_captcha(
            run_id=RUN_ID, signal="completed", session=session, deps=deps, pauses=phases
        )
    )
    # Requirement 11.8: re-entry into the recorded phase, on the same session,
    # under an advanced attempt so the next pause is its own boundary.
    assert resumed == PhaseStep.advance("developer_app", "captcha_resolved")
    assert phases.current_phase(run_id=RUN_ID) == ("developer_app", 1)
    assert (session.session_id, session.releases) == (SESSION_ID, 0)

    # --- a second challenge, then cancellation ------------------------------
    assert asyncio.run(
        pause_for_captcha(
            run_id=RUN_ID, phase_at_pause="developer_app", session=session, pauses=phases
        )
    ) == PhaseStep.advance("captcha_paused", "captcha_detected")
    # Requirement 11.9: the second pause is committed rather than swallowed as a
    # replay, and it counted its own prompt.
    assert phases.captcha_pause(run_id=RUN_ID).prompts == 2
    _commit(phases, phase="developer_app", attempt=1)

    cancelled = asyncio.run(
        resume_from_captcha(
            run_id=RUN_ID, signal="cancelled", session=session, deps=deps, pauses=phases
        )
    )
    # Requirement 11.12: cancelling commits ``cancelled`` and frees the session.
    assert cancelled == PhaseStep.advance("cancelled", "operator_cancelled")
    assert phases.current_phase(run_id=RUN_ID) == ("cancelled", 1)
    assert session.releases == 1

    # Requirements 11.1 and 11.14: one prompting gate type exists, and every other
    # mid-flight gate is dispositioned by the gate-resolution seam with no prompt.
    assert MIDFLIGHT_OPERATOR_PROMPTS == frozenset({"captcha"})
    assert midflight_gate_disposition("legal_acceptance", app_slug=APP_SLUG) == "human_only"
    assert midflight_gate_disposition("login_required", app_slug=APP_SLUG) == "reusable_login"


def test_the_owner_resume_signal_commits_the_same_boundary_and_replays_into_nothing(
    wired, tmp_path
) -> None:
    deps, session = wired
    phases = deps.phases
    storage = OperationsStorage(tmp_path / "private" / "ops.db")

    # The same pause the walk above records, so the two ways out of it are
    # compared from identical durable state.
    assert asyncio.run(
        pause_for_captcha(
            run_id=RUN_ID, phase_at_pause="developer_app", session=session, pauses=phases
        )
    ) == PhaseStep.advance("captcha_paused", "captcha_detected")
    _commit(phases, phase="developer_app", attempt=0)

    # The committer the resume route reaches, wired the way the run-service
    # boundary wires it: the phase history is both ports, and no session port is
    # supplied because a continuation must not hand the session back.
    controls = OnboardingRunControlService(storage=storage, phases=phases, effects=phases)
    resumed = controls.resume_from_pause(RUN_ID)

    # Requirement 1.9: re-entry into the recorded phase at the advanced attempt,
    # with the reason code the driver's own resume writes — the same boundary, not
    # a second one that happens to look similar.
    assert (resumed.accepted, resumed.committed) == (True, True)
    assert resumed.phase_at_pause == "developer_app"
    assert resumed.resumed_phase == "developer_app"
    assert resumed.reason_code == CAPTCHA_RESUME_REASON_CODE
    assert phases.current_phase(run_id=RUN_ID) == ("developer_app", 1)
    # Selected by the waiting phase: a CAPTCHA pause continues as itself, which is
    # what the timeline reads it back as.
    assert _continuations(storage) == 1
    # Nothing released the session, so the continuation costs no re-authentication.
    assert (session.session_id, session.releases) == (SESSION_ID, 0)

    committed = phases.history(run_id=RUN_ID)
    replayed = controls.resume_from_pause(RUN_ID)

    # Requirement 1.10: the run has left its waiting phase, so a second owner
    # signal is a replay — no boundary, no audit row, nothing committed twice.
    assert (replayed.accepted, replayed.committed) == (False, False)
    assert replayed.reason_code == PHASE_REPLAY_NOOP
    assert replayed.resumed_phase is None
    assert phases.history(run_id=RUN_ID) == committed
    assert _continuations(storage) == 1
