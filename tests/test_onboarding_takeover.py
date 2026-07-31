"""Property tests for the autonomous CAPTCHA takeover state machine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import get_args
from uuid import uuid4

from hypothesis import given, settings
from hypothesis import strategies as st

from ops.browser.takeover import (
    ClearanceObservation,
    ClearanceProbeReason,
    decide_takeover,
)
from ops.browser.worker import HumanActionType
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.onboarding.phase import ONBOARDING_REASON_CODES, REASON_CODE_PATTERN
from ops.runs.resume import OnboardingRunControlService

_DIGEST = "a" * 64
_HUMAN_ACTION_TYPES = tuple(get_args(HumanActionType))
_PROBE_REASONS = tuple(get_args(ClearanceProbeReason))


@dataclass(frozen=True)
class _PausedRun:
    run_id: str
    storage: OperationsStorage
    phases: SQLitePhaseHistoryStore
    control: OnboardingRunControlService


def _observation(
    *,
    gate: HumanActionType | None,
    attached: bool = True,
    final_probe_owed: bool = False,
) -> ClearanceObservation:
    return ClearanceObservation(
        session_present=True,
        lifecycle="ACTIVE",
        hitl_pending=True,
        attached=attached,
        final_probe_owed=final_probe_owed,
        gate=gate,
        probe_reason_code="observed",
        hitl_generation=1,
    )


def _paused_run(
    tmp_path: Path,
    *,
    attempt: int = 0,
    prompts: int = 1,
) -> _PausedRun:
    case_id = uuid4().hex
    run_id = f"run-takeover-{case_id}"
    db_path = tmp_path / "ops.db"
    storage = OperationsStorage(db_path)
    storage.create_run(
        run_id=run_id,
        thread_id=f"thread-{case_id}",
        app_name="Example Provider",
        app_slug="example-provider",
    )
    phases = SQLitePhaseHistoryStore(db_path)
    # The property needs the durable state at the takeover seam, not the earlier
    # admission walk. The real store validates this legal boundary and projects
    # the standing phase in one transaction, keeping 100 generated examples fast.
    assert phases.commit_phase(
        run_id=run_id,
        from_phase="developer_app",
        to_phase="captcha_paused",
        reason_code="captcha_detected",
        profile_digest=_DIGEST,
        attempt=attempt,
        correlation_id=f"pause-{case_id}",
    )
    for _ in range(prompts):
        phases.record_captcha_pause(run_id=run_id, phase_at_pause="developer_app")
    control = OnboardingRunControlService(storage=storage, phases=phases, effects=phases)
    return _PausedRun(run_id=run_id, storage=storage, phases=phases, control=control)


# Feature: autonomous-onboarding-reliability, Property 1: Clearance decides continuation
@given(
    paused_gate=st.sampled_from(_HUMAN_ACTION_TYPES),
    observed_gate=st.sampled_from((None, *_HUMAN_ACTION_TYPES)),
)
@settings(max_examples=100)
def test_clearance_decides_continuation(
    paused_gate: HumanActionType,
    observed_gate: HumanActionType | None,
) -> None:
    """**Validates: Requirements 1.3, 1.4**"""

    decision = decide_takeover(
        paused_gate=paused_gate,
        observation=_observation(gate=observed_gate),
    )

    assert (decision.action == "continue") is (observed_gate != paused_gate)


# Feature: autonomous-onboarding-reliability, Property 2: A present gate changes nothing
@given(
    gate=st.sampled_from(_HUMAN_ACTION_TYPES),
    attempt=st.integers(min_value=0, max_value=10),
    prompts=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=100)
def test_a_present_gate_changes_nothing(
    tmp_path: Path,
    gate: HumanActionType,
    attempt: int,
    prompts: int,
) -> None:
    """**Validates: Requirements 1.2, 1.7, 1.8**"""

    paused = _paused_run(tmp_path, attempt=attempt, prompts=prompts)
    history_before = paused.phases.history(run_id=paused.run_id)
    pause_before = paused.phases.captcha_pause(run_id=paused.run_id)

    decision = decide_takeover(
        paused_gate=gate,
        observation=_observation(gate=gate),
    )
    assert decision.action == "keep_waiting"
    assert decision.poll_again is True

    # This is the sweep's write policy: waiting decisions call neither committer.
    if decision.action == "continue":
        paused.control.resume_from_pause(paused.run_id)
    elif decision.action == "pause":
        paused.control.request_pause(paused.run_id, reason_code=decision.reason_code)

    assert paused.phases.history(run_id=paused.run_id) == history_before
    assert paused.phases.current_phase(run_id=paused.run_id) == ("captcha_paused", attempt)
    assert paused.phases.captcha_pause(run_id=paused.run_id) == pause_before
    assert pause_before.prompts == prompts


# Feature: autonomous-onboarding-reliability, Property 3: Continuation is idempotent under any interleaving
@given(
    signals=st.lists(
        st.sampled_from(("takeover", "owner")),
        min_size=1,
        max_size=12,
    ),
    attempt=st.integers(min_value=0, max_value=10),
)
@settings(max_examples=100)
def test_continuation_is_idempotent_under_any_interleaving(
    tmp_path: Path,
    signals: list[str],
    attempt: int,
) -> None:
    """**Validates: Requirements 1.5, 1.10**"""

    paused = _paused_run(tmp_path, attempt=attempt)
    for signal in signals:
        if signal == "takeover":
            decision = decide_takeover(
                paused_gate="captcha",
                observation=_observation(gate=None),
            )
            assert decision.action == "continue"
        paused.control.resume_from_pause(paused.run_id)

    departures = tuple(
        boundary
        for boundary in paused.phases.history(run_id=paused.run_id)
        if boundary.from_phase == "captcha_paused"
    )
    assert len(departures) == 1
    continuation = departures[0]
    assert continuation.to_phase == "developer_app"
    assert continuation.reason_code == "captcha_resolved"
    assert continuation.attempt == attempt + 1
    assert paused.phases.current_phase(run_id=paused.run_id) == ("developer_app", attempt + 1)
    assert paused.phases.captcha_pause(run_id=paused.run_id).prompts == 1


# Feature: autonomous-onboarding-reliability, Property 4: Exactly one final observation after the last detach
@given(
    paused_gate=st.sampled_from(_HUMAN_ACTION_TYPES),
    observed_gates=st.lists(
        st.sampled_from((None, *_HUMAN_ACTION_TYPES)),
        min_size=1,
        max_size=12,
    ),
)
@settings(max_examples=100)
def test_exactly_one_final_observation_after_the_last_detach(
    paused_gate: HumanActionType,
    observed_gates: list[HumanActionType | None],
) -> None:
    """**Validates: Requirements 1.12, 1.2**"""

    polling = True
    observations_answered = 0
    final_probe_owed = True
    for observed_gate in observed_gates:
        if not polling:
            continue
        decision = decide_takeover(
            paused_gate=paused_gate,
            observation=_observation(
                gate=observed_gate,
                attached=False,
                final_probe_owed=final_probe_owed,
            ),
        )
        observations_answered += 1
        final_probe_owed = False
        polling = decision.poll_again

    assert observations_answered == 1
    assert polling is False


@st.composite
def _observations(draw: st.DrawFn) -> ClearanceObservation:
    return ClearanceObservation(
        session_present=draw(st.booleans()),
        lifecycle=draw(st.sampled_from(("ACTIVE", "CLOSING", "CLOSED", ""))),
        hitl_pending=draw(st.booleans()),
        attached=draw(st.booleans()),
        final_probe_owed=draw(st.booleans()),
        gate=draw(st.sampled_from((None, *_HUMAN_ACTION_TYPES))),
        probe_reason_code=draw(st.sampled_from(_PROBE_REASONS)),
        hitl_generation=draw(st.integers(min_value=0, max_value=1_000_000)),
    )


# Feature: autonomous-onboarding-reliability, Property 5: Every non-continuing outcome names a closed reason code
@given(
    paused_gate=st.sampled_from(_HUMAN_ACTION_TYPES),
    observation=_observations(),
)
@settings(max_examples=100)
def test_every_outcome_names_a_closed_reason_code(
    paused_gate: HumanActionType,
    observation: ClearanceObservation,
) -> None:
    """**Validates: Requirements 1.11, 2.5, 2.6, 3.2, 9.6**"""

    decision = decide_takeover(paused_gate=paused_gate, observation=observation)

    assert decision.reason_code in ONBOARDING_REASON_CODES
    assert REASON_CODE_PATTERN.fullmatch(decision.reason_code)
