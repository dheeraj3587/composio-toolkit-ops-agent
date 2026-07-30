"""Happy path for the operator run controls: resume, pause, cancel, in that order.

One walk through what task 20.1 exists for. A run parked at ``captcha_paused``
re-enters the phase recorded at pause, is then paused by the operator with a
signup submission still reserved in the effect ledger, and is finally cancelled.

The three guarantees this walk is here to show, in the order they appear:

* resume names the phase at pause and commits re-entry into it (Requirement 14.4);
* pause settles the reserved submission before the run stops and leaves the
  browser session alone (Requirements 14.1, 14.2, 14.3);
* cancel releases the session and commits ``cancelled`` before it returns
  (Requirements 14.5, 14.6).

Real SQLite files under ``tmp_path`` for the phase history and the run ledger. The
effect ledger and the session release are fakes injected through the module's own
ports, because no reader enumerates a run's reservations yet and because a
cancellation must not need a browser to be tested.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from pathlib import Path

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import EffectReservationRecord, SQLitePhaseHistoryStore
from ops.onboarding.phase import OnboardingPhase
from ops.runs.resume import (
    CANCEL_REASON_CODE,
    CAPTCHA_RESUME_REASON_CODE,
    PAUSE_REASON_CODE,
    OnboardingRunControlService,
)

RUN_ID = "run-controls-001"
PROFILE_DIGEST = "b" * 64
OPERATION_KEY = f"{RUN_ID}:signup-submit:0123456789abcdef:v1"

# The walk the run has already committed when the operator arrives: signup was
# interrupted by a challenge, which is the one mid-flight prompt that exists.
WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase], ...] = (
    (None, "research"),
    ("research", "vault_check"),
    ("vault_check", "awaiting_admission"),
    ("awaiting_admission", "route_selected_signup"),
    ("route_selected_signup", "signup"),
    ("signup", "captcha_paused"),
)


class _FakeEffectLedger:
    """The run's reservations, settled in memory the way the store settles them."""

    def __init__(self, *reservations: EffectReservationRecord) -> None:
        self._records = {record.operation_key: record for record in reservations}

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        return tuple(record for record in self._records.values() if record.run_id == run_id)

    def complete_effect_reservation(
        self, *, run_id: str, operation_key: str, receipt: Mapping[str, str]
    ) -> EffectReservationRecord:
        record = dataclasses.replace(
            self._records[operation_key],
            disposition="skip",
            receipt=dict(receipt),
            reason_code="signup_submitted",
        )
        self._records[operation_key] = record
        return record

    def mark_effect_reservation_outcome_unknown(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord:
        record = dataclasses.replace(
            self._records[operation_key],
            disposition="pause_outcome_unknown",
            reason_code="outcome_unknown",
        )
        self._records[operation_key] = record
        return record


class _RecordingRelease:
    """Records every session release so pause can be shown not to call it."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, *, run_id: str, reason: str) -> bool:
        self.calls.append(reason)
        return True


@pytest.fixture
def controls(
    tmp_path: Path,
) -> tuple[
    OnboardingRunControlService, OperationsStorage, _RecordingRelease, SQLitePhaseHistoryStore
]:
    path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(path)
    storage.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Example Provider",
        app_slug="example-provider",
    )
    # The coarse status a run driving a browser holds, so the phase projection has
    # a legal status edge to take rather than being kept for lack of one.
    storage.update_run(RUN_ID, status="browser_running")
    phases = SQLitePhaseHistoryStore(path)
    for index, (source, target) in enumerate(WALK):
        assert phases.commit_phase(
            run_id=RUN_ID,
            from_phase=source,
            to_phase=target,
            reason_code="profile_corroborated",
            profile_digest=PROFILE_DIGEST,
            attempt=0,
            correlation_id=f"walk-{index}",
        )
    release = _RecordingRelease()
    service = OnboardingRunControlService(
        storage=storage,
        phases=phases,
        effects=_FakeEffectLedger(
            EffectReservationRecord(
                run_id=RUN_ID,
                operation_key=OPERATION_KEY,
                effect="signup_submit",
                generation=0,
                phase="signup",
                # Reserved and handed out: the submission this pause has to settle.
                disposition="execute",
                receipt=None,
                reason_code="signup_submitted",
            )
        ),
        release_session=release,
    )
    return service, storage, release, phases


def test_resume_then_pause_then_cancel_walks_one_run_through_the_controls(controls) -> None:
    service, storage, release, phases = controls

    # Requirement 14.4: the phase at pause is named, and re-entry is committed.
    resumed = service.resume_from_pause(RUN_ID)
    assert resumed.accepted is True
    assert resumed.phase_at_pause == "signup"
    assert resumed.resumed_phase == "signup"
    assert resumed.reason_code == CAPTCHA_RESUME_REASON_CODE
    assert phases.current_phase(run_id=RUN_ID) == ("signup", 1)

    # Requirements 14.1, 14.2, 14.3: the run stops after the phase it is in, the
    # reserved submission is reconciled first, and the session is left alone.
    paused = service.request_pause(RUN_ID)
    assert paused.accepted is True
    assert paused.committed is True
    assert paused.pausing_after_phase == "signup"
    assert paused.reason_code == PAUSE_REASON_CODE
    assert paused.browser_session_released is False
    assert [(item.effect, item.disposition) for item in paused.settlements] == [
        ("signup_submit", "pause_outcome_unknown")
    ]
    assert release.calls == []
    assert service.pause_requested(RUN_ID) is True
    assert phases.current_phase(run_id=RUN_ID) == ("paused", 1)
    record = storage.get_run(RUN_ID)
    assert record is not None
    assert record["status"] == "waiting_for_hitl"
    assert record["phase"] == "paused"

    # Requirements 14.5, 14.6: the session is released and the cancellation is
    # durable before the caller is answered.
    cancelled = service.cancel_run(RUN_ID)
    assert cancelled.accepted is True
    assert cancelled.committed is True
    assert cancelled.browser_session_released is True
    assert cancelled.reason_code == CANCEL_REASON_CODE
    assert release.calls == [f"cancel_{CANCEL_REASON_CODE}"]
    assert phases.current_phase(run_id=RUN_ID) == ("cancelled", 1)
    assert service.pause_requested(RUN_ID) is False
    final = storage.get_run(RUN_ID)
    assert final is not None
    assert final["status"] == "blocked"
    assert final["phase"] == "cancelled"
