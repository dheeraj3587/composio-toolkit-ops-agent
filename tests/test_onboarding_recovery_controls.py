"""Happy path for the two recovery controls: retry the current step, then reset.

One walk through what task 20.2 exists for. A run standing at ``signup`` with the
signup submission already completed in the effect ledger is retried — the step is
re-attempted, the completed effect is named and skipped, and the credential
generation counter is reused rather than advanced. The same run is then reset: the
session is released under the ``run_reset`` reason, the workflow state is cleared,
the phase returns to ``research``, and both vault references for the run's app slug
and account binding still resolve afterwards.

The guarantees this walk shows, in the order they appear:

* retry re-attempts only the current step and skips a completed effect
  (Requirement 14.13);
* retry reuses the generation counter, so it derives the already-reserved
  operation key (Requirement 14.15);
* reset releases the session and clears the workflow state (Requirement 14.7) and
  commits ``research`` (Requirement 14.8);
* reset preserves every vault reference, and the surviving pair is what routes the
  restarted run to login (Requirements 14.9, 14.10, 14.11).

A real ``SQLiteSecretStore`` under ``tmp_path`` holds the credentials, because the
claim is that a *stored* pair survives a reset — a double would only restate the
test's own assumption. The effect ledger, the workflow state, and the session
release are fakes injected through the module's ports: no reader enumerates a run's
reservations yet, and neither a browser nor a checkpoint database is needed to show
what reset does.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from ops.core.secret_store import SQLiteSecretStore
from ops.core.storage import OperationsStorage
from ops.onboarding.driver import EffectReservationRecord, SQLitePhaseHistoryStore
from ops.onboarding.phase import OnboardingPhase
from ops.runs.reconciliation import (
    RESET_REASON_CODE,
    RESET_RELEASE_REASON,
    RETRY_REASON_CODE,
    OnboardingRunRecoveryService,
)

RUN_ID = "run_" + "2" * 32
APP_SLUG = "acme-provider"
ACCOUNT_REF = "acct_" + "3" * 32
PROFILE_DIGEST = "c" * 64
OPERATION_KEY = f"{RUN_ID}:signup-submit:0123456789abcdef:v1"

# The walk the run has committed when the operator arrives: signup was submitted
# and the step then failed, which is the step a retry re-attempts.
WALK: tuple[tuple[OnboardingPhase | None, OnboardingPhase], ...] = (
    (None, "research"),
    ("research", "vault_check"),
    ("vault_check", "awaiting_admission"),
    ("awaiting_admission", "route_selected_signup"),
    ("route_selected_signup", "signup"),
)


class _CompletedSignupLedger:
    """One completed signup reservation, and a refusal to settle anything.

    The two settlement methods exist to be *not* called: a retry reads the ledger
    and skips what already happened, so a settlement here would mean the retry had
    started treating a completed effect as in flight.
    """

    def __init__(self, record: EffectReservationRecord) -> None:
        self._record = record

    def reservations(self, *, run_id: str) -> tuple[EffectReservationRecord, ...]:
        return (self._record,) if run_id == self._record.run_id else ()

    def complete_effect_reservation(
        self, *, run_id: str, operation_key: str, receipt: Mapping[str, str]
    ) -> EffectReservationRecord:
        raise AssertionError("a retry must not settle a reservation")

    def mark_effect_reservation_outcome_unknown(
        self, *, run_id: str, operation_key: str
    ) -> EffectReservationRecord:
        raise AssertionError("a retry must not settle a reservation")


class _RecordingRelease:
    """Records the reason every session release was requested under."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, *, run_id: str, reason: str) -> bool:
        self.calls.append(reason)
        return True


class _RecordingWorkflowState:
    """Records the workflow state a reset cleared."""

    def __init__(self) -> None:
        self.cleared: list[tuple[str, str]] = []

    def clear_workflow_state(self, *, run_id: str, thread_id: str) -> bool:
        self.cleared.append((run_id, thread_id))
        return True


@pytest.fixture
def recovery(tmp_path: Path):
    path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(path)
    storage.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name="Acme Provider",
        app_slug=APP_SLUG,
        browser_account_ref=ACCOUNT_REF,
    )
    # The coarse status a run driving a browser holds, so the phase projection has
    # a legal status edge rather than being kept for lack of one.
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
    # One supersede already advanced the credential counter. The retry must report
    # this value and leave it exactly here.
    assert phases.next_generation(run_id=RUN_ID, effect="generate_credential") == 1

    vault = SQLiteSecretStore(tmp_path / "secret_vault.db", Fernet.generate_key())
    vault.put_account_login_pair(
        app_slug=APP_SLUG,
        account_ref=ACCOUNT_REF,
        email="onboarding@example.invalid",
        password="generated-signup-password",  # pragma: allowlist secret
    )
    release = _RecordingRelease()
    workflow = _RecordingWorkflowState()
    service = OnboardingRunRecoveryService(
        storage=storage,
        phases=phases,
        effects=_CompletedSignupLedger(
            EffectReservationRecord(
                run_id=RUN_ID,
                operation_key=OPERATION_KEY,
                effect="signup_submit",
                generation=0,
                phase="signup",
                # The ledger's answer for a completed row: never submit it again.
                disposition="skip",
                receipt={"signup_confirmation": "provider-ack-1"},
                reason_code="signup_submitted",
            )
        ),
        workflow=workflow,
        credentials=vault,
        release_session=release,
    )
    return service, storage, phases, vault, release, workflow


def test_retry_reuses_the_reserved_key_and_reset_preserves_the_vault(recovery) -> None:
    service, storage, phases, vault, release, workflow = recovery

    # Requirements 14.13, 14.15: only the current step is re-attempted, the
    # completed submission is skipped, and the generation counter is reused.
    retried = service.retry_current_step(RUN_ID, expected_phase="signup")
    assert retried.accepted is True
    assert retried.committed is True
    assert retried.phase == "signup"
    assert retried.attempt == 1
    assert retried.reason_code == RETRY_REASON_CODE
    assert retried.skipped_effects == ("signup_submit",)
    assert retried.generation == 1
    assert phases.current_generation(run_id=RUN_ID, effect="generate_credential") == 1
    assert phases.current_phase(run_id=RUN_ID) == ("signup", 1)
    assert release.calls == []

    # Requirements 14.7, 14.8, 14.11: the session goes back under the reset reason,
    # the workflow state is cleared, and the run restarts at research.
    reset = service.reset_run(RUN_ID, confirm=True)
    assert reset.accepted is True
    assert reset.committed is True
    assert reset.phase == "research"
    assert reset.reason_code == RESET_REASON_CODE
    assert reset.browser_session_released is True
    assert reset.workflow_state_cleared is True
    assert release.calls == [RESET_RELEASE_REASON]
    assert workflow.cleared == [(RUN_ID, f"thread-{RUN_ID}")]
    assert phases.current_phase(run_id=RUN_ID)[0] == "research"
    record = storage.get_run(RUN_ID)
    assert record is not None
    assert record["phase"] == "research"

    # Requirements 14.9, 14.10, Property 13: both references survived, and they are
    # what makes the restarted run take the login route with no operator prompt.
    assert reset.vault_references_preserved == 2
    assert reset.expected_route_on_restart == "login"
    preserved = vault.account_login_references(app_slug=APP_SLUG, account_ref=ACCOUNT_REF)
    assert sorted(preserved) == ["login_email", "login_password"]
    assert vault.get_account_login_pair(app_slug=APP_SLUG, account_ref=ACCOUNT_REF) == {
        "login_email": "onboarding@example.invalid",
        "login_password": "generated-signup-password",  # pragma: allowlist secret
    }
