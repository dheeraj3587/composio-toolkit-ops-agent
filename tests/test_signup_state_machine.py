from __future__ import annotations

import pytest

from ops.signup_state_machine import (
    SQLiteSignupStateStore,
    SignupState,
    SignupStateConflict,
    SignupStateMachine,
)


def test_signup_state_survives_restart_and_advances_monotonically(tmp_path) -> None:
    db_path = tmp_path / "signup-state.db"
    first_machine = SignupStateMachine(SQLiteSignupStateStore(db_path))
    decision = first_machine.plan(
        "run_signup",
        account_policy="create_if_missing",
        account_exists=False,
    )

    assert decision.state is SignupState.SIGNUP_PAGE_LOADING
    assert decision.account_creation_authorized is True

    restarted = SignupStateMachine(SQLiteSignupStateStore(db_path))
    snapshot = restarted.snapshot("run_signup")
    assert snapshot.state is SignupState.SIGNUP_PAGE_LOADING

    detected = restarted.advance(
        "run_signup",
        SignupState.SIGNUP_FORM_DETECTED,
        expected_revision=snapshot.revision,
    )
    assert detected.revision == snapshot.revision + 1


def test_reuse_existing_policy_skips_signup(tmp_path) -> None:
    machine = SignupStateMachine(SQLiteSignupStateStore(tmp_path / "signup-state.db"))

    decision = machine.plan(
        "run_existing",
        account_policy="reuse_existing",
        account_exists=False,
    )

    assert decision.state is SignupState.ACCOUNT_EXISTS_DETECTED
    assert decision.next_phase == "login_account_detection"
    assert decision.account_creation_authorized is False


def test_detected_existing_account_skips_creation(tmp_path) -> None:
    machine = SignupStateMachine(SQLiteSignupStateStore(tmp_path / "signup-state.db"))

    decision = machine.plan(
        "run_existing",
        account_policy="create_if_missing",
        account_exists=True,
    )

    assert decision.state is SignupState.ACCOUNT_EXISTS_DETECTED
    assert decision.account_creation_authorized is False
    assert decision.reason_code == "existing_account_detected"


def test_illegal_or_stale_transition_is_rejected(tmp_path) -> None:
    machine = SignupStateMachine(SQLiteSignupStateStore(tmp_path / "signup-state.db"))
    snapshot = machine.snapshot("run_signup")

    with pytest.raises(SignupStateConflict):
        machine.advance("run_signup", SignupState.ACCOUNT_CREATED)

    machine.advance(
        "run_signup",
        SignupState.SIGNUP_PAGE_LOADING,
        expected_revision=snapshot.revision,
    )
    with pytest.raises(SignupStateConflict):
        machine.advance(
            "run_signup",
            SignupState.SIGNUP_FORM_DETECTED,
            expected_revision=snapshot.revision,
        )
