"""Happy path for reserving an operation key inside the phase commit.

One walk: reach the signup boundary, commit it together with the signup
submission's standing reservation, then replay that exact boundary. The point of
the test is the atomicity claim — both rows land in one unit of work — and the
replay claim: a replayed boundary reserves nothing new and reports no standing,
so a worker arriving at a replay has nothing it is authorized to do.
"""

from __future__ import annotations

import sqlite3

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import SQLitePhaseHistoryStore
from ops.onboarding.effects import plan_for_row_status

DIGEST = "d" * 64
KEY = "run-001:signup-submit:0f1e2d3c4b5a6978:v1"


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "private" / "ops.db"
    OperationsStorage(path).create_run(
        run_id="run-001",
        thread_id="thread-run-001",
        app_name="Example App",
        app_slug="example-app",
    )
    return path


@pytest.fixture
def store(db_path) -> SQLitePhaseHistoryStore:
    return SQLitePhaseHistoryStore(db_path)


def _walk_to_signup_route(store: SQLitePhaseHistoryStore) -> None:
    for index, (from_phase, to_phase, reason) in enumerate(
        (
            (None, "research", "profile_corroborated"),
            ("research", "vault_check", "credentials_present"),
            ("vault_check", "awaiting_admission", "signup_authorization_required"),
            ("awaiting_admission", "route_selected_signup", "operator_approved_signup"),
        )
    ):
        assert store.commit_phase(
            run_id="run-001",
            from_phase=from_phase,
            to_phase=to_phase,
            reason_code=reason,
            profile_digest=DIGEST,
            attempt=0,
            correlation_id=f"corr-{index}",
        )


def _reserve_signup(store: SQLitePhaseHistoryStore):
    plan = plan_for_row_status(operation_key=KEY, action="signup_submit", row_status=None)
    return store.commit_phase_with_reservation(
        run_id="run-001",
        from_phase="route_selected_signup",
        to_phase="signup",
        reason_code="signup_submitted",
        profile_digest=DIGEST,
        attempt=0,
        correlation_id="corr-signup",
        reservations=((plan.action, plan.operation_key, plan),),
    )


def test_phase_and_reservation_land_together_and_a_replay_reserves_nothing_new(
    store, db_path
) -> None:
    _walk_to_signup_route(store)

    reserved = _reserve_signup(store)

    # Both landed in one unit of work: the phase is current and the key is held.
    assert reserved.committed is True
    assert reserved.plan is not None
    assert reserved.plan.disposition == "execute"
    assert store.current_phase(run_id="run-001") == ("signup", 0)
    record = store.effect_reservation(run_id="run-001", operation_key=KEY)
    assert record is not None
    assert (record.effect, record.phase, record.disposition) == (
        "signup_submit",
        "signup",
        "execute",
    )

    history_before = store.history(run_id="run-001")
    replayed = _reserve_signup(store)

    # A replayed boundary writes no history row and reserves nothing new; it
    # reports no standing at all, so the replaying worker has nothing it is
    # authorized to do with the key.
    assert replayed.committed is False
    assert replayed.plan is None
    assert store.history(run_id="run-001") == history_before
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM onboarding_effect_reservations WHERE run_id = ?",
            ("run-001",),
        ).fetchone() == (1,)

    # An ambiguous outcome leaves the standing disposition pause-only: it
    # authorizes nothing further for the key.
    ambiguous = store.mark_effect_reservation_outcome_unknown(run_id="run-001", operation_key=KEY)
    assert ambiguous.disposition == "pause_outcome_unknown"
    assert ambiguous.phase == "signup"
