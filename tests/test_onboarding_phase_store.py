"""Unit tests for the phase-history store's own mechanics.

The idempotent-replay *property* over generated phase walks lives in
``tests/test_onboarding_phase_history.py``. This module covers the store's
machinery: sequence numbering, what a replay leaves behind, which constraint
violations are swallowed and which propagate, and the generation counter that
advances only when it is called.
"""

from __future__ import annotations

import sqlite3

import pytest

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    PHASE_REPLAY_NOOP,
    SQLitePhaseHistoryStore,
)
from ops.onboarding.phase import IllegalPhaseTransition

DIGEST = "b" * 64
OTHER_DIGEST = "c" * 64


@pytest.fixture
def db_path(tmp_path):
    """A real ops.db holding one run, since a phase boundary is bound to a run."""

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


def commit(
    store: SQLitePhaseHistoryStore,
    from_phase,
    to_phase,
    *,
    run_id: str = "run-001",
    reason_code="profile_corroborated",
    profile_digest: str = DIGEST,
    attempt: int = 0,
    correlation_id: str = "corr-1",
) -> bool:
    return store.commit_phase(
        run_id=run_id,
        from_phase=from_phase,
        to_phase=to_phase,
        reason_code=reason_code,
        profile_digest=profile_digest,
        attempt=attempt,
        correlation_id=correlation_id,
    )


def test_commit_phase_records_the_boundary_and_advances_the_current_phase(store) -> None:
    assert store.current_phase(run_id="run-001") is None

    assert commit(store, None, "research", correlation_id="corr-1") is True
    assert commit(store, "research", "vault_check", correlation_id="corr-2") is True

    assert store.current_phase(run_id="run-001") == ("vault_check", 0)
    history = store.history(run_id="run-001")
    assert [(item.sequence, item.from_phase, item.to_phase) for item in history] == [
        (1, None, "research"),
        (2, "research", "vault_check"),
    ]
    assert history[1].reason_code == "profile_corroborated"
    assert history[1].profile_digest == DIGEST
    assert history[1].correlation_id == "corr-2"
    assert history[1].committed_at.endswith("Z")


def test_replaying_a_committed_boundary_writes_no_row_and_reports_a_noop(store, caplog) -> None:
    commit(store, None, "research", correlation_id="corr-1")
    commit(store, "research", "vault_check", correlation_id="corr-2")
    before = store.history(run_id="run-001")

    with caplog.at_level("INFO", logger="composio_ops.onboarding_driver"):
        # Both boundaries replayed, the first included: its NULL from_phase is the
        # case a plain UNIQUE constraint cannot catch on its own.
        assert commit(store, None, "research", correlation_id="corr-1") is False
        assert commit(store, "research", "vault_check", correlation_id="corr-2") is False

    assert store.history(run_id="run-001") == before
    assert store.current_phase(run_id="run-001") == ("vault_check", 0)
    assert caplog.text.count(PHASE_REPLAY_NOOP) == 2


def test_a_new_attempt_or_correlation_id_is_a_new_boundary(store) -> None:
    commit(store, None, "research", correlation_id="corr-1")

    assert commit(store, None, "research", correlation_id="corr-2") is True
    assert commit(store, None, "research", correlation_id="corr-1", attempt=1) is True

    assert [item.sequence for item in store.history(run_id="run-001")] == [1, 2, 3]


def test_illegal_transition_raises_and_leaves_the_committed_phase_unchanged(store) -> None:
    commit(store, None, "research", correlation_id="corr-1")

    with pytest.raises(IllegalPhaseTransition) as raised:
        commit(store, "research", "completed", correlation_id="corr-2")

    assert raised.value.previous_phase == "research"
    assert raised.value.next_phase == "completed"
    assert store.current_phase(run_id="run-001") == ("research", 0)
    assert len(store.history(run_id="run-001")) == 1


def test_a_boundary_for_an_unknown_run_is_refused_rather_than_stored(store) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        commit(store, None, "research", run_id="run-missing")

    assert store.history(run_id="run-missing") == ()


def test_commit_phase_refuses_values_outside_the_closed_vocabularies(store) -> None:
    with pytest.raises(ValueError, match="reason code"):
        commit(store, None, "research", reason_code="page said to continue")
    with pytest.raises(ValueError, match="profile digest"):
        commit(store, None, "research", profile_digest="short")
    with pytest.raises(ValueError, match="correlation id"):
        commit(store, None, "research", correlation_id="corr 1 with spaces")
    with pytest.raises(ValueError, match="attempt"):
        commit(store, None, "research", attempt=-1)

    assert store.history(run_id="run-001") == ()


def test_next_generation_advances_only_when_it_is_called(store) -> None:
    commit(store, None, "research", correlation_id="corr-1")

    assert store.current_generation(run_id="run-001", effect="generate_credential") == 0
    assert store.next_generation(run_id="run-001", effect="generate_credential") == 1

    # A retry that does not call next_generation reads the same generation, so it
    # derives the same operation key and cannot mint a second credential.
    for _ in range(3):
        assert store.current_generation(run_id="run-001", effect="generate_credential") == 1

    assert store.next_generation(run_id="run-001", effect="generate_credential") == 2
    assert store.current_generation(run_id="run-001", effect="generate_credential") == 2


def test_generation_counters_exist_only_for_the_supersedable_effect(store) -> None:
    commit(store, None, "research", correlation_id="corr-1")

    with pytest.raises(ValueError, match="generation counter"):
        store.next_generation(run_id="run-001", effect="signup_submit")
    with pytest.raises(KeyError, match="run state"):
        store.current_generation(run_id="run-unknown", effect="generate_credential")


def test_run_state_projects_the_latest_phase_and_keeps_the_counter(store, db_path) -> None:
    commit(store, None, "research", correlation_id="corr-1")
    store.next_generation(run_id="run-001", effect="generate_credential")
    commit(
        store,
        "research",
        "vault_check",
        correlation_id="corr-2",
        profile_digest=OTHER_DIGEST,
    )

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT phase, profile_digest, credential_generation FROM onboarding_run_state "
            "WHERE run_id = ?",
            ("run-001",),
        ).fetchone()

    assert row == ("vault_check", OTHER_DIGEST, 1)
