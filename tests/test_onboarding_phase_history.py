"""Property 2: idempotent phase transitions.

A crashed worker resumes by re-driving the boundary it was mid-way through, so a
phase commit that has already happened is re-presented as a matter of course. This
module states what that must cost: nothing. Committing a generated walk of the
legal phase table, and committing that same walk with any prefix re-applied, leave
a run in byte-identical durable shape — same current phase, same history rows at
the same sequence numbers, same projected status — and every re-applied commit
returns ``False`` rather than raising or writing a second row.

**The replay here is a genuine one.** Each boundary carries the correlation id and
attempt of its position in the walk, and the replay re-presents those same values,
so what rejects it is the boundary uniqueness constraint in the database rather
than any bookkeeping in the test. Two runs are driven per example — one plain, one
with the prefix re-applied mid-walk — and compared, so a replay that silently
corrupted the *continuation* of the walk would fail here even though the replay
call itself returned ``False``.

**Structural backing is asserted, not assumed** (see the last two tests). The
mechanism has two halves, and both are pinned: ``UNIQUE (run_id, sequence)`` keeps
history gapless, while the boundary uniqueness is what makes the replay a no-op.
The boundary half is itself two constraints, because SQLite treats NULLs as
distinct inside a UNIQUE constraint — the declared
``UNIQUE (run_id, from_phase, to_phase, attempt, correlation_id)`` cannot reject a
replay of a run's *first* boundary, whose ``from_phase`` is NULL, so the folded
``idx_phase_history_boundary`` index carries that case. A shrunk counterexample
reports ``prefix_length=1``, which is exactly that first boundary, so the
structural tests are what say *which* constraint went missing.

Real SQLite files under ``tmp_path``; no mocks, no network. The store's own
mechanics (sequence numbering, which violations propagate, the generation counter)
are covered by ``tests/test_onboarding_phase_store.py``.

**Validates: Requirements 12.2, 12.3, 12.5, 12.6, 12.7**
"""

from __future__ import annotations

import itertools
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ops.core.storage import OperationsStorage
from ops.onboarding.driver import (
    PHASE_REPLAY_NOOP,
    PhaseTransition,
    SQLitePhaseHistoryStore,
)
from ops.onboarding.phase import (
    IllegalPhaseTransition,
    OnboardingPhase,
    project_status,
)
from tests.support.onboarding_strategies import illegal_phase_pairs, phase_sequences

PROFILE_DIGEST = "a" * 64
REASON_CODE = "profile_corroborated"
DRIVER_LOGGER = "composio_ops.onboarding_driver"


@dataclass(frozen=True, slots=True)
class Boundary:
    """One phase boundary as the driver would present it.

    ``correlation_id`` is the walk position, which is what makes every boundary of
    a walk distinct even when the walk revisits a pair (a ``paused -> research``
    reset lands on ``research -> vault_check`` a second time). Re-presenting the
    same position therefore re-presents the same boundary — the replay the
    property is about — rather than a new one that merely looks similar.
    """

    from_phase: OnboardingPhase | None
    to_phase: OnboardingPhase
    correlation_id: str
    attempt: int = 0


@dataclass(frozen=True, slots=True)
class Ledger:
    """A real ``ops.db`` plus a factory for the run rows a boundary needs.

    Every phase boundary is bound to a ``runs`` row by a foreign key, and each
    generated example needs its own run, since the store's uniqueness constraints
    are all scoped by run id and the file is reused across examples.
    """

    path: Path
    store: SQLitePhaseHistoryStore
    new_run: Callable[[], str]


@pytest.fixture
def ledger(tmp_path) -> Ledger:
    path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(path)
    store = SQLitePhaseHistoryStore(path)
    counter = itertools.count()

    def new_run() -> str:
        run_id = f"run-{next(counter):05d}"
        storage.create_run(
            run_id=run_id,
            thread_id=f"thread-{run_id}",
            app_name="Example App",
            app_slug="example-app",
        )
        return run_id

    return Ledger(path=path, store=store, new_run=new_run)


def _boundaries(walk: Sequence[OnboardingPhase]) -> tuple[Boundary, ...]:
    """The boundaries that commit ``walk``, starting from no phase at all."""

    sources: list[OnboardingPhase | None] = [None, *walk[:-1]]
    return tuple(
        Boundary(from_phase=source, to_phase=target, correlation_id=f"c{index}")
        for index, (source, target) in enumerate(zip(sources, walk, strict=True))
    )


def _commit(store: SQLitePhaseHistoryStore, run_id: str, boundary: Boundary) -> bool:
    return store.commit_phase(
        run_id=run_id,
        from_phase=boundary.from_phase,
        to_phase=boundary.to_phase,
        reason_code=REASON_CODE,
        profile_digest=PROFILE_DIGEST,
        attempt=boundary.attempt,
        correlation_id=boundary.correlation_id,
    )


def _shape(transition: PhaseTransition) -> tuple[object, ...]:
    """Every durable field of a recorded boundary except its commit timestamp."""

    return (
        transition.sequence,
        transition.from_phase,
        transition.to_phase,
        transition.reason_code,
        transition.profile_digest,
        transition.attempt,
        transition.correlation_id,
    )


def _stored_phase(path: Path, run_id: str) -> tuple[str, str] | None:
    """The ``onboarding_run_state`` projection: the phase a resume would read."""

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT phase, profile_digest FROM onboarding_run_state WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    return None if row is None else (str(row[0]), str(row[1]))


@st.composite
def _walks_with_a_replayed_prefix(
    draw: st.DrawFn,
) -> tuple[list[OnboardingPhase], int]:
    """A legal phase walk plus how many of its boundaries get re-applied.

    ``min_transitions=1`` guarantees the walk has a continuation past its first
    boundary, so a replay that corrupted what comes *after* it is observable.
    ``prefix_length`` shrinks toward 1, which re-applies the run's first boundary —
    the NULL ``from_phase`` case that only the folded index rejects.
    """

    walk = draw(phase_sequences(min_transitions=1))
    prefix_length = draw(st.integers(min_value=1, max_value=len(walk)))
    return walk, prefix_length


@given(case=_walks_with_a_replayed_prefix())
def test_replaying_any_prefix_of_a_walk_leaves_the_run_identical(ledger, caplog, case) -> None:
    walk, prefix_length = case
    boundaries = _boundaries(walk)

    plain = ledger.new_run()
    for boundary in boundaries:
        assert _commit(ledger.store, plain, boundary) is True

    replayed = ledger.new_run()
    for boundary in boundaries[:prefix_length]:
        assert _commit(ledger.store, replayed, boundary) is True

    with caplog.at_level("INFO", logger=DRIVER_LOGGER):
        caplog.clear()
        for boundary in boundaries[:prefix_length]:
            # No exception, no row, and no advance: the whole of Requirement 12.5.
            assert _commit(ledger.store, replayed, boundary) is False
        # Requirement 12.6: the replay is reported, once per re-applied boundary.
        assert caplog.text.count(PHASE_REPLAY_NOOP) == prefix_length

    # The walk continues from where it was, unaffected by the replay in its middle.
    for boundary in boundaries[prefix_length:]:
        assert _commit(ledger.store, replayed, boundary) is True

    plain_phase = ledger.store.current_phase(run_id=plain)
    replayed_phase = ledger.store.current_phase(run_id=replayed)
    assert replayed_phase == plain_phase
    assert plain_phase is not None
    assert plain_phase[0] == walk[-1]

    plain_history = ledger.store.history(run_id=plain)
    replayed_history = ledger.store.history(run_id=replayed)
    assert len(replayed_history) == len(plain_history) == len(boundaries)
    # Same rows at the same sequence numbers: the replay left no gap behind either.
    assert [_shape(item) for item in replayed_history] == [_shape(item) for item in plain_history]

    # The stored projection a resuming worker reads, not just the derived view.
    assert _stored_phase(ledger.path, replayed) == _stored_phase(ledger.path, plain)

    # Requirement 12.7: status follows from the phase and the credential flag alone.
    for credential_ready in (False, True):
        assert project_status(
            replayed_phase[0], credential_ready=credential_ready
        ) == project_status(plain_phase[0], credential_ready=credential_ready)


@given(pair=illegal_phase_pairs())
def test_a_transition_outside_the_table_is_refused_and_changes_nothing(ledger, pair) -> None:
    from_phase, to_phase = pair
    run_id = ledger.new_run()
    assert _commit(ledger.store, run_id, Boundary(None, "research", "c0")) is True
    before = ledger.store.history(run_id=run_id)

    with pytest.raises(IllegalPhaseTransition) as raised:
        _commit(ledger.store, run_id, Boundary(from_phase, to_phase, "c1"))

    # Requirement 12.3: both phases are recorded on the refusal, and nothing moved.
    assert raised.value.previous_phase == from_phase
    assert raised.value.next_phase == to_phase
    assert raised.value.reason_code == REASON_CODE
    assert ledger.store.history(run_id=run_id) == before
    assert ledger.store.current_phase(run_id=run_id) == ("research", 0)
    assert _stored_phase(ledger.path, run_id) == ("research", PROFILE_DIGEST)


def test_phase_history_declares_both_uniqueness_constraints(ledger) -> None:
    """The declared schema, read back, is the mechanism the property relies on."""

    with sqlite3.connect(ledger.path) as connection:
        unique_columns = set()
        for row in connection.execute("PRAGMA index_list(onboarding_phase_history)").fetchall():
            name = str(row[1])
            assert name.replace("_", "").isalnum(), name
            if not int(row[2]):
                continue
            unique_columns.add(
                tuple(
                    "<expression>" if info[2] is None else str(info[2])
                    for info in connection.execute(f"PRAGMA index_info('{name}')").fetchall()
                )
            )
        boundary_index = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
            ("idx_phase_history_boundary",),
        ).fetchone()

    # Gapless per-run history, and the boundary key a replay collides with.
    assert ("run_id", "sequence") in unique_columns
    assert ("run_id", "from_phase", "to_phase", "attempt", "correlation_id") in unique_columns
    # The NULL-safe restatement, which is the one that catches a first-boundary
    # replay. Its leading column is an expression, hence the placeholder.
    assert ("run_id", "<expression>", "to_phase", "attempt", "correlation_id") in unique_columns
    assert boundary_index is not None
    declaration = " ".join(str(boundary_index[0]).split())
    assert "CREATE UNIQUE INDEX" in declaration
    assert "COALESCE(from_phase, '')" in declaration


def test_the_database_refuses_a_replayed_boundary_and_a_reused_sequence(ledger) -> None:
    """The refusal comes from SQLite, not from a pre-read in the store.

    Both boundary cases are exercised directly against the table: a NULL
    ``from_phase`` (rejected only by the folded index) and a non-NULL one (rejected
    by the declared constraint). A pre-read would leave a window where two workers
    both saw "absent" and both wrote; these constraints have no such window.
    """

    run_id = ledger.new_run()
    assert _commit(ledger.store, run_id, Boundary(None, "research", "c0")) is True
    assert _commit(ledger.store, run_id, Boundary("research", "vault_check", "c1")) is True

    def insert(sequence: int, from_phase: str | None, to_phase: str, correlation_id: str) -> None:
        with sqlite3.connect(ledger.path) as connection:
            connection.execute(
                """
                INSERT INTO onboarding_phase_history (
                    run_id, sequence, from_phase, to_phase, reason_code,
                    profile_digest, attempt, correlation_id, committed_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, '2024-01-01T00:00:00Z')
                """,
                (
                    run_id,
                    sequence,
                    from_phase,
                    to_phase,
                    REASON_CODE,
                    PROFILE_DIGEST,
                    correlation_id,
                ),
            )

    # A replayed first boundary, offered a fresh sequence number so only the
    # boundary uniqueness can stop it.
    with pytest.raises(sqlite3.IntegrityError) as first_boundary:
        insert(3, None, "research", "c0")
    assert "idx_phase_history_boundary" in str(first_boundary.value)

    with pytest.raises(sqlite3.IntegrityError) as later_boundary:
        insert(4, "research", "vault_check", "c1")
    # A non-NULL boundary is covered twice over: by the declared table constraint
    # and by the folded index. Either refusal is the guarantee under test; SQLite
    # chooses which one it reports.
    assert any(
        name in str(later_boundary.value)
        for name in ("onboarding_phase_history", "idx_phase_history_boundary")
    )

    # A distinct boundary at an already-used sequence: the gapless-history half.
    with pytest.raises(sqlite3.IntegrityError, match="sequence"):
        insert(2, "vault_check", "awaiting_admission", "c2")

    assert [item.sequence for item in ledger.store.history(run_id=run_id)] == [1, 2]
