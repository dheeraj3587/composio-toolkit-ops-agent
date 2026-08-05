"""``runs.status`` as a closed vocabulary, and what a ledger predating it reads as.

Deployed ledgers carry a ``cancelled`` status that no current code path writes: it
was left by a since-removed execution path, and until the CHECK below existed the
column would accept any string at all. Two halves are covered here — the ledger now
refuses an unknown value on write, and the API still reads a run list back when a
row already holds one.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.service import LocalRunService
from ops.core.state import RUN_STATUSES
from ops.core.storage import OperationsStorage

_RUN_ID = "run_" + "a" * 32
_THREAD_ID = "local_" + "b" * 32


def _storage(tmp_path: Path) -> OperationsStorage:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    storage.create_run(run_id=_RUN_ID, thread_id=_THREAD_ID, app_name="Example", app_slug="example")
    return storage


def test_cancelled_is_in_the_status_vocabulary() -> None:
    """The status deployed rows carry, so the ledger and the API can both name it."""

    assert "cancelled" in RUN_STATUSES


def test_the_ledger_refuses_a_status_outside_the_vocabulary(tmp_path: Path) -> None:
    storage = _storage(tmp_path)

    with sqlite3.connect(storage.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute(
                "UPDATE runs SET status = 'not_a_status' WHERE run_id = ?", (_RUN_ID,)
            )


def test_every_vocabulary_member_is_accepted_by_the_check(tmp_path: Path) -> None:
    """Including ``cancelled``: the constraint must not strand an existing row."""

    storage = _storage(tmp_path)

    with sqlite3.connect(storage.db_path) as connection:
        for status in RUN_STATUSES:
            connection.execute("UPDATE runs SET status = ? WHERE run_id = ?", (status, _RUN_ID))


def test_the_check_migration_preserves_a_ledger_written_without_it(tmp_path: Path) -> None:
    """A pre-existing database is rebuilt with its rows, columns and children intact.

    The rebuild drops and recreates ``runs``, which thirteen tables reference with
    ON DELETE CASCADE, so "the audit trail survived" is the assertion that matters.
    """

    storage = _storage(tmp_path)
    storage.append_audit_event(run_id=_RUN_ID, event_type="run_created")
    with sqlite3.connect(storage.db_path) as connection:
        # Re-create the table the way a ledger written before the CHECK holds it.
        connection.execute("PRAGMA foreign_keys = OFF")
        original = str(
            connection.execute("SELECT sql FROM sqlite_master WHERE name = 'runs'").fetchone()[0]
        )
        columns = ", ".join(
            str(row[1]) for row in connection.execute("PRAGMA table_info(runs)").fetchall()
        )
        # The stored statement quotes the name once the table has been renamed.
        unchecked = re.sub(
            r'CREATE TABLE "?runs"?', "CREATE TABLE runs_unchecked", original, count=1
        )
        unchecked, stripped = re.subn(r"\s*CHECK \(status IN \([^)]*\)\)", "", unchecked, count=1)
        assert stripped == 1
        connection.execute(unchecked)
        connection.execute(f"INSERT INTO runs_unchecked SELECT {columns} FROM runs")  # noqa: S608
        connection.execute("DROP TABLE runs")
        connection.execute("PRAGMA legacy_alter_table = ON")
        connection.execute("ALTER TABLE runs_unchecked RENAME TO runs")
        connection.execute("PRAGMA legacy_alter_table = OFF")
        connection.execute("UPDATE runs SET status = 'cancelled' WHERE run_id = ?", (_RUN_ID,))

    OperationsStorage(storage.db_path).initialize()

    record = storage.get_run(_RUN_ID)
    assert record is not None
    assert record["status"] == "cancelled"
    assert len(storage.list_audit_events(_RUN_ID)) == 1
    with sqlite3.connect(storage.db_path) as connection:
        schema = str(
            connection.execute("SELECT sql FROM sqlite_master WHERE name = 'runs'").fetchone()[0]
        )
        assert "CHECK (status IN (" in schema
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'index' AND name = 'idx_runs_idempotency_key'"
            ).fetchone()[0]
            == 1
        )


def test_an_unreadable_status_degrades_to_blocked_instead_of_raising(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One row the vocabulary cannot name must not take the whole list with it."""

    record: dict[str, object] = {
        "run_id": _RUN_ID,
        "thread_id": _THREAD_ID,
        "app_name": "Example",
        "app_slug": "example",
        "status": "a_status_from_a_removed_code_path",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "external_actions": False,
    }

    with caplog.at_level(logging.WARNING, logger="composio_ops.api_service"):
        summary = LocalRunService._summary(record)

    assert summary.status == "blocked"
    assert "a_status_from_a_removed_code_path" in caplog.text
    assert _RUN_ID in caplog.text


def test_the_run_list_answers_over_a_row_carrying_a_legacy_status(tmp_path: Path) -> None:
    """``GET /api/runs`` stays a 200 with such a row in the ledger."""

    db_path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(db_path)
    storage.create_run(run_id=_RUN_ID, thread_id=_THREAD_ID, app_name="Example", app_slug="example")
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE runs SET status = 'cancelled' WHERE run_id = ?", (_RUN_ID,))

    with TestClient(create_app(db_path=db_path)) as client:
        response = client.get("/api/runs")

    assert response.status_code == 200
    statuses = {item["status"] for item in response.json()["items"]}
    assert statuses == {"cancelled"}
