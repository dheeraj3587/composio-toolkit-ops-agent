"""Durable operations metadata and side-effect idempotency regressions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ops.storage import OperationsStorage


def _create(storage: OperationsStorage) -> None:
    storage.create_run(
        run_id="run_" + "a" * 32,
        thread_id="local_" + "b" * 32,
        app_name="Example",
        app_slug="example",
        operational_research={
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
        },
        route_reason_code="verified_evidence_route",
        route_explanation="Verified evidence selected this route.",
        missing_fields=["token_url"],
        provider_status={"browser": "not_started"},
    )


def test_structured_shapes_survive_key_aware_redaction_words(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)

    record = storage.get_run("run_" + "a" * 32)
    assert record is not None
    assert record["operational_research"] == {
        "authorization_url": None,
        "credential_fields": [],
        "token_url": None,
    }
    assert record["missing_fields"] == ["token_url"]


def test_side_effect_reservation_is_atomic_across_threads(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)
    run_id = "run_" + "a" * 32

    def reserve(_: int) -> bool:
        _, created = storage.reserve_side_effect(
            run_id=run_id,
            operation_key="gmail-outreach-1",
            provider="composio",
        )
        return created

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(24)))

    assert results.count(True) == 1
    assert results.count(False) == 23
    stored = storage.get_side_effect(run_id, "gmail-outreach-1")
    assert stored is not None
    assert stored["status"] == "pending"


def test_ambiguous_side_effect_outcome_is_persisted_without_payload(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)
    run_id = "run_" + "a" * 32
    storage.reserve_side_effect(
        run_id=run_id,
        operation_key="gmail-outreach-1",
        provider="composio",
    )

    updated = storage.update_side_effect(
        run_id=run_id,
        operation_key="gmail-outreach-1",
        status="outcome_unknown",
    )

    assert updated["status"] == "outcome_unknown"
    assert updated["external_id"] is None
    assert "payload" not in updated


def _run_columns(db_path: Path) -> set[str]:
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        return {str(row[1]) for row in connection.execute("PRAGMA table_info(runs)").fetchall()}


def test_revision_columns_default_to_zero(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)

    record = storage.get_run("run_" + "a" * 32)
    assert record is not None
    assert record["state_revision"] == 0
    assert record["last_projected_revision"] == 0


def test_revision_columns_round_trip_and_increment_monotonically(tmp_path: Path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")
    _create(storage)
    run_id = "run_" + "a" * 32

    storage.update_run(run_id, state_revision=1, last_projected_revision=1)
    first = storage.get_run(run_id)
    assert first is not None
    assert first["state_revision"] == 1
    assert first["last_projected_revision"] == 1

    storage.update_run(run_id, state_revision=2)
    second = storage.get_run(run_id)
    assert second is not None
    assert second["state_revision"] == 2
    assert second["last_projected_revision"] == 1


def test_revision_columns_are_added_to_a_pre_existing_database(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "private" / "ops.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # An older schema without the revision (or other later) columns.
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                thread_id TEXT UNIQUE NOT NULL,
                app_name TEXT NOT NULL,
                app_slug TEXT NOT NULL,
                status TEXT NOT NULL,
                access_route TEXT,
                browser_session_id TEXT,
                browser_live_url TEXT,
                gmail_session_id TEXT,
                gmail_thread_id TEXT,
                integrator_bundle_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    storage = OperationsStorage(db_path)
    storage.initialize()

    columns = _run_columns(db_path)
    assert "state_revision" in columns
    assert "last_projected_revision" in columns

    _create(storage)
    migrated = storage.get_run("run_" + "a" * 32)
    assert migrated is not None
    assert migrated["state_revision"] == 0
    assert migrated["last_projected_revision"] == 0
