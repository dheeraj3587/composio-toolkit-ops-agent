from __future__ import annotations

import sqlite3
import stat

import pytest

from ops.storage import OperationsStorage


def mode(path: object) -> int:
    return stat.S_IMODE(path.stat().st_mode)  # type: ignore[union-attr]


def create_run(storage: OperationsStorage, *, run_id: str = "run-001") -> dict:
    return storage.create_run(
        run_id=run_id,
        thread_id=f"thread-{run_id}",
        app_name="Example App",
        app_slug="example-app",
    )


def test_storage_initializes_owner_only_database_and_round_trips_runs(tmp_path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    storage = OperationsStorage(db_path)

    created = create_run(storage)

    assert created["status"] == "created"
    assert storage.get_run("run-001") == created
    assert storage.list_runs() == [created]
    assert mode(db_path.parent) == 0o700
    assert mode(db_path) == 0o600


def test_storage_lists_runs_with_bounded_pagination(tmp_path) -> None:
    storage = OperationsStorage(tmp_path / "ops.db")
    create_run(storage, run_id="run-001")
    create_run(storage, run_id="run-002")

    first_page = storage.list_runs(limit=1, offset=0)
    second_page = storage.list_runs(limit=1, offset=1)

    assert storage.count_runs() == 2
    assert len(first_page) == 1
    assert len(second_page) == 1
    assert {first_page[0]["run_id"], second_page[0]["run_id"]} == {
        "run-001",
        "run-002",
    }
    with pytest.raises(ValueError, match="zero or greater"):
        storage.list_runs(offset=-1)


def test_run_and_audit_writes_are_sanitized_before_sqlite(tmp_path) -> None:
    db_path = tmp_path / "ops.db"
    storage = OperationsStorage(db_path)
    raw_password = "plaintext-password-fixture"  # pragma: allowlist secret
    raw_token = "temporary-browser-token-value"
    raw_api_key = "sk-test-abcdefghijklmnopqrstuvwxyz"  # pragma: allowlist secret
    credential_ref = "vault://example-app/client_secret/ref_123"  # pragma: allowlist secret
    create_run(storage)

    with pytest.raises(ValueError, match="capability URLs"):
        storage.update_run(
            "run-001",
            browser_live_url=(f"https://browser.example.test/live?token={raw_token}&view=operator"),
        )

    storage.update_run(
        "run-001",
        integrator_bundle={
            "credential_refs": {"client_secret": credential_ref},
            "operational_notes": [f"api_key={raw_api_key}"],
        },
    )
    event_id = storage.append_audit_event(
        run_id="run-001",
        event_type="credential_stored",
        payload={
            "password": raw_password,
            "message": f"API key was api_key={raw_api_key}",
            "credential_ref": credential_ref,
        },
    )

    raw_db = db_path.read_bytes()
    assert raw_password.encode() not in raw_db
    assert raw_token.encode() not in raw_db
    assert raw_api_key.encode() not in raw_db

    updated = storage.get_run("run-001")
    assert updated is not None
    assert updated["browser_live_url"] is None
    assert updated["integrator_bundle"]["credential_refs"]["client_secret"] == credential_ref
    assert "sk-test-" not in updated["integrator_bundle"]["operational_notes"][0]

    events = storage.list_audit_events("run-001")
    assert events[0]["id"] == event_id
    assert events[0]["payload"]["password"] == "[REDACTED]"
    assert raw_api_key not in events[0]["payload"]["message"]
    assert events[0]["payload"]["credential_ref"].startswith("vault://")


def test_audit_event_requires_an_existing_run(tmp_path) -> None:
    storage = OperationsStorage(tmp_path / "ops.db")

    with pytest.raises(Exception, match="FOREIGN KEY constraint failed"):
        storage.append_audit_event(
            run_id="missing",
            event_type="should_not_persist",
            payload={},
        )


def test_update_rejects_undeclared_columns(tmp_path) -> None:
    storage = OperationsStorage(tmp_path / "ops.db")
    create_run(storage)

    with pytest.raises(ValueError, match="unsupported"):
        storage.update_run("run-001", password="must-not-be-stored")  # pragma: allowlist secret


def test_audit_storage_never_stringifies_unknown_secret_objects(tmp_path) -> None:
    marker = "unknown object credential material"
    key_marker = "unknown map key credential material"

    class OpaquePayload:
        def __str__(self) -> str:
            return marker

    class OpaqueKey:
        def __str__(self) -> str:
            return key_marker

    db_path = tmp_path / "ops.db"
    storage = OperationsStorage(db_path)
    create_run(storage)
    storage.append_audit_event(
        run_id="run-001",
        event_type="redaction_regression",
        payload={
            "token": marker,
            "nested": {
                "secret": marker,
                "object": OpaquePayload(),
                OpaqueKey(): "associated value",
            },
        },
    )

    assert marker.encode() not in db_path.read_bytes()
    assert key_marker.encode() not in db_path.read_bytes()
    event = storage.list_audit_events("run-001")[0]
    assert event["payload"] == {
        "nested": {
            "[REDACTED_KEY]": "[REDACTED]",
            "object": "[REDACTED]",
            "secret": "[REDACTED]",
        },
        "token": "[REDACTED]",
    }


def test_storage_rejects_existing_permissive_parent_without_mutating_it(tmp_path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)
    db_path = parent / "ops.db"

    with pytest.raises(PermissionError, match="group or other"):
        OperationsStorage(db_path).initialize()

    assert mode(parent) == 0o755
    assert not db_path.exists()


def test_storage_rejects_existing_permissive_database_without_mutating_it(tmp_path) -> None:
    db_path = tmp_path / "ops.db"
    db_path.touch()
    db_path.chmod(0o644)

    with pytest.raises(PermissionError, match="group or other"):
        OperationsStorage(db_path).initialize()

    assert mode(db_path) == 0o644


def test_initialize_migrates_an_existing_database_for_internal_idempotency(tmp_path) -> None:
    db_path = tmp_path / "ops.db"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
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
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                sanitized_payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            """
        )
    db_path.chmod(0o600)
    storage = OperationsStorage(db_path)

    storage.initialize()
    storage.initialize()
    record = storage.create_run(
        run_id="run-migrated",
        thread_id="thread-migrated",
        app_name="Example App",
        app_slug="example-app",
        idempotency_key="idem_0123456789abcdef0123456789abcdef",
        request_fingerprint="a" * 64,
    )

    assert "idempotency_key" not in record
    assert "request_fingerprint" not in record
    with sqlite3.connect(db_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
        index_names = {row[1] for row in connection.execute("PRAGMA index_list(runs)")}
        stored = connection.execute(
            "SELECT idempotency_key, request_fingerprint FROM runs WHERE run_id = ?",
            ("run-migrated",),
        ).fetchone()

    assert {"idempotency_key", "request_fingerprint"} <= columns
    assert "idx_runs_idempotency_key" in index_names
    assert stored == ("idem_0123456789abcdef0123456789abcdef", "a" * 64)
