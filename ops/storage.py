"""Narrow, sanitized persistence API for runs and structured audit events."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ops.private_files import finalize_private_database, prepare_private_database
from ops.redaction import redact_data, redact_text
from ops.state import AccessRoute, RunStatus

_RUN_COLUMNS = (
    "run_id",
    "thread_id",
    "app_name",
    "app_slug",
    "status",
    "access_route",
    "browser_session_id",
    "browser_live_url",
    "gmail_session_id",
    "gmail_thread_id",
    "integrator_bundle_json",
    "created_at",
    "updated_at",
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(
        redact_data(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _safe_text(value: str | None) -> str | None:
    return redact_text(value) if value is not None else None


class OperationsUnitOfWork:
    """Transaction-bound run/audit methods; the SQLite handle never escapes."""

    def __init__(self, storage: OperationsStorage, connection: sqlite3.Connection) -> None:
        self._storage = storage
        self._connection = connection

    def create_run(
        self,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        return self._storage._create_run(
            self._connection,
            run_id=run_id,
            thread_id=thread_id,
            app_name=app_name,
            app_slug=app_slug,
            status=status,
            access_route=access_route,
            browser_session_id=browser_session_id,
            browser_live_url=browser_live_url,
            gmail_session_id=gmail_session_id,
            gmail_thread_id=gmail_thread_id,
            integrator_bundle=integrator_bundle,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._storage._get_run(self._connection, run_id)

    def get_idempotent_run(self, idempotency_key: str) -> tuple[dict[str, Any], str] | None:
        """Return the stored run and opaque request digest for one exact key."""

        return self._storage._get_idempotent_run(self._connection, idempotency_key)

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        return self._storage._update_run(self._connection, run_id, **changes)

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        return self._storage._append_audit_event(
            self._connection,
            run_id=run_id,
            event_type=event_type,
            payload=payload,
        )


class OperationsStorage:
    """SQLite persistence that sanitizes every free-form value before writing."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
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
                    idempotency_key TEXT,
                    request_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    sanitized_payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_events_run_id
                ON audit_events(run_id, id);
                """
            )
            existing_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            for column_name in ("idempotency_key", "request_fingerprint"):
                if column_name not in existing_columns:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} TEXT")
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_idempotency_key
                ON runs(idempotency_key)
                WHERE idempotency_key IS NOT NULL
                """
            )

    @contextmanager
    def unit_of_work(self) -> Iterator[OperationsUnitOfWork]:
        """Commit all run/audit mutations together or roll them all back."""

        self.initialize()
        with self._connect() as connection:
            # Serialize the idempotency lookup/insert pair across writers. The
            # transaction is still short because Phase 2 performs all snapshot
            # and routing computation before entering this boundary.
            connection.execute("BEGIN IMMEDIATE")
            yield OperationsUnitOfWork(self, connection)

    def create_run(
        self,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        with self._connect() as connection:
            return self._create_run(
                connection,
                run_id=run_id,
                thread_id=thread_id,
                app_name=app_name,
                app_slug=app_slug,
                status=status,
                access_route=access_route,
                browser_session_id=browser_session_id,
                browser_live_url=browser_live_url,
                gmail_session_id=gmail_session_id,
                gmail_thread_id=gmail_thread_id,
                integrator_bundle=integrator_bundle,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )

    def _create_run(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        thread_id: str,
        app_name: str,
        app_slug: str,
        status: RunStatus = "created",
        access_route: AccessRoute | None = None,
        browser_session_id: str | None = None,
        browser_live_url: str | None = None,
        gmail_session_id: str | None = None,
        gmail_thread_id: str | None = None,
        integrator_bundle: Mapping[str, object] | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        if (idempotency_key is None) != (request_fingerprint is None):
            raise ValueError("idempotency key and request fingerprint must be provided together")
        now = _utc_now()
        values = (
            _safe_text(run_id),
            _safe_text(thread_id),
            _safe_text(app_name),
            _safe_text(app_slug),
            status,
            access_route,
            _safe_text(browser_session_id),
            _safe_text(browser_live_url),
            _safe_text(gmail_session_id),
            _safe_text(gmail_thread_id),
            _json(integrator_bundle) if integrator_bundle is not None else None,
            _safe_text(idempotency_key),
            _safe_text(request_fingerprint),
            now,
            now,
        )
        connection.execute(
            """
            INSERT INTO runs (
                run_id, thread_id, app_name, app_slug, status, access_route,
                browser_session_id, browser_live_url, gmail_session_id,
                gmail_thread_id, integrator_bundle_json, idempotency_key,
                request_fingerprint, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        created = self._get_run(connection, str(values[0]))
        if created is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("created run could not be read back")
        return created

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            return self._get_run(connection, run_id)

    def _get_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM runs WHERE run_id = ?",
            (_safe_text(run_id),),
        ).fetchone()
        return self._run_from_row(row) if row is not None else None

    def _get_idempotent_run(
        self,
        connection: sqlite3.Connection,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], str] | None:
        row = connection.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)}, request_fingerprint "
            "FROM runs WHERE idempotency_key = ?",
            (_safe_text(idempotency_key),),
        ).fetchone()
        if row is None:
            return None
        fingerprint = row[len(_RUN_COLUMNS)]
        if not isinstance(fingerprint, str):  # pragma: no cover - paired write invariant
            raise RuntimeError("idempotent run is missing its request fingerprint")
        return (self._run_from_row(row[: len(_RUN_COLUMNS)]), fingerprint)

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        """Update only declared mutable run columns and return the fresh record."""

        self.initialize()
        with self._connect() as connection:
            return self._update_run(connection, run_id, **changes)

    def _update_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        **changes: object,
    ) -> dict[str, Any]:
        """Update one run on a caller-owned transaction."""

        allowed = {
            "status",
            "access_route",
            "browser_session_id",
            "browser_live_url",
            "gmail_session_id",
            "gmail_thread_id",
            "integrator_bundle",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError("unsupported run update field")
        if not changes:
            existing = self._get_run(connection, run_id)
            if existing is None:
                raise KeyError("run was not found")
            return existing

        assignments: list[str] = []
        values: list[object] = []
        for name, value in changes.items():
            column = "integrator_bundle_json" if name == "integrator_bundle" else name
            assignments.append(f"{column} = ?")
            if name == "integrator_bundle":
                values.append(_json(value) if value is not None else None)
            elif isinstance(value, str):
                values.append(_safe_text(value))
            else:
                values.append(value)
        assignments.append("updated_at = ?")
        values.extend((_utc_now(), _safe_text(run_id)))

        cursor = connection.execute(
            f"UPDATE runs SET {', '.join(assignments)} WHERE run_id = ?",
            values,
        )
        if cursor.rowcount != 1:
            raise KeyError("run was not found")
        updated = self._get_run(connection, run_id)
        if updated is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("updated run could not be read back")
        return updated

    def list_runs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self.initialize()
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be zero or greater")
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(_RUN_COLUMNS)} "
                "FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def count_runs(self) -> int:
        """Return the number of run records without exposing database details."""

        self.initialize()
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM runs").fetchone()
        if row is None:  # pragma: no cover - SQLite aggregate invariant
            raise RuntimeError("run count could not be read")
        return int(row[0])

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        self.initialize()
        with self._connect() as connection:
            return self._append_audit_event(
                connection,
                run_id=run_id,
                event_type=event_type,
                payload=payload,
            )

    def _append_audit_event(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        cursor = connection.execute(
            """
            INSERT INTO audit_events (
                run_id, event_type, sanitized_payload_json, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                _safe_text(run_id),
                _safe_text(event_type),
                _json(payload or {}),
                _utc_now(),
            ),
        )
        event_id = cursor.lastrowid
        if event_id is None:  # pragma: no cover - sqlite invariant
            raise RuntimeError("audit event id was not generated")
        return int(event_id)

    def list_audit_events(self, run_id: str) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, run_id, event_type, sanitized_payload_json, created_at
                FROM audit_events
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (_safe_text(run_id),),
            ).fetchall()
        return [
            {
                "id": row[0],
                "run_id": row[1],
                "event_type": row[2],
                "payload": json.loads(row[3]),
                "created_at": row[4],
            }
            for row in rows
        ]

    @staticmethod
    def _run_from_row(row: sqlite3.Row | tuple[object, ...]) -> dict[str, Any]:
        record = dict(zip(_RUN_COLUMNS, row, strict=True))
        serialized_bundle = record.pop("integrator_bundle_json")
        record["integrator_bundle"] = (
            json.loads(str(serialized_bundle)) if serialized_bundle is not None else None
        )
        return record

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            with connection:
                yield connection
        finally:
            connection.close()
