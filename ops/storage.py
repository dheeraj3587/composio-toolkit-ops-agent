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
    ) -> dict[str, Any]:
        self.initialize()
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
            now,
            now,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, thread_id, app_name, app_slug, status, access_route,
                    browser_session_id, browser_live_url, gmail_session_id,
                    gmail_thread_id, integrator_bundle_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        created = self.get_run(str(values[0]))
        if created is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("created run could not be read back")
        return created

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {', '.join(_RUN_COLUMNS)} FROM runs WHERE run_id = ?",
                (_safe_text(run_id),),
            ).fetchone()
        return self._run_from_row(row) if row is not None else None

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        """Update only declared mutable run columns and return the fresh record."""

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
            existing = self.get_run(run_id)
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

        with self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE runs SET {', '.join(assignments)} WHERE run_id = ?",
                values,
            )
        if cursor.rowcount != 1:
            raise KeyError("run was not found")
        updated = self.get_run(run_id)
        if updated is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("updated run could not be read back")
        return updated

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        self.initialize()
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(_RUN_COLUMNS)} FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def append_audit_event(
        self,
        *,
        run_id: str,
        event_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> int:
        self.initialize()
        with self._connect() as connection:
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
