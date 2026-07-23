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
    "p1_summary_json",
    "operational_research_json",
    "route_reason_code",
    "route_explanation",
    "missing_fields_json",
    "provider_status_json",
    "hitl_request_json",
    "validation_json",
    "scope_policy",
    "execution_mode",
    "external_actions",
    "state_revision",
    "last_projected_revision",
    "created_at",
    "updated_at",
)

_JSON_RUN_FIELDS = {
    "integrator_bundle": "integrator_bundle_json",
    "p1_summary": "p1_summary_json",
    "operational_research": "operational_research_json",
    "missing_fields": "missing_fields_json",
    "provider_status": "provider_status_json",
    "hitl_request": "hitl_request_json",
    "validation": "validation_json",
}

_DEFAULT_JSON_VALUES: dict[str, object] = {
    "missing_fields": [],
    "provider_status": {},
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(
        redact_data(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sanitize_structured(value: object) -> object:
    """Redact leaf strings while preserving a validated model's field shapes.

    Audit payloads use key-aware redaction because their shape is open-ended.
    Persisted Pydantic projections have fixed schemas whose legitimate field
    names include words such as ``token_url`` and ``credential_fields``.  A
    key-aware pass would replace those fields wholesale and make the stored
    model impossible to validate on read.
    """

    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(key): _sanitize_structured(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize_structured(item) for item in value]
    return redact_data(value)


def _structured_json(value: object) -> str:
    return json.dumps(
        _sanitize_structured(value),
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
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        external_actions: bool = False,
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
            p1_summary=p1_summary,
            operational_research=operational_research,
            route_reason_code=route_reason_code,
            route_explanation=route_explanation,
            missing_fields=missing_fields,
            provider_status=provider_status,
            hitl_request=hitl_request,
            validation=validation,
            scope_policy=scope_policy,
            execution_mode=execution_mode,
            external_actions=external_actions,
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

    def reserve_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        """Atomically reserve one external mutation inside this transaction."""

        return self._storage._reserve_side_effect(
            self._connection,
            run_id=run_id,
            operation_key=operation_key,
            provider=provider,
        )

    def update_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        return self._storage._update_side_effect(
            self._connection,
            run_id=run_id,
            operation_key=operation_key,
            status=status,
            external_id=external_id,
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
                    p1_summary_json TEXT,
                    operational_research_json TEXT,
                    route_reason_code TEXT,
                    route_explanation TEXT,
                    missing_fields_json TEXT NOT NULL DEFAULT '[]',
                    provider_status_json TEXT NOT NULL DEFAULT '{}',
                    hitl_request_json TEXT,
                    validation_json TEXT,
                    scope_policy TEXT NOT NULL DEFAULT 'maximum',
                    execution_mode TEXT NOT NULL DEFAULT 'local_dry_run',
                    external_actions INTEGER NOT NULL DEFAULT 0,
                    state_revision INTEGER NOT NULL DEFAULT 0,
                    last_projected_revision INTEGER NOT NULL DEFAULT 0,
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

                CREATE TABLE IF NOT EXISTS side_effect_intents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    operation_key TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (run_id, operation_key),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );
                """
            )
            existing_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            migration_columns = {
                "idempotency_key": "TEXT",
                "request_fingerprint": "TEXT",
                "p1_summary_json": "TEXT",
                "operational_research_json": "TEXT",
                "route_reason_code": "TEXT",
                "route_explanation": "TEXT",
                "missing_fields_json": "TEXT NOT NULL DEFAULT '[]'",
                "provider_status_json": "TEXT NOT NULL DEFAULT '{}'",
                "hitl_request_json": "TEXT",
                "validation_json": "TEXT",
                "scope_policy": "TEXT NOT NULL DEFAULT 'maximum'",
                "execution_mode": "TEXT NOT NULL DEFAULT 'local_dry_run'",
                "external_actions": "INTEGER NOT NULL DEFAULT 0",
                "state_revision": "INTEGER NOT NULL DEFAULT 0",
                "last_projected_revision": "INTEGER NOT NULL DEFAULT 0",
            }
            for column_name, declaration in migration_columns.items():
                if column_name not in existing_columns:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {declaration}")
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
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        external_actions: bool = False,
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
                p1_summary=p1_summary,
                operational_research=operational_research,
                route_reason_code=route_reason_code,
                route_explanation=route_explanation,
                missing_fields=missing_fields,
                provider_status=provider_status,
                hitl_request=hitl_request,
                validation=validation,
                scope_policy=scope_policy,
                execution_mode=execution_mode,
                external_actions=external_actions,
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
        p1_summary: Mapping[str, object] | None = None,
        operational_research: Mapping[str, object] | None = None,
        route_reason_code: str | None = None,
        route_explanation: str | None = None,
        missing_fields: list[str] | None = None,
        provider_status: Mapping[str, object] | None = None,
        hitl_request: Mapping[str, object] | None = None,
        validation: Mapping[str, object] | None = None,
        scope_policy: str = "maximum",
        execution_mode: str = "local_dry_run",
        external_actions: bool = False,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        if (idempotency_key is None) != (request_fingerprint is None):
            raise ValueError("idempotency key and request fingerprint must be provided together")
        if browser_live_url is not None:
            raise ValueError("browser live capability URLs cannot be persisted")
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
            _structured_json(integrator_bundle) if integrator_bundle is not None else None,
            _structured_json(p1_summary) if p1_summary is not None else None,
            _structured_json(operational_research) if operational_research is not None else None,
            _safe_text(route_reason_code),
            _safe_text(route_explanation),
            _structured_json(missing_fields or []),
            _structured_json(provider_status or {}),
            _structured_json(hitl_request) if hitl_request is not None else None,
            _structured_json(validation) if validation is not None else None,
            _safe_text(scope_policy),
            _safe_text(execution_mode),
            int(external_actions),
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
                gmail_thread_id, integrator_bundle_json,
                p1_summary_json, operational_research_json, route_reason_code,
                route_explanation, missing_fields_json, provider_status_json,
                hitl_request_json, validation_json, scope_policy, execution_mode,
                external_actions, idempotency_key, request_fingerprint,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            "p1_summary",
            "operational_research",
            "route_reason_code",
            "route_explanation",
            "missing_fields",
            "provider_status",
            "hitl_request",
            "validation",
            "scope_policy",
            "execution_mode",
            "external_actions",
            "state_revision",
            "last_projected_revision",
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
            if name == "browser_live_url" and value is not None:
                raise ValueError("browser live capability URLs cannot be persisted")
            column = _JSON_RUN_FIELDS.get(name, name)
            assignments.append(f"{column} = ?")
            if name in _JSON_RUN_FIELDS:
                default = _DEFAULT_JSON_VALUES.get(name)
                values.append(
                    _structured_json(default)
                    if value is None and default is not None
                    else _structured_json(value)
                    if value is not None
                    else None
                )
            elif name == "external_actions":
                values.append(int(bool(value)))
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

    def reserve_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        """Reserve an idempotent external mutation and report whether it is new."""

        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._reserve_side_effect(
                connection,
                run_id=run_id,
                operation_key=operation_key,
                provider=provider,
            )

    def _reserve_side_effect(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        provider: str,
    ) -> tuple[dict[str, Any], bool]:
        if not operation_key or len(operation_key) > 200:
            raise ValueError("operation key is invalid")
        if not provider or len(provider) > 64:
            raise ValueError("provider name is invalid")
        now = _utc_now()
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO side_effect_intents (
                run_id, operation_key, provider, status, created_at, updated_at
            ) VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (
                _safe_text(run_id),
                _safe_text(operation_key),
                _safe_text(provider),
                now,
                now,
            ),
        )
        record = self._get_side_effect(connection, run_id, operation_key)
        if record is None:  # pragma: no cover - foreign key/insertion invariant
            raise KeyError("run was not found")
        return (record, cursor.rowcount == 1)

    def get_side_effect(self, run_id: str, operation_key: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            return self._get_side_effect(connection, run_id, operation_key)

    @staticmethod
    def _get_side_effect(
        connection: sqlite3.Connection,
        run_id: str,
        operation_key: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """
            SELECT run_id, operation_key, provider, status, external_id,
                   created_at, updated_at
            FROM side_effect_intents
            WHERE run_id = ? AND operation_key = ?
            """,
            (_safe_text(run_id), _safe_text(operation_key)),
        ).fetchone()
        if row is None:
            return None
        return dict(
            zip(
                (
                    "run_id",
                    "operation_key",
                    "provider",
                    "status",
                    "external_id",
                    "created_at",
                    "updated_at",
                ),
                row,
                strict=True,
            )
        )

    def update_side_effect(
        self,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        with self._connect() as connection:
            return self._update_side_effect(
                connection,
                run_id=run_id,
                operation_key=operation_key,
                status=status,
                external_id=external_id,
            )

    def _update_side_effect(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation_key: str,
        status: str,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"pending", "completed", "outcome_unknown", "failed"}:
            raise ValueError("side-effect status is invalid")
        cursor = connection.execute(
            """
            UPDATE side_effect_intents
            SET status = ?, external_id = ?, updated_at = ?
            WHERE run_id = ? AND operation_key = ?
            """,
            (
                status,
                _safe_text(external_id),
                _utc_now(),
                _safe_text(run_id),
                _safe_text(operation_key),
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError("side-effect intent was not found")
        record = self._get_side_effect(connection, run_id, operation_key)
        if record is None:  # pragma: no cover - update invariant
            raise RuntimeError("side-effect intent could not be read back")
        return record

    @staticmethod
    def _run_from_row(row: sqlite3.Row | tuple[object, ...]) -> dict[str, Any]:
        record = dict(zip(_RUN_COLUMNS, row, strict=True))
        for public_name, column_name in _JSON_RUN_FIELDS.items():
            serialized = record.pop(column_name)
            if serialized is None:
                record[public_name] = _DEFAULT_JSON_VALUES.get(public_name)
            else:
                record[public_name] = json.loads(str(serialized))
        record["external_actions"] = bool(record["external_actions"])
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
