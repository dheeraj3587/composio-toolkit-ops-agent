"""Owner-only reservation ledger for crash-safe external side effects."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from ops.private_files import finalize_private_database, prepare_private_database
from ops.redaction import redact_data

EffectStatus = Literal["reserved", "completed", "reconcile_required"]


@dataclass(frozen=True, slots=True)
class EffectReservation:
    status: EffectStatus
    receipt: dict[str, str] | None = None


class EffectStore(Protocol):
    def reserve(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> EffectReservation: ...

    def complete(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
        receipt: Mapping[str, str],
    ) -> None: ...

    def mark_outcome_unknown(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> None: ...

    def mark_failed(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> None: ...


class SQLiteEffectStore:
    """Atomically reserve keys and refuse blind resend after ambiguous outcomes."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(external_effects)").fetchall()
            }
            if columns and "status" not in columns:
                self._migrate_v1(connection)
            self._create_table(connection)

    def reserve(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> EffectReservation:
        effect_key = self._key(provider, action, idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, receipt_json FROM external_effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO external_effects (
                        effect_key, provider, action, status, receipt_json, updated_at
                    ) VALUES (?, ?, ?, 'pending', NULL, CURRENT_TIMESTAMP)
                    """,
                    (effect_key, provider, action),
                )
                connection.commit()
                return EffectReservation(status="reserved")
            status = str(row[0])
            if status == "completed":
                receipt = self._deserialize_receipt(row[1])
                connection.commit()
                return EffectReservation(status="completed", receipt=receipt)
            if status == "failed":
                connection.execute(
                    """
                    UPDATE external_effects
                    SET status = 'pending', receipt_json = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE effect_key = ? AND status = 'failed'
                    """,
                    (effect_key,),
                )
                connection.commit()
                return EffectReservation(status="reserved")
            connection.commit()
            return EffectReservation(status="reconcile_required")

    def complete(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
        receipt: Mapping[str, str],
    ) -> None:
        serialized = self._serialize_receipt(receipt)
        self._transition(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
            from_status="pending",
            to_status="completed",
            receipt_json=serialized,
        )

    def mark_outcome_unknown(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> None:
        self._transition(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
            from_status="pending",
            to_status="outcome_unknown",
            receipt_json=None,
        )

    def mark_failed(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
    ) -> None:
        self._transition(
            provider=provider,
            action=action,
            idempotency_key=idempotency_key,
            from_status="pending",
            to_status="failed",
            receipt_json=None,
        )

    def _transition(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
        from_status: str,
        to_status: str,
        receipt_json: str | None,
    ) -> None:
        effect_key = self._key(provider, action, idempotency_key)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, receipt_json FROM external_effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise RuntimeError("external effect was not reserved")
            if str(row[0]) == to_status and row[1] == receipt_json:
                connection.commit()
                return
            if str(row[0]) != from_status:
                connection.rollback()
                raise RuntimeError("external effect is not in the expected reservation state")
            connection.execute(
                """
                UPDATE external_effects
                SET status = ?, receipt_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE effect_key = ? AND status = ?
                """,
                (to_status, receipt_json, effect_key, from_status),
            )
            connection.commit()

    @staticmethod
    def _serialize_receipt(receipt: Mapping[str, str]) -> str:
        if not receipt or not all(
            isinstance(key, str) and isinstance(value, str) and len(value) <= 1_000
            for key, value in receipt.items()
        ):
            raise ValueError("effect receipts must contain bounded string identifiers")
        sanitized = redact_data(dict(receipt))
        if not isinstance(sanitized, dict) or sanitized != dict(receipt):
            raise ValueError("effect receipts cannot contain secret-like values")
        return json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _deserialize_receipt(value: object) -> dict[str, str]:
        if not isinstance(value, str):
            raise RuntimeError("completed external effect has no receipt")
        decoded = json.loads(value)
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in decoded.items()
        ):
            raise RuntimeError("external effect receipt is invalid")
        return decoded

    @staticmethod
    def _key(provider: str, action: str, idempotency_key: str) -> str:
        if not provider or not action or not idempotency_key or len(idempotency_key) > 500:
            raise ValueError("provider, action, and idempotency key are required")
        source = f"{provider}\x00{action}\x00{idempotency_key}".encode()
        return hashlib.sha256(source).hexdigest()

    @staticmethod
    def _create_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS external_effects (
                effect_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('pending', 'completed', 'outcome_unknown', 'failed')
                ),
                receipt_json TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    @classmethod
    def _migrate_v1(cls, connection: sqlite3.Connection) -> None:
        connection.execute("ALTER TABLE external_effects RENAME TO external_effects_v1")
        cls._create_table(connection)
        connection.execute(
            """
            INSERT INTO external_effects (
                effect_key, provider, action, status, receipt_json, updated_at
            )
            SELECT effect_key, provider, action, 'completed', receipt_json, created_at
            FROM external_effects_v1
            """
        )
        connection.execute("DROP TABLE external_effects_v1")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self._path)
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        try:
            finalize_private_database(self._path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            yield connection
        finally:
            connection.close()
