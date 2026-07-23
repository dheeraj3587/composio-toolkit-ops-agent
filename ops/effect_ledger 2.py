"""Owner-only idempotency ledger for sanitized external side-effect receipts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from ops.private_files import finalize_private_database, prepare_private_database
from ops.redaction import redact_data


class EffectStore(Protocol):
    def get(self, *, provider: str, action: str, idempotency_key: str) -> dict[str, str] | None: ...

    def put(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
        receipt: Mapping[str, str],
    ) -> None: ...


class SQLiteEffectStore:
    """Persist exact effect receipts without provider payloads or request bodies."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS external_effects (
                    effect_key TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    action TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def get(self, *, provider: str, action: str, idempotency_key: str) -> dict[str, str] | None:
        effect_key = self._key(provider, action, idempotency_key)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM external_effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(str(row[0]))
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            raise RuntimeError("external effect receipt is invalid")
        return value

    def put(
        self,
        *,
        provider: str,
        action: str,
        idempotency_key: str,
        receipt: Mapping[str, str],
    ) -> None:
        if not receipt or not all(
            isinstance(key, str) and isinstance(value, str) and len(value) <= 1_000
            for key, value in receipt.items()
        ):
            raise ValueError("effect receipts must contain bounded string identifiers")
        sanitized = redact_data(dict(receipt))
        if not isinstance(sanitized, dict) or sanitized != dict(receipt):
            raise ValueError("effect receipts cannot contain secret-like values")
        effect_key = self._key(provider, action, idempotency_key)
        serialized = json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO external_effects (effect_key, provider, action, receipt_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(effect_key) DO NOTHING
                """,
                (effect_key, provider, action, serialized),
            )
            existing = connection.execute(
                "SELECT receipt_json FROM external_effects WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
        if existing is None or str(existing[0]) != serialized:
            raise RuntimeError("idempotency key was reused for a different effect receipt")

    @staticmethod
    def _key(provider: str, action: str, idempotency_key: str) -> str:
        if not provider or not action or not idempotency_key or len(idempotency_key) > 500:
            raise ValueError("provider, action, and idempotency key are required")
        source = f"{provider}\x00{action}\x00{idempotency_key}".encode()
        return hashlib.sha256(source).hexdigest()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self._path)
        connection = sqlite3.connect(self._path, timeout=30)
        try:
            finalize_private_database(self._path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            with connection:
                yield connection
        finally:
            connection.close()
