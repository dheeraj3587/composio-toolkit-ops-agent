"""Owner-only SQLite vault with Fernet encryption at the storage boundary."""

from __future__ import annotations

import re
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.fernet import Fernet, InvalidToken

from ops.private_files import finalize_private_database, prepare_private_database

_APP_SLUG = re.compile(r"^[a-z0-9-]+$")
_KIND = re.compile(r"^[a-z0-9_-]+$")
_REFERENCE = re.compile(
    r"^vault://(?P<app>[a-z0-9-]+)/(?P<kind>[a-z0-9_-]+)/"
    r"(?P<id>[A-Za-z0-9_-]+)$"
)


class SecretStoreError(RuntimeError):
    """Base class for non-sensitive vault errors."""


class SecretNotFoundError(SecretStoreError):
    """Raised when an exact reference does not exist."""


class SecretDecryptionError(SecretStoreError):
    """Raised when a vault row cannot be authenticated with the active key."""


@runtime_checkable
class SecretStore(Protocol):
    def put(self, *, app_slug: str, kind: str, value: str) -> str: ...

    def get(self, reference: str) -> str: ...

    def delete(self, reference: str) -> None: ...


class SQLiteSecretStore:
    """Fernet-encrypted vault addressable only through exact references."""

    def __init__(self, db_path: str | Path, key: str | bytes) -> None:
        self.db_path = Path(db_path)
        encoded_key = key.encode("ascii") if isinstance(key, str) else key
        try:
            self._fernet = Fernet(encoded_key)
        except (TypeError, ValueError):
            raise ValueError("SECRET_VAULT_KEY must be a valid Fernet key") from None
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,
                    app_slug TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (app_slug, kind, id)
                )
                """
            )

    def put(self, *, app_slug: str, kind: str, value: str) -> str:
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        if _KIND.fullmatch(kind) is None:
            raise ValueError("kind must contain lowercase letters, digits, underscores, or hyphens")
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")

        identifier = secrets.token_urlsafe(18)
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO vault_entries (id, app_slug, kind, ciphertext)
                VALUES (?, ?, ?, ?)
                """,
                (identifier, app_slug, kind, ciphertext),
            )
        return f"vault://{app_slug}/{kind}/{identifier}"

    def get(self, reference: str) -> str:
        app_slug, kind, identifier = self._parse_reference(reference)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT ciphertext
                FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ?
                """,
                (identifier, app_slug, kind),
            ).fetchone()
        if row is None:
            raise SecretNotFoundError("secret reference was not found")
        try:
            plaintext = self._fernet.decrypt(bytes(row[0]))
            return plaintext.decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            raise SecretDecryptionError(
                "secret could not be decrypted with the active vault key"
            ) from None

    def delete(self, reference: str) -> None:
        app_slug, kind, identifier = self._parse_reference(reference)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ?
                """,
                (identifier, app_slug, kind),
            )
        if cursor.rowcount != 1:
            raise SecretNotFoundError("secret reference was not found")

    @staticmethod
    def _parse_reference(reference: str) -> tuple[str, str, str]:
        match = _REFERENCE.fullmatch(reference)
        if match is None:
            raise ValueError("an exact vault:// reference is required")
        return match.group("app"), match.group("kind"), match.group("id")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            with connection:
                yield connection
        finally:
            connection.close()
