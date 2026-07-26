"""Owner-only SQLite vault with Fernet encryption at the storage boundary."""

from __future__ import annotations

import contextlib
import re
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


class TransientSecretError(SecretStoreError):
    """A typed, value-free failure when consuming a transient reference.

    The ``reason_code`` never reveals whether ANOTHER app's reference exists — a
    scope/app/kind mismatch and a missing row both surface as their own codes
    without confirming the existence of anyone else's secret.
    """

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class VaultReferenceParts:
    """The parsed components of a ``vault://app/kind/id`` reference."""

    app_slug: str
    kind: str
    identifier: str


def parse_vault_reference(reference: str) -> VaultReferenceParts:
    """Parse an exact vault reference, or raise ``ValueError``.

    The single shared parser (previously each module carried its own regex), so
    the reference grammar cannot drift between the writer and the consumer.
    """

    match = _REFERENCE.fullmatch(reference)
    if match is None:
        raise ValueError("an exact vault reference is required")
    return VaultReferenceParts(
        app_slug=match.group("app"), kind=match.group("kind"), identifier=match.group("id")
    )


# Reusable account-login secrets live in their OWN kind namespace so that a
# durable sign-in credential can never be confused with (or read through the
# same path as) a captured integration credential.
ACCOUNT_LOGIN_KIND_PREFIX = "account_login_"

# Only the sign-in fields the deterministic login state machine can actually
# use. An unknown field is refused rather than stored under a new kind.
REUSABLE_LOGIN_FIELDS: frozenset[str] = frozenset({"login_email", "login_password"})


def _account_login_kind(field: str) -> str:
    """Map a permitted login field to its durable vault kind."""

    if field not in REUSABLE_LOGIN_FIELDS:
        raise ValueError("field is not a reusable login credential")
    return f"{ACCOUNT_LOGIN_KIND_PREFIX}{field}"


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
            # Additive migration for transient (one-time, scoped, expiring) rows.
            # Only MISSING columns are added; existing permanent entries and their
            # ciphertext are never rewritten. All in one initialization txn.
            existing = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(vault_entries)")
            }
            for column, ddl in (
                ("scope_id", "ALTER TABLE vault_entries ADD COLUMN scope_id TEXT"),
                ("expires_at", "ALTER TABLE vault_entries ADD COLUMN expires_at TEXT"),
                (
                    "one_time",
                    "ALTER TABLE vault_entries ADD COLUMN one_time INTEGER NOT NULL DEFAULT 0",
                ),
                ("consumed_at", "ALTER TABLE vault_entries ADD COLUMN consumed_at TEXT"),
            ):
                if column not in existing:
                    connection.execute(ddl)

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

    def put_account_login(self, *, app_slug: str, field: str, value: str) -> str:
        """Store (or replace) ONE reusable account-login secret for an app.

        Autonomous sign-in needs the owner's app credentials to survive a single
        run: every other login path here is one-time and run-scoped, so a second
        run could never authenticate itself and always stopped at a human gate.

        Deliberately narrow so this cannot become a general secret-reading API:
        only ``login_*`` fields are accepted, the row is stored under a distinct
        ``account_login_`` kind (never the same namespace as a captured
        integration credential), and it is addressable only by (app, field) —
        which is why the previous value is REPLACED rather than accumulated.
        """

        kind = _account_login_kind(field)
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")

        identifier = secrets.token_urlsafe(18)
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._connect() as connection:
            # Replace, so exactly one current credential exists per (app, field)
            # and a rotated password can never be shadowed by a stale row.
            connection.execute(
                "DELETE FROM vault_entries WHERE app_slug = ? AND kind = ?",
                (app_slug, kind),
            )
            connection.execute(
                """
                INSERT INTO vault_entries (id, app_slug, kind, ciphertext)
                VALUES (?, ?, ?, ?)
                """,
                (identifier, app_slug, kind, ciphertext),
            )
        return f"vault://{app_slug}/{kind}/{identifier}"

    def get_account_login(self, *, app_slug: str, field: str) -> str | None:
        """Return a stored reusable login value, or None when none is stored.

        Returns None (never raises) for the absent case: "no stored credential"
        is a normal autonomous-run condition, not an error. A row that cannot be
        decrypted with the ACTIVE key is also None, so a rotated vault key
        degrades to "log in again" instead of crashing a run.
        """

        kind = _account_login_kind(field)
        if _APP_SLUG.fullmatch(app_slug) is None:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT ciphertext
                FROM vault_entries
                WHERE app_slug = ? AND kind = ? AND one_time = 0
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (app_slug, kind),
            ).fetchone()
        if row is None:
            return None
        try:
            return self._fernet.decrypt(bytes(row[0])).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            return None

    def delete_account_login(self, *, app_slug: str, field: str) -> None:
        """Forget a stored reusable login secret (idempotent)."""

        kind = _account_login_kind(field)
        if _APP_SLUG.fullmatch(app_slug) is None:
            return
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM vault_entries WHERE app_slug = ? AND kind = ?",
                (app_slug, kind),
            )

    def put_transient(
        self,
        *,
        app_slug: str,
        kind: str,
        scope_id: str,
        value: str,
        ttl_seconds: int = 600,
    ) -> str:
        """Store a ONE-TIME, scope-bound, expiring secret and return its reference.

        Used for browser-login credentials handed to the browser service: the raw
        value stays off the RPC wire, and the reference it replaces can be consumed
        exactly once, only by the matching (app, kind, scope), before it expires.
        """

        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        if _KIND.fullmatch(kind) is None:
            raise ValueError("kind must contain lowercase letters, digits, underscores, or hyphens")
        if not isinstance(scope_id, str) or not (1 <= len(scope_id) <= 200):
            raise ValueError("scope_id must be a bounded non-empty string")
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")
        if not (30 <= ttl_seconds <= 1_800):
            raise ValueError("transient ttl must be between 30 and 1800 seconds")

        identifier = secrets.token_urlsafe(18)
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO vault_entries
                    (id, app_slug, kind, ciphertext, scope_id, expires_at, one_time)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (identifier, app_slug, kind, ciphertext, scope_id, expires_at),
            )
        return f"vault://{app_slug}/{kind}/{identifier}"

    def consume_transient(
        self,
        reference: str,
        *,
        expected_app_slug: str,
        expected_kind: str,
        expected_scope_id: str,
    ) -> str:
        """Atomically read-and-delete a one-time transient secret.

        Everything happens in one ``BEGIN IMMEDIATE`` transaction so two racing
        consumers cannot both succeed. Every binding is checked exactly; a mismatch
        or expiry is a typed, value-free error that never confirms whether another
        app's reference exists.
        """

        parts = parse_vault_reference(reference)
        if parts.app_slug != expected_app_slug:
            raise TransientSecretError("browser_secret_app_mismatch")
        if parts.kind != expected_kind:
            raise TransientSecretError("browser_secret_kind_mismatch")

        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT ciphertext, scope_id, expires_at, one_time, consumed_at
                FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ?
                """,
                (parts.identifier, expected_app_slug, expected_kind),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise TransientSecretError("browser_secret_not_found")
            ciphertext, scope_id, expires_at, one_time, consumed_at = row
            if str(scope_id or "") != expected_scope_id:
                connection.rollback()
                raise TransientSecretError("browser_secret_scope_mismatch")
            if int(one_time or 0) != 1:
                connection.rollback()
                raise TransientSecretError("browser_secret_not_transient")
            if consumed_at is not None:
                connection.rollback()
                raise TransientSecretError("browser_secret_already_consumed")
            if self._is_expired(expires_at):
                connection.rollback()
                raise TransientSecretError("browser_secret_expired")
            try:
                plaintext = self._fernet.decrypt(bytes(ciphertext)).decode("utf-8")
            except (InvalidToken, UnicodeDecodeError):
                connection.rollback()
                raise TransientSecretError("browser_secret_decryption_failed") from None
            # Consume by DELETE (secure_delete on), so the value cannot be reused.
            connection.execute(
                """
                DELETE FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ? AND consumed_at IS NULL
                """,
                (parts.identifier, expected_app_slug, expected_kind),
            )
            connection.commit()
            return plaintext
        except TransientSecretError:
            raise
        except Exception:
            with contextlib.suppress(Exception):
                connection.rollback()
            raise TransientSecretError("browser_secret_consume_failed") from None
        finally:
            connection.close()

    @staticmethod
    def _is_expired(expires_at: object) -> bool:
        if not isinstance(expires_at, str) or not expires_at:
            return True  # a transient row without an expiry is treated as expired
        try:
            return datetime.now(UTC) >= datetime.fromisoformat(expires_at)
        except ValueError:
            return True

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
