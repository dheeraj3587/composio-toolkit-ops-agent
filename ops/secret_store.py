"""Owner-only SQLite vault with Fernet encryption at the storage boundary."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from cryptography.fernet import Fernet, InvalidToken

from ops.private_files import finalize_private_database, prepare_private_database

_APP_SLUG = re.compile(r"^[a-z0-9-]+$")
_KIND = re.compile(r"^[a-z0-9_-]+$")
_ACCOUNT_REF = re.compile(r"^(?:acct|run)_[0-9a-f]{32}$")
_REFERENCE = re.compile(
    r"^vault://(?P<app>[a-z0-9-]+)/(?P<kind>[a-z0-9_-]+)/"
    r"(?P<id>[A-Za-z0-9_-]+)$"
)
_BROKER_GRANT = re.compile(r"^bsg_[A-Za-z0-9_-]{43}$")
_BROKER_OPERATION = re.compile(r"^[A-Za-z0-9:_-]{1,300}$")
_BROKER_SCOPE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")


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


class SignupCredentialStateError(SecretStoreError):
    """A value-free failure from the run-scoped signup credential state machine."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class AccountLoginStateError(SecretStoreError):
    """A value-free failure from reusable existing-account login state."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class GmailMessageIngestionStateError(SecretStoreError):
    """A value-free failure from durable outreach-message ingestion state."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class BrowserSecretGrantError(SecretStoreError):
    """A value-free failure from the exact browser-secret grant ledger."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


EmailMessageIngestionStatus = Literal["acquired", "busy", "completed"]


@dataclass(frozen=True, slots=True)
class EmailMessageIngestionReservation:
    """Crash-safe ownership of one immutable Gmail outreach reply.

    ``credential_refs`` is populated only for the caller that owns an acquired
    lease. A completed or concurrently-held message never discloses another
    run's references.
    """

    status: EmailMessageIngestionStatus
    claim_token: str | None = None
    credential_refs: tuple[tuple[str, str], ...] = ()


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
        # Domain-separated key for deterministic, unguessable broker grants. The
        # raw grant is never stored; SQLite keeps only its SHA-256 digest.
        self._browser_grant_key = hmac.new(
            encoded_key,
            b"composio-ops/browser-secret-grant/v1",
            hashlib.sha256,
        ).digest()
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS staged_signup_logins (
                    run_id TEXT PRIMARY KEY,
                    app_slug TEXT NOT NULL,
                    account_ref TEXT NOT NULL,
                    email_ciphertext BLOB NOT NULL,
                    password_ciphertext BLOB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'promoted')),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    promoted_at TEXT,
                    UNIQUE (app_slug, account_ref)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS staged_existing_logins (
                    run_id TEXT PRIMARY KEY,
                    app_slug TEXT NOT NULL,
                    account_ref TEXT NOT NULL,
                    email_ciphertext BLOB NOT NULL,
                    password_ciphertext BLOB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'promoted')),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    promoted_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS gmail_message_ingestions (
                    ingestion_key TEXT PRIMARY KEY,
                    owner_run_id TEXT NOT NULL,
                    app_slug TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('processing', 'completed')),
                    claim_token TEXT,
                    credential_refs_json TEXT NOT NULL,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS browser_secret_grants (
                    grant_digest TEXT PRIMARY KEY,
                    operation_key TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    app_slug TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    action TEXT NOT NULL CHECK (action IN ('consume', 'capture')),
                    secret_reference TEXT,
                    status TEXT NOT NULL
                        CHECK (status IN ('reserved', 'completed', 'revoked')),
                    result_reference TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    completed_at TEXT,
                    CHECK (
                        (action = 'consume' AND secret_reference IS NOT NULL)
                        OR (action = 'capture' AND secret_reference IS NULL)
                    ),
                    CHECK (
                        (status = 'completed' AND action = 'capture'
                            AND result_reference IS NOT NULL)
                        OR status != 'completed'
                        OR action = 'consume'
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_browser_secret_grants_run_status
                ON browser_secret_grants (run_id, status)
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
                ("account_ref", "ALTER TABLE vault_entries ADD COLUMN account_ref TEXT"),
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

    @staticmethod
    def _validate_browser_grant_binding(
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None,
    ) -> None:
        if _BROKER_OPERATION.fullmatch(operation_key) is None:
            raise ValueError("browser secret operation key is invalid")
        if _BROKER_SCOPE.fullmatch(run_id) is None:
            raise ValueError("browser secret run scope is invalid")
        if _BROKER_SCOPE.fullmatch(session_id) is None:
            raise ValueError("browser secret session id is invalid")
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("browser secret app slug is invalid")
        if _KIND.fullmatch(kind) is None:
            raise ValueError("browser secret kind is invalid")
        if action == "consume":
            if reference is None:
                raise ValueError("consume grants require an exact reference")
            parts = parse_vault_reference(reference)
            if parts.app_slug != app_slug or parts.kind != kind:
                raise ValueError("consume grant reference binding is invalid")
        elif action == "capture":
            if reference is not None:
                raise ValueError("capture grants cannot bind an input reference")
        else:  # pragma: no cover - protected by the Literal type at call sites
            raise ValueError("browser secret action is invalid")

    def _browser_grant_token(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None,
    ) -> str:
        material = json.dumps(
            {
                "action": action,
                "app_slug": app_slug,
                "kind": kind,
                "operation_key": operation_key,
                "reference": reference,
                "run_id": run_id,
                "session_id": session_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hmac.new(self._browser_grant_key, material, hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return f"bsg_{encoded}"

    @staticmethod
    def _browser_grant_digest(grant: str) -> str:
        if _BROKER_GRANT.fullmatch(grant) is None:
            raise BrowserSecretGrantError("browser_secret_grant_invalid")
        return hashlib.sha256(grant.encode("ascii")).hexdigest()

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        """Durably reserve one exact broker operation and return its opaque grant.

        The caller reserves this while holding the canonical run lock. Repeating
        the same reservation deterministically returns the same bearer, which is
        essential for capture response-loss recovery without creating a duplicate
        vault row.
        """

        self._validate_browser_grant_binding(
            operation_key=operation_key,
            run_id=run_id,
            session_id=session_id,
            app_slug=app_slug,
            kind=kind,
            action=action,
            reference=reference,
        )
        if not (30 <= ttl_seconds <= 3_600):
            raise ValueError("browser secret grant ttl must be between 30 and 3600 seconds")
        grant = self._browser_grant_token(
            operation_key=operation_key,
            run_id=run_id,
            session_id=session_id,
            app_slug=app_slug,
            kind=kind,
            action=action,
            reference=reference,
        )
        grant_digest = self._browser_grant_digest(grant)
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO browser_secret_grants (
                    grant_digest, operation_key, run_id, session_id, app_slug,
                    kind, action, secret_reference, status, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?)
                """,
                (
                    grant_digest,
                    operation_key,
                    run_id,
                    session_id,
                    app_slug,
                    kind,
                    action,
                    reference,
                    expires_at,
                ),
            )
            row = connection.execute(
                """
                SELECT operation_key, run_id, session_id, app_slug, kind, action,
                       secret_reference, status
                FROM browser_secret_grants
                WHERE grant_digest = ?
                """,
                (grant_digest,),
            ).fetchone()
            expected = (
                operation_key,
                run_id,
                session_id,
                app_slug,
                kind,
                action,
                reference,
            )
            if row is None or tuple(
                str(value) if value is not None else None for value in row[:7]
            ) != (
                *expected[:-1],
                expected[-1],
            ):
                raise BrowserSecretGrantError("browser_secret_grant_binding_mismatch")
            if str(row[7]) == "revoked":
                raise BrowserSecretGrantError("browser_secret_grant_revoked")
            if str(row[7]) == "reserved":
                # A fresh authoritative reservation may extend an unused grant.
                connection.execute(
                    """
                    UPDATE browser_secret_grants
                    SET expires_at = ?
                    WHERE grant_digest = ? AND status = 'reserved'
                    """,
                    (expires_at, grant_digest),
                )
        return grant

    @staticmethod
    def _grant_row_matches(
        row: Sequence[object],
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: Literal["consume", "capture"],
        reference: str | None,
    ) -> bool:
        return (
            len(row) >= 10
            and str(row[0]) == run_id
            and str(row[1]) == session_id
            and str(row[2]) == app_slug
            and str(row[3]) == kind
            and str(row[4]) == action
            and (str(row[5]) if row[5] is not None else None) == reference
            and str(row[9]) == operation_key
        )

    def consume_transient_with_grant(
        self,
        grant: str,
        reference: str,
        *,
        expected_app_slug: str,
        expected_kind: str,
        expected_scope_id: str,
        expected_session_id: str,
        expected_operation_key: str,
    ) -> str:
        """Atomically claim an exact grant and delete its one-time vault row."""

        self._validate_browser_grant_binding(
            operation_key=expected_operation_key,
            run_id=expected_scope_id,
            session_id=expected_session_id,
            app_slug=expected_app_slug,
            kind=expected_kind,
            action="consume",
            reference=reference,
        )
        grant_digest = self._browser_grant_digest(grant)
        parts = parse_vault_reference(reference)
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")
            grant_row = connection.execute(
                """
                SELECT run_id, session_id, app_slug, kind, action, secret_reference,
                       status, result_reference, expires_at, operation_key
                FROM browser_secret_grants
                WHERE grant_digest = ?
                """,
                (grant_digest,),
            ).fetchone()
            if grant_row is None or not self._grant_row_matches(
                grant_row,
                operation_key=expected_operation_key,
                run_id=expected_scope_id,
                session_id=expected_session_id,
                app_slug=expected_app_slug,
                kind=expected_kind,
                action="consume",
                reference=reference,
            ):
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            if str(grant_row[6]) != "reserved":
                raise BrowserSecretGrantError("browser_secret_grant_already_used")
            if self._is_expired(grant_row[8]):
                raise BrowserSecretGrantError("browser_secret_grant_expired")
            secret_row = connection.execute(
                """
                SELECT ciphertext, scope_id, expires_at, one_time, consumed_at
                FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ?
                """,
                (parts.identifier, expected_app_slug, expected_kind),
            ).fetchone()
            if secret_row is None:
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            ciphertext, scope_id, expires_at, one_time, consumed_at = secret_row
            if (
                str(scope_id or "") != expected_scope_id
                or int(one_time or 0) != 1
                or consumed_at is not None
                or self._is_expired(expires_at)
            ):
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            try:
                value = self._fernet.decrypt(bytes(ciphertext)).decode("utf-8")
            except (InvalidToken, UnicodeDecodeError, TypeError):
                raise BrowserSecretGrantError("browser_secret_grant_unavailable") from None
            connection.execute(
                "DELETE FROM vault_entries WHERE id = ?",
                (parts.identifier,),
            )
            if connection.total_changes != 1:
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            connection.execute(
                """
                UPDATE browser_secret_grants
                SET status = 'completed', completed_at = CURRENT_TIMESTAMP
                WHERE grant_digest = ? AND status = 'reserved'
                """,
                (grant_digest,),
            )
            if connection.total_changes != 2:
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            connection.commit()
            return value
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def capture_with_grant(
        self,
        grant: str,
        *,
        app_slug: str,
        kind: str,
        scope_id: str,
        session_id: str,
        value: str,
        expected_operation_key: str,
    ) -> str:
        """Atomically capture once; an exact replay returns the original ref."""

        self._validate_browser_grant_binding(
            operation_key=expected_operation_key,
            run_id=scope_id,
            session_id=session_id,
            app_slug=app_slug,
            kind=kind,
            action="capture",
            reference=None,
        )
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")
        grant_digest = self._browser_grant_digest(grant)
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        connection = sqlite3.connect(self.db_path, timeout=5)
        try:
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")
            grant_row = connection.execute(
                """
                SELECT run_id, session_id, app_slug, kind, action, secret_reference,
                       status, result_reference, expires_at, operation_key
                FROM browser_secret_grants
                WHERE grant_digest = ?
                """,
                (grant_digest,),
            ).fetchone()
            if grant_row is None or not self._grant_row_matches(
                grant_row,
                operation_key=expected_operation_key,
                run_id=scope_id,
                session_id=session_id,
                app_slug=app_slug,
                kind=kind,
                action="capture",
                reference=None,
            ):
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            status_value = str(grant_row[6])
            if status_value == "completed":
                result_reference = str(grant_row[7] or "")
                try:
                    result_parts = parse_vault_reference(result_reference)
                except ValueError:
                    raise BrowserSecretGrantError("browser_secret_grant_state_invalid") from None
                result_row = connection.execute(
                    """
                    SELECT ciphertext
                    FROM vault_entries
                    WHERE id = ? AND app_slug = ? AND kind = ?
                    """,
                    (result_parts.identifier, app_slug, kind),
                ).fetchone()
                if result_row is None:
                    raise BrowserSecretGrantError("browser_secret_grant_state_invalid")
                try:
                    previous = self._fernet.decrypt(bytes(result_row[0])).decode("utf-8")
                except (InvalidToken, UnicodeDecodeError, TypeError):
                    raise BrowserSecretGrantError("browser_secret_grant_state_invalid") from None
                if not secrets.compare_digest(previous, value):
                    raise BrowserSecretGrantError("browser_secret_grant_replay_mismatch")
                connection.commit()
                return result_reference
            if status_value != "reserved":
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            if self._is_expired(grant_row[8]):
                raise BrowserSecretGrantError("browser_secret_grant_expired")
            identifier = secrets.token_urlsafe(18)
            reference = f"vault://{app_slug}/{kind}/{identifier}"
            connection.execute(
                """
                INSERT INTO vault_entries (id, app_slug, kind, ciphertext)
                VALUES (?, ?, ?, ?)
                """,
                (identifier, app_slug, kind, ciphertext),
            )
            connection.execute(
                """
                UPDATE browser_secret_grants
                SET status = 'completed', result_reference = ?,
                    completed_at = CURRENT_TIMESTAMP
                WHERE grant_digest = ? AND status = 'reserved'
                """,
                (reference, grant_digest),
            )
            if connection.total_changes != 2:
                raise BrowserSecretGrantError("browser_secret_grant_unavailable")
            connection.commit()
            return reference
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def begin_gmail_message_ingestion(
        self,
        *,
        connected_account_id: str,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        app_slug: str,
        credentials: Sequence[tuple[str, str]],
        lease_seconds: int = 900,
    ) -> EmailMessageIngestionReservation:
        """Atomically reserve one Gmail message and vault only its credentials.

        The reservation key is global to the connected Gmail account, thread and
        immutable message id; ``owner_run_id`` is deliberately not part of it.
        Credential rows and the processing reservation are committed in the same
        SQLite transaction, so a crash can leave neither duplicate nor orphan
        vault entries. A stale lease may be reclaimed only by its original run.
        """

        ingestion_key = self._gmail_ingestion_key(
            connected_account_id=connected_account_id,
            thread_id=thread_id,
            message_id=message_id,
        )
        self._validate_gmail_ingestion_input(
            owner_run_id=owner_run_id,
            app_slug=app_slug,
            credentials=credentials,
            lease_seconds=lease_seconds,
        )
        now = datetime.now(UTC)
        lease_expires_at = (now + timedelta(seconds=lease_seconds)).isoformat()
        claim_token = secrets.token_urlsafe(24)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT owner_run_id, status, credential_refs_json, lease_expires_at
                FROM gmail_message_ingestions
                WHERE ingestion_key = ?
                """,
                (ingestion_key,),
            ).fetchone()
            if existing is not None:
                stored_owner, status, serialized_refs, stored_expiry = existing
                if str(status) == "completed" or str(stored_owner) != owner_run_id:
                    return EmailMessageIngestionReservation(status="completed")
                if not self._lease_expired(stored_expiry, now=now):
                    return EmailMessageIngestionReservation(status="busy")
                credential_refs = self._decode_credential_refs(
                    serialized_refs,
                    expected_app_slug=app_slug,
                )
                connection.execute(
                    """
                    UPDATE gmail_message_ingestions
                    SET claim_token = ?, lease_expires_at = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE ingestion_key = ? AND owner_run_id = ?
                      AND status = 'processing'
                    """,
                    (claim_token, lease_expires_at, ingestion_key, owner_run_id),
                )
                return EmailMessageIngestionReservation(
                    status="acquired",
                    claim_token=claim_token,
                    credential_refs=tuple(credential_refs.items()),
                )

            credential_refs = self._insert_email_credentials(
                connection,
                app_slug=app_slug,
                credentials=credentials,
            )
            serialized_refs = json.dumps(
                credential_refs,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                """
                INSERT INTO gmail_message_ingestions (
                    ingestion_key, owner_run_id, app_slug, status, claim_token,
                    credential_refs_json, lease_expires_at
                ) VALUES (?, ?, ?, 'processing', ?, ?, ?)
                """,
                (
                    ingestion_key,
                    owner_run_id,
                    app_slug,
                    claim_token,
                    serialized_refs,
                    lease_expires_at,
                ),
            )
        return EmailMessageIngestionReservation(
            status="acquired",
            claim_token=claim_token,
            credential_refs=tuple(credential_refs.items()),
        )

    def complete_gmail_message_ingestion(
        self,
        *,
        connected_account_id: str,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        """Complete an acquired message after its run transition commits."""

        ingestion_key = self._gmail_ingestion_key(
            connected_account_id=connected_account_id,
            thread_id=thread_id,
            message_id=message_id,
        )
        self._validate_ingestion_owner(owner_run_id)
        self._validate_claim_token(claim_token)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT owner_run_id, status, claim_token
                FROM gmail_message_ingestions
                WHERE ingestion_key = ?
                """,
                (ingestion_key,),
            ).fetchone()
            if row is None or str(row[0]) != owner_run_id:
                return False
            if str(row[1]) == "completed":
                return True
            if str(row[2] or "") != claim_token:
                return False
            cursor = connection.execute(
                """
                UPDATE gmail_message_ingestions
                SET status = 'completed', claim_token = NULL,
                    lease_expires_at = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE ingestion_key = ? AND owner_run_id = ?
                  AND status = 'processing' AND claim_token = ?
                """,
                (ingestion_key, owner_run_id, claim_token),
            )
            return cursor.rowcount == 1

    def release_gmail_message_ingestion(
        self,
        *,
        connected_account_id: str,
        thread_id: str,
        message_id: str,
        owner_run_id: str,
        claim_token: str,
    ) -> bool:
        """Expire a failed processing lease so the same run can retry safely."""

        ingestion_key = self._gmail_ingestion_key(
            connected_account_id=connected_account_id,
            thread_id=thread_id,
            message_id=message_id,
        )
        self._validate_ingestion_owner(owner_run_id)
        self._validate_claim_token(claim_token)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE gmail_message_ingestions
                SET lease_expires_at = ?, updated_at = CURRENT_TIMESTAMP
                WHERE ingestion_key = ? AND owner_run_id = ?
                  AND status = 'processing' AND claim_token = ?
                """,
                (
                    (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                    ingestion_key,
                    owner_run_id,
                    claim_token,
                ),
            )
            return cursor.rowcount == 1

    @staticmethod
    def _gmail_ingestion_key(
        *,
        connected_account_id: str,
        thread_id: str,
        message_id: str,
    ) -> str:
        identities = (connected_account_id, thread_id, message_id)
        if any(
            not isinstance(value, str)
            or not value
            or len(value) > 1_000
            or any(character in value for character in "\r\n\x00")
            for value in identities
        ):
            raise ValueError("Gmail ingestion identifiers must be bounded and non-empty")
        source = "\x00".join(("gmail-outreach-v1", *identities)).encode("utf-8")
        return hashlib.sha256(source).hexdigest()

    @staticmethod
    def _validate_ingestion_owner(owner_run_id: str) -> None:
        if (
            not isinstance(owner_run_id, str)
            or not owner_run_id
            or len(owner_run_id) > 200
            or any(character in owner_run_id for character in "\r\n\x00")
        ):
            raise ValueError("owner_run_id must be a bounded opaque identifier")

    @staticmethod
    def _validate_claim_token(claim_token: str) -> None:
        if (
            not isinstance(claim_token, str)
            or not (20 <= len(claim_token) <= 200)
            or re.fullmatch(r"[A-Za-z0-9_-]+", claim_token) is None
        ):
            raise ValueError("claim_token is invalid")

    @classmethod
    def _validate_gmail_ingestion_input(
        cls,
        *,
        owner_run_id: str,
        app_slug: str,
        credentials: Sequence[tuple[str, str]],
        lease_seconds: int,
    ) -> None:
        cls._validate_ingestion_owner(owner_run_id)
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        if not 30 <= lease_seconds <= 3_600:
            raise ValueError("Gmail ingestion lease must be between 30 and 3600 seconds")
        if len(credentials) > 25:
            raise ValueError("too many credentials in one Gmail message")
        for kind, value in credentials:
            if _KIND.fullmatch(kind) is None:
                raise ValueError("email credential kind is invalid")
            if not isinstance(value, str) or not value or len(value) > 16_384:
                raise ValueError("email credential value is invalid")

    def _insert_email_credentials(
        self,
        connection: sqlite3.Connection,
        *,
        app_slug: str,
        credentials: Sequence[tuple[str, str]],
    ) -> dict[str, str]:
        credential_refs: dict[str, str] = {}
        counts: dict[str, int] = {}
        seen_values: set[str] = set()
        for kind, value in credentials:
            if value in seen_values:
                continue
            seen_values.add(value)
            counts[kind] = counts.get(kind, 0) + 1
            suffix = "" if counts[kind] == 1 else f"_{counts[kind]}"
            field_name = f"email_{kind}{suffix}"
            identifier = secrets.token_urlsafe(18)
            ciphertext = self._fernet.encrypt(value.encode("utf-8"))
            connection.execute(
                """
                INSERT INTO vault_entries (id, app_slug, kind, ciphertext)
                VALUES (?, ?, ?, ?)
                """,
                (identifier, app_slug, kind, ciphertext),
            )
            credential_refs[field_name] = f"vault://{app_slug}/{kind}/{identifier}"
        return credential_refs

    @staticmethod
    def _lease_expired(value: object, *, now: datetime) -> bool:
        if not isinstance(value, str):
            return True
        try:
            expiry = datetime.fromisoformat(value)
        except ValueError:
            return True
        return expiry.tzinfo is None or now >= expiry

    @staticmethod
    def _decode_credential_refs(
        value: object,
        *,
        expected_app_slug: str,
    ) -> dict[str, str]:
        if not isinstance(value, str):
            raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid")
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid") from None
        if not isinstance(decoded, Mapping):
            raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid")
        result: dict[str, str] = {}
        for key, reference in decoded.items():
            if (
                not isinstance(key, str)
                or _KIND.fullmatch(key) is None
                or not isinstance(reference, str)
            ):
                raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid")
            try:
                parts = parse_vault_reference(reference)
            except ValueError:
                raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid") from None
            if parts.app_slug != expected_app_slug:
                raise GmailMessageIngestionStateError("gmail_ingestion_state_invalid")
            result[key] = reference
        return result

    def put_account_login(self, *, app_slug: str, account_ref: str, field: str, value: str) -> str:
        """Store (or replace) one reusable login secret for one bound account.

        Autonomous sign-in needs the owner's app credentials to survive a single
        run: every other login path here is one-time and run-scoped, so a second
        run could never authenticate itself and always stopped at a human gate.

        Deliberately narrow so this cannot become a general secret-reading API:
        only ``login_*`` fields are accepted, the row is stored under a distinct
        ``account_login_`` kind (never the same namespace as a captured
        integration credential), and it is addressable only by
        ``(app, account_ref, field)``. A second signup for the same app therefore
        cannot overwrite an in-flight run's identity or another account's login.
        """

        kind = _account_login_kind(field)
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        if _ACCOUNT_REF.fullmatch(account_ref) is None:
            raise ValueError("account_ref must be an opaque browser account binding")

        identifier = secrets.token_urlsafe(18)
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._connect() as connection:
            # Replace, so exactly one current credential exists per account/field
            # and a rotated password can never be shadowed by a stale row.
            connection.execute(
                """
                DELETE FROM vault_entries
                WHERE app_slug = ? AND kind = ? AND account_ref = ?
                """,
                (app_slug, kind, account_ref),
            )
            connection.execute(
                """
                INSERT INTO vault_entries
                    (id, app_slug, kind, ciphertext, account_ref)
                VALUES (?, ?, ?, ?, ?)
                """,
                (identifier, app_slug, kind, ciphertext, account_ref),
            )
        return f"vault://{app_slug}/{kind}/{identifier}"

    def put_account_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        email: str,
        password: str,
    ) -> tuple[str, str]:
        """Atomically replace one complete reusable email/password pair.

        A pair is the minimum useful login unit.  Writing the two rows in one
        ``BEGIN IMMEDIATE`` transaction prevents a reader from observing a new
        email with an old password (or either half of a failed write).
        """

        self._validate_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=None,
            email=email,
            password=password,
        )
        rows = self._encrypted_login_pair(app_slug=app_slug, email=email, password=password)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._replace_account_login_pair(
                connection,
                app_slug=app_slug,
                account_ref=account_ref,
                rows=rows,
            )
        return tuple(row[4] for row in rows)  # type: ignore[return-value]

    def stage_existing_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
        email: str,
        password: str,
    ) -> dict[str, str]:
        """Encrypt one owner-supplied pair under its run without touching reuse state.

        A corrected submission may replace a still-pending pair for the SAME run.
        Once promoted, the stage is immutable. In every case the account-scoped
        known-good pair remains unchanged until
        :meth:`promote_staged_existing_login_pair` runs after positive browser
        authentication evidence.
        """

        self._validate_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
            email=email,
            password=password,
        )
        email_ciphertext = self._fernet.encrypt(email.encode("utf-8"))
        password_ciphertext = self._fernet.encrypt(password.encode("utf-8"))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT app_slug, account_ref, status,
                       email_ciphertext, password_ciphertext
                FROM staged_existing_logins
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if existing is not None:
                stored_app, stored_account, status, stored_email, stored_password = existing
                if str(stored_app) != app_slug or str(stored_account) != account_ref:
                    raise AccountLoginStateError("existing_login_stage_binding_mismatch")
                if str(status) == "promoted":
                    return self._decrypt_existing_pair(stored_email, stored_password)
                connection.execute(
                    """
                    UPDATE staged_existing_logins
                    SET email_ciphertext = ?, password_ciphertext = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                      AND status = 'pending'
                    """,
                    (
                        email_ciphertext,
                        password_ciphertext,
                        run_id,
                        app_slug,
                        account_ref,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO staged_existing_logins (
                        run_id, app_slug, account_ref, email_ciphertext,
                        password_ciphertext, status
                    ) VALUES (?, ?, ?, ?, ?, 'pending')
                    """,
                    (
                        run_id,
                        app_slug,
                        account_ref,
                        email_ciphertext,
                        password_ciphertext,
                    ),
                )
        return {"login_email": email, "login_password": password}

    def get_staged_existing_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, str]:
        """Load one exact run's pending/promoted existing-account pair."""

        if (
            _APP_SLUG.fullmatch(app_slug) is None
            or _ACCOUNT_REF.fullmatch(account_ref) is None
            or _ACCOUNT_REF.fullmatch(run_id) is None
        ):
            return {}
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT email_ciphertext, password_ciphertext
                FROM staged_existing_logins
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            ).fetchone()
        if row is None:
            return {}
        try:
            return self._decrypt_existing_pair(row[0], row[1])
        except AccountLoginStateError:
            return {}

    def promote_staged_existing_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> tuple[str, ...]:
        """Atomically make this run's authenticated pair reusable.

        An absent stage is a normal no-op: the run may have used an already
        reusable pair or no credentials at all. A present pair replaces the
        durable pair and is marked promoted in the same transaction, so a crash
        can expose neither half of a credential rotation.
        """

        self._validate_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
            email="validation@example.invalid",
            password="validation-only",  # pragma: allowlist secret
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT email_ciphertext, password_ciphertext
                FROM staged_existing_logins
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            ).fetchone()
            if row is None:
                return ()
            encrypted_rows = self._encrypted_login_pair_from_ciphertexts(
                app_slug=app_slug,
                email_ciphertext=bytes(row[0]),
                password_ciphertext=bytes(row[1]),
            )
            self._replace_account_login_pair(
                connection,
                app_slug=app_slug,
                account_ref=account_ref,
                rows=encrypted_rows,
            )
            connection.execute(
                """
                UPDATE staged_existing_logins
                SET status = 'promoted',
                    promoted_at = COALESCE(promoted_at, CURRENT_TIMESTAMP),
                    updated_at = CURRENT_TIMESTAMP
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            )
        return tuple(sorted(REUSABLE_LOGIN_FIELDS))

    def get_unique_account_login_pair(
        self,
        *,
        app_slug: str,
    ) -> tuple[str, dict[str, str]] | None:
        """Select the sole complete reusable account for an app.

        This is the backwards-compatible path for a later run whose request
        contains no raw login identity. It returns a pair only when selection is
        exact. More than one complete account is a typed ambiguity; the caller
        must ask the owner instead of guessing which identity to authenticate.
        """

        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        kinds = tuple(_account_login_kind(field) for field in sorted(REUSABLE_LOGIN_FIELDS))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT account_ref, kind, ciphertext
                FROM vault_entries
                WHERE app_slug = ? AND account_ref IS NOT NULL AND one_time = 0
                  AND kind IN (?, ?)
                ORDER BY account_ref, kind
                """,
                (app_slug, *kinds),
            ).fetchall()
        grouped: dict[str, dict[str, bytes]] = {}
        for account_ref, kind, ciphertext in rows:
            account = str(account_ref)
            if _ACCOUNT_REF.fullmatch(account) is None:
                continue
            grouped.setdefault(account, {})[str(kind)] = bytes(ciphertext)
        complete = {
            account: encrypted
            for account, encrypted in grouped.items()
            if set(encrypted) == set(kinds)
        }
        if not complete:
            return None
        if len(complete) != 1:
            raise AccountLoginStateError("stored_login_account_ambiguous")
        account_ref, encrypted = next(iter(complete.items()))
        values: dict[str, str] = {}
        try:
            for field in sorted(REUSABLE_LOGIN_FIELDS):
                values[field] = self._fernet.decrypt(encrypted[_account_login_kind(field)]).decode(
                    "utf-8"
                )
        except (InvalidToken, UnicodeDecodeError):
            raise AccountLoginStateError("stored_login_account_unreadable") from None
        return account_ref, values

    def stage_signup_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
        email: str,
        password: str,
    ) -> dict[str, str]:
        """Atomically stage generated signup credentials under one run.

        The unique ``(app_slug, account_ref)`` constraint serializes every
        process that tries to create the same app/mailbox identity. Replaying the
        same run returns its original encrypted pair; another run fails with a
        stable, value-free reason instead of replacing an in-flight or already
        promoted login.
        """

        self._validate_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
            email=email,
            password=password,
        )
        email_ciphertext = self._fernet.encrypt(email.encode("utf-8"))
        password_ciphertext = self._fernet.encrypt(password.encode("utf-8"))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT run_id, status, email_ciphertext, password_ciphertext
                FROM staged_signup_logins
                WHERE app_slug = ? AND account_ref = ?
                """,
                (app_slug, account_ref),
            ).fetchone()
            if existing is not None:
                owner_run, status, stored_email, stored_password = existing
                if str(owner_run) != run_id:
                    reason = (
                        "signup_identity_already_registered"
                        if str(status) == "promoted"
                        else "signup_identity_in_progress"
                    )
                    raise SignupCredentialStateError(reason)
                return self._decrypt_signup_pair(stored_email, stored_password)
            connection.execute(
                """
                INSERT INTO staged_signup_logins (
                    run_id, app_slug, account_ref, email_ciphertext,
                    password_ciphertext, status
                ) VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (
                    run_id,
                    app_slug,
                    account_ref,
                    email_ciphertext,
                    password_ciphertext,
                ),
            )
        return {"login_email": email, "login_password": password}

    def get_staged_signup_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> dict[str, str]:
        """Load one exact run's staged pair, or return an empty mapping."""

        if (
            _APP_SLUG.fullmatch(app_slug) is None
            or _ACCOUNT_REF.fullmatch(account_ref) is None
            or _ACCOUNT_REF.fullmatch(run_id) is None
        ):
            return {}
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT email_ciphertext, password_ciphertext
                FROM staged_signup_logins
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            ).fetchone()
        if row is None:
            return {}
        try:
            return self._decrypt_signup_pair(row[0], row[1])
        except SignupCredentialStateError:
            return {}

    def promote_staged_signup_login_pair(
        self,
        *,
        app_slug: str,
        account_ref: str,
        run_id: str,
    ) -> tuple[str, ...]:
        """Atomically promote a successful signup pair into account scope.

        This method is deliberately separate from staging so a failed or
        interrupted signup can never overwrite a known-good reusable login.
        Promotion is idempotent: after an observed authenticated success, a
        crash/retry repairs a missing durable pair from the retained encrypted
        staged values and returns the same field-name outcome.
        """

        self._validate_account_login_pair(
            app_slug=app_slug,
            account_ref=account_ref,
            run_id=run_id,
            email="validation@example.invalid",
            password="validation-only",  # pragma: allowlist secret
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT email_ciphertext, password_ciphertext
                FROM staged_signup_logins
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            ).fetchone()
            if row is None:
                raise SignupCredentialStateError("signup_login_stage_missing")
            encrypted_rows = self._encrypted_login_pair_from_ciphertexts(
                app_slug=app_slug,
                email_ciphertext=bytes(row[0]),
                password_ciphertext=bytes(row[1]),
            )
            self._replace_account_login_pair(
                connection,
                app_slug=app_slug,
                account_ref=account_ref,
                rows=encrypted_rows,
            )
            connection.execute(
                """
                UPDATE staged_signup_logins
                SET status = 'promoted', promoted_at = COALESCE(promoted_at, CURRENT_TIMESTAMP)
                WHERE run_id = ? AND app_slug = ? AND account_ref = ?
                """,
                (run_id, app_slug, account_ref),
            )
        return tuple(sorted(REUSABLE_LOGIN_FIELDS))

    def get_account_login(self, *, app_slug: str, account_ref: str, field: str) -> str | None:
        """Return a stored reusable login value, or None when none is stored.

        Returns None (never raises) for the absent case: "no stored credential"
        is a normal autonomous-run condition, not an error. A row that cannot be
        decrypted with the ACTIVE key is also None, so a rotated vault key
        degrades to "log in again" instead of crashing a run.
        """

        kind = _account_login_kind(field)
        if _APP_SLUG.fullmatch(app_slug) is None or _ACCOUNT_REF.fullmatch(account_ref) is None:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT ciphertext
                FROM vault_entries
                WHERE app_slug = ? AND kind = ? AND account_ref = ? AND one_time = 0
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (app_slug, kind, account_ref),
            ).fetchone()
        if row is None:
            return None
        try:
            return self._fernet.decrypt(bytes(row[0])).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            return None

    def get_account_login_pair(self, *, app_slug: str, account_ref: str) -> dict[str, str]:
        """Read one complete reusable pair from a single SQLite snapshot."""

        if _APP_SLUG.fullmatch(app_slug) is None or _ACCOUNT_REF.fullmatch(account_ref) is None:
            return {}
        kinds = tuple(_account_login_kind(field) for field in sorted(REUSABLE_LOGIN_FIELDS))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT kind, ciphertext
                FROM vault_entries
                WHERE app_slug = ? AND account_ref = ? AND one_time = 0
                  AND kind IN (?, ?)
                """,
                (app_slug, account_ref, *kinds),
            ).fetchall()
        encrypted = {str(kind): bytes(ciphertext) for kind, ciphertext in rows}
        if set(encrypted) != set(kinds):
            return {}
        values: dict[str, str] = {}
        try:
            for field in sorted(REUSABLE_LOGIN_FIELDS):
                values[field] = self._fernet.decrypt(encrypted[_account_login_kind(field)]).decode(
                    "utf-8"
                )
        except (InvalidToken, UnicodeDecodeError):
            return {}
        return values

    def delete_account_login(self, *, app_slug: str, account_ref: str, field: str) -> None:
        """Forget a stored reusable login secret (idempotent)."""

        kind = _account_login_kind(field)
        if _APP_SLUG.fullmatch(app_slug) is None or _ACCOUNT_REF.fullmatch(account_ref) is None:
            return
        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM vault_entries
                WHERE app_slug = ? AND kind = ? AND account_ref = ?
                """,
                (app_slug, kind, account_ref),
            )

    @staticmethod
    def _validate_account_login_pair(
        *,
        app_slug: str,
        account_ref: str,
        run_id: str | None,
        email: str,
        password: str,
    ) -> None:
        if _APP_SLUG.fullmatch(app_slug) is None:
            raise ValueError("app_slug must contain lowercase letters, digits, or hyphens")
        if _ACCOUNT_REF.fullmatch(account_ref) is None:
            raise ValueError("account_ref must be an opaque browser account binding")
        if run_id is not None and _ACCOUNT_REF.fullmatch(run_id) is None:
            raise ValueError("run_id must be an opaque run identifier")
        if not isinstance(email, str) or not email:
            raise ValueError("login email must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise ValueError("login password must be a non-empty string")

    def _encrypted_login_pair(
        self,
        *,
        app_slug: str,
        email: str,
        password: str,
    ) -> tuple[tuple[str, str, str, bytes, str], tuple[str, str, str, bytes, str]]:
        return self._encrypted_login_pair_from_ciphertexts(
            app_slug=app_slug,
            email_ciphertext=self._fernet.encrypt(email.encode("utf-8")),
            password_ciphertext=self._fernet.encrypt(password.encode("utf-8")),
        )

    @staticmethod
    def _encrypted_login_pair_from_ciphertexts(
        *,
        app_slug: str,
        email_ciphertext: bytes,
        password_ciphertext: bytes,
    ) -> tuple[tuple[str, str, str, bytes, str], tuple[str, str, str, bytes, str]]:
        rows = []
        for field, ciphertext in (
            ("login_email", email_ciphertext),
            ("login_password", password_ciphertext),
        ):
            identifier = secrets.token_urlsafe(18)
            kind = _account_login_kind(field)
            reference = f"vault://{app_slug}/{kind}/{identifier}"
            rows.append((identifier, app_slug, kind, ciphertext, reference))
        return (rows[0], rows[1])

    @staticmethod
    def _replace_account_login_pair(
        connection: sqlite3.Connection,
        *,
        app_slug: str,
        account_ref: str,
        rows: tuple[
            tuple[str, str, str, bytes, str],
            tuple[str, str, str, bytes, str],
        ],
    ) -> None:
        kinds = tuple(_account_login_kind(field) for field in sorted(REUSABLE_LOGIN_FIELDS))
        connection.execute(
            """
            DELETE FROM vault_entries
            WHERE app_slug = ? AND account_ref = ? AND kind IN (?, ?)
            """,
            (app_slug, account_ref, *kinds),
        )
        connection.executemany(
            """
            INSERT INTO vault_entries (id, app_slug, kind, ciphertext, account_ref)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (identifier, row_app_slug, kind, ciphertext, account_ref)
                for identifier, row_app_slug, kind, ciphertext, _reference in rows
            ],
        )

    def _decrypt_signup_pair(
        self,
        email_ciphertext: bytes,
        password_ciphertext: bytes,
    ) -> dict[str, str]:
        try:
            return {
                "login_email": self._fernet.decrypt(bytes(email_ciphertext)).decode("utf-8"),
                "login_password": self._fernet.decrypt(bytes(password_ciphertext)).decode("utf-8"),
            }
        except (InvalidToken, UnicodeDecodeError, TypeError):
            raise SignupCredentialStateError("signup_login_stage_unreadable") from None

    def _decrypt_existing_pair(
        self,
        email_ciphertext: bytes,
        password_ciphertext: bytes,
    ) -> dict[str, str]:
        try:
            return {
                "login_email": self._fernet.decrypt(bytes(email_ciphertext)).decode("utf-8"),
                "login_password": self._fernet.decrypt(bytes(password_ciphertext)).decode("utf-8"),
            }
        except (InvalidToken, UnicodeDecodeError, TypeError):
            raise AccountLoginStateError("existing_login_stage_unreadable") from None

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

    def delete_transient(
        self,
        reference: str,
        *,
        expected_app_slug: str,
        expected_kind: str,
        expected_scope_id: str,
    ) -> None:
        """Discard an unconsumed transient through its complete binding.

        This exists for pre-dispatch rollback when storing a multi-field browser
        login fails partway through.  The generic durable ``delete`` method is
        deliberately unable to revoke a one-time row using only its bearer
        reference.
        """

        parts = parse_vault_reference(reference)
        if parts.app_slug != expected_app_slug or parts.kind != expected_kind:
            raise TransientSecretError("browser_secret_not_found")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ?
                  AND scope_id = ? AND one_time = 1 AND consumed_at IS NULL
                """,
                (
                    parts.identifier,
                    expected_app_slug,
                    expected_kind,
                    expected_scope_id,
                ),
            )
        if cursor.rowcount != 1:
            raise TransientSecretError("browser_secret_not_found")

    @staticmethod
    def _is_expired(expires_at: object) -> bool:
        if not isinstance(expires_at, str) or not expires_at:
            return True  # a transient row without an expiry is treated as expired
        try:
            return datetime.now(UTC) >= datetime.fromisoformat(expires_at)
        except ValueError:
            return True

    def get(self, reference: str) -> str:
        """Read a durable secret through an exact reference.

        One-time browser secrets must only cross the scope-bound
        ``consume_transient*`` paths.  Treating them as absent here prevents a
        caller that learns a transient reference from bypassing its scope,
        expiry, and single-consumer checks through the generic durable reader.
        """

        app_slug, kind, identifier = self._parse_reference(reference)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT ciphertext
                FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ? AND one_time = 0
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
        """Delete one durable secret; transient rows require full scope binding."""

        app_slug, kind, identifier = self._parse_reference(reference)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM vault_entries
                WHERE id = ? AND app_slug = ? AND kind = ? AND one_time = 0
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
