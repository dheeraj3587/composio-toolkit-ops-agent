"""Idempotent generated account-password provisioning over the encrypted vault."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import string
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ops.private_files import finalize_private_database, prepare_private_database
from ops.secret_store import SecretStore, validate_app_slug

_SAFE_OWNER = frozenset(string.ascii_letters + string.digits + "_-.")
_DEFAULT_SYMBOLS = "!@#$%^&*()-_=+"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    min_length: int = 24
    max_length: int = 64
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    allowed_symbols: str = _DEFAULT_SYMBOLS

    def __post_init__(self) -> None:
        if not 12 <= self.min_length <= self.max_length <= 128:
            raise ValueError("password length policy is invalid")
        if not self.allowed_symbols or len(set(self.allowed_symbols)) != len(self.allowed_symbols):
            raise ValueError("password symbol policy is invalid")
        if any(character.isspace() for character in self.allowed_symbols):
            raise ValueError("password symbols cannot contain whitespace")
        required = sum(
            (self.require_lower, self.require_upper, self.require_digit, self.require_symbol)
        )
        if required > self.min_length:
            raise ValueError("password policy has more requirements than positions")


@dataclass(frozen=True, slots=True)
class SignupAccountBinding:
    owner_ref: str
    app_slug: str
    gmail_account_fingerprint: str
    provider_account_id: str | None = None
    workspace_id: str | None = None

    def __post_init__(self) -> None:
        validate_app_slug(self.app_slug)
        if (
            not self.owner_ref
            or len(self.owner_ref) > 200
            or any(character not in _SAFE_OWNER for character in self.owner_ref)
        ):
            raise ValueError("owner reference is invalid")
        if len(self.gmail_account_fingerprint) != 64 or any(
            character not in string.hexdigits for character in self.gmail_account_fingerprint
        ):
            raise ValueError("Gmail account fingerprint is invalid")
        for value in (self.provider_account_id, self.workspace_id):
            if value is not None and (not value or len(value) > 300 or "\x00" in value):
                raise ValueError("provider account binding is invalid")

    @property
    def binding_id(self) -> str:
        components = (
            "signup-account:v1",
            self.owner_ref,
            self.app_slug,
            self.gmail_account_fingerprint.casefold(),
            self.provider_account_id or "",
            self.workspace_id or "",
        )
        return hashlib.sha256("\0".join(components).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GeneratedAccountPassword:
    app_slug: str
    binding_id: str
    password_ref: str
    status: str
    created_at: str
    verified_at: str | None = None


class SQLiteSignupCredentialRegistry:
    """Secret-free metadata registry; password bytes remain in SecretStore."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        existed = prepare_private_database(self.db_path)
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            finalize_private_database(self.db_path, existed=existed)
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS signup_account_credentials (
                    binding_id TEXT PRIMARY KEY,
                    app_slug TEXT NOT NULL,
                    gmail_account_fingerprint TEXT NOT NULL,
                    password_ref TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    invalidated_at TEXT
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def get(self, binding: SignupAccountBinding) -> GeneratedAccountPassword | None:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            row = connection.execute(
                """
                SELECT app_slug, binding_id, password_ref, status, created_at, verified_at
                FROM signup_account_credentials
                WHERE binding_id = ? AND status IN ('active', 'verified')
                """,
                (binding.binding_id,),
            ).fetchone()
        return _record(row) if row is not None else None

    def put_if_absent(
        self,
        binding: SignupAccountBinding,
        password_ref: str,
    ) -> tuple[GeneratedAccountPassword, bool]:
        self.initialize()
        now = _utc_now()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO signup_account_credentials (
                    binding_id, app_slug, gmail_account_fingerprint,
                    password_ref, status, created_at
                ) VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (
                    binding.binding_id,
                    binding.app_slug,
                    binding.gmail_account_fingerprint.casefold(),
                    password_ref,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT app_slug, binding_id, password_ref, status, created_at, verified_at
                FROM signup_account_credentials WHERE binding_id = ?
                """,
                (binding.binding_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("signup credential registry write failed")
        return _record(row), cursor.rowcount == 1

    def mark_verified(self, binding: SignupAccountBinding, password_ref: str) -> None:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            cursor = connection.execute(
                """
                UPDATE signup_account_credentials
                SET status = 'verified', verified_at = ?
                WHERE binding_id = ? AND password_ref = ? AND status = 'active'
                """,
                (_utc_now(), binding.binding_id, password_ref),
            )
            if cursor.rowcount != 1:
                raise KeyError("active account password binding was not found")
            connection.commit()

    def invalidate(self, binding: SignupAccountBinding, password_ref: str) -> None:
        self.initialize()
        with sqlite3.connect(self.db_path, timeout=10) as connection:
            cursor = connection.execute(
                """
                UPDATE signup_account_credentials
                SET status = 'invalidated', invalidated_at = ?
                WHERE binding_id = ? AND password_ref = ?
                  AND status IN ('active', 'verified')
                """,
                (_utc_now(), binding.binding_id, password_ref),
            )
            if cursor.rowcount != 1:
                raise KeyError("account password binding was not found")
            connection.commit()


class SignupCredentialManager:
    """Generate once per account binding and return only an opaque vault ref."""

    def __init__(
        self,
        secret_store: SecretStore,
        registry: SQLiteSignupCredentialRegistry,
    ) -> None:
        self._secret_store = secret_store
        self._registry = registry

    def generate_account_password(
        self,
        binding: SignupAccountBinding,
        policy: PasswordPolicy | None = None,
    ) -> GeneratedAccountPassword:
        existing = self._registry.get(binding)
        if existing is not None:
            # Prove the reference still resolves before reusing its metadata.
            self._secret_store.get(existing.password_ref)
            return existing

        raw = _generate_password(policy or PasswordPolicy())
        reference: str | None = None
        try:
            reference = self._secret_store.put(
                app_slug=binding.app_slug,
                kind="account_password",
                value=raw,
            )
            record, inserted = self._registry.put_if_absent(binding, reference)
            if not inserted and record.password_ref != reference:
                # A concurrent writer won. Delete our compensated vault entry
                # and use the already-registered reference.
                self._secret_store.delete(reference)
                self._secret_store.get(record.password_ref)
            return record
        except Exception:
            if reference is not None:
                try:
                    self._secret_store.delete(reference)
                except Exception:
                    pass
            raise
        finally:
            raw = ""  # drop the only plaintext binding immediately

    def get_account_password_reference(self, binding: SignupAccountBinding) -> str | None:
        record = self._registry.get(binding)
        if record is None:
            return None
        self._secret_store.get(record.password_ref)
        return record.password_ref

    def mark_account_password_verified(
        self,
        binding: SignupAccountBinding,
        password_ref: str,
    ) -> None:
        self._secret_store.get(password_ref)
        self._registry.mark_verified(binding, password_ref)

    def invalidate_account_password(
        self,
        binding: SignupAccountBinding,
        password_ref: str,
    ) -> None:
        self._registry.invalidate(binding, password_ref)
        self._secret_store.delete(password_ref)


def _record(row: tuple[object, ...]) -> GeneratedAccountPassword:
    return GeneratedAccountPassword(
        app_slug=str(row[0]),
        binding_id=str(row[1]),
        password_ref=str(row[2]),
        status=str(row[3]),
        created_at=str(row[4]),
        verified_at=str(row[5]) if row[5] is not None else None,
    )


def _generate_password(policy: PasswordPolicy) -> str:
    pools: list[str] = []
    required: list[str] = []
    if policy.require_lower:
        pools.append(string.ascii_lowercase)
        required.append(secrets.choice(string.ascii_lowercase))
    if policy.require_upper:
        pools.append(string.ascii_uppercase)
        required.append(secrets.choice(string.ascii_uppercase))
    if policy.require_digit:
        pools.append(string.digits)
        required.append(secrets.choice(string.digits))
    if policy.require_symbol:
        pools.append(policy.allowed_symbols)
        required.append(secrets.choice(policy.allowed_symbols))
    if not pools:
        pools.append(string.ascii_letters + string.digits)
    alphabet = "".join(pools)
    characters = required + [
        secrets.choice(alphabet) for _ in range(policy.min_length - len(required))
    ]
    secrets.SystemRandom().shuffle(characters)
    generated = "".join(characters)
    if len(generated) > policy.max_length:
        raise RuntimeError("generated password exceeded its policy")
    return generated


__all__ = [
    "GeneratedAccountPassword",
    "PasswordPolicy",
    "SQLiteSignupCredentialRegistry",
    "SignupAccountBinding",
    "SignupCredentialManager",
]
