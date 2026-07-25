from __future__ import annotations

import stat

import pytest
from cryptography.fernet import Fernet

from ops.secret_store import (
    SecretDecryptionError,
    SecretNotFoundError,
    SQLiteSecretStore,
)


def permissions(path: object) -> int:
    return stat.S_IMODE(path.stat().st_mode)  # type: ignore[union-attr]


def test_vault_encrypts_round_trips_and_uses_owner_only_permissions(tmp_path) -> None:
    db_path = tmp_path / "vault-private" / "secrets.db"
    store = SQLiteSecretStore(db_path, Fernet.generate_key())
    plaintext = "fixture-credential-value-never-store-raw"

    reference = store.put(
        app_slug="example-app",
        kind="client_secret",
        value=plaintext,
    )

    assert reference.startswith("vault://example-app/client_secret/")
    assert store.get(reference) == plaintext
    assert plaintext.encode() not in db_path.read_bytes()
    assert permissions(db_path.parent) == 0o700
    assert permissions(db_path) == 0o600


def test_wrong_key_cannot_decrypt_existing_ciphertext(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    first = SQLiteSecretStore(db_path, Fernet.generate_key())
    reference = first.put(
        app_slug="example",
        kind="access_token",
        value="wrong-key-test-credential",
    )
    second = SQLiteSecretStore(db_path, Fernet.generate_key())

    with pytest.raises(SecretDecryptionError, match="could not be decrypted"):
        second.get(reference)


def test_delete_requires_an_exact_reference_and_is_effective(tmp_path) -> None:
    store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())
    reference = store.put(app_slug="example", kind="api_key", value="delete-me")

    with pytest.raises(ValueError, match="exact vault"):
        store.get(reference + "/suffix")

    store.delete(reference)
    with pytest.raises(SecretNotFoundError):
        store.get(reference)
    with pytest.raises(SecretNotFoundError):
        store.delete(reference)


def test_vault_exposes_no_enumeration_method(tmp_path) -> None:
    store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())

    assert not any(name.startswith("list") for name in dir(store))


def test_vault_rejects_existing_permissive_parent_without_mutating_it(tmp_path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)
    db_path = parent / "vault.db"

    with pytest.raises(PermissionError, match="group or other"):
        SQLiteSecretStore(db_path, Fernet.generate_key())

    assert permissions(parent) == 0o755
    assert not db_path.exists()


def test_vault_rejects_symlink_database_without_following_it(tmp_path) -> None:
    target = tmp_path / "target.db"
    target.write_text("do not mutate", encoding="utf-8")
    target.chmod(0o600)
    db_path = tmp_path / "vault.db"
    db_path.symlink_to(target)

    with pytest.raises(PermissionError, match="regular file"):
        SQLiteSecretStore(db_path, Fernet.generate_key())

    assert target.read_text(encoding="utf-8") == "do not mutate"
    assert db_path.is_symlink()


# ============================================ P0-4: transient one-time secrets
class TestTransientSecrets:
    """One-time, scope-bound, expiring references for browser-login credentials."""

    @staticmethod
    def _store(tmp_path: object) -> SQLiteSecretStore:
        return SQLiteSecretStore(tmp_path / "vault" / "secrets.db", Fernet.generate_key())  # type: ignore[operator]

    def test_consume_once_returns_value_then_is_gone(self, tmp_path) -> None:
        from ops.secret_store import TransientSecretError

        store = self._store(tmp_path)
        ref = store.put_transient(
            app_slug="pipedrive",
            kind="browser_login_login_password",
            scope_id="run-123",
            value="s3cret-value",
        )
        got = store.consume_transient(
            ref,
            expected_app_slug="pipedrive",
            expected_kind="browser_login_login_password",
            expected_scope_id="run-123",
        )
        assert got == "s3cret-value"
        # A second consume must fail: the row was deleted.
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="pipedrive",
                expected_kind="browser_login_login_password",
                expected_scope_id="run-123",
            )
        assert excinfo.value.reason_code == "browser_secret_not_found"

    def test_wrong_app_is_refused(self, tmp_path) -> None:
        from ops.secret_store import TransientSecretError

        store = self._store(tmp_path)
        ref = store.put_transient(
            app_slug="pipedrive", kind="browser_login_login_email", scope_id="r", value="v"
        )
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="hubspot",
                expected_kind="browser_login_login_email",
                expected_scope_id="r",
            )
        assert excinfo.value.reason_code == "browser_secret_app_mismatch"

    def test_wrong_kind_is_refused(self, tmp_path) -> None:
        from ops.secret_store import TransientSecretError

        store = self._store(tmp_path)
        ref = store.put_transient(
            app_slug="pipedrive", kind="browser_login_login_email", scope_id="r", value="v"
        )
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="pipedrive",
                expected_kind="browser_login_login_password",
                expected_scope_id="r",
            )
        assert excinfo.value.reason_code == "browser_secret_kind_mismatch"

    def test_wrong_scope_is_refused(self, tmp_path) -> None:
        from ops.secret_store import TransientSecretError

        store = self._store(tmp_path)
        ref = store.put_transient(
            app_slug="pipedrive", kind="browser_login_login_email", scope_id="run-A", value="v"
        )
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="pipedrive",
                expected_kind="browser_login_login_email",
                expected_scope_id="run-B",
            )
        assert excinfo.value.reason_code == "browser_secret_scope_mismatch"

    def test_expired_reference_is_refused(self, tmp_path) -> None:
        import sqlite3
        from datetime import UTC, datetime, timedelta

        from ops.secret_store import TransientSecretError, parse_vault_reference

        store = self._store(tmp_path)
        ref = store.put_transient(
            app_slug="pipedrive", kind="browser_login_login_otp", scope_id="r", value="483920"
        )
        # Force the row's expiry into the past.
        parts = parse_vault_reference(ref)
        past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        connection = sqlite3.connect(store.db_path)
        try:
            connection.execute(
                "UPDATE vault_entries SET expires_at = ? WHERE id = ?", (past, parts.identifier)
            )
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="pipedrive",
                expected_kind="browser_login_login_otp",
                expected_scope_id="r",
            )
        assert excinfo.value.reason_code == "browser_secret_expired"

    def test_permanent_entry_cannot_be_consumed_as_transient(self, tmp_path) -> None:
        from ops.secret_store import TransientSecretError

        store = self._store(tmp_path)
        # A normal permanent put (one_time=0) must not be consumable one-time.
        ref = store.put(app_slug="pipedrive", kind="api_token", value="tok")
        with pytest.raises(TransientSecretError) as excinfo:
            store.consume_transient(
                ref,
                expected_app_slug="pipedrive",
                expected_kind="api_token",
                expected_scope_id="whatever",
            )
        assert excinfo.value.reason_code == "browser_secret_scope_mismatch"

    def test_ttl_bounds_are_enforced(self, tmp_path) -> None:
        store = self._store(tmp_path)
        for bad in (10, 3_600):
            with pytest.raises(ValueError, match="ttl"):
                store.put_transient(
                    app_slug="pipedrive",
                    kind="browser_login_login_email",
                    scope_id="r",
                    value="v",
                    ttl_seconds=bad,
                )

    def test_migration_is_idempotent_and_preserves_permanent_entries(self, tmp_path) -> None:
        db = tmp_path / "vault" / "secrets.db"
        key = Fernet.generate_key()
        first = SQLiteSecretStore(db, key)
        ref = first.put(app_slug="pipedrive", kind="api_token", value="keep-me")
        # Re-open (re-runs initialize/migration); the permanent entry survives.
        second = SQLiteSecretStore(db, key)
        assert second.get(ref) == "keep-me"

    def test_parse_vault_reference_is_the_shared_parser(self) -> None:
        from ops.secret_store import parse_vault_reference

        parts = parse_vault_reference("vault://pipedrive/browser_login_login_email/abc123")
        assert parts.app_slug == "pipedrive"
        assert parts.kind == "browser_login_login_email"
        with pytest.raises(ValueError, match="exact vault reference"):
            parse_vault_reference("not a reference")
