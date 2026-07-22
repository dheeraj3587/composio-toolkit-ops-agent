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
