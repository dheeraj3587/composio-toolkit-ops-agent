from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from api.models import CreateRunRequest
from ops.gmail_identity import identity_from_profile
from ops.models import CompanyProfile, OperationsRequest
from ops.secret_store import SQLiteSecretStore
from ops.signup_credentials import (
    SignupAccountBinding,
    SignupCredentialManager,
    SQLiteSignupCredentialRegistry,
)


def company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Authorized integration provisioning",
    )


def test_legacy_domain_policies_normalize() -> None:
    request = OperationsRequest(
        app_name="Pipedrive",
        company=company(),
        account_creation_requested=True,
        credential_creation_policy="reuse_only",
    )
    assert request.account_policy == "create_if_missing"
    assert request.developer_app_policy == "reuse_existing"
    assert request.credential_policy == "reuse_existing"
    assert request.account_creation_requested is True
    assert request.credential_creation_policy == "reuse_only"
    assert "account_creation_requested" not in request.model_dump()


def test_legacy_api_policy_conflict_is_rejected() -> None:
    payload = {
        "app_name": "Pipedrive",
        "company": company().model_dump(mode="json"),
        "account_policy": "reuse_existing",
        "account_creation_requested": True,
    }
    try:
        CreateRunRequest.model_validate(payload)
    except ValueError:
        pass
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("conflicting policy fields were accepted")


def test_gmail_profile_identity_is_stable() -> None:
    first = identity_from_profile(
        {"emailAddress": "User@Example.com"},
        connected_account_id="ca_1",
        composio_user_id="owner_1",
    )
    second = identity_from_profile(
        {"email_address": "user@example.com"},
        connected_account_id="ca_1",
        composio_user_id="owner_1",
    )
    assert first.canonical_email == "user@example.com"
    assert first.account_fingerprint == second.account_fingerprint


def test_generated_password_is_reference_only_and_idempotent(tmp_path: Path) -> None:
    vault = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode())
    registry = SQLiteSignupCredentialRegistry(tmp_path / "signup.db")
    manager = SignupCredentialManager(vault, registry)
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="pipedrive",
        gmail_account_fingerprint="a" * 64,
    )
    first = manager.generate_account_password(binding)
    second = manager.generate_account_password(binding)
    assert first.password_ref == second.password_ref
    assert first.password_ref.startswith("vault://pipedrive/account_password/")
    assert len(vault.get(first.password_ref)) >= 24


def test_policy_changes_request_fingerprint() -> None:
    from ops.run_service import _request_fingerprint

    baseline = OperationsRequest(app_name="Pipedrive", company=company())
    account_create = baseline.model_copy(update={"account_policy": "create_if_missing"})
    app_create = baseline.model_copy(update={"developer_app_policy": "create_if_missing"})
    credential_create = baseline.model_copy(update={"credential_policy": "create_if_missing"})
    fingerprints = {
        _request_fingerprint(item, "plan_only")
        for item in (baseline, account_create, app_create, credential_create)
    }
    assert len(fingerprints) == 4


def test_browser_rpc_policy_contract_accepts_all_three() -> None:
    from browser_service.models import NavigateRequest

    payload = NavigateRequest(
        research={},
        account_policy="create_if_missing",
        developer_app_policy="create_if_missing",
        credential_policy="create_if_missing",
    )
    assert payload.account_policy == "create_if_missing"
    assert payload.developer_app_policy == "create_if_missing"
    assert payload.credential_policy == "create_if_missing"


def test_password_plaintext_is_not_stored_in_registry(tmp_path: Path) -> None:
    import sqlite3

    vault = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key().decode())
    registry_path = tmp_path / "signup.db"
    registry = SQLiteSignupCredentialRegistry(registry_path)
    manager = SignupCredentialManager(vault, registry)
    binding = SignupAccountBinding(
        owner_ref="owner_1",
        app_slug="pipedrive",
        gmail_account_fingerprint="b" * 64,
    )
    generated = manager.generate_account_password(binding)
    raw = vault.get(generated.password_ref)
    with sqlite3.connect(registry_path) as connection:
        row = connection.execute(
            "SELECT password_ref FROM signup_account_credentials WHERE binding_id = ?",
            (binding.binding_id,),
        ).fetchone()
    assert row == (generated.password_ref,)
    assert raw not in registry_path.read_bytes().decode("latin-1")
