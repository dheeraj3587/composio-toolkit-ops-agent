from __future__ import annotations

from ops.redaction import REDACTED, redact_data
from ops.run_service import _public_run
from ops.storage import OperationsStorage


def test_canonical_credential_policy_is_public_metadata() -> None:
    payload = {
        "credential_policy": "reuse_existing",
        "credential_creation_policy": "reuse_only",
        "client_secret": "must-not-survive",  # pragma: allowlist secret
    }

    sanitized = redact_data(payload)

    assert sanitized["credential_policy"] == "reuse_existing"
    assert sanitized["credential_creation_policy"] == "reuse_only"
    assert sanitized["client_secret"] == REDACTED


def test_public_run_keeps_canonical_and_legacy_policy_names() -> None:
    projected = _public_run(
        {
            "run_id": "run_policy_regression",
            "thread_id": "local_policy_regression",
            "app_name": "Example",
            "app_slug": "example",
            "status": "route_selected",
            "access_route": "self_serve",
            "created_at": "2026-07-27T00:00:00Z",
            "updated_at": "2026-07-27T00:00:00Z",
            "execution_mode": "local_dry_run",
            "browser_provider": "playwright",
            "account_policy": "reuse_existing",
            "developer_app_policy": "reuse_existing",
            "credential_policy": "reuse_existing",
            "credential_creation_policy": "reuse_only",
            "external_actions": False,
        }
    )

    assert projected["credential_policy"] == "reuse_existing"
    assert projected["credential_creation_policy"] == "reuse_only"


def test_storage_round_trip_does_not_put_legacy_value_in_canonical_column(tmp_path) -> None:
    storage = OperationsStorage(tmp_path / "private" / "ops.db")

    created = storage.create_run(
        run_id="run_policy_storage",
        thread_id="local_policy_storage",
        app_name="Example",
        app_slug="example",
        account_policy="reuse_existing",
        developer_app_policy="reuse_existing",
        credential_policy="reuse_existing",
        credential_creation_policy="reuse_only",
    )

    assert created["credential_policy"] == "reuse_existing"
    assert created["credential_creation_policy"] == "reuse_only"
    assert storage.get_run("run_policy_storage") == created
