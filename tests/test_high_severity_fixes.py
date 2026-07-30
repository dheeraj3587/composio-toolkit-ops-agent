"""Regression tests for the high-severity production fixes (H1, H2, H7, H10)."""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import SecretStr

from api.models import SecurityState
from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.core.secret_store import SQLiteSecretStore
from ops.runs.service import RunService


def _request(app_name: str = "HubSpot") -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Authorized integration via the provider developer API.",
        ),
    )


# ---- H2: Browser Use cost cap defaults high (not $1) -------------------------
def test_browser_cost_cap_defaults_high() -> None:
    settings = Settings.from_env(env={})
    assert settings.browser_use_max_cost_usd == 50.0


# ---- H10: SecurityState reports the actual state-storage boundary -------------
def test_security_state_reports_ordinary_sqlite_without_checkpoint_readiness() -> None:
    assert "checkpoint_encryption" not in SecurityState.model_fields
    assert "operational_state_storage" in SecurityState.model_fields
    state = SecurityState(owner_only_storage="verified_owner_only")
    assert state.operational_state_storage == "sqlite_not_app_encrypted"


# ---- H1: GmailWorker is wired with the secret store + effect ledger ----------
def test_gmail_worker_is_wired_with_secret_store(tmp_path: Path) -> None:
    settings = Settings(
        composio_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_api_key=SecretStr("test-gmail-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        outreach_recipient_override="controlled@example.test",
        provider_effects_db_path=tmp_path / "effects.db",
    )
    service = RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    service._secret_store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())

    deps = service._build_workflow_dependencies(settings)

    assert deps.gmail is not None
    # Previously the Gmail worker was built without the vault, so a reply carrying
    # a credential raised secret_store_missing and wedged the email path.
    assert deps.gmail._secret_store is service._secret_store
    assert deps.gmail._effect_store is not None


# ---- H7: startup reconciliation recovers stranded browser_running runs -------
def test_reconcile_marks_stranded_browser_run_recoverable(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    run = service.create_run(_request("HubSpot"), execution_mode="plan_only")
    run_id = run["run_id"]

    # A self-serve plan-only run rests at route_selected; move it to
    # browser_running to simulate a run whose navigation thread was killed by a
    # restart, then reconcile.
    service.guarded_status_update(
        run_id, expected_revision=1, next_status="browser_running", command="test"
    )
    assert service.get_run(run_id)["status"] == "browser_running"

    service._reconcile_stranded_runs()

    reconciled = service.get_run(run_id)
    assert reconciled is not None
    assert reconciled["status"] == "configuration_required"
    events = [e["event_type"] for e in service.get_timeline(run_id)]
    assert "run_reconciled_on_startup" in events


def test_reconcile_marks_hitl_without_a_live_provider_session_lost(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    run = service.create_run(_request("HubSpot"), execution_mode="plan_only")
    run_id = run["run_id"]
    service.guarded_status_update(
        run_id, expected_revision=1, next_status="browser_running", command="test"
    )
    service.guarded_status_update(
        run_id, expected_revision=2, next_status="waiting_for_hitl", command="test"
    )

    service._reconcile_stranded_runs()

    # A status token alone is not proof that Chromium survived. With no configured
    # provider and no persisted live session, reconciliation must fail closed.
    reconciled = service.get_run(run_id)
    assert reconciled["status"] == "configuration_required"
    assert reconciled["phase"] == "session_lost"
    assert reconciled["reason_code"] == "provider_unavailable_session_lost"
    assert "run_reconciled_on_startup" in [
        event["event_type"] for event in service.get_timeline(run_id)
    ]
