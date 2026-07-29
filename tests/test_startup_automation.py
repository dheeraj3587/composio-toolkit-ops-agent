from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from ops.config import Settings
from ops.deploy_acceptance import write_deployment_acceptance_marker
from ops.models import CompanyProfile, OperationsRequest
from ops.run_advance import RunAdvanceService
from ops.run_email import RunEmailService
from ops.run_service import RunService


def _request() -> OperationsRequest:
    return OperationsRequest(
        app_name="HubSpot",
        company=CompanyProfile(
            legal_name="Example Company",
            website="https://example.test",
            work_email_ref="vault://company/work_email/unconfigured",
            use_case="Evaluate the reviewed managed-auth route.",
        ),
    )


def _service(tmp_path: Path, *, enabled: bool) -> RunService:
    settings = Settings(
        ops_startup_automation_enabled=enabled,
        provider_effects_db_path=tmp_path / "provider-effects.db",
    )
    return RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)


def test_startup_automation_setting_is_fail_closed_and_strict() -> None:
    assert Settings.from_env(env={}).ops_startup_automation_enabled is False
    assert (
        Settings.from_env(
            env={"OPS_STARTUP_AUTOMATION_ENABLED": "true"}
        ).ops_startup_automation_enabled
        is True
    )
    with pytest.raises(ValueError, match="boolean environment values"):
        Settings.from_env(env={"OPS_STARTUP_AUTOMATION_ENABLED": "sometimes"})


def test_malformed_vault_key_disables_store_and_validator_without_crash(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    invalid_value = "invalid-vault-value-that-must-never-be-logged"
    settings = Settings(
        secret_vault_key=SecretStr(invalid_value),
        secret_vault_db_path=tmp_path / "vault.db",
        provider_effects_db_path=tmp_path / "provider-effects.db",
    )
    service = RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)

    try:
        service.startup()
    finally:
        service.shutdown()

    wiring = {row["dependency"]: row for row in service.wiring_audit()}
    assert wiring["secret_store"]["configured"] is True
    assert wiring["secret_store"]["runtime_wired"] is False
    assert wiring["credential_validator"]["runtime_wired"] is False
    assert invalid_value not in caplog.text
    assert "SECRET_VAULT_KEY is invalid" in caplog.text


def test_disabled_startup_is_observational_but_new_run_still_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, enabled=False)
    startup_effects: list[str] = []
    monkeypatch.setattr(
        service,
        "_reconcile_stranded_runs",
        lambda: startup_effects.append("reconcile"),
    )
    monkeypatch.setattr(
        service,
        "_start_email_poller",
        lambda: startup_effects.append("poller"),
    )
    monkeypatch.setattr(
        service,
        "_start_autonomous_advancer",
        lambda: startup_effects.append("maintenance"),
    )

    try:
        service.startup()
        run = service.create_run(_request(), execution_mode="plan_only")
    finally:
        service.shutdown()

    assert startup_effects == []
    assert run["status"] == "route_selected"
    assert run["route_kind"] == "managed_auth"
    startup_wiring = next(
        row for row in service.wiring_audit() if row["dependency"] == "startup_automation"
    )
    assert startup_wiring["configured"] is False
    assert startup_wiring["runtime_wired"] is False


def test_enabled_startup_starts_delayed_maintenance_without_inline_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, enabled=True)
    startup_effects: list[str] = []
    monkeypatch.setattr(
        service,
        "_reconcile_stranded_runs",
        lambda: startup_effects.append("reconcile"),
    )
    monkeypatch.setattr(
        service,
        "_start_email_poller",
        lambda: startup_effects.append("poller"),
    )
    monkeypatch.setattr(
        service,
        "_start_autonomous_advancer",
        lambda: startup_effects.append("maintenance"),
    )

    try:
        service.startup()
    finally:
        service.shutdown()

    # Reconciliation is executed by the maintenance thread only after the
    # interruptible grace period. The startup caller never invokes it inline.
    assert startup_effects == ["maintenance", "poller"]
    startup_wiring = next(
        row for row in service.wiring_audit() if row["dependency"] == "startup_automation"
    )
    assert startup_wiring["configured"] is True
    assert startup_wiring["runtime_wired"] is True


class _DelayedEmailContext:
    def __init__(self) -> None:
        self._settings = Settings(
            ops_automation_start_delay_seconds=1,
            email_poll_interval_seconds=10,
            email_poll_max_runs_per_cycle=3,
        )
        self._gmail_worker = object()
        self._email_poller_thread: threading.Thread | None = None
        self._email_poller_stop = threading.Event()
        self.calls: list[tuple[str, object]] = []
        self.stop_after_reply = False

    def resolve_pending_otps(
        self,
        *,
        limit: int = 1_000,
        max_attempts_per_run: int | None = None,
    ) -> int:
        self.calls.append(("otp", (limit, max_attempts_per_run)))
        return 0

    def poll_waiting_runs(self, *, limit: int = 100) -> int:
        self.calls.append(("reply", limit))
        if self.stop_after_reply:
            self._email_poller_stop.set()
        return 0

    def poll_email(self, run_id: str) -> dict[str, Any]:
        del run_id
        return {}


class _DelayedMaintenanceContext:
    def __init__(self) -> None:
        self._settings = Settings(ops_automation_start_delay_seconds=1)
        self._autonomous_advances: dict[str, int] = {}
        self._advance_thread: threading.Thread | None = None
        self._advance_stop = threading.Event()
        self.calls: list[str] = []

    def _reconcile_stranded_runs(self) -> None:
        self.calls.append("reconcile")


def test_delayed_workers_can_stop_without_any_provider_or_reconciliation_call() -> None:
    email_context = _DelayedEmailContext()
    RunEmailService(email_context).start_poller()  # type: ignore[arg-type]
    email_context._email_poller_stop.set()
    assert email_context._email_poller_thread is not None
    email_context._email_poller_thread.join(timeout=2)

    maintenance_context = _DelayedMaintenanceContext()
    RunAdvanceService(maintenance_context).start()  # type: ignore[arg-type]
    maintenance_context._advance_stop.set()
    assert maintenance_context._advance_thread is not None
    maintenance_context._advance_thread.join(timeout=2)

    assert email_context.calls == []
    assert maintenance_context.calls == []


def test_email_cycle_is_capped_and_defers_otp_retry_to_the_next_cycle(
    tmp_path: Path,
) -> None:
    context = _DelayedEmailContext()
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    context._settings = context._settings.model_copy(
        update={
            "app_revision": "a" * 40,
            "ops_deploy_acceptance_nonce": SecretStr("N" * 64),
            "ops_deploy_acceptance_marker_path": data / "deploy-acceptance.json",
        }
    )
    write_deployment_acceptance_marker(context._settings)
    context.stop_after_reply = True

    RunEmailService(context)._poller_loop(  # type: ignore[arg-type]
        interval=10,
        initial_delay=0,
        cycle_limit=3,
    )

    assert context.calls == [("otp", (3, 1)), ("reply", 3)]
