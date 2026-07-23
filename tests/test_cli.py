"""Behavior tests for the honest, local-only CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from ops.cli import (
    EXIT_ERROR,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_PHASE_UNAVAILABLE,
    main,
)


def _run_cli(
    capsys: pytest.CaptureFixture[str],
    db_path: Path,
    *arguments: str,
) -> tuple[int, dict[str, object]]:
    exit_code = main(["--db-path", str(db_path), *arguments])
    captured = capsys.readouterr()
    rendered = captured.out or captured.err
    assert rendered
    return exit_code, json.loads(rendered)


def _create_run(
    capsys: pytest.CaptureFixture[str],
    db_path: Path,
    app_name: str = "Example App",
) -> str:
    exit_code, payload = _run_cli(capsys, db_path, "run", app_name)
    assert exit_code == EXIT_OK
    run = payload["run"]
    assert isinstance(run, dict)
    run_id = run["run_id"]
    assert isinstance(run_id, str)
    return run_id


def test_run_creates_and_routes_only_a_local_dry_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "private" / "ops.db"

    exit_code, payload = _run_cli(capsys, db_path, "run", "Example App")

    assert exit_code == EXIT_OK
    run = payload["run"]
    assert isinstance(run, dict)
    assert run["app_name"] == "Example App"
    assert run["app_slug"] == "example-app"
    assert run["status"] == "researching"
    assert run["access_route"] == "unknown"
    assert run["execution_mode"] == "plan_only"
    assert run["external_actions"] is False
    assert "browser_live_url" not in run
    assert "gmail_thread_id" not in run
    assert db_path.is_file()


def test_status_returns_sanitized_run_and_timeline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ops.db"
    run_id = _create_run(capsys, db_path, "Linear")

    exit_code, payload = _run_cli(capsys, db_path, "status", run_id)

    assert exit_code == EXIT_OK
    run = payload["run"]
    timeline = payload["timeline"]
    assert isinstance(run, dict)
    assert run["run_id"] == run_id
    assert run["status"] == "route_selected"
    assert isinstance(timeline, list)
    assert timeline[0]["event_type"] == "dry_run_created"
    assert timeline[0]["payload"]["external_actions"] is False
    assert timeline[-1]["event_type"] == "route_selected"
    assert timeline[-1]["payload"]["external_actions"] is False


@pytest.mark.parametrize("command", ["resume", "poll-email", "show-output"])
def test_future_phase_commands_fail_explicitly(
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ops.db"
    run_id = _create_run(capsys, db_path)

    exit_code, payload = _run_cli(capsys, db_path, command, run_id)

    assert exit_code == EXIT_PHASE_UNAVAILABLE
    assert payload == {
        "available_in": "a later implementation phase",
        "command": command,
        "error": "phase_unavailable",
        "external_actions": False,
        "run_id": run_id,
    }


def test_unknown_run_is_not_misreported_as_phase_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, payload = _run_cli(
        capsys,
        tmp_path / "ops.db",
        "status",
        "run_missing",
    )

    assert exit_code == EXIT_NOT_FOUND
    assert payload == {"error": "run_not_found", "run_id": "run_missing"}


def test_invalid_vault_reference_never_echoes_rejected_value(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rejected_value = "raw-client-secret-must-not-appear"

    exit_code = main(
        [
            "--db-path",
            str(tmp_path / "ops.db"),
            "run",
            "Example App",
            "--work-email-ref",
            rejected_value,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == EXIT_ERROR
    assert rejected_value not in captured.out
    assert rejected_value not in captured.err
    payload = json.loads(captured.err)
    assert payload["error"] == "invalid_request"
    assert "company.work_email_ref" in payload["fields"]


def test_doctor_checks_snapshot_and_safe_email_default(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ALLOW_LIVE_VENDOR_EMAIL", raising=False)
    monkeypatch.delenv("SECRET_VAULT_KEY", raising=False)

    exit_code, payload = _run_cli(capsys, tmp_path / "ops.db", "doctor")

    assert exit_code == EXIT_OK
    assert payload["status"] == "ready_for_phase_2_local"
    assert payload["phase"] == "0/1/2"
    assert payload["external_operations"] == "unavailable"
    checks = payload["checks"]
    assert isinstance(checks, list)
    check_statuses = {check["name"]: check["status"] for check in checks}
    assert check_statuses["p1_snapshot_manifest"] == "pass"
    assert check_statuses["results"] == "pass"
    assert check_statuses["coverage"] == "pass"
    assert check_statuses["live_vendor_email_disabled"] == "pass"
    assert check_statuses["secret_vault_key"] == "not_configured"  # pragma: allowlist secret


def test_doctor_rejects_live_vendor_email_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOW_LIVE_VENDOR_EMAIL", "true")

    exit_code, payload = _run_cli(capsys, tmp_path / "ops.db", "doctor")

    assert exit_code == EXIT_ERROR
    assert payload["status"] == "configuration_error"


def test_doctor_accepts_a_valid_fernet_vault_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_VAULT_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.delenv("ALLOW_LIVE_VENDOR_EMAIL", raising=False)

    exit_code, payload = _run_cli(capsys, tmp_path / "ops.db", "doctor")

    assert exit_code == EXIT_OK
    checks = payload["checks"]
    assert isinstance(checks, list)
    check_statuses = {check["name"]: check["status"] for check in checks}
    assert check_statuses["secret_vault_key"] == "configured"  # pragma: allowlist secret


def test_doctor_rejects_invalid_fernet_key_without_echoing_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_key = "invalid-vault-key-must-never-render"
    monkeypatch.setenv("SECRET_VAULT_KEY", invalid_key)
    monkeypatch.delenv("ALLOW_LIVE_VENDOR_EMAIL", raising=False)

    exit_code = main(["--db-path", str(tmp_path / "ops.db"), "doctor"])
    captured = capsys.readouterr()

    assert exit_code == EXIT_ERROR
    assert invalid_key not in captured.out
    assert invalid_key not in captured.err
    payload = json.loads(captured.out)
    assert payload["status"] == "configuration_error"
    checks = payload["checks"]
    assert isinstance(checks, list)
    check_statuses = {check["name"]: check["status"] for check in checks}
    assert check_statuses["secret_vault_key"] == "fail"  # pragma: allowlist secret
