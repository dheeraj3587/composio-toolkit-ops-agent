"""Per-run command serialization and the typed run_conflict outcome."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import RunConflictError, RunService


def _request(app_name: str = "HubSpot") -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Company",
            website="https://example.test",
            work_email_ref="vault://company/work_email/unconfigured",
            use_case="Evaluate documented integration access.",
        ),
        dry_run=True,
    )


def test_second_concurrent_command_returns_run_conflict(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    run = service.create_run(_request())  # revision 1, status route_selected
    run_id = run["run_id"]

    def attempt(_: int) -> str:
        try:
            service.guarded_status_update(
                run_id,
                expected_revision=1,
                next_status="configuration_required",
                command="retry",
            )
            return "ok"
        except RunConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(24)))

    assert results.count("ok") == 1
    assert results.count("conflict") == 23
    stored = service.storage.get_run(run_id)
    assert stored is not None
    assert stored["state_revision"] == 2  # exactly one increment
    assert stored["status"] == "configuration_required"


def test_conflict_performs_no_partial_write_or_external_action(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    run = service.create_run(_request())
    run_id = run["run_id"]

    with pytest.raises(RunConflictError):
        service.guarded_status_update(
            run_id,
            expected_revision=99,  # stale revision
            next_status="configuration_required",
            command="retry",
        )

    stored = service.storage.get_run(run_id)
    assert stored is not None
    assert stored["state_revision"] == 1  # unchanged
    assert stored["status"] == "route_selected"  # unchanged
    assert stored["external_actions"] is False
