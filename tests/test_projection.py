"""Revision-guarded idempotent projection into the sanitized ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import RunService
from ops.state import IllegalStatusTransition


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


def test_higher_revision_projection_advances_state_and_validates(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    run = service.create_run(_request())  # plan_only: revision 1, status route_selected
    run_id = run["run_id"]

    projected = service.project(run_id, {"status": "configuration_required"}, 2, command="retry")

    assert projected["status"] == "configuration_required"
    stored = service.storage.get_run(run_id)
    assert stored is not None
    assert stored["state_revision"] == 2
    assert stored["last_projected_revision"] == 2


def test_equal_or_lower_revision_is_a_noop_without_duplicate_audit(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    run = service.create_run(_request())
    run_id = run["run_id"]
    before = service.storage.get_run(run_id)
    assert before is not None
    events_before = service.get_timeline(run_id)

    # last_projected_revision is 1 after create; equal (1) and lower (0) are no-ops.
    service.project(run_id, {"status": "configuration_required"}, 1, command="retry")
    service.project(run_id, {"status": "configuration_required"}, 0, command="retry")

    after = service.storage.get_run(run_id)
    assert after is not None
    assert after["status"] == before["status"]
    assert after["state_revision"] == before["state_revision"]
    assert len(service.get_timeline(run_id)) == len(events_before)


def test_projection_rejects_illegal_transition_without_writing(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    run = service.create_run(_request())
    run_id = run["run_id"]

    with pytest.raises(IllegalStatusTransition):
        service.project(run_id, {"status": "completed"}, 2, command="workflow")

    stored = service.storage.get_run(run_id)
    assert stored is not None
    assert stored["status"] == "route_selected"
    assert stored["state_revision"] == 1
