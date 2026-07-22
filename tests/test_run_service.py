from __future__ import annotations

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ops.models import CompanyProfile, OperationsRequest
from ops.p1_adapter import DEFAULT_P1_ROOT, SnapshotIntegrityError
from ops.run_service import (
    IdempotencyConflictError,
    InvalidIdempotencyKeyError,
    RunService,
)
from ops.storage import OperationsUnitOfWork


def request_for(app_name: str) -> OperationsRequest:
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


def test_run_service_records_verified_research_and_final_route(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"))
    timeline = service.get_timeline(run["run_id"])

    assert run["status"] == "route_selected"
    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    assert [event["event_type"] for event in timeline] == [
        "dry_run_created",
        "p1_snapshot_loaded",
        "operational_research_built",
        "route_selected",
    ]
    research_event = timeline[1]["payload"]
    assert research_event["source"] == "verified_p1_snapshot"
    assert research_event["verification_status"] == "Hand-Checked"
    assert research_event["evidence_count"] == 4
    assert timeline[-1]["payload"]["is_final"] is True


def test_run_service_records_typed_unknown_without_external_probe(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")

    run = service.create_run(request_for("An App Outside The Snapshot"))
    timeline = service.get_timeline(run["run_id"])

    assert run["access_route"] == "unknown"
    assert run["status"] == "researching"
    assert [event["event_type"] for event in timeline] == [
        "dry_run_created",
        "p1_snapshot_not_found",
        "route_pending",
    ]
    route_payload = timeline[-1]["payload"]
    assert route_payload["status"] == "researching"
    assert route_payload["reason_code"] == "insufficient_evidence_probe_available"
    assert route_payload["is_final"] is False
    assert route_payload["unknown_probe_attempts"] == 0
    assert route_payload["unknown_probe_remaining"] == 1
    assert route_payload["external_actions"] is False
    assert "no external provider was invoked" in route_payload["explanation"].lower()


def test_run_service_lists_pages_and_never_exposes_storage_details(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    service = RunService.from_paths(db_path=db_path)
    service.create_run(request_for("HubSpot"))
    service.create_run(request_for("Salesforce"))

    runs, total = service.list_runs(limit=1, offset=1)

    assert total == 2
    assert len(runs) == 1
    assert "db_path" not in runs[0]
    assert "browser_session_id" not in runs[0]
    assert "gmail_session_id" not in runs[0]
    assert str(db_path) not in str(runs[0])


def test_run_service_redacts_provider_keys_before_deriving_public_slug(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")
    provider_key = "AIza0123456789abcdefghijKLMN"  # pragma: allowlist secret

    run = service.create_run(request_for(f"Example {provider_key}"))

    assert provider_key not in str(run)
    assert provider_key.casefold() not in str(run).casefold()
    assert run["app_name"] == "Example [REDACTED]"
    assert run["app_slug"] == "example-redacted"


def test_snapshot_failure_happens_before_any_run_write(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "p1"
    shutil.copytree(DEFAULT_P1_ROOT, snapshot_root)
    results_path = snapshot_root / "results.json"
    results_path.write_bytes(results_path.read_bytes() + b"\n")
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        snapshot_root=snapshot_root,
    )

    with pytest.raises(SnapshotIntegrityError):
        service.create_run(request_for("HubSpot"))

    assert service.storage.count_runs() == 0


def test_idempotency_replay_returns_original_run_without_duplicate_events(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")
    request = request_for("HubSpot")
    idempotency_key = "idem_0123456789abcdef0123456789abcdef"

    first = service.create_run(request, idempotency_key=idempotency_key)
    first_timeline = service.get_timeline(first["run_id"])
    replay = service.create_run(request, idempotency_key=idempotency_key)

    assert replay == first
    assert service.storage.count_runs() == 1
    assert service.get_timeline(first["run_id"]) == first_timeline
    assert "idempotency_key" not in replay
    assert "request_fingerprint" not in replay


def test_concurrent_idempotency_replay_creates_exactly_one_atomic_run(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")
    request = request_for("HubSpot")
    idempotency_key = "idem_1234567890abcdef1234567890abcdef"

    with ThreadPoolExecutor(max_workers=16) as executor:
        runs = list(
            executor.map(
                lambda _: service.create_run(request, idempotency_key=idempotency_key),
                range(32),
            )
        )

    run_ids = {run["run_id"] for run in runs}
    assert len(run_ids) == 1
    assert service.storage.count_runs() == 1
    assert len(service.storage.list_audit_events(run_ids.pop())) == 4


def test_idempotency_key_reuse_with_different_request_is_rejected(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    idempotency_key = "idem_fedcba9876543210fedcba9876543210"
    service.create_run(request_for("HubSpot"), idempotency_key=idempotency_key)

    with pytest.raises(IdempotencyConflictError) as raised:
        service.create_run(request_for("Salesforce"), idempotency_key=idempotency_key)

    assert idempotency_key not in str(raised.value)
    assert service.storage.count_runs() == 1


@pytest.mark.parametrize(
    "idempotency_key",
    [
        "",
        "idem_too-short",
        "idem_0123456789ABCDEF0123456789ABCDEF",
        "idem_0123456789abcdef0123456789abcdef-extra",
    ],
)
def test_invalid_idempotency_keys_fail_before_persistence(
    tmp_path: Path,
    idempotency_key: str,
) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")

    with pytest.raises(InvalidIdempotencyKeyError) as raised:
        service.create_run(request_for("HubSpot"), idempotency_key=idempotency_key)

    if idempotency_key:
        assert idempotency_key not in str(raised.value)
    assert service.storage.count_runs() == 0


def test_run_creation_rolls_back_when_an_audit_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    original_append = OperationsUnitOfWork.append_audit_event

    def append_then_fail(
        self: OperationsUnitOfWork,
        *,
        run_id: str,
        event_type: str,
        payload: object = None,
    ) -> int:
        event_id = original_append(
            self,
            run_id=run_id,
            event_type=event_type,
            payload=payload,  # type: ignore[arg-type]
        )
        if event_type == "p1_snapshot_loaded":
            raise RuntimeError("injected audit failure")
        return event_id

    monkeypatch.setattr(OperationsUnitOfWork, "append_audit_event", append_then_fail)

    with pytest.raises(RuntimeError, match="injected audit failure"):
        service.create_run(request_for("HubSpot"))

    assert service.storage.count_runs() == 0
    with sqlite3.connect(service.storage.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (0,)


def test_run_creation_rolls_back_when_the_status_update_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    original_update = OperationsUnitOfWork.update_run

    def update_then_fail(
        self: OperationsUnitOfWork,
        run_id: str,
        **changes: object,
    ) -> dict[str, object]:
        original_update(self, run_id, **changes)
        raise RuntimeError("injected update failure")

    monkeypatch.setattr(OperationsUnitOfWork, "update_run", update_then_fail)

    with pytest.raises(RuntimeError, match="injected update failure"):
        service.create_run(request_for("HubSpot"))

    assert service.storage.count_runs() == 0
    with sqlite3.connect(service.storage.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (0,)
