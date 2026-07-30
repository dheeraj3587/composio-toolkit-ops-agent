from __future__ import annotations

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ops.core.models import (
    CompanyProfile,
    OperationsRequest,
)
from ops.core.storage import OperationsUnitOfWork
from ops.research.p1_adapter import DEFAULT_P1_ROOT, SnapshotIntegrityError
from ops.runs.service import (
    IdempotencyConflictError,
    InvalidIdempotencyKeyError,
    RunService,
)


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


def test_run_service_records_canonical_recipe_and_final_route(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"))
    timeline = service.get_timeline(run["run_id"])

    assert run["status"] == "route_selected"
    assert run["access_route"] == "self_serve"
    assert run["route_kind"] == "managed_auth"
    assert run["readiness_tier"] == "managed_auth_ready"
    assert run["state_engine"] == "canonical_v1"
    assert run["external_actions"] is False
    assert [event["event_type"] for event in timeline] == [
        "run_created",
        "route_selected",
    ]
    assert timeline[0]["payload"]["recipe_version"] == run["recipe_version"]
    assert timeline[-1]["payload"]["reason_code"] == "managed_connection_required"


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


def test_legacy_browser_use_fingerprint_replays_without_false_conflict(tmp_path: Path) -> None:
    from ops.runs.service import _legacy_request_fingerprint

    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")
    request = request_for("HubSpot")
    idempotency_key = "idem_1123456789abcdef0123456789abcdef"
    first = service.create_run(request, idempotency_key=idempotency_key)
    legacy = _legacy_request_fingerprint(request, "plan_only")
    with service.storage._connect() as connection:  # noqa: SLF001 - migration compatibility test
        connection.execute(
            "UPDATE runs SET request_fingerprint = ? WHERE run_id = ?",
            (legacy, first["run_id"]),
        )

    assert service.create_run(request, idempotency_key=idempotency_key) == first


def test_idempotency_fingerprint_freezes_browser_provider(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    idempotency_key = "idem_2123456789abcdef0123456789abcdef"
    browser_use = request_for("HubSpot")
    playwright = browser_use.model_copy(update={"browser_provider": "playwright"})
    service.create_run(browser_use, idempotency_key=idempotency_key)

    with pytest.raises(IdempotencyConflictError):
        service.create_run(playwright, idempotency_key=idempotency_key)


def test_idempotency_fingerprint_freezes_credential_creation_policy(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    idempotency_key = "idem_3123456789abcdef0123456789abcdef"
    reuse = request_for("HubSpot")
    create = reuse.model_copy(update={"credential_creation_policy": "create_if_missing"})
    service.create_run(reuse, idempotency_key=idempotency_key)

    with pytest.raises(IdempotencyConflictError):
        service.create_run(create, idempotency_key=idempotency_key)


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
    events = service.storage.list_audit_events(run_ids.pop())
    assert [event["event_type"] for event in events] == ["run_created", "route_selected"]


def test_idempotency_key_reuse_with_different_request_is_rejected(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    idempotency_key = "idem_fedcba9876543210fedcba9876543210"
    service.create_run(request_for("HubSpot"), idempotency_key=idempotency_key)

    with pytest.raises(IdempotencyConflictError) as raised:
        service.create_run(request_for("Salesforce"), idempotency_key=idempotency_key)

    assert idempotency_key not in str(raised.value)
    assert service.storage.count_runs() == 1


def test_idempotency_key_reuse_with_different_execution_mode_is_rejected(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    idempotency_key = "idem_abcdef0123456789abcdef0123456789"
    service.create_run(
        request_for("HubSpot"),
        idempotency_key=idempotency_key,
        execution_mode="plan_only",
    )

    with pytest.raises(IdempotencyConflictError) as raised:
        service.create_run(
            request_for("HubSpot"),
            idempotency_key=idempotency_key,
            execution_mode="execute_when_configured",
        )

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
        if event_type == "route_selected":
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


def test_plan_only_terminates_at_route_selected(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"), execution_mode="plan_only")

    assert run["status"] == "route_selected"
    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    # plan_only never advances into execution states.
    assert run["status"] not in {"browser_running", "outreach_sent", "completed"}


def test_plan_only_persists_local_dry_run_token_but_exposes_logical_mode(
    tmp_path: Path,
) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"), execution_mode="plan_only")

    # The public boundary exposes the logical mode, not the persisted token.
    assert run["execution_mode"] == "plan_only"
    # The persisted storage token is unchanged (no migration).
    stored = service.storage.get_run(run["run_id"])
    assert stored is not None
    assert stored["execution_mode"] == "local_dry_run"


def test_default_execution_mode_is_plan_only(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")

    run = service.create_run(request_for("HubSpot"))

    assert run["execution_mode"] == "plan_only"
    stored = service.storage.get_run(run["run_id"])
    assert stored is not None
    assert stored["execution_mode"] == "local_dry_run"


def test_operations_token_enters_canonical_managed_connection_state(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"), execution_mode="execute_when_configured")

    # Persisted "operations" token maps to the logical public value.
    assert run["execution_mode"] == "execute_when_configured"
    stored = service.storage.get_run(run["run_id"])
    assert stored is not None
    assert stored["execution_mode"] == "operations"
    # Run creation selects the reviewed managed-auth route but does not call the
    # provider; connection creation remains an explicit follow-up operation.
    assert run["external_actions"] is False
    assert run["state_engine"] == "canonical_v1"
    assert run["route_kind"] == "managed_auth"
    assert run["status"] == "connection_required"
    assert run["phase"] == "connection_required"
    assert run["reason_code"] == "managed_connection_required"


def test_execution_mode_does_not_change_idempotent_replay(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")
    request = request_for("HubSpot")
    idempotency_key = "idem_0f0e0d0c0b0a09080706050403020100"

    first = service.create_run(request, idempotency_key=idempotency_key, execution_mode="plan_only")
    replay = service.create_run(
        request, idempotency_key=idempotency_key, execution_mode="plan_only"
    )

    assert replay == first
    assert service.storage.count_runs() == 1


# --- Legacy research stays offline for canonical run creation ----------------


def _event_types(service: RunService, run_id: str) -> list[str]:
    return [event["event_type"] for event in service.get_timeline(run_id)]


class _RaisingEnricher:
    """Fails loudly if a plan-only or out-of-scope probe is attempted."""

    async def enrich(self, *, app_name, p1_record, baseline):  # type: ignore[no-untyped-def]
        raise AssertionError("enrichment must not run for this case")


def test_default_run_service_performs_no_enrichment(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"), execution_mode="plan_only")

    assert "operational_research_enriched" not in _event_types(service, run["run_id"])


def test_plan_only_never_calls_a_configured_enricher(tmp_path: Path) -> None:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        research_enricher=_RaisingEnricher(),
    )

    run = service.create_run(request_for("HubSpot"), execution_mode="plan_only")

    assert run["status"] == "route_selected"
    assert run["access_route"] == "self_serve"
    assert "operational_research_enriched" not in _event_types(service, run["run_id"])


def test_missing_record_never_triggers_enrichment_probe(tmp_path: Path) -> None:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        research_enricher=_RaisingEnricher(),
    )

    run = service.create_run(request_for("An App Outside The Snapshot"))

    # Not-found runs have no official allowlist source, so no probe is attempted.
    assert run["access_route"] == "unknown"
    assert run["status"] == "researching"
    assert "operational_research_enriched" not in _event_types(service, run["run_id"])
