from __future__ import annotations

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ops.models import (
    CapabilityAvailability,
    CompanyProfile,
    OperationalResearch,
    OperationsRequest,
    ScopeRequirement,
)
from ops.operational_research import ResearchEnrichmentOutcome
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


def test_operations_token_is_presented_as_execute_when_configured(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "private" / "ops.db")

    run = service.create_run(request_for("HubSpot"), execution_mode="execute_when_configured")

    # Persisted "operations" token maps to the logical public value.
    assert run["execution_mode"] == "execute_when_configured"
    stored = service.storage.get_run(run["run_id"])
    assert stored is not None
    assert stored["execution_mode"] == "operations"
    # Without a configured durable workflow (no encryption key), execute_when_configured
    # is truthful: configuration_required, no provider action, never a fabricated success.
    assert run["external_actions"] is False
    assert run["status"] == "configuration_required"
    assert run["status"] not in {"browser_running", "outreach_sent", "completed"}


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


# --- M3: one-probe operational-research enrichment wiring -------------------


def _event_types(service: RunService, run_id: str) -> list[str]:
    return [event["event_type"] for event in service.get_timeline(run_id)]


class _ReadyEnricher:
    """Fake configured enricher: returns an enriched baseline, no side effects."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome:
        del app_name, p1_record
        enriched = baseline.model_copy(
            update={
                "signup_url": "https://developers.hubspot.com/get-started",
                "developer_portal_url": "https://developers.hubspot.com",
                "authorization_url": "https://app.hubspot.com/oauth/authorize",
                "token_url": "https://api.hubapi.com/oauth/v1/token",
                "evidence_urls": ["https://developers.hubspot.com/docs/oauth"],
                "scopes": [
                    ScopeRequirement(
                        name="crm.objects.contacts.read",
                        source_url="https://developers.hubspot.com/docs/oauth",
                    )
                ],
                "confidence": 0.9,
            }
        )
        return ResearchEnrichmentOutcome(
            research=enriched,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="ready",
                reason_code="official_evidence_enriched",
                detail="Operational fields were extracted from fetched allowlisted evidence.",
            ),
            missing_fields=[],
            documents_fetched=2,
        )


class _UnconfiguredEnricher:
    """Fake unconfigured enricher: retains the verified baseline truthfully."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome:
        del app_name, p1_record
        return ResearchEnrichmentOutcome(
            research=baseline,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="configuration_required",
                reason_code="provider_credentials_missing",
                detail="Perplexity discovery and Gemini extraction must both be configured.",
            ),
            missing_fields=["scopes"],
            documents_fetched=0,
        )


class _RaisingEnricher:
    """Fails loudly if a plan-only or out-of-scope probe is attempted."""

    async def enrich(self, *, app_name, p1_record, baseline):  # type: ignore[no-untyped-def]
        raise AssertionError("enrichment must not run for this case")


class _FailingEnricher:
    """Simulates an unavailable provider without exposing its exception."""

    async def enrich(self, *, app_name, p1_record, baseline):  # type: ignore[no-untyped-def]
        del app_name, p1_record, baseline
        raise RuntimeError("provider transport failed")


def test_incomplete_verified_record_triggers_single_bounded_enrichment(tmp_path: Path) -> None:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        research_enricher=_ReadyEnricher(),
    )

    run = service.create_run(request_for("HubSpot"), execution_mode="execute_when_configured")
    research = service.get_research(run["run_id"])
    events = _event_types(service, run["run_id"])
    enriched_event = next(
        event
        for event in service.get_timeline(run["run_id"])
        if event["event_type"] == "operational_research_enriched"
    )

    # The enrichment is independent of the later durable workflow. This unit
    # service intentionally has no workflow configured, so the execution branch
    # reports that prerequisite after persisting the enrichment outcome.
    assert run["status"] == "configuration_required"
    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    assert "operational_research_enriched" in events
    assert research is not None
    assert research.signup_url == "https://developers.hubspot.com/get-started"
    assert research.token_url == "https://api.hubapi.com/oauth/v1/token"
    assert enriched_event["payload"]["status"] == "ready"
    assert enriched_event["payload"]["enrichment_attempts"] == 1
    assert enriched_event["payload"]["documents_fetched"] == 2
    assert enriched_event["payload"]["source"] == "official_evidence_combined"
    assert enriched_event["payload"]["external_actions"] is False


def test_unconfigured_enricher_retains_baseline_and_reports_configuration_required(
    tmp_path: Path,
) -> None:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        research_enricher=_UnconfiguredEnricher(),
    )

    run = service.create_run(request_for("HubSpot"), execution_mode="execute_when_configured")
    research = service.get_research(run["run_id"])
    enriched_event = next(
        event
        for event in service.get_timeline(run["run_id"])
        if event["event_type"] == "operational_research_enriched"
    )

    # Baseline retained, no fabricated operational fields, truthful route.
    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    assert research is not None
    assert research.signup_url is None
    assert research.token_url is None
    assert enriched_event["payload"]["status"] == "configuration_required"
    assert enriched_event["payload"]["enrichment_attempts"] == 0
    assert enriched_event["payload"]["documents_fetched"] == 0


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


def test_failed_enrichment_retains_verified_baseline_and_persists_run(tmp_path: Path) -> None:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        research_enricher=_FailingEnricher(),
    )

    run = service.create_run(request_for("HubSpot"), execution_mode="execute_when_configured")
    enriched_event = next(
        event
        for event in service.get_timeline(run["run_id"])
        if event["event_type"] == "operational_research_enriched"
    )

    assert run["status"] == "configuration_required"
    assert enriched_event["payload"]["status"] == "failed"
    assert enriched_event["payload"]["reason_code"] == "official_evidence_provider_failed"
    assert "provider transport failed" not in str(enriched_event)


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
