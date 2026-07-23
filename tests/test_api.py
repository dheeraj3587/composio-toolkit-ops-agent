"""HTTP contract and leakage regressions for the FastAPI presentation boundary."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from api.app import create_app
from api.models import ActionReceipt
from api.service import LocalRunService
from ops.run_service import RunService as CoreRunService


def create_payload(app_name: str = "HubSpot") -> dict[str, object]:
    return {
        "app_name": app_name,
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/test-operator",
            "use_case": "Evaluate documented integration access.",
            "callback_urls": ["https://example.test/oauth/callback"],
        },
        "requested_scope_policy": "maximum",
        "dry_run": True,
        "outreach_recipient_override": "controlled@example.test",
    }


class TrackingRunService(LocalRunService):
    def __init__(self, db_path: Path, core_service: CoreRunService) -> None:
        super().__init__(db_path, core_service=core_service)
        self.started = False
        self.stopped = False

    async def startup(self) -> None:
        await super().startup()
        self.started = True

    async def shutdown(self) -> None:
        await super().shutdown()
        self.stopped = True


class SuccessfulActionService(TrackingRunService):
    """Test double for the stable success contract of future phase actions."""

    async def resume(
        self,
        run_id: str,
        *,
        browser_login: object = None,
        signal: str = "completed",
    ) -> ActionReceipt:
        await self.get_run(run_id)
        return ActionReceipt(run_id=run_id, action="resume")

    async def poll_email(self, run_id: str) -> ActionReceipt:
        await self.get_run(run_id)
        return ActionReceipt(run_id=run_id, action="poll_email")


@dataclass(frozen=True)
class ApiHarness:
    client: TestClient
    service: TrackingRunService
    core: CoreRunService
    db_path: Path


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[ApiHarness]:
    db_path = tmp_path / "private" / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path)
    service = TrackingRunService(db_path, core)
    application = create_app(service=service, cors_origins=["http://localhost:5173"])
    with TestClient(application, raise_server_exceptions=False) as client:
        assert service.started is True
        yield ApiHarness(client=client, service=service, core=core, db_path=db_path)
    assert service.stopped is True


def create_run(
    harness: ApiHarness,
    app_name: str = "HubSpot",
    *,
    idempotency_key: str | None = None,
) -> dict[str, object]:
    headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
    response = harness.client.post("/api/runs", json=create_payload(app_name), headers=headers)
    assert response.status_code == 201
    return response.json()


def test_exact_requested_routes_are_registered(harness: ApiHarness) -> None:
    routes = {
        (route.path, method)
        for route in harness.client.app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }

    assert routes == {
        ("/api/runs", "POST"),
        ("/api/runs", "GET"),
        ("/api/runs/{run_id}", "GET"),
        ("/api/runs/{run_id}/timeline", "GET"),
        ("/api/runs/{run_id}/resume", "POST"),
        ("/api/runs/{run_id}/credentials", "POST"),
        ("/api/runs/{run_id}/credentials/reveal", "POST"),
        ("/api/runs/{run_id}/live-view", "GET"),
        ("/api/runs/{run_id}/poll-email", "POST"),
        ("/api/runs/{run_id}/retry", "POST"),
        ("/api/runs/{run_id}/output", "GET"),
        ("/api/apps/search", "GET"),
        ("/api/apps/{app_slug}/research", "GET"),
        ("/api/system/health", "GET"),
    }


def test_create_and_detail_expose_verified_phase_two_contract(harness: ApiHarness) -> None:
    created = create_run(harness)

    assert set(created) == {
        "run",
        "research",
        "phases",
        "security",
        "route_decision",
        "missing_fields",
        "provider_states",
        "hitl_request",
    }
    run = created["run"]
    assert isinstance(run, dict)
    assert set(run) == {
        "run_id",
        "thread_id",
        "app_name",
        "app_slug",
        "status",
        "access_route",
        "execution_mode",
        "external_actions",
        "created_at",
        "updated_at",
    }
    assert run["status"] == "route_selected"
    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    assert str(run["thread_id"]).startswith("local_")

    research = created["research"]
    assert isinstance(research, dict)
    assert research["app_name"] == "HubSpot"
    assert research["access_route"] == "self_serve"
    assert len(research["evidence_urls"]) == 4

    phases = {phase["key"]: phase["status"] for phase in created["phases"]}
    assert phases == {
        "research": "ready",
        "browser": "configuration_required",
        "hitl": "configuration_required",
        "email": "configuration_required",
        "output": "waiting",
    }
    assert created["security"]["redaction"] == "enabled"
    assert (
        created["security"]["secret_vault"] == "not_configured"  # pragma: allowlist secret
    )
    assert created["security"]["owner_only_storage"] == "verified_owner_only"
    assert created["security"]["live_vendor_email"] == "disabled"
    assert created["security"]["live_browser"] == "disabled"
    assert created["security"]["external_actions"] is False
    assert created["security"]["raw_secrets_exposed"] is False

    response = harness.client.get(f"/api/runs/{run['run_id']}")
    assert response.status_code == 200
    assert response.json() == created


def test_unknown_snapshot_app_has_typed_unknown_route_and_null_research(
    harness: ApiHarness,
) -> None:
    created = create_run(harness, "App Outside Snapshot")

    assert created["run"]["access_route"] == "unknown"
    assert created["run"]["status"] == "researching"
    assert created["research"] is None
    assert created["run"]["external_actions"] is False
    research_phase = next(phase for phase in created["phases"] if phase["key"] == "research")
    assert research_phase["status"] == "waiting"
    assert research_phase["available"] is False
    assert "pending" in research_phase["detail"].lower()

    timeline = harness.client.get(f"/api/runs/{created['run']['run_id']}/timeline")
    assert timeline.status_code == 200
    assert "route_pending" in {item["event_type"] for item in timeline.json()["items"]}


def test_create_run_is_idempotent_for_safe_generated_key(harness: ApiHarness) -> None:
    idempotency_key = "idem_" + "a" * 32

    first = create_run(harness, idempotency_key=idempotency_key)
    retried = create_run(harness, idempotency_key=idempotency_key)

    assert retried == first
    assert harness.core.storage.count_runs() == 1
    assert len(harness.core.storage.list_audit_events(first["run"]["run_id"])) == 4


def test_idempotency_conflict_is_typed_and_never_echoes_key(harness: ApiHarness) -> None:
    idempotency_key = "idem_" + "b" * 32
    create_run(harness, "HubSpot", idempotency_key=idempotency_key)

    response = harness.client.post(
        "/api/runs",
        json=create_payload("Salesforce"),
        headers={"Idempotency-Key": idempotency_key},
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": "idempotency_conflict",
        "message": "Idempotency key was already used for another request.",
        "external_actions": False,
    }
    assert idempotency_key not in response.text
    assert harness.core.storage.count_runs() == 1


def test_list_endpoint_returns_frontend_pagination_contract(harness: ApiHarness) -> None:
    first = create_run(harness, "HubSpot")
    create_run(harness, "Salesforce")

    response = harness.client.get("/api/runs", params={"limit": 1, "offset": 1})

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"items", "total", "limit", "offset"}
    assert payload["total"] == 2
    assert payload["limit"] == 1
    assert payload["offset"] == 1
    assert payload["items"] == [first["run"]]


def test_timeline_endpoint_returns_summaries_not_raw_audit_payloads(
    harness: ApiHarness,
) -> None:
    created = create_run(harness)
    run_id = created["run"]["run_id"]
    harness.core.storage.append_audit_event(
        run_id=run_id,
        event_type="credential_stored",
        payload={
            "authorization": "Bearer synthetic-value",
            "provider_payload": {"client_secret": "synthetic-value"},  # pragma: allowlist secret
        },
    )

    response = harness.client.get(f"/api/runs/{run_id}/timeline")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"run_id", "items"}
    assert payload["run_id"] == run_id
    assert payload["items"]
    assert all(
        set(item) == {"event_type", "summary", "status", "created_at"} for item in payload["items"]
    )
    rendered = response.text
    assert "provider_payload" not in rendered
    assert "synthetic-value" not in rendered
    assert '"payload"' not in rendered


@pytest.mark.parametrize(
    ("method", "suffix", "action"),
    [
        ("post", "resume", "resume"),
        ("post", "poll-email", "poll_email"),
        ("get", "output", "output"),
    ],
)
def test_future_actions_are_typed_http_409(
    harness: ApiHarness,
    method: str,
    suffix: str,
    action: str,
) -> None:
    run_id = create_run(harness)["run"]["run_id"]

    response = getattr(harness.client, method)(f"/api/runs/{run_id}/{suffix}")

    assert response.status_code == 409
    expected_error = "phase_unavailable" if action == "output" else "configuration_required"
    assert response.json()["error"] == expected_error
    assert response.json()["action"] == action
    assert response.json()["available_in"]
    assert all(isinstance(item, str) and item for item in response.json()["available_in"])
    assert response.json()["external_actions"] is False
    assert response.headers["cache-control"] == "no-store"


def test_future_action_success_contract_matches_frontend_receipt(tmp_path: Path) -> None:
    db_path = tmp_path / "private" / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path)
    service = SuccessfulActionService(db_path, core)
    application = create_app(service=service)

    with TestClient(application, raise_server_exceptions=False) as client:
        created = client.post("/api/runs", json=create_payload()).json()
        run_id = created["run"]["run_id"]

        resume = client.post(f"/api/runs/{run_id}/resume")
        poll = client.post(f"/api/runs/{run_id}/poll-email")

    assert resume.status_code == 200
    assert resume.json() == {"run_id": run_id, "action": "resume", "status": "accepted"}
    assert poll.status_code == 200
    assert poll.json() == {"run_id": run_id, "action": "poll_email", "status": "accepted"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/runs/run_00000000000000000000000000000000"),
        ("get", "/api/runs/run_00000000000000000000000000000000/timeline"),
        ("post", "/api/runs/run_00000000000000000000000000000000/resume"),
        ("post", "/api/runs/run_00000000000000000000000000000000/poll-email"),
        ("post", "/api/runs/run_00000000000000000000000000000000/retry"),
        ("get", "/api/runs/run_00000000000000000000000000000000/output"),
    ],
)
def test_unknown_runs_return_typed_404(harness: ApiHarness, method: str, path: str) -> None:
    kwargs = {"json": {"capability": "research"}} if path.endswith("/retry") else {}
    response = getattr(harness.client, method)(path, **kwargs)

    assert response.status_code == 404
    assert response.json() == {
        "error": "run_not_found",
        "message": "Run was not found.",
        "run_id": "run_00000000000000000000000000000000",
    }


def test_health_reports_verified_snapshot_without_environment_or_paths(
    harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_marker = "must-not-render-from-environment"
    monkeypatch.setenv("PERPLEXITY_API_KEY", environment_marker)

    response = harness.client.get("/api/system/health")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "phase", "version", "snapshot", "checks", "providers"}
    assert payload["status"] == "healthy"
    assert payload["phase"] == "2"
    assert payload["version"] == "0.2.0"
    assert payload["snapshot"]["verified"] is True
    assert len(payload["snapshot"]["results_sha256"]) == 64
    assert len(payload["snapshot"]["coverage_sha256"]) == 64
    expected_commit = "d69549be542e00574ba2046eb7a498bc147fa756"  # pragma: allowlist secret
    assert payload["snapshot"]["source_commit"] == expected_commit
    assert payload["checks"] == [
        {"name": "operations_storage_read", "status": "pass"},
        {"name": "operations_storage_owner_only", "status": "pass"},
        {"name": "p1_snapshot_integrity", "status": "pass"},
    ]
    assert "vault" not in {check["name"] for check in payload["checks"]}
    assert environment_marker not in response.text
    assert str(harness.db_path) not in response.text


def test_security_headers_and_explicit_localhost_cors(harness: ApiHarness) -> None:
    response = harness.client.get(
        "/api/system/health",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"

    rejected = harness.client.get(
        "/api/system/health",
        headers={"Origin": "https://attacker.example"},
    )
    assert "access-control-allow-origin" not in rejected.headers
    assert "access-control-allow-credentials" not in rejected.headers

    preflight = harness.client.options(
        "/api/runs",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Idempotency-Key",
        },
    )
    assert preflight.status_code == 200
    allowed_headers = preflight.headers["access-control-allow-headers"].lower()
    assert "idempotency-key" in allowed_headers


def test_validation_response_never_echoes_rejected_input(harness: ApiHarness) -> None:
    rejected_value = "raw-client-secret-must-not-appear"
    payload = create_payload()
    company = payload["company"]
    assert isinstance(company, dict)
    company["work_email_ref"] = rejected_value

    response = harness.client.post("/api/runs", json=payload)

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"
    assert "body.company.work_email_ref" in response.json()["fields"]
    assert rejected_value not in response.text


@pytest.mark.parametrize("nested", [False, True])
def test_validation_response_never_echoes_attacker_controlled_extra_field_names(
    harness: ApiHarness,
    nested: bool,
) -> None:
    attacker_field = "client_" + "secret_" + "field_marker"
    payload = create_payload()
    target = payload["company"] if nested else payload
    assert isinstance(target, dict)
    target[attacker_field] = "attacker-controlled-value"

    response = harness.client.post("/api/runs", json=payload)

    assert response.status_code == 422
    assert response.json()["fields"] == ["unknown_field"]
    assert attacker_field not in response.text
    assert "attacker-controlled-value" not in response.text


def test_invalid_run_id_is_rejected_without_reflection(harness: ApiHarness) -> None:
    rejected_run_id = "run_" + "sk_" + "live_" + "attacker_path_marker"

    response = harness.client.get(f"/api/runs/{rejected_run_id}")

    assert response.status_code == 422
    assert response.json() == {
        "error": "invalid_request",
        "message": "Request validation failed.",
        "fields": ["path.run_id"],
    }
    assert rejected_run_id not in response.text


@pytest.mark.parametrize(
    ("field", "rejected_url"),
    [
        ("website", "https://"),
        ("website", "https://user@example.test/private"),
        ("website", "https://example.test:not-a-port"),
        ("website", "ftp://example.test/resource"),
        ("callback_urls", "https://"),
        ("callback_urls", "https://user@example.test/callback"),
        ("callback_urls", "https://example.test:99999/callback"),
        ("callback_urls", "https://example.test/" + "a" * 2049),
    ],
)
def test_company_urls_require_bounded_parsed_http_urls(
    harness: ApiHarness,
    field: str,
    rejected_url: str,
) -> None:
    payload = create_payload()
    company = payload["company"]
    assert isinstance(company, dict)
    company[field] = [rejected_url] if field == "callback_urls" else rejected_url

    response = harness.client.post("/api/runs", json=payload)

    assert response.status_code == 422
    assert response.json()["fields"] == [f"body.company.{field}"]
    assert rejected_url not in response.text


def test_invalid_idempotency_key_is_rejected_without_reflection(harness: ApiHarness) -> None:
    rejected_key = "idem attacker-controlled-header-marker"

    response = harness.client.post(
        "/api/runs",
        json=create_payload(),
        headers={"Idempotency-Key": rejected_key},
    )

    assert response.status_code == 422
    assert response.json()["fields"] == ["header.idempotency-key"]
    assert rejected_key not in response.text


def test_health_degrades_when_storage_permissions_are_not_owner_only(
    harness: ApiHarness,
) -> None:
    harness.db_path.chmod(0o644)
    try:
        response = harness.client.get("/api/system/health")
    finally:
        harness.db_path.chmod(0o600)

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    checks = {check["name"]: check["status"] for check in response.json()["checks"]}
    assert checks == {
        "operations_storage_read": "fail",
        "operations_storage_owner_only": "fail",
        "p1_snapshot_integrity": "pass",
    }
    assert str(harness.db_path) not in response.text


def test_response_projection_omits_provider_sessions_and_internal_records(
    harness: ApiHarness,
) -> None:
    created = create_run(harness)
    run_id = created["run"]["run_id"]
    with pytest.raises(ValueError, match="capability URLs"):
        harness.core.storage.update_run(
            run_id,
            browser_live_url="https://browser.example.test/live?token=internal-marker",
        )
    harness.core.storage.update_run(
        run_id,
        browser_session_id="browser-session-internal",
        gmail_session_id="gmail-session-internal",
        gmail_thread_id="gmail-thread-internal",
    )

    responses = [
        harness.client.get("/api/runs"),
        harness.client.get(f"/api/runs/{run_id}"),
        harness.client.get(f"/api/runs/{run_id}/timeline"),
    ]
    rendered = "\n".join(response.text for response in responses)

    assert all(response.status_code == 200 for response in responses)
    for forbidden in (
        "browser-session-internal",
        "gmail-session-internal",
        "gmail-thread-internal",
        "internal-marker",
        "browser_session_id",
        "gmail_session_id",
        "browser_live_url",
        str(harness.db_path),
        "vault://company/work_email/test-operator",
        "controlled@example.test",
    ):
        assert forbidden not in rendered


class ExplodingHealthService(TrackingRunService):
    async def health(self) -> object:  # type: ignore[override]
        raise RuntimeError("internal-exception-marker-must-not-render")


def test_unhandled_exception_response_is_generic_and_sanitized(tmp_path: Path) -> None:
    db_path = tmp_path / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path)
    service = ExplodingHealthService(db_path, core)
    application = create_app(service=service)

    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/api/system/health")

    assert response.status_code == 500
    assert response.json() == {
        "error": "internal_error",
        "message": "Request could not be completed.",
    }
    assert "internal-exception-marker" not in response.text
