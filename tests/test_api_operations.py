"""Production API contracts added for the operations control plane."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.app import create_app
from api.models import CreateRunRequest


def _payload(app_name: str = "HubSpot") -> dict[str, object]:
    return {
        "app_name": app_name,
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/operator",
            "use_case": "Evaluate official integration access.",
            "callback_urls": ["https://example.test/oauth/callback"],
        },
        "requested_scope_policy": "maximum",
        "dry_run": True,
    }


def test_catalog_search_and_research_are_verified_safe_projections(tmp_path: Path) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        search = client.get("/api/apps/search", params={"q": "HubSpot"})
        research = client.get("/api/apps/hubspot/research")

    assert search.status_code == 200
    assert search.json()["total"] == 1
    assert search.json()["items"][0]["app_slug"] == "hubspot"
    assert research.status_code == 200
    payload = research.json()
    assert payload["app"]["app_slug"] == "hubspot"
    assert payload["research"]["access_route"] == "self_serve"
    assert payload["provenance"]["verified"] is True
    rendered = research.text.casefold()
    assert "database" not in rendered
    assert "environment" not in rendered


def test_app_research_response_includes_explicit_nullable_fields(tmp_path: Path) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        response = client.get("/api/apps/github/research")

    assert response.status_code == 200
    research = response.json()["research"]
    for field in {
        "api_available",
        "api_base_url",
        "authorization_url",
        "token_url",
        "developer_portal_url",
        "signup_url",
        "production_approval_required",
        "contact_email",
        "contact_url",
    }:
        assert field in research
        assert research[field] is None


def test_api_routes_require_internal_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPS_INTERNAL_API_TOKEN", "expected-internal-token")
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        client.headers.pop("X-Ops-Internal-Token", None)
        missing = client.get("/api/system/health")
        wrong = client.get(
            "/api/system/health",
            headers={"X-Ops-Internal-Token": "wrong-internal-token"},
        )
        valid = client.get(
            "/api/system/health",
            headers={"X-Ops-Internal-Token": "expected-internal-token"},
        )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert valid.status_code == 200
    assert missing.json() == {
        "error": "unauthorized",
        "message": "Internal API token is required.",
    }


def test_run_detail_explains_route_and_configuration_without_claiming_success(
    tmp_path: Path,
) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        created = client.post("/api/runs", json=_payload())

    assert created.status_code == 201
    body = created.json()
    assert body["route_decision"]["reason_code"] == "managed_connection_required"
    assert body["route_decision"]["is_final"] is True
    assert body["missing_fields"] == []
    assert body["run"]["external_actions"] is False
    recipes = next(item for item in body["provider_states"] if item["provider"] == "recipes")
    assert recipes["status"] == "ready"
    managed = next(
        item for item in body["provider_states"] if item["provider"] == "composio_managed_auth"
    )
    assert managed["status"] == "not_configured"
    assert all(
        phase["status"] != "complete"
        for phase in body["phases"]
        if phase["key"] in {"browser", "email", "output"}
    )


def test_plan_only_retry_is_rejected_without_external_action(
    tmp_path: Path,
) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        created = client.post("/api/runs", json=_payload()).json()
        run_id = created["run"]["run_id"]
        response = client.post(
            f"/api/runs/{run_id}/retry",
            json={"capability": "email"},
        )

    assert response.status_code == 409
    assert response.json()["error"] == "phase_unavailable"
    assert response.json()["action"] == "retry"
    assert response.json()["external_actions"] is False


def test_docs_and_cors_are_explicit_configuration(tmp_path: Path) -> None:
    disabled = create_app(db_path=tmp_path / "a" / "ops.db", enable_docs=False)
    with TestClient(disabled) as client:
        assert client.get("/docs").status_code == 404
        response = client.get(
            "/api/system/health",
            headers={"Origin": "https://console.example.test"},
        )
        assert "access-control-allow-origin" not in response.headers

    enabled = create_app(
        db_path=tmp_path / "b" / "ops.db",
        enable_docs=True,
        cors_origins=["https://console.example.test"],
    )
    with TestClient(enabled) as client:
        assert client.get("/docs").status_code == 200
        response = client.get(
            "/api/system/health",
            headers={"Origin": "https://console.example.test"},
        )
        assert response.headers["access-control-allow-origin"] == "https://console.example.test"


def test_app_and_retry_inputs_are_strict(tmp_path: Path) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        app = client.get("/api/apps/INVALID%20SLUG/research")
        created = client.post("/api/runs", json=_payload()).json()
        retry = client.post(
            f"/api/runs/{created['run']['run_id']}/retry",
            json={"capability": "email", "unknown": True},
        )

    assert app.status_code == 422
    assert app.json()["fields"] == ["path.app_slug"]
    assert retry.status_code == 422
    assert retry.json()["fields"] == ["unknown_field"]


def _request_payload(**overrides: object) -> dict[str, object]:
    """A valid create-run body with neither dry_run nor execution_mode set."""

    payload: dict[str, object] = {
        "app_name": "HubSpot",
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/operator",
            "use_case": "Evaluate official integration access.",
            "callback_urls": ["https://example.test/oauth/callback"],
        },
        "requested_scope_policy": "maximum",
    }
    payload.update(overrides)
    return payload


def test_execution_mode_defaults_to_plan_only() -> None:
    request = CreateRunRequest.model_validate(_request_payload())
    assert request.execution_mode == "plan_only"


def test_browser_provider_defaults_to_browser_use_for_legacy_clients() -> None:
    request = CreateRunRequest.model_validate(_request_payload())
    assert request.browser_provider == "browser_use"


def test_credential_creation_policy_defaults_to_reuse_only_for_legacy_clients() -> None:
    request = CreateRunRequest.model_validate(_request_payload())
    assert request.credential_creation_policy == "reuse_only"


@pytest.mark.parametrize("policy", ["reuse_only", "create_if_missing"])
def test_credential_creation_policy_accepts_canonical_values(policy: str) -> None:
    request = CreateRunRequest.model_validate(_request_payload(credential_creation_policy=policy))
    assert request.credential_creation_policy == policy


def test_credential_creation_policy_rejects_unknown_values() -> None:
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(
            _request_payload(credential_creation_policy="always_create")
        )


@pytest.mark.parametrize("provider", ["browser_use", "playwright"])
def test_browser_provider_accepts_both_canonical_values(provider: str) -> None:
    request = CreateRunRequest.model_validate(_request_payload(browser_provider=provider))
    assert request.browser_provider == provider


def test_browser_provider_rejects_unknown_values() -> None:
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(_request_payload(browser_provider="automatic"))


def test_dry_run_true_normalizes_to_plan_only() -> None:
    request = CreateRunRequest.model_validate(_request_payload(dry_run=True))
    assert request.execution_mode == "plan_only"
    # The deprecated alias is never rewritten from execution_mode.
    assert request.dry_run is True


def test_execute_when_configured_is_accepted_without_dry_run() -> None:
    request = CreateRunRequest.model_validate(
        _request_payload(execution_mode="execute_when_configured")
    )
    assert request.execution_mode == "execute_when_configured"


def test_dry_run_false_does_not_imply_execute_when_configured() -> None:
    request = CreateRunRequest.model_validate(_request_payload(dry_run=False))
    assert request.execution_mode == "plan_only"
    assert request.dry_run is False


def test_dry_run_alias_conflict_is_rejected_at_the_model() -> None:
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(
            _request_payload(dry_run=True, execution_mode="execute_when_configured")
        )


def test_dry_run_alias_conflicts_with_execute_mode(tmp_path: Path) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        response = client.post(
            "/api/runs",
            json=_payload() | {"execution_mode": "execute_when_configured"},
        )

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


def test_create_run_rejects_unknown_fields(tmp_path: Path) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        response = client.post("/api/runs", json=_payload() | {"unknown": True})

    assert response.status_code == 422
    assert response.json()["fields"] == ["unknown_field"]


def test_execute_when_configured_via_api_waits_for_managed_connection_without_key(
    tmp_path: Path,
) -> None:
    from api.service import LocalRunService
    from ops.config import Settings

    service = LocalRunService(db_path=tmp_path / "private" / "ops.db", settings=Settings())
    application = create_app(service=service)
    with TestClient(application) as client:
        response = client.post(
            "/api/runs",
            json=_request_payload(execution_mode="execute_when_configured"),
        )

    assert response.status_code == 201
    run = response.json()["run"]
    assert run["execution_mode"] == "execute_when_configured"
    assert run["status"] == "connection_required"
    assert run["state_engine"] == "canonical_v1"
    assert run["route_kind"] == "managed_auth"
    assert run["status"] != "accepted"
    assert run["external_actions"] is False


def test_execute_when_configured_does_not_put_langgraph_on_the_new_run_path(
    tmp_path: Path,
) -> None:
    from pydantic import SecretStr

    from api.service import LocalRunService
    from ops.config import Settings

    settings = Settings(
        langgraph_aes_key=SecretStr("0" * 32),
        checkpoint_db_path=tmp_path / "private" / "checkpoints.db",
    )
    service = LocalRunService(db_path=tmp_path / "private" / "ops.db", settings=settings)
    application = create_app(service=service)
    with TestClient(application) as client:
        response = client.post(
            "/api/runs",
            json=_request_payload(execution_mode="execute_when_configured"),
        )

    assert response.status_code == 201
    run = response.json()["run"]
    assert run["execution_mode"] == "execute_when_configured"
    assert run["state_engine"] == "canonical_v1"
    assert run["status"] == "connection_required"
    assert run["status"] != "accepted"
    assert run["external_actions"] is False
    assert not settings.checkpoint_db_path.exists()


def test_run_conflict_is_mapped_to_http_409(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ops.run_service import RunConflictError

    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        created = client.post("/api/runs", json=_payload()).json()
        run_id = created["run"]["run_id"]

        async def _raise_conflict(
            target_run_id: str, *, browser_login: object = None, signal: str = "completed"
        ) -> object:
            del browser_login, signal
            raise RunConflictError(target_run_id, "resume")

        monkeypatch.setattr(application.state.run_service, "resume", _raise_conflict)
        response = client.post(f"/api/runs/{run_id}/resume")

    assert response.status_code == 409
    body = response.json()
    assert body["error"] == "run_conflict"
    assert body["run_id"] == run_id
    assert body["external_actions"] is False


def test_api_package_does_not_import_ops_graph_directly() -> None:
    import ast

    api_dir = Path(__file__).resolve().parents[1] / "api"
    for path in sorted(api_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not alias.name.startswith("ops.graph") for alias in node.names), (
                    path.name
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module != "ops.graph", path.name
                assert not node.module.startswith("ops.graph."), path.name
