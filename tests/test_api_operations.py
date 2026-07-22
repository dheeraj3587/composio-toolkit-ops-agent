"""Production API contracts added for the operations control plane."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app


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


def test_run_detail_explains_route_and_configuration_without_claiming_success(
    tmp_path: Path,
) -> None:
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        created = client.post("/api/runs", json=_payload())

    assert created.status_code == 201
    body = created.json()
    assert body["route_decision"]["reason_code"] == "verified_evidence_route"
    assert body["route_decision"]["is_final"] is True
    assert body["missing_fields"]
    assert body["run"]["external_actions"] is False
    assert all(item["status"] != "ready" for item in body["provider_states"])
    assert all(
        phase["status"] != "complete"
        for phase in body["phases"]
        if phase["key"] in {"browser", "email", "output"}
    )


def test_retry_returns_typed_configuration_required_without_external_action(
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

    assert response.status_code == 200
    assert response.json() == {
        "run_id": run_id,
        "action": "retry",
        "status": "configuration_required",
        "detail": "Required provider configuration or policy opt-in is missing.",
    }


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
