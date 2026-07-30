from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from typing import Any

import httpx
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app as create_api_app
from api.service import LocalRunService
from browser_service.main import create_app as create_browser_app
from browser_service.settings import BrowserServiceSettings
from ops.browser.readiness import BrowserReadiness, probe_playwright
from ops.browser.service_client import BrowserServiceClient, BrowserServiceHealth
from ops.core.config import Settings
from ops.runs.service import RunService as CoreRunService


def test_browser_health_is_cache_only_and_ready_owns_refresh(
    monkeypatch: Any,
) -> None:
    calls = {"count": 0}

    async def ready_probe(*, timeout_seconds: float = 30.0) -> BrowserReadiness:
        del timeout_seconds
        calls["count"] += 1
        return BrowserReadiness(
            status="ready",
            reason_code="chromium_launch_verified",
            detail="",
        )

    monkeypatch.setattr("ops.browser.readiness.probe_playwright", ready_probe)
    app = create_browser_app(
        BrowserServiceSettings(
            service_token=SecretStr("s" * 32),
            max_sessions=1,
        )
    )
    with TestClient(app) as client:
        assert calls["count"] == 1
        app.state.readiness.checked_at = 0.0
        cached = client.get("/internal/health")
        assert cached.status_code == 200
        assert calls["count"] == 1
        refreshed = client.get("/internal/ready")
        assert refreshed.status_code == 200
        assert calls["count"] == 2


def test_interactive_readiness_launches_headed_chromium(
    monkeypatch: Any,
) -> None:
    launch_options: dict[str, object] = {}

    class FakePage:
        async def set_content(self, value: str) -> None:
            del value

        async def title(self) -> str:
            return "readiness"

        async def screenshot(self, *, type: str) -> bytes:
            assert type == "png"
            return b"png"

    class FakeBrowser:
        async def new_page(self) -> FakePage:
            return FakePage()

        async def close(self) -> None:
            return None

    class FakeChromium:
        async def launch(self, **kwargs: object) -> FakeBrowser:
            launch_options.update(kwargs)
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        async def stop(self) -> None:
            return None

    class FakeStarter:
        async def start(self) -> FakePlaywright:
            return FakePlaywright()

    fake_module = SimpleNamespace(async_playwright=lambda: FakeStarter())
    real_import = importlib.import_module

    def import_module(name: str) -> object:
        return fake_module if name == "playwright.async_api" else real_import(name)

    monkeypatch.setattr(importlib, "import_module", import_module)
    monkeypatch.setattr(
        "ops.browser.readiness.Settings.from_env",
        lambda: SimpleNamespace(
            playwright_disable_sandbox=False,
            browser_interactive_hitl_enabled=True,
        ),
    )
    monkeypatch.setenv("DISPLAY", ":99")
    sentinel_names = {
        "BROWSER_SECRET_BROKER_TOKEN",
        "BROWSER_SERVICE_TOKEN",
        "BROWSER_STORAGE_STATE_KEY",
        "GROQ_API_KEY",
        "OPS_INTERNAL_API_TOKEN",
    }
    for index, name in enumerate(sorted(sentinel_names)):
        monkeypatch.setenv(name, f"readiness-sentinel-{index}")

    result = asyncio.run(probe_playwright(timeout_seconds=1.0))

    assert result.ok is True
    assert launch_options["headless"] is False
    assert launch_options["chromium_sandbox"] is True
    launch_environment = launch_options["env"]
    assert isinstance(launch_environment, dict)
    assert launch_environment["DISPLAY"] == ":99"
    assert sentinel_names.isdisjoint(launch_environment)


def test_browser_client_health_uses_tight_timeout_and_rejects_bad_payload() -> None:
    seen_timeout: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_timeout.update(request.extensions.get("timeout", {}))
        return httpx.Response(
            200,
            json={
                "state": "ready",
                "reason_code": "chromium_launch_verified",
                "version": "1.0.0",
                "chromium_installed": "yes",
                "context_launch_ok": True,
                "capacity_total": 1,
                "capacity_in_use": 0,
                "janitor_running": True,
            },
        )

    async def exercise() -> BrowserServiceHealth:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            service = BrowserServiceClient(
                base_url="http://browser-worker:8081",
                token="t" * 32,
                owner="production-owner",
                capability_key="c" * 32,
                client=client,
            )
            return await service.health(timeout_seconds=1.25)

    health = asyncio.run(exercise())

    assert health.state == "degraded"
    assert health.reason_code == "browser_service_health_invalid"
    assert seen_timeout
    assert max(float(value) for value in seen_timeout.values()) <= 1.25


def test_live_api_health_fails_closed_with_actual_browser_cache_state(
    tmp_path: Any,
    monkeypatch: Any,
) -> None:
    settings = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        browser_service_url="http://browser-worker:8081",
        browser_service_token=SecretStr("t" * 32),
        browser_session_capability_key=SecretStr("c" * 32),
        browser_service_owner="production-owner",
    )
    db_path = tmp_path / "private" / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path, settings=settings)
    service = LocalRunService(db_path, core_service=core, settings=settings)

    async def degraded() -> BrowserServiceHealth:
        return BrowserServiceHealth(
            state="degraded",
            reason_code="interactive_display_stack_unavailable",
            version="1.0.0",
            chromium_installed=True,
            context_launch_ok=False,
            capacity_total=2,
            capacity_in_use=0,
            janitor_running=True,
        )

    monkeypatch.setattr(service, "_cached_browser_service_health", degraded)
    with TestClient(create_api_app(service=service)) as client:
        response = client.get("/api/system/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert {
        "name": "browser_service_cached_readiness",
        "status": "fail",
    } in payload["checks"]
    assert payload["browser_service"] == {
        "state": "degraded",
        "reason_code": "interactive_display_stack_unavailable",
        "version": "1.0.0",
        "chromium_installed": True,
        "context_launch_ok": False,
        "capacity_total": 2,
        "capacity_in_use": 0,
        "janitor_running": True,
    }
    playwright = next(
        provider for provider in payload["providers"] if provider["provider"] == "playwright"
    )
    assert playwright["status"] == "configured_not_verified"
    assert "version=1.0.0" in playwright["detail"]
