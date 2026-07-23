"""Offline tests for assignment live-session retention and readiness projection."""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import SecretStr

from api.assignment_live_evidence import (
    _assignment_provider_states,
    _retained_run_assignment_task,
)
from api.assignment_runtime import AssignmentBrowserWorker
from api.service import LocalRunService
from ops.config import Settings
from ops.models import OperationalResearch


class _FakeSessions:
    def __init__(self) -> None:
        self.stopped: list[str] = []

    async def get(self, session_id: str) -> dict[str, object]:
        return {
            "id": session_id,
            "live_url": "https://live.browser-use.example/session",
        }

    async def stop(self, session_id: str) -> None:
        self.stopped.append(session_id)


class _FakeClient:
    def __init__(self, output: dict[str, object]) -> None:
        self.sessions = _FakeSessions()
        self.output = output
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, task: str, **kwargs: Any) -> dict[str, object]:
        self.calls.append((task, kwargs))
        return dict(self.output)


class _FakeCoreService:
    def wiring_audit(self) -> list[dict[str, object]]:
        return [
            {"dependency": "workflow", "runtime_wired": True},
            {"dependency": "secret_store", "runtime_wired": True},
            {"dependency": "research_enricher", "runtime_wired": True},
            {"dependency": "composio_preflight", "runtime_wired": True},
            {"dependency": "browser", "runtime_wired": True},
        ]


def _settings() -> Settings:
    return Settings(
        langgraph_aes_key=SecretStr("0123456789abcdef0123456789abcdef"),
        secret_vault_key=SecretStr("vault-test-key"),
        perplexity_api_key=SecretStr("perplexity-test-key"),
        google_genai_api_key=SecretStr("gemini-test-key"),
        composio_api_key=SecretStr("composio-test-key"),
        browser_use_api_key=SecretStr("browser-test-key"),
        allow_live_browser=True,
    )


def _research() -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": "Pipedrive",
            "app_slug": "pipedrive",
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["OAuth2", "API Key"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": "https://developers.pipedrive.com/",
            "signup_url": None,
            "access_route": "self_serve",
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": ["https://developers.pipedrive.com/docs/api/v1"],
            "confidence": 0.95,
        }
    )


def test_successful_assignment_task_retains_live_session_until_explicit_stop() -> None:
    client = _FakeClient(
        {
            "id": "provider-session-1",
            "output": {
                "current_url": "https://app.pipedrive.com/settings/api",
                "reached_official_setup_page": True,
                "hitl_required": False,
                "hitl_reason": None,
                "safe_summary": "Pipedrive API settings reached.",
            },
        }
    )
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)
    context = asyncio.run(worker.start(None))

    observation = asyncio.run(
        _retained_run_assignment_task(
            worker,
            context=context,
            research=_research(),
            resume_signal=None,
        )
    )

    assert observation.status == "credential_page_ready"
    assert worker.live_url(context.session_id) == "https://live.browser-use.example/session"
    assert client.sessions.stopped == []
    assert client.calls[0][1]["keep_alive"] is True
    assert client.calls[0][1]["allowed_domains"] == [
        "developers.pipedrive.com",
        "app.pipedrive.com",
        "oauth.pipedrive.com",
        "*.pipedrive.com",
    ]
    assert "documentation page or developer landing page alone is not" in client.calls[0][0]

    asyncio.run(worker.stop(context))
    assert client.sessions.stopped == ["provider-session-1"]
    assert worker.live_url(context.session_id) is None


def test_assignment_provider_projection_marks_initialized_adapters_ready() -> None:
    service = LocalRunService(
        core_service=_FakeCoreService(),  # type: ignore[arg-type]
        settings=_settings(),
    )

    states = _assignment_provider_states(service)

    assert {state.provider: state.status for state in states} == {
        "langgraph": "ready",
        "vault": "ready",
        "perplexity": "ready",
        "gemini": "ready",
        "composio": "ready",
        "browser_use": "ready",
    }
