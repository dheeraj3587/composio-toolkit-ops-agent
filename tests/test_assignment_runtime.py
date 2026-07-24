"""Offline regression tests for the assignment live-execution bootstrap."""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import SecretStr

from api.assignment_runtime import (
    AssignmentBrowserWorker,
    _assignment_after_route,
    assignment_policy,
)
from ops.config import Settings
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest


class _FakeSessions:
    def __init__(self) -> None:
        self.create_calls = 0
        self.stopped: list[str] = []

    async def create(self, **kwargs: object) -> object:
        # Option A: the session is created up front so its live URL exists for the
        # whole task; the bounded onboarding task then runs against this session.
        del kwargs
        self.create_calls += 1
        return {
            "id": "provider-session-1",
            "live_url": "https://live.browser-use.example/session",
        }

    async def stop(self, session_id: str) -> None:
        self.stopped.append(session_id)


class _FakeClient:
    def __init__(self, outputs: list[dict[str, object]]) -> None:
        self.sessions = _FakeSessions()
        self.outputs = list(outputs)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, task: str, **kwargs: Any) -> dict[str, object]:
        self.calls.append((task, kwargs))
        return self.outputs.pop(0)


def _settings() -> Settings:
    return Settings(
        browser_use_api_key=SecretStr("browser-test-key"),
        allow_live_browser=True,
    )


def _research(slug: str = "hubspot", route: str = "self_serve") -> OperationalResearch:
    host = {
        "hubspot": "developers.hubspot.com",
        "salesforce": "developer.salesforce.com",
    }.get(slug, "developers.pipedrive.com")
    return OperationalResearch.model_validate(
        {
            "app_name": slug.replace("-", " ").title(),
            "app_slug": slug,
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["OAuth2"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": f"https://{host}/",
            "signup_url": None,
            "access_route": route,
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": [f"https://{host}/docs"],
            "confidence": 0.9,
        }
    )


def _output(*, hitl: bool = False) -> dict[str, object]:
    return {
        "session_id": "provider-session-1",
        "live_url": "https://live.browser-use.example/session",
        "output": {
            "current_url": "https://developers.hubspot.com/docs",
            "reached_official_setup_page": not hitl,
            "hitl_required": hitl,
            "hitl_reason": "Enter your password." if hitl else None,
            "safe_summary": "Official developer page reached.",
        },
    }


def test_assignment_matrix_activates_nine_browser_apps_and_keeps_sherlock_blocked() -> None:
    active = {
        "hubspot",
        "pipedrive",
        "attio",
        "twenty",
        "zendesk",
        "google-ads",
        "whatsapp-business",
        "salesforce",
        "close",
    }
    for slug in active:
        policy = assignment_policy(slug)
        assert policy is not None
        assert policy.active is True
        assert policy.exact_hosts or policy.vendor_wildcard_domains

    sherlock = assignment_policy("sherlock")
    assert sherlock is not None
    assert sherlock.active is False


def test_first_browser_operation_contains_task_and_provider_allowlist() -> None:
    client = _FakeClient([_output()])
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)

    context = asyncio.run(worker.start(None))
    observation = asyncio.run(worker.navigate_onboarding(context, _research()))

    # The live session is created up front, so the bounded task reuses it via
    # session_id (navigation target is carried in the task text, not start_url).
    assert client.sessions.create_calls == 1
    assert context.session_id == "provider-session-1"
    assert context.live_view_available is True
    assert len(client.calls) == 1
    task, kwargs = client.calls[0]
    assert kwargs["session_id"] == "provider-session-1"
    assert kwargs["allowed_domains"] == [
        "developers.hubspot.com",
        "app.hubspot.com",
    ]
    assert "STRICT APP TRACE: HubSpot" in task
    assert "Development" in task
    assert "DIVERGENCE:" in task
    assert "start_url" not in kwargs
    assert observation.status == "credential_page_ready"
    assert client.sessions.stopped == ["provider-session-1"]


def test_hitl_resume_reuses_the_same_provider_session() -> None:
    client = _FakeClient([_output(hitl=True), _output()])
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)

    context = asyncio.run(worker.start(None))
    first = asyncio.run(worker.navigate_onboarding(context, _research()))
    second = asyncio.run(worker.resume_after_hitl(context, "completed"))

    assert first.status == "human_action_required"
    assert second.status == "credential_page_ready"
    # One up-front session creation; both the first task and the HITL resume run
    # against that same provider session id.
    assert client.sessions.create_calls == 1
    assert len(client.calls) == 2
    assert client.calls[0][1]["session_id"] == "provider-session-1"
    assert client.calls[1][1]["session_id"] == "provider-session-1"
    assert client.sessions.stopped == ["provider-session-1"]


def test_assignment_route_uses_browser_for_gated_apps_but_not_blocked_apps() -> None:
    company = CompanyProfile(
        legal_name="Example Labs",
        website="https://example.com",
        work_email_ref="vault://company/work_email/test",
        use_case="Build an authorized integration.",
    )
    request = OperationsRequest(
        app_name="Salesforce",
        company=company,
        dry_run=False,
    )
    state = {
        "request": request.model_dump(mode="json"),
        "app_slug": "salesforce",
        "access_route": "partner_gated",
    }
    assert _assignment_after_route(object(), state) == "browser_start"

    blocked = {**state, "app_slug": "sherlock", "access_route": "blocked"}
    assert _assignment_after_route(object(), blocked) == "finalize"

    dry_run = {
        **state,
        "request": request.model_copy(update={"dry_run": True}).model_dump(mode="json"),
    }
    assert _assignment_after_route(object(), dry_run) == "finalize"
