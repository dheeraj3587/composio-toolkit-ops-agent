"""Offline regression tests for the Browser Use session hardening fixes:

F1 - a live run on the base worker fails closed (loop-unsafe) unless the
     production loop-safe subclass is installed.
F3 - the terminal cleanup deletes the per-run profile, stops the session, and
     closes a worker-owned temporary client (an injected client is left open).
F5 - a run timeout is classified outcome_unknown and PRESERVES the session for
     reconciliation, while a generic error is a clean failure that stops it.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from api.assignment_runtime import AssignmentBrowserWorker
from ops.config import Settings
from ops.models import OperationalResearch
from ops.provider_errors import ConfigurationRequiredError, ProviderOperationError


def _settings() -> Settings:
    return Settings(browser_use_api_key=SecretStr("browser-test-key"), allow_live_browser=True)


def _research(slug: str = "hubspot") -> OperationalResearch:
    return OperationalResearch.model_validate(
        {
            "app_name": "HubSpot",
            "app_slug": slug,
            "api_available": True,
            "api_type": "REST",
            "api_base_url": None,
            "auth_methods": ["OAuth2"],
            "authorization_url": None,
            "token_url": None,
            "credential_fields": [],
            "scopes": [],
            "developer_portal_url": "https://developers.hubspot.com/",
            "signup_url": None,
            "access_route": "self_serve",
            "production_approval_required": None,
            "contact_email": None,
            "contact_url": None,
            "evidence_urls": ["https://developers.hubspot.com/docs"],
            "confidence": 0.9,
        }
    )


class _Sessions:
    def __init__(self) -> None:
        self.stopped: list[str] = []
        self.create_calls = 0

    async def create(self, **kwargs: object) -> dict[str, object]:
        del kwargs
        self.create_calls += 1
        return {"id": "provider-session-1", "live_url": "https://live.browser-use.example/s"}

    async def stop(self, session_id: str) -> None:
        self.stopped.append(session_id)


class _Profiles:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def create(self, **kwargs: object) -> dict[str, object]:
        del kwargs
        return {"id": "profile-1"}

    async def delete(self, profile_id: str) -> None:
        self.deleted.append(profile_id)


class _HardeningClient:
    def __init__(self, *, run_exc: Exception | None = None) -> None:
        self.sessions = _Sessions()
        self.profiles = _Profiles()
        self._run_exc = run_exc
        self.closed = False
        self.run_calls = 0

    def run(self, task: str, **kwargs: Any) -> dict[str, object]:
        del task, kwargs
        self.run_calls += 1
        if self._run_exc is not None:
            raise self._run_exc
        return {"current_url": "https://developers.hubspot.com/docs", "safe_summary": "ok"}

    async def close(self) -> None:
        self.closed = True


def _true_base_worker_cls() -> type:
    """Return the real base BrowserWorker class even if the module attribute was
    monkey-patched to the AssignmentBrowserWorker subclass by another test."""

    import ops.browser_worker as bw

    cls = bw.BrowserWorker
    if cls.__name__ != "BrowserWorker":
        cls = next(c for c in cls.__mro__ if c.__name__ == "BrowserWorker")
    return cls


# --- F1: base worker refuses a live run without the loop-safe patch ------------
def test_base_worker_live_without_patch_fails_closed() -> None:
    worker = _true_base_worker_cls()(settings=_settings())
    with pytest.raises(ConfigurationRequiredError) as excinfo:
        worker._require_configuration()
    assert excinfo.value.reason_code == "assignment_runtime_not_installed"


def test_base_worker_with_injected_client_is_exempt() -> None:
    worker = _true_base_worker_cls()(settings=_settings(), client=object())
    worker._require_configuration()  # injected client is loop-local per call: no raise


def test_assignment_worker_is_not_blocked_by_the_guard() -> None:
    worker = AssignmentBrowserWorker(settings=_settings())
    worker._require_configuration()  # loop-safe subclass: no raise


# --- F3: terminal cleanup deletes profile, stops session, closes owned client --
def test_safe_stop_deletes_profile_and_stops_session() -> None:
    client = _HardeningClient()
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)
    worker._provider_sessions["h"] = "sess-9"
    worker._profile_ids["h"] = "prof-9"

    asyncio.run(worker._safe_stop_handle("h"))

    assert client.sessions.stopped == ["sess-9"]
    assert client.profiles.deleted == ["prof-9"]  # profile no longer leaks
    assert client.closed is False  # an injected client is caller-owned


def test_close_if_owned_closes_only_worker_created_clients() -> None:
    injected = _HardeningClient()
    worker_with_injected = AssignmentBrowserWorker(settings=_settings(), client=injected)
    asyncio.run(worker_with_injected._close_if_owned(injected))
    assert injected.closed is False  # caller owns it

    temp = _HardeningClient()
    worker_no_client = AssignmentBrowserWorker(settings=_settings())
    asyncio.run(worker_no_client._close_if_owned(temp))
    assert temp.closed is True  # worker-created temporary -> closed


# --- F5: timeout is outcome_unknown (session preserved); generic error stops ---
def test_run_timeout_is_outcome_unknown_and_preserves_session() -> None:
    client = _HardeningClient(run_exc=httpx.ReadTimeout("slow"))
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)
    context = asyncio.run(worker.start(None))

    with pytest.raises(ProviderOperationError) as excinfo:
        asyncio.run(worker.navigate_onboarding(context, _research()))

    assert excinfo.value.reason_code == "provider_outcome_unknown"
    # The remote agent may still be running: the session must NOT be stopped.
    assert client.sessions.stopped == []


def test_run_generic_error_is_clean_failure_and_stops_session() -> None:
    client = _HardeningClient(run_exc=ValueError("boom"))
    worker = AssignmentBrowserWorker(settings=_settings(), client=client)
    context = asyncio.run(worker.start(None))

    with pytest.raises(ProviderOperationError) as excinfo:
        asyncio.run(worker.navigate_onboarding(context, _research()))

    assert excinfo.value.reason_code == "provider_request_failed"
    assert client.sessions.stopped == ["provider-session-1"]  # clean fail stops it
