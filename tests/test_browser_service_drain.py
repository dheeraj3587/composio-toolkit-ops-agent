from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from browser_service.main import create_app
from browser_service.session_manager import SessionManager, SessionUnavailable
from browser_service.settings import BrowserServiceSettings
from ops.browser.session_capability import (
    CAPABILITY_HEADER,
    capability_digest,
    derive_browser_session_capability,
)
from ops.recipes.app_recipes import get_app_recipe

RPC_TOKEN = "drain-test-browser-rpc-token-32-characters"
CAPABILITY_KEY = "drain-test-session-capability-key-32-chars"
OWNER = "browser-service"


def _manager(*, max_sessions: int = 4, closer: Any = None) -> SessionManager:
    return SessionManager(
        max_sessions=max_sessions,
        inactivity_seconds=900,
        maximum_age_seconds=3_600,
        drain_seconds=0.1,
        closer=closer,
    )


def _create(manager: SessionManager) -> Any:
    return manager.create(
        owner=OWNER,
        app_slug="pipedrive",
        live_view_mode="screenshot",
    )


def _rpc_headers(*, capability_scope: str | None = None) -> dict[str, str]:
    headers = {
        "X-Browser-Service-Token": RPC_TOKEN,
        "X-Browser-Session-Owner": OWNER,
    }
    if capability_scope is not None:
        headers[CAPABILITY_HEADER] = derive_browser_session_capability(
            key=CAPABILITY_KEY,
            owner=OWNER,
            scope=capability_scope,
        )
    return headers


def _race_create(manager: SessionManager, barrier: threading.Barrier) -> str:
    barrier.wait()
    try:
        _create(manager)
    except SessionUnavailable as exc:
        return exc.reason_code
    return "created"


def _race_drain(manager: SessionManager, barrier: threading.Barrier) -> None:
    barrier.wait()
    manager.begin_drain()


def test_drain_preserves_existing_sessions_and_undrain_reopens_admission() -> None:
    manager = _manager(max_sessions=2)
    existing = _create(manager)

    manager.begin_drain()
    assert manager.drain_status() == (False, 1, 2)
    with pytest.raises(SessionUnavailable) as excinfo:
        _create(manager)
    assert excinfo.value.reason_code == "service_draining"

    # Drain is only an admission gate. Existing work remains fully leasable.
    with manager.lease(existing.session_id) as leased:
        assert leased.session_id == existing.session_id

    manager.undrain()
    assert manager.accepting_new_sessions is True
    second = _create(manager)
    assert second.session_id != existing.session_id


def test_create_and_begin_drain_have_one_atomic_admission_order() -> None:
    # Exercise both lock contenders repeatedly. A create may linearize before the
    # drain and succeed, or after it and receive service_draining; no third state
    # or post-drain admission is allowed.
    for _ in range(50):
        manager = _manager(max_sessions=1)
        barrier = threading.Barrier(3)

        with ThreadPoolExecutor(max_workers=2) as pool:
            create_future = pool.submit(_race_create, manager, barrier)
            drain_future = pool.submit(_race_drain, manager, barrier)
            barrier.wait()
            outcome = create_future.result(timeout=2)
            drain_future.result(timeout=2)

        assert outcome in {"created", "service_draining"}
        assert manager.accepting_new_sessions is False
        with pytest.raises(SessionUnavailable) as excinfo:
            _create(manager)
        assert excinfo.value.reason_code == "service_draining"


def test_drain_endpoints_require_token_and_owner_but_not_run_capability() -> None:
    app = create_app(BrowserServiceSettings(service_token=SecretStr(RPC_TOKEN)))

    with TestClient(app) as client:
        assert client.get("/internal/drain").status_code == 401
        assert (
            client.get(
                "/internal/drain",
                headers={"X-Browser-Service-Token": RPC_TOKEN},
            ).status_code
            == 400
        )
        assert (
            client.get(
                "/internal/drain",
                headers={
                    "X-Browser-Service-Token": "wrong-token",
                    "X-Browser-Session-Owner": OWNER,
                },
            ).status_code
            == 401
        )

        initial = client.get("/internal/drain", headers=_rpc_headers())
        assert initial.status_code == 200
        assert initial.json() == {
            "accepting_new_sessions": True,
            "capacity_in_use": 0,
            "capacity_total": 2,
        }

        draining = client.post("/internal/drain", headers=_rpc_headers())
        assert draining.status_code == 200
        assert draining.json() == {
            "accepting_new_sessions": False,
            "capacity_in_use": 0,
            "capacity_total": 2,
        }

        reopened = client.delete("/internal/drain", headers=_rpc_headers())
        assert reopened.status_code == 200
        assert reopened.json() == {
            "accepting_new_sessions": True,
            "capacity_in_use": 0,
            "capacity_total": 2,
        }


def test_drained_create_is_fixed_503_while_existing_status_still_works() -> None:
    app = create_app(
        BrowserServiceSettings(
            service_token=SecretStr(RPC_TOKEN),
            max_sessions=2,
        )
    )
    scope = "run-existing"
    capability = derive_browser_session_capability(
        key=CAPABILITY_KEY,
        owner=OWNER,
        scope=scope,
    )
    existing = app.state.manager.create(
        owner=OWNER,
        app_slug="pipedrive",
        live_view_mode="screenshot",
        session_capability_digest=capability_digest(capability),
        secret_scope=scope,
        account_ref="shared-account",
    )
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None

    with TestClient(app) as client:
        assert client.post("/internal/drain", headers=_rpc_headers()).status_code == 200

        status_response = client.get(
            f"/internal/browser/sessions/{existing.session_id}/status",
            headers=_rpc_headers(capability_scope=scope),
        )
        assert status_response.status_code == 200

        create_response = client.post(
            "/internal/browser/sessions",
            headers=_rpc_headers(capability_scope="run-new"),
            json={
                "app_slug": "pipedrive",
                "recipe_snapshot": recipe.model_dump(mode="json"),
                "secret_scope": "run-new",  # pragma: allowlist secret
                "account_ref": "shared-account",
            },
        )
        assert create_response.status_code == 503
        assert create_response.json() == {"detail": "service_draining"}


def test_close_all_starts_all_session_teardowns_concurrently() -> None:
    async def scenario() -> None:
        gate = asyncio.Event()
        every_closer_started = asyncio.Event()
        active = 0
        max_active = 0

        async def closer(_session: Any) -> None:
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            if active == 3:
                every_closer_started.set()
            await gate.wait()
            active -= 1

        manager = _manager(max_sessions=3, closer=closer)
        for _ in range(3):
            _create(manager)

        closing = asyncio.create_task(manager.close_all())
        await asyncio.wait_for(every_closer_started.wait(), timeout=1)
        assert max_active == 3
        gate.set()
        await asyncio.wait_for(closing, timeout=1)
        assert manager.capacity_in_use == 0
        assert manager.all_sessions() == ()

    asyncio.run(scenario())
