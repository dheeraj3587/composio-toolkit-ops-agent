from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from browser_service.main import _storage_binding, create_app
from browser_service.models import CreateSessionRequest
from browser_service.settings import BrowserServiceSettings
from ops.app_recipes import get_app_recipe
from ops.browser_service_client import BrowserServiceClient
from ops.browser_session_capability import (
    CAPABILITY_HEADER,
    capability_digest,
    derive_browser_session_capability,
)
from ops.browser_worker import BrowserSessionContext
from ops.config import Settings
from ops.provider_errors import ConfigurationRequiredError

RPC_TOKEN = "browser-rpc-token-that-is-long-enough"
CAPABILITY_KEY = "browser-session-capability-test-key-32-chars"
OWNER = "browser-service"


class _FakeBrowserWorker:
    provider_name = "playwright"

    def __init__(self) -> None:
        self.started = 0
        self.stopped = 0

    async def start(
        self,
        profile_id: str | None,
        *,
        recipe: Any,
        **_: Any,
    ) -> BrowserSessionContext:
        self.started += 1
        now = datetime.now(UTC).isoformat()
        return BrowserSessionContext(
            profile_id=profile_id or f"profile-{self.started}",
            session_id=f"pw_{self.started}",
            live_view_available=False,
            allowed_domains=(),
            created_at=now,
            inactivity_expires_at=now,
            maximum_expires_at=now,
        )

    async def install_live_pixel_mask(
        self,
        _context: BrowserSessionContext,
        _app_slug: str,
        *,
        recipe: Any,
    ) -> bool:
        del recipe
        return True

    async def refresh_session_screenshot(
        self,
        _context: BrowserSessionContext,
        *,
        redact: bool = True,
    ) -> bytes:
        del redact
        return b"\x89PNG\r\n\x1a\n"

    async def stop(self, _context: BrowserSessionContext) -> None:
        self.stopped += 1


def _cap(scope: str, *, owner: str = OWNER) -> str:
    return derive_browser_session_capability(
        key=CAPABILITY_KEY,
        owner=owner,
        scope=scope,
    )


def _headers(scope: str | None, *, owner: str = OWNER) -> dict[str, str]:
    headers = {
        "X-Browser-Service-Token": RPC_TOKEN,
        "X-Browser-Session-Owner": owner,
    }
    if scope is not None:
        headers[CAPABILITY_HEADER] = _cap(scope, owner=owner)
    return headers


def _create_payload(scope: str) -> dict[str, Any]:
    recipe = get_app_recipe("pipedrive")
    assert recipe is not None
    return {
        "app_slug": "pipedrive",
        "secret_scope": scope,
        "account_ref": "shared-account",
        "recipe_snapshot": recipe.model_dump(mode="json"),
        "use_storage_state": False,
    }


def test_capability_derivation_is_stable_and_bound_to_owner_and_run() -> None:
    run_a = _cap("run-a")

    assert run_a == _cap("run-a")
    assert run_a != _cap("run-b")
    assert run_a != _cap("run-a", owner="another-owner")
    assert len(run_a) == 43
    assert len(capability_digest(run_a)) == 32


def test_authority_checks_execute_both_constant_time_comparisons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_service.auth as auth_module

    comparisons: list[tuple[str | bytes, str | bytes]] = []

    def compare(left: str | bytes, right: str | bytes) -> bool:
        comparisons.append((left, right))
        return False

    monkeypatch.setattr(auth_module.secrets, "compare_digest", compare)

    with pytest.raises(HTTPException) as excinfo:
        auth_module.assert_session_access(
            session_owner="expected-owner",
            caller_owner="wrong-owner",
            session_capability_digest=b"expected-digest",
            caller_capability_digest=b"wrong-digest",
        )

    assert excinfo.value.status_code == 404
    assert comparisons == [
        ("expected-owner", "wrong-owner"),
        (b"expected-digest", b"wrong-digest"),
    ]


def test_settings_reject_weak_placeholder_or_reused_capability_keys() -> None:
    with pytest.raises(ValidationError):
        Settings(ops_internal_api_token=SecretStr("short"))

    with pytest.raises(ValidationError):
        Settings(
            browser_secret_broker_token=SecretStr("replace-with-random-browser-secret-broker-token")
        )

    with pytest.raises(ValidationError):
        Settings(browser_session_capability_key=SecretStr("short"))

    with pytest.raises(ValidationError):
        Settings(
            browser_session_capability_key=SecretStr("replace-with-browser-session-capability-key")
        )

    with pytest.raises(ValidationError):
        Settings(
            browser_service_token=SecretStr(CAPABILITY_KEY),
            browser_session_capability_key=SecretStr(CAPABILITY_KEY),
        )

    with pytest.raises(ValidationError):
        Settings(
            ops_internal_api_token=SecretStr(CAPABILITY_KEY),
            browser_session_capability_key=SecretStr(CAPABILITY_KEY),
        )

    with pytest.raises(ValidationError):
        Settings(
            ops_internal_api_token=SecretStr(CAPABILITY_KEY),
            browser_service_token=SecretStr(CAPABILITY_KEY),
        )

    with pytest.raises(ValidationError):
        Settings(
            ops_internal_api_token=SecretStr(CAPABILITY_KEY),
            browser_secret_broker_token=SecretStr(CAPABILITY_KEY),
        )


@pytest.mark.parametrize(
    "token",
    (
        "short",
        "replace-with-random-browser-service-token",
        "change-me-browser-service-token-value",
        "example-browser-service-token-value",
    ),
)
def test_api_and_browser_service_reject_weak_rpc_tokens(token: str) -> None:
    with pytest.raises(ValidationError):
        Settings(browser_service_token=SecretStr(token))
    with pytest.raises(ValidationError):
        BrowserServiceSettings(service_token=SecretStr(token))


@pytest.mark.parametrize(
    "owner",
    (
        "two owners",
        "owner/path",
        "ténant",
        "owner\x7f",
        "x" * 201,
    ),
)
def test_settings_reject_an_owner_the_capability_transport_cannot_use(owner: str) -> None:
    with pytest.raises(ValidationError):
        Settings(browser_service_owner=owner)


def test_settings_normalizes_the_owner_once_before_capability_derivation() -> None:
    settings = Settings(browser_service_owner="  stable-owner  ")
    assert settings.browser_service_owner == "stable-owner"
    assert derive_browser_session_capability(
        key=CAPABILITY_KEY,
        owner=settings.browser_service_owner,
        scope="run-a",
    ) == derive_browser_session_capability(
        key=CAPABILITY_KEY,
        owner="stable-owner",
        scope="run-a",
    )


def test_client_sends_a_separate_run_bound_header_and_never_serializes_it() -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200,
            json={
                "session_id": request.url.path.rsplit("/", 1)[-1],
                "status": "active",
                "current_url": "about:blank",
                "pending_challenge": None,
                "blocked_reason": None,
            },
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
            client = BrowserServiceClient(
                base_url="https://browser.internal",
                token=SecretStr(RPC_TOKEN),
                owner=OWNER,
                capability_key=SecretStr(CAPABILITY_KEY),
                client=transport,
            )
            await client.session_status("bs_a", capability_scope="run-a")
            await client.session_status("bs_b", capability_scope="run-b")
            await client.session_status("bs_a", capability_scope="run-a")

    asyncio.run(scenario())

    caps = [request.headers[CAPABILITY_HEADER] for request in observed]
    assert caps == [_cap("run-a"), _cap("run-b"), _cap("run-a")]
    assert all(request.headers["X-Browser-Session-Owner"] == OWNER for request in observed)
    assert all(cap not in str(request.url) for request, cap in zip(observed, caps, strict=True))
    assert all(
        cap.encode() not in request.content for request, cap in zip(observed, caps, strict=True)
    )


def test_client_fails_closed_without_the_api_side_master_key() -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
            client = BrowserServiceClient(
                base_url="https://browser.internal",
                token=SecretStr(RPC_TOKEN),
                owner=OWNER,
                client=transport,
            )
            with pytest.raises(ConfigurationRequiredError):
                await client.session_status("bs_a", capability_scope="run-a")

    asyncio.run(scenario())
    assert called is False


def test_every_session_rpc_requires_the_matching_tenant_and_capability() -> None:
    worker = _FakeBrowserWorker()
    app = create_app(
        BrowserServiceSettings(
            service_token=SecretStr(RPC_TOKEN),
            max_sessions=4,
        )
    )
    app.state.worker = worker

    with TestClient(app) as client:
        missing = client.post(
            "/internal/browser/sessions",
            headers=_headers(None),
            json=_create_payload("run-a"),
        )
        assert missing.status_code == 400

        created_a = client.post(
            "/internal/browser/sessions",
            headers=_headers("run-a"),
            json=_create_payload("run-a"),
        )
        created_b = client.post(
            "/internal/browser/sessions",
            headers=_headers("run-b"),
            json=_create_payload("run-b"),
        )
        assert created_a.status_code == 201, created_a.text
        assert created_b.status_code == 201, created_b.text
        session_a = created_a.json()["session_id"]
        session_b = created_b.json()["session_id"]

        denied_requests = (
            ("GET", f"/internal/browser/sessions/{session_b}/status", None),
            ("POST", f"/internal/browser/sessions/{session_b}/navigate", {"research": {}}),
            (
                "POST",
                f"/internal/browser/sessions/{session_b}/resume",
                {"signal": "completed"},
            ),
            (
                "POST",
                f"/internal/browser/sessions/{session_b}/capture-credentials",
                {"broker_grant": "bsg_" + ("g" * 43)},
            ),
            ("GET", f"/internal/browser/sessions/{session_b}/screenshot", None),
            ("POST", f"/internal/browser/sessions/{session_b}/live-view", {}),
            ("DELETE", f"/internal/browser/sessions/{session_b}", None),
        )
        for method, path, payload in denied_requests:
            response = client.request(
                method,
                path,
                headers=_headers("run-a"),
                json=payload,
            )
            assert response.status_code == 404, (method, path, response.text)

        assert (
            client.get(
                f"/internal/browser/sessions/{session_b}/status",
                headers=_headers("run-b"),
            ).status_code
            == 200
        )

        reconciled_a = client.post(
            "/internal/browser/sessions/reconcile",
            headers=_headers("run-a"),
            json={
                "app_slug": "pipedrive",
                "secret_scope": "run-a",  # pragma: allowlist secret
                "account_ref": "shared-account",
            },
        )
        cross_run = client.post(
            "/internal/browser/sessions/reconcile",
            headers=_headers("run-a"),
            json={
                "app_slug": "pipedrive",
                "secret_scope": "run-b",  # pragma: allowlist secret
                "account_ref": "shared-account",
            },
        )
        assert reconciled_a.status_code == 200
        assert reconciled_a.json()["session_ids"] == [session_a]
        assert cross_run.status_code == 200
        assert cross_run.json()["session_ids"] == []

        assert (
            client.delete(
                f"/internal/browser/sessions/{session_a}",
                headers=_headers("run-a"),
            ).status_code
            == 200
        )
        assert (
            client.delete(
                f"/internal/browser/sessions/{session_b}",
                headers=_headers("run-b"),
            ).status_code
            == 200
        )


def test_master_key_is_only_in_the_api_container_environment() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = (root / "compose.prod.yaml").read_text(encoding="utf-8")
    marker = "BROWSER_SESSION_CAPABILITY_KEY:"

    assert sum(line.strip().startswith(marker) for line in compose.splitlines()) == 1
    api_block, remainder = compose.split("  api:", 1)[1].split("  browser-worker:", 1)
    assert marker in api_block
    assert marker not in remainder

    production_env = (root / ".env.production.example").read_text(encoding="utf-8")
    assert "BROWSER_SESSION_CAPABILITY_KEY=" in production_env


def test_managed_session_persists_only_a_digest_not_the_raw_capability() -> None:
    raw = _cap("run-a")
    from browser_service.session_manager import ManagedSession

    fields = ManagedSession.__dataclass_fields__
    assert "session_capability_digest" in fields
    assert "session_capability" not in fields

    serialized_fields = json.dumps(sorted(fields))
    assert raw not in serialized_fields


def test_cross_run_storage_state_reuse_stays_bound_to_static_owner_and_account() -> None:
    run_a = CreateSessionRequest(
        app_slug="pipedrive",
        secret_scope="run-a",  # pragma: allowlist secret
        account_ref="shared-account",
        use_storage_state=True,
    )
    run_b = CreateSessionRequest(
        app_slug="pipedrive",
        secret_scope="run-b",  # pragma: allowlist secret
        account_ref="shared-account",
        use_storage_state=True,
    )

    binding_a = _storage_binding(run_a, OWNER)
    binding_b = _storage_binding(run_b, OWNER)
    assert binding_a == binding_b
    assert binding_a.fingerprint() == binding_b.fingerprint()
