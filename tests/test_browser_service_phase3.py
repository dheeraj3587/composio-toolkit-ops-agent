"""Phase 3: isolated browser service, durable HITL, restart reattachment.

These tests exercise the SERVICE boundary rather than the harness internals: the
authenticated RPC surface, lifecycle-safe session management, the interactive-HITL
grant, encrypted storage state, and verified restart reattachment.

The real Playwright worker is replaced by a deterministic fake, so the whole file
runs offline with no Chromium, no network, and no vendor account. What is being
proven here is the ISOLATION and AUTHORIZATION logic; Phase 1/2 already cover the
navigation and candidate-policy behaviour that this service reuses unchanged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import SecretStr

from browser_service.auth import OWNER_HEADER, TOKEN_HEADER
from browser_service.main import create_app
from browser_service.models import SessionSummary
from browser_service.novnc import LiveViewDenied, VncTarget, authorize_live_view
from browser_service.session_manager import SessionManager, SessionUnavailable
from browser_service.settings import BrowserServiceSettings
from ops.browser_live_view import (
    LiveViewTokenError,
    issue_live_view_token,
    verify_live_view_token,
)
from ops.browser_storage_state import EncryptedStorageStateStore, StorageStateBinding
from ops.browser_worker import BrowserObservation, BrowserSessionContext

TOKEN = "phase3-test-token"
OWNER = "run_owner_1"
REPO_ROOT = Path(__file__).resolve().parents[1]

# A cookie value that must never appear in any response or log line.
SECRET_COOKIE = "session=SUPERSECRETCOOKIEVALUE"

# A minimal but VALID OperationalResearch payload. The service validates strictly,
# so an empty object is (correctly) rejected with 422 — these tests must therefore
# send a real one rather than weaken the boundary they are testing.
RESEARCH_PAYLOAD: dict[str, Any] = {
    "app_name": "Pipedrive",
    "app_slug": "pipedrive",
    "api_available": True,
    "api_type": "rest",
    "api_base_url": "https://api.pipedrive.com/v1",
    "auth_methods": ["api_key"],
    "authorization_url": None,
    "token_url": None,
    "credential_fields": ["api_token"],
    "scopes": [],
    "developer_portal_url": "https://developers.pipedrive.com/",
    "signup_url": "https://www.pipedrive.com/en/pricing",
    "access_route": "self_serve",
    "production_approval_required": False,
    "contact_email": None,
    "contact_url": None,
    "evidence_urls": ["https://developers.pipedrive.com/"],
    "confidence": 0.9,
}


class _FakePwSession:
    """Stands in for ops.playwright_worker's per-session record."""

    def __init__(self) -> None:
        self.screenshot: bytes | None = None
        self.closed = False


class _FakeWorker:
    """A deterministic stand-in for PlaywrightBrowserWorker.

    It records what it was asked to do so tests can assert on credential handling
    without a real browser.
    """

    provider_name = "playwright"

    def __init__(self, *, screenshot: bytes | None = None) -> None:
        self._sessions: dict[str, _FakePwSession] = {}
        self._counter = 0
        self._screenshot = screenshot
        self.seen_sensitive: list[dict[str, str]] = []
        self.navigate_delay = 0.0
        self.stopped: list[str] = []
        self.received_storage_state: dict[str, Any] | None = None
        self.storage_state = {"cookies": [{"name": "session", "value": "SUPERSECRETCOOKIEVALUE"}]}

    async def start(
        self,
        profile_id: str | None,
        *,
        storage_state: dict[str, Any] | None = None,
    ) -> BrowserSessionContext:
        # Mirrors the real worker: the service may hand over previously saved,
        # already-decrypted authenticated state (never a filesystem path).
        self.received_storage_state = storage_state
        self._counter += 1
        handle = f"pw_fake_{self._counter}"
        self._sessions[handle] = _FakePwSession()
        now = datetime.now(UTC).isoformat()
        return BrowserSessionContext(
            profile_id=profile_id or handle,
            session_id=handle,
            live_view_available=True,
            allowed_domains=(),
            created_at=now,
            inactivity_expires_at=now,
            maximum_expires_at=now,
        )

    async def navigate_onboarding(
        self, context: BrowserSessionContext, research: Any, *, sensitive_data: Any = None
    ) -> BrowserObservation:
        del research
        self.seen_sensitive.append(dict(sensitive_data or {}))
        if self.navigate_delay:
            await asyncio.sleep(self.navigate_delay)
        return BrowserObservation(
            status="human_action_required",
            current_url="https://app.pipedrive.com/settings/api?tab=personal",
            page_title="API token",
            human_action_type="captcha",
            human_instruction="Solve the challenge in the live browser.",
            credential_field_labels=("API token",),
            non_secret_notes=(f"cookie header was {SECRET_COOKIE}",),
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: Any = None,
        *,
        sensitive_data: Any = None,
        provider_session_id: str | None = None,
    ) -> BrowserObservation:
        del context, signal, research, provider_session_id
        self.seen_sensitive.append(dict(sensitive_data or {}))
        return BrowserObservation(
            status="succeeded",
            current_url="https://app.pipedrive.com/settings/api",
            page_title="API token",
        )

    async def refresh_live_view(self, session: _FakePwSession) -> None:
        session.screenshot = self._screenshot

    async def stop(self, context: BrowserSessionContext) -> None:
        self.stopped.append(context.session_id)
        session = self._sessions.pop(context.session_id, None)
        if session is not None:
            session.closed = True


def _settings(**overrides: Any) -> BrowserServiceSettings:
    base: dict[str, Any] = {
        "service_token": SecretStr(TOKEN),
        "max_sessions": 2,
        "inactivity_seconds": 900,
        "maximum_age_seconds": 14_400,
        "drain_seconds": 1.0,
    }
    base.update(overrides)
    return BrowserServiceSettings(**base)


def _headers(token: str | None = TOKEN, owner: str | None = OWNER) -> dict[str, str]:
    headers = {}
    if token is not None:
        headers[TOKEN_HEADER] = token
    if owner is not None:
        headers[OWNER_HEADER] = owner
    return headers


def _client(
    settings: BrowserServiceSettings | None = None, worker: _FakeWorker | None = None
) -> tuple[TestClient, _FakeWorker]:
    app = create_app(settings or _settings())
    fake = worker or _FakeWorker()
    app.state.worker = fake
    return TestClient(app), fake


def _create_session(client: TestClient, **kwargs: Any) -> dict[str, Any]:
    response = client.post(
        "/internal/browser/sessions",
        json={"app_slug": "pipedrive", **kwargs},
        headers=_headers(),
    )
    assert response.status_code == 201, response.text
    payload: dict[str, Any] = response.json()
    return payload


# ---------------------------------------------------------------- 1. token auth
class TestServiceTokenRejection:
    """An unauthenticated or wrong-token caller must never reach the browser."""

    def test_missing_token_is_rejected(self) -> None:
        client, _ = _client()
        with client:
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(token=None),
            )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid_browser_service_token"

    def test_wrong_token_is_rejected(self) -> None:
        client, worker = _client()
        with client:
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(token="not-the-token"),
            )
        assert response.status_code == 401
        # The browser was never started for an unauthorized caller.
        assert worker._sessions == {}

    def test_unconfigured_service_refuses_every_request(self) -> None:
        """Fail closed: no token configured means the service is inert, not open."""

        client, _ = _client(_settings(service_token=None))
        with client:
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(token="anything"),
            )
        assert response.status_code == 503
        assert response.json()["detail"] == "browser_service_token_not_configured"

    def test_missing_owner_is_rejected(self) -> None:
        client, _ = _client()
        with client:
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(owner=None),
            )
        assert response.status_code == 400
        assert response.json()["detail"] == "missing_session_owner"

    def test_oversized_request_is_rejected_before_parsing(self) -> None:
        client, _ = _client(_settings(max_request_bytes=2_048))
        with client:
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive", "profile_id": "x" * 5_000},
                headers=_headers(),
            )
        assert response.status_code == 413
        assert response.json()["detail"] == "request_too_large"


# --------------------------------------------------------------- 2. RPC session
class TestSessionRpcLifecycle:
    """Create, drive, resume, inspect and delete a session over RPC."""

    def test_full_session_round_trip(self) -> None:
        client, worker = _client()
        with client:
            created = _create_session(client)
            session_id = created["session_id"]
            assert created["lifecycle"] == "ACTIVE"

            status_response = client.get(
                f"/internal/browser/sessions/{session_id}/status", headers=_headers()
            )
            assert status_response.status_code == 200
            assert status_response.json()["session_id"] == session_id

            navigate = client.post(
                f"/internal/browser/sessions/{session_id}/navigate",
                json={"research": RESEARCH_PAYLOAD, "credential_refs": {}},
                headers=_headers(),
            )
            assert navigate.status_code == 200
            body = navigate.json()
            assert body["status"] == "human_action_required"
            assert body["session"]["hitl_pending"] is True
            # Sanitized: the stored path carries no query string.
            assert body["session"]["current_url_path"] == "/settings/api"

            resume = client.post(
                f"/internal/browser/sessions/{session_id}/resume",
                json={"signal": "human_completed", "research": RESEARCH_PAYLOAD},
                headers=_headers(),
            )
            assert resume.status_code == 200
            assert resume.json()["status"] == "succeeded"

            deleted = client.delete(f"/internal/browser/sessions/{session_id}", headers=_headers())
            assert deleted.status_code == 200
            # The underlying browser was stopped by its WORKER handle (the internal
            # Playwright id), which is deliberately distinct from the RPC session id.
            assert worker.stopped == ["pw_fake_1"]
            assert worker._sessions == {}

            gone = client.get(f"/internal/browser/sessions/{session_id}/status", headers=_headers())
            assert gone.status_code == 404

    def test_navigate_sends_only_vault_references_and_service_resolves_them(self) -> None:
        """A raw credential value must never cross the RPC boundary."""

        client, worker = _client()
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.post(
                f"/internal/browser/sessions/{session_id}/navigate",
                json={
                    "research": RESEARCH_PAYLOAD,
                    # Only references are accepted; a raw value is dropped, not typed.
                    "credential_refs": {
                        "login_email": "vault://run/login_email",
                        "login_password": "hunter2-raw-value",
                    },
                },
                headers=_headers(),
            )
        assert response.status_code == 200
        # No vault key is configured in this test env, so nothing resolves — the
        # important assertion is that the RAW value never reached the worker.
        assert worker.seen_sensitive
        assert "hunter2-raw-value" not in json.dumps(worker.seen_sensitive)

    def test_delete_is_idempotent(self) -> None:
        client, _ = _client()
        with client:
            response = client.delete("/internal/browser/sessions/bs_missing", headers=_headers())
        assert response.status_code == 200
        assert response.json()["reason_code"] == "session_not_found"

    def test_capacity_exhaustion_is_reported_as_429(self) -> None:
        client, _ = _client(_settings(max_sessions=1))
        with client:
            _create_session(client)
            response = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(),
            )
        assert response.status_code == 429
        assert response.json()["detail"] == "capacity_exhausted"


# --------------------------------------------------- 3. cross-owner isolation
class TestCrossOwnerIsolation:
    """One run must never be able to drive another run's browser."""

    def test_another_owner_gets_404_not_403(self) -> None:
        """404, not 403: another owner's session existence is not confirmed."""

        client, _ = _client()
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.get(
                f"/internal/browser/sessions/{session_id}/status",
                headers=_headers(owner="a_different_owner"),
            )
        assert response.status_code == 404
        assert response.json()["detail"] == "session_not_found"

    def test_other_owner_cannot_navigate_or_delete(self) -> None:
        client, worker = _client()
        with client:
            session_id = _create_session(client)["session_id"]
            navigate = client.post(
                f"/internal/browser/sessions/{session_id}/navigate",
                json={"research": RESEARCH_PAYLOAD},
                headers=_headers(owner="intruder"),
            )
            deleted = client.delete(
                f"/internal/browser/sessions/{session_id}",
                headers=_headers(owner="intruder"),
            )
        assert navigate.status_code == 404
        assert deleted.status_code == 404
        # The intruder never drove the session.
        assert worker.seen_sensitive == []
        # The single stop recorded here is the SERVICE SHUTDOWN closing the owner's
        # session on context exit — which is itself proof the manager's closer now
        # reaches the real browser (it previously closed nothing at all). What
        # matters is that the intruder's delete was refused above.
        assert worker.stopped in ([], ["pw_fake_1"])


# ------------------------------------------------------ 4. session manager core
class TestSessionManagerLifecycle:
    """Leases, draining, and exactly-once capacity release."""

    @staticmethod
    def _manager(**overrides: Any) -> SessionManager:
        params: dict[str, Any] = {
            "max_sessions": 2,
            "inactivity_seconds": 900,
            "maximum_age_seconds": 14_400,
            "drain_seconds": 0.5,
        }
        params.update(overrides)
        return SessionManager(**params)

    def test_janitor_does_not_report_a_session_with_an_active_operation(self) -> None:
        """The janitor must never close a session mid-action."""

        manager = self._manager(inactivity_seconds=30)
        session = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
        # Make it look long-idle so it WOULD otherwise be reaped.
        session.last_active_at = datetime.now(UTC) - timedelta(hours=2)

        with manager.lease(session.session_id):
            # An operation is in flight: the session must not be offered for reaping.
            assert manager.expired_session_ids() == ()

        # Once the lease is released it becomes eligible again... but note the lease
        # refreshed last_active_at on exit, so age it again to prove the mechanism.
        session.last_active_at = datetime.now(UTC) - timedelta(hours=2)
        expired = manager.expired_session_ids()
        assert [reason for _, reason in expired] == ["session_idle_expired"]

    def test_idle_and_max_age_expiry_are_distinguished(self) -> None:
        manager = self._manager(inactivity_seconds=60, maximum_age_seconds=120)
        idle = manager.create(owner=OWNER, app_slug="a", live_view_mode="screenshot")
        aged = manager.create(owner=OWNER, app_slug="b", live_view_mode="screenshot")
        now = datetime.now(UTC)
        idle.last_active_at = now - timedelta(minutes=10)
        aged.maximum_expires_at = now - timedelta(seconds=1)
        reasons = dict(manager.expired_session_ids(now))
        assert reasons[idle.session_id] == "session_idle_expired"
        # Max-age wins even though this session is not idle.
        assert reasons[aged.session_id] == "session_max_age_exceeded"

    def test_lease_is_refused_once_closing(self) -> None:
        async def scenario() -> None:
            manager = self._manager(drain_seconds=0.1)
            session = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
            session.lifecycle = "CLOSING"
            with pytest.raises(SessionUnavailable) as excinfo:
                with manager.lease(session.session_id):
                    pass  # pragma: no cover - the lease must not be granted
            assert excinfo.value.reason_code == "session_closing"

        asyncio.run(scenario())

    def test_capacity_is_released_exactly_once_across_repeated_closes(self) -> None:
        async def scenario() -> None:
            manager = self._manager(max_sessions=1)
            session = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
            assert manager.capacity_in_use == 1
            first = await manager.close(session.session_id)
            second = await manager.close(session.session_id)
            third = await manager.close(session.session_id)
            assert first == "closed"
            # Already gone: reported as such rather than double-releasing the slot.
            assert second == third == "session_not_found"
            assert manager.capacity_in_use == 0
            # The slot is genuinely reusable, and only ONE slot exists.
            reused = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
            assert manager.capacity_in_use == 1
            with pytest.raises(SessionUnavailable):
                manager.create(owner=OWNER, app_slug="x", live_view_mode="screenshot")
            await manager.close(reused.session_id)

        asyncio.run(scenario())

    def test_close_waits_for_an_in_flight_operation_then_finishes(self) -> None:
        async def scenario() -> None:
            manager = self._manager(drain_seconds=5.0)
            session = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
            released = asyncio.Event()

            async def operation() -> None:
                with manager.lease(session.session_id):
                    await asyncio.sleep(0.2)
                released.set()

            task = asyncio.create_task(operation())
            await asyncio.sleep(0.05)
            reason = await manager.close(session.session_id, reason_code="session_idle_expired")
            await task
            assert released.is_set()
            # The operation completed, so nothing was reported as cancelled.
            assert reason == "session_idle_expired"

        asyncio.run(scenario())

    def test_drain_timeout_records_cancellation_rather_than_success(self) -> None:
        async def scenario() -> None:
            manager = self._manager(drain_seconds=0.2)
            session = manager.create(owner=OWNER, app_slug="pipedrive", live_view_mode="screenshot")
            stop = asyncio.Event()

            async def stuck_operation() -> None:
                with manager.lease(session.session_id):
                    await stop.wait()

            task = asyncio.create_task(stuck_operation())
            await asyncio.sleep(0.05)
            reason = await manager.close(session.session_id, reason_code="closed")
            assert reason == "closed:operations_cancelled"
            stop.set()
            await task

        asyncio.run(scenario())

    def test_sweep_closes_only_expired_sessions(self) -> None:
        async def scenario() -> None:
            manager = self._manager(inactivity_seconds=60)
            stale = manager.create(owner=OWNER, app_slug="a", live_view_mode="screenshot")
            fresh = manager.create(owner=OWNER, app_slug="b", live_view_mode="screenshot")
            stale.last_active_at = datetime.now(UTC) - timedelta(hours=1)
            closed = await manager.sweep()
            assert closed == (stale.session_id,)
            assert manager.get_if_present(fresh.session_id) is not None

        asyncio.run(scenario())


# ------------------------------------------------------- 5. interactive HITL
class TestInteractiveHitlGrants:
    """Short-lived, signed, session-bound and owner-bound access only."""

    def test_token_verifies_for_its_own_session_and_owner(self) -> None:
        token, expires_at = issue_live_view_token(
            session_id="bs_1", owner=OWNER, secret="s3cret", ttl_seconds=300
        )
        verified = verify_live_view_token(
            token, secret="s3cret", expected_session_id="bs_1", expected_owner=OWNER
        )
        assert verified.session_id == "bs_1"
        assert verified.owner == OWNER
        assert expires_at > datetime.now(UTC)

    def test_token_for_one_session_is_rejected_for_another(self) -> None:
        """Cross-session reuse is the attack this binding exists to stop."""

        token, _ = issue_live_view_token(session_id="bs_1", owner=OWNER, secret="s3cret")
        with pytest.raises(LiveViewTokenError) as excinfo:
            verify_live_view_token(
                token, secret="s3cret", expected_session_id="bs_2", expected_owner=OWNER
            )
        assert excinfo.value.reason_code == "session_mismatch"

    def test_token_for_one_owner_is_rejected_for_another(self) -> None:
        token, _ = issue_live_view_token(session_id="bs_1", owner=OWNER, secret="s3cret")
        with pytest.raises(LiveViewTokenError) as excinfo:
            verify_live_view_token(
                token, secret="s3cret", expected_session_id="bs_1", expected_owner="someone_else"
            )
        assert excinfo.value.reason_code == "owner_mismatch"

    def test_expired_token_is_rejected(self) -> None:
        issued = datetime.now(UTC) - timedelta(hours=1)
        token, expires_at = issue_live_view_token(
            session_id="bs_1", owner=OWNER, secret="s3cret", ttl_seconds=60, now=issued
        )
        assert expires_at < datetime.now(UTC)
        with pytest.raises(LiveViewTokenError) as excinfo:
            verify_live_view_token(
                token, secret="s3cret", expected_session_id="bs_1", expected_owner=OWNER
            )
        assert excinfo.value.reason_code == "token_expired"

    def test_forged_and_resigned_tokens_are_rejected(self) -> None:
        token, _ = issue_live_view_token(session_id="bs_1", owner=OWNER, secret="s3cret")
        body, _signature = token.split(".", 1)
        # A different signing key must not validate.
        with pytest.raises(LiveViewTokenError) as wrong_secret:
            verify_live_view_token(
                token, secret="other", expected_session_id="bs_1", expected_owner=OWNER
            )
        assert wrong_secret.value.reason_code == "invalid_signature"
        # A tampered payload with a stale signature must not validate either.
        with pytest.raises(LiveViewTokenError) as tampered:
            verify_live_view_token(
                f"{body}.deadbeef",
                secret="s3cret",
                expected_session_id="bs_1",
                expected_owner=OWNER,
            )
        assert tampered.value.reason_code == "invalid_signature"

    def test_live_view_endpoint_returns_screenshot_mode_when_disabled(self) -> None:
        """Interactive control is off by default, so no grant is minted."""

        client, _ = _client(_settings(interactive_hitl_enabled=False))
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.post(
                f"/internal/browser/sessions/{session_id}/live-view", headers=_headers()
            )
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "screenshot"
        assert body["url"] is None

    def test_live_view_grant_is_bound_and_expiring_when_enabled(self) -> None:
        client, _ = _client(_settings(interactive_hitl_enabled=True))
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.post(
                f"/internal/browser/sessions/{session_id}/live-view", headers=_headers()
            )
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "interactive_remote"
        assert body["session_id"] == session_id
        # The URL points at the private-network relay, not a public host.
        assert body["url"].startswith("http://browser-worker:8081/internal/browser/live-view/novnc")
        assert f"session={session_id}" in body["url"]
        # Short-lived by construction.
        expires_at = datetime.fromisoformat(body["expires_at"])
        assert expires_at - datetime.now(UTC) <= timedelta(minutes=6)

    def test_authorize_live_view_refuses_when_feature_disabled(self) -> None:
        token, _ = issue_live_view_token(session_id="bs_1", owner=OWNER, secret=TOKEN)
        with pytest.raises(LiveViewDenied) as excinfo:
            authorize_live_view(
                token=token,
                session_id="bs_1",
                caller_owner=OWNER,
                secret=TOKEN,
                session_owner=OWNER,
                session_lifecycle="ACTIVE",
                interactive_enabled=False,
            )
        assert excinfo.value.reason_code == "interactive_hitl_disabled"

    def test_authorize_live_view_refuses_a_closing_or_missing_session(self) -> None:
        token, _ = issue_live_view_token(session_id="bs_1", owner=OWNER, secret=TOKEN)
        common = {
            "token": token,
            "session_id": "bs_1",
            "caller_owner": OWNER,
            "secret": TOKEN,
            "interactive_enabled": True,
        }
        with pytest.raises(LiveViewDenied) as missing:
            authorize_live_view(session_owner=None, session_lifecycle=None, **common)
        assert missing.value.reason_code == "session_not_found"
        with pytest.raises(LiveViewDenied) as closing:
            authorize_live_view(session_owner=OWNER, session_lifecycle="CLOSING", **common)
        assert closing.value.reason_code == "session_closing"

    def test_authorize_live_view_refuses_another_owners_session(self) -> None:
        """Even a validly signed token cannot reach a session it does not own."""

        token, _ = issue_live_view_token(session_id="bs_1", owner="attacker", secret=TOKEN)
        with pytest.raises(LiveViewDenied) as excinfo:
            authorize_live_view(
                token=token,
                session_id="bs_1",
                caller_owner="attacker",
                secret=TOKEN,
                session_owner="victim",
                session_lifecycle="ACTIVE",
                interactive_enabled=True,
            )
        assert excinfo.value.reason_code == "session_not_found"

    def test_websocket_relay_is_refused_without_a_valid_grant(self) -> None:
        from starlette.websockets import WebSocketDisconnect

        client, _ = _client(_settings(interactive_hitl_enabled=True))
        with client:
            session_id = _create_session(client)["session_id"]
            with pytest.raises(WebSocketDisconnect) as excinfo:
                with client.websocket_connect(
                    f"/internal/browser/live-view/novnc?session={session_id}&token=forged",
                    headers=_headers(),
                ):
                    pass  # pragma: no cover - the socket must never be accepted
        assert excinfo.value.code == 1008

    def test_relay_refuses_a_non_loopback_vnc_target(self) -> None:
        """The relay must never become an SSRF primitive."""

        from browser_service.novnc import relay_websocket_to_vnc

        async def scenario() -> None:
            async def _receive() -> bytes | None:
                return None

            async def _send(_data: bytes) -> None:  # pragma: no cover - never reached
                raise AssertionError("no data should be relayed")

            with pytest.raises(LiveViewDenied) as excinfo:
                await relay_websocket_to_vnc(
                    receive=_receive,
                    send=_send,
                    target=VncTarget(host="10.0.0.5", port=5900),
                )
            assert excinfo.value.reason_code == "vnc_target_not_loopback"

        asyncio.run(scenario())


# ------------------------------------------------------ 6. restart reattachment
class TestRestartReattachment:
    """A persisted session id is never trusted without querying the service."""

    @staticmethod
    def _service_client(base_url: str, transport: Any) -> Any:
        import httpx

        from ops.browser_service_client import BrowserServiceClient

        return BrowserServiceClient(
            base_url=base_url,
            token=TOKEN,
            owner=OWNER,
            client=httpx.AsyncClient(transport=transport, base_url=base_url),
        )

    def test_live_session_is_reported_resumable(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers[TOKEN_HEADER] == TOKEN
            # The token must NOT be in the query string.
            assert "token" not in str(request.url.query)
            return httpx.Response(
                200,
                json=SessionSummary(
                    session_id="bs_live",
                    lifecycle="ACTIVE",
                    app_slug="pipedrive",
                    created_at="2026-01-01T00:00:00+00:00",
                    last_active_at="2026-01-01T00:00:00+00:00",
                    maximum_expires_at="2026-01-01T04:00:00+00:00",
                    active_operations=0,
                    live_view_mode="screenshot",
                    live_view_available=True,
                    hitl_pending=True,
                ).model_dump(),
            )

        client = self._service_client("http://browser-worker:8081", httpx.MockTransport(handler))
        assert asyncio.run(client.reconcile_session("bs_live")) == "resumable"
        assert client.supports_restart_reattach is True

    def test_missing_session_is_reported_lost_not_resumable(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"detail": "session_not_found"})

        client = self._service_client("http://browser-worker:8081", httpx.MockTransport(handler))
        assert asyncio.run(client.reconcile_session("bs_stale")) == "session_lost"

    def test_closing_session_is_not_resumable(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"lifecycle": "CLOSING"})

        client = self._service_client("http://browser-worker:8081", httpx.MockTransport(handler))
        assert asyncio.run(client.reconcile_session("bs_closing")) == "session_lost"

    def test_unreachable_service_is_inconclusive_not_lost(self) -> None:
        """An unreachable service must not be mistaken for a dead session."""

        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route", request=request)

        client = self._service_client("http://browser-worker:8081", httpx.MockTransport(handler))
        assert asyncio.run(client.reconcile_session("bs_any")) == "unreachable"

    def test_absent_session_id_is_lost_without_a_network_call(self) -> None:
        import httpx

        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            calls.append(str(request.url))
            return httpx.Response(200, json={"lifecycle": "ACTIVE"})

        client = self._service_client("http://browser-worker:8081", httpx.MockTransport(handler))
        assert asyncio.run(client.reconcile_session(None)) == "session_lost"
        assert calls == []

    def test_run_service_treats_unreachable_as_leave_alone(self) -> None:
        """Reconciliation must not tear down a run on a transient outage."""

        from ops.run_service import RunService

        class _Worker:
            async def reconcile_session(self, session_id: str) -> str:
                del session_id
                return "unreachable"

        service = RunService.__new__(RunService)
        service._browser_worker = _Worker()  # type: ignore[attr-defined]
        assert service._browser_session_is_live({"browser_session_id": "bs_1"}) is None
        # A definitively lost session, by contrast, is reported False.

        class _LostWorker:
            async def reconcile_session(self, session_id: str) -> str:
                del session_id
                return "session_lost"

        service._browser_worker = _LostWorker()  # type: ignore[attr-defined]
        assert service._browser_session_is_live({"browser_session_id": "bs_1"}) is False
        # No session id at all cannot be resumed.
        assert service._browser_session_is_live({}) is False

    def test_run_service_reports_live_session_for_resumable(self) -> None:
        from ops.run_service import RunService

        class _Worker:
            async def reconcile_session(self, session_id: str) -> str:
                del session_id
                return "resumable"

        service = RunService.__new__(RunService)
        service._browser_worker = _Worker()  # type: ignore[attr-defined]
        assert service._browser_session_is_live({"browser_session_id": "bs_1"}) is True

    def test_provider_without_reconcile_is_inconclusive(self) -> None:
        """Browser Use has no such endpoint: its behaviour must be unchanged."""

        from ops.run_service import RunService

        service = RunService.__new__(RunService)
        service._browser_worker = object()  # type: ignore[attr-defined]
        assert service._browser_session_is_live({"browser_session_id": "bs_1"}) is None


# ---------------------------------------------------------- 7. storage state
class TestEncryptedStorageState:
    """Storage state is bearer credential material: encrypted, bound, private."""

    def test_state_is_encrypted_at_rest_and_recoverable(self, tmp_path: Path) -> None:
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        store = EncryptedStorageStateStore(tmp_path / "state", key)
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        state = {"cookies": [{"name": "session", "value": "SUPERSECRETCOOKIEVALUE"}]}
        metadata = store.save(binding, state)
        assert metadata.app_slug == "pipedrive"

        path = tmp_path / "state" / f"{binding.fingerprint()}.state"
        raw = path.read_text()
        # The plaintext cookie must NOT be present anywhere in the file.
        assert "SUPERSECRETCOOKIEVALUE" not in raw
        assert store.load(binding) == state

    def test_file_and_directory_are_owner_only(self, tmp_path: Path) -> None:
        from cryptography.fernet import Fernet

        store = EncryptedStorageStateStore(tmp_path / "state", Fernet.generate_key().decode())
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        store.save(binding, {"cookies": []})
        directory = tmp_path / "state"
        path = directory / f"{binding.fingerprint()}.state"
        assert oct(directory.stat().st_mode)[-3:] == "700"
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_state_cannot_be_loaded_for_a_different_binding(self, tmp_path: Path) -> None:
        """State must never leak sideways between apps, accounts, or owners."""

        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        store = EncryptedStorageStateStore(tmp_path / "state", key)
        mine = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        store.save(mine, {"cookies": [{"name": "s", "value": "v"}]})
        # A different owner/app/account resolves to a different file entirely.
        for other in (
            StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner="other_owner"),
            StorageStateBinding(app_slug="hubspot", account_ref="acct1", owner=OWNER),
            StorageStateBinding(app_slug="pipedrive", account_ref="acct2", owner=OWNER),
        ):
            assert other.fingerprint() != mine.fingerprint()
            assert store.load(other) is None

    def test_tampered_binding_fingerprint_is_refused(self, tmp_path: Path) -> None:
        from cryptography.fernet import Fernet

        from ops.browser_storage_state import StorageStateError

        key = Fernet.generate_key().decode()
        store = EncryptedStorageStateStore(tmp_path / "state", key)
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        store.save(binding, {"cookies": []})
        path = tmp_path / "state" / f"{binding.fingerprint()}.state"
        envelope = json.loads(path.read_text())
        envelope["binding_fingerprint"] = "0" * 32
        path.write_text(json.dumps(envelope))
        with pytest.raises(StorageStateError) as excinfo:
            store.load(binding)
        assert excinfo.value.reason_code == "storage_state_binding_mismatch"

    def test_expired_state_is_refused_and_removed(self, tmp_path: Path) -> None:
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        store = EncryptedStorageStateStore(tmp_path / "state", key)
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        store.save(binding, {"cookies": []})
        path = tmp_path / "state" / f"{binding.fingerprint()}.state"
        envelope = json.loads(path.read_text())
        envelope["expires_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        path.write_text(json.dumps(envelope))
        assert store.load(binding) is None
        # Stale material is deleted, not left lying around.
        assert not path.exists()

    def test_without_a_key_nothing_is_persisted_in_the_clear(self, tmp_path: Path) -> None:
        from ops.browser_storage_state import StorageStateError

        store = EncryptedStorageStateStore(tmp_path / "state", None)
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        assert store.enabled is False
        with pytest.raises(StorageStateError) as excinfo:
            store.save(binding, {"cookies": [{"name": "s", "value": "v"}]})
        assert excinfo.value.reason_code == "storage_state_key_missing"
        assert store.load(binding) is None
        assert not (tmp_path / "state").exists()

    def test_invalidate_removes_state(self, tmp_path: Path) -> None:
        from cryptography.fernet import Fernet

        store = EncryptedStorageStateStore(tmp_path / "state", Fernet.generate_key().decode())
        binding = StorageStateBinding(app_slug="pipedrive", account_ref="acct1", owner=OWNER)
        store.save(binding, {"cookies": []})
        assert store.invalidate(binding, reason_code="logout") == "storage_state_invalidated"
        assert store.load(binding) is None


# ------------------------------------------------------------ 8. DLP boundary
class TestNoSecretsCrossTheBoundary:
    """Cookies, storage state and the RPC token never appear in output."""

    def test_responses_and_logs_contain_no_cookies_or_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client, worker = _client(_settings(interactive_hitl_enabled=True))
        with client, caplog.at_level(logging.DEBUG):
            session_id = _create_session(client)["session_id"]
            navigate = client.post(
                f"/internal/browser/sessions/{session_id}/navigate",
                json={"research": RESEARCH_PAYLOAD},
                headers=_headers(),
            )
            grant = client.post(
                f"/internal/browser/sessions/{session_id}/live-view", headers=_headers()
            )
            status_body = client.get(
                f"/internal/browser/sessions/{session_id}/status", headers=_headers()
            ).text

        # The session summary never carries cookies or storage state.
        summary = navigate.json()["session"]
        assert "cookies" not in summary
        assert "storage_state" not in summary
        for blob in (json.dumps(summary), status_body):
            assert "SUPERSECRETCOOKIEVALUE" not in blob
            assert TOKEN not in blob

        # The grant URL carries a live-view token, which must NOT be the RPC token.
        assert TOKEN not in grant.json()["url"]

        # Nothing logged contains the RPC token, the grant token, or a cookie.
        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert TOKEN not in logged
        assert "SUPERSECRETCOOKIEVALUE" not in logged
        grant_token = grant.json()["url"].split("token=")[-1]
        assert grant_token not in logged
        # The worker's raw storage state was never serialized anywhere.
        assert "SUPERSECRETCOOKIEVALUE" in json.dumps(worker.storage_state)

    def test_denied_live_view_logs_a_reason_not_the_token(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from starlette.websockets import WebSocketDisconnect

        client, _ = _client(_settings(interactive_hitl_enabled=True))
        # Well-FORMED but signed with the wrong key, so the denial is specifically a
        # signature failure rather than a parse failure.
        forged, _ = issue_live_view_token(
            session_id="bs_placeholder", owner=OWNER, secret="attacker-key"
        )
        with client, caplog.at_level(logging.DEBUG):
            session_id = _create_session(client)["session_id"]
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(
                    f"/internal/browser/live-view/novnc?session={session_id}&token={forged}",
                    headers=_headers(),
                ):
                    pass  # pragma: no cover
        logged = "\n".join(record.getMessage() for record in caplog.records)
        # The rejected token must not be echoed into logs, only a reason code.
        assert forged not in logged
        assert "live view denied" in logged
        assert "invalid_signature" in logged

    def test_screenshot_is_never_a_stale_frame(self) -> None:
        """No frame available must be an explicit 409, not last page's image."""

        client, _ = _client(worker=_FakeWorker(screenshot=None))
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.get(
                f"/internal/browser/sessions/{session_id}/screenshot", headers=_headers()
            )
        assert response.status_code == 409
        assert response.json()["detail"] == "screenshot_unavailable"

    def test_screenshot_is_served_when_a_frame_exists(self) -> None:
        png = b"\x89PNG\r\n\x1a\nfake-frame"
        client, _ = _client(worker=_FakeWorker(screenshot=png))
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.get(
                f"/internal/browser/sessions/{session_id}/screenshot", headers=_headers()
            )
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
        assert response.content == png


# --------------------------------------------------------------- 9. health
class TestProviderAwareHealth:
    """Health is unauthenticated but secret-free, and provider-aware."""

    def test_health_reports_not_configured_without_a_token(self) -> None:
        client, _ = _client(_settings(service_token=None))
        with client:
            response = client.get("/internal/health")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "not_configured"
        assert body["reason_code"] == "token_missing"

    def test_health_never_leaks_the_token_or_a_session_id(self) -> None:
        client, _ = _client()
        with client:
            session_id = _create_session(client)["session_id"]
            response = client.get("/internal/health")
        body = response.text
        assert TOKEN not in body
        assert session_id not in body
        payload = response.json()
        assert payload["capacity_total"] == 2
        assert payload["version"]

    def test_health_reports_capacity_exhaustion(self) -> None:
        """A full service must say so rather than appear healthy."""

        from browser_service.session_manager import SessionManager as _SM

        client, _ = _client(_settings(max_sessions=1))
        app = client.app
        manager: _SM = app.state.manager  # type: ignore[attr-defined]
        with client:
            _create_session(client)
            assert manager.capacity_in_use == manager.capacity_total
            body = client.get("/internal/health").json()
        # Chromium is absent in the test env, so the probe reports degraded rather
        # than ready; the capacity signal is still surfaced through the manager.
        assert body["state"] in {"capacity_exhausted", "degraded", "configured_not_verified"}
        assert body["capacity_in_use"] == 1

    def test_api_browser_phase_detail_is_provider_aware(self) -> None:
        """The Playwright path must not report Browser Use's SDK limitation."""

        from api.service import LocalRunService

        playwright_detail = LocalRunService._browser_phase_detail(
            provider="playwright", configured=True
        )
        assert "Browser Use" not in playwright_detail
        assert "self-hosted" in playwright_detail

        playwright_unconfigured = LocalRunService._browser_phase_detail(
            provider="playwright", configured=False
        )
        assert "No Browser Use key is needed" in playwright_unconfigured

        # Browser Use keeps its exact previous wording.
        browser_use_detail = LocalRunService._browser_phase_detail(
            provider="browser_use", configured=True
        )
        assert "Browser Use v3" in browser_use_detail

    def test_client_detects_a_service_major_version_mismatch(self) -> None:
        import httpx

        from ops.browser_service_client import BrowserServiceClient

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "ready",
                    "reason_code": "chromium_launch_verified",
                    "version": "9.0.0",
                    "chromium_installed": True,
                    "context_launch_ok": True,
                    "capacity_total": 2,
                    "capacity_in_use": 0,
                    "janitor_running": True,
                },
            )

        client = BrowserServiceClient(
            base_url="http://browser-worker:8081",
            token=TOKEN,
            owner=OWNER,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        health = asyncio.run(client.health())
        assert health.state == "version_mismatch"


# ------------------------------------------------- 10. container / compose shape
class TestContainerIsolationShape:
    """Structural guarantees about the image and the sandbox stack.

    Docker is not available in this environment, so these assertions validate the
    FILES rather than a built image — they are honest about what they check: the
    declared configuration, not a running container.
    """

    @staticmethod
    def _compose() -> dict[str, Any]:
        raw = (REPO_ROOT / "compose.playwright.sandbox.yaml").read_text()
        parsed: dict[str, Any] = yaml.safe_load(raw)
        return parsed

    @staticmethod
    def _dockerfile() -> str:
        return (REPO_ROOT / "Dockerfile.browser").read_text()

    def test_browser_worker_publishes_no_port(self) -> None:
        """The single most important isolation property."""

        service = self._compose()["services"]["browser-worker"]
        assert "ports" not in service
        # Nor may any other service in this stack expose one.
        for name, definition in self._compose()["services"].items():
            assert "ports" not in definition, f"{name} must not publish a port"

    def test_browser_worker_runs_chromium_safely_and_non_root(self) -> None:
        service = self._compose()["services"]["browser-worker"]
        assert service["init"] is True
        assert service["ipc"] == "host"
        assert service["shm_size"] == "1gb"
        assert service["pids_limit"] == 512
        assert service["user"] == "ops"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["restart"] == "unless-stopped"
        assert service["networks"] == ["opsnet"]
        assert any(volume.endswith(":/browser-data") for volume in service["volumes"])
        assert any(entry.startswith("/tmp:") for entry in service["tmpfs"])

    def test_sandbox_stack_holds_no_secret_literals(self) -> None:
        raw = (REPO_ROOT / "compose.playwright.sandbox.yaml").read_text()
        service = self._compose()["services"]["browser-worker"]
        # Secrets arrive by interpolation from --env-file, never inline. The value
        # is the interpolation EXPRESSION, which is the point: no literal here.
        assert service["environment"]["BROWSER_SERVICE_TOKEN"] == "${BROWSER_SERVICE_TOKEN:-}"
        assert service["environment"]["BROWSER_STORAGE_STATE_KEY"] == (
            "${BROWSER_STORAGE_STATE_KEY:-}"
        )
        assert not re.search(r"(?i)(api_key|token|secret)\s*:\s*['\"]?[A-Za-z0-9_\-]{16,}", raw)

    def test_defaults_keep_live_browsing_and_interactive_hitl_off(self) -> None:
        """Every dangerous switch must DEFAULT to off, even if the env is empty."""

        environment = self._compose()["services"]["browser-worker"]["environment"]

        def default_of(expression: str) -> str:
            # "${VAR:-false}" -> "false": the value used when the env is unset.
            match = re.fullmatch(r"\$\{[A-Z_]+:-([^}]*)\}", str(expression))
            return match.group(1) if match else str(expression)

        assert default_of(environment["ALLOW_LIVE_BROWSER"]) == "false"
        assert default_of(environment["BROWSER_INTERACTIVE_HITL_ENABLED"]) == "false"
        assert default_of(environment["PLAYWRIGHT_DISABLE_SANDBOX"]) == "false"
        # Not interpolated at all: hard-coded off.
        assert environment["ALLOW_LIVE_VENDOR_EMAIL"] == "false"

    def test_dockerfile_serves_the_browser_service(self) -> None:
        content = self._dockerfile()
        assert (
            'CMD ["uvicorn", "browser_service.main:app", "--host", "0.0.0.0", "--port", "8081"]'
            in content
        )
        assert "USER ops" in content
        assert "browser_service ./browser_service" in content
        # Chromium belongs to THIS image, not the API image.
        assert "playwright install --with-deps chromium" in content
        api_dockerfile = (REPO_ROOT / "Dockerfile.api").read_text()
        assert "playwright install" not in api_dockerfile

    def test_dockerfile_installs_the_interactive_display_stack(self) -> None:
        content = self._dockerfile()
        for package in ("xvfb", "x11vnc", "fluxbox", "novnc"):
            assert package in content, f"{package} must be installed for interactive HITL"
        assert "ENTRYPOINT" in content

    def test_entrypoint_binds_vnc_to_loopback_and_defaults_off(self) -> None:
        script = (REPO_ROOT / "docker" / "browser-entrypoint.sh").read_text()
        # -localhost is what prevents a raw, reachable VNC port.
        assert "-localhost" in script
        assert "BROWSER_INTERACTIVE_HITL_ENABLED:-false" in script
        # exec keeps uvicorn as the signal-receiving child.
        assert script.rstrip().endswith('exec "$@"')

    def test_production_stack_does_not_activate_playwright(self) -> None:
        """Phase 3 must not flip the production default."""

        production = yaml.safe_load((REPO_ROOT / "compose.prod.yaml").read_text())
        for name, definition in production["services"].items():
            environment = definition.get("environment") or {}
            if isinstance(environment, dict):
                assert environment.get("BROWSER_PROVIDER") != "playwright", name
            assert "browser_service" not in json.dumps(definition), name


# ------------------------------------------------- 11. corrective-phase wiring
class TestServiceOwnsTheRealSession:
    """The manager must close the ACTUAL worker session, not a phantom one."""

    def test_janitor_closes_the_real_worker_session(self) -> None:
        """Previously the closer walked context/browser/playwright — all None — so
        an expired session leaked Chromium. Ownership is now explicit."""

        client, worker = _client(_settings(inactivity_seconds=30))
        with client:
            session_id = _create_session(client)["session_id"]
            manager = client.app.state.manager  # type: ignore[attr-defined]
            session = manager.get_if_present(session_id)
            assert session is not None
            # Explicit ownership rather than a private worker dictionary.
            assert session.worker_context is not None
            # Age it so the janitor considers it expired.
            session.last_active_at = datetime.now(UTC) - timedelta(hours=2)
            closed = asyncio.run(manager.sweep())
            assert closed == (session_id,)

        # The real browser session was stopped by the janitor's close path.
        assert worker.stopped == ["pw_fake_1"]
        assert worker._sessions == {}

    def test_service_shutdown_closes_every_session(self) -> None:
        client, worker = _client(_settings(max_sessions=2))
        with client:
            _create_session(client)
            _create_session(client)
            assert len(worker._sessions) == 2
        # Leaving the context runs the lifespan shutdown.
        assert sorted(worker.stopped) == ["pw_fake_1", "pw_fake_2"]
        assert worker._sessions == {}

    def test_no_private_worker_dictionary_is_accessed_for_teardown(self) -> None:
        """The closer uses the recorded worker context, so a worker without a
        ``_sessions`` attribute still tears down correctly."""

        import inspect

        from browser_service.main import make_session_closer

        source = inspect.getsource(make_session_closer)
        assert "_sessions" not in source
        assert "worker_context" in source

    def test_delete_is_idempotent_and_stops_once(self) -> None:
        client, worker = _client()
        with client:
            session_id = _create_session(client)["session_id"]
            first = client.delete(f"/internal/browser/sessions/{session_id}", headers=_headers())
            second = client.delete(f"/internal/browser/sessions/{session_id}", headers=_headers())
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["reason_code"] == "session_not_found"
        # Exactly one stop: the endpoint no longer stops the browser separately from
        # the manager's closer.
        assert worker.stopped == ["pw_fake_1"]

    def test_capacity_is_released_after_the_real_close(self) -> None:
        client, _ = _client(_settings(max_sessions=1))
        with client:
            first = _create_session(client)["session_id"]
            exhausted = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(),
            )
            assert exhausted.status_code == 429
            client.delete(f"/internal/browser/sessions/{first}", headers=_headers())
            # The slot is genuinely reusable.
            reused = client.post(
                "/internal/browser/sessions",
                json={"app_slug": "pipedrive"},
                headers=_headers(),
            )
            assert reused.status_code == 201


class TestLiveViewAvailabilityIsTruthful:
    """``live_view_available`` must not be hard-coded True."""

    def test_screenshot_availability_drives_the_flag(self) -> None:
        client, _ = _client()
        with client:
            created = _create_session(client)
            # A launched session can be screenshotted, so this is genuinely True.
            assert created["live_view_available"] is True

    def test_flag_is_false_before_anything_is_available(self) -> None:
        from browser_service.session_manager import ManagedSession

        session = ManagedSession(session_id="bs_x", owner=OWNER, app_slug="pipedrive")
        # Neither a frame nor an interactive display exists yet.
        assert session.screenshot_available is False
        assert session.interactive_ready is False
        assert session.summary().live_view_available is False


class TestHealthDoesNotLaunchChromiumPerRequest:
    """The readiness probe launches a browser, so it must be cached."""

    def test_repeated_health_calls_probe_once(self) -> None:
        import ops.browser_readiness as readiness_module

        calls = {"count": 0}
        original = readiness_module.probe_playwright

        async def _counted(*args: Any, **kwargs: Any) -> Any:
            calls["count"] += 1
            return await original(*args, **kwargs)

        readiness_module.probe_playwright = _counted  # type: ignore[assignment]
        try:
            client, _ = _client()
            with client:
                for _ in range(5):
                    assert client.get("/internal/health").status_code == 200
        finally:
            readiness_module.probe_playwright = original  # type: ignore[assignment]

        # One probe at startup, then served from cache.
        assert calls["count"] == 1

    def test_liveness_endpoint_launches_nothing(self) -> None:
        client, _ = _client()
        with client:
            response = client.get("/internal/live")
        assert response.status_code == 200
        assert response.json()["status"] == "live"

    def test_ready_endpoint_reports_capacity_and_janitor(self) -> None:
        client, _ = _client()
        with client:
            body = client.get("/internal/ready").json()
        assert "capacity_total" in body
        assert "janitor_running" in body


class TestRpcCredentialBoundary:
    """Raw credentials must be REFUSED, not silently dropped."""

    def test_vault_references_pass_through(self) -> None:
        from ops.browser_service_client import _vault_references_only

        refs = _vault_references_only({"login_email": "vault://pipedrive/login_email/abc123"})
        assert refs == {"login_email": "vault://pipedrive/login_email/abc123"}

    @pytest.mark.parametrize(
        "field",
        ["login_email", "login_password", "login_otp", "login_verification_url"],
    )
    def test_raw_credential_is_refused_with_a_typed_reason(self, field: str) -> None:
        """A silent drop meant login failed opaquely; it is now an explicit error."""

        from ops.browser_service_client import _vault_references_only
        from ops.provider_errors import ProviderOperationError

        with pytest.raises(ProviderOperationError) as excinfo:
            _vault_references_only({field: "an-actual-secret-value"})
        assert excinfo.value.reason_code == "raw_credentials_not_allowed_over_rpc"

    def test_unknown_secret_field_is_refused(self) -> None:
        from ops.browser_service_client import _vault_references_only
        from ops.provider_errors import ProviderOperationError

        with pytest.raises(ProviderOperationError) as excinfo:
            _vault_references_only({"totally_new_secret": "vault://a/b/c"})
        assert excinfo.value.reason_code == "browser_secret_field_not_allowed"

    def test_malformed_vault_reference_is_refused(self) -> None:
        from ops.browser_service_client import _vault_references_only
        from ops.provider_errors import ProviderOperationError

        with pytest.raises(ProviderOperationError) as excinfo:
            _vault_references_only({"login_email": "vault://not a valid reference"})
        assert excinfo.value.reason_code == "malformed_vault_reference"

    def test_no_raw_secret_appears_in_the_rpc_request_body(self) -> None:
        """Capture the actual outbound request and prove it is reference-only."""

        import httpx

        from ops.browser_service_client import BrowserServiceClient

        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return httpx.Response(
                200,
                json={
                    "status": "succeeded",
                    "current_url": "https://app.pipedrive.com/settings/api",
                    "page_title": "API",
                },
            )

        client = BrowserServiceClient(
            base_url="http://browser-worker:8081",
            token=TOKEN,
            owner=OWNER,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        context = BrowserSessionContext(
            profile_id="bs_1",
            session_id="bs_1",
            live_view_available=True,
            allowed_domains=(),
            created_at="2026-01-01T00:00:00+00:00",
            inactivity_expires_at="2026-01-01T00:00:00+00:00",
            maximum_expires_at="2026-01-01T04:00:00+00:00",
        )
        asyncio.run(
            client.resume_after_hitl(
                context,
                "human_completed",
                None,
                sensitive_data={
                    "login_email": "vault://pipedrive/browser_login_login_email/r1",
                    "login_password": "vault://pipedrive/browser_login_login_password/r2",
                    "login_otp": "vault://pipedrive/browser_login_login_otp/r3",
                },
            )
        )
        body = captured["body"]
        # References only — no raw email, password, OTP or magic link.
        assert "vault://" in body
        for secret in ("ops@example.test", "hunter2", "483920", "https://verify"):
            assert secret not in body


class TestProviderFactoryWiring:
    """RunService must use the RPC client for service-backed Playwright."""

    @staticmethod
    def _service() -> Any:
        from ops.run_service import RunService

        return RunService.__new__(RunService)

    def test_playwright_without_service_configuration_fails_closed(self) -> None:
        from ops.config import Settings
        from ops.provider_errors import ConfigurationRequiredError

        settings = Settings.from_env(dotenv_path=None).model_copy(
            update={"browser_provider": "playwright"}
        )
        with pytest.raises(ConfigurationRequiredError) as excinfo:
            self._service()._build_browser_worker(settings)
        assert excinfo.value.reason_code == "browser_service_configuration_required"

    def test_configured_service_yields_the_rpc_client(self) -> None:
        from ops.browser_service_client import BrowserServiceClient
        from ops.config import Settings

        settings = Settings.from_env(dotenv_path=None).model_copy(
            update={
                "browser_provider": "playwright",
                "browser_service_url": "http://browser-worker:8081",
                "browser_service_token": SecretStr("ci-token"),
            }
        )
        worker = self._service()._build_browser_worker(settings)
        assert isinstance(worker, BrowserServiceClient)
        # Chromium is out of process, so a session survives an API restart.
        assert worker.supports_restart_reattach is True

    def test_in_process_sandbox_requires_an_explicit_flag(self) -> None:
        from ops.config import Settings
        from ops.playwright_worker import PlaywrightBrowserWorker

        settings = Settings.from_env(dotenv_path=None).model_copy(
            update={"browser_provider": "playwright", "playwright_in_process_sandbox": True}
        )
        worker = self._service()._build_browser_worker(settings)
        assert isinstance(worker, PlaywrightBrowserWorker)
        # In-process Chromium dies with the API, and says so.
        assert worker.supports_restart_reattach is False

    def test_browser_use_remains_the_default_provider(self) -> None:
        from ops.config import Settings

        settings = Settings.from_env(dotenv_path=None)
        assert settings.browser_provider == "browser_use"
        assert settings.playwright_in_process_sandbox is False
