"""Focused checks for the write/one-time-consume browser vault boundary."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.browser_secret_broker import (
    BrowserCredentialCaptureRequest,
    BrowserSecretConsumeRequest,
    BrowserSecretUnavailable,
    _capture_sync,
    _consume_sync,
)
from browser_service.auth import OWNER_HEADER
from browser_service.secret_broker import (
    BROKER_TOKEN_HEADER,
    BrokerCaptureStore,
    BrowserSecretBrokerClient,
)
from ops.browser_session_capability import (
    CAPABILITY_HEADER,
    derive_browser_session_capability,
)
from ops.secret_store import SQLiteSecretStore

BROKER_TOKEN = "broker-token-" + ("b" * 40)  # pragma: allowlist secret
OPS_TOKEN = "ops-token-" + ("o" * 40)  # pragma: allowlist secret
SERVICE_TOKEN = "service-token-" + ("s" * 40)  # pragma: allowlist secret
RUN_ID = "run_" + ("a" * 32)
SESSION_ID = "bs_" + ("b" * 32)
OWNER = "production-owner"
CAPABILITY_KEY = "capability-key-" + ("k" * 32)  # pragma: allowlist secret


class _Core:
    class _Storage:
        def __init__(self, core: _Core) -> None:
            self._core = core

        def get_run(self, run_id: str) -> dict[str, object] | None:
            return self._core.records.get(run_id)

    def __init__(self, store: SQLiteSecretStore) -> None:
        self._secret_store = store
        # The production broker reads the authoritative storage row, never the
        # public RunService projection. This test double intentionally exposes the
        # same narrow storage surface.
        self.records: dict[str, dict[str, object]] = {}
        self.storage = self._Storage(self)
        self._locks: dict[str, threading.RLock] = {}

    def get_run(self, run_id: str) -> dict[str, object] | None:
        record = self.records.get(run_id)
        if record is None:
            return None
        # Mirrors RunService.get_run: safe for an owner response, insufficient
        # for a vault authorization decision.
        return {
            key: record[key] for key in ("run_id", "app_slug", "status", "phase") if key in record
        }

    def _run_lock(self, run_id: str) -> threading.RLock:
        return self._locks.setdefault(run_id, threading.RLock())


class _ApiService:
    def __init__(self, core: _Core) -> None:
        self._service = core

    async def startup(self) -> None:
        return None

    async def shutdown(self) -> None:
        return None


def _client(
    tmp_path: Path,
    monkeypatch: Any,
) -> tuple[TestClient, SQLiteSecretStore, _Core]:
    store = SQLiteSecretStore(tmp_path / "vault.db", Fernet.generate_key())
    core = _Core(store)
    monkeypatch.setenv("BROWSER_SECRET_BROKER_TOKEN", BROKER_TOKEN)
    monkeypatch.setenv("BROWSER_SESSION_CAPABILITY_KEY", CAPABILITY_KEY)
    monkeypatch.setenv("OPS_INTERNAL_API_TOKEN", OPS_TOKEN)
    monkeypatch.setenv("BROWSER_SERVICE_TOKEN", SERVICE_TOKEN)
    app = create_app(service=_ApiService(core), cors_origins=[], enable_docs=False)
    return TestClient(app), store, core


def _headers(
    token: str = BROKER_TOKEN,
    *,
    scope_id: str = RUN_ID,
) -> dict[str, str]:
    return {
        BROKER_TOKEN_HEADER: token,
        OWNER_HEADER: OWNER,
        CAPABILITY_HEADER: derive_browser_session_capability(
            key=CAPABILITY_KEY,
            owner=OWNER,
            scope=scope_id,
        ),
    }


def _active_record(
    *,
    phase: str = "authentication_submitted",
    effect_identity: str | None = None,
    session_id: str = SESSION_ID,
) -> dict[str, object]:
    return {
        "run_id": RUN_ID,
        "app_slug": "pipedrive",
        "status": "browser_running",
        "phase": phase,
        "execution_mode": "operations",
        "state_engine": "canonical_v1",
        "browser_provider": "playwright",
        "browser_session_id": session_id,
        "effect_identity": effect_identity or f"{RUN_ID}:browser-resume:1",
    }


def _consume_grant(
    store: SQLiteSecretStore,
    reference: str,
    *,
    field: str,
    effect_identity: str | None = None,
) -> str:
    effect = effect_identity or f"{RUN_ID}:browser-resume:1"
    return store.reserve_browser_secret_grant(
        operation_key=f"{effect}:consume:{field}",
        run_id=RUN_ID,
        session_id=SESSION_ID,
        app_slug="pipedrive",
        kind=f"browser_login_{field}",
        action="consume",
        reference=reference,
    )


def _capture_grant(
    store: SQLiteSecretStore,
    *,
    effect_identity: str | None = None,
) -> str:
    effect = effect_identity or f"{RUN_ID}:credential-capture:v1"
    return store.reserve_browser_secret_grant(
        operation_key=f"{effect}:capture:api_token",
        run_id=RUN_ID,
        session_id=SESSION_ID,
        app_slug="pipedrive",
        kind="api_token",
        action="capture",
    )


@pytest.mark.parametrize("reused_token", (OPS_TOKEN, SERVICE_TOKEN, CAPABILITY_KEY))
def test_broker_rejects_reuse_of_every_other_control_plane_token(
    tmp_path: Path,
    monkeypatch: Any,
    reused_token: str,
) -> None:
    client, _store, _core = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("BROWSER_SECRET_BROKER_TOKEN", reused_token)

    with client:
        response = client.post(
            "/internal/browser-secret-broker/consume",
            json={},
            headers={BROKER_TOKEN_HEADER: reused_token},
        )

    assert response.status_code == 503
    assert response.json() == {"error": "browser_secret_broker_unavailable"}


def test_broker_consumes_only_exact_transient_once(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client, store, core = _client(tmp_path, monkeypatch)
    core.records[RUN_ID] = _active_record()
    reference = store.put_transient(
        app_slug="pipedrive",
        kind="browser_login_login_password",
        scope_id=RUN_ID,
        value="login-value",
    )
    grant = _consume_grant(store, reference, field="login_password")
    body = {
        "grant": grant,
        "reference": reference,
        "app_slug": "pipedrive",
        "kind": "browser_login_login_password",
        "scope_id": RUN_ID,
        "session_id": SESSION_ID,
    }
    with client:
        wrong_capability = client.post(
            "/internal/browser-secret-broker/consume",
            json=body,
            headers={"X-Ops-Internal-Token": OPS_TOKEN},
        )
        first = client.post(
            "/internal/browser-secret-broker/consume",
            json=body,
            headers=_headers(),
        )
        second = client.post(
            "/internal/browser-secret-broker/consume",
            json=body,
            headers=_headers(),
        )

    assert wrong_capability.status_code == 401
    assert first.status_code == 200
    assert first.json() == {"value": "login-value"}
    assert second.status_code == 409
    assert second.json() == {"error": "browser_secret_unavailable"}


def test_broker_cannot_consume_durable_or_unrelated_entries(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client, store, core = _client(tmp_path, monkeypatch)
    core.records[RUN_ID] = _active_record()
    durable = store.put(app_slug="pipedrive", kind="api_token", value="durable-value")
    body = {
        "grant": "bsg_" + ("x" * 43),
        "reference": durable,
        "app_slug": "pipedrive",
        "kind": "api_token",
        "scope_id": RUN_ID,
        "session_id": SESSION_ID,
    }
    with client:
        response = client.post(
            "/internal/browser-secret-broker/consume",
            json=body,
            headers=_headers(),
        )

    assert response.status_code == 409
    assert response.json() == {"error": "browser_secret_unavailable"}
    assert store.get(durable) == "durable-value"


def test_capture_is_write_only_and_bound_to_active_reviewed_run(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client, store, core = _client(tmp_path, monkeypatch)
    effect_identity = f"{RUN_ID}:credential-capture:v1"
    core.records[RUN_ID] = _active_record(
        phase="credential_capture_reserved",
        effect_identity=effect_identity,
    )
    grant = _capture_grant(store, effect_identity=effect_identity)
    body = {
        "grant": grant,
        "app_slug": "pipedrive",
        "kind": "api_token",
        "scope_id": RUN_ID,
        "session_id": SESSION_ID,
        "value": "c" * 40,
    }
    with client:
        captured = client.post(
            "/internal/browser-secret-broker/capture",
            json=body,
            headers=_headers(),
        )
        replayed = client.post(
            "/internal/browser-secret-broker/capture",
            json=body,
            headers=_headers(),
        )
        rejected = client.post(
            "/internal/browser-secret-broker/capture",
            json={**body, "kind": "client_secret"},
            headers=_headers(),
        )

    assert captured.status_code == 200
    assert set(captured.json()) == {"reference"}
    reference = captured.json()["reference"]
    assert replayed.status_code == 200
    assert replayed.json() == {"reference": reference}
    assert store.get(reference) == "c" * 40
    assert "c" * 40 not in captured.text
    assert rejected.status_code == 403
    assert rejected.json() == {"error": "browser_capture_not_authorized"}


def test_capture_reapplies_reviewed_pipedrive_token_format_before_vault_write(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client, store, core = _client(tmp_path, monkeypatch)
    effect_identity = f"{RUN_ID}:credential-capture:v1"
    core.records[RUN_ID] = _active_record(
        phase="credential_capture_reserved",
        effect_identity=effect_identity,
    )
    grant = _capture_grant(store, effect_identity=effect_identity)
    body = {
        "grant": grant,
        "app_slug": "pipedrive",
        "kind": "api_token",
        "scope_id": RUN_ID,
        "session_id": SESSION_ID,
    }
    with client:
        wrong_length = client.post(
            "/internal/browser-secret-broker/capture",
            json={**body, "value": "c" * 39},
            headers=_headers(),
        )
        wrong_alphabet = client.post(
            "/internal/browser-secret-broker/capture",
            json={**body, "value": "z" * 40},
            headers=_headers(),
        )

    assert wrong_length.status_code == 403
    assert wrong_length.json() == {"error": "browser_capture_not_authorized"}
    assert wrong_alphabet.status_code == 403
    assert wrong_alphabet.json() == {"error": "browser_capture_not_authorized"}
    assert "c" * 39 not in wrong_length.text
    assert "z" * 40 not in wrong_alphabet.text
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM vault_entries").fetchone()[0] == 0


def test_browser_adapter_sends_exact_scope_and_receives_only_reference() -> None:
    requests: list[httpx.Request] = []
    consume_grant = "bsg_" + ("g" * 43)
    capture_grant = "bsg_" + ("h" * 43)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        payload = json.loads(request.content)
        if request.url.path.endswith("/consume"):
            assert payload == {
                "grant": consume_grant,
                "reference": "vault://pipedrive/browser_login_login_email/reference_1",
                "app_slug": "pipedrive",
                "kind": "browser_login_login_email",
                "scope_id": RUN_ID,
                "session_id": SESSION_ID,
            }
            return httpx.Response(200, json={"value": "login@example.test"})
        assert payload == {
            "grant": capture_grant,
            "app_slug": "pipedrive",
            "kind": "api_token",
            "scope_id": RUN_ID,
            "session_id": SESSION_ID,
            "value": "c" * 40,
        }
        return httpx.Response(
            200,
            json={"reference": "vault://pipedrive/api_token/reference_2"},
        )

    broker = BrowserSecretBrokerClient(
        base_url="http://api:8000",
        token=SecretStr(BROKER_TOKEN),
        timeout_seconds=5,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    value = broker.consume(
        grant=consume_grant,
        reference="vault://pipedrive/browser_login_login_email/reference_1",
        app_slug="pipedrive",
        kind="browser_login_login_email",
        scope_id=RUN_ID,
        session_id=SESSION_ID,
        owner=OWNER,
        capability=derive_browser_session_capability(
            key=CAPABILITY_KEY,
            owner=OWNER,
            scope=RUN_ID,
        ),
    )
    store = BrokerCaptureStore(
        broker=broker,
        grant=capture_grant,
        app_slug="pipedrive",
        scope_id=RUN_ID,
        session_id=SESSION_ID,
        owner=OWNER,
        capability=derive_browser_session_capability(
            key=CAPABILITY_KEY,
            owner=OWNER,
            scope=RUN_ID,
        ),
    )
    reference = store.put(app_slug="pipedrive", kind="api_token", value="c" * 40)

    assert value == "login@example.test"
    assert reference == "vault://pipedrive/api_token/reference_2"
    assert all(request.headers[BROKER_TOKEN_HEADER] == BROKER_TOKEN for request in requests)
    assert all(request.headers[OWNER_HEADER] == OWNER for request in requests)
    assert all(request.headers.get(CAPABILITY_HEADER) for request in requests)


def test_broker_rejects_wrong_run_capability_and_unreserved_capture(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client, _store, core = _client(tmp_path, monkeypatch)
    core.records[RUN_ID] = _active_record()
    body = {
        "grant": "bsg_" + ("u" * 43),
        "app_slug": "pipedrive",
        "kind": "api_token",
        "scope_id": RUN_ID,
        "session_id": SESSION_ID,
        "value": "c" * 40,
    }
    with client:
        wrong_capability = client.post(
            "/internal/browser-secret-broker/capture",
            json=body,
            headers=_headers(scope_id="run_" + ("f" * 32)),
        )
        unreserved = client.post(
            "/internal/browser-secret-broker/capture",
            json=body,
            headers=_headers(),
        )

    assert wrong_capability.status_code == 403
    assert wrong_capability.json() == {"error": "browser_capture_not_authorized"}
    assert unreserved.status_code == 403
    assert unreserved.json() == {"error": "browser_capture_not_authorized"}


def test_delayed_callback_cannot_cross_to_a_later_effect(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _client_instance, store, core = _client(tmp_path, monkeypatch)
    old_effect = f"{RUN_ID}:browser-resume:1"
    core.records[RUN_ID] = _active_record(effect_identity=old_effect)
    reference = store.put_transient(
        app_slug="pipedrive",
        kind="browser_login_login_password",
        scope_id=RUN_ID,
        value="still-present",
    )
    grant = _consume_grant(
        store,
        reference,
        field="login_password",
        effect_identity=old_effect,
    )
    payload = BrowserSecretConsumeRequest(
        grant=grant,
        reference=reference,
        app_slug="pipedrive",
        kind="browser_login_login_password",
        scope_id=RUN_ID,
        session_id=SESSION_ID,
    )
    callback_started = threading.Event()
    callback_result: list[BaseException | str] = []
    run_lock = core._run_lock(RUN_ID)
    run_lock.acquire()

    def delayed_callback() -> None:
        callback_started.set()
        try:
            callback_result.append(_consume_sync(_ApiService(core), payload, authorized=True))
        except BaseException as exc:  # noqa: BLE001 - assert exact typed failure below
            callback_result.append(exc)

    thread = threading.Thread(target=delayed_callback)
    thread.start()
    assert callback_started.wait(timeout=1)
    # Keep the broad status, phase, session, app and scope identical. Only the
    # durable effect changes, proving an old grant cannot revive when a later
    # resume cycles back through ``authentication_submitted``.
    core.records[RUN_ID] = _active_record(
        effect_identity=f"{RUN_ID}:browser-resume:2",
    )
    run_lock.release()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert len(callback_result) == 1
    assert isinstance(callback_result[0], BrowserSecretUnavailable)
    assert (
        store.consume_transient(
            reference,
            expected_app_slug="pipedrive",
            expected_kind="browser_login_login_password",
            expected_scope_id=RUN_ID,
        )
        == "still-present"
    )


def test_concurrent_capture_retry_returns_one_reference(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _client_instance, store, core = _client(tmp_path, monkeypatch)
    effect = f"{RUN_ID}:credential-capture:v1"
    core.records[RUN_ID] = _active_record(
        phase="credential_capture_reserved",
        effect_identity=effect,
    )
    payload = BrowserCredentialCaptureRequest(
        grant=_capture_grant(store, effect_identity=effect),
        app_slug="pipedrive",
        kind="api_token",
        scope_id=RUN_ID,
        session_id=SESSION_ID,
        value="c" * 40,
    )
    barrier = threading.Barrier(3)
    references: list[str] = []

    def capture() -> None:
        barrier.wait(timeout=2)
        references.append(_capture_sync(_ApiService(core), payload, authorized=True))

    threads = [threading.Thread(target=capture) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=2)
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert len(references) == 2
    assert references[0] == references[1]
    with sqlite3.connect(store.db_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM vault_entries WHERE app_slug = ? AND kind = ?",
                ("pipedrive", "api_token"),
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize(
    ("phase", "session_id"),
    [
        ("challenge_pending", SESSION_ID),
        ("authentication_submitted", "bs_" + ("c" * 32)),
    ],
)
def test_callback_is_rejected_after_phase_or_session_changes(
    tmp_path: Path,
    monkeypatch: Any,
    phase: str,
    session_id: str,
) -> None:
    client, store, core = _client(tmp_path, monkeypatch)
    effect = f"{RUN_ID}:browser-resume:1"
    reference = store.put_transient(
        app_slug="pipedrive",
        kind="browser_login_login_email",
        scope_id=RUN_ID,
        value="owner@example.test",
    )
    grant = _consume_grant(
        store,
        reference,
        field="login_email",
        effect_identity=effect,
    )
    core.records[RUN_ID] = _active_record(
        phase=phase,
        effect_identity=effect,
        session_id=session_id,
    )
    with client:
        response = client.post(
            "/internal/browser-secret-broker/consume",
            json={
                "grant": grant,
                "reference": reference,
                "app_slug": "pipedrive",
                "kind": "browser_login_login_email",
                "scope_id": RUN_ID,
                "session_id": SESSION_ID,
            },
            headers=_headers(),
        )

    assert response.status_code == 409
    assert response.json() == {"error": "browser_secret_unavailable"}


def test_production_browser_has_no_vault_or_host_ipc() -> None:
    import yaml

    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "compose.prod.yaml").read_text(encoding="utf-8"))
    browser = compose["services"]["browser-worker"]
    environment = browser["environment"]

    assert "ipc" not in browser
    assert environment["PLAYWRIGHT_DISABLE_SANDBOX"] == "${PLAYWRIGHT_DISABLE_SANDBOX:-false}"
    assert "SECRET_VAULT_KEY" not in environment
    assert "SECRET_VAULT_DB_PATH" not in environment
    assert "OPS_INTERNAL_API_TOKEN" not in environment
    assert all("/vault" not in str(volume) for volume in browser.get("volumes", ()))
    assert browser["networks"] == ["browser-control", "browser-egress"]
    assert compose["networks"]["browser-control"]["internal"] is True
    for service in compose["services"].values():
        assert service["logging"]["options"]["max-size"] == "${CONTAINER_LOG_MAX_SIZE:-10m}"
        assert service["logging"]["options"]["max-file"] == "${CONTAINER_LOG_MAX_FILES:-5}"


def test_edge_display_and_backup_hardening_are_declared() -> None:
    root = Path(__file__).resolve().parents[1]
    caddy = (root / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    entrypoint = (root / "docker" / "browser-entrypoint.sh").read_text(encoding="utf-8")
    backup = (root / "scripts" / "backup-production-data.sh").read_text(encoding="utf-8")

    assert "Strict-Transport-Security" in caddy
    assert "wait_for_listener" in entrypoint
    assert '"${control_vnc_pid}"' in entrypoint
    assert '"${view_vnc_pid}"' in entrypoint
    assert "browser_profiles" in backup
