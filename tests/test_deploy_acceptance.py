from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.service import LocalRunService
from ops.core.config import Settings
from ops.deploy.acceptance import (
    deployment_is_accepted,
    deployment_payload_is_accepted,
    wait_for_deployment_acceptance,
    write_deployment_acceptance_marker,
)
from ops.runs.email import RunEmailService
from ops.runs.service import RunService

REVISION = "a" * 40
NONCE = "N" * 64


def _settings(tmp_path: Path, *, nonce: str = NONCE) -> Settings:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    data.chmod(0o700)
    return Settings(
        app_revision=REVISION,
        ops_deploy_acceptance_nonce=SecretStr(nonce),
        ops_deploy_acceptance_marker_path=data / "deploy-acceptance.json",
    )


def test_marker_is_atomic_private_digest_bound_and_nonce_unique(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    write_deployment_acceptance_marker(settings)

    marker = settings.ops_deploy_acceptance_marker_path
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert deployment_is_accepted(settings) is True
    assert stat_mode(marker) == 0o600
    assert NONCE not in marker.read_text(encoding="utf-8")
    assert payload["revision"] == REVISION
    assert len(payload["acceptance_digest"]) == 64
    assert deployment_payload_is_accepted(settings, payload) is True

    same_revision_new_deploy = settings.model_copy(
        update={"ops_deploy_acceptance_nonce": SecretStr("M" * 64)}
    )
    assert deployment_is_accepted(same_revision_new_deploy) is False


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_manual_or_tampered_markers_never_accept(tmp_path: Path) -> None:
    manual = _settings(tmp_path, nonce="manual-unaccepted")
    assert deployment_is_accepted(manual) is False

    settings = _settings(tmp_path)
    write_deployment_acceptance_marker(settings)
    marker = settings.ops_deploy_acceptance_marker_path
    marker.write_text('{"schema_version":1,"revision":"bad"}\n', encoding="utf-8")
    marker.chmod(0o600)
    assert deployment_is_accepted(settings) is False

    marker.unlink()
    target = marker.with_name("target")
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    marker.symlink_to(target)
    assert deployment_is_accepted(settings) is False


def test_malformed_acceptance_configuration_fails_closed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    malformed_nonce = settings.model_copy(
        update={"ops_deploy_acceptance_nonce": "not-a-secret-wrapper"}
    )
    malformed_path = settings.model_copy(update={"ops_deploy_acceptance_marker_path": None})

    assert deployment_is_accepted(malformed_nonce) is False  # type: ignore[arg-type]
    assert deployment_payload_is_accepted(malformed_nonce, {}) is False  # type: ignore[arg-type]
    assert deployment_is_accepted(malformed_path) is False  # type: ignore[arg-type]
    assert deployment_payload_is_accepted(malformed_path, {}) is False  # type: ignore[arg-type]


def test_marker_read_is_bounded_and_pinned_to_validated_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    marker = settings.ops_deploy_acceptance_marker_path
    marker.write_bytes(b"x" * 513)
    marker.chmod(0o600)
    assert deployment_is_accepted(settings) is False

    # Prepare a valid replacement, but leave an invalid private regular file at
    # the configured path when validation begins.
    replacement = marker.with_name("replacement.json")
    replacement_settings = settings.model_copy(
        update={"ops_deploy_acceptance_marker_path": replacement}
    )
    write_deployment_acceptance_marker(replacement_settings)
    marker.write_text("{}\n", encoding="utf-8")
    marker.chmod(0o600)

    real_fstat = os.fstat
    replaced = False

    def replace_path_after_fstat(descriptor: int) -> os.stat_result:
        nonlocal replaced
        info = real_fstat(descriptor)
        if not replaced:
            os.replace(replacement, marker)
            replaced = True
        return info

    monkeypatch.setattr(os, "fstat", replace_path_after_fstat)
    # The path now names a valid marker, but this decision must remain bound to
    # the invalid inode opened before the replacement.
    assert deployment_is_accepted(settings) is False
    assert replaced is True
    monkeypatch.setattr(os, "fstat", real_fstat)
    assert deployment_is_accepted(settings) is True


def test_acceptance_wait_is_interruptible(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stop = threading.Event()
    result: list[bool] = []
    thread = threading.Thread(
        target=lambda: result.append(
            wait_for_deployment_acceptance(settings, stop, poll_seconds=0.05)
        )
    )
    thread.start()
    time.sleep(0.1)
    assert result == []
    stop.set()
    thread.join(timeout=1)
    assert result == [False]


class _EmailContext:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._gmail_worker = object()
        self._email_poller_stop = threading.Event()
        self._email_poller_thread = None
        self.called = threading.Event()

    def resolve_pending_otps(
        self,
        *,
        limit: int,
        max_attempts_per_run: int,
    ) -> int:
        del limit, max_attempts_per_run
        self.called.set()
        return 0

    def poll_waiting_runs(self, *, limit: int) -> int:
        del limit
        return 0


def test_email_maintenance_cannot_run_until_exact_deploy_acceptance(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    context = _EmailContext(settings)
    service = RunEmailService(context)  # type: ignore[arg-type]
    thread = threading.Thread(
        target=service._poller_loop,
        args=(10, 0.05, 1),
    )
    thread.start()
    time.sleep(0.2)
    assert context.called.is_set() is False

    write_deployment_acceptance_marker(settings)
    assert context.called.wait(timeout=2.0) is True
    context._email_poller_stop.set()
    thread.join(timeout=1)
    assert thread.is_alive() is False


def test_marker_owner_matches_the_runtime_user(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    write_deployment_acceptance_marker(settings)

    assert settings.ops_deploy_acceptance_marker_path.stat().st_uid == os.getuid()


def _create_payload() -> dict[str, object]:
    return {
        "app_name": "HubSpot",
        "account_mode": "existing_account",
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/test-operator",
            "use_case": "Evaluate documented integration access.",
            "callback_urls": [],
        },
        "requested_scope_policy": "maximum",
        "dry_run": True,
    }


@pytest.fixture
def acceptance_api(tmp_path: Path) -> Iterator[tuple[TestClient, RunService, Settings]]:
    settings = _settings(tmp_path).model_copy(
        update={
            "ops_startup_automation_enabled": True,
            # Keep the API fixture deterministic; the acceptance gate itself is
            # exercised, while maintenance threads remain interruptible.
            "ops_automation_start_delay_seconds": 300,
        }
    )
    core = RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)
    service = LocalRunService(
        db_path=tmp_path / "ops.db",
        core_service=core,
        settings=settings,
    )
    with TestClient(create_app(service=service)) as client:
        yield client, core, settings


def test_candidate_release_rejects_api_mutations_without_persisting(
    acceptance_api: tuple[TestClient, RunService, Settings],
) -> None:
    client, core, settings = acceptance_api

    blocked = client.post("/api/runs", json=_create_payload())

    assert blocked.status_code == 503
    assert blocked.json() == {
        "error": "deployment_not_accepted",
        "message": "Release acceptance is still in progress; retry shortly.",
    }
    assert blocked.headers["retry-after"] == "5"
    assert core.storage.count_runs() == 0

    write_deployment_acceptance_marker(settings)
    accepted = client.post("/api/runs", json=_create_payload())
    assert accepted.status_code == 201
    assert core.storage.count_runs() == 1


def test_marker_is_rechecked_for_each_new_mutation_admission(
    acceptance_api: tuple[TestClient, RunService, Settings],
) -> None:
    """New requests see revocation; deploy must quiesce already-admitted work."""

    client, core, settings = acceptance_api
    write_deployment_acceptance_marker(settings)
    accepted = client.post("/api/runs", json=_create_payload())
    assert accepted.status_code == 201

    # Production never revokes a marker under a running release: deploy/restore
    # closes admission and stops services first. This removal demonstrates the
    # gate's uncached behavior, while documenting why it is not an in-flight lock.
    settings.ops_deploy_acceptance_marker_path.unlink()
    blocked = client.post(
        "/api/runs",
        headers={"Idempotency-Key": f"idem_{'b' * 32}"},
        json=_create_payload(),
    )
    assert blocked.status_code == 503
    assert core.storage.count_runs() == 1


def test_candidate_release_keeps_read_only_health_available(
    acceptance_api: tuple[TestClient, RunService, Settings],
) -> None:
    client, core, _settings_value = acceptance_api

    response = client.get("/api/system/health")

    assert response.status_code == 200
    assert core.storage.count_runs() == 0


def test_candidate_release_blocks_live_view_grant_before_service_call(
    acceptance_api: tuple[TestClient, RunService, Settings],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _core, _settings_value = acceptance_api
    service = client.app.state.run_service
    called = False

    async def unexpected_live_view(run_id: str) -> None:
        del run_id
        nonlocal called
        called = True

    monkeypatch.setattr(service, "get_live_view", unexpected_live_view)
    response = client.get(f"/api/runs/run_{'a' * 32}/live-view")

    assert response.status_code == 503
    assert response.json()["error"] == "deployment_not_accepted"
    assert called is False


def test_candidate_release_rejects_browser_broker_mutations(
    acceptance_api: tuple[TestClient, RunService, Settings],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _core, settings = acceptance_api
    broker_token = "broker-test-token-" + ("b" * 32)
    monkeypatch.setenv("BROWSER_SECRET_BROKER_TOKEN", broker_token)

    blocked = client.post(
        "/internal/browser-secret-broker/capture",
        json={},
        headers={"X-Browser-Secret-Broker-Token": broker_token},
    )

    assert blocked.status_code == 503
    assert blocked.json()["error"] == "deployment_not_accepted"

    write_deployment_acceptance_marker(settings)
    accepted = client.post(
        "/internal/browser-secret-broker/capture",
        json={},
        headers={"X-Browser-Secret-Broker-Token": broker_token},
    )
    assert accepted.status_code == 422
