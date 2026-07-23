"""Offline owner-only credential submission through the real vault + validator.

Every test is offline-safe: the browser adapter is a fake, the vault is the real
encrypted SQLiteSecretStore, and the read-only validator runs against an
in-process ``httpx.MockTransport``. No live HubSpot, Browser Use, or Composio
call occurs. These tests prove the submit boundary encrypts raw values, returns
references only, validates read-only, and never leaks the raw secret.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.composio_capability import ComposioCapabilityReport
from ops.config import Settings
from ops.credential_validator import (
    HUBSPOT_ACCOUNT_INFO_ENDPOINT,
    CredentialValidator,
    PolicyBoundCredentialValidator,
    hubspot_validation_policy,
)
from ops.graph import WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import CredentialSubmissionError, RunService
from ops.secret_store import SQLiteSecretStore

SELF_SERVE_APP = "HubSpot"
RAW_TOKEN = "hs-owner-supplied-token-DO-NOT-PERSIST"  # pragma: allowlist secret


class _FakeBrowser:
    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        return BrowserSessionContext(
            profile_id=profile_id or "profile-hs",
            session_id="browser-sess-1",
            live_view_available=False,
            allowed_domains=("developers.hubspot.com",),
            created_at="2026-01-01T00:00:00Z",
            inactivity_expires_at="2026-01-01T00:15:00Z",
            maximum_expires_at="2026-01-01T04:00:00Z",
        )

    async def navigate_onboarding(self, context: object, research: object) -> BrowserObservation:
        del context, research
        return BrowserObservation(
            status="credential_page_ready",
            current_url="https://developers.hubspot.com/apps/new",
            page_title="Create a developer app",
        )

    async def resume_after_hitl(self, context: object, signal: object) -> BrowserObservation:
        raise AssertionError("resume is out of scope")


class _StubPreflight:
    async def evaluate(
        self, *, app_name: str, app_slug: str | None = None, required_tools: object = ()
    ) -> ComposioCapabilityReport:
        del app_name, app_slug, required_tools
        return ComposioCapabilityReport(
            app_slug="hubspot",
            toolkit_available=False,
            toolkit_slug=None,
            required_auth_schemes=(),
            managed_auth_available=False,
            active_connected_account=False,
            required_tools_present=False,
            capability_state="toolkit_unavailable",
            reason_code="composio_toolkit_absent",
            detail="stub",
        )


def _request() -> OperationsRequest:
    return OperationsRequest(
        app_name=SELF_SERVE_APP,
        company=_company(),
    )


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Deliver an authorized integration via the provider developer API.",
    )


def _validator(status_code: int) -> PolicyBoundCredentialValidator:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.hubapi.com"
        assert request.url.path == "/account-info/2026-03/details"
        assert request.headers["Authorization"] == f"Bearer {RAW_TOKEN}"
        return httpx.Response(status_code, json={"portalId": 12345})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return PolicyBoundCredentialValidator(
        validator=CredentialValidator(
            secret_store=_shared_store,
            http_client=client,
            policies=(hubspot_validation_policy(),),
        ),
        endpoints={"hubspot": HUBSPOT_ACCOUNT_INFO_ENDPOINT},
    )


_shared_store: SQLiteSecretStore


def _service(tmp: Path, *, status_code: int) -> RunService:
    global _shared_store
    _shared_store = SQLiteSecretStore(tmp / "private" / "vault.db", Fernet.generate_key())
    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(browser=_FakeBrowser()),  # type: ignore[arg-type]
    )
    service = RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=Settings(),
        workflow=workflow,
        capability_preflight=_StubPreflight(),  # type: ignore[arg-type]
    )
    service._secret_store = _shared_store
    service._credential_validator = _validator(status_code)  # type: ignore[assignment]
    return service


def _run_at_browser_running(service: RunService) -> str:
    run = service.create_run(_request(), execution_mode="execute_when_configured")
    assert run["status"] == "browser_running"
    return str(run["run_id"])


def test_valid_submission_completes_with_reference_only_bundle(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=200)
    run_id = _run_at_browser_running(service)

    result = service.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"access_token": SecretStr(RAW_TOKEN)},
    )

    assert result["status"] == "completed"
    output = service.get_output(run_id)
    assert output is not None
    assert output["readiness"] == "credentials_ready"
    assert set(output["credential_refs"]) == {"access_token"}
    for reference in output["credential_refs"].values():
        assert reference.startswith("vault://hubspot/access_token/")


def test_invalid_credentials_return_configuration_required(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=401)
    run_id = _run_at_browser_running(service)

    result = service.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"access_token": SecretStr(RAW_TOKEN)},
    )

    assert result["status"] == "configuration_required"


def test_raw_token_never_persisted_anywhere(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=200)
    run_id = _run_at_browser_running(service)

    service.submit_owner_credentials(
        run_id,
        company=_company(),
        fields={"access_token": SecretStr(RAW_TOKEN)},
    )

    stored = service.storage.get_run(run_id)
    output = service.get_output(run_id)
    timeline = service.get_timeline(run_id)
    haystack = repr(stored) + repr(output) + repr(timeline)
    assert RAW_TOKEN not in haystack

    for db_name in ("ops.db", "checkpoints.db"):
        db_path = tmp_path / "private" / db_name
        if db_path.exists():
            assert RAW_TOKEN.encode() not in db_path.read_bytes()

    # The value is retrievable only through its exact vault reference.
    reference = next(iter(service.get_output(run_id)["credential_refs"].values()))  # type: ignore[index]
    assert _shared_store.get(reference) == RAW_TOKEN


def test_submission_requires_browser_running_state(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=200)
    run = service.create_run(_request(), execution_mode="plan_only")

    with pytest.raises(CredentialSubmissionError) as excinfo:
        service.submit_owner_credentials(
            str(run["run_id"]),
            company=_company(),
            fields={"access_token": SecretStr(RAW_TOKEN)},
        )
    assert excinfo.value.reason_code == "run_not_awaiting_credentials"


def test_unconfigured_boundary_is_rejected(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=200)
    run_id = _run_at_browser_running(service)
    service._credential_validator = None

    with pytest.raises(CredentialSubmissionError) as excinfo:
        service.submit_owner_credentials(
            run_id,
            company=_company(),
            fields={"access_token": SecretStr(RAW_TOKEN)},
        )
    assert excinfo.value.reason_code == "credential_boundary_not_configured"


def test_empty_or_malformed_fields_are_rejected(tmp_path: Path) -> None:
    service = _service(tmp_path, status_code=200)
    run_id = _run_at_browser_running(service)

    with pytest.raises(CredentialSubmissionError):
        service.submit_owner_credentials(run_id, company=_company(), fields={})
    with pytest.raises(CredentialSubmissionError):
        service.submit_owner_credentials(
            run_id, company=_company(), fields={"Bad Kind": SecretStr(RAW_TOKEN)}
        )
