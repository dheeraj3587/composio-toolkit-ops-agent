"""M6 secure credential capture, read-only validation, and IntegratorBundle.

Every test is offline-safe: credential capture and validation are fakes, the
vault is the real encrypted SQLiteSecretStore, and the browser adapter is a fake.
No live HubSpot, Browser Use, Composio, Gmail, or OAuth call occurs.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.composio_capability import ComposioCapabilityReport
from ops.config import Settings
from ops.credential_validator import CredentialValidationResult, ValidationStatus
from ops.graph import WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationsRequest
from ops.provider_errors import ConfigurationRequiredError
from ops.run_service import RunService
from ops.secret_store import SecretNotFoundError, SQLiteSecretStore

SELF_SERVE_APP = "HubSpot"
GATED_APP = "Salesforce"
RAW_SECRET = "hs-test-access-token-DO-NOT-PERSIST"  # pragma: allowlist secret
HUBSPOT_ENDPOINT = "https://api.hubapi.com/account-info/v3/details"


class _FakeBrowser:
    def __init__(self, outcome: str = "credential_page_ready") -> None:
        self.outcome = outcome
        self.starts = 0

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        self.starts += 1
        return BrowserSessionContext(
            profile_id=profile_id or "profile-hs",
            session_id="browser-sess-1",
            live_view_available=False,
            allowed_domains=("developers.hubspot.com",),
            created_at="2026-01-01T00:00:00Z",
            inactivity_expires_at="2026-01-01T00:15:00Z",
            maximum_expires_at="2026-01-01T04:00:00Z",
        )

    async def navigate_onboarding(
        self, context: object, research: object, *, sensitive_data: object = None
    ) -> BrowserObservation:
        del context, research, sensitive_data
        if self.outcome == "hitl":
            return BrowserObservation(
                status="human_action_required",
                current_url="https://app.hubspot.com/login",
                page_title="Log in",
                human_action_type="captcha",
                human_instruction="Solve the CAPTCHA in the live browser.",
            )
        return BrowserObservation(
            status="credential_page_ready",
            current_url="https://developers.hubspot.com/apps/new",
            page_title="Create a developer app",
        )

    async def resume_after_hitl(
        self,
        context: object,
        signal: object,
        research: object = None,
        *,
        sensitive_data: object = None,
        provider_session_id: object = None,
    ) -> BrowserObservation:
        raise AssertionError("resume is out of scope")


class _StubPreflight:
    def __init__(self, report: ComposioCapabilityReport) -> None:
        self._report = report

    async def evaluate(
        self, *, app_name: str, app_slug: str | None = None, required_tools: object = ()
    ) -> ComposioCapabilityReport:
        del app_name, app_slug, required_tools
        return self._report


def _fallback_report() -> ComposioCapabilityReport:
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


class _FakeCapture:
    def __init__(self, store: SQLiteSecretStore | None, *, missing_config: bool = False) -> None:
        self._store = store
        self._missing_config = missing_config
        self.calls = 0

    async def capture(self, *, app_slug: str, app_name: str) -> dict[str, str]:
        del app_name
        self.calls += 1
        if self._missing_config or self._store is None:
            raise ConfigurationRequiredError(
                phase=6, capability="credential capture", reason_code="secret_store_missing"
            )
        reference = self._store.put(app_slug=app_slug, kind="access_token", value=RAW_SECRET)
        return {"access_token": reference}


class _FakeValidator:
    def __init__(self, status: ValidationStatus, *, missing_config: bool = False) -> None:
        self._status = status
        self._missing_config = missing_config
        self.calls = 0

    async def validate(
        self, *, app_slug: str, credential_refs: dict[str, str]
    ) -> CredentialValidationResult:
        del app_slug, credential_refs
        self.calls += 1
        if self._missing_config:
            raise ConfigurationRequiredError(
                phase=6,
                capability="credential validation",
                reason_code="trusted_validation_adapter_missing",
            )
        reasons = {
            "valid": ("read_only_identity_confirmed", 200),
            "invalid": ("provider_rejected_credentials", 401),
            "unavailable": ("provider_temporarily_unavailable", 503),
            "failed": ("unexpected_validation_status", 418),
        }
        reason_code, http_status = reasons[self._status]
        return CredentialValidationResult(
            status=self._status,
            endpoint=HUBSPOT_ENDPOINT,
            http_status=http_status,
            checked_at="2026-01-01T00:00:00Z",
            reason_code=reason_code,
        )


def _request(app_name: str) -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Deliver an authorized integration via the provider developer API.",
        ),
    )


def _service(
    tmp: Path,
    *,
    capturer: object,
    validator: object,
    browser_outcome: str = "credential_page_ready",
    gmail: object = None,
) -> RunService:
    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(
            browser=_FakeBrowser(browser_outcome),  # type: ignore[arg-type]
            gmail=gmail,  # type: ignore[arg-type]
        ),
    )
    return RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=Settings(),
        workflow=workflow,
        capability_preflight=_StubPreflight(_fallback_report()),
        credential_capturer=capturer,  # type: ignore[arg-type]
        credential_validator=validator,  # type: ignore[arg-type]
    )


def _store(tmp: Path) -> SQLiteSecretStore:
    return SQLiteSecretStore(tmp / "private" / "vault.db", Fernet.generate_key())


def _events(service: RunService, run_id: str) -> list[str]:
    return [event["event_type"] for event in service.get_timeline(run_id)]


def _event(service: RunService, run_id: str, event_type: str) -> dict[str, object] | None:
    for event in service.get_timeline(run_id):
        if event["event_type"] == event_type:
            return event["payload"]
    return None


def test_credential_page_ready_captures_once(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    events = _events(service, run["run_id"])

    assert capture.calls == 1
    assert validator.calls == 1
    assert run["status"] == "completed"
    for expected in (
        "credential_capture_started",
        "credentials_stored",
        "credential_validation_started",
        "credentials_validated",
        "integrator_bundle_generated",
    ):
        assert expected in events


def test_captured_secrets_become_vault_references(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    service = _service(tmp_path, capturer=capture, validator=_FakeValidator("valid"))

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    output = service.get_output(run["run_id"])
    stored_event = _event(service, run["run_id"], "credentials_stored")

    assert output is not None
    refs = output["credential_refs"]
    assert refs
    for reference in refs.values():
        assert reference.startswith("vault://")
    assert stored_event is not None
    assert stored_event["kinds"] == ["access_token"]


def test_no_raw_secret_persisted_anywhere(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    service = _service(tmp_path, capturer=capture, validator=_FakeValidator("valid"))

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    stored = service.storage.get_run(run["run_id"])
    output = service.get_output(run["run_id"])
    haystack = repr(run) + repr(stored) + repr(output) + repr(service.get_timeline(run["run_id"]))
    assert RAW_SECRET not in haystack

    for db_name in ("ops.db", "checkpoints.db"):
        db_path = tmp_path / "private" / db_name
        if db_path.exists():
            assert RAW_SECRET.encode() not in db_path.read_bytes()


def test_valid_credentials_complete_run_with_bundle(tmp_path: Path) -> None:
    service = _service(
        tmp_path, capturer=_FakeCapture(_store(tmp_path)), validator=_FakeValidator("valid")
    )

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    output = service.get_output(run["run_id"])

    assert run["status"] == "completed"
    assert output is not None
    assert output["readiness"] == "credentials_ready"


def test_invalid_credentials_return_configuration_required(tmp_path: Path) -> None:
    service = _service(
        tmp_path, capturer=_FakeCapture(_store(tmp_path)), validator=_FakeValidator("invalid")
    )

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    validated = _event(service, run["run_id"], "credentials_validated")

    assert run["status"] == "configuration_required"
    assert validated is not None
    assert validated["validation_status"] == "invalid"
    assert validated["reason_code"] == "provider_rejected_credentials"


def test_missing_vault_configuration_returns_configuration_required(tmp_path: Path) -> None:
    capture = _FakeCapture(None, missing_config=True)
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")

    assert run["status"] == "configuration_required"
    assert capture.calls == 1
    assert validator.calls == 0
    assert _event(service, run["run_id"], "credentials_stored") is None


def test_ambiguous_validation_is_outcome_unknown(tmp_path: Path) -> None:
    service = _service(
        tmp_path, capturer=_FakeCapture(_store(tmp_path)), validator=_FakeValidator("unavailable")
    )

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")
    validated = _event(service, run["run_id"], "credentials_validated")

    assert run["status"] == "configuration_required"
    assert decision is not None
    assert decision["reason_code"] == "validation_outcome_unknown"
    assert validated is not None
    assert validated["validation_status"] == "unavailable"


def test_idempotent_replay_does_not_capture_twice(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator)
    key = "idem_0123456789abcdef0123456789abcdef"

    first = service.create_run(
        _request(SELF_SERVE_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )
    replay = service.create_run(
        _request(SELF_SERVE_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )

    assert replay == first
    assert capture.calls == 1
    assert validator.calls == 1
    assert service.storage.count_runs() == 1


def test_plan_only_performs_zero_credential_actions(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="plan_only")

    assert run["status"] == "route_selected"
    assert capture.calls == 0
    assert validator.calls == 0


def test_waiting_for_hitl_does_not_capture_credentials(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator, browser_outcome="hitl")

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")

    assert run["status"] == "waiting_for_hitl"
    assert capture.calls == 0
    assert validator.calls == 0


def test_gated_flow_does_not_invoke_credential_capture(tmp_path: Path) -> None:
    capture = _FakeCapture(_store(tmp_path))
    validator = _FakeValidator("valid")
    service = _service(tmp_path, capturer=capture, validator=validator)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")

    assert run["access_route"] in {"approval_required", "partner_gated"}
    assert capture.calls == 0
    assert validator.calls == 0


def test_secret_store_retrieval_requires_exact_reference(tmp_path: Path) -> None:
    store = _store(tmp_path)
    capture = _FakeCapture(store)
    service = _service(tmp_path, capturer=capture, validator=_FakeValidator("valid"))

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    output = service.get_output(run["run_id"])
    assert output is not None
    reference = next(iter(output["credential_refs"].values()))

    assert store.get(reference) == RAW_SECRET
    try:
        store.get("vault://hubspot/access_token/wrong-identifier")
    except SecretNotFoundError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("wrong reference must not resolve")


def test_api_backed_output_exposes_sanitized_bundle(tmp_path: Path) -> None:
    service = _service(
        tmp_path, capturer=_FakeCapture(_store(tmp_path)), validator=_FakeValidator("valid")
    )

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    output = service.get_output(run["run_id"])

    assert output is not None
    assert output["app_slug"] == "hubspot"
    assert output["readiness"] == "credentials_ready"
    assert output["access_route"] == "self_serve"
    assert set(output["credential_refs"]) == {"access_token"}
