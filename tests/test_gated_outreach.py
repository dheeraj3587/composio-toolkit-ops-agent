"""M4 controlled gated-app outreach through Composio Gmail, gated by capability.

Every test is offline-safe. The Composio SDK is replaced by an in-process fake
client and the capability preflight is a stub, so no live email is ever sent.
The controlled ``OUTREACH_RECIPIENT_OVERRIDE`` is always applied, so a discovered
vendor address is never contacted.
"""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

import pytest
from pydantic import SecretStr

from ops.composio_capability import CapabilityState, ComposioCapabilityReport
from ops.config import Settings
from ops.effect_ledger import SQLiteEffectStore
from ops.gmail_worker import GmailWorker
from ops.graph import WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationalResearch, OperationsRequest
from ops.p1_adapter import P1OperationalAdapter, to_operational_research
from ops.provider_errors import ProviderOperationError
from ops.run_service import RunService

GATED_APP = "Salesforce"
SELF_SERVE_APP = "HubSpot"
OVERRIDE = "controlled-inbox@example.test"
VENDOR = "partnerships@salesforce.com"

_TOOL_SCHEMAS: dict[str, dict[str, object]] = {
    "GMAIL_GET_PROFILE": {
        "properties": {"user_id": {"type": "string"}},
        "required": ["user_id"],
    },
    "GMAIL_SEND_EMAIL": {
        "properties": {
            "recipient_email": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
            "is_html": {"type": "boolean"},
        },
        "required": ["recipient_email", "subject", "body"],
    },
}


class _Resp:
    def __init__(self, successful: bool, data: dict[str, object]) -> None:
        self.successful = successful
        self.data = data


class _RawTool:
    def __init__(self, params: dict[str, object]) -> None:
        self.input_parameters = params


class _Session:
    def __init__(self, session_id: str) -> None:
        self.id = session_id


class _Sessions:
    def create(self, **kwargs: object) -> _Session:
        del kwargs
        return _Session("session-abc123")


class _Tools:
    def __init__(self, sends: list[dict[str, object]], *, send_successful: bool = True) -> None:
        self._sends = sends
        self._send_successful = send_successful

    def get_raw_composio_tool_by_slug(self, slug: str) -> _RawTool:
        return _RawTool(_TOOL_SCHEMAS[slug])

    def execute(self, slug: str, arguments: dict[str, object], **kwargs: object) -> _Resp:
        del kwargs
        if slug == "GMAIL_GET_PROFILE":
            return _Resp(True, {"email": "ops-bot@example.test"})
        if slug == "GMAIL_SEND_EMAIL":
            self._sends.append(dict(arguments))
            if not self._send_successful:
                return _Resp(False, {})
            return _Resp(True, {"message_id": "msg-1", "thread_id": "thread-xyz"})
        return _Resp(True, {})


class _FakeComposio:
    def __init__(self, sends: list[dict[str, object]], *, send_successful: bool = True) -> None:
        self.sessions = _Sessions()
        self.tools = _Tools(sends, send_successful=send_successful)

    def close(self) -> None:  # pragma: no cover - parity with the real client
        return None


class _StubPreflight:
    """A capability preflight that returns a canned report and counts calls."""

    def __init__(self, report: ComposioCapabilityReport) -> None:
        self._report = report
        self.calls = 0

    async def evaluate(
        self,
        *,
        app_name: str,
        app_slug: str | None = None,
        required_tools: object = (),
    ) -> ComposioCapabilityReport:
        del app_name, app_slug, required_tools
        self.calls += 1
        return self._report


def _report(state: CapabilityState, *, reason: str) -> ComposioCapabilityReport:
    available = state != "toolkit_unavailable"
    return ComposioCapabilityReport(
        app_slug="salesforce",
        toolkit_available=available,
        toolkit_slug="salesforce" if available else None,
        required_auth_schemes=(),
        managed_auth_available=state == "connection_required",
        active_connected_account=state == "composio_ready",
        required_tools_present=True,
        capability_state=state,
        reason_code=reason,
        detail="stub capability report",
    )


def _settings() -> Settings:
    return Settings(
        composio_api_key=SecretStr("test-key"),  # pragma: allowlist secret
        composio_gmail_connected_account_id="gmail-acct-1",
        outreach_recipient_override=OVERRIDE,
    )


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Deliver an authorized customer support automation via the provider API.",
    )


def _request(app_name: str) -> OperationsRequest:
    return OperationsRequest(app_name=app_name, company=_company())


def _gated_research_with_contact() -> OperationalResearch:
    baseline = to_operational_research(P1OperationalAdapter().lookup(GATED_APP).record)
    return baseline.model_copy(update={"contact_email": VENDOR})


def _worker(
    sends: list[dict[str, object]], tmp: Path, *, send_successful: bool = True
) -> GmailWorker:
    return GmailWorker(
        settings=_settings(),
        effect_store=SQLiteEffectStore(tmp / "effects.db"),
        sdk_client=_FakeComposio(sends, send_successful=send_successful),
    )


def _service_with_gmail(
    tmp: Path,
    gmail: object,
    *,
    with_contact: bool = True,
    preflight: object = None,
) -> RunService:
    research = _gated_research_with_contact() if with_contact else None

    def loader(app_name: str) -> OperationalResearch:
        if research is not None:
            return research
        return to_operational_research(P1OperationalAdapter().lookup(app_name).record)

    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(gmail=gmail, research_loader=loader),  # type: ignore[arg-type]
    )
    return RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=_settings(),
        workflow=workflow,
        capability_preflight=preflight,  # type: ignore[arg-type]
    )


def _event(service: RunService, run_id: str, event_type: str) -> dict[str, object] | None:
    for event in service.get_timeline(run_id):
        if event["event_type"] == event_type:
            return event["payload"]
    return None


# --- GmailWorker-level exactly-once, override, and ambiguity guarantees -------


def test_gmail_worker_sends_once_to_override_and_persists_receipt(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    worker = _worker(sends, tmp_path)
    key = "run_00000000000000000000000000000001:initial-outreach"

    result = asyncio.run(worker.send_outreach(VENDOR, "Subject", "Body text.", key))

    assert len(sends) == 1
    assert sends[0]["recipient_email"] == OVERRIDE
    assert result.intended_recipient == VENDOR
    assert result.actual_recipient == OVERRIDE
    assert result.thread_id == "thread-xyz"


def test_gmail_worker_retry_same_key_does_not_resend(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    worker = _worker(sends, tmp_path)
    key = "run_00000000000000000000000000000002:initial-outreach"

    first = asyncio.run(worker.send_outreach(VENDOR, "Subject", "Body text.", key))
    second = asyncio.run(worker.send_outreach(VENDOR, "Subject", "Body text.", key))

    assert len(sends) == 1
    assert second == first


def test_gmail_worker_ambiguous_failure_marks_outcome_unknown_and_blocks_resend(
    tmp_path: Path,
) -> None:
    sends: list[dict[str, object]] = []
    worker = _worker(sends, tmp_path, send_successful=False)
    key = "run_00000000000000000000000000000003:initial-outreach"

    with pytest.raises(ProviderOperationError):
        asyncio.run(worker.send_outreach(VENDOR, "Subject", "Body text.", key))
    assert len(sends) == 1

    with pytest.raises(ProviderOperationError) as raised:
        asyncio.run(worker.send_outreach(VENDOR, "Subject", "Body text.", key))
    assert len(sends) == 1
    assert raised.value.reason_code == "reconciliation_required"


# --- Capability-gated RunService outreach path --------------------------------


def test_plan_only_does_not_invoke_capability_checker(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("toolkit_unavailable", reason="composio_toolkit_absent"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="plan_only")

    assert stub.calls == 0
    assert run["external_actions"] is False
    assert run["status"] == "route_selected"
    assert sends == []


def test_composio_ready_suppresses_outreach(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("composio_ready", reason="composio_connection_active"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    capability = _event(service, run["run_id"], "composio_capability_evaluated")
    decision = _event(service, run["run_id"], "configuration_required")

    assert stub.calls == 1
    assert sends == []
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert capability is not None
    assert capability["capability_state"] == "composio_ready"
    assert decision is not None
    assert decision["reason_code"] == "composio_ready"


def test_connection_required_suppresses_outreach(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("connection_required", reason="composio_connection_missing"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert stub.calls == 1
    assert sends == []
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "composio_connection_required"


def test_custom_auth_sends_one_controlled_outreach(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(
        _report(
            "custom_auth_or_approval_required", reason="composio_custom_auth_or_approval_required"
        )
    )
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    stored = service.storage.get_run(run["run_id"])
    outreach = _event(service, run["run_id"], "outreach_sent")

    assert stub.calls == 1
    assert run["status"] == "waiting_for_reply"
    assert run["external_actions"] is True
    assert len(sends) == 1
    assert sends[0]["recipient_email"] == OVERRIDE
    assert stored is not None
    assert stored["gmail_thread_id"] == "thread-xyz"
    assert outreach is not None
    assert outreach["actual_recipient"] == OVERRIDE
    assert outreach["intended_recipient"] == VENDOR
    assert outreach["provider_outcome"] == "sent"


def test_toolkit_unavailable_sends_one_controlled_outreach(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("toolkit_unavailable", reason="composio_toolkit_absent"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")

    assert stub.calls == 1
    assert run["status"] == "waiting_for_reply"
    assert run["external_actions"] is True
    assert len(sends) == 1
    assert sends[0]["recipient_email"] == OVERRIDE


def test_unconfigured_preflight_fails_closed_with_zero_sends(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("configuration_required", reason="composio_not_configured"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert sends == []
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "composio_not_configured"


def test_missing_preflight_fails_closed(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    # No preflight injected: a gated execute run must never send blindly.
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=None)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")

    assert sends == []
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False


def test_custom_auth_without_gmail_dependency_is_configuration_required(tmp_path: Path) -> None:
    stub = _StubPreflight(
        _report(
            "custom_auth_or_approval_required", reason="composio_custom_auth_or_approval_required"
        )
    )
    service = _service_with_gmail(tmp_path, None, preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "gmail_adapter_missing"


def test_idempotent_replay_does_not_send_a_second_email(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("toolkit_unavailable", reason="composio_toolkit_absent"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)
    key = "idem_0123456789abcdef0123456789abcdef"

    first = service.create_run(
        _request(GATED_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )
    replay = service.create_run(
        _request(GATED_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )

    assert replay == first
    assert len(sends) == 1
    assert stub.calls == 1
    assert service.storage.count_runs() == 1


def test_self_serve_run_sends_zero_emails(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    # Self-serve routes never enter the Gmail outreach path (browser onboarding is
    # covered by the M5 suite). With no capability preflight it stays route-only.
    service = _service_with_gmail(
        tmp_path, _worker(sends, tmp_path), with_contact=False, preflight=None
    )

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")

    assert run["access_route"] == "self_serve"
    assert run["external_actions"] is False
    assert sends == []
    assert _event(service, run["run_id"], "outreach_sent") is None


def test_gated_outreach_persists_no_secret_material(tmp_path: Path) -> None:
    sends: list[dict[str, object]] = []
    stub = _StubPreflight(_report("toolkit_unavailable", reason="composio_toolkit_absent"))
    service = _service_with_gmail(tmp_path, _worker(sends, tmp_path), preflight=stub)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")
    stored = service.storage.get_run(run["run_id"])
    timeline = service.get_timeline(run["run_id"])
    haystack = repr(stored) + repr(timeline) + repr(run)

    for forbidden in ("test-key", "vault://company/work_email/profile_1", "SecretStr"):
        assert forbidden not in haystack


def test_build_workflow_dependencies_injects_gmail_only_when_configured(tmp_path: Path) -> None:
    configured_settings = _settings().model_copy(
        update={"provider_effects_db_path": tmp_path / "configured_effects.db"}
    )
    configured_service = RunService.from_paths(
        db_path=tmp_path / "configured.db", settings=configured_settings
    )
    configured = configured_service._build_workflow_dependencies(configured_settings)
    assert configured.gmail is not None
    assert configured.browser is None

    unconfigured_settings = Settings(provider_effects_db_path=tmp_path / "unconfigured_effects.db")
    unconfigured_service = RunService.from_paths(
        db_path=tmp_path / "unconfigured.db", settings=unconfigured_settings
    )
    unconfigured = unconfigured_service._build_workflow_dependencies(unconfigured_settings)
    assert unconfigured.gmail is None
