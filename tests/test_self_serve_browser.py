"""M5 controlled self-serve browser onboarding, gated by Composio capability.

Every test is offline-safe: the browser adapter and the capability preflight are
fakes. No live Browser Use call, no credential capture, no credential validation.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.composio_capability import CapabilityState, ComposioCapabilityReport
from ops.config import Settings
from ops.effect_ledger import SQLiteEffectStore
from ops.graph import WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationsRequest
from ops.provider_errors import ProviderOperationError
from ops.run_service import RunService

SELF_SERVE_APP = "HubSpot"
GATED_APP = "Salesforce"


class _FakeBrowser:
    """Minimal WorkflowBrowser: start + navigate, returning one bounded outcome."""

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.starts = 0

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        self.starts += 1
        if self.outcome == "ambiguous_start":
            raise ProviderOperationError(
                capability="Browser Use session", reason_code="provider_outcome_unknown"
            )
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
        if self.outcome == "credential_page_ready":
            return BrowserObservation(
                status="credential_page_ready",
                current_url="https://developers.hubspot.com/apps/new",
                page_title="Create a developer app",
            )
        if self.outcome == "hitl":
            return BrowserObservation(
                status="human_action_required",
                current_url="https://app.hubspot.com/login",
                page_title="Log in",
                human_action_type="captcha",
                human_instruction="Solve the CAPTCHA in the live browser.",
            )
        raise AssertionError(f"unexpected navigate outcome {self.outcome!r}")

    async def resume_after_hitl(
        self,
        context: object,
        signal: object,
        research: object = None,
        *,
        sensitive_data: object = None,
        provider_session_id: object = None,
    ) -> BrowserObservation:
        raise AssertionError("HITL resume is out of M5 scope")


class _StubPreflight:
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
        app_slug="hubspot",
        toolkit_available=available,
        toolkit_slug="hubspot" if available else None,
        required_auth_schemes=(),
        managed_auth_available=state == "connection_required",
        active_connected_account=state == "composio_ready",
        required_tools_present=True,
        capability_state=state,
        reason_code=reason,
        detail="stub capability report",
    )


def _fallback_report() -> ComposioCapabilityReport:
    return _report("toolkit_unavailable", reason="composio_toolkit_absent")


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
    browser: object,
    *,
    preflight: object,
    effect_store: SQLiteEffectStore | None = None,
    gmail: object = None,
) -> RunService:
    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(
            browser=browser,  # type: ignore[arg-type]
            gmail=gmail,  # type: ignore[arg-type]
            effect_store=effect_store,
        ),
    )
    return RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=Settings(),
        workflow=workflow,
        capability_preflight=preflight,  # type: ignore[arg-type]
    )


def _events(service: RunService, run_id: str) -> list[str]:
    return [event["event_type"] for event in service.get_timeline(run_id)]


def _event(service: RunService, run_id: str, event_type: str) -> dict[str, object] | None:
    for event in service.get_timeline(run_id):
        if event["event_type"] == event_type:
            return event["payload"]
    return None


def test_plan_only_starts_zero_browser_sessions(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_fallback_report())
    service = _service(tmp_path, browser, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="plan_only")

    assert browser.starts == 0
    assert stub.calls == 0
    assert run["status"] == "route_selected"
    assert run["external_actions"] is False


def test_self_serve_fallback_starts_exactly_one_session_and_reaches_credential_page(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_fallback_report())
    effects = SQLiteEffectStore(tmp_path / "effects.db")
    service = _service(tmp_path, browser, preflight=stub, effect_store=effects)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    stored = service.storage.get_run(run["run_id"])
    events = _events(service, run["run_id"])

    assert browser.starts == 1
    assert stub.calls == 1
    assert run["access_route"] == "self_serve"
    assert run["status"] == "browser_running"
    assert run["external_actions"] is True
    assert stored is not None
    assert stored["gmail_thread_id"] is None
    assert "browser_session_started" in events
    assert "browser_navigation_completed" in events
    assert "credential_page_ready" in events


def test_captcha_requirement_reaches_waiting_for_hitl(tmp_path: Path) -> None:
    browser = _FakeBrowser("hitl")
    stub = _StubPreflight(_fallback_report())
    service = _service(tmp_path, browser, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    hitl = _event(service, run["run_id"], "browser_hitl_required")
    events = _events(service, run["run_id"])

    assert browser.starts == 1
    assert run["status"] == "waiting_for_hitl"
    assert run["external_actions"] is True
    assert "browser_session_started" in events
    assert hitl is not None
    assert hitl["required_human_action"] == "captcha"


def test_replay_same_idempotency_key_starts_zero_additional_sessions(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_fallback_report())
    service = _service(tmp_path, browser, preflight=stub)
    key = "idem_0123456789abcdef0123456789abcdef"

    first = service.create_run(
        _request(SELF_SERVE_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )
    replay = service.create_run(
        _request(SELF_SERVE_APP), idempotency_key=key, execution_mode="execute_when_configured"
    )

    assert replay == first
    assert browser.starts == 1
    assert stub.calls == 1
    assert service.storage.count_runs() == 1


def test_composio_ready_starts_zero_browser_sessions(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_report("composio_ready", reason="composio_connection_active"))
    service = _service(tmp_path, browser, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert browser.starts == 0
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "composio_ready"


def test_composio_connection_required_starts_zero_browser_sessions(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_report("connection_required", reason="composio_connection_missing"))
    service = _service(tmp_path, browser, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert browser.starts == 0
    assert run["status"] == "configuration_required"
    assert decision is not None
    assert decision["reason_code"] == "composio_connection_required"


def test_gated_route_starts_zero_browser_sessions(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_fallback_report())
    # Gated app with no Gmail dependency: routes to outreach (not browser).
    service = _service(tmp_path, browser, preflight=stub, gmail=None)

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")

    assert browser.starts == 0
    assert run["access_route"] in {"approval_required", "partner_gated"}
    assert run["external_actions"] is False


def test_missing_browser_configuration_returns_configuration_required(tmp_path: Path) -> None:
    stub = _StubPreflight(_fallback_report())
    service = _service(tmp_path, None, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "browser_adapter_missing"


def test_ambiguous_session_start_is_outcome_unknown_without_blind_retry(tmp_path: Path) -> None:
    browser = _FakeBrowser("ambiguous_start")
    stub = _StubPreflight(_fallback_report())
    effects = SQLiteEffectStore(tmp_path / "effects.db")
    service = _service(tmp_path, browser, preflight=stub, effect_store=effects)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    decision = _event(service, run["run_id"], "configuration_required")

    assert browser.starts == 1
    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
    assert decision is not None
    assert decision["reason_code"] == "browser_outcome_unknown"
    assert _event(service, run["run_id"], "credential_page_ready") is None

    # The reservation is outcome-unknown: a fresh reserve of the same effect key
    # requires reconciliation rather than a blind resend.
    # The graph keys the effect on the workflow thread_id (its internal run_id).
    reservation = effects.reserve(
        provider="browser_use",
        action="start_session",
        idempotency_key=f"{run['thread_id']}:browser-start",
    )
    assert reservation.status == "reconcile_required"


def test_browser_onboarding_persists_no_secret_material(tmp_path: Path) -> None:
    browser = _FakeBrowser("credential_page_ready")
    stub = _StubPreflight(_fallback_report())
    service = _service(tmp_path, browser, preflight=stub)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    stored = service.storage.get_run(run["run_id"])
    timeline = service.get_timeline(run["run_id"])
    haystack = repr(stored) + repr(timeline) + repr(run)

    for forbidden in ("vault://company/work_email/profile_1", "SecretStr", "password", "cdp_url"):
        assert forbidden not in haystack
