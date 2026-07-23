"""Credential-injection HITL, owner-only raw reveal, and gated outreach routing.

Every test is offline-safe: the Browser Use client, Gmail, capability preflight,
and credential capture/validation are fakes; the vault is the real encrypted
SQLiteSecretStore. No live Browser Use, Composio, Gmail, HubSpot, or OAuth call
occurs. These tests cover the "human submits login -> agent logs in autonomously
-> obtained credential revealed to the owner; gated app -> controlled outreach"
inversion.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.app import create_app
from api.assignment_runtime import (
    _GATED_OUTREACH_APPS,
    AssignmentBrowserWorker,
    _assignment_after_route,
)
from ops.browser_worker import (
    BrowserObservation,
    BrowserSessionContext,
    BrowserTaskOutput,
    _render_browser_task,
)
from ops.composio_capability import CapabilityState, ComposioCapabilityReport
from ops.config import Settings
from ops.credential_validator import CredentialValidationResult, ValidationStatus
from ops.gmail_worker import GmailSendResult
from ops.graph import WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationsRequest
from ops.p1_adapter import P1OperationalAdapter, to_operational_research
from ops.redaction import redact_data
from ops.run_service import RunService
from ops.secret_store import SQLiteSecretStore

SELF_SERVE_APP = "HubSpot"
GATED_APP = "Close"
OVERRIDE = "controlled-inbox@example.test"
RAW_EMAIL = "owner-login@corp.example"  # pragma: allowlist secret
RAW_PASSWORD = "sup3r-s3cret-P@ssw0rd"  # pragma: allowlist secret
RAW_TOKEN = "hs-access-token-DO-NOT-PERSIST"  # pragma: allowlist secret


# --------------------------------------------------------------------------- #
# Shared fakes                                                                #
# --------------------------------------------------------------------------- #
class _StubPreflight:
    def __init__(self, report: ComposioCapabilityReport) -> None:
        self._report = report

    async def evaluate(
        self, *, app_name: str, app_slug: str | None = None, required_tools: object = ()
    ) -> ComposioCapabilityReport:
        del app_name, app_slug, required_tools
        return self._report


def _report(state: CapabilityState, *, slug: str = "hubspot") -> ComposioCapabilityReport:
    available = state != "toolkit_unavailable"
    return ComposioCapabilityReport(
        app_slug=slug,
        toolkit_available=available,
        toolkit_slug=slug if available else None,
        required_auth_schemes=(),
        managed_auth_available=state == "connection_required",
        active_connected_account=state == "composio_ready",
        required_tools_present=True,
        capability_state=state,
        reason_code="stub",
        detail="stub capability report",
    )


def _fallback_report(slug: str = "hubspot") -> ComposioCapabilityReport:
    return _report("toolkit_unavailable", slug=slug)


def _session(session_id: str = "browser-sess-1") -> BrowserSessionContext:
    return BrowserSessionContext(
        profile_id="profile-1",
        session_id=session_id,
        live_view_available=False,
        allowed_domains=(),
        created_at="2026-01-01T00:00:00Z",
        inactivity_expires_at="2026-01-01T00:15:00Z",
        maximum_expires_at="2026-01-01T04:00:00Z",
    )


class _LoginThenCredentialBrowser:
    """Pauses for a login HITL, then advances to the credential page on resume.

    ``resume_after_hitl`` records the ``sensitive_data`` the graph forwarded so a
    test can assert the owner login reached the provider boundary.
    """

    def __init__(self) -> None:
        self.starts = 0
        self.resume_sensitive_data: list[dict[str, str] | None] = []

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        self.starts += 1
        return _session()

    async def navigate_onboarding(self, context: object, research: object) -> BrowserObservation:
        del context, research
        return BrowserObservation(
            status="human_action_required",
            current_url="https://app.hubspot.com/login",
            page_title="Log in",
            human_action_type="provider_verification",
            human_instruction="Log in to your account to continue.",
        )

    async def resume_after_hitl(
        self,
        context: object,
        signal: object,
        *,
        sensitive_data: dict[str, str] | None = None,
    ) -> BrowserObservation:
        del context, signal
        self.resume_sensitive_data.append(
            dict(sensitive_data) if sensitive_data is not None else None
        )
        return BrowserObservation(
            status="credential_page_ready",
            current_url="https://developers.hubspot.com/apps/new",
            page_title="Create a developer app",
        )


class _CredentialPageBrowser:
    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        return _session()

    async def navigate_onboarding(self, context: object, research: object) -> BrowserObservation:
        del context, research
        return BrowserObservation(
            status="credential_page_ready",
            current_url="https://developers.hubspot.com/apps/new",
            page_title="Create a developer app",
        )

    async def resume_after_hitl(
        self, context: object, signal: object, *, sensitive_data: object = None
    ) -> BrowserObservation:
        raise AssertionError("resume is out of scope for this fake")


class _FakeCapture:
    def __init__(self, store: SQLiteSecretStore) -> None:
        self._store = store

    async def capture(self, *, app_slug: str, app_name: str) -> dict[str, str]:
        del app_name
        return {
            "access_token": self._store.put(app_slug=app_slug, kind="access_token", value=RAW_TOKEN)
        }


class _FakeValidator:
    def __init__(self, status: ValidationStatus) -> None:
        self._status = status

    async def validate(
        self, *, app_slug: str, credential_refs: dict[str, str]
    ) -> CredentialValidationResult:
        del app_slug, credential_refs
        return CredentialValidationResult(
            status=self._status,
            endpoint="https://api.hubapi.com/account-info/v3/details",
            http_status=200,
            checked_at="2026-01-01T00:00:00Z",
            reason_code="read_only_identity_confirmed",
        )


class _RecordingGmail:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    async def send_outreach(
        self, recipient: str, subject: str, body: str, idempotency_key: str
    ) -> GmailSendResult:
        del subject, body, idempotency_key
        self.sent.append({"recipient": recipient})
        return GmailSendResult(
            session_id="gmail-sess",
            thread_id="thread-xyz",
            message_id="msg-1",
            intended_recipient=recipient,
            actual_recipient=OVERRIDE,
        )


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Deliver an authorized integration via the provider developer API.",
    )


def _request(app_name: str) -> OperationsRequest:
    return OperationsRequest(app_name=app_name, company=_company())


def _timeline_event(service: RunService, run_id: str, event_type: str) -> dict[str, object] | None:
    for event in service.get_timeline(run_id):
        if event["event_type"] == event_type:
            return event["payload"]
    return None


# --------------------------------------------------------------------------- #
# 1. Login-aware task text                                                    #
# --------------------------------------------------------------------------- #
def test_login_task_uses_secret_placeholders_and_drops_password_hard_stop() -> None:
    task = _render_browser_task(
        "https://app.hubspot.com/login",
        ("app.hubspot.com", "developers.hubspot.com"),
        "completed",
        ("login_email", "login_password"),
    )

    assert "<secret>login_email</secret>" in task
    assert "<secret>login_password</secret>" in task
    # With injected credentials, entering a password is no longer a hard stop...
    assert "entering a password" not in task
    # ...but every other human-only gate still pauses for HITL.
    assert "CAPTCHA" in task
    assert "MFA/OTP" in task
    # Raw values never appear (only placeholder key names do).
    assert RAW_PASSWORD not in task


def test_non_login_task_keeps_password_as_a_hard_stop() -> None:
    task = _render_browser_task(
        "https://app.hubspot.com/login",
        ("app.hubspot.com",),
        None,
    )

    assert "entering a password" in task
    assert "<secret>login_email</secret>" not in task


# --------------------------------------------------------------------------- #
# 2. Worker forwards sensitive_data to the Browser Use client                 #
# --------------------------------------------------------------------------- #
def test_worker_resume_forwards_sensitive_data_and_never_leaks_values() -> None:
    import asyncio

    research = to_operational_research(P1OperationalAdapter().lookup(SELF_SERVE_APP).record)

    class _RecordingClient:
        def __init__(self) -> None:
            self.captured: list[dict[str, object]] = []

        def run(self, task: str, **kwargs: object) -> BrowserTaskOutput:
            self.captured.append({"task": task, **kwargs})
            return BrowserTaskOutput(
                current_url="https://developers.hubspot.com/apps/new",
                reached_official_setup_page=True,
                hitl_required=False,
                safe_summary="Reached the developer app page.",
            )

    client = _RecordingClient()
    worker = AssignmentBrowserWorker(
        settings=Settings(allow_live_browser=True, browser_use_api_key=SecretStr("bu-key")),
        client=client,
    )
    context = _session()
    worker._provider_sessions[context.session_id] = "provider-1"
    worker._assignment_research[context.session_id] = research

    observation = asyncio.run(
        worker.resume_after_hitl(
            context,
            "completed",
            sensitive_data={"login_email": RAW_EMAIL, "login_password": RAW_PASSWORD},
        )
    )

    assert observation.status == "credential_page_ready"
    call = client.captured[0]
    assert call["sensitive_data"] == {"login_email": RAW_EMAIL, "login_password": RAW_PASSWORD}
    # The raw values are injected out-of-band; only placeholder keys reach the task text.
    assert RAW_PASSWORD not in call["task"]
    assert RAW_EMAIL not in call["task"]
    assert "<secret>login_password</secret>" in call["task"]


# --------------------------------------------------------------------------- #
# 3. End-to-end resume injection through the real graph, with no persistence  #
# --------------------------------------------------------------------------- #
def _injection_service(tmp: Path, browser: object) -> RunService:
    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(browser=browser),  # type: ignore[arg-type]
    )
    return RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=Settings(),
        workflow=workflow,
        capability_preflight=_StubPreflight(_fallback_report()),
    )


def test_resume_injects_login_and_advances_without_persisting_secrets(tmp_path: Path) -> None:
    browser = _LoginThenCredentialBrowser()
    service = _injection_service(tmp_path, browser)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    assert run["status"] == "waiting_for_hitl"

    resumed = service.resume_run(
        run["run_id"],
        signal="completed",
        browser_login={
            "login_email": SecretStr(RAW_EMAIL),
            "login_password": SecretStr(RAW_PASSWORD),
        },
    )

    # The agent logged in autonomously with the injected credentials.
    assert browser.resume_sensitive_data == [
        {"login_email": RAW_EMAIL, "login_password": RAW_PASSWORD}
    ]
    assert resumed["status"] == "browser_running"

    # Only the non-secret field names are recorded; never the values.
    injected = _timeline_event(service, run["run_id"], "login_credentials_injected")
    assert injected is not None
    assert injected["fields"] == ["login_email", "login_password"]

    # No raw credential value is persisted to the ledger, timeline, or databases.
    stored = service.storage.get_run(run["run_id"])
    haystack = repr(stored) + repr(service.get_timeline(run["run_id"])) + repr(resumed)
    for forbidden in (RAW_EMAIL, RAW_PASSWORD):
        assert forbidden not in haystack
    for db_name in ("ops.db", "checkpoints.db"):
        db_path = tmp_path / "private" / db_name
        if db_path.exists():
            raw = db_path.read_bytes()
            assert RAW_EMAIL.encode() not in raw
            assert RAW_PASSWORD.encode() not in raw


def test_resume_without_login_is_backward_compatible(tmp_path: Path) -> None:
    browser = _LoginThenCredentialBrowser()
    service = _injection_service(tmp_path, browser)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    resumed = service.resume_run(run["run_id"], signal="completed")

    assert browser.resume_sensitive_data == [None]
    assert resumed["status"] == "browser_running"
    assert _timeline_event(service, run["run_id"], "login_credentials_injected") is None


# --------------------------------------------------------------------------- #
# 4. Owner-only raw credential reveal                                         #
# --------------------------------------------------------------------------- #
def _reveal_service(tmp: Path, store: SQLiteSecretStore) -> RunService:
    workflow = build_graph(
        checkpoint_path=tmp / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(browser=_CredentialPageBrowser()),  # type: ignore[arg-type]
    )
    service = RunService.from_paths(
        db_path=tmp / "private" / "ops.db",
        settings=Settings(),
        workflow=workflow,
        capability_preflight=_StubPreflight(_fallback_report()),
        credential_capturer=_FakeCapture(store),
        credential_validator=_FakeValidator("valid"),
    )
    # Wire the same encrypted vault the capture wrote into so the owner reveal can
    # resolve the references back to raw values.
    service._secret_store = store
    return service


def test_reveal_returns_raw_values_and_audits_kinds_only(tmp_path: Path) -> None:
    store = SQLiteSecretStore(tmp_path / "private" / "vault.db", Fernet.generate_key())
    service = _reveal_service(tmp_path, store)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="execute_when_configured")
    assert run["status"] == "completed"

    revealed = service.reveal_credentials(run["run_id"])

    assert revealed == {"access_token": RAW_TOKEN}
    # The act of revealing is audited, but only by kind -- never the value.
    event = _timeline_event(service, run["run_id"], "credentials_revealed")
    assert event is not None
    assert event["kinds"] == ["access_token"]
    assert RAW_TOKEN not in repr(event)
    # The reference-only output bundle still exposes no raw value.
    output = service.get_output(run["run_id"])
    assert output is not None
    assert RAW_TOKEN not in repr(output)


def test_reveal_without_bundle_returns_empty(tmp_path: Path) -> None:
    store = SQLiteSecretStore(tmp_path / "private" / "vault.db", Fernet.generate_key())
    service = _reveal_service(tmp_path, store)

    run = service.create_run(_request(SELF_SERVE_APP), execution_mode="plan_only")
    assert service.reveal_credentials(run["run_id"]) == {}


def test_reveal_unknown_run_returns_none(tmp_path: Path) -> None:
    store = SQLiteSecretStore(tmp_path / "private" / "vault.db", Fernet.generate_key())
    service = _reveal_service(tmp_path, store)

    assert service.reveal_credentials("run_" + "0" * 32) is None


# --------------------------------------------------------------------------- #
# 5. Redaction defense-in-depth                                               #
# --------------------------------------------------------------------------- #
def test_login_email_key_is_redacted() -> None:
    sanitized = redact_data({"login_email": RAW_EMAIL, "login_password": RAW_PASSWORD})
    assert sanitized == {"login_email": "[REDACTED]", "login_password": "[REDACTED]"}


# --------------------------------------------------------------------------- #
# 6. API owner-only gating                                                    #
# --------------------------------------------------------------------------- #
def _create_payload(app_name: str = SELF_SERVE_APP) -> dict[str, object]:
    return {
        "app_name": app_name,
        "company": {
            "legal_name": "Example Company",
            "website": "https://example.test",
            "work_email_ref": "vault://company/work_email/test-operator",
            "use_case": "Evaluate documented integration access.",
        },
        "execution_mode": "plan_only",
        "dry_run": True,
    }


def test_resume_with_login_requires_owner_optin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", raising=False)
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        run_id = client.post("/api/runs", json=_create_payload()).json()["run"]["run_id"]
        body = {"browser_login": {"email": RAW_EMAIL, "password": RAW_PASSWORD}}
        forbidden = client.post(f"/api/runs/{run_id}/resume", json=body)
        # A bare resume (no login credentials) is not owner-gated.
        plain = client.post(f"/api/runs/{run_id}/resume")

    assert forbidden.status_code == 403
    assert plain.status_code != 403


def test_reveal_requires_owner_optin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", raising=False)
    application = create_app(db_path=tmp_path / "private" / "ops.db")
    with TestClient(application) as client:
        run_id = client.post("/api/runs", json=_create_payload()).json()["run"]["run_id"]
        blocked = client.post(f"/api/runs/{run_id}/credentials/reveal")

        monkeypatch.setenv("ALLOW_LOCAL_CREDENTIAL_SUBMISSION", "true")
        opted_in = client.post(f"/api/runs/{run_id}/credentials/reveal")

    assert blocked.status_code == 403
    # With the owner opt-in the gate passes; the run simply has no revealable
    # credential vault configured, so it is no longer a 403.
    assert opted_in.status_code != 403


# --------------------------------------------------------------------------- #
# 7. Gated live-matrix apps route to controlled outreach                      #
# --------------------------------------------------------------------------- #
def _executing_request(app_name: str) -> dict[str, object]:
    # _assignment_after_route runs only for a real (non-dry) execution.
    return _request(app_name).model_copy(update={"dry_run": False}).model_dump(mode="json")


@pytest.mark.parametrize("slug", sorted(_GATED_OUTREACH_APPS))
def test_assignment_route_sends_gated_apps_to_outreach(slug: str) -> None:
    state = {
        "request": _executing_request(GATED_APP),
        "access_route": "partner_gated",
        "app_slug": slug,
    }
    assert _assignment_after_route(None, state) == "outreach_send"


def test_assignment_route_keeps_self_serve_apps_on_browser() -> None:
    state = {
        "request": _executing_request(SELF_SERVE_APP),
        "access_route": "self_serve",
        "app_slug": "hubspot",
    }
    assert _assignment_after_route(None, state) == "browser_start"


def test_assignment_route_finalizes_dry_run_and_blocked() -> None:
    dry = {
        "request": _request(GATED_APP).model_copy(update={"dry_run": True}).model_dump(mode="json"),
        "access_route": "partner_gated",
        "app_slug": "close",
    }
    blocked = {
        "request": _executing_request(GATED_APP),
        "access_route": "blocked",
        "app_slug": "close",
    }
    assert _assignment_after_route(None, dry) == "finalize"
    assert _assignment_after_route(None, blocked) == "finalize"


def test_gated_outreach_falls_back_to_override_when_no_contact(tmp_path: Path) -> None:
    gmail = _RecordingGmail()

    def loader(app_name: str) -> object:
        return to_operational_research(P1OperationalAdapter().lookup(app_name).record)

    workflow = build_graph(
        checkpoint_path=tmp_path / "private" / "checkpoints.db",
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(
            gmail=gmail,  # type: ignore[arg-type]
            research_loader=loader,  # type: ignore[arg-type]
            outreach_recipient=OVERRIDE,
        ),
    )
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(outreach_recipient_override=OVERRIDE),
        workflow=workflow,
        capability_preflight=_StubPreflight(
            _report("custom_auth_or_approval_required", slug="close")
        ),
    )

    # Close is partner_gated and carries no discovered contact address.
    research = to_operational_research(P1OperationalAdapter().lookup(GATED_APP).record)
    assert research.contact_email is None

    run = service.create_run(_request(GATED_APP), execution_mode="execute_when_configured")

    assert run["status"] == "waiting_for_reply"
    assert len(gmail.sent) == 1
    assert gmail.sent[0]["recipient"] == OVERRIDE
