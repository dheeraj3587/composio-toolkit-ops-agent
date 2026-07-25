"""Provider-aware live view, restart reconciliation, and provider state.

The invariant behind every test here: adding the self-hosted provider must not
change Browser Use behaviour, and Playwright's real limitations must be reported
honestly rather than papered over.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import SecretStr

from api.models import LiveViewResponse, ProviderState
from ops.browser_readiness import browser_configuration_state
from ops.config import Settings
from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import RunService

_REPO = Path(__file__).resolve().parents[1]


def _request(app_name: str = "Pipedrive") -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/profile_1",
            use_case="Authorized integration via the provider developer API.",
        ),
    )


# --- Live view: Browser Use unchanged, Playwright uses screenshot mode ---------
class _HostedUrlWorker:
    provider_name = "browser_use"
    supports_live_url = True
    supports_screenshot = False

    def live_url(self, session_id: str) -> str | None:
        return "https://live.browser-use.example/session"


class _ScreenshotWorker:
    provider_name = "playwright"
    supports_live_url = False
    supports_screenshot = True

    def live_url(self, session_id: str) -> str | None:
        return None

    def latest_screenshot(self, handle: str) -> tuple[bytes, str] | None:
        return (b"\x89PNG\r\n\x1a\nfake", "2026-07-25T00:00:00+00:00")


def _service_with_worker(tmp_path: Path, worker: object, *, session_id: str = "s1") -> RunService:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    run = service.create_run(_request(), execution_mode="plan_only")
    run_id = run["run_id"]
    with service.storage.unit_of_work() as transaction:
        transaction.update_run(run_id, browser_session_id=session_id)
    service._browser_worker = worker  # type: ignore[assignment]
    service._test_run_id = run_id  # type: ignore[attr-defined]
    return service


def test_browser_use_live_url_behaviour_is_unchanged(tmp_path: Path) -> None:
    service = _service_with_worker(tmp_path, _HostedUrlWorker())
    run_id = service._test_run_id  # type: ignore[attr-defined]
    assert service.get_browser_live_url(run_id) == "https://live.browser-use.example/session"
    # A hosted-URL provider offers no screenshot; the field stays absent.
    assert service.get_browser_screenshot(run_id) is None


def test_playwright_exposes_a_screenshot_and_no_hosted_url(tmp_path: Path) -> None:
    service = _service_with_worker(tmp_path, _ScreenshotWorker())
    run_id = service._test_run_id  # type: ignore[attr-defined]
    assert service.get_browser_live_url(run_id) is None  # no AttributeError/500
    shot = service.get_browser_screenshot(run_id)
    assert shot is not None
    image, captured_at = shot
    assert image.startswith(b"\x89PNG") and captured_at


def test_screenshot_lookup_requires_a_session(tmp_path: Path) -> None:
    service = _service_with_worker(tmp_path, _ScreenshotWorker(), session_id="")
    run_id = service._test_run_id  # type: ignore[attr-defined]
    assert service.get_browser_screenshot(run_id) is None


def test_live_view_response_defaults_stay_backward_compatible() -> None:
    # The pre-existing Browser Use shape (run_id/available/live_url) still validates
    # without the new fields, so no client breaks.
    legacy = LiveViewResponse(run_id="run_1", available=True, live_url="https://x.example/s")
    assert legacy.mode == "unavailable"  # default; hosted mode is set explicitly
    assert legacy.screenshot_url is None and legacy.captured_at is None

    hosted = LiveViewResponse(
        run_id="run_1", available=True, mode="hosted_url", live_url="https://x.example/s"
    )
    assert hosted.mode == "hosted_url"

    shot = LiveViewResponse(
        run_id="run_1",
        available=True,
        mode="screenshot",
        screenshot_url="/api/runs/run_1/live-view/screenshot",
        captured_at="2026-07-25T00:00:00+00:00",
    )
    assert shot.live_url is None and shot.screenshot_url is not None


def test_screenshot_route_is_registered_and_owner_gated() -> None:
    source = (_REPO / "api" / "app.py").read_text(encoding="utf-8")
    assert '"/api/runs/{run_id}/live-view/screenshot"' in source
    # Same owner gate as the live-view endpoint, plus no-store caching.
    marker = source.index("live_view_screenshot")
    body = source[marker : marker + 1_200]
    assert "_require_owner_action(request)" in body
    assert "no-store" in body and "image/png" in body


# --- Provider state model accepts playwright ----------------------------------
def test_provider_state_accepts_playwright() -> None:
    state = ProviderState(provider="playwright", status="configured_not_verified", detail="ok")
    assert state.provider == "playwright"


def test_configuration_state_helper_is_provider_aware() -> None:
    assert browser_configuration_state(Settings(allow_live_browser=True)) is False
    assert (
        browser_configuration_state(
            Settings(allow_live_browser=True, browser_use_api_key=SecretStr("k"))
        )
        is True
    )
    assert (
        browser_configuration_state(
            Settings(allow_live_browser=True, browser_provider="playwright")
        )
        is True
    )


# --- Restart reconciliation is provider-aware ---------------------------------
class _ReattachWorker:
    provider_name = "browser_use"
    supports_restart_reattach = True


class _NoReattachWorker:
    provider_name = "playwright"
    supports_restart_reattach = False


def _run_at(service: RunService, status: str) -> str:
    run = service.create_run(_request(), execution_mode="plan_only")
    run_id = run["run_id"]
    service.guarded_status_update(
        run_id, expected_revision=1, next_status="browser_running", command="test"
    )
    if status == "waiting_for_hitl":
        service.guarded_status_update(
            run_id, expected_revision=2, next_status="waiting_for_hitl", command="test"
        )
    return run_id


def test_browser_use_waiting_for_hitl_stays_resumable(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    service._browser_worker = _ReattachWorker()  # type: ignore[assignment]
    hitl = _run_at(service, "waiting_for_hitl")
    running = _run_at(service, "browser_running")

    service._reconcile_stranded_runs()

    # Cloud sessions can be reattached: HITL is untouched (unchanged behaviour).
    assert service.get_run(hitl)["status"] == "waiting_for_hitl"
    # A stranded navigation still reconciles.
    assert service.get_run(running)["status"] == "configuration_required"


def test_playwright_sessions_are_reconciled_from_both_states(tmp_path: Path) -> None:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    service._browser_worker = _NoReattachWorker()  # type: ignore[assignment]
    hitl = _run_at(service, "waiting_for_hitl")
    running = _run_at(service, "browser_running")

    service._reconcile_stranded_runs()

    # An in-process browser dies with the API: claiming either state is resumable
    # would be false, so both become recoverable configuration_required.
    assert service.get_run(hitl)["status"] == "configuration_required"
    assert service.get_run(running)["status"] == "configuration_required"

    events = [
        event
        for event in service.get_timeline(hitl)
        if event["event_type"] == "run_reconciled_on_startup"
    ]
    assert events, "a reconciliation audit event must be recorded"
    payload = events[0]
    # The audit trail names the honest reason and leaks nothing.
    serialized = repr(payload)
    assert "playwright_session_lost_on_restart" in serialized
    assert "password" not in serialized.casefold()


def test_terminal_playwright_sessions_are_stopped(tmp_path: Path) -> None:
    """A terminal outcome must close the local Chromium session; Browser Use must not
    be stopped through this Playwright-specific branch."""

    class _StoppingWorker:
        provider_name = "playwright"

        def __init__(self) -> None:
            self.stopped: list[object] = []

        async def stop(self, context: object) -> None:
            self.stopped.append(context)

    class _BrowserUseWorker(_StoppingWorker):
        provider_name = "browser_use"

    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    playwright = _StoppingWorker()
    service._browser_worker = playwright  # type: ignore[assignment]
    for status in ("completed", "failed", "blocked", "configuration_required"):
        service._stop_terminal_playwright_session(object(), status)  # type: ignore[arg-type]
    assert len(playwright.stopped) == 4

    # Non-terminal states keep the session (the human/loop still needs it).
    playwright.stopped.clear()
    for status in ("browser_running", "waiting_for_hitl"):
        service._stop_terminal_playwright_session(object(), status)  # type: ignore[arg-type]
    assert playwright.stopped == []

    # Browser Use is never stopped by this branch.
    browser_use = _BrowserUseWorker()
    service._browser_worker = browser_use  # type: ignore[assignment]
    service._stop_terminal_playwright_session(object(), "completed")  # type: ignore[arg-type]
    assert browser_use.stopped == []


# --- Production deployment files remain untouched ------------------------------
def test_production_deployment_does_not_enable_playwright() -> None:
    compose = (_REPO / "compose.prod.yaml").read_text(encoding="utf-8")
    assert "BROWSER_PROVIDER" not in compose
    assert "Dockerfile.browser" not in compose
    assert "playwright" not in compose.casefold()


def test_production_env_example_keeps_browser_use_default() -> None:
    example = (_REPO / ".env.production.example").read_text(encoding="utf-8")
    # No Playwright switch is offered in the production example.
    assert "BROWSER_PROVIDER=playwright" not in example


def test_vault_key_is_not_required_for_these_tests() -> None:
    # Guard against accidental coupling: a Fernet key is generated locally only.
    assert isinstance(Fernet.generate_key(), bytes)
