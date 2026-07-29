"""Provider-aware live view, restart reconciliation, and provider state.

The invariant behind every test here: adding the self-hosted provider must not
change Browser Use behaviour, and Playwright's real limitations must be reported
honestly rather than papered over.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from api.models import LiveViewResponse, ProviderState
from ops.browser_readiness import browser_configuration_state
from ops.config import Settings
from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import RunService

_REPO = Path(__file__).resolve().parents[1]
_INTERACTIVE_GRANT = (
    "http://browser-worker:8081/internal/browser/live-view/novnc"
    "?session=bs_1&token=e30.c2lnbmF0dXJl"
)


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


class _InteractiveGrantWorker(_ScreenshotWorker):
    def request_live_view_sync(self, session_id: str) -> tuple[str, str, str, bool]:
        assert session_id == "bs_1"
        return "interactive_remote", _INTERACTIVE_GRANT, "2026-07-25T00:05:00+00:00", True


def _service_with_worker(tmp_path: Path, worker: object, *, session_id: str = "s1") -> RunService:
    service = RunService.from_paths(db_path=tmp_path / "ops.db")
    service.initialize()
    provider = getattr(worker, "provider_name", "browser_use")
    request = _request().model_copy(update={"browser_provider": provider})
    run = service.create_run(request, execution_mode="plan_only")
    run_id = run["run_id"]
    with service.storage.unit_of_work() as transaction:
        transaction.update_run(run_id, browser_session_id=session_id)
    service._browser_workers = {provider: worker}  # type: ignore[dict-item]
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


def test_playwright_grant_is_minted_for_running_and_hitl_without_being_persisted(
    tmp_path: Path,
) -> None:
    service = _service_with_worker(tmp_path, _InteractiveGrantWorker(), session_id="bs_1")
    run_id = service._test_run_id  # type: ignore[attr-defined]
    with service.storage.unit_of_work() as transaction:
        transaction.update_run(run_id, status="browser_running")
    running_grant = service.get_browser_interactive_grant(run_id)
    assert running_grant is not None and running_grant[1] == _INTERACTIVE_GRANT

    with service.storage.unit_of_work() as transaction:
        transaction.update_run(run_id, status="waiting_for_hitl")
    grant = service.get_browser_interactive_grant(run_id)

    assert grant is not None and grant[1] == _INTERACTIVE_GRANT
    persisted = service.storage.get_run(run_id)
    assert persisted is not None
    assert "c2lnbmF0dXJl" not in str(persisted)
    assert "c2lnbmF0dXJl" not in str(service.get_timeline(run_id))


def test_live_view_modes_are_provider_aware_and_self_consistent() -> None:
    # Browser Use keeps its hosted, interactive shape.
    hosted = LiveViewResponse(
        run_id="run_1",
        provider="browser_use",
        available=True,
        mode="hosted_url",
        live_url="https://x.example/s",
        interaction_available=True,
    )
    assert hosted.mode == "hosted_url" and hosted.interaction_available is True
    assert hosted.screenshot_url is None and hosted.interactive_url is None

    # Playwright reports viewable-but-not-drivable masked frames.
    shot = LiveViewResponse(
        run_id="run_1",
        provider="playwright",
        available=True,
        mode="screenshot",
        screenshot_url="/api/runs/run_1/live-view/screenshot",
        captured_at="2026-07-25T00:00:00+00:00",
    )
    assert shot.live_url is None and shot.interaction_available is False

    interactive = LiveViewResponse(
        run_id="run_1",
        provider="playwright",
        available=True,
        mode="interactive_remote",
        interactive_url=_INTERACTIVE_GRANT,
        interaction_available=True,
    )
    assert interactive.interactive_url == _INTERACTIVE_GRANT

    idle = LiveViewResponse(
        run_id="run_1",
        provider="playwright",
        available=False,
        reason_code="no_active_browser_session",
    )
    assert idle.mode == "unavailable" and idle.available is False


@pytest.mark.parametrize(
    "payload",
    [
        # A mode without its matching viewer URL.
        {"provider": "browser_use", "available": True, "mode": "hosted_url"},
        {"provider": "playwright", "available": True, "mode": "screenshot"},
        {"provider": "playwright", "available": True, "mode": "interactive_remote"},
        # An unavailable view must not carry a viewer URL at all.
        {
            "provider": "browser_use",
            "available": False,
            "mode": "unavailable",
            "live_url": "https://x.example/s",
        },
        {
            "provider": "playwright",
            "available": False,
            "mode": "unavailable",
            "screenshot_url": "/api/runs/run_1/live-view/screenshot",
        },
        # A viewer mode that denies availability, and frames claiming interaction.
        {
            "provider": "playwright",
            "available": False,
            "mode": "screenshot",
            "screenshot_url": "/api/runs/run_1/live-view/screenshot",
        },
        {
            "provider": "playwright",
            "available": True,
            "mode": "screenshot",
            "screenshot_url": "/api/runs/run_1/live-view/screenshot",
            "interaction_available": True,
        },
        # A viewer path for a DIFFERENT run.
        {
            "provider": "playwright",
            "available": True,
            "mode": "screenshot",
            "screenshot_url": "/api/runs/run_2/live-view/screenshot",
        },
    ],
)
def test_live_view_rejects_inconsistent_mode_and_url_combinations(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        LiveViewResponse(run_id="run_1", **payload)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "address",
    [
        "http://browser-worker:8081/vnc.html?session=pw_1&token=t",
        "https://browser-worker.opsnet/vnc.html",
        "http://127.0.0.1:6080/vnc.html",
        "/api/runs/run_1/live-view/../../internal",
    ],
)
def test_live_view_rejects_unapproved_browser_service_addresses(address: str) -> None:
    """Only the exact bounded browser-worker grant may cross to the Next server."""

    for field in ("screenshot_url", "interactive_url"):
        with pytest.raises(ValidationError):
            LiveViewResponse(
                run_id="run_1",
                provider="playwright",
                available=True,
                mode="screenshot" if field == "screenshot_url" else "interactive_remote",
                **{field: address},  # type: ignore[arg-type]
            )


class _FakeCoreService:
    """Minimal core-service surface the live-view projection actually reads."""

    def __init__(
        self,
        *,
        live_url: str | None,
        screenshot: tuple[bytes, str] | None,
        browser_provider: str,
        interactive_grant: tuple[str, str, str, bool] | None = None,
    ) -> None:
        self._live_url = live_url
        self._screenshot = screenshot
        self._browser_provider = browser_provider
        self._interactive_grant = interactive_grant

    def get_run(self, run_id: str) -> dict[str, object]:
        return {
            "run_id": run_id,
            "browser_provider": self._browser_provider,
            "status": "waiting_for_hitl" if self._interactive_grant else "browser_running",
        }

    def get_browser_live_url(self, run_id: str) -> str | None:
        del run_id
        return self._live_url

    def get_browser_screenshot(self, run_id: str) -> tuple[bytes, str] | None:
        del run_id
        return self._screenshot

    def get_browser_interactive_grant(self, run_id: str) -> tuple[str, str, str, bool] | None:
        del run_id
        return self._interactive_grant


def _projected_live_view(
    *,
    live_url: str | None,
    screenshot: tuple[bytes, str] | None,
    browser_provider: str = "browser_use",
    interactive_grant: tuple[str, str, str, bool] | None = None,
) -> LiveViewResponse:
    from api.service import LocalRunService

    service = LocalRunService(
        core_service=_FakeCoreService(
            live_url=live_url,
            screenshot=screenshot,
            browser_provider=browser_provider,
            interactive_grant=interactive_grant,
        ),  # type: ignore[arg-type]
        settings=Settings(browser_provider=browser_provider),  # type: ignore[arg-type]
    )
    return service._live_view_sync("run_1")  # noqa: SLF001 - projection under test


def test_browser_use_live_view_stays_hosted_and_interactive() -> None:
    view = _projected_live_view(
        live_url="https://live.browser-use.example/session", screenshot=None
    )

    assert view.provider == "browser_use"
    assert view.mode == "hosted_url"
    assert view.interaction_available is True
    assert view.live_url == "https://live.browser-use.example/session"


def test_playwright_live_view_is_screenshot_only() -> None:
    view = _projected_live_view(
        live_url=None,
        screenshot=(b"\x89PNG frame", "2026-07-25T00:00:00+00:00"),
        browser_provider="playwright",
    )

    assert view.provider == "playwright"
    assert view.mode == "screenshot"
    # interactive_remote is never advertised until that path is served end to end.
    assert view.interaction_available is False
    assert view.screenshot_url == "/api/runs/run_1/live-view/screenshot"
    assert view.interactive_url is None


def test_playwright_hitl_live_view_returns_a_fresh_interactive_grant() -> None:
    view = _projected_live_view(
        live_url=None,
        screenshot=None,
        browser_provider="playwright",
        interactive_grant=(
            "interactive_remote",
            _INTERACTIVE_GRANT,
            "2026-07-25T00:05:00+00:00",
            True,
        ),
    )

    assert view.mode == "interactive_remote"
    assert view.interactive_url == _INTERACTIVE_GRANT
    assert view.interaction_available is True


def test_playwright_running_live_view_is_remote_and_view_only() -> None:
    view = _projected_live_view(
        live_url=None,
        screenshot=None,
        browser_provider="playwright",
        interactive_grant=(
            "interactive_remote",
            _INTERACTIVE_GRANT,
            "2026-07-25T00:05:00+00:00",
            False,
        ),
    )

    assert view.mode == "interactive_remote"
    assert view.available is True
    assert view.interaction_available is False


def test_idle_live_view_reports_the_configured_provider_without_a_viewer() -> None:
    view = _projected_live_view(live_url=None, screenshot=None, browser_provider="playwright")

    assert view.provider == "playwright"
    assert view.mode == "unavailable"
    assert view.available is False
    assert view.live_url is None and view.screenshot_url is None
    assert view.reason_code == "no_active_browser_session"


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
    # Playwright needs no Browser Use key, but it does need a browser service
    # (or the explicit in-process sandbox) — the same rule the factory enforces.
    assert (
        browser_configuration_state(
            Settings(allow_live_browser=True, browser_provider="playwright")
        )
        is False
    )
    assert (
        browser_configuration_state(
            Settings(
                allow_live_browser=True,
                browser_provider="playwright",
                browser_service_url="http://browser-worker:8081",
                browser_service_token=SecretStr("service-token-" + ("s" * 32)),
                browser_session_capability_key=SecretStr("c" * 32),
            )
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


def _run_at(service: RunService, status: str, *, provider: str = "browser_use") -> str:
    request = _request().model_copy(update={"browser_provider": provider})
    run = service.create_run(request, execution_mode="plan_only")
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
    service._browser_workers = {"browser_use": _ReattachWorker()}  # type: ignore[dict-item]
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
    service._browser_workers = {"playwright": _NoReattachWorker()}  # type: ignore[dict-item]
    hitl = _run_at(service, "waiting_for_hitl", provider="playwright")
    running = _run_at(service, "browser_running", provider="playwright")

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
    service._browser_workers = {"playwright": playwright}  # type: ignore[dict-item]
    for status in ("completed", "failed", "blocked", "configuration_required"):
        service._stop_terminal_playwright_session(object(), status, "playwright")  # type: ignore[arg-type]
    assert len(playwright.stopped) == 4

    # Non-terminal states keep the session (the human/loop still needs it).
    playwright.stopped.clear()
    for status in ("browser_running", "waiting_for_hitl"):
        service._stop_terminal_playwright_session(object(), status, "playwright")  # type: ignore[arg-type]
    assert playwright.stopped == []

    # Browser Use is never stopped by this branch.
    browser_use = _BrowserUseWorker()
    service._browser_workers = {"browser_use": browser_use}  # type: ignore[dict-item]
    service._stop_terminal_playwright_session(object(), "completed", "browser_use")  # type: ignore[arg-type]
    assert browser_use.stopped == []


# --- Production keeps the API browser-free and service-backs Playwright --------
def test_production_deployment_wires_isolated_playwright() -> None:
    compose = (_REPO / "compose.prod.yaml").read_text(encoding="utf-8")
    assert "Dockerfile.browser" in compose
    assert "BROWSER_SERVICE_URL: http://browser-worker:8081" in compose
    assert 'PLAYWRIGHT_IN_PROCESS_SANDBOX: "false"' in compose
    assert "Dockerfile.api" in compose


def test_production_env_example_selects_playwright_for_the_rollout() -> None:
    example = (_REPO / ".env.production.example").read_text(encoding="utf-8")
    assert "BROWSER_PROVIDER=playwright" in example
    assert "BROWSER_USE_COMPATIBILITY_ENABLED=false" in example
    assert "BROWSER_SERVICE_TOKEN=" in example


def test_vault_key_is_not_required_for_these_tests() -> None:
    # Guard against accidental coupling: a Fernet key is generated locally only.
    assert isinstance(Fernet.generate_key(), bytes)
