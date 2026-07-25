"""Regressions for the external Playwright audit findings.

Each test pins one verified defect so it cannot come back:

A1  Chromium is installed by a SEPARATE browser image (not the hardened API image).
A2  Login is submitted, and credential_page_ready requires a VERIFIED success signal.
A3  live_url() exists on the Playwright provider (no AttributeError -> HTTP 500).
A6  Off-allowlist ACTIVE requests (fetch/XHR/websocket) are aborted, not just docs.
A7  Screenshots mask credential fields.
A8  BrowserLoop.run enforces its timeout.
A9  Each session has its own operation lock.
A10 --no-sandbox is opt-in, not hardcoded.
A12 Health/wiring gating is provider-aware.
A13 Effect-ledger provider identity follows the wired backend.
A14 Launch failures map to specific reason codes.
A15 An invalid BROWSER_PROVIDER raises instead of silently selecting Browser Use.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from ops.browser_loop import BrowserLoop, BrowserOperationTimeout
from ops.browser_readiness import browser_configuration_state
from ops.config import Settings
from ops.playwright_worker import (
    PlaywrightBrowserWorker,
    _launch_reason_code,
    make_route_handler,
    matched_success_signals,
)

_HOSTS = ("app.pipedrive.com", "*.pipedrive.com")
_REPO = Path(__file__).resolve().parents[1]


# --- A1: Chromium ships in a dedicated browser image ---------------------------
def test_browser_dockerfile_installs_chromium() -> None:
    dockerfile = (_REPO / "Dockerfile.browser").read_text(encoding="utf-8")
    assert "playwright install --with-deps chromium" in dockerfile


def test_api_image_stays_chromium_free() -> None:
    # Keeping the browser OUT of the control-plane image is deliberate: a Chromium
    # crash or memory spike must not take down the API.
    api = (_REPO / "Dockerfile.api").read_text(encoding="utf-8")
    assert "playwright install" not in api


# --- A2: success signals gate the credential-page claim ------------------------
def test_matched_success_signals_requires_real_evidence() -> None:
    signals = ("API settings page is visible", "API token field label is visible")
    # Nothing on the page -> no match (an email-first login page must NOT pass).
    assert (
        matched_success_signals(
            signals, url="https://app.pipedrive.com/login", title="Log in", text="Email"
        )
        == ()
    )
    # Evidence in the visible text -> matched.
    hits = matched_success_signals(
        signals,
        url="https://app.pipedrive.com/settings/api",
        title="API",
        text="Your API token field label is visible here",
    )
    assert hits and "API token" in hits[0]


def test_matched_success_signals_can_match_via_url_or_title() -> None:
    assert matched_success_signals(
        ("settings api",), url="https://app.pipedrive.com/settings/api", title="", text=""
    )
    assert matched_success_signals(
        ("personal preferences",), url="", title="Personal Preferences", text=""
    )


def test_submit_login_clicks_a_submit_control() -> None:
    """Behavioral: _submit_login must actually click/press, not just exist."""

    from ops.playwright_worker import _submit_login

    clicked: list[str] = []

    class _Locator:
        def __init__(self, selector: str, count: int) -> None:
            self._selector = selector
            self._count = count
            self.first = self

        async def count(self) -> int:
            return self._count

        async def click(self, timeout: int = 0) -> None:
            clicked.append(self._selector)

        async def press(self, key: str, timeout: int = 0) -> None:
            clicked.append(f"press:{key}")

    class _Page:
        def locator(self, selector: str) -> _Locator:
            # Only the standard submit button exists on this page.
            return _Locator(selector, 1 if selector == "button[type='submit']" else 0)

        async def wait_for_load_state(self, state: str, timeout: int = 0) -> None:
            clicked.append(f"wait:{state}")

    assert asyncio.run(_submit_login(_Page())) is True
    assert "button[type='submit']" in clicked


def test_submit_login_falls_back_to_pressing_enter() -> None:
    from ops.playwright_worker import _submit_login

    pressed: list[str] = []

    class _Locator:
        def __init__(self) -> None:
            self.first = self

        async def count(self) -> int:
            return 0  # no submit control anywhere

        async def press(self, key: str, timeout: int = 0) -> None:
            pressed.append(key)

    class _Page:
        def locator(self, selector: str) -> _Locator:
            return _Locator()

        async def wait_for_load_state(self, state: str, timeout: int = 0) -> None:
            return None

    assert asyncio.run(_submit_login(_Page())) is True
    assert pressed == ["Enter"]


# --- A3: live_url exists so the live-view lookup cannot 500 --------------------
def test_playwright_worker_exposes_live_url_and_provider_session_id() -> None:
    worker = PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True))
    assert worker.live_url("anything") is None  # no hosted URL, but NO AttributeError
    assert worker.provider_session_id("missing") is None


def test_playwright_worker_declares_provider_capabilities() -> None:
    worker = PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True))
    assert worker.provider_name == "playwright"
    assert worker.supports_screenshot is True
    assert worker.supports_live_url is False
    assert worker.supports_restart_reattach is False


# --- A6: active off-allowlist egress is blocked --------------------------------
class _Req:
    def __init__(self, url: str, resource_type: str) -> None:
        self.url = url
        self.resource_type = resource_type

    def is_navigation_request(self) -> bool:
        return self.resource_type == "document"


class _Route:
    def __init__(self, req: _Req) -> None:
        self.request = req
        self.aborted = False
        self.continued = False

    async def abort(self) -> None:
        self.aborted = True

    async def continue_(self) -> None:
        self.continued = True


def _route(url: str, resource_type: str) -> _Route:
    handler = make_route_handler(_HOSTS)
    route = _Route(_Req(url, resource_type))
    asyncio.run(handler(route))
    return route


@pytest.mark.parametrize(
    "resource_type", ["document", "xhr", "fetch", "websocket", "eventsource", "script", "other"]
)
def test_offlist_active_requests_are_aborted(resource_type: str) -> None:
    # These are the exfiltration channels: a compromised page script must not be
    # able to beacon DOM contents (which include typed credentials) off-allowlist.
    route = _route("https://evil.example/collect", resource_type)
    assert route.aborted is True and route.continued is False


@pytest.mark.parametrize("resource_type", ["image", "font", "stylesheet", "media"])
def test_offlist_passive_assets_still_load(resource_type: str) -> None:
    route = _route("https://cdn.example/logo.png", resource_type)
    assert route.continued is True and route.aborted is False


def test_onlist_requests_always_continue() -> None:
    route = _route("https://app.pipedrive.com/api/v1/self", "fetch")
    assert route.continued is True


def test_unknown_resource_type_fails_closed() -> None:
    route = _route("https://evil.example/x", "totally-unknown-kind")
    assert route.aborted is True


# --- A7 / A10: masked screenshots, opt-in sandbox flag -------------------------
def test_screenshot_masks_credential_fields() -> None:
    source = (_REPO / "ops" / "playwright_worker.py").read_text(encoding="utf-8")
    assert "mask=masks" in source
    assert "input[type='password']" in source


def test_no_sandbox_is_opt_in() -> None:
    default = PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True))
    assert "--no-sandbox" not in default._launch_args()
    opted = PlaywrightBrowserWorker(
        settings=Settings(allow_live_browser=True, playwright_disable_sandbox=True)
    )
    assert "--no-sandbox" in opted._launch_args()


# --- A8: the loop timeout is enforced ------------------------------------------
def test_browser_loop_run_enforces_timeout() -> None:
    loop = BrowserLoop()
    try:

        async def _hang() -> None:
            await asyncio.sleep(30)

        with pytest.raises(BrowserOperationTimeout):
            asyncio.run(loop.run(_hang(), timeout=0.25))
    finally:
        loop.close()


# --- A9: per-session operation lock --------------------------------------------
def test_session_has_its_own_operation_lock() -> None:
    from ops.playwright_worker import _PwSession

    first = _PwSession(None, None, None, None, asyncio.Lock())
    second = _PwSession(None, None, None, None, asyncio.Lock())
    assert first.operation_lock is not second.operation_lock


def test_session_expiry_is_tracked() -> None:
    from datetime import UTC, datetime, timedelta

    from ops.playwright_worker import _PwSession

    session = _PwSession(None, None, None, None, asyncio.Lock())
    now = datetime.now(UTC)
    assert session.is_expired(now) is False
    assert session.is_expired(now + timedelta(hours=5)) is True  # max lifetime
    session.last_active_at = now - timedelta(minutes=30)
    assert session.is_expired(now) is True  # inactivity


# --- A12: provider-aware configuration gating ---------------------------------
def test_configuration_state_is_provider_aware() -> None:
    # Playwright needs no Browser Use key, but it does need somewhere to run:
    # the live opt-in alone is NOT configured, because the provider factory
    # (_build_browser_worker) fails closed without a service or the sandbox flag.
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
                playwright_in_process_sandbox=True,
            )
        )
        is True
    )
    assert (
        browser_configuration_state(
            Settings(
                allow_live_browser=True,
                browser_provider="playwright",
                browser_service_url="http://browser-worker:8081",
                browser_service_token=SecretStr("service-token"),
            )
        )
        is True
    )
    # A service URL without a token stays unconfigured (the service fails closed).
    assert (
        browser_configuration_state(
            Settings(
                allow_live_browser=True,
                browser_provider="playwright",
                browser_service_url="http://browser-worker:8081",
            )
        )
        is False
    )
    # Browser Use still requires its key.
    assert browser_configuration_state(Settings(allow_live_browser=True)) is False
    assert (
        browser_configuration_state(
            Settings(allow_live_browser=True, browser_use_api_key=SecretStr("k"))
        )
        is True
    )
    # The live opt-in still gates both.
    assert browser_configuration_state(Settings(browser_provider="playwright")) is False


# --- A13: effect-ledger provider identity follows the backend ------------------
def test_graph_resolves_browser_provider_name() -> None:
    from ops.graph import DurableOperationsWorkflow

    source = (_REPO / "ops" / "graph.py").read_text(encoding="utf-8")
    # No hardcoded browser_use literal remains at the ledger call sites.
    assert 'provider="browser_use"' not in source
    assert "provider=self._browser_provider_name()" in source
    assert hasattr(DurableOperationsWorkflow, "_browser_provider_name")


# --- A14: specific launch reason codes ----------------------------------------
@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Executable doesn't exist at /ms-playwright/chromium", "chromium_executable_missing"),
        ("Host system is missing dependencies to run browsers", "chromium_dependency_missing"),
        ("Timeout 30000ms exceeded while launching", "browser_launch_timeout"),
        ("Cannot allocate memory", "browser_out_of_memory"),
        ("something else entirely", "browser_launch_failed"),
    ],
)
def test_launch_reason_codes_are_specific(message: str, expected: str) -> None:
    assert _launch_reason_code(RuntimeError(message)) == expected


# --- A15: invalid provider must not silently fall back -------------------------
def test_invalid_browser_provider_raises() -> None:
    with pytest.raises((ValueError, ValidationError)):
        Settings.from_env(env={"BROWSER_PROVIDER": "playwrite"})


def test_absent_browser_provider_uses_the_default() -> None:
    assert Settings.from_env(env={}).browser_provider == "browser_use"


# --- capacity guard ------------------------------------------------------------
def test_session_capacity_is_bounded_by_settings() -> None:
    worker = PlaywrightBrowserWorker(
        settings=Settings(allow_live_browser=True, playwright_max_sessions=1)
    )
    assert worker._max_sessions == 1
