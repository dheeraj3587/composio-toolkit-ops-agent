"""Phase B core: the self-hosted Playwright harness.

Pure unit tests (always run) cover the security-critical host guard and blocked
observation. Live tests (real Chromium) run where a browser is launchable and
skip otherwise, so the offline gate stays green everywhere while the sandbox
exercises the real lifecycle, host enforcement, and coded secret injection in a
single event loop.
"""

from __future__ import annotations

import asyncio

import pytest

from ops.browser_worker import BrowserObservation
from ops.config import Settings
from ops.playwright_worker import (
    PlaywrightBrowserWorker,
    _blocked,
    make_route_handler,
    navigation_allowed,
)

_PATTERNS = ("app.pipedrive.com", "*.pipedrive.com")


# --- pure: host allowlist decision --------------------------------------------
def test_navigation_allowed_matches_exact_and_wildcard() -> None:
    assert navigation_allowed("https://app.pipedrive.com/settings/api", _PATTERNS) is True
    assert navigation_allowed("https://acme.pipedrive.com/", _PATTERNS) is True
    assert navigation_allowed("https://evil.example/login", _PATTERNS) is False
    assert navigation_allowed("http://app.pipedrive.com/", _PATTERNS) is False  # not https


# --- pure: route handler aborts off-allowlist NAVIGATIONS only ----------------
class _FakeRequest:
    def __init__(self, url: str, resource_type: str, is_nav: bool) -> None:
        self.url = url
        self.resource_type = resource_type
        self._is_nav = is_nav

    def is_navigation_request(self) -> bool:
        return self._is_nav


class _FakeRoute:
    def __init__(self, request: _FakeRequest) -> None:
        self.request = request
        self.aborted = False
        self.continued = False

    async def abort(self) -> None:
        self.aborted = True

    async def continue_(self) -> None:
        self.continued = True


def _run_route(url: str, resource_type: str, is_nav: bool) -> _FakeRoute:
    handler = make_route_handler(_PATTERNS)
    route = _FakeRoute(_FakeRequest(url, resource_type, is_nav))
    asyncio.run(handler(route))
    return route


def test_route_aborts_offlist_document_navigation() -> None:
    route = _run_route("https://evil.example/steal", "document", True)
    assert route.aborted is True and route.continued is False


def test_route_allows_onlist_document_navigation() -> None:
    route = _run_route("https://app.pipedrive.com/settings/api", "document", True)
    assert route.continued is True and route.aborted is False


def test_route_blocks_offlist_active_script() -> None:
    # Hardened after audit: an off-allowlist SCRIPT is an active/exfiltration-capable
    # request, not a harmless asset — credentials are typed into the DOM, so a
    # third-party script must not be able to load and beacon them out.
    route = _run_route("https://cdn.evil-but-asset.example/app.js", "script", False)
    assert route.aborted is True and route.continued is False


def test_route_allows_offlist_passive_asset() -> None:
    # Render-only assets (images/fonts/stylesheets/media) still load off-allowlist
    # so real vendor pages display correctly.
    route = _run_route("https://cdn.example/logo.png", "image", False)
    assert route.continued is True and route.aborted is False


# --- pure: blocked observation -------------------------------------------------
def test_blocked_observation_is_bounded_and_named() -> None:
    obs = _blocked("https://evil.example/x")
    assert isinstance(obs, BrowserObservation)
    assert obs.status == "blocked"
    assert "evil.example" in obs.page_title


# --- live: real Chromium lifecycle + injection (skips if not launchable) ------
def _worker() -> PlaywrightBrowserWorker:
    return PlaywrightBrowserWorker(settings=Settings(allow_live_browser=True))


def test_live_lifecycle_and_secret_injection() -> None:
    """Page work MUST be submitted to the worker's owning loop (worker._loop.run);
    touching session.page from a foreign loop would hang, which is exactly the
    event-loop hazard the BrowserLoop exists to remove."""

    async def _flow() -> tuple[bool, bool, str, str]:
        worker = _worker()
        try:
            context = await worker.start(None)
        except Exception as exc:  # no browser binary here -> skip, don't fail
            pytest.skip(f"Chromium not launchable in this environment: {type(exc).__name__}")
        registered = context.session_id in worker._sessions
        session = worker._sessions[context.session_id]

        from ops.playwright_worker import _has_password_field, _inject_login

        async def _drive() -> tuple[bool, str, str]:
            # A controlled local login form (no external network).
            await session.page.set_content(
                "<form><input type='email' name='email'>"
                "<input type='password' name='password'></form>"
            )
            had_password = await _has_password_field(session.page)
            await _inject_login(
                session.page,
                {"login_email": "ops@example.test", "login_password": "  spaced secret  "},
            )
            email_val = await session.page.locator("input[type='email']").input_value()
            pw_val = await session.page.locator("input[type='password']").input_value()
            return had_password, email_val, pw_val

        had_password, email_val, pw_val = await worker._loop.run(_drive())
        await worker.stop(context)
        return registered, had_password, email_val, pw_val

    registered, had_password, email_val, pw_val = asyncio.run(_flow())
    assert registered is True
    assert had_password is True
    assert email_val == "ops@example.test"
    # Injected verbatim (no trim) — mirrors the secret-fidelity guarantee.
    assert pw_val == "  spaced secret  "


# --- integration: the provider factory now selects the Playwright harness -----
def test_factory_selects_playwright_worker(tmp_path: object) -> None:
    from pathlib import Path

    from ops.run_service import RunService

    settings = Settings(allow_live_browser=True, browser_provider="playwright")
    svc = RunService.from_paths(db_path=Path(str(tmp_path)) / "ops.db", settings=settings)
    worker = svc._build_browser_worker(settings)
    assert type(worker).__name__ == "PlaywrightBrowserWorker"
