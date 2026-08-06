"""Phase B core: the self-hosted Playwright harness.

Pure unit tests (always run) cover the security-critical host guard and blocked
observation. Live tests (real Chromium) run where a browser is launchable and
skip otherwise, so the offline gate stays green everywhere while the sandbox
exercises the real lifecycle, host enforcement, and coded secret injection in a
single event loop.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest

from ops.browser.worker import BrowserObservation
from ops.core.config import Settings
from ops.playwright.worker import (
    PlaywrightBrowserWorker,
    _blocked,
    make_route_handler,
    navigation_allowed,
)
from tests.browser_app.harness import require_chromium

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


def test_chromium_child_environment_excludes_worker_secrets_in_every_launch_mode() -> None:
    safe_environment = {
        "HOME": "/tmp/browser-home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
        "XDG_CACHE_HOME": "/tmp/browser-home/.cache",
        "XDG_CONFIG_HOME": "/tmp/browser-home/.config",
        "XDG_RUNTIME_DIR": "/tmp/browser-home/run",
    }
    secret_names = {
        "BROWSER_SECRET_BROKER_TOKEN",
        "BROWSER_SERVICE_TOKEN",
        "BROWSER_SESSION_CAPABILITY_KEY",
        "BROWSER_STORAGE_STATE_KEY",
        "CEREBRAS_API_KEY",
        "COMPOSIO_API_KEY",
        "GOOGLE_GENAI_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "OPS_INTERNAL_API_TOKEN",
        "SECRET_VAULT_KEY",
    }
    process_environment = {
        **safe_environment,
        **{name: f"sentinel-{index}" for index, name in enumerate(sorted(secret_names))},
        # A prefix match would be too broad: only real locale categories are safe.
        "LC_SECRET_SENTINEL": "must-not-escape",  # pragma: allowlist secret
        "DISPLAY": ":77",
    }

    with patch.dict(os.environ, process_environment, clear=True):
        headless = PlaywrightBrowserWorker._launch_env(None, headless=True)
        local_headed = PlaywrightBrowserWorker._launch_env(None, headless=False)
        leased_headed = PlaywrightBrowserWorker._launch_env(":108", headless=False)

    assert headless == safe_environment
    assert local_headed == {**safe_environment, "DISPLAY": ":77"}
    assert leased_headed == {**safe_environment, "DISPLAY": ":108"}
    for name in (*secret_names, "LC_SECRET_SENTINEL"):
        assert name not in headless
        assert name not in local_headed
        assert name not in leased_headed


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
            require_chromium(exc)
        registered = context.session_id in worker._sessions
        session = worker._sessions[context.session_id]

        # The live credential-typing path. This used to import a second copy of
        # these helpers from ops.playwright.worker that production never called,
        # so the test passed while the real login was broken.
        from ops.browser.login import _PASSWORD_SELECTOR, _count_visible_enabled, _fill_first

        async def _drive() -> tuple[bool, str, str]:
            # A controlled local login form (no external network).
            await session.page.set_content(
                "<form><input type='email' name='email'>"
                "<input type='password' name='password'></form>"
            )
            had_password = await _count_visible_enabled(session.page, _PASSWORD_SELECTOR) == 1
            await _fill_first(session.page, "input[type='email']", "ops@example.test")
            await _fill_first(session.page, _PASSWORD_SELECTOR, "  spaced secret  ")
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
def test_factory_selects_the_browser_service_for_playwright(tmp_path: object) -> None:
    """Service-backed Playwright is the NORMAL path; in-process is opt-in.

    This previously asserted that selecting the provider returned the in-process
    worker, which is exactly why the browser service, its RPC auth, restart
    reattachment and lifecycle manager were never reached by the real application.
    """

    from pathlib import Path

    from pydantic import SecretStr

    from ops.providers.errors import ConfigurationRequiredError
    from ops.runs.service import RunService

    settings = Settings(allow_live_browser=True, browser_provider="playwright")
    svc = RunService.from_paths(db_path=Path(str(tmp_path)) / "ops.db", settings=settings)

    # Unconfigured service: fail closed rather than silently launching Chromium
    # inside the control plane.
    with pytest.raises(ConfigurationRequiredError) as excinfo:
        svc._build_browser_worker(settings)
    assert excinfo.value.reason_code == "browser_service_configuration_required"

    # Configured service: the RPC client, which can survive an API restart.
    service_settings = settings.model_copy(
        update={
            "browser_service_url": "http://browser-worker:8081",
            "browser_service_token": SecretStr("test-token"),
            "browser_session_capability_key": SecretStr("c" * 32),
        }
    )
    client = svc._build_browser_worker(service_settings)
    assert type(client).__name__ == "BrowserServiceClient"
    assert client.supports_restart_reattach is True

    # In-process Chromium remains available, but only when asked for explicitly.
    sandbox_settings = settings.model_copy(update={"playwright_in_process_sandbox": True})
    worker = svc._build_browser_worker(sandbox_settings)
    assert type(worker).__name__ == "PlaywrightBrowserWorker"
