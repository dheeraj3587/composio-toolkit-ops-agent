"""Phase A: browser provider abstraction + factory.

The default provider must keep the Browser Use path byte-for-byte: same wiring
condition (live opt-in + API key) and the same worker class. The setting parses
from env and fails closed to browser_use on an unknown value. The playwright
branch needs only the live opt-in and is selected by the factory.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr

from ops.config import Settings
from ops.run_service import RunService


def _svc(tmp_path: Path, settings: Settings) -> RunService:
    return RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)


# --- setting default + env parsing (fail closed) ------------------------------
def test_default_provider_is_browser_use() -> None:
    assert Settings().browser_provider == "browser_use"


def test_from_env_parses_provider_and_fails_closed() -> None:
    assert Settings.from_env(env={}).browser_provider == "browser_use"
    assert Settings.from_env(env={"BROWSER_PROVIDER": "playwright"}).browser_provider == "playwright"
    assert Settings.from_env(env={"BROWSER_PROVIDER": "PLAYWRIGHT"}).browser_provider == "playwright"
    # An unknown value must not crash and must not silently enable a new backend.
    assert Settings.from_env(env={"BROWSER_PROVIDER": "garbage"}).browser_provider == "browser_use"


# --- wiring condition parity --------------------------------------------------
def test_browser_use_wiring_condition_is_unchanged(tmp_path: Path) -> None:
    with_key = _svc(tmp_path, Settings(allow_live_browser=True, browser_use_api_key=SecretStr("k")))
    assert with_key._browser_provider_enabled(with_key._settings) is True

    # Missing API key -> not wired (exactly the pre-existing prod condition).
    no_key = _svc(tmp_path, Settings(allow_live_browser=True))
    assert no_key._browser_provider_enabled(no_key._settings) is False

    off = _svc(tmp_path, Settings(browser_use_api_key=SecretStr("k")))  # live opt-in off
    assert off._browser_provider_enabled(off._settings) is False


def test_playwright_wiring_needs_only_live_opt_in(tmp_path: Path) -> None:
    settings = Settings(allow_live_browser=True, browser_provider="playwright")
    svc = _svc(tmp_path, settings)
    # No browser_use_api_key required for the self-hosted backend.
    assert svc._browser_provider_enabled(settings) is True


# --- factory returns the Browser Use worker for the default -------------------
def test_factory_default_builds_a_browser_use_worker(tmp_path: Path) -> None:
    settings = Settings(allow_live_browser=True, browser_use_api_key=SecretStr("k"))
    svc = _svc(tmp_path, settings)
    worker = svc._build_browser_worker(settings)
    # Base BrowserWorker or the prod AssignmentBrowserWorker subclass, never the
    # Playwright harness; and it satisfies the provider surface.
    assert type(worker).__name__ in {"BrowserWorker", "AssignmentBrowserWorker"}
    assert hasattr(worker, "navigate_onboarding") and hasattr(worker, "start")
