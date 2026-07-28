"""Provider registry and disabled Browser Use compatibility boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ops.config import Settings
from ops.run_service import RunService


def _svc(tmp_path: Path, settings: Settings) -> RunService:
    return RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)


# --- setting default + env parsing (fail closed) ------------------------------
def test_default_provider_is_browser_use() -> None:
    assert Settings().browser_provider == "browser_use"


def test_from_env_parses_provider_and_rejects_typos() -> None:
    import pytest

    assert Settings.from_env(env={}).browser_provider == "browser_use"
    assert (
        Settings.from_env(env={"BROWSER_PROVIDER": "playwright"}).browser_provider == "playwright"
    )
    assert (
        Settings.from_env(env={"BROWSER_PROVIDER": "PLAYWRIGHT"}).browser_provider == "playwright"
    )
    # Hardened after audit: a present-but-invalid value must RAISE, not silently
    # select a different backend than the operator intended (e.g. "playwrite"
    # quietly falling back to the paid provider).
    with pytest.raises(ValueError):
        Settings.from_env(env={"BROWSER_PROVIDER": "garbage"})


# --- wiring condition parity --------------------------------------------------
def test_browser_use_wiring_requires_the_explicit_compatibility_switch(tmp_path: Path) -> None:
    disabled = _svc(
        tmp_path,
        Settings(allow_live_browser=True, browser_use_api_key=SecretStr("k")),
    )
    assert disabled._browser_provider_enabled(disabled._settings) is False

    with_key = _svc(
        tmp_path,
        Settings(
            allow_live_browser=True,
            browser_use_api_key=SecretStr("k"),
            browser_use_compatibility_enabled=True,
        ),
    )
    assert with_key._browser_provider_enabled(with_key._settings) is True

    # Missing API key -> not wired (exactly the pre-existing prod condition).
    no_key = _svc(tmp_path, Settings(allow_live_browser=True))
    assert no_key._browser_provider_enabled(no_key._settings) is False

    off = _svc(tmp_path, Settings(browser_use_api_key=SecretStr("k")))  # live opt-in off
    assert off._browser_provider_enabled(off._settings) is False


def test_playwright_wiring_needs_an_execution_location(tmp_path: Path) -> None:
    # The live opt-in alone is NOT enough: the factory fails closed without a
    # browser service or the explicit in-process sandbox, so the wiring condition
    # must agree with it (otherwise health reports "configured" and every run fails).
    live_only = Settings(allow_live_browser=True, browser_provider="playwright")
    svc = _svc(tmp_path, live_only)
    assert svc._browser_provider_enabled(live_only) is False

    # No browser_use_api_key is required for the self-hosted backend.
    service_backed = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        browser_service_url="http://browser-worker:8081",
        browser_service_token=SecretStr("service-token"),
    )
    assert svc._browser_provider_enabled(service_backed) is True

    sandbox = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
    )
    assert svc._browser_provider_enabled(sandbox) is True


# --- factory returns the Browser Use worker for the default -------------------
def test_factory_default_builds_a_browser_use_worker(tmp_path: Path) -> None:
    settings = Settings(
        allow_live_browser=True,
        browser_use_api_key=SecretStr("k"),
        browser_use_compatibility_enabled=True,
    )
    svc = _svc(tmp_path, settings)
    worker = svc._build_browser_worker(settings)
    # Base BrowserWorker or the prod AssignmentBrowserWorker subclass, never the
    # Playwright harness; and it satisfies the provider surface.
    assert type(worker).__name__ in {"BrowserWorker", "AssignmentBrowserWorker"}
    assert hasattr(worker, "navigate_onboarding") and hasattr(worker, "start")


def test_registry_wires_both_configured_providers_concurrently(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    settings = Settings(
        allow_live_browser=True,
        browser_use_api_key=SecretStr("browser-use-test-key"),
        browser_service_url="http://browser-worker:8081",
        browser_service_token=SecretStr("service-test-token"),
        browser_use_compatibility_enabled=True,
    )
    service = _svc(tmp_path, settings)

    class Worker:
        def __init__(self, provider_name: str) -> None:
            self.provider_name = provider_name

    built: list[str] = []

    def build(_settings: Settings, *, provider: str | None = None) -> Any:
        assert provider is not None
        built.append(provider)
        return Worker(provider)

    monkeypatch.setattr(service, "_build_browser_worker", build)
    dependencies = service._build_workflow_dependencies(settings)  # noqa: SLF001

    assert set(built) == {"browser_use", "playwright"}
    assert set(dependencies.browsers) == {"browser_use", "playwright"}
    assert dependencies.browsers["browser_use"].provider_name == "browser_use"
    assert dependencies.browsers["playwright"].provider_name == "playwright"


def test_run_provider_lookup_never_cross_routes_workers(tmp_path: Path) -> None:
    service = _svc(tmp_path, Settings())
    browser_use = object()
    playwright = object()
    service._browser_workers = {  # type: ignore[dict-item]
        "browser_use": browser_use,
        "playwright": playwright,
    }

    assert service._browser_worker_for({"browser_provider": "browser_use"}) is browser_use
    assert service._browser_worker_for({"browser_provider": "playwright"}) is playwright
