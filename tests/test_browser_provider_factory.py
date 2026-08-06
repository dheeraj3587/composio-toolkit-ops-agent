"""Provider registry wiring for the one browser backend that exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ops.core.config import Settings
from ops.runs.service import RunService


def _svc(tmp_path: Path, settings: Settings) -> RunService:
    return RunService.from_paths(db_path=tmp_path / "ops.db", settings=settings)


# --- setting default + env parsing (fail closed) ------------------------------
def test_default_provider_is_playwright() -> None:
    assert Settings().browser_provider == "playwright"


def test_from_env_parses_provider_and_rejects_typos() -> None:
    import pytest

    assert Settings.from_env(env={}).browser_provider == "playwright"
    assert (
        Settings.from_env(env={"BROWSER_PROVIDER": "playwright"}).browser_provider == "playwright"
    )
    assert (
        Settings.from_env(env={"BROWSER_PROVIDER": "PLAYWRIGHT"}).browser_provider == "playwright"
    )
    # Hardened after audit: a present-but-invalid value must RAISE, not silently
    # select a different backend than the operator intended. That still holds now
    # that there is one backend — a deployment naming the retired cloud adapter is
    # telling us something false about where its browser actions will run.
    with pytest.raises(ValueError):
        Settings.from_env(env={"BROWSER_PROVIDER": "garbage"})
    with pytest.raises(ValueError):
        Settings.from_env(env={"BROWSER_PROVIDER": "browser_use"})


# --- wiring condition ---------------------------------------------------------
def test_playwright_wiring_needs_an_execution_location(tmp_path: Path) -> None:
    # The live opt-in alone is NOT enough: the factory fails closed without a
    # browser service or the explicit in-process sandbox, so the wiring condition
    # must agree with it (otherwise health reports "configured" and every run fails).
    live_only = Settings(allow_live_browser=True, browser_provider="playwright")
    svc = _svc(tmp_path, live_only)
    assert svc._browser_provider_enabled(live_only) is False

    service_backed = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        browser_service_url="http://browser-worker:8081",
        browser_service_token=SecretStr("service-token-" + ("s" * 32)),
        browser_session_capability_key=SecretStr("c" * 32),
    )
    assert svc._browser_provider_enabled(service_backed) is True

    sandbox = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
    )
    assert svc._browser_provider_enabled(sandbox) is True


# --- the factory returns the self-hosted harness ------------------------------
def test_factory_builds_the_self_hosted_harness(tmp_path: Path) -> None:
    settings = Settings(
        allow_live_browser=True,
        browser_provider="playwright",
        playwright_in_process_sandbox=True,
    )
    svc = _svc(tmp_path, settings)
    worker = svc._build_browser_worker(settings)

    # It declares the identity runs are frozen onto, and satisfies the surface the
    # workflow drives it through.
    assert worker.provider_name == "playwright"
    assert hasattr(worker, "navigate_onboarding") and hasattr(worker, "start")


def test_registry_wires_the_single_configured_provider(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    settings = Settings(
        allow_live_browser=True,
        browser_service_url="http://browser-worker:8081",
        browser_service_token=SecretStr("service-test-token-" + ("s" * 32)),
        browser_session_capability_key=SecretStr("c" * 32),
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

    assert built == ["playwright"]
    assert set(dependencies.browsers) == {"playwright"}
    assert dependencies.browsers["playwright"].provider_name == "playwright"


def test_run_provider_lookup_never_cross_routes_workers(tmp_path: Path) -> None:
    service = _svc(tmp_path, Settings())
    playwright = object()
    service._browser_workers = {"playwright": playwright}  # type: ignore[dict-item]

    assert service._browser_worker_for({"browser_provider": "playwright"}) is playwright
    # A run recorded before the cloud adapter was removed still carries its name.
    # There is no worker for it, and the Playwright worker must not be handed over
    # in its place: the frozen provider decides what a resume is allowed to run on.
    assert service._browser_worker_for({"browser_provider": "browser_use"}) is None
