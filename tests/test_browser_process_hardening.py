from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import browser_service.main as browser_main
import ops.browser.process_hardening as process_hardening
from browser_service.settings import BrowserServiceSettings
from ops.browser.process_hardening import (
    PLAYWRIGHT_DRIVER_CONTRACT_VERSION,
    install_playwright_driver_environment_guard,
)
from ops.browser.readiness import BrowserReadiness

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_playwright_driver_contract_matches_the_exact_runtime_pin() -> None:
    assert importlib.metadata.version("playwright") == PLAYWRIGHT_DRIVER_CONTRACT_VERSION
    provider_requirements = (_REPOSITORY_ROOT / "requirements-providers.txt").read_text(
        encoding="utf-8"
    )
    assert f"playwright=={PLAYWRIGHT_DRIVER_CONTRACT_VERSION}" in provider_requirements.splitlines()
    runtime_lock = (_REPOSITORY_ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    assert any(
        line.startswith(f"playwright=={PLAYWRIGHT_DRIVER_CONTRACT_VERSION} ")
        for line in runtime_lock.splitlines()
    )


def test_playwright_driver_environment_excludes_parent_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_environment = {
        "HOME": "/tmp/browser-home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
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
        **{name: f"driver-sentinel-{index}" for index, name in enumerate(sorted(secret_names))},
        "DISPLAY": ":99",
        "LC_SECRET_SENTINEL": "must-not-escape",  # pragma: allowlist secret
        "NODE_OPTIONS": "--require=/tmp/untrusted.js",
        "PLAYWRIGHT_NODEJS_PATH": "/tmp/untrusted-node",
    }
    captured: dict[str, object] = {}

    class FakeProcess:
        stdin = object()

    async def fake_create_subprocess_exec(*command: object, **kwargs: object) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    async def connect_transport() -> None:
        transport_module = importlib.import_module("playwright._impl._transport")
        transport = transport_module.PipeTransport(asyncio.get_running_loop())
        await transport.connect()

    with patch.dict(os.environ, process_environment, clear=True):
        install_playwright_driver_environment_guard()
        asyncio.run(connect_transport())

    driver_module = importlib.import_module("playwright._impl._driver")
    transport_module = importlib.import_module("playwright._impl._transport")
    assert driver_module.get_driver_env is transport_module.get_driver_env

    command = captured["command"]
    assert isinstance(command, tuple)
    assert command[-1] == "run-driver"
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    driver_environment = kwargs["env"]
    assert driver_environment == {
        **safe_environment,
        "PW_CLI_DISPLAY_VERSION": PLAYWRIGHT_DRIVER_CONTRACT_VERSION,
        "PW_LANG_NAME": "python",
        "PW_LANG_NAME_VERSION": f"{sys.version_info.major}.{sys.version_info.minor}",
    }
    for name in (
        *secret_names,
        "DISPLAY",
        "LC_SECRET_SENTINEL",
        "NODE_OPTIONS",
        "PLAYWRIGHT_NODEJS_PATH",
    ):
        assert name not in driver_environment


def test_playwright_driver_environment_guard_rejects_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "1.62.0")

    with pytest.raises(RuntimeError, match="^playwright_driver_environment_contract_changed$"):
        install_playwright_driver_environment_guard()


def test_playwright_parent_hardening_precedes_driver_environment_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        process_hardening,
        "disable_process_dumpability",
        lambda: events.append("nondumpable"),
    )
    monkeypatch.setattr(
        process_hardening,
        "install_playwright_driver_environment_guard",
        lambda: events.append("driver-env"),
    )

    process_hardening.harden_playwright_parent_process()

    assert events == ["nondumpable", "driver-env"]


def test_in_process_worker_hardens_parent_before_driver_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ops.core.config import Settings
    from ops.playwright.worker import PlaywrightBrowserWorker

    events: list[str] = []

    def async_playwright() -> object:
        events.append("driver-start")
        raise AssertionError("Playwright driver started before parent hardening")

    fake_async_api = SimpleNamespace(async_playwright=async_playwright)
    real_import = importlib.import_module

    def import_module(name: str) -> object:
        return fake_async_api if name == "playwright.async_api" else real_import(name)

    def fail_hardening() -> None:
        events.append("parent-hardening")
        raise RuntimeError("browser_process_dumpability_hardening_failed")

    monkeypatch.setattr(importlib, "import_module", import_module)
    monkeypatch.setattr(
        "ops.playwright.worker.harden_playwright_parent_process",
        fail_hardening,
    )
    worker = PlaywrightBrowserWorker(
        settings=Settings(
            allow_live_browser=True,
            browser_provider="playwright",
            playwright_in_process_sandbox=True,
        ),
        service_mode=False,
    )

    with pytest.raises(RuntimeError, match="^browser_process_dumpability_hardening_failed$"):
        asyncio.run(worker.start(None))

    assert events == ["parent-hardening"]


def test_readiness_hardens_parent_before_driver_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ops.browser.readiness import probe_playwright

    events: list[str] = []

    def async_playwright() -> object:
        events.append("driver-start")
        raise AssertionError("Playwright driver started before parent hardening")

    fake_async_api = SimpleNamespace(async_playwright=async_playwright)
    real_import = importlib.import_module

    def import_module(name: str) -> object:
        return fake_async_api if name == "playwright.async_api" else real_import(name)

    def fail_hardening() -> None:
        events.append("parent-hardening")
        raise RuntimeError("browser_process_dumpability_hardening_failed")

    monkeypatch.setattr(importlib, "import_module", import_module)
    monkeypatch.setattr(
        "ops.browser.readiness.harden_playwright_parent_process",
        fail_hardening,
    )

    result = asyncio.run(probe_playwright(timeout_seconds=1.0))

    assert result.reason_code == "playwright_parent_process_hardening_failed"
    assert events == ["parent-hardening"]


def test_browser_service_hardens_parent_before_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def harden() -> None:
        events.append("harden")

    def install_log_filters() -> None:
        events.append("logs")

    async def readiness_probe(*, timeout_seconds: float = 30.0) -> BrowserReadiness:
        del timeout_seconds
        events.append("readiness")
        return BrowserReadiness(
            status="ready",
            reason_code="chromium_launch_verified",
            detail="",
        )

    monkeypatch.setattr(browser_main, "harden_browser_service_process", harden)
    monkeypatch.setattr(browser_main, "install_browser_service_log_filters", install_log_filters)
    monkeypatch.setattr("ops.browser.readiness.probe_playwright", readiness_probe)

    app = browser_main.create_app(
        BrowserServiceSettings(
            service_token=SecretStr("s" * 32),
            max_sessions=1,
        )
    )
    with TestClient(app):
        pass

    assert events[:3] == ["harden", "logs", "readiness"]


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc/self/environ").exists(),
    reason="Linux procfs is required for the dumpability boundary test",
)
def test_nondumpable_parent_denies_child_proc_environ_access() -> None:
    child_script = textwrap.dedent(
        """
        import errno
        import os
        import sys

        os.kill(int(sys.argv[1]), 0)
        try:
            with open(f"/proc/{sys.argv[1]}/environ", "rb") as environ_file:
                environ_file.read(1)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                raise SystemExit(0)
            if exc.errno == errno.ENOENT:
                # hidepid-style procfs mounts deliberately mask protected PIDs
                # as nonexistent even while the parent is waiting below.
                raise SystemExit(0)
            raise SystemExit(3)
        raise SystemExit(2)
        """
    )
    parent_script = textwrap.dedent(
        f"""
        import os
        import subprocess
        import sys

        from ops.browser.process_hardening import disable_process_dumpability

        disable_process_dumpability()
        child_env = {{
            name: value
            for name, value in os.environ.items()
            if name in {{
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "TMPDIR",
                "TZ",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "XDG_RUNTIME_DIR",
            }}
        }}
        completed = subprocess.run(
            [sys.executable, "-c", {child_script!r}, str(os.getpid())],
            env=child_env,
            check=False,
        )
        raise SystemExit(completed.returncode)
        """
    )
    parent_environment = {
        "HOME": "/tmp/browser-home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PROC_PARENT_SECRET_SENTINEL": "must-not-be-readable",  # pragma: allowlist secret
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        [sys.executable, "-c", parent_script],
        cwd=_REPOSITORY_ROOT,
        env=parent_environment,
        check=False,
    )

    assert completed.returncode == 0
