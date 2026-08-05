"""Process-boundary hardening for the secret-bearing browser service.

Playwright has two child-process boundaries:

* Python starts Playwright's bundled Node driver.
* The Node driver starts Chromium.

Passing ``env=`` to ``chromium.launch`` protects only the second boundary.  In
Playwright 1.61.0 the Python transport otherwise copies all of ``os.environ``
into the Node driver.  The adapter below is deliberately pinned to that private
transport contract and refuses to operate when the installed implementation no
longer matches the reviewed shape.
"""

from __future__ import annotations

import ctypes
import importlib
import importlib.metadata
import inspect
import os
import sys
import threading
from collections.abc import Callable
from typing import Any, Final, cast

PLAYWRIGHT_DRIVER_CONTRACT_VERSION: Final = "1.61.0"

# These values are process mechanics, not application configuration. Locale
# categories are enumerated instead of accepting arbitrary ``LC_*`` names, which
# would turn a prefix into a secret-smuggling channel.
_PROCESS_ENV_ALLOWLIST: Final = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ADDRESS",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NAME",
        "LC_NUMERIC",
        "LC_PAPER",
        "LC_TELEPHONE",
        "LC_TIME",
        "PATH",
        "TMPDIR",
        "TZ",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
    }
)

# The Node driver resolves the browser installation from this variable in the
# production image. No other Playwright/Node setting is ambiently inherited.
_DRIVER_ENV_ALLOWLIST: Final = _PROCESS_ENV_ALLOWLIST | {"PLAYWRIGHT_BROWSERS_PATH"}
_DRIVER_MODULE = "playwright._impl._driver"
_TRANSPORT_MODULE = "playwright._impl._transport"
_REPO_VERSION_MODULE = "playwright._repo_version"
_GUARD_MARKER = "__ops_secret_free_playwright_driver_env__"
_INSTALL_LOCK = threading.Lock()

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4


def _allowlisted_environment(names: frozenset[str]) -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if name in names}


def chromium_launch_environment(display: str | None, *, headless: bool) -> dict[str, str]:
    """Return the strict environment supplied to every Chromium launch."""

    launch_env = _allowlisted_environment(_PROCESS_ENV_ALLOWLIST)
    # A leased display always wins. A headed worker with no lease may fall back to
    # the process display for local development; a headless launch renders nothing,
    # so it is never given one. Inheriting it there would let a missing lease
    # silently draw on whatever display the parent held instead of failing closed.
    target_display = display or (None if headless else os.environ.get("DISPLAY"))
    if target_display:
        launch_env["DISPLAY"] = target_display

    browser_home = os.environ.get("BROWSER_HOME") or "/tmp/browser-home"
    current_home = launch_env.get("HOME")
    if not current_home or current_home == "/app" or os.environ.get("BROWSER_HOME"):
        launch_env["HOME"] = browser_home
        launch_env["XDG_CACHE_HOME"] = os.path.join(browser_home, ".cache")
        launch_env["XDG_CONFIG_HOME"] = os.path.join(browser_home, ".config")
        launch_env["XDG_RUNTIME_DIR"] = os.path.join(browser_home, "run")

    return launch_env


def _secret_free_driver_environment() -> dict[str, str]:
    """Replacement for Playwright 1.61.0's environment-copying builder."""

    driver_env = _allowlisted_environment(_DRIVER_ENV_ALLOWLIST)
    driver_env["PW_LANG_NAME"] = "python"
    driver_env["PW_LANG_NAME_VERSION"] = f"{sys.version_info.major}.{sys.version_info.minor}"
    driver_env["PW_CLI_DISPLAY_VERSION"] = PLAYWRIGHT_DRIVER_CONTRACT_VERSION
    return driver_env


setattr(_secret_free_driver_environment, _GUARD_MARKER, True)


def _is_secret_free_adapter(candidate: object) -> bool:
    return bool(getattr(candidate, _GUARD_MARKER, False))


def _validate_original_driver_builder(candidate: object) -> None:
    """Fail closed unless the pinned private helper still has its reviewed shape."""

    if not callable(candidate):
        raise RuntimeError("playwright_driver_environment_contract_changed")
    builder = cast(Callable[..., Any], candidate)
    if getattr(candidate, "__module__", None) != _DRIVER_MODULE:
        raise RuntimeError("playwright_driver_environment_contract_changed")
    if inspect.signature(builder).parameters:
        raise RuntimeError("playwright_driver_environment_contract_changed")

    code = getattr(candidate, "__code__", None)
    if code is None:
        raise RuntimeError("playwright_driver_environment_contract_changed")
    if not {"os", "environ", "copy"}.issubset(code.co_names):
        raise RuntimeError("playwright_driver_environment_contract_changed")
    constants = frozenset(item for item in code.co_consts if isinstance(item, str))
    if not {
        "PW_LANG_NAME",
        "PW_LANG_NAME_VERSION",
        "PW_CLI_DISPLAY_VERSION",
    }.issubset(constants):
        raise RuntimeError("playwright_driver_environment_contract_changed")


def install_playwright_driver_environment_guard() -> None:
    """Replace Playwright's Node-driver env builder without mutating ``os.environ``.

    ``_transport`` imports the helper by value, so both bindings must be replaced.
    The dependency version and bytecode-level call sites are checked first; an
    upgrade or partial patch is a startup error rather than silent inheritance.
    """

    try:
        installed_version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("playwright_driver_environment_contract_unavailable") from None
    if installed_version != PLAYWRIGHT_DRIVER_CONTRACT_VERSION:
        raise RuntimeError("playwright_driver_environment_contract_changed")

    with _INSTALL_LOCK:
        driver_module = importlib.import_module(_DRIVER_MODULE)
        transport_module = importlib.import_module(_TRANSPORT_MODULE)
        repo_version_module = importlib.import_module(_REPO_VERSION_MODULE)
        if getattr(repo_version_module, "version", None) != PLAYWRIGHT_DRIVER_CONTRACT_VERSION:
            raise RuntimeError("playwright_driver_environment_contract_changed")

        driver_builder = getattr(driver_module, "get_driver_env", None)
        transport_builder = getattr(transport_module, "get_driver_env", None)
        driver_is_guarded = _is_secret_free_adapter(driver_builder)
        transport_is_guarded = _is_secret_free_adapter(transport_builder)
        if driver_is_guarded and transport_is_guarded:
            return
        if driver_is_guarded or transport_is_guarded or driver_builder is not transport_builder:
            raise RuntimeError("playwright_driver_environment_contract_changed")

        _validate_original_driver_builder(driver_builder)
        connect = getattr(getattr(transport_module, "PipeTransport", None), "connect", None)
        connect_code = getattr(connect, "__code__", None)
        if connect_code is None or not {
            "get_driver_env",
            "create_subprocess_exec",
        }.issubset(connect_code.co_names):
            raise RuntimeError("playwright_driver_environment_contract_changed")

        # Patch the transport binding first: it is the executable child-process
        # boundary. The driver-module assignment keeps both private bindings
        # consistent for introspection and any direct callers.
        transport_module.__dict__["get_driver_env"] = _secret_free_driver_environment
        driver_module.__dict__["get_driver_env"] = _secret_free_driver_environment


def disable_process_dumpability() -> None:
    """Make a Linux browser-service parent unreadable through ptrace-style `/proc`.

    Chromium and the Playwright Node driver do not need to inspect their Python
    parent. On other operating systems there is no Linux ``prctl`` contract to
    apply, so this is intentionally a no-op.
    """

    if sys.platform != "linux":
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
        verified = prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0)
    except (AttributeError, OSError):
        raise RuntimeError("browser_process_dumpability_hardening_failed") from None
    if result != 0 or verified != 0:
        raise RuntimeError("browser_process_dumpability_hardening_failed")


def harden_playwright_parent_process() -> None:
    """Protect a secret-bearing Python parent before any Playwright child starts."""

    disable_process_dumpability()
    install_playwright_driver_environment_guard()


def harden_browser_service_process() -> None:
    """Apply Playwright protections during browser-service startup."""

    harden_playwright_parent_process()


__all__ = [
    "PLAYWRIGHT_DRIVER_CONTRACT_VERSION",
    "chromium_launch_environment",
    "disable_process_dumpability",
    "harden_browser_service_process",
    "harden_playwright_parent_process",
    "install_playwright_driver_environment_guard",
]
