"""Declared extension points for the production assignment runtime.

The assignment layer needs to swap two factories and three graph routing decisions.
It used to do that by REWRITING class attributes on ``ops`` modules at import time
(``ops.run_service.BrowserWorker = ...``, ``DurableOperationsWorkflow._route = ...``).
That worked but was silently fragile in two ways:

* it required the consuming code to keep living in one specific module namespace, so
  moving a function to another module disabled the override with nothing failing, and
* it patched the DEFINING modules too, so the effective class depended on import
  order rather than on configuration.

The overrides are now registered here explicitly. The core code asks this registry
at call time, so an override applies wherever the code lives, and a missing override
means "use the core behavior" rather than "hope the patch landed".

Registration is process-global because it represents one deployment's identity (the
production ASGI entry point installs it once at import), but it is INTENTIONALLY a
narrow, typed surface rather than arbitrary attribute surgery, and ``reset()`` makes
it reversible in a test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ops.browser_worker import BrowserWorker
    from ops.composio_capability import ComposioCapabilityPreflight
    from ops.config import Settings

# A graph node override receives the workflow instance and the current state, the
# same two arguments the core node method gets.
RouteOverride = Callable[[Any, Mapping[str, object]], dict[str, object]]
BranchOverride = Callable[[Any, Mapping[str, object]], str]


@dataclass(frozen=True, slots=True)
class RuntimeExtensions:
    """The complete set of behaviors a deployment may replace.

    Every field is optional and ``None`` means "core behavior". Keeping them in one
    frozen record makes the full extension surface reviewable in one place.
    """

    browser_worker_factory: Callable[[Settings], BrowserWorker] | None = None
    capability_preflight_factory: Callable[[Settings], ComposioCapabilityPreflight] | None = None
    route: RouteOverride | None = None
    after_route: BranchOverride | None = None
    after_browser: BranchOverride | None = None


_LOCK = threading.Lock()
_ACTIVE = RuntimeExtensions()


def active() -> RuntimeExtensions:
    """The currently installed extensions (all-``None`` by default)."""

    return _ACTIVE


def install(**overrides: Any) -> RuntimeExtensions:
    """Install or update extensions, returning the resulting set.

    Merges rather than replaces, so an installer can register its factories and its
    routing separately without clobbering the other half.
    """

    global _ACTIVE
    with _LOCK:
        _ACTIVE = replace(_ACTIVE, **overrides)
        return _ACTIVE


def reset() -> None:
    """Restore pure core behavior. Used by tests and local tooling."""

    global _ACTIVE
    with _LOCK:
        _ACTIVE = RuntimeExtensions()


__all__ = [
    "BranchOverride",
    "RouteOverride",
    "RuntimeExtensions",
    "active",
    "install",
    "reset",
]
