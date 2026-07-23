"""Canonical ASGI import path for development and container runtimes."""

import os

# browser-use-sdk 3.10.0 currently exposes claude-opus-4.6, not the old 4.7
# placeholder used by the original assignment configuration.
if os.environ.get("BROWSER_USE_MODEL", "").strip() in {"", "claude-opus-4.7"}:
    os.environ["BROWSER_USE_MODEL"] = "claude-opus-4.6"

from api.assignment_runtime import install_assignment_runtime  # noqa: E402

install_assignment_runtime()

from api.assignment_live_bootstrap import install_assignment_live_bootstrap  # noqa: E402

install_assignment_live_bootstrap()

from api.assignment_projection import install_assignment_projection  # noqa: E402

install_assignment_projection()

from api.app import app, create_app  # noqa: E402

__all__ = ["app", "create_app"]
