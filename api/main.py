"""Canonical ASGI import path for development and container runtimes."""

from api.assignment_runtime import install_assignment_runtime

install_assignment_runtime()

from api.app import app, create_app  # noqa: E402

__all__ = ["app", "create_app"]
