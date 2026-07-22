"""Canonical ASGI import path for development and container runtimes."""

from api.app import app, create_app

__all__ = ["app", "create_app"]
