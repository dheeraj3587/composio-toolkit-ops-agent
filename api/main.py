"""Canonical ASGI import path for every environment.

Production and tests import the same application factory. Runtime behaviour is
constructed from explicit settings and dependencies during lifespan startup; this
module performs no environment mutation and installs no process-global patches.
"""

from api.app import app, create_app

__all__ = ["app", "create_app"]
