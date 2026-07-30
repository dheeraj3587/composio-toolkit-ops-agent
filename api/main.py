"""Canonical ASGI import path for every environment.

Production and tests import the same application factory. Runtime behaviour is
constructed from explicit settings and dependencies during lifespan startup; this
module performs no environment mutation and installs no process-global patches.

This is also the API process's view of the onboarding composition root. Two
bindings happen behind it, and both are the application boundary rather than a
call site:

* ``api.app.create_app``'s lifespan installs the redaction filter on the root,
  application, and uvicorn loggers before the service starts, so every record the
  process emits — access lines included — passes redaction (Requirement 19.4). The
  CLI installs the same filter in ``ops.cli.main``.
* ``ops.onboarding.composition.build_onboarding_ports`` binds the durable stores,
  the run queue, the mailbox adapter, the credential validator, the research
  adapters, and the inference-backed decider to their implementations. It is
  re-exported here so a worker entry point and this ASGI entry point compose the
  same graph, and so the one place that knows which implementation is behind each
  port is importable without reaching into the runtime.
"""

from api.app import app, create_app
from ops.onboarding.composition import OnboardingPorts, build_onboarding_ports

__all__ = ["OnboardingPorts", "app", "build_onboarding_ports", "create_app"]
