"""Isolated browser service: Chromium runs HERE, never in the API process.

Putting a browser inside the control-plane container means a Chromium crash,
memory spike, or hung page can take down the API — and it makes an API restart
kill every in-flight browser session. This package is the separate service that
owns Chromium and exposes a small, authenticated, private-network RPC surface
that the API's provider client speaks to.

Nothing here is published publicly: every route lives under ``/internal`` and
requires the shared browser-service token, and the container publishes no host
port (see ``compose.playwright.sandbox.yaml``).
"""

from __future__ import annotations

__all__ = ["__version__"]

# Bumped when the RPC contract changes; the API client compares against this so a
# mismatched pair reports `version_mismatch` instead of failing mysteriously.
__version__ = "1.0.0"
