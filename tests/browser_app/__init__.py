"""A local, deterministic browser test application.

Phase 1/2 served pages by intercepting Playwright routes. That is fine for DOM
assertions but it cannot prove the security properties Phase 4 must demonstrate:
if every request is fulfilled by the test itself, an "off-domain request was
blocked" assertion proves nothing about the production guard.

So this package runs a REAL HTTP server on loopback, on two distinct origins:

* the **vendor** origin — the app under automation, and
* the **third-party** origin — a separate host used only as an off-domain target
  (a tracking pixel, an analytics script, a beacon fetch).

Because they are genuinely different hosts, "the guard aborted this request"
becomes a real observation: the third-party server records every hit it receives,
so a test can assert the request never arrived.

No real provider credentials exist here. The only accepted password is a constant
defined in this module, and every "token" is obviously fake test data.
"""

from tests.browser_app.server import (
    ACCEPTED_EMAIL,
    ACCEPTED_PASSWORD,
    FAKE_API_TOKEN,
    MAGIC_LINK_PATH,
    OTP_CODE,
    BrowserTestApp,
    browser_test_app,
)

__all__ = [
    "ACCEPTED_EMAIL",
    "ACCEPTED_PASSWORD",
    "FAKE_API_TOKEN",
    "MAGIC_LINK_PATH",
    "OTP_CODE",
    "BrowserTestApp",
    "browser_test_app",
]
