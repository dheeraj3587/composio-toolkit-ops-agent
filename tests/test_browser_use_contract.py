"""Contract tests pinning the installed browser-use-sdk v3 API surface.

These assert the SDK reality the worker depends on, so a future SDK/API change
is caught by CI instead of silently degrading the browser session:

- v3 run() has NO allowed_domains parameter (it is accepted only via **extra),
  which is why host restriction is DETECTION (post-task URL check + task hard
  stops), not provider-side enforcement. If a future SDK adds a real domain
  allowlist, the first test fails on purpose — prompting a switch to real
  enforcement.
- The lifecycle methods the cleanup path relies on (client.close, sessions.stop,
  profiles.delete) exist.
"""

from __future__ import annotations

import inspect


def test_v3_run_has_no_allowed_domains_and_accepts_extra() -> None:
    from browser_use_sdk import v3

    signature = inspect.signature(v3.AsyncBrowserUse.run)
    params = signature.parameters
    assert "allowed_domains" not in params
    assert "allowedDomains" not in params
    # allowed_domains is therefore accepted only through **extra (undocumented,
    # not enforced). Confirm such a catch-all exists so passing it cannot raise.
    assert any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def test_v3_request_models_declare_no_domain_allowlist() -> None:
    from browser_use_sdk.generated.v3 import models

    run_request = models.AppEndpointsApiV3SessionsViewsRunTaskRequest
    session_request = models.CreateBrowserSessionRequest
    forbidden = {"allowed_domains", "allowedDomains", "domains", "allowlist", "allowed_urls"}
    for model in (run_request, session_request):
        assert not (set(model.model_fields) & forbidden), model.__name__


def test_v3_exposes_lifecycle_cleanup_methods() -> None:
    from browser_use_sdk import v3
    from browser_use_sdk.v3.resources import profiles, sessions

    # Client close (F3 client cleanup) and the stop/delete calls the terminal
    # cleanup path invokes must exist on the async resources.
    assert callable(getattr(v3.AsyncBrowserUse, "close", None))
    assert hasattr(sessions.AsyncSessions, "stop")
    assert hasattr(profiles.AsyncProfiles, "delete")
