"""Internal RPC authentication for the browser service.

Four properties, all fail-closed:

* **Shared token, constant-time compare.** The token travels in a header, never
  a query string (query strings land in access logs and referrers). Comparison
  uses ``secrets.compare_digest`` so a wrong token cannot be discovered by
  timing.
* **Unconfigured means closed.** With no token configured the service refuses
  every request rather than serving an open browser to the network.
* **Request-size limit.** A body larger than the configured bound is rejected
  before it is parsed.
* **Tenant + run capability.** The stable owner namespaces reusable storage state;
  a separate high-entropy capability binds each live session to one run.

The token is never returned in a response, never logged, never written to run
state, and never rendered into a screenshot.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, Request, status

from browser_service.settings import BrowserServiceSettings
from ops.browser.session_capability import (
    CAPABILITY_HEADER,
    BrowserSessionCapabilityError,
    capability_digest,
    validate_capability_owner,
)

TOKEN_HEADER = "X-Browser-Service-Token"
OWNER_HEADER = "X-Browser-Session-Owner"


class AuthContext:
    """The authenticated caller identity for one RPC request."""

    __slots__ = ("_capability", "capability_digest", "owner")

    def __init__(self, owner: str, capability: str | None = None) -> None:
        self.owner = owner
        # Retain the bearer only for this request object. The isolated worker
        # forwards it to the API-owned secret broker, where it is re-derived and
        # bound to the exact run scope. It is never stored on ManagedSession.
        self._capability = capability
        if capability is None:
            self.capability_digest: bytes | None = None
        else:
            try:
                self.capability_digest = capability_digest(capability)
            except BrowserSessionCapabilityError:
                raise _reject("invalid_session_capability", status.HTTP_400_BAD_REQUEST) from None


def _reject(detail: str, code: int = status.HTTP_401_UNAUTHORIZED) -> HTTPException:
    """Build a sanitized rejection.

    The detail is a fixed reason code — never the expected token, the provided
    token, or any hint about which part matched.
    """

    return HTTPException(status_code=code, detail=detail)


def verify_token(settings: BrowserServiceSettings, provided: str | None) -> None:
    """Constant-time token check that fails closed when unconfigured."""

    if not settings.token_configured:
        # No token configured: refuse everything rather than expose the browser.
        raise _reject("browser_service_token_not_configured", status.HTTP_503_SERVICE_UNAVAILABLE)
    expected = settings.service_token.get_secret_value() if settings.service_token else ""
    candidate = provided or ""
    if not candidate or not secrets.compare_digest(candidate, expected):
        raise _reject("invalid_browser_service_token")


async def enforce_request_size(request: Request, settings: BrowserServiceSettings) -> None:
    """Reject an oversized body before parsing it.

    Checks the declared Content-Length first (cheap) and then the actual body
    length, so a lying header cannot smuggle a large payload through.
    """

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_request_bytes:
        raise _reject("request_too_large", status.HTTP_413_CONTENT_TOO_LARGE)
    body = await request.body()
    if len(body) > settings.max_request_bytes:
        raise _reject("request_too_large", status.HTTP_413_CONTENT_TOO_LARGE)


def require_owner(owner: str | None) -> str:
    """Every RPC call must present the run/session owner it acts for."""

    normalized = (owner or "").strip()
    if not normalized:
        raise _reject("missing_session_owner", status.HTTP_400_BAD_REQUEST)
    try:
        return validate_capability_owner(normalized)
    except BrowserSessionCapabilityError:
        raise _reject("invalid_session_owner", status.HTTP_400_BAD_REQUEST) from None


def authenticate(
    settings: BrowserServiceSettings,
    token: str | None,
    owner: str | None,
    capability: str | None = None,
) -> AuthContext:
    """Verify the token and owner for one request."""

    verify_token(settings, token)
    return AuthContext(owner=require_owner(owner), capability=capability)


def assert_session_owner(*, session_owner: str, caller_owner: str) -> None:
    """Refuse cross-session access: the caller must own the session it names."""

    if not secrets.compare_digest(session_owner, caller_owner):
        # 404 rather than 403 so the existence of another owner's session is not
        # confirmed to an unauthorized caller.
        raise _reject("session_not_found", status.HTTP_404_NOT_FOUND)


def require_session_capability(auth: AuthContext) -> bytes:
    """Return the presented digest, failing closed on unscoped session RPCs."""

    if auth.capability_digest is None:
        raise _reject("missing_session_capability", status.HTTP_400_BAD_REQUEST)
    return auth.capability_digest


def require_session_capability_value(auth: AuthContext) -> str:
    """Return the request-scoped bearer for a same-run broker handoff."""

    if auth.capability_digest is None or auth._capability is None:
        raise _reject("missing_session_capability", status.HTTP_400_BAD_REQUEST)
    return auth._capability


def assert_session_access(
    *,
    session_owner: str,
    caller_owner: str,
    session_capability_digest: bytes,
    caller_capability_digest: bytes | None,
) -> None:
    """Authorize one session without revealing which binding did not match."""

    owner_matches = secrets.compare_digest(session_owner, caller_owner)
    capability_matches = secrets.compare_digest(
        session_capability_digest,
        caller_capability_digest or b"",
    )
    if not (owner_matches and capability_matches):
        raise _reject("session_not_found", status.HTTP_404_NOT_FOUND)


async def token_dependency(
    request: Request,
    x_browser_service_token: str | None = Header(default=None, alias=TOKEN_HEADER),
    x_browser_session_owner: str | None = Header(default=None, alias=OWNER_HEADER),
    x_browser_session_capability: str | None = Header(default=None, alias=CAPABILITY_HEADER),
) -> AuthContext:
    """FastAPI dependency: size limit plus service/tenant authentication."""

    settings: BrowserServiceSettings = request.app.state.settings
    await enforce_request_size(request, settings)
    return authenticate(
        settings,
        x_browser_service_token,
        x_browser_session_owner,
        x_browser_session_capability,
    )


__all__ = [
    "OWNER_HEADER",
    "TOKEN_HEADER",
    "AuthContext",
    "assert_session_access",
    "assert_session_owner",
    "authenticate",
    "enforce_request_size",
    "require_session_capability",
    "require_session_capability_value",
    "require_owner",
    "token_dependency",
    "verify_token",
]
