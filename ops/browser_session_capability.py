"""Run-bound capabilities for isolated browser-service sessions.

The browser-service RPC token authenticates the API process. It does not identify
which run an individual request is acting for. This module derives a second,
run-bound bearer capability so a session-id mix-up cannot let one run operate
another run's browser.

Only the API receives the master key. The browser service receives the derived
capability in a header and stores only its SHA-256 digest on the in-memory session.
Nothing from this module is persisted to run state, checkpoints, audit events, or
URLs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

CAPABILITY_HEADER = "X-Browser-Session-Capability"

_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_OWNER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_CAPABILITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DOMAIN_SEPARATOR = b"browser-session/v1\x00"


class BrowserSessionCapabilityError(ValueError):
    """A fixed, value-free capability configuration or input failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def validate_capability_key(key: str) -> str:
    """Return a valid master key or fail with a sanitized reason code."""

    if len(key) < 32:
        raise BrowserSessionCapabilityError("browser_session_capability_key_too_short")
    return key


def validate_capability_scope(scope: str) -> str:
    """Validate the non-secret immutable run scope used for derivation."""

    normalized = scope.strip()
    if _SCOPE_PATTERN.fullmatch(normalized) is None:
        raise BrowserSessionCapabilityError("browser_session_capability_scope_invalid")
    return normalized


def validate_capability_owner(owner: str) -> str:
    """Normalize one HTTP-safe tenant/storage namespace."""

    normalized = owner.strip()
    if _OWNER_PATTERN.fullmatch(normalized) is None:
        raise BrowserSessionCapabilityError("browser_session_owner_invalid")
    return normalized


def derive_browser_session_capability(*, key: str, owner: str, scope: str) -> str:
    """Derive one stable 256-bit capability for ``(tenant owner, run scope)``."""

    secret = validate_capability_key(key)
    tenant = validate_capability_owner(owner)
    run_scope = validate_capability_scope(scope)
    message = _DOMAIN_SEPARATOR + tenant.encode("utf-8") + b"\x00" + run_scope.encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def capability_digest(capability: str) -> bytes:
    """Validate and hash a presented capability for in-memory comparison."""

    if _CAPABILITY_PATTERN.fullmatch(capability) is None:
        raise BrowserSessionCapabilityError("browser_session_capability_invalid")
    return hashlib.sha256(capability.encode("ascii")).digest()


__all__ = [
    "CAPABILITY_HEADER",
    "BrowserSessionCapabilityError",
    "capability_digest",
    "derive_browser_session_capability",
    "validate_capability_owner",
    "validate_capability_key",
    "validate_capability_scope",
]
