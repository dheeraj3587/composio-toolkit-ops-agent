"""Short-lived, session-bound interactive HITL grants.

Screenshot-only HITL cannot solve a CAPTCHA, an account chooser, or an MFA
prompt — those need real interaction. Interactive access is therefore supported,
but it is a genuinely dangerous surface (a live browser holding an authenticated
session), so access is gated by a token that is:

* **signed** (HMAC-SHA256 over the payload; a forged token fails verification),
* **bound to ONE session id** (a token for session A cannot open session B),
* **bound to the owner** (another run's operator cannot use it),
* **short-lived** (minutes, not hours), and
* **single-purpose** (it authorizes viewing/interacting, nothing else).

There is no raw public VNC port and no unauthenticated noVNC: the container
publishes nothing, and the URL is only reachable on the private network. The
grant URL is returned once for immediate use and is NEVER durably persisted —
run state stores only the sanitized fact that interactive access was opened.
"""

from __future__ import annotations

import base64
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Literal

LiveViewMode = Literal["screenshot", "interactive_remote"]

_TOKEN_VERSION = "lv1"


class LiveViewTokenError(RuntimeError):
    """A typed verification failure (never echoes the token itself)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class LiveViewToken:
    """A verified grant's contents."""

    session_id: str
    owner: str
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) >= self.expires_at


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def issue_live_view_token(
    *,
    session_id: str,
    owner: str,
    secret: str,
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[str, datetime]:
    """Mint a signed, session-bound, expiring grant token."""

    if not session_id or not owner:
        raise LiveViewTokenError("session_and_owner_required")
    if not secret:
        raise LiveViewTokenError("live_view_secret_missing")
    issued = now or datetime.now(UTC)
    expires_at = issued + timedelta(seconds=max(30, min(ttl_seconds, 3_600)))
    payload = {
        "v": _TOKEN_VERSION,
        "sid": session_id,
        "own": owner,
        "exp": int(expires_at.timestamp()),
    }
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64(hmac.new(secret.encode(), body.encode(), sha256).digest())
    return f"{body}.{signature}", expires_at


def verify_live_view_token(
    token: str,
    *,
    secret: str,
    expected_session_id: str,
    expected_owner: str,
    now: datetime | None = None,
) -> LiveViewToken:
    """Verify a grant, failing closed on signature/binding/expiry problems."""

    if not secret:
        raise LiveViewTokenError("live_view_secret_missing")
    if not token or token.count(".") != 1:
        raise LiveViewTokenError("malformed_token")
    body, signature = token.split(".", 1)
    expected_sig = _b64(hmac.new(secret.encode(), body.encode(), sha256).digest())
    # Constant-time: a wrong signature must not be discoverable by timing.
    if not hmac.compare_digest(signature, expected_sig):
        raise LiveViewTokenError("invalid_signature")
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, TypeError):
        raise LiveViewTokenError("malformed_token") from None
    if not isinstance(payload, dict) or payload.get("v") != _TOKEN_VERSION:
        raise LiveViewTokenError("unsupported_token_version")
    session_id = str(payload.get("sid") or "")
    owner = str(payload.get("own") or "")
    # Binding checks: a token is valid ONLY for its own session and owner.
    if not hmac.compare_digest(session_id, expected_session_id):
        raise LiveViewTokenError("session_mismatch")
    if not hmac.compare_digest(owner, expected_owner):
        raise LiveViewTokenError("owner_mismatch")
    try:
        expires_at = datetime.fromtimestamp(int(payload.get("exp", 0)), tz=UTC)
    except (ValueError, TypeError, OSError):
        raise LiveViewTokenError("malformed_token") from None
    verified = LiveViewToken(session_id=session_id, owner=owner, expires_at=expires_at)
    if verified.is_expired(now):
        raise LiveViewTokenError("token_expired")
    return verified


def build_interactive_url(*, base_url: str, token: str, session_id: str) -> str:
    """Compose the private-network noVNC URL for a verified grant.

    ``base_url`` must be a private-network address supplied by configuration —
    never derived from page content, a redirect, or model output.
    """

    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}session={session_id}&token={token}"


@dataclass(frozen=True, slots=True)
class LiveViewAudit:
    """A sanitized audit row: never the token, never the URL."""

    session_id: str
    owner: str
    event: Literal["opened", "closed", "denied"]
    reason_code: str
    at: str

    @classmethod
    def record(
        cls,
        *,
        session_id: str,
        owner: str,
        event: Literal["opened", "closed", "denied"],
        reason_code: str,
    ) -> LiveViewAudit:
        return cls(
            session_id=session_id,
            owner=owner,
            event=event,
            reason_code=reason_code,
            at=datetime.now(UTC).isoformat(),
        )


__all__ = [
    "LiveViewAudit",
    "LiveViewMode",
    "LiveViewToken",
    "LiveViewTokenError",
    "build_interactive_url",
    "issue_live_view_token",
    "verify_live_view_token",
]
