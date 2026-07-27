"""Strict, non-token projection of the connected Gmail mailbox identity."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

_EMAIL = re.compile(r"^[^@\s<>;,]+@[^@\s<>;,]+$")
_PROFILE_EMAIL_KEYS = ("emailAddress", "email_address", "email")


@dataclass(frozen=True, slots=True)
class GmailAccountIdentity:
    connected_account_id: str
    composio_user_id: str
    canonical_email: str
    account_fingerprint: str
    verified_at: str
    display_name: str | None = None

    def __post_init__(self) -> None:
        if not self.connected_account_id or len(self.connected_account_id) > 300:
            raise ValueError("connected Gmail account id is invalid")
        if not self.composio_user_id or len(self.composio_user_id) > 300:
            raise ValueError("Composio user id is invalid")
        if _EMAIL.fullmatch(self.canonical_email) is None or len(self.canonical_email) > 320:
            raise ValueError("connected Gmail address is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", self.account_fingerprint) is None:
            raise ValueError("Gmail account fingerprint is invalid")
        if self.display_name is not None and len(self.display_name) > 200:
            raise ValueError("Gmail display name is invalid")


def identity_from_profile(
    profile: Mapping[str, object],
    *,
    connected_account_id: str,
    composio_user_id: str,
) -> GmailAccountIdentity:
    """Project the Gmail ``users.getProfile`` response onto safe identity data.

    Multiple different email fields are rejected rather than selecting one
    arbitrarily. Gmail's documented field is ``emailAddress``; the snake-case
    alias is accepted for Composio response normalization compatibility.
    """

    candidates = {
        str(profile[key]).strip().casefold()
        for key in _PROFILE_EMAIL_KEYS
        if isinstance(profile.get(key), str) and str(profile[key]).strip()
    }
    if len(candidates) != 1:
        raise ValueError("Gmail profile did not contain one unambiguous mailbox")
    email = candidates.pop()
    if _EMAIL.fullmatch(email) is None or len(email) > 320:
        raise ValueError("Gmail profile mailbox is invalid")
    connected = str(connected_account_id).strip()
    user = str(composio_user_id).strip()
    if not connected or not user:
        raise ValueError("Gmail identity binding is incomplete")
    digest = hashlib.sha256(f"gmail-account:v1\0{connected}\0{user}\0{email}".encode()).hexdigest()
    display = profile.get("displayName") or profile.get("display_name")
    display_name = (
        str(display).strip()[:200] if isinstance(display, str) and display.strip() else None
    )
    return GmailAccountIdentity(
        connected_account_id=connected,
        composio_user_id=user,
        canonical_email=email,
        display_name=display_name,
        account_fingerprint=digest,
        verified_at=datetime.now(UTC).isoformat(),
    )


__all__ = ["GmailAccountIdentity", "identity_from_profile"]
