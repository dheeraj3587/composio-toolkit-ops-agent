"""Shared, account-aware selection of safe browser entry URLs.

Both browser providers use this module so account-state ordering cannot drift.  It
only selects already-reviewed URLs: field-level operational claims are preferred,
reviewed traces are accepted at their configured position, and the deliberately
narrow legacy fallbacks remain explicit per provider.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

AccountState = Literal[
    "authenticated",
    "existing_account",
    "account_creation_required",
    "unknown",
]
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)
_FIELD_NAMES = frozenset(
    {
        "credential_management_url",
        "developer_portal_url",
        "login_url",
        "signup_url",
    }
)


class _TargetValidator:
    """Protocol-free adapter for the existing provider host predicate."""

    def __init__(self, allowed_domains: Sequence[str], allowed: Any) -> None:
        self._allowed_domains = tuple(allowed_domains)
        self._allowed = allowed

    def accepts(self, value: object) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        safe = sanitize_target_url(value)
        if safe is None or not self._allowed(safe, self._allowed_domains):
            return None
        return safe


def derive_account_state(
    *,
    restored_storage_state: bool = False,
    sensitive_data: Mapping[str, str] | None = None,
    account_creation_requested: bool = False,
) -> AccountState:
    """Derive state solely from local, trusted facts.

    A successfully restored Playwright storage state takes precedence because it
    proves this browser session is authenticated.  An explicit account-creation
    request then wins over otherwise contradictory supplied login values.  No
    browser page, research result, or model output participates in this decision.
    """

    if restored_storage_state:
        return "authenticated"
    if account_creation_requested:
        return "account_creation_required"
    if sensitive_data and any(
        key in sensitive_data and bool(str(value).strip())
        for key, value in sensitive_data.items()
        if key in {"login_email", "login_username", "login_password"}
    ):
        return "existing_account"
    return "unknown"


def ordered_target_kinds(account_state: AccountState) -> tuple[str, ...]:
    """Return the one reviewed ordering for every browser provider."""

    orders: dict[AccountState, tuple[str, ...]] = {
        "authenticated": (
            "credential_management_url",
            "developer_portal_url",
            "trace_start_url",
            "login_url",
            "signup_url",
        ),
        "existing_account": (
            "login_url",
            "credential_management_url",
            "developer_portal_url",
            "trace_start_url",
            "signup_url",
        ),
        "account_creation_required": (
            "signup_url",
            "login_url",
            "developer_portal_url",
            "credential_management_url",
            "trace_start_url",
        ),
        "unknown": (
            "login_url",
            "signup_url",
            "developer_portal_url",
            "credential_management_url",
            "trace_start_url",
        ),
    }
    return orders[account_state]


def sanitize_target_url(value: str) -> str | None:
    """Accept only a complete HTTPS target without credential-like URL parts.

    Browser observations may be sanitized after navigation, but a selected entry
    target must *reject*, rather than silently strip, sensitive query parameters
    or fragments.  This prevents a secret-bearing discovered URL from becoming a
    navigation request in either provider.
    """

    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return None
    if any(name.casefold() in _SENSITIVE_QUERY_NAMES for name, _ in parse_qsl(parsed.query, True)):
        return None
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def select_browser_target(
    *,
    research: Any,
    trace: Any | None,
    allowed_domains: Sequence[str],
    account_state: AccountState,
    is_allowed_url: Any,
) -> str | None:
    """Pick the first safe reviewed target for the account's trusted state.

    Claims always outrank unverified research fields.  A trace is itself reviewed
    and retains its account-state position.  The only unverified fallback is the
    trace-less developer-portal behavior.

    There used to be a second, looser fallback — the baseline API/evidence URLs —
    reachable only by the Browser Use backend.  It went with that backend: an
    evidence URL is a page the research cited, not a reviewed place to start
    driving, and nothing selects it now.
    """

    validator = _TargetValidator(allowed_domains, is_allowed_url)
    claims = _verified_claims(research, validator)
    trace_target = validator.accepts(getattr(trace, "start_url", None))

    # Field-level claims and reviewed trace URLs are the only normal candidates.
    # Each is passed through the same strict target validation and host policy.
    for kind in ordered_target_kinds(account_state):
        candidate = trace_target if kind == "trace_start_url" else claims.get(kind)
        if candidate is not None:
            return candidate

    # Preserve the existing conservative Playwright compatibility behavior: an
    # unverified developer portal was allowed only when no reviewed trace exists.
    if trace is None:
        developer_portal = validator.accepts(getattr(research, "developer_portal_url", None))
        if developer_portal is not None:
            return developer_portal

    return None


def _verified_claims(research: Any, validator: _TargetValidator) -> dict[str, str]:
    """Return the first field-level claim that remains valid under current policy."""

    verified: dict[str, str] = {}
    for claim in getattr(research, "operational_url_claims", ()) or ():
        field = getattr(claim, "field", None)
        if field not in _FIELD_NAMES or field in verified:
            continue
        safe = validator.accepts(getattr(claim, "url", None))
        if safe is not None:
            verified[field] = safe
    return verified


__all__ = [
    "AccountState",
    "derive_account_state",
    "ordered_target_kinds",
    "sanitize_target_url",
    "select_browser_target",
]
