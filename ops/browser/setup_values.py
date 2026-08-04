"""Validate immutable, non-secret browser setup values."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from ops.core.model_input_dlp import contains_secret_material

_PROVIDER_LIMITS: dict[str, int] = {
    "application_name": 200,
    "credential_name": 200,
    "bot_name": 120,
    "bot_username": 64,
    "callback_url": 2_048,
    "store_domain": 253,
    "account_name": 200,
    "team_name": 200,
    "organization_name": 200,
    "project_name": 200,
    "instance_name": 200,
    "region": 100,
    "plan": 100,
    "expiration": 100,
    "permission_profile": 100,
    "service_account_name": 200,
    "service_account_email": 320,
    "site": 100,
}
_COMPANY_LIMITS = {
    "company_name": 200,
    "company_website": 2_048,
    "use_case": 2_000,
    "expected_volume": 200,
}
_SAFE_TEXT = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$")
_DOMAIN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
_BOT_USERNAME = re.compile(r"^[A-Za-z0-9_]{5,32}bot$", re.IGNORECASE)

APPROVED_BROWSER_VALUE_REFS = frozenset({*_PROVIDER_LIMITS, *_COMPANY_LIMITS})


def _safe_value(key: str, raw: object, maximum: int) -> str:
    if not isinstance(raw, str):
        raise ValueError("browser setup field must be text")
    value = raw.strip()
    if (
        not value
        or len(value) > maximum
        or _SAFE_TEXT.fullmatch(value) is None
        or "vault://" in value.casefold()
        or contains_secret_material(value)
    ):
        raise ValueError("browser setup field value is invalid")
    if key in {"callback_url", "company_website"}:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("browser setup URL is invalid")
    elif key == "store_domain":
        value = value.casefold().rstrip(".")
        if _DOMAIN.fullmatch(value) is None:
            raise ValueError("provider store domain is invalid")
    elif key == "service_account_email" and _EMAIL.fullmatch(value) is None:
        raise ValueError("provider service-account email is invalid")
    elif key == "bot_username" and _BOT_USERNAME.fullmatch(value) is None:
        raise ValueError("provider bot username is invalid")
    return value


_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

# The refusal reason a caller can turn into an operator-facing pause. The field
# name is appended so a human can see WHICH field a provider asked for that this
# deployment has not reviewed.
FIELD_NOT_IN_ALLOWLIST: str = "field_not_in_allowlist"


def _unapproved_reason(unapproved: Sequence[str]) -> str:
    """``field_not_in_allowlist:<name>`` for the offending keys, safely rendered.

    The keys are untrusted input, so only allowlist-shaped names are echoed; any
    other key is reported as ``<unprintable>`` rather than reflecting arbitrary
    text into a log line or an API body. Sorted so the message is deterministic.
    """

    named = ",".join(
        name if _FIELD_NAME.fullmatch(name) else "<unprintable>" for name in sorted(unapproved)[:5]
    )
    return f"{FIELD_NOT_IN_ALLOWLIST}:{named}"


def _normalize(values: Mapping[str, object] | None, limits: Mapping[str, int]) -> dict[str, str]:
    if not values:
        return {}
    # Naming the field is the whole point: the allowlist is a REVIEWED security
    # control, so a provider asking for something outside it must surface as a
    # diagnosable pause a human can act on -- never as a silent runtime extension
    # of the allowlist, and never as an anonymous "not approved".
    unapproved = set(values) - set(limits)
    if unapproved:
        raise ValueError(_unapproved_reason(tuple(unapproved)))
    if len(values) > len(limits):
        raise ValueError("browser setup fields exceed the approved count")
    return {key: _safe_value(key, raw, limits[key]) for key, raw in values.items()}


def normalize_provider_setup_fields(values: Mapping[str, object] | None) -> dict[str, str]:
    """Validate provider-specific setup values."""

    return _normalize(values, _PROVIDER_LIMITS)


def normalize_browser_setup_fields(values: Mapping[str, object] | None) -> dict[str, str]:
    """Validate the complete browser value-reference mapping."""

    return _normalize(values, {**_PROVIDER_LIMITS, **_COMPANY_LIMITS})


def browser_setup_values(
    provider_setup: Mapping[str, object] | None,
    *,
    company_name: str,
    company_website: str,
    use_case: str,
    expected_volume: str | None,
    callback_urls: Sequence[str],
    app_slug: str,
) -> dict[str, str]:
    """Build the immutable browser value-reference mapping."""

    values = normalize_provider_setup_fields(provider_setup)
    values.setdefault("application_name", f"composio-{app_slug}-integration"[:200])
    values.setdefault("credential_name", f"composio-{app_slug}-credential"[:200])
    if callback_urls:
        values.setdefault("callback_url", callback_urls[0])
    values.update(
        company_name=company_name,
        company_website=company_website,
        use_case=use_case,
    )
    if expected_volume:
        values["expected_volume"] = expected_volume
    return normalize_browser_setup_fields(values)


__all__ = [
    "APPROVED_BROWSER_VALUE_REFS",
    "FIELD_NOT_IN_ALLOWLIST",
    "browser_setup_values",
    "normalize_browser_setup_fields",
    "normalize_provider_setup_fields",
]
