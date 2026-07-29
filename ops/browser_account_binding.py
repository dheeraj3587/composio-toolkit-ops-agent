"""Opaque account bindings for persisted Playwright authentication state."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping

from pydantic import SecretStr

_APP_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")
_ACCOUNT_REF = re.compile(r"^(?:acct|run)_[0-9a-f]{32}$")
_IDENTITY_FIELDS = ("login_email", "login_username")


def derive_browser_account_ref(
    *,
    run_id: str,
    app_slug: str,
    work_email_ref: str,
    browser_login: Mapping[str, SecretStr] | None,
    binding_secret: SecretStr | str | None,
) -> str:
    """Return a persisted, non-secret storage-state binding.

    An explicitly submitted login identity can be reused across runs only when a
    stable server secret is available to HMAC it.  The raw identity is never
    persisted or sent to the browser service.  Without one unambiguous identity,
    the binding is run-scoped: it still survives API/browser restarts for this run,
    but can never load another run's authenticated state.
    """

    if _RUN_ID.fullmatch(run_id) is None:
        raise ValueError("run_id is invalid")
    if _APP_SLUG.fullmatch(app_slug) is None:
        raise ValueError("app_slug is invalid")

    identities: list[str] = []
    for field in _IDENTITY_FIELDS:
        secret = browser_login.get(field) if browser_login is not None else None
        if secret is None:
            continue
        value = secret.get_secret_value().strip().casefold()
        if value and value not in identities:
            identities.append(value)

    key = (
        binding_secret.get_secret_value()
        if isinstance(binding_secret, SecretStr)
        else binding_secret
    )
    if len(identities) == 1 and isinstance(key, str) and key:
        digest = hmac.new(
            key.encode("utf-8"),
            f"browser-account-v1\0{app_slug}\0{identities[0]}".encode(),
            hashlib.sha256,
        ).hexdigest()[:32]
        return f"acct_{digest}"

    # ``work_email_ref`` is already opaque. It is mixed in only to domain-separate
    # two operators that somehow reuse a run id; the public run id guarantees this
    # fallback never authorizes cross-run state reuse.
    digest = hashlib.sha256(
        f"browser-run-v1\0{app_slug}\0{run_id}\0{work_email_ref}".encode()
    ).hexdigest()[:32]
    return f"run_{digest}"


def validate_browser_account_ref(value: object) -> str:
    """Accept only bindings produced by :func:`derive_browser_account_ref`."""

    if not isinstance(value, str) or _ACCOUNT_REF.fullmatch(value) is None:
        raise ValueError("browser account reference is invalid")
    return value


__all__ = ["derive_browser_account_ref", "validate_browser_account_ref"]
