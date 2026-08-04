"""The one place a captured credential is pattern-checked before it is stored.

Both transports that can capture a credential call :func:`capture_validated_credential`,
so the contract the broker's own comment asserts — "re-apply the recipe's exact value
contract at the API/vault boundary so a compromised worker cannot persist arbitrary
material" — is a property of ONE function rather than of two that could drift:

* the production RPC path, through ``api.browser_secret_broker._capture_sync``, where
  the value arrives over HTTP from the isolated browser container;
* the local in-process path, where the onboarding credential surface reads the value
  itself because there is no second process to read it in.

``SQLiteSecretStore.capture_with_grant`` deliberately applies NO pattern of its own —
it enforces the grant binding and writes. So this function is the only thing standing
between a read value and a vault row, and it is written to be unskippable:

**There is no parameter that can disable the check.** No ``validate: bool``, no
optional pattern, no "trusted caller" flag. The pattern comes from the field spec the
caller already had to resolve, and a spec that declares no field for the requested
kind authorizes nothing. Adding such a parameter later would silently retire the
invariant, so don't.

**The order is fixed:** resolve the field, then ``re.fullmatch`` the whole value, then
store. Anything else is refused with ``CaptureRefused`` before the vault
is touched.

The asymmetry with the READ side is deliberate and is what
``ops.onboarding.capture_specs`` describes: a provider with no reviewed recipe has no
selectors, so the read may be broad, and correctness comes from this anchored
re-validation rather than from having picked the right DOM node.
"""

from __future__ import annotations

import re
from typing import Protocol

from ops.core.secret_store import BrowserSecretGrantError
from ops.credentials.capture_specs import CredentialCaptureSpec


class CaptureRefused(Exception):
    """One refusal for every way a capture can fail to be authorized.

    Deliberately single-valued and deliberately not subclassed per cause. The three
    failure modes — the spec declares no field for this kind, the value does not match
    the checked-in pattern, the grant binding is refused — are all "this write is not
    authorized", and splitting them would let a caller treat one as softer than
    another.

    ``api.browser_secret_broker`` translates this into its own
    ``BrowserCaptureNotAuthorized`` so the RPC response vocabulary is unchanged. The
    dependency runs from the broker to here and never the other way, which is why this
    module raises its own type rather than the broker's.
    """


class CaptureVault(Protocol):
    """The one vault verb a capture needs. No read verb, by construction."""

    def capture_with_grant(
        self,
        grant: str,
        *,
        app_slug: str,
        kind: str,
        scope_id: str,
        session_id: str,
        value: str,
        expected_operation_key: str,
    ) -> str:
        """Atomically capture once, returning the ``vault://`` reference."""


def capture_validated_credential(
    *,
    store: CaptureVault,
    spec: CredentialCaptureSpec,
    grant: str,
    app_slug: str,
    kind: str,
    scope_id: str,
    session_id: str,
    value: str,
    operation_key: str,
    field_kind: str | None = None,
) -> str:
    """Pattern-check one captured value against its contract, then store it.

    PRE:  ``spec`` was resolved by the caller from a reviewed recipe or from the
          run's committed profile — never from page text. ``operation_key`` is the
          key the grant was reserved under; a mismatch is refused by the vault's own
          grant-binding check rather than trusted here.
    POST: returns the ``vault://`` reference of a row the vault already wrote, or
          raises :class:`CaptureRefused` having written nothing.

    ``kind`` is the VAULT ROW kind the value is stored under. ``field_kind`` is
    the contract's field the value is matched against, and defaults to ``kind``:
    the reviewed vocabulary happens to make them the same string on the broker
    path, while the onboarding path stores under its ``onboarding_*`` namespace
    and matches against the contract's own field name. One value, two names, and
    neither is a place a value may appear.

    RAISES: :class:`CaptureRefused` when the spec declares no field for
          ``field_kind`` (or ``kind`` when ``field_kind`` is ``None``), when
          ``value`` is not a whole-string match for that field's
          ``value_pattern``, or when the vault refuses the grant binding.
    """

    # The requested kind must be one the contract declares; a contract that declares
    # no pattern for it authorizes nothing.
    field = spec.field(field_kind if field_kind is not None else kind)
    if field is None:
        raise CaptureRefused
    # The worker — local or remote — is trusted to transport a reviewed capture, not
    # to redefine its format. ``fullmatch`` and the pattern's own ``\A``/``\Z``
    # anchors both apply: a value with trailing page text is not this credential.
    if re.fullmatch(field.value_pattern, value) is None:
        raise CaptureRefused
    try:
        return str(
            store.capture_with_grant(
                grant,
                app_slug=app_slug,
                kind=kind,
                scope_id=scope_id,
                session_id=session_id,
                value=value,
                expected_operation_key=operation_key,
            )
        )
    except BrowserSecretGrantError:
        # A refused grant binding is the same "not authorized" answer as a pattern
        # mismatch, and nothing was persisted: the vault checks the binding before it
        # writes. Folded into one refusal so a caller cannot treat it as softer.
        raise CaptureRefused from None


__all__ = [
    "CaptureRefused",
    "CaptureVault",
    "capture_validated_credential",
]
