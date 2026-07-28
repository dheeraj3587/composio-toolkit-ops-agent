"""Composio managed-auth boundary with crash-safe connection linking.

The installed Composio 0.18 SDK is synchronous.  This adapter keeps those
calls off the event loop, exposes only stable provider identifiers, and treats
the OAuth redirect as an ephemeral response value.  Redirect URLs are never
written to the effect ledger and the result object deliberately cannot be
pickled or serialized as a mapping.
"""

from __future__ import annotations

import asyncio
import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import SecretStr

from ops.config import Settings
from ops.effect_ledger import EffectStore, SQLiteEffectStore
from ops.models import validate_https_url, validate_operational_url
from ops.provider_errors import (
    ConfigurationRequiredError,
    ProviderContractError,
    ProviderOperationError,
)

MANAGED_AUTH_EFFECT_PROVIDER = "composio_managed_auth"
MANAGED_AUTH_CONFIG_ACTION = "create_auth_config"
MANAGED_AUTH_LINK_ACTION = "link_account"

_CAPABILITY = "Composio managed auth"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_TOOLKIT_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,119}$")
_PENDING_STATUSES = frozenset({"INITIALIZING", "INITIATED", "INACTIVE"})
_TERMINAL_STATUSES = frozenset({"FAILED", "EXPIRED", "REVOKED"})

ConnectionPollState = Literal["pending", "active", "terminal"]


class _AuthConfigsResource(Protocol):
    def list(
        self,
        *,
        toolkit_slug: str,
        is_composio_managed: bool,
        show_disabled: bool,
        limit: float,
    ) -> object: ...

    def create(self, toolkit: str, options: Mapping[str, object]) -> object: ...


class _ConnectedAccountsResource(Protocol):
    def link(
        self,
        user_id: str,
        auth_config_id: str,
        *,
        callback_url: str | None = None,
        allow_multiple: bool = False,
    ) -> object: ...

    def get(self, nanoid: str) -> object: ...


class ManagedAuthSdkClient(Protocol):
    """The exact Composio 0.18 surface used by this boundary."""

    @property
    def auth_configs(self) -> _AuthConfigsResource: ...

    @property
    def connected_accounts(self) -> _ConnectedAccountsResource: ...


class ManagedConnectionStart:
    """A connection identifier plus a deliberately non-serializable redirect.

    ``redirect_url`` is available only to the immediate HTTP response builder.
    Replaying a completed effect returns the same request identifier with no URL,
    because persisting a one-time OAuth URL would violate the secret boundary.
    """

    __slots__ = ("_redirect_url", "connection_request_id", "replayed")

    def __init__(
        self,
        *,
        connection_request_id: str,
        redirect_url: str | None,
        replayed: bool,
    ) -> None:
        self.connection_request_id = _validate_identifier(
            connection_request_id, "connection_request_id"
        )
        self._redirect_url = SecretStr(redirect_url) if redirect_url is not None else None
        self.replayed = replayed

    @property
    def redirect_url(self) -> str | None:
        """Return the redirect for the immediate response; never persist it."""

        return self._redirect_url.get_secret_value() if self._redirect_url is not None else None

    def __repr__(self) -> str:
        availability = "present" if self._redirect_url is not None else "absent"
        return (
            "ManagedConnectionStart("
            f"connection_request_id={self.connection_request_id!r}, "
            f"redirect_url=<{availability}:ephemeral>, replayed={self.replayed!r})"
        )

    def __getstate__(self) -> None:
        raise TypeError("managed-auth connection redirects are ephemeral and cannot be serialized")


@dataclass(frozen=True, slots=True)
class ManagedConnectionPoll:
    """Sanitized result of retrieving a Composio connected account."""

    connection_request_id: str
    state: ConnectionPollState
    provider_status: str
    reason_code: str

    @property
    def active(self) -> bool:
        return self.state == "active"


class ComposioManagedAuthProvider:
    """Resolve managed auth and create at most one connection link per effect."""

    def __init__(
        self,
        *,
        sdk_client: ManagedAuthSdkClient,
        effect_store: EffectStore,
        user_id: str,
    ) -> None:
        self._client = sdk_client
        self._effects = effect_store
        self._user_id = _validate_identifier(user_id, "user_id")

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        effect_store: EffectStore | None = None,
    ) -> ComposioManagedAuthProvider:
        """Build the real lazy SDK boundary without making a network request."""

        if settings.composio_api_key is None:
            raise ConfigurationRequiredError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="composio_not_configured",
            )
        module = importlib.import_module("composio")
        client_type = getattr(module, "Composio", None)
        if not callable(client_type):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="composio_sdk_incompatible",
            )
        client = client_type(
            api_key=settings.composio_api_key.get_secret_value(),
            allow_tracking=False,
        )
        return cls(
            sdk_client=cast(ManagedAuthSdkClient, client),
            effect_store=effect_store or SQLiteEffectStore(settings.provider_effects_db_path),
            user_id=settings.composio_user_id,
        )

    async def start_connection(
        self,
        *,
        toolkit_slug: str,
        callback_url: str,
        effect_identity: str,
    ) -> ManagedConnectionStart:
        """Resolve/create managed auth, then create one Composio Connect Link.

        The caller must persist ``effect_identity`` before invoking this method.
        A replay returns the durable request identifier but intentionally cannot
        replay the one-time redirect URL.
        """

        safe_toolkit = _validate_toolkit_slug(toolkit_slug)
        safe_callback = validate_operational_url(callback_url)
        if safe_callback is None:  # pragma: no cover - non-optional public argument
            raise ValueError("callback_url is required")
        safe_effect = _validate_effect_identity(effect_identity)
        reservation = self._effects.reserve(
            provider=MANAGED_AUTH_EFFECT_PROVIDER,
            action=MANAGED_AUTH_LINK_ACTION,
            idempotency_key=safe_effect,
        )
        if reservation.status == "completed":
            request_id = _receipt_identifier(reservation.receipt, "request_id")
            if (
                reservation.receipt is None
                or reservation.receipt.get("toolkit_slug") != safe_toolkit
            ):
                raise ProviderContractError(
                    phase=4,
                    capability=_CAPABILITY,
                    reason_code="effect_identity_conflict",
                )
            return ManagedConnectionStart(
                connection_request_id=request_id,
                redirect_url=None,
                replayed=True,
            )
        if reservation.status == "reconcile_required":
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_required",
            )

        try:
            auth_config_id = await self._resolve_or_create_auth_config(safe_toolkit)
        except Exception:
            # No link call has occurred, so this reservation is safe to retry.
            self._mark_failed(MANAGED_AUTH_LINK_ACTION, safe_effect)
            raise

        try:
            response = await asyncio.to_thread(
                self._client.connected_accounts.link,
                self._user_id,
                auth_config_id,
                callback_url=safe_callback,
                allow_multiple=False,
            )
        except Exception:
            self._mark_outcome_unknown(MANAGED_AUTH_LINK_ACTION, safe_effect)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_link_failed",
            ) from None

        try:
            request_id = _validate_identifier(
                _required_string_field(response, "id"), "connection_request_id"
            )
            raw_redirect = _required_string_field(response, "redirect_url")
            redirect_url = validate_https_url(raw_redirect)
        except (TypeError, ValueError):
            self._mark_outcome_unknown(MANAGED_AUTH_LINK_ACTION, safe_effect)
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_link_response_invalid",
            ) from None

        self._complete_or_fail_closed(
            action=MANAGED_AUTH_LINK_ACTION,
            effect_identity=safe_effect,
            receipt={"request_id": request_id, "toolkit_slug": safe_toolkit},
        )
        return ManagedConnectionStart(
            connection_request_id=request_id,
            redirect_url=redirect_url,
            replayed=False,
        )

    async def poll_connection(self, connection_request_id: str) -> ManagedConnectionPoll:
        """Retrieve one connection and normalize it to pending/active/terminal."""

        safe_id = _validate_identifier(connection_request_id, "connection_request_id")
        try:
            response = await asyncio.to_thread(self._client.connected_accounts.get, safe_id)
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_poll_failed",
            ) from None

        try:
            returned_id = _validate_identifier(
                _required_string_field(response, "id"), "connection_request_id"
            )
            if returned_id != safe_id:
                raise ValueError("connection response identifier mismatch")
            provider_status = _required_string_field(response, "status").upper()
            state, reason_code = _normalize_connection_status(provider_status)
        except (TypeError, ValueError):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_poll_response_invalid",
            ) from None

        return ManagedConnectionPoll(
            connection_request_id=safe_id,
            state=state,
            provider_status=provider_status,
            reason_code=reason_code,
        )

    async def _resolve_or_create_auth_config(self, toolkit_slug: str) -> str:
        existing = await self._find_managed_auth_config(toolkit_slug)
        if existing is not None:
            return existing

        effect_identity = f"managed-auth-config:v1:{toolkit_slug}"
        reservation = self._effects.reserve(
            provider=MANAGED_AUTH_EFFECT_PROVIDER,
            action=MANAGED_AUTH_CONFIG_ACTION,
            idempotency_key=effect_identity,
        )
        if reservation.status == "completed":
            return _receipt_identifier(reservation.receipt, "config_id")
        if reservation.status == "reconcile_required":
            # The read above is the reconciliation attempt.  If no managed config
            # is visible, creating another one would risk a duplicate.
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="auth_config_reconciliation_required",
            )

        # Recheck after winning the reservation.  This closes the race with a
        # config created outside this process between the first read and reserve.
        try:
            existing = await self._find_managed_auth_config(toolkit_slug)
        except Exception:
            self._mark_failed(MANAGED_AUTH_CONFIG_ACTION, effect_identity)
            raise
        if existing is not None:
            self._complete_or_fail_closed(
                action=MANAGED_AUTH_CONFIG_ACTION,
                effect_identity=effect_identity,
                receipt={"config_id": existing, "toolkit_slug": toolkit_slug},
            )
            return existing

        options: Mapping[str, object] = {
            "type": "use_composio_managed_auth",
            "name": f"Composio Ops - {toolkit_slug}",
            "tool_access_config": {"tools_for_connected_account_creation": []},
        }
        try:
            response = await asyncio.to_thread(
                self._client.auth_configs.create,
                toolkit_slug,
                options,
            )
        except Exception:
            self._mark_outcome_unknown(MANAGED_AUTH_CONFIG_ACTION, effect_identity)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="auth_config_create_failed",
            ) from None

        try:
            config_id = _validate_identifier(
                _required_string_field(response, "id"), "auth_config_id"
            )
            managed = _field(response, "is_composio_managed")
            if managed is not True:
                raise ValueError("created auth config is not Composio-managed")
        except (TypeError, ValueError):
            self._mark_outcome_unknown(MANAGED_AUTH_CONFIG_ACTION, effect_identity)
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="auth_config_create_response_invalid",
            ) from None

        self._complete_or_fail_closed(
            action=MANAGED_AUTH_CONFIG_ACTION,
            effect_identity=effect_identity,
            receipt={"config_id": config_id, "toolkit_slug": toolkit_slug},
        )
        return config_id

    async def _find_managed_auth_config(self, toolkit_slug: str) -> str | None:
        try:
            response = await asyncio.to_thread(
                self._client.auth_configs.list,
                toolkit_slug=toolkit_slug,
                is_composio_managed=True,
                show_disabled=False,
                limit=1000,
            )
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="auth_config_lookup_failed",
            ) from None

        items = _field(response, "items")
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="auth_config_lookup_response_invalid",
            )

        candidates: list[tuple[str, str]] = []
        for item in items:
            status = _optional_string_field(item, "status")
            if status is not None and status.upper() != "ENABLED":
                continue
            managed = _field(item, "is_composio_managed")
            config_type = _optional_string_field(item, "type")
            if managed is not True and config_type != "default":
                continue
            toolkit = _field(item, "toolkit")
            if _optional_string_field(toolkit, "slug") != toolkit_slug:
                continue
            try:
                config_id = _validate_identifier(
                    _required_string_field(item, "id"), "auth_config_id"
                )
            except (TypeError, ValueError):
                # An exact managed-config match with an invalid identifier is
                # provider drift, not absence. Creating another config here could
                # duplicate a real one, so fail closed.
                raise ProviderContractError(
                    phase=4,
                    capability=_CAPABILITY,
                    reason_code="auth_config_lookup_response_invalid",
                ) from None
            created_at = _optional_string_field(item, "created_at") or ""
            candidates.append((created_at, config_id))
        if not candidates:
            return None
        # Prefer the newest enabled config, with the identifier as a stable tie-break.
        return max(candidates)[1]

    def _complete_or_fail_closed(
        self,
        *,
        action: str,
        effect_identity: str,
        receipt: Mapping[str, str],
    ) -> None:
        try:
            self._effects.complete(
                provider=MANAGED_AUTH_EFFECT_PROVIDER,
                action=action,
                idempotency_key=effect_identity,
                receipt=receipt,
            )
        except Exception:
            self._mark_outcome_unknown(action, effect_identity)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="effect_receipt_persistence_failed",
            ) from None

    def _mark_outcome_unknown(self, action: str, effect_identity: str) -> None:
        try:
            self._effects.mark_outcome_unknown(
                provider=MANAGED_AUTH_EFFECT_PROVIDER,
                action=action,
                idempotency_key=effect_identity,
            )
        except Exception:
            pass

    def _mark_failed(self, action: str, effect_identity: str) -> None:
        try:
            self._effects.mark_failed(
                provider=MANAGED_AUTH_EFFECT_PROVIDER,
                action=action,
                idempotency_key=effect_identity,
            )
        except Exception:
            pass


def _field(value: object, name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _required_string_field(value: object, name: str) -> str:
    result = _field(value, name)
    if not isinstance(result, str) or not result:
        raise ValueError(f"{name} is missing")
    return result


def _optional_string_field(value: object, name: str) -> str | None:
    result = _field(value, name)
    return result if isinstance(result, str) and result else None


def _validate_identifier(value: str, name: str) -> str:
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")
    return value


def _validate_toolkit_slug(value: str) -> str:
    normalized = value.strip().casefold()
    if _TOOLKIT_SLUG.fullmatch(normalized) is None:
        raise ValueError("toolkit_slug is invalid")
    return normalized


def _validate_effect_identity(value: str) -> str:
    if not value or len(value) > 500 or any(character in value for character in "\r\n\x00"):
        raise ValueError("effect_identity is invalid")
    return value


def _receipt_identifier(receipt: Mapping[str, str] | None, key: str) -> str:
    if receipt is None:
        raise ProviderContractError(
            phase=4,
            capability=_CAPABILITY,
            reason_code="effect_receipt_invalid",
        )
    value = receipt.get(key)
    try:
        return _validate_identifier(value or "", key)
    except ValueError:
        raise ProviderContractError(
            phase=4,
            capability=_CAPABILITY,
            reason_code="effect_receipt_invalid",
        ) from None


def _normalize_connection_status(status: str) -> tuple[ConnectionPollState, str]:
    if status == "ACTIVE":
        return "active", "connection_active"
    if status in _PENDING_STATUSES:
        return "pending", "connection_pending"
    if status in _TERMINAL_STATUSES:
        return "terminal", f"connection_{status.casefold()}"
    raise ValueError("unsupported connection status")


__all__ = [
    "ComposioManagedAuthProvider",
    "ConnectionPollState",
    "MANAGED_AUTH_CONFIG_ACTION",
    "MANAGED_AUTH_EFFECT_PROVIDER",
    "MANAGED_AUTH_LINK_ACTION",
    "ManagedAuthSdkClient",
    "ManagedConnectionPoll",
    "ManagedConnectionStart",
]
