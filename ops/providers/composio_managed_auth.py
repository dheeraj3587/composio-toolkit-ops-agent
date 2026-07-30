"""Composio managed-auth boundary with crash-safe connection linking.

The installed Composio 0.18 SDK is synchronous.  This adapter keeps those
calls off the event loop, exposes only stable provider identifiers, and treats
the OAuth redirect as an ephemeral response value.  Redirect URLs are never
written to the effect ledger; a replay retrieves the still-pending URL from
Composio only long enough to rebuild the owner response.  The result object
deliberately cannot be pickled or serialized as a mapping.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, cast
from urllib.parse import urlsplit

from pydantic import SecretStr

from ops.core.config import Settings
from ops.core.effect_ledger import EffectStore, SQLiteEffectStore
from ops.core.models import validate_https_url, validate_operational_url
from ops.providers.errors import (
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
        alias: str | None = None,
        allow_multiple: bool = False,
    ) -> object: ...

    def get(self, nanoid: str) -> object: ...

    def list(
        self,
        *,
        auth_config_ids: Sequence[str],
        toolkit_slugs: Sequence[str],
        user_ids: Sequence[str],
        limit: float,
    ) -> object: ...


class ManagedAuthSdkClient(Protocol):
    """The exact Composio 0.18 surface used by this boundary."""

    @property
    def auth_configs(self) -> _AuthConfigsResource: ...

    @property
    def connected_accounts(self) -> _ConnectedAccountsResource: ...


class ManagedConnectionStart:
    """A connection identifier plus a deliberately non-serializable redirect.

    ``redirect_url`` is available only to the immediate HTTP response builder.
    Replaying a completed effect may retrieve the still-pending redirect from
    Composio, but it is never copied into a receipt, checkpoint, or audit event.
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
        project_fingerprint: str,
    ) -> None:
        self._client = sdk_client
        self._effects = effect_store
        self._user_id = _validate_identifier(user_id, "user_id")
        self._project_fingerprint = _validate_fingerprint(project_fingerprint)

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
        try:
            validate_managed_auth_callback_base_url(settings.managed_auth_callback_base_url)
        except (TypeError, ValueError):
            raise ConfigurationRequiredError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="managed_auth_callback_not_configured",
            ) from None
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
        project_fingerprint = hashlib.sha256(
            settings.composio_api_key.get_secret_value().encode("utf-8")
        ).hexdigest()
        return cls(
            sdk_client=cast(ManagedAuthSdkClient, client),
            effect_store=effect_store or SQLiteEffectStore(settings.provider_effects_db_path),
            user_id=settings.composio_user_id,
            project_fingerprint=project_fingerprint,
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
        safe_callback = _validate_callback_url(callback_url)
        safe_effect = _validate_effect_identity(effect_identity)
        binding_digest = self._binding_digest(
            toolkit_slug=safe_toolkit,
            callback_url=safe_callback,
        )
        alias = self._connection_alias(
            effect_identity=safe_effect,
            binding_digest=binding_digest,
        )
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
                or reservation.receipt.get("binding_digest") != binding_digest
            ):
                raise ProviderContractError(
                    phase=4,
                    capability=_CAPABILITY,
                    reason_code="effect_identity_conflict",
                )
            redirect_url = await self._recover_redirect(
                request_id,
                toolkit_slug=safe_toolkit,
            )
            return ManagedConnectionStart(
                connection_request_id=request_id,
                redirect_url=redirect_url,
                replayed=True,
            )
        if reservation.status == "reconcile_required":
            return await self._reconcile_connection(
                toolkit_slug=safe_toolkit,
                effect_identity=safe_effect,
                binding_digest=binding_digest,
                alias=alias,
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
                alias=alias,
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
            redirect_url = _validate_redirect_url(raw_redirect)
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
            receipt={
                "request_id": request_id,
                "toolkit_slug": safe_toolkit,
                "binding_digest": binding_digest,
            },
        )
        return ManagedConnectionStart(
            connection_request_id=request_id,
            redirect_url=redirect_url,
            replayed=False,
        )

    async def poll_connection(
        self,
        connection_request_id: str,
        *,
        toolkit_slug: str | None = None,
    ) -> ManagedConnectionPoll:
        """Retrieve one connection and normalize it to pending/active/terminal."""

        safe_id = _validate_identifier(connection_request_id, "connection_request_id")
        safe_toolkit = _validate_toolkit_slug(toolkit_slug) if toolkit_slug is not None else None
        response = await self._get_connection(
            safe_id,
            toolkit_slug=safe_toolkit,
            operation_reason_code="connection_poll_failed",
        )

        try:
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

    async def _reconcile_connection(
        self,
        *,
        toolkit_slug: str,
        effect_identity: str,
        binding_digest: str,
        alias: str,
    ) -> ManagedConnectionStart:
        """Recover an ambiguously-created link by its deterministic alias."""

        auth_config_id = await self._resolve_or_create_auth_config(toolkit_slug)
        request_id = await self._find_connection_request(
            toolkit_slug=toolkit_slug,
            auth_config_id=auth_config_id,
            alias=alias,
        )
        if request_id is None:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_required",
            )
        redirect_url = await self._recover_redirect(
            request_id,
            toolkit_slug=toolkit_slug,
        )
        receipt = {
            "request_id": request_id,
            "toolkit_slug": toolkit_slug,
            "binding_digest": binding_digest,
        }
        try:
            self._effects.reconcile_completed(
                provider=MANAGED_AUTH_EFFECT_PROVIDER,
                action=MANAGED_AUTH_LINK_ACTION,
                idempotency_key=effect_identity,
                receipt=receipt,
            )
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="effect_receipt_persistence_failed",
            ) from None
        return ManagedConnectionStart(
            connection_request_id=request_id,
            redirect_url=redirect_url,
            replayed=True,
        )

    async def _find_connection_request(
        self,
        *,
        toolkit_slug: str,
        auth_config_id: str,
        alias: str,
    ) -> str | None:
        try:
            response = await asyncio.to_thread(
                self._client.connected_accounts.list,
                auth_config_ids=[auth_config_id],
                toolkit_slugs=[toolkit_slug],
                user_ids=[self._user_id],
                limit=1000,
            )
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_lookup_failed",
            ) from None
        items = _field(response, "items")
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_response_invalid",
            )
        matches = [item for item in items if _optional_string_field(item, "alias") == alias]
        if not matches:
            return None
        if len(matches) != 1:
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_response_invalid",
            )
        match = matches[0]
        try:
            request_id = _validate_identifier(
                _required_string_field(match, "id"),
                "connection_request_id",
            )
            returned_user = _validate_identifier(
                _required_string_field(match, "user_id"),
                "user_id",
            )
            returned_toolkit = _validate_toolkit_slug(
                _required_string_field(_field(match, "toolkit"), "slug")
            )
            returned_config = _validate_identifier(
                _required_string_field(_field(match, "auth_config"), "id"),
                "auth_config_id",
            )
            if (
                returned_user != self._user_id
                or returned_toolkit != toolkit_slug
                or returned_config != auth_config_id
            ):
                raise ValueError("connection ownership mismatch")
        except (TypeError, ValueError):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_response_invalid",
            ) from None
        return request_id

    async def _get_connection(
        self,
        connection_request_id: str,
        *,
        toolkit_slug: str | None,
        operation_reason_code: str,
    ) -> object:
        try:
            response = await asyncio.to_thread(
                self._client.connected_accounts.get,
                connection_request_id,
            )
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code=operation_reason_code,
            ) from None
        try:
            returned_id = _validate_identifier(
                _required_string_field(response, "id"),
                "connection_request_id",
            )
            returned_user = _validate_identifier(
                _required_string_field(response, "user_id"),
                "user_id",
            )
            returned_toolkit = _validate_toolkit_slug(
                _required_string_field(_field(response, "toolkit"), "slug")
            )
            if returned_id != connection_request_id or returned_user != self._user_id:
                raise ValueError("connection ownership mismatch")
            if toolkit_slug is not None and returned_toolkit != toolkit_slug:
                raise ValueError("connection toolkit mismatch")
        except (TypeError, ValueError):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_ownership_invalid",
            ) from None
        return response

    async def _recover_redirect(
        self,
        connection_request_id: str,
        *,
        toolkit_slug: str,
    ) -> str | None:
        response = await self._get_connection(
            connection_request_id,
            toolkit_slug=toolkit_slug,
            operation_reason_code="connection_replay_lookup_failed",
        )
        try:
            provider_status = _required_string_field(response, "status").upper()
            state, _reason_code = _normalize_connection_status(provider_status)
            if state != "pending":
                return None
            state_value = _field(_field(response, "state"), "val")
            raw_redirect = _required_string_field(state_value, "redirect_url")
            return _validate_redirect_url(raw_redirect)
        except (TypeError, ValueError):
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="connection_replay_response_invalid",
            ) from None

    def _binding_digest(self, *, toolkit_slug: str, callback_url: str) -> str:
        source = (
            f"managed-auth-binding:v1\0{self._project_fingerprint}\0"
            f"{self._user_id}\0{toolkit_slug}\0{callback_url}"
        )
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    @staticmethod
    def _connection_alias(*, effect_identity: str, binding_digest: str) -> str:
        source = f"managed-auth-alias:v1\0{binding_digest}\0{effect_identity}"
        return f"ops-{hashlib.sha256(source.encode('utf-8')).hexdigest()[:32]}"

    async def _resolve_or_create_auth_config(self, toolkit_slug: str) -> str:
        existing = await self._find_managed_auth_config(toolkit_slug)
        if existing is not None:
            return existing

        effect_identity = f"managed-auth-config:v2:{self._project_fingerprint}:{toolkit_slug}"
        reservation = self._effects.reserve(
            provider=MANAGED_AUTH_EFFECT_PROVIDER,
            action=MANAGED_AUTH_CONFIG_ACTION,
            idempotency_key=effect_identity,
        )
        if reservation.status == "completed":
            config_id = _receipt_identifier(reservation.receipt, "config_id")
            if (
                reservation.receipt is None
                or reservation.receipt.get("toolkit_slug") != toolkit_slug
            ):
                raise ProviderContractError(
                    phase=4,
                    capability=_CAPABILITY,
                    reason_code="effect_identity_conflict",
                )
            return config_id
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
            if managed is False:
                continue
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


def _validate_fingerprint(value: str) -> str:
    normalized = value.casefold()
    if re.fullmatch(r"[a-f0-9]{64}", normalized) is None:
        raise ValueError("project_fingerprint is invalid")
    return normalized


def _validate_strict_https_url(value: str) -> str:
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("URL must not contain whitespace or control characters")
    validated = validate_https_url(value)
    parsed = urlsplit(validated)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is malformed") from exc
    if parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise ValueError("URL port is malformed")
    hostname = parsed.hostname
    if hostname is None:  # pragma: no cover - validate_https_url enforces it
        raise ValueError("URL host is missing")
    normalized_host = hostname.rstrip(".").casefold()
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError("loopback URL hosts are not allowed")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("non-public URL addresses are not allowed")
    _ = port
    return validated


def _validate_callback_url(value: str) -> str:
    validated = validate_operational_url(_validate_strict_https_url(value))
    if validated is None:  # pragma: no cover - non-optional public argument
        raise ValueError("callback_url is required")
    parsed = urlsplit(validated)
    if parsed.query or parsed.fragment:
        raise ValueError("callback URL must not contain query data or a fragment")
    return validated


def validate_managed_auth_callback_base_url(value: str | None) -> str:
    """Validate the public HTTPS origin used to build managed-auth callbacks.

    This is intentionally an offline structural policy. Production deployment
    additionally binds the hostname to ``DOMAIN`` before starting any service.
    """

    if not isinstance(value, str) or not value:
        raise ValueError("managed-auth callback base is required")
    normalized = value.casefold().rstrip("/")
    if normalized in {
        "https://your-domain.example",
        "https://localhost.invalid",
    } or any(marker in normalized for marker in ("replace-with", "change-me", "placeholder")):
        raise ValueError("managed-auth callback base contains a placeholder")
    validated = _validate_strict_https_url(value)
    parsed = urlsplit(validated)
    try:
        port = parsed.port
    except ValueError as exc:  # pragma: no cover - strict validator handles it
        raise ValueError("managed-auth callback port is malformed") from exc
    hostname = parsed.hostname
    if hostname is None:  # pragma: no cover - strict validator handles it
        raise ValueError("managed-auth callback host is missing")
    normalized_hostname = hostname.casefold()
    if normalized_hostname in {"example.com", "example.net", "example.org"} or (
        normalized_hostname == "example" or normalized_hostname.endswith(".example")
    ):
        raise ValueError("managed-auth callback base contains a placeholder")
    if hostname.endswith(".") or "." not in hostname:
        raise ValueError("managed-auth callback host must be a public DNS name")
    if port not in {None, 443}:
        raise ValueError("managed-auth callback must use the standard HTTPS port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("managed-auth callback base must be an HTTPS origin")
    return validated.rstrip("/")


def managed_auth_configuration_is_valid(settings: Settings) -> bool:
    """Return whether managed auth has both a key and a safe callback base."""

    if settings.composio_api_key is None:
        return False
    try:
        validate_managed_auth_callback_base_url(settings.managed_auth_callback_base_url)
    except (TypeError, ValueError):
        return False
    return True


def _validate_redirect_url(value: str) -> str:
    return _validate_strict_https_url(value)


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
