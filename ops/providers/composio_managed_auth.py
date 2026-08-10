"""Composio managed-auth boundary with crash-safe connection linking.

The installed Composio 0.18 SDK is synchronous.  This adapter keeps those
calls off the event loop, exposes only stable provider identifiers, and treats
the OAuth redirect as an ephemeral response value.  Redirect URLs are never
written to the effect ledger; a replay retrieves the still-pending URL from
Composio only long enough to rebuild the owner response.  The result object
deliberately cannot be pickled or serialized as a mapping.

There are two ways in, and they differ in whether a human is in the loop.
:meth:`ComposioManagedAuthProvider.start_connection` is the redirect flow: a
Composio-managed OAuth config, a Connect Link, and an owner who has to visit it.
:meth:`ComposioManagedAuthProvider.create_api_key_connection` is the synchronous
one: the owner already holds a key, so a ``use_custom_auth`` config pinned to
API_KEY or BEARER_TOKEN turns it into an ACTIVE connected account in a single
call.  The two never share an effect action or an auth config, because a managed
OAuth config and a custom key config are not substitutable for the same toolkit.
The owner's key reaches the SDK call and nothing else -- no ledger receipt, no
returned object, no log line, no audit payload.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
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
# Distinct ``create_auth_config`` variants.  A key-scheme auth config is
# ``use_custom_auth`` and is NOT interchangeable with the Composio-managed
# OAuth config for the same toolkit, so it must never share a ledger effect
# key with it: the ledger keys on (provider, action, idempotency_key), and a
# shared action would let a replay of one hand back the other's config id.
MANAGED_KEY_CONFIG_ACTION = "create_key_auth_config"
MANAGED_KEY_CONNECT_ACTION = "create_key_connection"

_CAPABILITY = "Composio managed auth"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_TOOLKIT_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,119}$")
_PENDING_STATUSES = frozenset({"INITIALIZING", "INITIATED", "INACTIVE"})
_TERMINAL_STATUSES = frozenset({"FAILED", "EXPIRED", "REVOKED"})

ConnectionPollState = Literal["pending", "active", "terminal"]
# The three key schemes this boundary imports.  All three return an ACTIVE
# connected account from the same synchronous call -- no redirect, no browser, no
# human -- because the SDK's own helpers pin the status:
# ``composio/core/models/connected_accounts.py`` emits ``"status": "ACTIVE"`` in
# ``AuthScheme.api_key``, ``AuthScheme.basic``, and ``AuthScheme.bearer_token``
# alike.  Other ACTIVE-pinning schemes there (NO_AUTH, service accounts) stay
# excluded because each carries a DIFFERENT credential shape that would need its
# own reviewed field mapping, not because they would redirect.
KeyAuthScheme = Literal["API_KEY", "BASIC", "BEARER_TOKEN"]
# The connection-state field each scheme carries the owner's secret in.  The
# names differ and cannot be derived from the scheme: the generated request type
# calls the API key ``api_key``, the bearer credential ``token``, and the basic
# credential ``password``.  Verified against the generated union in
# ``composio_client/types/connected_account_create_params.py``, whose members are
# ordered API_KEY (2), BASIC (3), BEARER_TOKEN (4) -- note this does NOT match
# the ``ConnectionStateUnionMember3Val`` cast in the SDK's own ``api_key``
# helper, which is why this mapping is written out rather than imported.
# Every value below is a FIELD NAME, not a value: the pragmas mark the scanner's
# keyword heuristic as a false positive. They sit on the mapping's own lines
# because detect-secrets anchors a pragma to the line it reported, so one on the
# opening brace suppresses nothing and the gate fails on a comment's position.
_KEY_SCHEME_SECRET_FIELDS: Mapping[str, str] = MappingProxyType(
    {
        "API_KEY": "api_key",  # pragma: allowlist secret
        "BASIC": "password",  # pragma: allowlist secret
        "BEARER_TOKEN": "token",  # pragma: allowlist secret
    }
)
# Schemes whose ACTIVE connection state is INCOMPLETE without a second,
# non-secret value, mapped to the state key that value must occupy.  Only BASIC
# has one: its ACTIVE variant marks ``username`` ``Required`` while ``password``
# is optional, so publishing a BASIC connection with the secret alone would be
# accepted by the type and rejected -- or worse, silently created broken -- by
# the vendor.  Enforced in ``_key_connection_state`` rather than trusted to
# callers.
_KEY_SCHEME_REQUIRED_COMPANIONS: Mapping[str, str] = MappingProxyType({"BASIC": "username"})
# The only connection-state keys a companion value may be written to.  A closed
# set because the companion travels from catalog data into the request body: an
# open mapping would let a future recipe edit place owner-supplied text into any
# field of the connection state, including one that changes where the vendor
# call is sent (``base_url``, ``api_url``).  ``username`` carries an account
# identity such as Jira's Atlassian email; ``account_id`` carries a tenant
# selector such as Harvest's account id.
_KEY_COMPANION_STATE_KEYS: frozenset[str] = frozenset({"username", "account_id"})


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

    def initiate(
        self,
        user_id: str,
        auth_config_id: str,
        *,
        config: Mapping[str, object] | None = None,
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


@dataclass(frozen=True, slots=True)
class ManagedKeyConnection:
    """Sanitized result of a synchronous key-scheme connection.

    Carries no credential: the owner's secret reaches the SDK call and nothing
    else.  ``state`` is normalized exactly as ``poll_connection`` normalizes it,
    so a caller that already understands one understands both.
    """

    connected_account_id: str
    state: ConnectionPollState
    provider_status: str
    reason_code: str
    replayed: bool

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

        already_connected = _multiple_connected_accounts_error()
        try:
            response = await asyncio.to_thread(
                self._client.connected_accounts.link,
                self._user_id,
                auth_config_id,
                callback_url=safe_callback,
                alias=alias,
                allow_multiple=False,
            )
        except already_connected:
            # Composio refused to create a second connection because an ACTIVE one
            # already covers this user and auth config, so no link was made. Adopt
            # the existing connection instead of failing: effect_identity is
            # per-run, so every retry would present a new identity (and a new
            # alias) and could never reconcile this app.
            return await self._adopt_active_connection(
                toolkit_slug=safe_toolkit,
                auth_config_id=auth_config_id,
                effect_identity=safe_effect,
                binding_digest=binding_digest,
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

    async def create_api_key_connection(
        self,
        *,
        toolkit_slug: str,
        auth_scheme: KeyAuthScheme,
        secret: SecretStr,
        effect_identity: str,
        companion: tuple[str, str] | None = None,
    ) -> ManagedKeyConnection:
        """Import an owner-held key as an ACTIVE Composio connection, in one call.

        This is the synchronous half of managed auth, and until it existed there
        was no route to it at all.  :meth:`start_connection` can only ever hand
        back a redirect because :meth:`_resolve_or_create_auth_config` hardcodes
        ``use_composio_managed_auth``, which is OAuth by construction; an app
        whose only credential is a key the owner already holds therefore fell
        through to browser onboarding or vendor outreach for a toolkit Composio
        already integrates.

        The key never becomes state.  It is read out of ``secret`` at the SDK
        call and nowhere else: it is absent from the ledger receipt, from the
        returned dataclass, from every reason code, and from every exception
        raised here -- each provider failure is re-raised ``from None`` so an SDK
        message that echoed the credential cannot ride out on ``__cause__``.

        ``companion`` is the reviewed ``(state_key, value)`` pair for a vendor
        whose key does not identify an account by itself -- Jira's API token
        needs the Atlassian account email, Harvest's needs the account id. It is
        deliberately NOT a secret and is validated, not vaulted. Passing it is
        mandatory for BASIC and refused for an unreviewed state key; see
        :func:`_key_connection_state`.

        The caller must persist ``effect_identity`` before invoking this method,
        exactly as for :meth:`start_connection`.
        """

        safe_toolkit = _validate_toolkit_slug(toolkit_slug)
        safe_scheme = _validate_key_auth_scheme(auth_scheme)
        safe_secret = _validate_key_secret(secret)
        safe_effect = _validate_effect_identity(effect_identity)
        # Built before the ledger reservation so a malformed companion is refused
        # without ever reserving a side effect that would then need reconciling.
        connection_state = _key_connection_state(safe_scheme, safe_secret, companion)
        binding_digest = self._key_binding_digest(
            toolkit_slug=safe_toolkit,
            auth_scheme=safe_scheme,
        )
        alias = self._connection_alias(
            effect_identity=safe_effect,
            binding_digest=binding_digest,
        )
        reservation = self._effects.reserve(
            provider=MANAGED_AUTH_EFFECT_PROVIDER,
            action=MANAGED_KEY_CONNECT_ACTION,
            idempotency_key=safe_effect,
        )
        if reservation.status == "completed":
            account_id = _receipt_identifier(reservation.receipt, "account_id")
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
            return await self._key_connection_from_provider(
                account_id,
                toolkit_slug=safe_toolkit,
                replayed=True,
            )
        if reservation.status == "reconcile_required":
            return await self._reconcile_key_connection(
                toolkit_slug=safe_toolkit,
                auth_scheme=safe_scheme,
                effect_identity=safe_effect,
                binding_digest=binding_digest,
                alias=alias,
            )

        try:
            auth_config_id = await self._resolve_or_create_key_auth_config(
                safe_toolkit,
                safe_scheme,
            )
        except Exception:
            # No connection call has occurred, so this reservation is safe to retry.
            self._mark_failed(MANAGED_KEY_CONNECT_ACTION, safe_effect)
            raise

        already_connected = _multiple_connected_accounts_error()
        try:
            response = await asyncio.to_thread(
                self._client.connected_accounts.initiate,
                self._user_id,
                auth_config_id,
                config=connection_state,
                alias=alias,
                allow_multiple=False,
            )
        except already_connected:
            # Same refusal, same remedy as the OAuth path: Composio would not add
            # a second connection because an ACTIVE one already covers this user
            # and auth config, so nothing was created. Adopt it rather than fail
            # -- effect_identity is per-run, so a retry brings a new identity and
            # a new alias and could never reconcile this app.
            return await self._adopt_active_key_connection(
                toolkit_slug=safe_toolkit,
                auth_config_id=auth_config_id,
                effect_identity=safe_effect,
                binding_digest=binding_digest,
            )
        except Exception:
            self._mark_outcome_unknown(MANAGED_KEY_CONNECT_ACTION, safe_effect)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="key_connection_create_failed",
            ) from None

        try:
            account_id = _validate_identifier(
                _required_string_field(response, "id"), "connected_account_id"
            )
            provider_status = _required_string_field(response, "status").upper()
            state, reason_code = _normalize_connection_status(provider_status)
        except (TypeError, ValueError):
            self._mark_outcome_unknown(MANAGED_KEY_CONNECT_ACTION, safe_effect)
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="key_connection_response_invalid",
            ) from None

        self._complete_or_fail_closed(
            action=MANAGED_KEY_CONNECT_ACTION,
            effect_identity=safe_effect,
            receipt={
                "account_id": account_id,
                "toolkit_slug": safe_toolkit,
                "binding_digest": binding_digest,
            },
        )
        return ManagedKeyConnection(
            connected_account_id=account_id,
            state=state,
            provider_status=provider_status,
            reason_code=reason_code,
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

    async def _adopt_active_connection(
        self,
        *,
        toolkit_slug: str,
        auth_config_id: str,
        effect_identity: str,
        binding_digest: str,
    ) -> ManagedConnectionStart:
        """Complete this effect against the ACTIVE connection Composio already holds.

        No link call succeeded, so nothing was duplicated; the run simply inherits
        the connection that made a second link impossible. An already-active
        account has no pending redirect, which is exactly right — there is nothing
        left for the owner to authorize.
        """

        try:
            request_id = await self._find_connection_request(
                toolkit_slug=toolkit_slug,
                auth_config_id=auth_config_id,
                alias=None,
            )
        except Exception:
            # The lookup failed, or found two ACTIVE accounts and refused to guess.
            # Release the reservation before the error escapes: Composio refused
            # the link, so no effect was spent and "failed" is the honest status.
            # Leaving it pending is the trap this arm exists to avoid — the next
            # arrival would read ``reconcile_required`` and reconcile BY ALIAS,
            # and this run's alias was never written to any connection, so it
            # would refuse forever even after an operator removed the duplicate.
            self._mark_failed(MANAGED_AUTH_LINK_ACTION, effect_identity)
            raise
        if request_id is None:
            # Composio reported an active account but will not show it; creating
            # another link here could duplicate a real connection.
            self._mark_failed(MANAGED_AUTH_LINK_ACTION, effect_identity)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_required",
            )
        redirect_url = await self._recover_redirect(request_id, toolkit_slug=toolkit_slug)
        self._complete_or_fail_closed(
            action=MANAGED_AUTH_LINK_ACTION,
            effect_identity=effect_identity,
            receipt={
                "request_id": request_id,
                "toolkit_slug": toolkit_slug,
                "binding_digest": binding_digest,
            },
        )
        return ManagedConnectionStart(
            connection_request_id=request_id,
            redirect_url=redirect_url,
            replayed=True,
        )

    async def _reconcile_key_connection(
        self,
        *,
        toolkit_slug: str,
        auth_scheme: str,
        effect_identity: str,
        binding_digest: str,
        alias: str,
    ) -> ManagedKeyConnection:
        """Recover an ambiguously-created key connection by its deterministic alias."""

        auth_config_id = await self._resolve_or_create_key_auth_config(toolkit_slug, auth_scheme)
        account_id = await self._find_connection_request(
            toolkit_slug=toolkit_slug,
            auth_config_id=auth_config_id,
            alias=alias,
        )
        if account_id is None:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_required",
            )
        result = await self._key_connection_from_provider(
            account_id,
            toolkit_slug=toolkit_slug,
            replayed=True,
        )
        try:
            self._effects.reconcile_completed(
                provider=MANAGED_AUTH_EFFECT_PROVIDER,
                action=MANAGED_KEY_CONNECT_ACTION,
                idempotency_key=effect_identity,
                receipt={
                    "account_id": account_id,
                    "toolkit_slug": toolkit_slug,
                    "binding_digest": binding_digest,
                },
            )
        except Exception:
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="effect_receipt_persistence_failed",
            ) from None
        return result

    async def _adopt_active_key_connection(
        self,
        *,
        toolkit_slug: str,
        auth_config_id: str,
        effect_identity: str,
        binding_digest: str,
    ) -> ManagedKeyConnection:
        """Complete this effect against the ACTIVE connection Composio already holds.

        The reasoning is :meth:`_adopt_active_connection`'s, and so is the failure
        handling: no connection was created, so "failed" is the honest status and
        leaving the reservation pending would send the next arrival down the
        alias-based reconcile path for an alias no connection ever carried.

        Re-importing the key would be the alternative and is worse: it would mint
        a second credential the owner did not ask for, and Composio refusing it is
        the signal that this app is already connected.
        """

        try:
            account_id = await self._find_connection_request(
                toolkit_slug=toolkit_slug,
                auth_config_id=auth_config_id,
                alias=None,
            )
        except Exception:
            self._mark_failed(MANAGED_KEY_CONNECT_ACTION, effect_identity)
            raise
        if account_id is None:
            # Composio reported an active account but will not show it; importing
            # the key again here could duplicate a real connection.
            self._mark_failed(MANAGED_KEY_CONNECT_ACTION, effect_identity)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="connection_reconciliation_required",
            )
        result = await self._key_connection_from_provider(
            account_id,
            toolkit_slug=toolkit_slug,
            replayed=True,
        )
        self._complete_or_fail_closed(
            action=MANAGED_KEY_CONNECT_ACTION,
            effect_identity=effect_identity,
            receipt={
                "account_id": account_id,
                "toolkit_slug": toolkit_slug,
                "binding_digest": binding_digest,
            },
        )
        return result

    async def _key_connection_from_provider(
        self,
        connected_account_id: str,
        *,
        toolkit_slug: str,
        replayed: bool,
    ) -> ManagedKeyConnection:
        """Rebuild one key connection's sanitized state by re-reading the provider.

        A replay must not assert ``active`` from a receipt written some time ago:
        the connection may have been revoked since, and a stale "active" would
        skip the very onboarding the owner is asking for. Re-reading costs one
        request, carries no credential, and normalizes through exactly the same
        status table :meth:`poll_connection` uses.
        """

        poll = await self.poll_connection(connected_account_id, toolkit_slug=toolkit_slug)
        return ManagedKeyConnection(
            connected_account_id=poll.connection_request_id,
            state=poll.state,
            provider_status=poll.provider_status,
            reason_code=poll.reason_code,
            replayed=replayed,
        )

    async def _find_connection_request(
        self,
        *,
        toolkit_slug: str,
        auth_config_id: str,
        alias: str | None,
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
        if alias is None:
            # Adoption path: match the ACTIVE account the SDK itself found, since
            # this run's alias was never written to any connection.
            matches = [
                item
                for item in items
                if (_optional_string_field(item, "status") or "").upper() == "ACTIVE"
            ]
        else:
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

    def _key_binding_digest(self, *, toolkit_slug: str, auth_scheme: str) -> str:
        """Bind a key effect to its project, user, toolkit and SCHEME.

        There is no callback URL to bind here, and the scheme takes its place for
        a reason rather than for symmetry: API_KEY and BEARER_TOKEN produce
        different auth configs and different credentials, so a replay that
        presented the same effect identity under the other scheme must read as a
        conflict instead of handing back an account it does not describe.  The
        ``managed-key-`` prefix keeps this digest from ever colliding with an
        OAuth one even if every other component matched.
        """

        source = (
            f"managed-key-binding:v1\0{self._project_fingerprint}\0"
            f"{self._user_id}\0{toolkit_slug}\0{auth_scheme}"
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
        except Exception as exc:
            self._mark_create_failure(MANAGED_AUTH_CONFIG_ACTION, effect_identity, exc)
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

    async def _resolve_or_create_key_auth_config(
        self,
        toolkit_slug: str,
        auth_scheme: str,
    ) -> str:
        """Resolve or create the ``use_custom_auth`` config one key scheme needs.

        Deliberately a sibling of :meth:`_resolve_or_create_auth_config` rather
        than a branch inside it.  The two produce configs that are not
        substitutable -- one is Composio's managed OAuth app for the toolkit, the
        other is a custom config pinned to a single key scheme -- and the ledger
        keys on (provider, action, idempotency_key), so sharing an action would
        let a replay of one hand back the other's config id and silently turn a
        key import into a redirect nobody asked for.  The lookup has to be
        separate for the same reason: ``_find_managed_auth_config`` filters on
        ``is_composio_managed=True`` and would never see this config, then create
        a duplicate on every run.
        """

        existing = await self._find_key_auth_config(toolkit_slug, auth_scheme)
        if existing is not None:
            return existing

        effect_identity = (
            f"managed-key-config:v1:{self._project_fingerprint}:{toolkit_slug}:{auth_scheme}"
        )
        reservation = self._effects.reserve(
            provider=MANAGED_AUTH_EFFECT_PROVIDER,
            action=MANAGED_KEY_CONFIG_ACTION,
            idempotency_key=effect_identity,
        )
        if reservation.status == "completed":
            config_id = _receipt_identifier(reservation.receipt, "config_id")
            if (
                reservation.receipt is None
                or reservation.receipt.get("toolkit_slug") != toolkit_slug
                or reservation.receipt.get("auth_scheme") != auth_scheme
            ):
                raise ProviderContractError(
                    phase=4,
                    capability=_CAPABILITY,
                    reason_code="effect_identity_conflict",
                )
            return config_id
        if reservation.status == "reconcile_required":
            # The read above is the reconciliation attempt.  If no matching key
            # config is visible, creating another one would risk a duplicate.
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="auth_config_reconciliation_required",
            )

        # Recheck after winning the reservation, closing the race with a config
        # created outside this process between the first read and the reserve.
        try:
            existing = await self._find_key_auth_config(toolkit_slug, auth_scheme)
        except Exception:
            self._mark_failed(MANAGED_KEY_CONFIG_ACTION, effect_identity)
            raise
        if existing is not None:
            self._complete_or_fail_closed(
                action=MANAGED_KEY_CONFIG_ACTION,
                effect_identity=effect_identity,
                receipt={
                    "config_id": existing,
                    "toolkit_slug": toolkit_slug,
                    "auth_scheme": auth_scheme,
                },
            )
            return existing

        # ``tool_access_config`` is absent on purpose: the generated parameter
        # documents it as scope generation "only valid for OAuth", and a key
        # config has no scopes to derive.
        options: Mapping[str, object] = {
            "type": "use_custom_auth",
            "auth_scheme": auth_scheme,
            "name": f"Composio Ops - {toolkit_slug} ({auth_scheme.casefold()})",
        }
        try:
            response = await asyncio.to_thread(
                self._client.auth_configs.create,
                toolkit_slug,
                options,
            )
        except Exception as exc:
            self._mark_create_failure(MANAGED_KEY_CONFIG_ACTION, effect_identity, exc)
            raise ProviderOperationError(
                capability=_CAPABILITY,
                reason_code="auth_config_create_failed",
            ) from None

        try:
            config_id = _validate_identifier(
                _required_string_field(response, "id"), "auth_config_id"
            )
            if _optional_string_field(response, "auth_scheme") != auth_scheme:
                raise ValueError("created auth config is not the requested key scheme")
            if _field(response, "is_composio_managed") is True:
                raise ValueError("created auth config is Composio-managed, not custom")
        except (TypeError, ValueError):
            self._mark_outcome_unknown(MANAGED_KEY_CONFIG_ACTION, effect_identity)
            raise ProviderContractError(
                phase=4,
                capability=_CAPABILITY,
                reason_code="auth_config_create_response_invalid",
            ) from None

        self._complete_or_fail_closed(
            action=MANAGED_KEY_CONFIG_ACTION,
            effect_identity=effect_identity,
            receipt={
                "config_id": config_id,
                "toolkit_slug": toolkit_slug,
                "auth_scheme": auth_scheme,
            },
        )
        return config_id

    async def _find_key_auth_config(self, toolkit_slug: str, auth_scheme: str) -> str | None:
        """Find an enabled custom auth config for exactly this toolkit and scheme.

        Narrower than :meth:`_find_managed_auth_config` in the one way that
        matters: a custom config's scheme is part of its identity, so a
        BEARER_TOKEN config for the same toolkit is not a match and must not be
        reused to import an API key.
        """

        try:
            response = await asyncio.to_thread(
                self._client.auth_configs.list,
                toolkit_slug=toolkit_slug,
                is_composio_managed=False,
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
            if _field(item, "is_composio_managed") is True:
                continue
            if _optional_string_field(item, "auth_scheme") != auth_scheme:
                continue
            toolkit = _field(item, "toolkit")
            if _optional_string_field(toolkit, "slug") != toolkit_slug:
                continue
            try:
                config_id = _validate_identifier(
                    _required_string_field(item, "id"), "auth_config_id"
                )
            except (TypeError, ValueError):
                # An exact match with an invalid identifier is provider drift, not
                # absence. Creating another config here could duplicate a real
                # one, so fail closed.
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

    def _mark_create_failure(self, action: str, effect_identity: str, exc: BaseException) -> None:
        """Record a failed create as retryable when it PROVES nothing was created.

        Every create failure used to land on ``outcome_unknown``, which is the one
        status nothing in this repo ever clears: the effect key is
        deployment-wide (project fingerprint + toolkit, not per run), so a single
        transient 429 latched that toolkit into
        ``auth_config_reconciliation_required`` for every future run, forever,
        with no operator action that resolves it.

        A rejection the server ISSUED — 4xx, and 429 above all — is proof the
        request was understood and refused, so no config exists and the effect can
        be recycled for a straight retry. Ambiguity (a timeout, a reset, a 5xx)
        keeps ``outcome_unknown``, because there the create may well have landed.
        """

        if _create_definitely_rejected(exc):
            self._mark_failed(action, effect_identity)
            return
        self._mark_outcome_unknown(action, effect_identity)

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


def _create_definitely_rejected(exc: BaseException) -> bool:
    """True only when the server answered the create with a 4xx refusal.

    Reads a status code off whichever attribute the SDK exposes it under, and off
    a ``response`` object when the exception wraps one. No message-text matching:
    a vendor string is not a contract, and being wrong here in the permissive
    direction would recycle an effect whose side effect really happened. Anything
    unrecognized is NOT a proven rejection, so the caller keeps
    ``outcome_unknown``.

    408 (request timeout) and 425 (too early) are excluded from the 4xx range on
    purpose: both mean the server may have begun processing.
    """

    candidates: list[object] = [getattr(exc, "status_code", None), getattr(exc, "status", None)]
    response = getattr(exc, "response", None)
    if response is not None:
        candidates.append(getattr(response, "status_code", None))
    for value in candidates:
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        if value in {408, 425}:
            return False
        if 400 <= value < 500:
            return True
    return False


class _UnraisableSdkError(Exception):
    """Stand-in that can never be raised, used when the SDK class is unavailable."""


@lru_cache(maxsize=1)
def _multiple_connected_accounts_error() -> type[BaseException]:
    """Resolve ``composio.exceptions.ComposioMultipleConnectedAccountsError`` lazily.

    The SDK stays an optional, lazily imported dependency: when it is absent or
    has dropped the class, the returned sentinel simply never matches and the
    existing catch-all keeps its behaviour.
    """

    try:
        module = importlib.import_module("composio.exceptions")
    except ImportError:  # pragma: no cover - the SDK is installed in this project
        return _UnraisableSdkError
    error = getattr(module, "ComposioMultipleConnectedAccountsError", None)
    if isinstance(error, type) and issubclass(error, BaseException):
        return error
    return _UnraisableSdkError  # pragma: no cover - guards SDK drift only


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


def _validate_key_auth_scheme(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("auth_scheme is invalid")
    normalized = value.strip().upper()
    if normalized not in _KEY_SCHEME_SECRET_FIELDS:
        raise ValueError("auth_scheme is not a synchronous key scheme")
    return normalized


def _validate_key_secret(value: SecretStr) -> SecretStr:
    """Check the owner's key is usable without ever putting it in a message.

    The bounds are structural, not semantic -- only Composio can say whether a
    key is real. What they do rule out is the shape that would make this boundary
    unsafe: an empty value that would create a broken ACTIVE connection, and a
    newline or NUL that could split whatever the SDK serializes the key into.
    Every rejection message names the argument and never its value.
    """

    if not isinstance(value, SecretStr):
        raise ValueError("secret must be a SecretStr")
    raw = value.get_secret_value()
    if not raw or len(raw) > 8_192 or any(character in raw for character in "\r\n\x00"):
        raise ValueError("secret is invalid")
    return value


def _validate_key_companion(state_key: str, value: str) -> tuple[str, str]:
    """Check the non-secret value that travels beside the key.

    A companion is not a credential -- it is an account email or a tenant id --
    but it lands in the same request body, so it gets the same structural
    treatment: bounded length, no newline or NUL that could split whatever the
    SDK serializes it into. The state key is additionally held to
    ``_KEY_COMPANION_STATE_KEYS``, because that key decides which field of the
    connection state the value occupies.
    """

    if state_key not in _KEY_COMPANION_STATE_KEYS:
        raise ValueError("companion_state_key is not reviewed")
    if not isinstance(value, str):
        raise ValueError("companion value is invalid")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 500 or any(ch in cleaned for ch in "\r\n\x00"):
        raise ValueError("companion value is invalid")
    return (state_key, cleaned)


def _key_connection_state(
    auth_scheme: str,
    secret: SecretStr,
    companion: tuple[str, str] | None = None,
) -> Mapping[str, object]:
    """Build the single SDK argument the owner's key ever appears in.

    Mirrors the SDK's own helpers rather than calling them, so the mapping stays
    inspectable at this boundary: ``AuthScheme.api_key``, ``AuthScheme.basic``,
    and ``AuthScheme.bearer_token`` all build exactly ``{"auth_scheme": ...,
    "val": {"status": "ACTIVE", ...}}``, and that pinned ACTIVE is what makes the
    call synchronous.

    ``companion`` is the reviewed ``(state_key, value)`` pair for the vendors
    whose key is meaningless alone -- Jira's key identifies nothing without the
    Atlassian account email, Harvest's without the account id. It is refused
    unless the state key is reviewed, and a scheme in
    ``_KEY_SCHEME_REQUIRED_COMPANIONS`` is refused WITHOUT one: publishing BASIC
    with a password and no username builds a connection the vendor cannot
    authenticate, which Composio would still report ACTIVE.

    The returned mapping is handed straight to ``connected_accounts.initiate``
    and is never stored, logged, or returned.
    """

    value: dict[str, object] = {
        "status": "ACTIVE",
        _KEY_SCHEME_SECRET_FIELDS[auth_scheme]: secret.get_secret_value(),
    }
    required = _KEY_SCHEME_REQUIRED_COMPANIONS.get(auth_scheme)
    if companion is not None:
        state_key, companion_value = _validate_key_companion(*companion)
        if required is not None and state_key != required:
            raise ValueError("companion_state_key does not satisfy the scheme")
        value[state_key] = companion_value
    elif required is not None:
        raise ValueError("auth_scheme requires a companion value")
    return {"auth_scheme": auth_scheme, "val": value}


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
    "KeyAuthScheme",
    "MANAGED_AUTH_CONFIG_ACTION",
    "MANAGED_AUTH_EFFECT_PROVIDER",
    "MANAGED_AUTH_LINK_ACTION",
    "MANAGED_KEY_CONFIG_ACTION",
    "MANAGED_KEY_CONNECT_ACTION",
    "ManagedAuthSdkClient",
    "ManagedConnectionPoll",
    "ManagedConnectionStart",
    "ManagedKeyConnection",
]
