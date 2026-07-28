"""Offline contract tests for the Composio managed-auth boundary."""

from __future__ import annotations

import pickle
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops.composio_managed_auth import (
    MANAGED_AUTH_EFFECT_PROVIDER,
    MANAGED_AUTH_LINK_ACTION,
    ComposioManagedAuthProvider,
)
from ops.config import Settings
from ops.effect_ledger import SQLiteEffectStore
from ops.provider_errors import (
    ConfigurationRequiredError,
    ProviderContractError,
    ProviderOperationError,
)

REDIRECT = "https://connect.example.test/oauth?state=one-time-value"
CALLBACK = "https://ops.example.test/api/composio/callback"


class _FakeAuthConfigs:
    def __init__(self, items: list[object] | None = None) -> None:
        self.items = list(items or [])
        self.list_calls: list[dict[str, object]] = []
        self.create_calls: list[tuple[str, dict[str, object]]] = []
        self.create_error: Exception | None = None
        self.add_before_error = False
        self.keep_creation_invisible = False

    def list(
        self,
        *,
        toolkit_slug: str,
        is_composio_managed: bool,
        show_disabled: bool,
        limit: float,
    ) -> object:
        self.list_calls.append(
            {
                "toolkit_slug": toolkit_slug,
                "is_composio_managed": is_composio_managed,
                "show_disabled": show_disabled,
                "limit": limit,
            }
        )
        return SimpleNamespace(items=list(self.items))

    def create(self, toolkit: str, options: Mapping[str, object]) -> object:
        self.create_calls.append((toolkit, dict(options)))
        created = _managed_config("ac_created", toolkit, created_at="2026-07-28T12:00:00Z")
        if self.create_error is not None:
            if self.add_before_error:
                self.items.append(created)
            raise self.create_error
        if not self.keep_creation_invisible:
            self.items.append(created)
        return SimpleNamespace(id="ac_created", is_composio_managed=True)


class _FakeConnectedAccounts:
    def __init__(self) -> None:
        self.link_calls: list[tuple[str, str, dict[str, object]]] = []
        self.get_calls: list[str] = []
        self.link_error: Exception | None = None
        self.link_response: object = SimpleNamespace(id="ca_request", redirect_url=REDIRECT)
        self.poll_responses: dict[str, object] = {}

    def link(
        self,
        user_id: str,
        auth_config_id: str,
        *,
        callback_url: str | None = None,
        allow_multiple: bool = False,
    ) -> object:
        self.link_calls.append(
            (
                user_id,
                auth_config_id,
                {"callback_url": callback_url, "allow_multiple": allow_multiple},
            )
        )
        if self.link_error is not None:
            raise self.link_error
        return self.link_response

    def get(self, nanoid: str) -> object:
        self.get_calls.append(nanoid)
        return self.poll_responses[nanoid]


class _FakeClient:
    def __init__(self, auth_configs: _FakeAuthConfigs | None = None) -> None:
        self.auth_configs = auth_configs or _FakeAuthConfigs()
        self.connected_accounts = _FakeConnectedAccounts()


def _managed_config(
    config_id: str,
    toolkit_slug: str,
    *,
    created_at: str = "2026-07-28T10:00:00Z",
) -> object:
    return SimpleNamespace(
        id=config_id,
        status="ENABLED",
        type="default",
        is_composio_managed=True,
        toolkit=SimpleNamespace(slug=toolkit_slug),
        created_at=created_at,
    )


def _provider(tmp_path: Path, client: _FakeClient) -> ComposioManagedAuthProvider:
    return ComposioManagedAuthProvider(
        sdk_client=client,
        effect_store=SQLiteEffectStore(tmp_path / "effects.db"),
        user_id="owner-1",
    )


@pytest.mark.asyncio
async def test_existing_managed_config_uses_exact_link_contract_and_ephemeral_redirect(
    tmp_path: Path,
) -> None:
    auth_configs = _FakeAuthConfigs(
        [
            _managed_config("ac_old", "github", created_at="2026-01-01T00:00:00Z"),
            _managed_config("ac_new", "github", created_at="2026-07-01T00:00:00Z"),
        ]
    )
    client = _FakeClient(auth_configs)
    provider = _provider(tmp_path, client)

    result = await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-1:managed-connect",
    )

    assert result.connection_request_id == "ca_request"
    assert result.redirect_url == REDIRECT
    assert result.replayed is False
    assert auth_configs.create_calls == []
    assert auth_configs.list_calls == [
        {
            "toolkit_slug": "github",
            "is_composio_managed": True,
            "show_disabled": False,
            "limit": 1000,
        }
    ]
    assert client.connected_accounts.link_calls == [
        (
            "owner-1",
            "ac_new",
            {"callback_url": CALLBACK, "allow_multiple": False},
        )
    ]
    assert REDIRECT not in repr(result)
    with pytest.raises(TypeError, match="ephemeral"):
        pickle.dumps(result)

    database_text = (tmp_path / "effects.db").read_bytes()
    assert REDIRECT.encode() not in database_text


@pytest.mark.asyncio
async def test_auth_config_and_link_are_idempotent_without_replaying_redirect(
    tmp_path: Path,
) -> None:
    client = _FakeClient()
    provider = _provider(tmp_path, client)

    first = await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-2:managed-connect",
    )
    second = await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-2:managed-connect",
    )

    assert first.redirect_url == REDIRECT
    assert second.connection_request_id == first.connection_request_id
    assert second.redirect_url is None
    assert second.replayed is True
    assert len(client.auth_configs.create_calls) == 1
    assert client.auth_configs.create_calls[0] == (
        "github",
        {
            "type": "use_composio_managed_auth",
            "name": "Composio Ops - github",
            "tool_access_config": {"tools_for_connected_account_creation": []},
        },
    )
    assert len(client.connected_accounts.link_calls) == 1

    with sqlite3.connect(tmp_path / "effects.db") as connection:
        receipts = [
            str(row[0])
            for row in connection.execute(
                "SELECT receipt_json FROM external_effects ORDER BY action"
            ).fetchall()
        ]
    assert receipts
    assert all("redirect" not in receipt.casefold() for receipt in receipts)
    assert all(REDIRECT not in receipt for receipt in receipts)


@pytest.mark.asyncio
async def test_completed_config_effect_handles_eventual_catalog_consistency(tmp_path: Path) -> None:
    auth_configs = _FakeAuthConfigs()
    auth_configs.keep_creation_invisible = True
    client = _FakeClient(auth_configs)
    provider = _provider(tmp_path, client)

    await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-3:first",
    )
    await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-3:second",
    )

    assert len(auth_configs.create_calls) == 1
    assert [call[1] for call in client.connected_accounts.link_calls] == [
        "ac_created",
        "ac_created",
    ]


@pytest.mark.asyncio
async def test_ambiguous_config_create_reconciles_by_read_without_duplicate(tmp_path: Path) -> None:
    auth_configs = _FakeAuthConfigs()
    auth_configs.create_error = TimeoutError("provider response lost")
    auth_configs.add_before_error = True
    client = _FakeClient(auth_configs)
    provider = _provider(tmp_path, client)

    with pytest.raises(ProviderOperationError) as raised:
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-4:managed-connect",
        )
    assert raised.value.reason_code == "auth_config_create_failed"

    recovered = await provider.start_connection(
        toolkit_slug="github",
        callback_url=CALLBACK,
        effect_identity="run-4:managed-connect",
    )
    assert recovered.connection_request_id == "ca_request"
    assert len(auth_configs.create_calls) == 1
    assert len(client.connected_accounts.link_calls) == 1


@pytest.mark.asyncio
async def test_ambiguous_config_create_without_visible_result_requires_reconciliation(
    tmp_path: Path,
) -> None:
    auth_configs = _FakeAuthConfigs()
    auth_configs.create_error = TimeoutError("provider response lost")
    client = _FakeClient(auth_configs)
    provider = _provider(tmp_path, client)

    with pytest.raises(ProviderOperationError):
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-5:managed-connect",
        )
    with pytest.raises(ProviderOperationError) as raised:
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-5:managed-connect",
        )

    assert raised.value.reason_code == "auth_config_reconciliation_required"
    assert len(auth_configs.create_calls) == 1
    assert client.connected_accounts.link_calls == []


@pytest.mark.asyncio
async def test_ambiguous_link_is_not_blindly_retried(tmp_path: Path) -> None:
    client = _FakeClient(_FakeAuthConfigs([_managed_config("ac_existing", "github")]))
    client.connected_accounts.link_error = TimeoutError("provider response lost")
    provider = _provider(tmp_path, client)

    with pytest.raises(ProviderOperationError) as first:
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-6:managed-connect",
        )
    with pytest.raises(ProviderOperationError) as second:
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-6:managed-connect",
        )

    assert first.value.reason_code == "connection_link_failed"
    assert second.value.reason_code == "connection_reconciliation_required"
    assert len(client.connected_accounts.link_calls) == 1
    reservation = SQLiteEffectStore(tmp_path / "effects.db").reserve(
        provider=MANAGED_AUTH_EFFECT_PROVIDER,
        action=MANAGED_AUTH_LINK_ACTION,
        idempotency_key="run-6:managed-connect",
    )
    assert reservation.status == "reconcile_required"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_status", "state", "reason_code"),
    [
        ("INITIATED", "pending", "connection_pending"),
        ("INACTIVE", "pending", "connection_pending"),
        ("ACTIVE", "active", "connection_active"),
        ("FAILED", "terminal", "connection_failed"),
        ("EXPIRED", "terminal", "connection_expired"),
        ("REVOKED", "terminal", "connection_revoked"),
    ],
)
async def test_poll_retrieves_and_normalizes_connection_state(
    tmp_path: Path,
    provider_status: str,
    state: str,
    reason_code: str,
) -> None:
    client = _FakeClient()
    client.connected_accounts.poll_responses["ca_poll"] = SimpleNamespace(
        id="ca_poll",
        status=provider_status,
        status_reason="raw provider detail that must not escape",
    )
    provider = _provider(tmp_path, client)

    result = await provider.poll_connection("ca_poll")

    assert result.state == state
    assert result.reason_code == reason_code
    assert result.active is (state == "active")
    assert client.connected_accounts.get_calls == ["ca_poll"]
    assert "raw provider detail" not in repr(result)


@pytest.mark.asyncio
async def test_invalid_link_response_fails_closed_and_marks_effect_ambiguous(
    tmp_path: Path,
) -> None:
    client = _FakeClient(_FakeAuthConfigs([_managed_config("ac_existing", "github")]))
    client.connected_accounts.link_response = SimpleNamespace(
        id="ca_request",
        redirect_url=None,
    )
    provider = _provider(tmp_path, client)

    with pytest.raises(ProviderContractError) as raised:
        await provider.start_connection(
            toolkit_slug="github",
            callback_url=CALLBACK,
            effect_identity="run-7:managed-connect",
        )

    assert raised.value.reason_code == "connection_link_response_invalid"
    reservation = SQLiteEffectStore(tmp_path / "effects.db").reserve(
        provider=MANAGED_AUTH_EFFECT_PROVIDER,
        action=MANAGED_AUTH_LINK_ACTION,
        idempotency_key="run-7:managed-connect",
    )
    assert reservation.status == "reconcile_required"


def test_from_settings_fails_without_api_key_before_import_or_network() -> None:
    with pytest.raises(ConfigurationRequiredError) as raised:
        ComposioManagedAuthProvider.from_settings(Settings())

    assert raised.value.reason_code == "composio_not_configured"
